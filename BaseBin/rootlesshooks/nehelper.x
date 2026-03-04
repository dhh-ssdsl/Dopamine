#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>
#import <objc/runtime.h>

// ============================================================
// Logging
// ============================================================

static void _ne_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _ne_log(const char *fmt, ...) {
	FILE *f = fopen(JBROOT_PATH_CSTRING("/var/mobile/hook_debug.log"), "a");
	if (!f) return;
	time_t t = time(NULL);
	struct tm tm; localtime_r(&t, &tm);
	fprintf(f, "%02d:%02d:%02d [nehelper] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
	va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
	fprintf(f, "\n"); fclose(f);
}
#define NE_LOG(fmt, ...) _ne_log(fmt, ##__VA_ARGS__)

// ============================================================
// JB App Detection
// ============================================================

static NSString *gJBRootPrefix = nil;
static dispatch_once_t gJBRootOnce;

static NSString *jbRootPrefix(void)
{
	dispatch_once(&gJBRootOnce, ^{
		gJBRootPrefix = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/")];
		if (![gJBRootPrefix hasSuffix:@"/"])
			gJBRootPrefix = [gJBRootPrefix stringByAppendingString:@"/"];
	});
	return gJBRootPrefix;
}

static BOOL isJBBundleID(NSString *bundleID)
{
	if (!bundleID.length) return NO;

	Class LSProxy = NSClassFromString(@"LSApplicationProxy");
	if (LSProxy) {
		id proxy = [LSProxy applicationProxyForIdentifier:bundleID];
		NSString *bundlePath = [[proxy valueForKey:@"bundleURL"] path];
		if (bundlePath.length) {
			return [bundlePath hasPrefix:jbRootPrefix()];
		}
	}

	// Fallback: /Applications directory scan
	NSString *jbAppsPath = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/Applications")];
	NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbAppsPath error:nil];
	for (NSString *item in contents) {
		if (![item hasSuffix:@".app"]) continue;
		NSString *infoPath = [[jbAppsPath stringByAppendingPathComponent:item]
		                      stringByAppendingPathComponent:@"Info.plist"];
		NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
		if ([info[@"CFBundleIdentifier"] isEqualToString:bundleID]) return YES;
	}
	return NO;
}

// ============================================================
// Dynamic method probe: hooks every instance method of a class,
// logs when the method is called.
// ============================================================

// Generic trampoline that logs method name when called.
// We use a single global IMP array trick with libffi or similar.
// Since we don't have libffi, use a simpler approach:
// just hook 'methods that look like save/load/write/update/commit/serialize'.

typedef void (*VoidIMP)(id, SEL);
static void (*orig_ne_void_methods[64])(id, SEL);
static char gNEProbeMethodNames[64][256];
static int gNEProbeCount = 0;

static void ne_probe_trampoline_log(id self, SEL cmd, ...)
{
	NE_LOG("PROBE CALL: [%s %s]", object_getClassName(self), sel_getName(cmd));
}

// Hook all instance methods of a class whose name matches any of the filter words.
static void probeClassMethods(Class cls, const char *className)
{
	if (!cls) return;
	unsigned int methodCount = 0;
	Method *methods = class_copyMethodList(cls, &methodCount);
	NE_LOG("PROBE: scanning class %s, found %u methods", className, methodCount);
	for (unsigned int i = 0; i < methodCount; i++) {
		const char *name = sel_getName(method_getName(methods[i]));
		// Filter for methods that are likely related to saving/loading/updating
		if (strstr(name, "save") || strstr(name, "Save") ||
		    strstr(name, "write") || strstr(name, "Write") ||
		    strstr(name, "store") || strstr(name, "Store") ||
		    strstr(name, "commit") || strstr(name, "Commit") ||
		    strstr(name, "persist") || strstr(name, "Persist") ||
		    strstr(name, "update") || strstr(name, "Update") ||
		    strstr(name, "sync") || strstr(name, "Sync") ||
		    strstr(name, "load") || strstr(name, "Load") ||
		    strstr(name, "read") || strstr(name, "Read") ||
		    strstr(name, "fetch") || strstr(name, "Fetch") ||
		    strstr(name, "encode") || strstr(name, "decode") ||
		    strstr(name, "Rule") || strstr(name, "rule") ||
		    strstr(name, "Config") || strstr(name, "config") ||
		    strstr(name, "cellular") || strstr(name, "Cellular") ||
		    strstr(name, "wifi") || strstr(name, "Wifi") ||
		    strstr(name, "network") || strstr(name, "Network") ||
		    strstr(name, "path") || strstr(name, "Path")
		) {
			NE_LOG("PROBE: will hook [%s %s]", className, name);
		}
	}
	free(methods);
}

// ============================================================
// NSKeyedArchiver/UnArchiver route probes:
// Only log encode/decode of the keys we care about
// (config-aggregate-rules, Rules, PathController).
// ============================================================

static void (*orig_encode_object_forKey)(id self, SEL _cmd, id obj, NSString *key);
static void hook_encode_object_forKey(id self, SEL _cmd, id obj, NSString *key)
{
	if ([key isEqualToString:@"config-aggregate-rules"] ||
	    [key isEqualToString:@"Rules"] ||
	    [key isEqualToString:@"PayloadAppRules"] ||
	    [key isEqualToString:@"PathController"]) {

		NE_LOG("PROBE ENCODE: key='%s' obj_class=%s", key.UTF8String, object_getClassName(obj));

		if ([obj isKindOfClass:[NSArray class]]) {
			NSArray *arr = (NSArray *)obj;
			NE_LOG("PROBE ENCODE: array count=%lu", (unsigned long)arr.count);
			int jbCount = 0, sysCount = 0;
			for (id rule in arr) {
				if ([rule respondsToSelector:@selector(matchSigningIdentifier)]) {
					NSString *bid = [rule valueForKey:@"matchSigningIdentifier"];
					if (bid) {
						if (isJBBundleID(bid)) jbCount++;
						else sysCount++;
					}
				}
				// Log ALL property names on the first few rule objects
				// so we know exactly what properties are available
				static int logged = 0;
				if (logged < 3) {
					logged++;
					unsigned int propCount = 0;
					objc_property_t *props = class_copyPropertyList(object_getClass(rule), &propCount);
					NSMutableString *propNames = [NSMutableString string];
					for (unsigned int p = 0; p < propCount; p++) {
						if (p) [propNames appendString:@", "];
						[propNames appendString:@(property_getName(props[p]))];
					}
					free(props);
					NE_LOG("PROBE ENCODE: rule[%d] class=%s props=[%s]",
					       logged, object_getClassName(rule), propNames.UTF8String);
				}
			}
			NE_LOG("PROBE ENCODE: JB rules=%d, System rules=%d", jbCount, sysCount);
		}
	}
	orig_encode_object_forKey(self, _cmd, obj, key);
}

static id (*orig_decode_object_forKey)(id self, SEL _cmd, NSString *key);
static id hook_decode_object_forKey(id self, SEL _cmd, NSString *key)
{
	id obj = orig_decode_object_forKey(self, _cmd, key);

	if (obj && ([key isEqualToString:@"config-aggregate-rules"] ||
	            [key isEqualToString:@"Rules"] ||
	            [key isEqualToString:@"PayloadAppRules"] ||
	            [key isEqualToString:@"PathController"])) {

		NE_LOG("PROBE DECODE: key='%s' obj_class=%s", key.UTF8String, object_getClassName(obj));

		if ([obj isKindOfClass:[NSArray class]]) {
			NSArray *arr = (NSArray *)obj;
			NE_LOG("PROBE DECODE: array count=%lu", (unsigned long)arr.count);
			int jbCount = 0, sysCount = 0;
			for (id rule in arr) {
				if ([rule respondsToSelector:@selector(matchSigningIdentifier)]) {
					NSString *bid = [rule valueForKey:@"matchSigningIdentifier"];
					if (bid) {
						NE_LOG("PROBE DECODE: rule SigningIdentifier='%s' isJB=%d",
						       bid.UTF8String, isJBBundleID(bid) ? 1 : 0);
						if (isJBBundleID(bid)) jbCount++;
						else sysCount++;
					}
				}
			}
			NE_LOG("PROBE DECODE: JB rules=%d, System rules=%d", jbCount, sysCount);
		}
	}

	return obj;
}

// ============================================================
void nehelperInit(void)
{
	NE_LOG("nehelperInit() called in process: %s (pid=%d)", getprogname(), getpid());

	// Scan NEPathController and NEConfiguration methods at runtime
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
	               dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		probeClassMethods(NSClassFromString(@"NEPathController"), "NEPathController");
		probeClassMethods(NSClassFromString(@"NEConfiguration"), "NEConfiguration");
		probeClassMethods(NSClassFromString(@"NEPathRule"), "NEPathRule");
	});

	// -- NSKeyedArchiver focused probes --
	Class archiverClass = objc_getClass("NSKeyedArchiver");
	if (archiverClass) {
		MSHookMessageEx(archiverClass,
		    @selector(encodeObject:forKey:),
		    (IMP)hook_encode_object_forKey,
		    (IMP *)&orig_encode_object_forKey);
		NE_LOG("nehelperInit: NSKeyedArchiver probe installed");
	}

	// -- NSKeyedUnarchiver focused probes --
	Class unarchiverClass = objc_getClass("NSKeyedUnarchiver");
	if (unarchiverClass) {
		MSHookMessageEx(unarchiverClass,
		    @selector(decodeObjectForKey:),
		    (IMP)hook_decode_object_forKey,
		    (IMP *)&orig_decode_object_forKey);
		NE_LOG("nehelperInit: NSKeyedUnarchiver probe installed");
	}

	NE_LOG("nehelperInit: probes installed, scan will run after 0.5s");
}

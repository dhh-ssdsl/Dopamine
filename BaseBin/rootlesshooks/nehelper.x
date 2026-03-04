#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>
#import <objc/runtime.h>

// LSApplicationProxy forward declaration (MobileCoreServices private)
@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier;
@property (nonatomic, readonly) NSURL *bundleURL;
@end

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
// NSKeyedArchiver / NSKeyedUnarchiver DIAGNOSTIC HOOKS
//
// Purpose: log every key encountered during NE plist encode/decode
// so we can find the exact key that contains per-app network rules.
// Once identified, replace with routing logic.
// ============================================================


// -- NSKeyedArchiver hooks --

static void (*orig_encode_object_forKey)(id self, SEL _cmd, id object, NSString *key);
static void hook_encode_object_forKey(id self, SEL _cmd, id object, NSString *key)
{
	if (key) {
		NSString *objDesc = @"(nil)";
		if (object) {
			if ([object isKindOfClass:[NSDictionary class]]) {
				NSDictionary *dict = (NSDictionary *)object;
				// Log first few keys of the dict to identify bundle-ID style keys
				NSArray *sampleKeys = [dict.allKeys subarrayWithRange:NSMakeRange(0, MIN(5u, dict.count))];
				objDesc = [NSString stringWithFormat:@"NSDictionary(%lu entries, sample keys: %@)",
				           (unsigned long)dict.count, sampleKeys];

				// Check if any key looks like a bundle ID and might be a JB app
				for (NSString *k in dict) {
					if ([k containsString:@"."] && isJBBundleID(k)) {
						NE_LOG("  ** FOUND JB bundleID as dict key in encodeObject:forKey:'%s' -> bundleID='%s'",
						       key.UTF8String, k.UTF8String);
					}
				}
			} else {
				objDesc = [NSString stringWithFormat:@"%@", [object class]];
			}
		}
		NE_LOG("NSKeyedArchiver encodeObject:forKey: '%s' obj=%s",
		       key.UTF8String, objDesc.UTF8String);
	}
	orig_encode_object_forKey(self, _cmd, object, key);
}

// Also hook encodeObject: (no key, for collections)
static void (*orig_encode_object)(id self, SEL _cmd, id object);
static void hook_encode_object(id self, SEL _cmd, id object)
{
	// Only log dicts that look like they could contain bundle IDs
	if ([object isKindOfClass:[NSDictionary class]]) {
		NSDictionary *dict = (NSDictionary *)object;
		for (NSString *k in dict) {
			if ([k containsString:@"."] && isJBBundleID(k)) {
				NE_LOG("NSKeyedArchiver encodeObject:(no-key) NSDictionary has JB bundleID key='%s'",
				       k.UTF8String);
				break;
			}
		}
	}
	orig_encode_object(self, _cmd, object);
}

// -- NSKeyedUnarchiver hooks --

static id (*orig_decode_object_forKey)(id self, SEL _cmd, NSString *key);
static id hook_decode_object_forKey(id self, SEL _cmd, NSString *key)
{
	id result = orig_decode_object_forKey(self, _cmd, key);

	if (key) {
		NSString *resultDesc = @"(nil)";
		if (result) {
			if ([result isKindOfClass:[NSDictionary class]]) {
				NSDictionary *dict = (NSDictionary *)result;
				NSArray *sampleKeys = [dict.allKeys subarrayWithRange:NSMakeRange(0, MIN(5u, dict.count))];
				resultDesc = [NSString stringWithFormat:@"NSDictionary(%lu entries, sample keys: %@)",
				              (unsigned long)dict.count, sampleKeys];

				for (NSString *k in dict) {
					if ([k containsString:@"."] && isJBBundleID(k)) {
						NE_LOG("  ** FOUND JB bundleID as dict key in decodeObjectForKey:'%s' -> bundleID='%s'",
						       key.UTF8String, k.UTF8String);
					}
				}
			} else {
				resultDesc = [NSString stringWithFormat:@"%@", [result class]];
			}
		}
		NE_LOG("NSKeyedUnarchiver decodeObjectForKey: '%s' -> %s",
		       key.UTF8String, resultDesc.UTF8String);
	}

	return result;
}

// ============================================================
// NSData file I/O hooks (backup layer: detect NE plist writes
// and log what bundle IDs appear in $objects array)
// ============================================================

static NSString *const kNEPlistName = @"com.apple.networkextension.plist";

static BOOL isNEPlist(NSString *path)
{
	return [path hasSuffix:kNEPlistName];
}

static NSString *jbNEPlistPath(void)
{
	static NSString *path = nil;
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		path = [NSString stringWithUTF8String:
		        JBROOT_PATH_CSTRING("/var/preferences/com.apple.networkextension.plist")];
	});
	return path;
}

static void ensureJBPreferencesDir(void)
{
	NSString *dir = [jbNEPlistPath() stringByDeletingLastPathComponent];
	if (![[NSFileManager defaultManager] fileExistsAtPath:dir]) {
		[[NSFileManager defaultManager] createDirectoryAtPath:dir
		                          withIntermediateDirectories:YES
		                                           attributes:nil
		                                               error:nil];
	}
}

static __thread BOOL gNEIsRouting = NO;

// ============================================================
// Objective-C Object Probes for NEConfiguration / NEPathController
// ============================================================

// Forward declarations for Private Framework classes
@interface NEPathRule : NSObject
@property (retain) NSString *matchSigningIdentifier;
@property NSInteger cellularBehavior;
@property NSInteger wifiBehavior;
@end

@interface NEPathController : NSObject
@property (retain) NSArray *pathRules;
@property (retain) NSArray *payloadAppRules;
@end

@interface NEConfiguration : NSObject
@property (readonly) NEPathController *pathController;
@property (retain) NSString *identifier;
@property (retain) NSString *name;
@end


static void (*orig_encode_object_forKey)(id self, SEL _cmd, id obj, NSString *key);
static void hook_encode_object_forKey(id self, SEL _cmd, id obj, NSString *key)
{
	if ([key isEqualToString:@"config-aggregate-rules"] ||
	    [key isEqualToString:@"Rules"] ||
	    [key isEqualToString:@"PayloadAppRules"]) {

		NE_LOG("PROBE ENCODE: key='%s' obj_class=%s", key.UTF8String, object_getClassName(obj));

		if ([obj isKindOfClass:[NSArray class]]) {
			NSArray *arr = (NSArray *)obj;
			NE_LOG("PROBE ENCODE: array count=%lu", (unsigned long)arr.count);
			int jbCount = 0;
			int sysCount = 0;
			for (id rule in arr) {
				if ([rule respondsToSelector:@selector(matchSigningIdentifier)]) {
					NSString *bid = [rule valueForKey:@"matchSigningIdentifier"];
					if (bid) {
						if (isJBBundleID(bid)) {
							jbCount++;
						} else {
							sysCount++;
						}
					}
				}
			}
			NE_LOG("PROBE ENCODE: array analysis -> JB rules: %d, System rules: %d", jbCount, sysCount);
		}
	}

	if ([obj isKindOfClass:NSClassFromString(@"NEConfiguration")]) {
		NE_LOG("PROBE ENCODE: Found NEConfiguration");
	}
	if ([obj isKindOfClass:NSClassFromString(@"NEPathController")]) {
		NE_LOG("PROBE ENCODE: Found NEPathController");
	}

	orig_encode_object_forKey(self, _cmd, obj, key);
}


static id (*orig_decode_object_forKey)(id self, SEL _cmd, NSString *key);
static id hook_decode_object_forKey(id self, SEL _cmd, NSString *key)
{
	id obj = orig_decode_object_forKey(self, _cmd, key);

	if (obj && ([key isEqualToString:@"config-aggregate-rules"] ||
	            [key isEqualToString:@"Rules"] ||
	            [key isEqualToString:@"PayloadAppRules"])) {

		NE_LOG("PROBE DECODE: key='%s' obj_class=%s", key.UTF8String, object_getClassName(obj));

		if ([obj isKindOfClass:[NSArray class]]) {
			NSArray *arr = (NSArray *)obj;
			NE_LOG("PROBE DECODE: array count=%lu", (unsigned long)arr.count);
			int jbCount = 0;
			int sysCount = 0;
			for (id rule in arr) {
				if ([rule respondsToSelector:@selector(matchSigningIdentifier)]) {
					NSString *bid = [rule valueForKey:@"matchSigningIdentifier"];
					if (bid) {
						if (isJBBundleID(bid)) {
							jbCount++;
						} else {
							sysCount++;
						}
					}
				}
			}
			NE_LOG("PROBE DECODE: array analysis -> JB rules: %d, System rules: %d", jbCount, sysCount);
		}
	}

	return obj;
}


// ============================================================
void nehelperInit(void)
{
	NE_LOG("nehelperInit() called in process: %s (pid=%d)", getprogname(), getpid());

	// -- NSKeyedArchiver object probes --
	Class archiverClass = objc_getClass("NSKeyedArchiver");
	if (archiverClass) {
		MSHookMessageEx(archiverClass,
		    @selector(encodeObject:forKey:),
		    (IMP)hook_encode_object_forKey,
		    (IMP *)&orig_encode_object_forKey);
		NE_LOG("nehelperInit: NSKeyedArchiver probe installed");
	}

	// -- NSKeyedUnarchiver object probes --
	Class unarchiverClass = objc_getClass("NSKeyedUnarchiver");
	if (unarchiverClass) {
		MSHookMessageEx(unarchiverClass,
		    @selector(decodeObjectForKey:),
		    (IMP)hook_decode_object_forKey,
		    (IMP *)&orig_decode_object_forKey);
		NE_LOG("nehelperInit: NSKeyedUnarchiver probe installed");
	}

	NE_LOG("nehelperInit: Objective-C object probes installed");
}

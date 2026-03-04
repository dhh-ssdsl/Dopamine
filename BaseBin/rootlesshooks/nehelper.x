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

// Track whether we are in an NE-related archiving context
// (nehelper archives several things; we want to focus on networkextension.plist)
static __thread BOOL gInNEArchive = NO;
static __thread int  gNEArchiveDepth = 0;

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

// Scan $objects for JB bundle IDs and log them
static void logNEPlistBundleIDs(NSData *data, const char *context)
{
	NSError *error = nil;
	NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:data
	                                                                options:0
	                                                                 format:nil
	                                                                  error:&error];
	NSArray *objects = plist[@"$objects"];
	if (![objects isKindOfClass:[NSArray class]]) {
		NE_LOG("%s: no $objects in plist (parse error: %s)", context,
		       error.localizedDescription.UTF8String ?: "unknown");
		return;
	}

	NSMutableArray *jbIDs = [NSMutableArray array];
	NSMutableArray *sysIDs = [NSMutableArray array];
	for (id obj in objects) {
		if (![obj isKindOfClass:[NSString class]]) continue;
		NSString *str = (NSString *)obj;
		if ([str hasPrefix:@"$"] || [str hasPrefix:@"NS."] || str.length > 256) continue;
		if (![str containsString:@"."]) continue;
		// Only log things that look like bundle IDs (reverse-domain, 2+ components)
		NSArray *parts = [str componentsSeparatedByString:@"."];
		if (parts.count < 2) continue;
		if (isJBBundleID(str)) {
			[jbIDs addObject:str];
		} else if (parts.count >= 3) {
			// Plausible bundle ID, not JB
			[sysIDs addObject:str];
		}
	}
	NE_LOG("%s: $objects scan: %lu JB bundleIDs, %lu system bundleIDs",
	       context, (unsigned long)jbIDs.count, (unsigned long)sysIDs.count);
	for (NSString *bid in jbIDs) {
		NE_LOG("  JB bundleID: %s", bid.UTF8String);
	}
}

static BOOL (*orig_NSData_writeToFile_options_error)(NSData *self, SEL _cmd, NSString *path, NSDataWritingOptions opts, NSError **error);
static BOOL hook_NSData_writeToFile_options_error(NSData *self, SEL _cmd, NSString *path, NSDataWritingOptions opts, NSError **error)
{
	if (!gNEIsRouting && isNEPlist(path)) {
		NE_LOG("WRITE intercepted: %s (%lu bytes)", path.UTF8String, (unsigned long)self.length);
		logNEPlistBundleIDs(self, "WRITE");

		// Save JB mirror (full copy for now; will refine after key name confirmed)
		gNEIsRouting = YES;
		ensureJBPreferencesDir();
		[self writeToFile:jbNEPlistPath() atomically:YES];
		gNEIsRouting = NO;
		NE_LOG("WRITE: JB mirror saved to %s", jbNEPlistPath().UTF8String);
	}
	return orig_NSData_writeToFile_options_error(self, _cmd, path, opts, error);
}

static NSData *(*orig_NSData_dataWithContentsOfFile_options_error)(id self, SEL _cmd, NSString *path, NSDataReadingOptions opts, NSError **error);
static NSData *hook_NSData_dataWithContentsOfFile_options_error(id self, SEL _cmd, NSString *path, NSDataReadingOptions opts, NSError **error)
{
	NSData *data = orig_NSData_dataWithContentsOfFile_options_error(self, _cmd, path, opts, error);
	if (!gNEIsRouting && isNEPlist(path)) {
		NE_LOG("READ intercepted: %s (%lu bytes)", path.UTF8String, (unsigned long)data.length);
		logNEPlistBundleIDs(data, "READ");
	}
	return data;
}

// ============================================================
void nehelperInit(void)
{
	NE_LOG("nehelperInit() called in process: %s (pid=%d)", getprogname(), getpid());

	// -- NSKeyedArchiver diagnostic hooks --
	Class archiverClass = objc_getClass("NSKeyedArchiver");
	if (archiverClass) {
		MSHookMessageEx(archiverClass,
		    @selector(encodeObject:forKey:),
		    (IMP)hook_encode_object_forKey,
		    (IMP *)&orig_encode_object_forKey);
		MSHookMessageEx(archiverClass,
		    @selector(encodeObject:),
		    (IMP)hook_encode_object,
		    (IMP *)&orig_encode_object);
		NE_LOG("nehelperInit: NSKeyedArchiver encode hooks installed");
	}

	// -- NSKeyedUnarchiver diagnostic hooks --
	Class unarchiverClass = objc_getClass("NSKeyedUnarchiver");
	if (unarchiverClass) {
		MSHookMessageEx(unarchiverClass,
		    @selector(decodeObjectForKey:),
		    (IMP)hook_decode_object_forKey,
		    (IMP *)&orig_decode_object_forKey);
		NE_LOG("nehelperInit: NSKeyedUnarchiver decode hooks installed");
	}

	// -- NSData file I/O hooks (backup layer) --
	MSHookMessageEx(
		objc_getMetaClass("NSData"),
		@selector(dataWithContentsOfFile:options:error:),
		(IMP)hook_NSData_dataWithContentsOfFile_options_error,
		(IMP *)&orig_NSData_dataWithContentsOfFile_options_error
	);
	MSHookMessageEx(
		objc_getClass("NSData"),
		@selector(writeToFile:options:error:),
		(IMP)hook_NSData_writeToFile_options_error,
		(IMP *)&orig_NSData_writeToFile_options_error
	);

	NE_LOG("nehelperInit: all hooks installed");
}

#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>
#import <objc/runtime.h>

// LSApplicationProxy forward declaration (MobileCoreServices private)
@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier;
@property (nonatomic, readonly) NSURL *bundleURL;
@end

static void _bb_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _bb_log(const char *fmt, ...) {
	FILE *f = fopen(JBROOT_PATH_CSTRING("/var/mobile/hook_debug.log"), "a");
	if (!f) return;
	time_t t = time(NULL);
	struct tm tm; localtime_r(&t, &tm);
	fprintf(f, "%02d:%02d:%02d [BulletinBoard] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
	va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
	fprintf(f, "\n"); fclose(f);
}
#define BB_LOG(fmt, ...) _bb_log(fmt, ##__VA_ARGS__)

static NSString *kSectionInfoPath = @"/var/mobile/Library/BulletinBoard/VersionedSectionInfo.plist";
static NSString *kClearedSectionsPath = @"/var/mobile/Library/BulletinBoard/ClearedSections.plist";

static __thread BOOL gIsRouting; // Thread-local: prevent recursive hooks per-thread

// JB root path prefix (e.g. /private/preboot/.../procursus)
static NSString *gJBRootPrefix = nil;
static dispatch_once_t gJBRootOnce;

static NSString *jbRootPrefix(void)
{
	dispatch_once(&gJBRootOnce, ^{
		gJBRootPrefix = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/")];
		// Normalize trailing slash
		if (![gJBRootPrefix hasSuffix:@"/"]) {
			gJBRootPrefix = [gJBRootPrefix stringByAppendingString:@"/"];
		}
		BB_LOG("jbRootPrefix initialized: %s", gJBRootPrefix.UTF8String);
	});
	return gJBRootPrefix;
}

// Check if a bundle ID belongs to a JB-installed app by querying LSApplicationProxy
// for the app's bundle URL and checking if it lives under the JB root prefix.
// Falls back to /Applications directory scan if LSApplicationProxy is unavailable.
static BOOL isJBBundleID(NSString *bundleID)
{
	if (!bundleID.length) return NO;

	// Primary: query LSApplicationProxy for the bundle path
	Class LSProxy = NSClassFromString(@"LSApplicationProxy");
	if (LSProxy) {
		id proxy = [LSProxy applicationProxyForIdentifier:bundleID];
		NSURL *bundleURL = [proxy valueForKey:@"bundleURL"];
		NSString *bundlePath = bundleURL.path;
		if (bundlePath.length) {
			BOOL result = [bundlePath hasPrefix:jbRootPrefix()];
			return result;
		}
	}

	// Fallback: check if <jbroot>/Applications/<*.app>/Info.plist contains this bundle ID
	NSString *jbAppsPath = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/Applications")];
	NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbAppsPath error:nil];
	for (NSString *item in contents) {
		if (![item hasSuffix:@".app"]) continue;
		NSString *appPath = [jbAppsPath stringByAppendingPathComponent:item];
		NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[appPath stringByAppendingPathComponent:@"Info.plist"]];
		if ([info[@"CFBundleIdentifier"] isEqualToString:bundleID]) {
			return YES;
		}
	}
	return NO;
}

static NSString *jbNotificationPlistPath(void)
{
	static NSString *path = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		path = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/var/mobile/Library/BulletinBoard/.jb_VersionedSectionInfo.plist")];
	});
	return path;
}

static NSString *jbClearedSectionsPath(void)
{
	static NSString *path = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		path = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/var/mobile/Library/BulletinBoard/.jb_ClearedSections.plist")];
	});
	return path;
}

static BOOL isBulletinBoardPlist(NSString *path)
{
	return [path isEqualToString:kSectionInfoPath] || [path hasSuffix:@"VersionedSectionInfo.plist"];
}

static BOOL isClearedSectionsPlist(NSString *path)
{
	return [path isEqualToString:kClearedSectionsPath] || [path hasSuffix:@"ClearedSections.plist"];
}

static void ensureJBBulletinBoardDir(void)
{
	NSString *dir = [jbNotificationPlistPath() stringByDeletingLastPathComponent];
	if (![[NSFileManager defaultManager] fileExistsAtPath:dir]) {
		[[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
	}
}

// ============================================================
// INJECT-ON-WRITE HOOK: Forget about intercepting early reads.
// When SpringBoard writes the plist, we take the data it\'s about to write
// (which may be missing JB apps if it read before our hook or via unknown API),
// combine it with our saved JB apps, and write the combined data to the system plist.
// We also update our saved JB apps plist.
// ============================================================

static void performInjectOnWrite(NSData *data, NSString *path,
							  BOOL (^writeOriginal)(NSData *d, NSString *p))
{
	NSError *error = nil;
	NSPropertyListFormat format = 0;
	NSDictionary *fullDict = [NSPropertyListSerialization propertyListWithData:data options:0 format:&format error:&error];
	
	if (![fullDict isKindOfClass:[NSDictionary class]]) {
		BB_LOG("performInjectOnWrite: failed to parse plist, writing as-is");
		writeOriginal(data, path);
		return;
	}

	if (isBulletinBoardPlist(path)) {
		NSDictionary *sbSectionInfo = fullDict[@"sectionInfo"];
		if (![sbSectionInfo isKindOfClass:[NSDictionary class]]) {
			writeOriginal(data, path);
			return;
		}

		NSMutableDictionary *mergedSectionInfo = [sbSectionInfo mutableCopy];
		NSMutableDictionary *jbSectionInfo = [NSMutableDictionary dictionary];

		// 1. Separate current JB entries from SB's save attempt
		for (NSString *bundleID in sbSectionInfo) {
			if (isJBBundleID(bundleID)) {
				jbSectionInfo[bundleID] = sbSectionInfo[bundleID];
			}
		}

		// 2. Load previous JB entries from the backup file
		NSData *savedJBData = [NSData dataWithContentsOfFile:jbNotificationPlistPath()];
		if (savedJBData) {
			NSDictionary *savedJBDict = [NSPropertyListSerialization propertyListWithData:savedJBData options:0 format:nil error:nil];
			if ([savedJBDict isKindOfClass:[NSDictionary class]]) {
				NSDictionary *savedJBSectionInfo = savedJBDict[@"sectionInfo"];
				if ([savedJBSectionInfo isKindOfClass:[NSDictionary class]]) {
					// 3. For any JB apps in the backup that aren't in the current save attempt, merge them in.
					for (NSString *bundleID in savedJBSectionInfo) {
						if (!jbSectionInfo[bundleID]) {
							jbSectionInfo[bundleID] = savedJBSectionInfo[bundleID]; // Keep our backup copy
							mergedSectionInfo[bundleID] = savedJBSectionInfo[bundleID]; // Inject back into system save
						}
					}
				}
			}
		}

		BB_LOG("performInjectOnWrite: writing %lu total sectionInfo entries (%lu are JB)", 
			(unsigned long)mergedSectionInfo.count, (unsigned long)jbSectionInfo.count);

		// 4. Save the full merged list to the system path
		NSMutableDictionary *finalSystemDict = [fullDict mutableCopy];
		finalSystemDict[@"sectionInfo"] = mergedSectionInfo;
		NSData *systemDataToWrite = [NSPropertyListSerialization dataWithPropertyList:finalSystemDict format:format options:0 error:nil];
		if (systemDataToWrite) {
			writeOriginal(systemDataToWrite, path);
		} else {
			writeOriginal(data, path);
		}

		// 5. Save the updated JB entries to our backup path
		if (jbSectionInfo.count > 0) {
			ensureJBBulletinBoardDir();
			NSMutableDictionary *finalJBDict = [fullDict mutableCopy];
			finalJBDict[@"sectionInfo"] = jbSectionInfo;
			NSData *jbDataToWrite = [NSPropertyListSerialization dataWithPropertyList:finalJBDict format:format options:0 error:nil];
			if (jbDataToWrite) {
				[jbDataToWrite writeToFile:jbNotificationPlistPath() atomically:YES];
			}
		}
		return;
	}

	if (isClearedSectionsPlist(path)) {
		NSMutableDictionary *mergedEntries = [(NSDictionary *)fullDict mutableCopy];
		NSMutableDictionary *jbEntries = [NSMutableDictionary dictionary];

		for (NSString *bundleID in fullDict) {
			if (isJBBundleID(bundleID)) {
				jbEntries[bundleID] = fullDict[bundleID];
			}
		}

		NSData *savedJBData = [NSData dataWithContentsOfFile:jbClearedSectionsPath()];
		if (savedJBData) {
			NSDictionary *savedJBDict = [NSPropertyListSerialization propertyListWithData:savedJBData options:0 format:nil error:nil];
			if ([savedJBDict isKindOfClass:[NSDictionary class]]) {
				for (NSString *bundleID in savedJBDict) {
					if (!jbEntries[bundleID]) {
						jbEntries[bundleID] = savedJBDict[bundleID];
						mergedEntries[bundleID] = savedJBDict[bundleID];
					}
				}
			}
		}

		BB_LOG("performInjectOnWrite(ClearedSections): writing %lu total entries (%lu are JB)", 
			(unsigned long)mergedEntries.count, (unsigned long)jbEntries.count);

		NSData *systemDataToWrite = [NSPropertyListSerialization dataWithPropertyList:mergedEntries format:format options:0 error:nil];
		if (systemDataToWrite) {
			writeOriginal(systemDataToWrite, path);
		} else {
			writeOriginal(data, path);
		}

		if (jbEntries.count > 0) {
			ensureJBBulletinBoardDir();
			NSData *jbDataToWrite = [NSPropertyListSerialization dataWithPropertyList:jbEntries format:format options:0 error:nil];
			if (jbDataToWrite) {
				[jbDataToWrite writeToFile:jbClearedSectionsPath() atomically:YES];
			}
		}
	}
}

static BOOL (*orig_NSData_writeToFile_atomically)(NSData *self, SEL _cmd, NSString *path, BOOL atomically);
static BOOL hook_NSData_writeToFile_atomically(NSData *self, SEL _cmd, NSString *path, BOOL atomically)
{
	if (gIsRouting || !path) {
		return orig_NSData_writeToFile_atomically(self, _cmd, path, atomically);
	}

	if (isBulletinBoardPlist(path) || isClearedSectionsPlist(path)) {
		gIsRouting = YES;
		__block BOOL result = YES;
		performInjectOnWrite(self, path,
			^BOOL(NSData *d, NSString *p) { result = orig_NSData_writeToFile_atomically(d, _cmd, p, atomically); return result; }
		);
		gIsRouting = NO;
		return result;
	}

	return orig_NSData_writeToFile_atomically(self, _cmd, path, atomically);
}

// Hook -writeToFile:options:error: (modern API, used on iOS 15/16)
static BOOL (*orig_NSData_writeToFile_options_error)(NSData *self, SEL _cmd, NSString *path, NSDataWritingOptions options, NSError **error);
static BOOL hook_NSData_writeToFile_options_error(NSData *self, SEL _cmd, NSString *path, NSDataWritingOptions options, NSError **error)
{
	if (gIsRouting || !path) {
		return orig_NSData_writeToFile_options_error(self, _cmd, path, options, error);
	}

	if (isBulletinBoardPlist(path) || isClearedSectionsPlist(path)) {
		gIsRouting = YES;
		__block BOOL result = YES;
		__block NSError *capturedError = nil;
		performInjectOnWrite(self, path,
			^BOOL(NSData *d, NSString *p) { result = orig_NSData_writeToFile_options_error(d, _cmd, p, options, &capturedError); return result; }
		);
		if (error) *error = capturedError;
		gIsRouting = NO;
		return result;
	}

	return orig_NSData_writeToFile_options_error(self, _cmd, path, options, error);
}

// ============================================================
// DIAGNOSTIC READ HOOKS: "Log Dragnet" to catch SpringBoard reads
// ============================================================

static id (*orig_NSDictionary_dictionaryWithContentsOfFile)(id self, SEL _cmd, NSString *path);
static id hook_NSDictionary_dictionaryWithContentsOfFile(id self, SEL _cmd, NSString *path) {
	if (path && [path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSDictionary dictionaryWithContentsOfFile:] - Path: %s", path.UTF8String);
	}
	return orig_NSDictionary_dictionaryWithContentsOfFile(self, _cmd, path);
}

static id (*orig_NSDictionary_dictionaryWithContentsOfURL)(id self, SEL _cmd, NSURL *url);
static id hook_NSDictionary_dictionaryWithContentsOfURL(id self, SEL _cmd, NSURL *url) {
	if (url.path && [url.path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSDictionary dictionaryWithContentsOfURL:] - URL: %s", url.absoluteString.UTF8String);
	}
	return orig_NSDictionary_dictionaryWithContentsOfURL(self, _cmd, url);
}

static id (*orig_NSDictionary_dictionaryWithContentsOfURLError)(id self, SEL _cmd, NSURL *url, NSError **error);
static id hook_NSDictionary_dictionaryWithContentsOfURLError(id self, SEL _cmd, NSURL *url, NSError **error) {
	if (url.path && [url.path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSDictionary dictionaryWithContentsOfURL:error:] - URL: %s", url.absoluteString.UTF8String);
	}
	return orig_NSDictionary_dictionaryWithContentsOfURLError(self, _cmd, url, error);
}

static id (*orig_NSArray_arrayWithContentsOfFile)(id self, SEL _cmd, NSString *path);
static id hook_NSArray_arrayWithContentsOfFile(id self, SEL _cmd, NSString *path) {
	if (path && [path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSArray arrayWithContentsOfFile:] - Path: %s", path.UTF8String);
	}
	return orig_NSArray_arrayWithContentsOfFile(self, _cmd, path);
}

static id (*orig_NSArray_arrayWithContentsOfURL)(id self, SEL _cmd, NSURL *url);
static id hook_NSArray_arrayWithContentsOfURL(id self, SEL _cmd, NSURL *url) {
	if (url.path && [url.path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSArray arrayWithContentsOfURL:] - URL: %s", url.absoluteString.UTF8String);
	}
	return orig_NSArray_arrayWithContentsOfURL(self, _cmd, url);
}

static id (*orig_NSArray_arrayWithContentsOfURLError)(id self, SEL _cmd, NSURL *url, NSError **error);
static id hook_NSArray_arrayWithContentsOfURLError(id self, SEL _cmd, NSURL *url, NSError **error) {
	if (url.path && [url.path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSArray arrayWithContentsOfURL:error:] - URL: %s", url.absoluteString.UTF8String);
	}
	return orig_NSArray_arrayWithContentsOfURLError(self, _cmd, url, error);
}

static id (*orig_NSData_dataWithContentsOfFile)(id self, SEL _cmd, NSString *path);
static id hook_NSData_dataWithContentsOfFile(id self, SEL _cmd, NSString *path) {
	if (path && [path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSData dataWithContentsOfFile:] - Path: %s", path.UTF8String);
	}
	return orig_NSData_dataWithContentsOfFile(self, _cmd, path);
}

static id (*orig_NSData_dataWithContentsOfURL)(id self, SEL _cmd, NSURL *url);
static id hook_NSData_dataWithContentsOfURL(id self, SEL _cmd, NSURL *url) {
	if (url.path && [url.path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSData dataWithContentsOfURL:] - URL: %s", url.absoluteString.UTF8String);
	}
	return orig_NSData_dataWithContentsOfURL(self, _cmd, url);
}

static id (*orig_NSData_dataWithContentsOfFileOptionsError)(id self, SEL _cmd, NSString *path, NSDataReadingOptions readOptionsMask, NSError **errorPtr);
static id hook_NSData_dataWithContentsOfFileOptionsError(id self, SEL _cmd, NSString *path, NSDataReadingOptions readOptionsMask, NSError **errorPtr) {
	if (path && [path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSData dataWithContentsOfFile:options:error:] - Path: %s", path.UTF8String);
	}
	return orig_NSData_dataWithContentsOfFileOptionsError(self, _cmd, path, readOptionsMask, errorPtr);
}

static id (*orig_NSData_dataWithContentsOfURLOptionsError)(id self, SEL _cmd, NSURL *url, NSDataReadingOptions readOptionsMask, NSError **errorPtr);
static id hook_NSData_dataWithContentsOfURLOptionsError(id self, SEL _cmd, NSURL *url, NSDataReadingOptions readOptionsMask, NSError **errorPtr) {
	if (url.path && [url.path containsString:@"VersionedSectionInfo.plist"]) {
		BB_LOG("[BOMBSHELL] Caught read via +[NSData dataWithContentsOfURL:options:error:] - URL: %s", url.absoluteString.UTF8String);
	}
	return orig_NSData_dataWithContentsOfURLOptionsError(self, _cmd, url, readOptionsMask, errorPtr);
}

void bulletinboarddInit(void)
{
	BB_LOG("bulletinboarddInit() called in process: %s (pid=%d)", getprogname(), getpid());
	ensureJBBulletinBoardDir();

	// Hook NSData -writeToFile:atomically: for write interception
	MSHookMessageEx(
		objc_getClass("NSData"),
		@selector(writeToFile:atomically:),
		(IMP)hook_NSData_writeToFile_atomically,
		(IMP *)&orig_NSData_writeToFile_atomically
	);

	// Hook NSData -writeToFile:options:error: (modern API on iOS 15/16)
	MSHookMessageEx(
		objc_getClass("NSData"),
		@selector(writeToFile:options:error:),
		(IMP)hook_NSData_writeToFile_options_error,
		(IMP *)&orig_NSData_writeToFile_options_error
	);

	// Diagnostic Hooks
	BB_LOG("bulletinboarddInit: Deploying diagnostic read hooks...");
	Class nsDictionaryClass = objc_getClass("NSDictionary");
	MSHookMessageEx(nsDictionaryClass, @selector(dictionaryWithContentsOfFile:), (IMP)hook_NSDictionary_dictionaryWithContentsOfFile, (IMP *)&orig_NSDictionary_dictionaryWithContentsOfFile);
	MSHookMessageEx(nsDictionaryClass, @selector(dictionaryWithContentsOfURL:), (IMP)hook_NSDictionary_dictionaryWithContentsOfURL, (IMP *)&orig_NSDictionary_dictionaryWithContentsOfURL);
	MSHookMessageEx(nsDictionaryClass, @selector(dictionaryWithContentsOfURL:error:), (IMP)hook_NSDictionary_dictionaryWithContentsOfURLError, (IMP *)&orig_NSDictionary_dictionaryWithContentsOfURLError);

	Class nsArrayClass = objc_getClass("NSArray");
	MSHookMessageEx(nsArrayClass, @selector(arrayWithContentsOfFile:), (IMP)hook_NSArray_arrayWithContentsOfFile, (IMP *)&orig_NSArray_arrayWithContentsOfFile);
	MSHookMessageEx(nsArrayClass, @selector(arrayWithContentsOfURL:), (IMP)hook_NSArray_arrayWithContentsOfURL, (IMP *)&orig_NSArray_arrayWithContentsOfURL);
	MSHookMessageEx(nsArrayClass, @selector(arrayWithContentsOfURL:error:), (IMP)hook_NSArray_arrayWithContentsOfURLError, (IMP *)&orig_NSArray_arrayWithContentsOfURLError);

	Class nsDataClass = objc_getClass("NSData");
	MSHookMessageEx(nsDataClass, @selector(dataWithContentsOfFile:), (IMP)hook_NSData_dataWithContentsOfFile, (IMP *)&orig_NSData_dataWithContentsOfFile);
	MSHookMessageEx(nsDataClass, @selector(dataWithContentsOfURL:), (IMP)hook_NSData_dataWithContentsOfURL, (IMP *)&orig_NSData_dataWithContentsOfURL);
	MSHookMessageEx(nsDataClass, @selector(dataWithContentsOfFile:options:error:), (IMP)hook_NSData_dataWithContentsOfFileOptionsError, (IMP *)&orig_NSData_dataWithContentsOfFileOptionsError);
	MSHookMessageEx(nsDataClass, @selector(dataWithContentsOfURL:options:error:), (IMP)hook_NSData_dataWithContentsOfURLOptionsError, (IMP *)&orig_NSData_dataWithContentsOfURLOptionsError);
}

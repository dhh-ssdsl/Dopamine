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
			BB_LOG("isJBBundleID(%s): bundlePath=%s -> %s",
				   bundleID.UTF8String, bundlePath.UTF8String, result ? "JB" : "system");
			return result;
		}
	}

	// Fallback: check if <jbroot>/Applications/<*.app>/Info.plist contains this bundle ID
	BB_LOG("isJBBundleID(%s): LSApplicationProxy unavailable or no bundlePath, using /Applications fallback", bundleID.UTF8String);
	NSString *jbAppsPath = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/Applications")];
	NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbAppsPath error:nil];
	for (NSString *item in contents) {
		if (![item hasSuffix:@".app"]) continue;
		NSString *appPath = [jbAppsPath stringByAppendingPathComponent:item];
		NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[appPath stringByAppendingPathComponent:@"Info.plist"]];
		if ([info[@"CFBundleIdentifier"] isEqualToString:bundleID]) {
			BB_LOG("isJBBundleID(%s): FOUND in /Applications fallback -> JB", bundleID.UTF8String);
			return YES;
		}
	}
	BB_LOG("isJBBundleID(%s): NOT FOUND in /Applications fallback -> system", bundleID.UTF8String);
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
	BB_LOG("ensureJBBulletinBoardDir: path=%s", dir.UTF8String);
	if (![[NSFileManager defaultManager] fileExistsAtPath:dir]) {
		NSError *error = nil;
		BOOL ok = [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&error];
		if (!ok) {
			BB_LOG("ERROR creating BulletinBoard dir: %s", error.localizedDescription.UTF8String);
		} else {
			BB_LOG("Created BulletinBoard dir OK");
		}
	} else {
		BB_LOG("BulletinBoard dir already exists");
	}
}

// ============================================================
// READ HOOK: When bulletinboardd reads the plist, merge JB entries in
// ============================================================

static NSData *(*orig_NSData_dataWithContentsOfFile)(id self, SEL _cmd, NSString *path);
static NSData *hook_NSData_dataWithContentsOfFile(id self, SEL _cmd, NSString *path)
{
	NSData *origData = orig_NSData_dataWithContentsOfFile(self, _cmd, path);

	if (gIsRouting || !path) return origData;

	if (isBulletinBoardPlist(path)) {
		BB_LOG("READ intercepted: %s", path.UTF8String);
		gIsRouting = YES;
		NSData *jbData = orig_NSData_dataWithContentsOfFile(self, _cmd, jbNotificationPlistPath());
		gIsRouting = NO;

		if (!jbData) return origData;

		NSError *error = nil;
		NSPropertyListFormat format = 0;
		NSMutableDictionary *merged = nil;

		if (origData) {
			merged = [[NSPropertyListSerialization propertyListWithData:origData options:NSPropertyListMutableContainersAndLeaves format:&format error:&error] mutableCopy];
		}
		if (!merged) {
			merged = [NSMutableDictionary dictionary];
			format = NSPropertyListBinaryFormat_v1_0;
		}

		// VersionedSectionInfo.plist structure:
		// { sectionInfo = { "com.bundle.id" = {...}; }; sectionInfoVersionNumber = N; }
		// Merge at the sectionInfo sub-dictionary level
		NSDictionary *jbDict = [NSPropertyListSerialization propertyListWithData:jbData options:0 format:NULL error:&error];
		if ([jbDict isKindOfClass:[NSDictionary class]]) {
			NSDictionary *jbSectionInfo = jbDict[@"sectionInfo"];
			if ([jbSectionInfo isKindOfClass:[NSDictionary class]]) {
				NSMutableDictionary *mergedSectionInfo = [merged[@"sectionInfo"] mutableCopy] ?: [NSMutableDictionary dictionary];
				[mergedSectionInfo addEntriesFromDictionary:jbSectionInfo];
				merged[@"sectionInfo"] = mergedSectionInfo;
				BB_LOG("READ: merged %lu JB sectionInfo entries", (unsigned long)jbSectionInfo.count);
			}
		}

		NSData *mergedData = [NSPropertyListSerialization dataWithPropertyList:merged format:format options:0 error:nil];
		return mergedData ?: origData;
	}

	if (isClearedSectionsPlist(path)) {
		BB_LOG("READ intercepted (ClearedSections): %s", path.UTF8String);
		gIsRouting = YES;
		NSData *jbData = orig_NSData_dataWithContentsOfFile(self, _cmd, jbClearedSectionsPath());
		gIsRouting = NO;

		if (!jbData) return origData;

		NSError *error = nil;
		NSPropertyListFormat format = 0;
		NSMutableDictionary *merged = nil;

		if (origData) {
			merged = [[NSPropertyListSerialization propertyListWithData:origData options:NSPropertyListMutableContainersAndLeaves format:&format error:&error] mutableCopy];
		}
		if (!merged) {
			merged = [NSMutableDictionary dictionary];
			format = NSPropertyListBinaryFormat_v1_0;
		}

		// ClearedSections.plist is a flat dict of bundleID->date, merge at top level
		NSDictionary *jbEntries = [NSPropertyListSerialization propertyListWithData:jbData options:0 format:NULL error:&error];
		if ([jbEntries isKindOfClass:[NSDictionary class]]) {
			[merged addEntriesFromDictionary:jbEntries];
		}

		NSData *mergedData = [NSPropertyListSerialization dataWithPropertyList:merged format:format options:0 error:nil];
		return mergedData ?: origData;
	}

	return origData;
}

// ============================================================
// WRITE HOOK: When SpringBoard writes the plist, split JB entries out
// Shared helper: split data into system/JB parts and write both
// ============================================================

static void performSplitWrite(NSData *data, NSString *path,
							  BOOL (^writeSystem)(NSData *d, NSString *p),
							  BOOL (^writeJB)(NSData *d, NSString *p))
{
	NSError *error = nil;
	NSPropertyListFormat format = 0;
	NSDictionary *fullDict = [NSPropertyListSerialization propertyListWithData:data options:0 format:&format error:&error];
	if (![fullDict isKindOfClass:[NSDictionary class]]) {
		BB_LOG("performSplitWrite: failed to parse plist, writing to system path as-is");
		writeSystem(data, path);
		return;
	}

	// VersionedSectionInfo.plist structure:
	// { sectionInfo = { "com.bundle.id" = {...}; }; sectionInfoVersionNumber = N; }
	// Bundle IDs are NESTED inside the sectionInfo sub-dictionary, not at the top level.
	// We must split at the sectionInfo sub-dict level.
	if (isBulletinBoardPlist(path)) {
		NSDictionary *sectionInfoDict = fullDict[@"sectionInfo"];
		if (![sectionInfoDict isKindOfClass:[NSDictionary class]]) {
			// No sectionInfo key — write as-is to system
			BB_LOG("performSplitWrite: no sectionInfo key, writing as-is");
			writeSystem(data, path);
			return;
		}

		NSMutableDictionary *systemSectionInfo = [NSMutableDictionary dictionary];
		NSMutableDictionary *jbSectionInfo = [NSMutableDictionary dictionary];

		for (NSString *bundleID in sectionInfoDict) {
			if (isJBBundleID(bundleID)) {
				jbSectionInfo[bundleID] = sectionInfoDict[bundleID];
			} else {
				systemSectionInfo[bundleID] = sectionInfoDict[bundleID];
			}
		}

		BB_LOG("performSplitWrite: %lu system sectionInfo entries, %lu JB sectionInfo entries",
			   (unsigned long)systemSectionInfo.count, (unsigned long)jbSectionInfo.count);

		// Build system plist: all top-level keys intact, but sectionInfo only has system entries
		NSMutableDictionary *systemDict = [fullDict mutableCopy];
		systemDict[@"sectionInfo"] = systemSectionInfo;
		NSData *systemData = [NSPropertyListSerialization dataWithPropertyList:systemDict format:format options:0 error:nil];
		if (systemData) writeSystem(systemData, path);

		// Build JB plist: same top-level structure but sectionInfo only has JB entries
		if (jbSectionInfo.count) {
			ensureJBBulletinBoardDir();
			NSMutableDictionary *jbDict = [fullDict mutableCopy];
			jbDict[@"sectionInfo"] = jbSectionInfo;
			NSData *jbData = [NSPropertyListSerialization dataWithPropertyList:jbDict format:format options:0 error:nil];
			if (jbData) {
				BOOL ok = writeJB(jbData, jbNotificationPlistPath());
				BB_LOG("performSplitWrite: JB plist write %s", ok ? "OK" : "FAILED");
			}
		}
		return;
	}

	// ClearedSections.plist: flat dict of bundleID -> timestamp, split at top level
	NSMutableDictionary *systemEntries = [NSMutableDictionary dictionary];
	NSMutableDictionary *jbEntries = [NSMutableDictionary dictionary];

	for (NSString *key in fullDict) {
		if (isJBBundleID(key)) {
			jbEntries[key] = fullDict[key];
		} else {
			systemEntries[key] = fullDict[key];
		}
	}

	BB_LOG("performSplitWrite(ClearedSections): %lu system, %lu JB",
		   (unsigned long)systemEntries.count, (unsigned long)jbEntries.count);

	NSData *systemData = [NSPropertyListSerialization dataWithPropertyList:systemEntries format:format options:0 error:nil];
	if (systemData) writeSystem(systemData, path);

	if (jbEntries.count) {
		ensureJBBulletinBoardDir();
		NSData *jbData = [NSPropertyListSerialization dataWithPropertyList:jbEntries format:format options:0 error:nil];
		if (jbData) {
			BOOL ok = writeJB(jbData, jbClearedSectionsPath());
			BB_LOG("performSplitWrite(ClearedSections): JB write %s", ok ? "OK" : "FAILED");
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
		BB_LOG("WRITE(atomically) intercepted: %s", path.UTF8String);
		gIsRouting = YES;
		__block BOOL result = YES;
		performSplitWrite(self, path,
			^BOOL(NSData *d, NSString *p) { result = orig_NSData_writeToFile_atomically(d, _cmd, p, atomically); return result; },
			^BOOL(NSData *d, NSString *p) { return orig_NSData_writeToFile_atomically(d, _cmd, p, atomically); }
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
		BB_LOG("WRITE(options:error:) intercepted: %s", path.UTF8String);
		gIsRouting = YES;
		__block BOOL result = YES;
		__block NSError *capturedError = nil;
		performSplitWrite(self, path,
			^BOOL(NSData *d, NSString *p) { result = orig_NSData_writeToFile_options_error(d, _cmd, p, options, &capturedError); return result; },
			^BOOL(NSData *d, NSString *p) { return orig_NSData_writeToFile_options_error(d, _cmd, p, options, nil); }
		);
		if (error) *error = capturedError;
		gIsRouting = NO;
		return result;
	}

	return orig_NSData_writeToFile_options_error(self, _cmd, path, options, error);
}

// Hook +dataWithContentsOfFile:options:error: (modern read API)
static NSData *(*orig_NSData_dataWithContentsOfFile_options_error)(id self, SEL _cmd, NSString *path, NSDataReadingOptions options, NSError **error);
static NSData *hook_NSData_dataWithContentsOfFile_options_error(id self, SEL _cmd, NSString *path, NSDataReadingOptions options, NSError **error)
{
	NSData *origData = orig_NSData_dataWithContentsOfFile_options_error(self, _cmd, path, options, error);
	if (gIsRouting || !path) return origData;

	if (isBulletinBoardPlist(path)) {
		BB_LOG("READ(options:error:) intercepted: %s", path.UTF8String);
		gIsRouting = YES;
		NSData *jbData = orig_NSData_dataWithContentsOfFile_options_error(self, _cmd, jbNotificationPlistPath(), options, nil);
		gIsRouting = NO;
		if (!jbData) return origData;

		NSError *mergeError = nil;
		NSPropertyListFormat format = 0;
		NSMutableDictionary *merged = origData
			? [[NSPropertyListSerialization propertyListWithData:origData options:NSPropertyListMutableContainersAndLeaves format:&format error:&mergeError] mutableCopy]
			: [NSMutableDictionary dictionary];
		if (!merged) { merged = [NSMutableDictionary dictionary]; format = NSPropertyListBinaryFormat_v1_0; }

		// Merge at sectionInfo sub-dictionary level
		NSDictionary *jbDict = [NSPropertyListSerialization propertyListWithData:jbData options:0 format:NULL error:&mergeError];
		if ([jbDict isKindOfClass:[NSDictionary class]]) {
			NSDictionary *jbSectionInfo = jbDict[@"sectionInfo"];
			if ([jbSectionInfo isKindOfClass:[NSDictionary class]]) {
				NSMutableDictionary *mergedSectionInfo = [merged[@"sectionInfo"] mutableCopy] ?: [NSMutableDictionary dictionary];
				[mergedSectionInfo addEntriesFromDictionary:jbSectionInfo];
				merged[@"sectionInfo"] = mergedSectionInfo;
				BB_LOG("READ(options:error:): merged %lu JB sectionInfo entries, total sectionInfo now %lu",
				       (unsigned long)jbSectionInfo.count, (unsigned long)mergedSectionInfo.count);
			} else {
				BB_LOG("READ(options:error:): JB plist has no sectionInfo sub-dict");
			}
		} else {
			BB_LOG("READ(options:error:): failed to parse JB plist (error=%s)",
			       mergeError.localizedDescription.UTF8String ?: "unknown");
		}
		NSData *mergedData = [NSPropertyListSerialization dataWithPropertyList:merged format:format options:0 error:nil];
		return mergedData ?: origData;
	}

	if (isClearedSectionsPlist(path)) {
		BB_LOG("READ(ClearedSections options:error:) intercepted: %s", path.UTF8String);
		gIsRouting = YES;
		NSData *jbData = orig_NSData_dataWithContentsOfFile_options_error(self, _cmd, jbClearedSectionsPath(), options, nil);
		gIsRouting = NO;
		if (!jbData) return origData;

		NSError *mergeError = nil;
		NSPropertyListFormat format = 0;
		NSMutableDictionary *merged = origData
			? [[NSPropertyListSerialization propertyListWithData:origData options:NSPropertyListMutableContainersAndLeaves format:&format error:&mergeError] mutableCopy]
			: [NSMutableDictionary dictionary];
		if (!merged) { merged = [NSMutableDictionary dictionary]; format = NSPropertyListBinaryFormat_v1_0; }
		NSDictionary *jbEntries = [NSPropertyListSerialization propertyListWithData:jbData options:0 format:NULL error:&mergeError];
		if ([jbEntries isKindOfClass:[NSDictionary class]]) [merged addEntriesFromDictionary:jbEntries];
		NSData *mergedData = [NSPropertyListSerialization dataWithPropertyList:merged format:format options:0 error:nil];
		return mergedData ?: origData;
	}

	return origData;
}

void bulletinboarddInit(void)
{
	BB_LOG("bulletinboarddInit() called in process: %s (pid=%d)", getprogname(), getpid());
	ensureJBBulletinBoardDir();

	// Hook NSData +dataWithContentsOfFile: for read interception
	MSHookMessageEx(
		objc_getClass("NSData"),
		@selector(dataWithContentsOfFile:),
		(IMP)hook_NSData_dataWithContentsOfFile,
		(IMP *)&orig_NSData_dataWithContentsOfFile
	);

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

	// Hook NSData +dataWithContentsOfFile:options:error: (modern read API)
	MSHookMessageEx(
		objc_getMetaClass("NSData"),
		@selector(dataWithContentsOfFile:options:error:),
		(IMP)hook_NSData_dataWithContentsOfFile_options_error,
		(IMP *)&orig_NSData_dataWithContentsOfFile_options_error
	);
}

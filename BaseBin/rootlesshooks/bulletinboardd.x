#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>
#import <objc/runtime.h>

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

static NSSet<NSString *> *gJailbreakBundleIDs = nil;
static time_t gLastBundleRefresh = 0;
static __thread BOOL gIsRouting; // Thread-local: prevent recursive hooks per-thread

static void refreshJBBundleIDs(void)
{
	NSMutableSet *bundleIDs = [NSMutableSet set];
	NSString *jbAppsPath = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/Applications")];
	NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbAppsPath error:nil];
	for (NSString *item in contents) {
		if (![item hasSuffix:@".app"]) continue;
		NSString *appPath = [jbAppsPath stringByAppendingPathComponent:item];
		NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[appPath stringByAppendingPathComponent:@"Info.plist"]];
		NSString *bundleID = info[@"CFBundleIdentifier"];
		if (bundleID) {
			[bundleIDs addObject:bundleID];
		}
	}
	gJailbreakBundleIDs = [bundleIDs copy];
	gLastBundleRefresh = time(NULL);
}

static void refreshJBBundleIDsIfNeeded(void)
{
	time_t now = time(NULL);
	if (!gJailbreakBundleIDs || (now - gLastBundleRefresh) >= 10) {
		refreshJBBundleIDs();
	}
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
		refreshJBBundleIDsIfNeeded();

		// Read JB notification plist
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

		NSDictionary *jbEntries = [NSPropertyListSerialization propertyListWithData:jbData options:0 format:NULL error:&error];
		if ([jbEntries isKindOfClass:[NSDictionary class]]) {
			[merged addEntriesFromDictionary:jbEntries];
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
	// Always force-refresh on writes (writes are rare, never use stale cache here)
	refreshJBBundleIDs();

	NSError *error = nil;
	NSPropertyListFormat format = 0;
	NSDictionary *fullDict = [NSPropertyListSerialization propertyListWithData:data options:0 format:&format error:&error];
	if (![fullDict isKindOfClass:[NSDictionary class]]) {
		BB_LOG("performSplitWrite: failed to parse plist, writing to system path as-is");
		writeSystem(data, path);
		return;
	}

	// If no JB bundle IDs are known yet (e.g. mid-boot), write system data
	// to system path but do NOT overwrite the JB plist — leave it intact.
	if (!gJailbreakBundleIDs.count) {
		BB_LOG("performSplitWrite: JB bundle ID set empty, writing all to system path (JB plist preserved)");
		writeSystem(data, path);
		return;
	}

	NSMutableDictionary *systemEntries = [NSMutableDictionary dictionary];
	NSMutableDictionary *jbEntries = [NSMutableDictionary dictionary];
	for (NSString *key in fullDict) {
		if ([gJailbreakBundleIDs containsObject:key]) {
			jbEntries[key] = fullDict[key];
		} else {
			systemEntries[key] = fullDict[key];
		}
	}

	BB_LOG("performSplitWrite: %lu system entries, %lu JB entries",
		   (unsigned long)systemEntries.count, (unsigned long)jbEntries.count);

	NSData *systemData = [NSPropertyListSerialization dataWithPropertyList:systemEntries format:format options:0 error:nil];
	if (systemData) writeSystem(systemData, path);

	if (jbEntries.count) {
		ensureJBBulletinBoardDir();
		NSString *jbPath = isBulletinBoardPlist(path) ? jbNotificationPlistPath() : jbClearedSectionsPath();
		NSData *jbData = [NSPropertyListSerialization dataWithPropertyList:jbEntries format:format options:0 error:nil];
		if (jbData) {
			BOOL ok = writeJB(jbData, jbPath);
			BB_LOG("performSplitWrite: JB plist write to %s %s",
				   jbPath.UTF8String, ok ? "OK" : "FAILED");
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
		NSDictionary *jbEntries = [NSPropertyListSerialization propertyListWithData:jbData options:0 format:NULL error:&mergeError];
		if ([jbEntries isKindOfClass:[NSDictionary class]]) [merged addEntriesFromDictionary:jbEntries];
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
	refreshJBBundleIDs();
	BB_LOG("Found %lu JB bundle IDs", (unsigned long)gJailbreakBundleIDs.count);
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

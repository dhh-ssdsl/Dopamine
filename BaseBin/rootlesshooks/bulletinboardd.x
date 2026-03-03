#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>

static void _bb_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _bb_log(const char *fmt, ...) {
	FILE *f = fopen(JBROOT_PATH_CSTRING("/basebin/hook_debug.log"), "a");
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
static BOOL gIsRouting = NO; // Prevent recursive hooks

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
// WRITE HOOK: When bulletinboardd writes the plist, split JB entries out
// ============================================================

static BOOL (*orig_NSData_writeToFile_atomically)(NSData *self, SEL _cmd, NSString *path, BOOL atomically);
static BOOL hook_NSData_writeToFile_atomically(NSData *self, SEL _cmd, NSString *path, BOOL atomically)
{
	if (gIsRouting || !path) {
		return orig_NSData_writeToFile_atomically(self, _cmd, path, atomically);
	}

	if (isBulletinBoardPlist(path) || isClearedSectionsPlist(path)) {
		BB_LOG("WRITE intercepted: %s", path.UTF8String);
		gIsRouting = YES;
		refreshJBBundleIDsIfNeeded();

		NSError *error = nil;
		NSPropertyListFormat format = 0;
		NSDictionary *fullDict = [NSPropertyListSerialization propertyListWithData:self options:0 format:&format error:&error];

		if (![fullDict isKindOfClass:[NSDictionary class]] || !gJailbreakBundleIDs.count) {
			gIsRouting = NO;
			return orig_NSData_writeToFile_atomically(self, _cmd, path, atomically);
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

		// Write system entries to original path
		NSData *systemData = [NSPropertyListSerialization dataWithPropertyList:systemEntries format:format options:0 error:nil];
		BOOL result = YES;
		if (systemData) {
			result = orig_NSData_writeToFile_atomically(systemData, _cmd, path, atomically);
		}

		// Write JB entries to jbroot path
		if (jbEntries.count) {
			ensureJBBulletinBoardDir();
			NSString *jbPath = isBulletinBoardPlist(path) ? jbNotificationPlistPath() : jbClearedSectionsPath();
			NSData *jbData = [NSPropertyListSerialization dataWithPropertyList:jbEntries format:format options:0 error:nil];
			if (jbData) {
				orig_NSData_writeToFile_atomically(jbData, _cmd, jbPath, atomically);
			}
		}

		gIsRouting = NO;
		return result;
	}

	return orig_NSData_writeToFile_atomically(self, _cmd, path, atomically);
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
}

#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>
#import <objc/runtime.h>
#import "perm_router.h"

static void _bb_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _bb_log(const char *fmt, ...)
{
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

static __thread BOOL gIsRouting;

static BOOL isJBBundleID(NSString *bundleID)
{
	return perm_is_jailbreak_bundle_id(bundleID);
}

static NSString *jbNotificationPlistPath(void)
{
	static NSString *path = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		path = perm_jb_mirror_path_ns(kSectionInfoPath);
	});
	return path;
}

static NSString *jbClearedSectionsPath(void)
{
	static NSString *path = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		path = perm_jb_mirror_path_ns(kClearedSectionsPath);
	});
	return path;
}

static BOOL isSystemSectionInfoPlist(NSString *path)
{
	if (!path.length || perm_is_path_under_jbroot(path)) return NO;
	return [path isEqualToString:kSectionInfoPath] || [path hasSuffix:@"/VersionedSectionInfo.plist"];
}

static BOOL isSystemClearedSectionsPlist(NSString *path)
{
	if (!path.length || perm_is_path_under_jbroot(path)) return NO;
	return [path isEqualToString:kClearedSectionsPath] || [path hasSuffix:@"/ClearedSections.plist"];
}

static void ensureJBBulletinBoardDir(void)
{
	perm_ensure_parent_dir_for_path(jbNotificationPlistPath());
	perm_ensure_parent_dir_for_path(jbClearedSectionsPath());
}

static NSData *serializePlist(id plistObj, NSPropertyListFormat format)
{
	return [NSPropertyListSerialization dataWithPropertyList:plistObj format:format options:0 error:nil];
}

static NSDictionary *loadPlistDict(NSString *path)
{
	if (!path.length) return nil;
	NSData *data = [NSData dataWithContentsOfFile:path];
	if (!data) return nil;
	id obj = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
	return [obj isKindOfClass:[NSDictionary class]] ? obj : nil;
}

static void splitSectionInfoByBundle(NSDictionary *sectionInfo, NSMutableDictionary *systemOut, NSMutableDictionary *jbOut)
{
	for (NSString *bundleID in sectionInfo) {
		id value = sectionInfo[bundleID];
		if (isJBBundleID(bundleID)) {
			jbOut[bundleID] = value;
		} else {
			systemOut[bundleID] = value;
		}
	}
}

static void splitClearedSectionsByBundle(NSDictionary *cleared, NSMutableDictionary *systemOut, NSMutableDictionary *jbOut)
{
	for (NSString *bundleID in cleared) {
		id value = cleared[bundleID];
		if (isJBBundleID(bundleID)) {
			jbOut[bundleID] = value;
		} else {
			systemOut[bundleID] = value;
		}
	}
}

static void performSplitOnWrite(NSData *data, NSString *path, BOOL (^writeOriginal)(NSData *d, NSString *p))
{
	NSError *error = nil;
	NSPropertyListFormat format = 0;
	id plistObj = [NSPropertyListSerialization propertyListWithData:data options:0 format:&format error:&error];
	if (!plistObj || error) {
		writeOriginal(data, path);
		return;
	}

	if (isSystemSectionInfoPlist(path) && [plistObj isKindOfClass:[NSDictionary class]]) {
		NSDictionary *fullDict = (NSDictionary *)plistObj;
		NSDictionary *sectionInfo = fullDict[@"sectionInfo"];
		if (![sectionInfo isKindOfClass:[NSDictionary class]]) {
			writeOriginal(data, path);
			return;
		}

		NSMutableDictionary *systemSection = [NSMutableDictionary dictionary];
		NSMutableDictionary *jbSection = [NSMutableDictionary dictionary];
		splitSectionInfoByBundle(sectionInfo, systemSection, jbSection);

		NSMutableDictionary *systemWriteDict = [fullDict mutableCopy];
		systemWriteDict[@"sectionInfo"] = systemSection;
		NSData *systemWriteData = serializePlist(systemWriteDict, format);
		if (systemWriteData) {
			writeOriginal(systemWriteData, path);
		} else {
			writeOriginal(data, path);
		}

		if (jbSection.count) {
			ensureJBBulletinBoardDir();
			NSMutableDictionary *jbWriteDict = [fullDict mutableCopy];
			jbWriteDict[@"sectionInfo"] = jbSection;
			NSData *jbData = serializePlist(jbWriteDict, format);
			if (jbData) {
				[jbData writeToFile:jbNotificationPlistPath() atomically:YES];
			}
		} else {
			// Startup races can produce a transient jb=0 write; keep last JB mirror instead of deleting it.
			if ([[NSFileManager defaultManager] fileExistsAtPath:jbNotificationPlistPath()]) {
				BB_LOG("write split (VersionedSectionInfo): jb=0, keep existing JB mirror");
			}
		}

		BB_LOG("write split (VersionedSectionInfo): system=%lu jb=%lu",
		       (unsigned long)systemSection.count, (unsigned long)jbSection.count);
		return;
	}

	if (isSystemClearedSectionsPlist(path) && [plistObj isKindOfClass:[NSDictionary class]]) {
		NSDictionary *fullDict = (NSDictionary *)plistObj;
		NSMutableDictionary *systemEntries = [NSMutableDictionary dictionary];
		NSMutableDictionary *jbEntries = [NSMutableDictionary dictionary];
		splitClearedSectionsByBundle(fullDict, systemEntries, jbEntries);

		NSData *systemWriteData = serializePlist(systemEntries, format);
		if (systemWriteData) {
			writeOriginal(systemWriteData, path);
		} else {
			writeOriginal(data, path);
		}

		if (jbEntries.count) {
			ensureJBBulletinBoardDir();
			NSData *jbData = serializePlist(jbEntries, format);
			if (jbData) [jbData writeToFile:jbClearedSectionsPath() atomically:YES];
		} else {
			if ([[NSFileManager defaultManager] fileExistsAtPath:jbClearedSectionsPath()]) {
				BB_LOG("write split (ClearedSections): jb=0, keep existing JB mirror");
			}
		}

		BB_LOG("write split (ClearedSections): system=%lu jb=%lu",
		       (unsigned long)systemEntries.count, (unsigned long)jbEntries.count);
		return;
	}

	writeOriginal(data, path);
}

static id mergeReadObjectForPath(id systemObj, NSString *path)
{
	if (isSystemSectionInfoPlist(path) && [systemObj isKindOfClass:[NSDictionary class]]) {
		NSDictionary *systemDict = (NSDictionary *)systemObj;
		NSDictionary *systemSection = systemDict[@"sectionInfo"];
		if (![systemSection isKindOfClass:[NSDictionary class]]) return systemObj;

		NSDictionary *jbDict = loadPlistDict(jbNotificationPlistPath());
		NSDictionary *jbSection = jbDict[@"sectionInfo"];
		if (![jbSection isKindOfClass:[NSDictionary class]] || jbSection.count == 0) return systemObj;

		NSMutableDictionary *mergedSection = [systemSection mutableCopy];
		[mergedSection addEntriesFromDictionary:jbSection]; // JB override

		NSMutableDictionary *mergedDict = [systemDict mutableCopy];
		mergedDict[@"sectionInfo"] = mergedSection;
		return mergedDict;
	}

	if (isSystemClearedSectionsPlist(path) && [systemObj isKindOfClass:[NSDictionary class]]) {
		NSDictionary *jbDict = loadPlistDict(jbClearedSectionsPath());
		if (![jbDict isKindOfClass:[NSDictionary class]] || jbDict.count == 0) return systemObj;

		NSMutableDictionary *merged = [(NSDictionary *)systemObj mutableCopy];
		[merged addEntriesFromDictionary:jbDict]; // JB override
		return merged;
	}

	return systemObj;
}

static NSData *mergeReadDataForPath(NSData *systemData, NSString *path)
{
	if (!systemData.length) return systemData;

	NSPropertyListFormat format = 0;
	id systemObj = [NSPropertyListSerialization propertyListWithData:systemData options:0 format:&format error:nil];
	if (!systemObj) return systemData;

	id mergedObj = mergeReadObjectForPath(systemObj, path);
	if (mergedObj == systemObj) return systemData;

	NSData *mergedData = serializePlist(mergedObj, format);
	return mergedData ?: systemData;
}

static void migrateBulletinBoardIfNeeded(void)
{
	if (perm_migration_is_done(@"bulletinboard")) return;

	NSDictionary *sectionDict = loadPlistDict(kSectionInfoPath);
	if ([sectionDict isKindOfClass:[NSDictionary class]]) {
		NSDictionary *sectionInfo = sectionDict[@"sectionInfo"];
		if ([sectionInfo isKindOfClass:[NSDictionary class]]) {
			NSMutableDictionary *systemSection = [NSMutableDictionary dictionary];
			NSMutableDictionary *jbSection = [NSMutableDictionary dictionary];
			splitSectionInfoByBundle(sectionInfo, systemSection, jbSection);

			if (jbSection.count) {
				ensureJBBulletinBoardDir();
				NSMutableDictionary *jbWriteDict = [sectionDict mutableCopy];
				jbWriteDict[@"sectionInfo"] = jbSection;
				NSData *jbData = serializePlist(jbWriteDict, NSPropertyListXMLFormat_v1_0);
				if (jbData) [jbData writeToFile:jbNotificationPlistPath() atomically:YES];

				NSMutableDictionary *sysWriteDict = [sectionDict mutableCopy];
				sysWriteDict[@"sectionInfo"] = systemSection;
				NSData *sysData = serializePlist(sysWriteDict, NSPropertyListXMLFormat_v1_0);
				if (sysData) [sysData writeToFile:kSectionInfoPath atomically:YES];

				BB_LOG("migrate VersionedSectionInfo: moved %lu JB entries", (unsigned long)jbSection.count);
			}
		}
	}

	NSDictionary *clearedDict = loadPlistDict(kClearedSectionsPath);
	if ([clearedDict isKindOfClass:[NSDictionary class]]) {
		NSMutableDictionary *systemEntries = [NSMutableDictionary dictionary];
		NSMutableDictionary *jbEntries = [NSMutableDictionary dictionary];
		splitClearedSectionsByBundle(clearedDict, systemEntries, jbEntries);

		if (jbEntries.count) {
			ensureJBBulletinBoardDir();
			NSData *jbData = serializePlist(jbEntries, NSPropertyListXMLFormat_v1_0);
			if (jbData) [jbData writeToFile:jbClearedSectionsPath() atomically:YES];
			NSData *sysData = serializePlist(systemEntries, NSPropertyListXMLFormat_v1_0);
			if (sysData) [sysData writeToFile:kClearedSectionsPath atomically:YES];
			BB_LOG("migrate ClearedSections: moved %lu JB entries", (unsigned long)jbEntries.count);
		}
	}

	perm_migration_mark_done(@"bulletinboard");
}

static BOOL (*orig_NSData_writeToFile_atomically)(NSData *self, SEL _cmd, NSString *path, BOOL atomically);
static BOOL hook_NSData_writeToFile_atomically(NSData *self, SEL _cmd, NSString *path, BOOL atomically)
{
	if (gIsRouting || !path) {
		return orig_NSData_writeToFile_atomically(self, _cmd, path, atomically);
	}

	if (isSystemSectionInfoPlist(path) || isSystemClearedSectionsPlist(path)) {
		gIsRouting = YES;
		__block BOOL result = YES;
		performSplitOnWrite(self, path,
			^BOOL(NSData *d, NSString *p) { result = orig_NSData_writeToFile_atomically(d, _cmd, p, atomically); return result; });
		gIsRouting = NO;
		return result;
	}

	return orig_NSData_writeToFile_atomically(self, _cmd, path, atomically);
}

static BOOL (*orig_NSData_writeToFile_options_error)(NSData *self, SEL _cmd, NSString *path, NSDataWritingOptions options, NSError **error);
static BOOL hook_NSData_writeToFile_options_error(NSData *self, SEL _cmd, NSString *path, NSDataWritingOptions options, NSError **error)
{
	if (gIsRouting || !path) {
		return orig_NSData_writeToFile_options_error(self, _cmd, path, options, error);
	}

	if (isSystemSectionInfoPlist(path) || isSystemClearedSectionsPlist(path)) {
		gIsRouting = YES;
		__block BOOL result = YES;
		__block NSError *capturedError = nil;
		performSplitOnWrite(self, path,
			^BOOL(NSData *d, NSString *p) { result = orig_NSData_writeToFile_options_error(d, _cmd, p, options, &capturedError); return result; });
		if (error) *error = capturedError;
		gIsRouting = NO;
		return result;
	}

	return orig_NSData_writeToFile_options_error(self, _cmd, path, options, error);
}

static id (*orig_NSDictionary_dictionaryWithContentsOfFile)(id self, SEL _cmd, NSString *path);
static id hook_NSDictionary_dictionaryWithContentsOfFile(id self, SEL _cmd, NSString *path)
{
	id obj = orig_NSDictionary_dictionaryWithContentsOfFile(self, _cmd, path);
	return mergeReadObjectForPath(obj, path);
}

static id (*orig_NSDictionary_dictionaryWithContentsOfURL)(id self, SEL _cmd, NSURL *url);
static id hook_NSDictionary_dictionaryWithContentsOfURL(id self, SEL _cmd, NSURL *url)
{
	id obj = orig_NSDictionary_dictionaryWithContentsOfURL(self, _cmd, url);
	return mergeReadObjectForPath(obj, url.path);
}

static id (*orig_NSDictionary_dictionaryWithContentsOfURLError)(id self, SEL _cmd, NSURL *url, NSError **error);
static id hook_NSDictionary_dictionaryWithContentsOfURLError(id self, SEL _cmd, NSURL *url, NSError **error)
{
	id obj = orig_NSDictionary_dictionaryWithContentsOfURLError(self, _cmd, url, error);
	return mergeReadObjectForPath(obj, url.path);
}

static id (*orig_NSData_dataWithContentsOfFile)(id self, SEL _cmd, NSString *path);
static id hook_NSData_dataWithContentsOfFile(id self, SEL _cmd, NSString *path)
{
	NSData *data = orig_NSData_dataWithContentsOfFile(self, _cmd, path);
	return mergeReadDataForPath(data, path);
}

static id (*orig_NSData_dataWithContentsOfURL)(id self, SEL _cmd, NSURL *url);
static id hook_NSData_dataWithContentsOfURL(id self, SEL _cmd, NSURL *url)
{
	NSData *data = orig_NSData_dataWithContentsOfURL(self, _cmd, url);
	return mergeReadDataForPath(data, url.path);
}

static id (*orig_NSData_dataWithContentsOfFileOptionsError)(id self, SEL _cmd, NSString *path, NSDataReadingOptions readOptionsMask, NSError **errorPtr);
static id hook_NSData_dataWithContentsOfFileOptionsError(id self, SEL _cmd, NSString *path, NSDataReadingOptions readOptionsMask, NSError **errorPtr)
{
	NSData *data = orig_NSData_dataWithContentsOfFileOptionsError(self, _cmd, path, readOptionsMask, errorPtr);
	return mergeReadDataForPath(data, path);
}

static id (*orig_NSData_dataWithContentsOfURLOptionsError)(id self, SEL _cmd, NSURL *url, NSDataReadingOptions readOptionsMask, NSError **errorPtr);
static id hook_NSData_dataWithContentsOfURLOptionsError(id self, SEL _cmd, NSURL *url, NSDataReadingOptions readOptionsMask, NSError **errorPtr)
{
	NSData *data = orig_NSData_dataWithContentsOfURLOptionsError(self, _cmd, url, readOptionsMask, errorPtr);
	return mergeReadDataForPath(data, url.path);
}

void bulletinboarddInit(void)
{
	BB_LOG("bulletinboardInit() called in SpringBoard process: %s (pid=%d)", getprogname(), getpid());
	ensureJBBulletinBoardDir();
	migrateBulletinBoardIfNeeded();

	MSHookMessageEx(objc_getClass("NSData"),
	                @selector(writeToFile:atomically:),
	                (IMP)hook_NSData_writeToFile_atomically,
	                (IMP *)&orig_NSData_writeToFile_atomically);

	MSHookMessageEx(objc_getClass("NSData"),
	                @selector(writeToFile:options:error:),
	                (IMP)hook_NSData_writeToFile_options_error,
	                (IMP *)&orig_NSData_writeToFile_options_error);

	Class nsDictionaryClass = objc_getClass("NSDictionary");
	MSHookMessageEx(nsDictionaryClass, @selector(dictionaryWithContentsOfFile:), (IMP)hook_NSDictionary_dictionaryWithContentsOfFile, (IMP *)&orig_NSDictionary_dictionaryWithContentsOfFile);
	MSHookMessageEx(nsDictionaryClass, @selector(dictionaryWithContentsOfURL:), (IMP)hook_NSDictionary_dictionaryWithContentsOfURL, (IMP *)&orig_NSDictionary_dictionaryWithContentsOfURL);
	MSHookMessageEx(nsDictionaryClass, @selector(dictionaryWithContentsOfURL:error:), (IMP)hook_NSDictionary_dictionaryWithContentsOfURLError, (IMP *)&orig_NSDictionary_dictionaryWithContentsOfURLError);

	Class nsDataClass = objc_getClass("NSData");
	MSHookMessageEx(nsDataClass, @selector(dataWithContentsOfFile:), (IMP)hook_NSData_dataWithContentsOfFile, (IMP *)&orig_NSData_dataWithContentsOfFile);
	MSHookMessageEx(nsDataClass, @selector(dataWithContentsOfURL:), (IMP)hook_NSData_dataWithContentsOfURL, (IMP *)&orig_NSData_dataWithContentsOfURL);
	MSHookMessageEx(nsDataClass, @selector(dataWithContentsOfFile:options:error:), (IMP)hook_NSData_dataWithContentsOfFileOptionsError, (IMP *)&orig_NSData_dataWithContentsOfFileOptionsError);
	MSHookMessageEx(nsDataClass, @selector(dataWithContentsOfURL:options:error:), (IMP)hook_NSData_dataWithContentsOfURLOptionsError, (IMP *)&orig_NSData_dataWithContentsOfURLOptionsError);

	BB_LOG("bulletinboardInit: hooks installed");
}

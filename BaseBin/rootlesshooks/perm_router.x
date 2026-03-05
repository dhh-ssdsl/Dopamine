#import "perm_router.h"
#import <libroot.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <string.h>

static NSString *perm_normalize_prefix(NSString *prefix)
{
	if (!prefix.length) return nil;
	if ([prefix isEqualToString:@"/"]) return prefix;
	while (prefix.length > 1 && [prefix hasSuffix:@"/"]) {
		prefix = [prefix substringToIndex:prefix.length - 1];
	}
	return prefix;
}

static NSString *perm_normalize_system_path(NSString *systemPath)
{
	if (!systemPath.length) return systemPath;

	// iOS often reports the same path as either /var/... or /private/var/...
	// Mirror routing should treat them as the same system location.
	static NSString *privateVarPrefix = @"/private/var/";
	if ([systemPath hasPrefix:privateVarPrefix]) {
		return [@"/var/" stringByAppendingString:[systemPath substringFromIndex:privateVarPrefix.length]];
	}

	return systemPath;
}

NSString *perm_jb_root_prefix_ns(void)
{
	static NSString *prefix = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		NSString *resolved = nil;

#ifdef JBROOT_PATH_NSSTRING
		resolved = JBROOT_PATH_NSSTRING(@"/");
#endif
#ifndef JBROOT_PATH_NSSTRING
#ifdef JBROOT_PATH
		resolved = JBROOT_PATH(@"/");
#endif
#endif

		if (!resolved.length) {
			const char *(*librootPrefixFn)(void) = dlsym(RTLD_DEFAULT, "libroot_get_jbroot_prefix");
			if (librootPrefixFn) {
				const char *rawPrefix = librootPrefixFn();
				if (rawPrefix && rawPrefix[0]) {
					resolved = [NSString stringWithUTF8String:rawPrefix];
				}
			}
		}

		prefix = perm_normalize_prefix(resolved);
	});
	return prefix;
}

NSString *perm_jb_mirror_path_ns(NSString *systemPath)
{
	if (!systemPath.length) return nil;
	if (![systemPath hasPrefix:@"/"]) return systemPath;

	NSString *normalizedSystemPath = perm_normalize_system_path(systemPath);
	if (perm_is_path_under_jbroot(normalizedSystemPath)) return normalizedSystemPath;
	if (perm_is_path_under_jbroot(systemPath)) return systemPath;

#ifdef JBROOT_PATH_NSSTRING
	NSString *mirrored = JBROOT_PATH_NSSTRING(normalizedSystemPath);
	if (mirrored.length) return mirrored;
#endif

#ifndef JBROOT_PATH_NSSTRING
#ifdef JBROOT_PATH
	NSString *mirrored = JBROOT_PATH(normalizedSystemPath);
	if (mirrored.length) return mirrored;
#endif
#endif

	NSString *prefix = perm_jb_root_prefix_ns();
	if (!prefix.length) return nil;
	if ([prefix isEqualToString:@"/"]) return normalizedSystemPath;
	return [prefix stringByAppendingString:normalizedSystemPath];
}

int perm_jb_mirror_path_c(const char *systemPath, char *outPath, size_t outSize)
{
	if (!systemPath || !outPath || outSize == 0) return -1;
	outPath[0] = '\0';

	NSString *input = [NSString stringWithUTF8String:systemPath];
	NSString *mirrored = perm_jb_mirror_path_ns(input);
	if (!mirrored.length) return -1;

	strlcpy(outPath, mirrored.UTF8String, outSize);
	return 0;
}

BOOL perm_is_path_under_jbroot(NSString *path)
{
	if (!path.length) return NO;
	NSString *prefix = perm_jb_root_prefix_ns();
	if (!prefix.length || [prefix isEqualToString:@"/"]) return NO;
	return [path hasPrefix:prefix];
}

static NSMutableSet<NSString *> *gCachedJBBundleIDs = nil;
static CFAbsoluteTime gBundleCacheLastRefresh = 0;
static const CFAbsoluteTime kBundleCacheTTL = 30.0;

static NSSet<NSString *> *perm_cached_jb_bundle_ids(void)
{
	CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
	if (gCachedJBBundleIDs && (now - gBundleCacheLastRefresh) < kBundleCacheTTL) {
		return gCachedJBBundleIDs;
	}

	NSString *jbAppsPath = perm_jb_mirror_path_ns(@"/Applications");
	if (!jbAppsPath.length) {
		gCachedJBBundleIDs = [NSMutableSet set];
		gBundleCacheLastRefresh = now;
		return gCachedJBBundleIDs;
	}
	NSArray<NSString *> *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbAppsPath error:nil];

	NSMutableSet<NSString *> *newSet = [NSMutableSet set];
	for (NSString *item in contents) {
		if (![item hasSuffix:@".app"]) continue;
		NSString *infoPath = [[jbAppsPath stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
		NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
		NSString *bundleID = info[@"CFBundleIdentifier"];
		if (bundleID.length) [newSet addObject:bundleID];
	}

	gCachedJBBundleIDs = newSet;
	gBundleCacheLastRefresh = now;
	return gCachedJBBundleIDs;
}

PERMBundleClass perm_classify_bundle_id(NSString *bundleID)
{
	return perm_is_jailbreak_bundle_id(bundleID) ? PERMBundleClassJailbreak : PERMBundleClassSystem;
}

BOOL perm_is_jailbreak_bundle_id(NSString *bundleID)
{
	if (!bundleID.length) return NO;
	if ([perm_cached_jb_bundle_ids() containsObject:bundleID]) return YES;

	Class lsProxyClass = NSClassFromString(@"LSApplicationProxy");
	SEL proxySel = NSSelectorFromString(@"applicationProxyForIdentifier:");
	if (lsProxyClass && [lsProxyClass respondsToSelector:proxySel]) {
		id (*sendMsg)(id, SEL, id) = (void *)objc_msgSend;
		id proxy = sendMsg(lsProxyClass, proxySel, bundleID);
		@try {
			NSString *bundlePath = [[proxy valueForKey:@"bundleURL"] path];
			if (perm_is_path_under_jbroot(bundlePath)) {
				return YES;
			}
		} @catch (NSException *e) {
			(void)e;
		}
	}

	return NO;
}

NSArray *perm_merge_array_jb_first(NSArray *systemRecords,
                                   NSArray *jbRecords,
                                   NSString * (^keyBlock)(id record))
{
	if (!systemRecords.count && !jbRecords.count) return @[];
	if (!keyBlock) {
		NSMutableArray *flat = [NSMutableArray array];
		if (systemRecords.count) [flat addObjectsFromArray:systemRecords];
		if (jbRecords.count) [flat addObjectsFromArray:jbRecords];
		return flat;
	}

	NSMutableArray *merged = [NSMutableArray array];
	NSMutableDictionary<NSString *, NSNumber *> *indexByKey = [NSMutableDictionary dictionary];

	for (id record in systemRecords) {
		NSString *key = keyBlock(record);
		if (key.length) {
			if (!indexByKey[key]) {
				indexByKey[key] = @(merged.count);
				[merged addObject:record];
			}
		} else {
			[merged addObject:record];
		}
	}

	for (id record in jbRecords) {
		NSString *key = keyBlock(record);
		if (key.length) {
			NSNumber *idx = indexByKey[key];
			if (idx) {
				merged[idx.unsignedIntegerValue] = record;
			} else {
				indexByKey[key] = @(merged.count);
				[merged addObject:record];
			}
		} else {
			[merged addObject:record];
		}
	}

	return [merged copy];
}

void perm_ensure_parent_dir_for_path(NSString *path)
{
	if (!path.length) return;
	NSString *dir = [path stringByDeletingLastPathComponent];
	if (!dir.length) return;
	[[NSFileManager defaultManager] createDirectoryAtPath:dir
	                          withIntermediateDirectories:YES
	                                         attributes:nil
	                                              error:nil];
}

static NSString *perm_migration_stamp_path(NSString *domainKey)
{
	if (!domainKey.length) return nil;
	NSString *systemStampPath = [@"/var/mobile/Library/Preferences" stringByAppendingPathComponent:
	                             [NSString stringWithFormat:@".perm_router_migrated_%@", domainKey]];
	return perm_jb_mirror_path_ns(systemStampPath);
}

BOOL perm_migration_is_done(NSString *domainKey)
{
	NSString *stampPath = perm_migration_stamp_path(domainKey);
	if (!stampPath.length) return NO;
	return [[NSFileManager defaultManager] fileExistsAtPath:stampPath];
}

void perm_migration_mark_done(NSString *domainKey)
{
	NSString *stampPath = perm_migration_stamp_path(domainKey);
	if (!stampPath.length) return;
	perm_ensure_parent_dir_for_path(stampPath);

	NSString *stamp = [NSString stringWithFormat:@"done=%@\n", [NSDate date]];
	[stamp writeToFile:stampPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

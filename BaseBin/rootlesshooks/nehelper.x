#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import "perm_router.h"

// ============================================================
// Logging
// ============================================================

static void _ne_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _ne_log(const char *fmt, ...)
{
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
// JB App Detection + Cache
// ============================================================

static BOOL isJBBundleID(NSString *bundleID)
{
	return perm_is_jailbreak_bundle_id(bundleID);
}

static NSMutableSet *gJBBundleIDCache = nil;
static CFAbsoluteTime gJBCacheLastRefresh = 0;
static const CFAbsoluteTime kJBCacheTTL = 30.0; // refresh every 30 seconds

static NSSet *cachedJBBundleIDs(void)
{
	CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
	if (gJBBundleIDCache && (now - gJBCacheLastRefresh) < kJBCacheTTL) {
		return gJBBundleIDCache;
	}

	NSMutableSet *newCache = [NSMutableSet set];
	NSString *jbAppsPath = perm_jb_mirror_path_ns(@"/Applications");
	if (!jbAppsPath.length) {
		gJBBundleIDCache = newCache;
		gJBCacheLastRefresh = now;
		return gJBBundleIDCache;
	}
	NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbAppsPath error:nil];
	for (NSString *item in contents) {
		if (![item hasSuffix:@".app"]) continue;
		NSString *infoPath = [[jbAppsPath stringByAppendingPathComponent:item]
		                      stringByAppendingPathComponent:@"Info.plist"];
		NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
		NSString *bid = info[@"CFBundleIdentifier"];
		if (bid.length) [newCache addObject:bid];
	}

	gJBBundleIDCache = newCache;
	gJBCacheLastRefresh = now;
	NE_LOG("cachedJBBundleIDs: refreshed, found %lu JB apps", (unsigned long)newCache.count);
	return gJBBundleIDCache;
}

// ============================================================
// Paths
// ============================================================

static NSString *systemNetworkRulesPlistPath(void)
{
	return @"/var/mobile/Library/Preferences/com.apple.networkextension.plist";
}

static NSString *jbNetworkRulesPlistPath(void)
{
	static NSString *path = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		path = perm_jb_mirror_path_ns(systemNetworkRulesPlistPath());
	});
	return path;
}

static NSString *legacyJBRulesPlistPath(void)
{
	static NSString *path = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		path = perm_jb_mirror_path_ns(@"/var/mobile/Library/Preferences/.jb_ne_rules.plist");
	});
	return path;
}

// ============================================================
// Rule Serialization
// ============================================================

static NSData *archiveRulesArray(NSArray *rules, NSString *key)
{
	if (![rules isKindOfClass:[NSArray class]]) return nil;
	@try {
		return [NSKeyedArchiver archivedDataWithRootObject:rules requiringSecureCoding:NO error:nil];
	} @catch (NSException *e) {
		NE_LOG("archiveRulesArray(%s): exception: %s", key.UTF8String, e.reason.UTF8String);
		return nil;
	}
}

static NSArray *decodeRulesData(NSData *archivedData, NSString *key)
{
	if (![archivedData isKindOfClass:[NSData class]]) return nil;

	NSError *err = nil;
	NSArray *rules = nil;
	@try {
		NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:archivedData error:&err];
		if (unarchiver) {
			unarchiver.requiresSecureCoding = NO;
			rules = [unarchiver decodeObjectForKey:NSKeyedArchiveRootObjectKey];
			[unarchiver finishDecoding];
		}
	} @catch (NSException *e) {
		NE_LOG("decodeRulesData(%s): exception: %s", key.UTF8String, e.reason.UTF8String);
		return nil;
	}
	if (![rules isKindOfClass:[NSArray class]]) return nil;
	return rules;
}

static NSString *ruleBundleID(id rule)
{
	NSString *bid = nil;
	@try {
		if ([rule respondsToSelector:@selector(matchSigningIdentifier)]) {
			bid = [rule valueForKey:@"matchSigningIdentifier"];
		}
	} @catch (NSException *e) {
		(void)e;
	}
	return bid;
}

static NSString *ruleMergeKey(id rule)
{
	NSString *bid = nil;
	NSString *path = nil;
	@try {
		if ([rule respondsToSelector:@selector(matchSigningIdentifier)]) {
			bid = [rule valueForKey:@"matchSigningIdentifier"];
		}
		if ([rule respondsToSelector:@selector(matchPath)]) {
			path = [rule valueForKey:@"matchPath"];
		}
	} @catch (NSException *e) {
		(void)e;
	}
	if (bid.length || path.length) {
		return [NSString stringWithFormat:@"%@|%@", bid ?: @"", path ?: @""];
	}
	return nil;
}

static void splitRulesByBundleClass(NSArray *allRules, NSMutableArray *systemRules, NSMutableArray *jbRules)
{
	for (id rule in allRules) {
		NSString *bid = ruleBundleID(rule);
		if (bid.length && isJBBundleID(bid)) {
			[jbRules addObject:rule];
		} else {
			[systemRules addObject:rule];
		}
	}
}

// ============================================================
// JB Rules Store (mirror path)
// ============================================================

static NSMutableDictionary *loadRuleStoreAtPath(NSString *path)
{
	if (!path.length || ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
		return [NSMutableDictionary dictionary];
	}

	NSData *data = [NSData dataWithContentsOfFile:path];
	if (!data) return [NSMutableDictionary dictionary];

	NSDictionary *dict = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
	if (![dict isKindOfClass:[NSDictionary class]]) {
		return [NSMutableDictionary dictionary];
	}
	return [dict mutableCopy];
}

static void saveRuleStoreToPath(NSDictionary *store, NSString *path, const char *tag)
{
	if (!path.length) return;
	if (![store isKindOfClass:[NSDictionary class]]) return;

	if (store.count == 0) {
		[[NSFileManager defaultManager] removeItemAtPath:path error:nil];
		NE_LOG("%s: emptied, removed file", tag);
		return;
	}

	NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:store
	                                                              format:NSPropertyListXMLFormat_v1_0
	                                                             options:0
	                                                               error:nil];
	if (!plistData) {
		NE_LOG("%s: failed to serialize plist", tag);
		return;
	}

	perm_ensure_parent_dir_for_path(path);
	BOOL ok = [plistData writeToFile:path atomically:YES];
	NE_LOG("%s: write %s (%lu keys)", tag, ok ? "OK" : "FAILED", (unsigned long)store.count);
}

static void saveJBRules(NSArray *jbRules, NSString *key)
{
	if (!key.length) return;

	NSString *path = jbNetworkRulesPlistPath();
	NSMutableDictionary *store = loadRuleStoreAtPath(path);

	if (!jbRules.count) {
		[store removeObjectForKey:key];
		NE_LOG("saveJBRules: removed key %s", key.UTF8String);
	} else {
		NSData *archived = archiveRulesArray(jbRules, key);
		if (!archived) return;
		store[key] = archived;
	}

	saveRuleStoreToPath(store, path, "saveJBRules");
}

static NSArray *loadJBRules(NSString *key)
{
	if (!key.length) return nil;
	NSString *path = jbNetworkRulesPlistPath();
	NSDictionary *store = loadRuleStoreAtPath(path);
	NSData *archived = store[key];
	NSArray *rules = decodeRulesData(archived, key);
	if (rules.count) {
		NE_LOG("loadJBRules: loaded %lu JB rules for %s", (unsigned long)rules.count, key.UTF8String);
	}
	return rules;
}

// ============================================================
// Migration (first-run): system plist -> mirror + system cleanup
// ============================================================

static void migrateLegacyJBRuleStoreIfNeeded(void)
{
	NSString *legacyPath = legacyJBRulesPlistPath();
	if (!legacyPath.length || ![[NSFileManager defaultManager] fileExistsAtPath:legacyPath]) return;

	NSMutableDictionary *legacyStore = loadRuleStoreAtPath(legacyPath);
	if (!legacyStore.count) {
		[[NSFileManager defaultManager] removeItemAtPath:legacyPath error:nil];
		return;
	}

	NSString *newPath = jbNetworkRulesPlistPath();
	NSMutableDictionary *newStore = loadRuleStoreAtPath(newPath);
	[newStore addEntriesFromDictionary:legacyStore];
	saveRuleStoreToPath(newStore, newPath, "migrateLegacyJBRuleStore");
	[[NSFileManager defaultManager] removeItemAtPath:legacyPath error:nil];
	NE_LOG("migrateLegacyJBRuleStore: migrated %lu keys", (unsigned long)legacyStore.count);
}

static void migrateNetworkRulesIfNeeded(void)
{
	if (perm_migration_is_done(@"networkextension")) return;

	migrateLegacyJBRuleStoreIfNeeded();

	NSString *systemPath = systemNetworkRulesPlistPath();
	if (![[NSFileManager defaultManager] fileExistsAtPath:systemPath]) {
		perm_migration_mark_done(@"networkextension");
		NE_LOG("migrateNetworkRulesIfNeeded: no system plist, marked done");
		return;
	}

	NSMutableDictionary *systemStore = loadRuleStoreAtPath(systemPath);
	if (!systemStore.count) {
		perm_migration_mark_done(@"networkextension");
		NE_LOG("migrateNetworkRulesIfNeeded: empty system plist, marked done");
		return;
	}

	BOOL changed = NO;
	NSArray<NSString *> *keys = @[@"config-aggregate-rules", @"Rules"];
	for (NSString *key in keys) {
		NSArray *allRules = decodeRulesData(systemStore[key], key);
		if (!allRules.count) continue;

		NSMutableArray *systemRules = [NSMutableArray array];
		NSMutableArray *jbRules = [NSMutableArray array];
		splitRulesByBundleClass(allRules, systemRules, jbRules);

		if (jbRules.count) {
			saveJBRules(jbRules, key);
			changed = YES;
		}

		if (systemRules.count != allRules.count) {
			if (systemRules.count) {
				NSData *archivedSystem = archiveRulesArray(systemRules, key);
				if (archivedSystem) {
					systemStore[key] = archivedSystem;
				} else {
					[systemStore removeObjectForKey:key];
				}
			} else {
				[systemStore removeObjectForKey:key];
			}
			changed = YES;
		}
	}

	if (changed) {
		saveRuleStoreToPath(systemStore, systemPath, "migrateNetworkRulesIfNeeded(system)");
	}

	perm_migration_mark_done(@"networkextension");
	NE_LOG("migrateNetworkRulesIfNeeded: finished (changed=%d)", changed);
}

// ============================================================
// NSKeyedArchiver / NSKeyedUnarchiver Hooks
// ============================================================

static __thread BOOL gIsRoutingNE;

static void (*orig_encode_object_forKey)(id self, SEL _cmd, id obj, NSString *key);
static void hook_encode_object_forKey(id self, SEL _cmd, id obj, NSString *key)
{
	if (!gIsRoutingNE &&
	    ([key isEqualToString:@"config-aggregate-rules"] || [key isEqualToString:@"Rules"]) &&
	    [obj isKindOfClass:[NSArray class]]) {
		NSArray *allRules = (NSArray *)obj;
		NSMutableArray *systemRules = [NSMutableArray array];
		NSMutableArray *jbRules = [NSMutableArray array];
		splitRulesByBundleClass(allRules, systemRules, jbRules);

		NE_LOG("ENCODE %s: total=%lu, JB=%lu, system=%lu",
		       key.UTF8String,
		       (unsigned long)allRules.count,
		       (unsigned long)jbRules.count,
		       (unsigned long)systemRules.count);

		gIsRoutingNE = YES;
		saveJBRules(jbRules, key);
		gIsRoutingNE = NO;

		orig_encode_object_forKey(self, _cmd, systemRules, key);
		return;
	}

	orig_encode_object_forKey(self, _cmd, obj, key);
}

static id (*orig_decode_object_forKey)(id self, SEL _cmd, NSString *key);
static id hook_decode_object_forKey(id self, SEL _cmd, NSString *key)
{
	id obj = orig_decode_object_forKey(self, _cmd, key);

	if (!gIsRoutingNE &&
	    ([key isEqualToString:@"Rules"] || [key isEqualToString:@"config-aggregate-rules"]) &&
	    [obj isKindOfClass:[NSArray class]]) {
		gIsRoutingNE = YES;
		NSArray *jbRules = loadJBRules(key);
		gIsRoutingNE = NO;

		if (jbRules.count) {
			NSArray *merged = perm_merge_array_jb_first((NSArray *)obj, jbRules, ^NSString * _Nullable(id record) {
				return ruleMergeKey(record);
			});
			NE_LOG("DECODE %s: system=%lu + JB=%lu -> merged=%lu",
			       key.UTF8String,
			       (unsigned long)((NSArray *)obj).count,
			       (unsigned long)jbRules.count,
			       (unsigned long)merged.count);
			return merged;
		}
	}

	return obj;
}

// ============================================================
// LSApplicationProxy Hooks (JB app UUID resolution)
// ============================================================

static id (*orig_LSProxy_bundleURL)(id self, SEL _cmd);
static id hook_LSProxy_bundleURL(id self, SEL _cmd)
{
	id result = orig_LSProxy_bundleURL(self, _cmd);
	if (!result) {
		NSString *bid = nil;
		@try {
			bid = [self valueForKey:@"applicationIdentifier"];
			if (!bid) bid = [self valueForKey:@"bundleIdentifier"];
		} @catch (NSException *e) {
			(void)e;
		}

		if (bid && [cachedJBBundleIDs() containsObject:bid]) {
			NSString *jbAppsPath = perm_jb_mirror_path_ns(@"/Applications");
			if (!jbAppsPath.length) return result;
			NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbAppsPath error:nil];
			for (NSString *item in contents) {
				if (![item hasSuffix:@".app"]) continue;
				NSString *infoPath = [[jbAppsPath stringByAppendingPathComponent:item]
				                      stringByAppendingPathComponent:@"Info.plist"];
				NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
				if ([info[@"CFBundleIdentifier"] isEqualToString:bid]) {
					NSString *appPath = [jbAppsPath stringByAppendingPathComponent:item];
					result = [NSURL fileURLWithPath:appPath isDirectory:YES];
					NE_LOG("LSProxy_bundleURL: injected JB path for '%s': %s",
					       bid.UTF8String, appPath.UTF8String);
					break;
				}
			}
		}
	}
	return result;
}

static id (*orig_LSProxy_bundleContainerURL)(id self, SEL _cmd);
static id hook_LSProxy_bundleContainerURL(id self, SEL _cmd)
{
	id result = orig_LSProxy_bundleContainerURL(self, _cmd);
	if (!result) {
		NSString *bid = nil;
		@try {
			bid = [self valueForKey:@"applicationIdentifier"];
			if (!bid) bid = [self valueForKey:@"bundleIdentifier"];
		} @catch (NSException *e) {
			(void)e;
		}

		if (bid && [cachedJBBundleIDs() containsObject:bid]) {
			NSString *appsPath = perm_jb_mirror_path_ns(@"/Applications");
			if (appsPath.length) {
				result = [NSURL fileURLWithPath:appsPath isDirectory:YES];
			}
			NE_LOG("LSProxy_bundleContainerURL: injected JB container for '%s'", bid.UTF8String);
		}
	}
	return result;
}

static id (*orig_LSProxy_proxyForIdentifier)(id self, SEL _cmd, NSString *bundleID);
static id hook_LSProxy_proxyForIdentifier(id self, SEL _cmd, NSString *bundleID)
{
	id result = orig_LSProxy_proxyForIdentifier(self, _cmd, bundleID);

	if (result && bundleID) {
		NSURL *bundleURL = nil;
		@try {
			bundleURL = [result valueForKey:@"bundleURL"];
		} @catch (NSException *e) {
			(void)e;
		}
		if (!bundleURL && [cachedJBBundleIDs() containsObject:bundleID]) {
			NE_LOG("LSProxy_proxyForIdentifier: proxy for '%s' has nil bundleURL",
			       bundleID.UTF8String);
		}
	} else if (!result && bundleID && [cachedJBBundleIDs() containsObject:bundleID]) {
		NE_LOG("LSProxy_proxyForIdentifier: nil proxy for JB app '%s'", bundleID.UTF8String);
	}

	return result;
}

// ============================================================
// nehelperInit
// ============================================================

void nehelperInit(void)
{
	NE_LOG("nehelperInit() called in process: %s (pid=%d)", getprogname(), getpid());

	(void)cachedJBBundleIDs();
	migrateNetworkRulesIfNeeded();

	Class archiverClass = objc_getClass("NSKeyedArchiver");
	if (archiverClass) {
		MSHookMessageEx(archiverClass,
		                @selector(encodeObject:forKey:),
		                (IMP)hook_encode_object_forKey,
		                (IMP *)&orig_encode_object_forKey);
		NE_LOG("nehelperInit: NSKeyedArchiver hook installed");
	}

	Class unarchiverClass = objc_getClass("NSKeyedUnarchiver");
	if (unarchiverClass) {
		MSHookMessageEx(unarchiverClass,
		                @selector(decodeObjectForKey:),
		                (IMP)hook_decode_object_forKey,
		                (IMP *)&orig_decode_object_forKey);
		NE_LOG("nehelperInit: NSKeyedUnarchiver hook installed");
	}

	Class lsProxyClass = objc_getClass("LSApplicationProxy");
	if (lsProxyClass) {
		MSHookMessageEx(lsProxyClass,
		                NSSelectorFromString(@"bundleURL"),
		                (IMP)hook_LSProxy_bundleURL,
		                (IMP *)&orig_LSProxy_bundleURL);

		if ([lsProxyClass instancesRespondToSelector:NSSelectorFromString(@"bundleContainerURL")]) {
			MSHookMessageEx(lsProxyClass,
			                NSSelectorFromString(@"bundleContainerURL"),
			                (IMP)hook_LSProxy_bundleContainerURL,
			                (IMP *)&orig_LSProxy_bundleContainerURL);
		}

		Class lsProxyMetaClass = object_getClass(lsProxyClass);
		if (lsProxyMetaClass) {
			MSHookMessageEx(lsProxyMetaClass,
			                NSSelectorFromString(@"applicationProxyForIdentifier:"),
			                (IMP)hook_LSProxy_proxyForIdentifier,
			                (IMP *)&orig_LSProxy_proxyForIdentifier);
		}
		NE_LOG("nehelperInit: LSApplicationProxy hooks installed");
	}

	NE_LOG("nehelperInit: hooks installed. mirror rules plist: %s",
	       jbNetworkRulesPlistPath().UTF8String);
}

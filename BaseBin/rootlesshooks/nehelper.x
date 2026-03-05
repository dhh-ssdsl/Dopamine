#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>

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
// JB Root Path
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

// ============================================================
// JB App Detection — scan jbroot /Applications for bundleID
// ============================================================

static BOOL isJBBundleID(NSString *bundleID)
{
	if (!bundleID.length) return NO;

	// Check if LSApplicationProxy resolves to a jbroot path
	Class LSProxy = NSClassFromString(@"LSApplicationProxy");
	SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
	if (LSProxy && [LSProxy respondsToSelector:sel]) {
		id (*msgSend)(id, SEL, id) = (void *)objc_msgSend;
		id proxy = msgSend(LSProxy, sel, bundleID);
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

// Cache for JB bundleIDs with time-based refresh (30s TTL).
// This ensures newly installed JB apps are detected without restarting nehelper.
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
	NSString *jbAppsPath = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/Applications")];
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
// Deterministic UUID Generation
//
// Generates a stable UUID from bundleID (same UUID across reboots).
// Uses MD5 hash formatted as UUID v3 style.
// ============================================================

static NSUUID *generateDeterministicUUID(NSString *bundleID)
{
	NSString *input = [NSString stringWithFormat:@"jb-ne-uuid:%@", bundleID];
	const char *cstr = [input UTF8String];
	unsigned char digest[CC_SHA256_DIGEST_LENGTH];
	CC_SHA256(cstr, (CC_LONG)strlen(cstr), digest);

	// Format as UUID v3 (set version and variant bits)
	digest[6] = (digest[6] & 0x0F) | 0x30; // version 3
	digest[8] = (digest[8] & 0x3F) | 0x80; // variant 1

	return [[NSUUID alloc] initWithUUIDBytes:digest];
}

// ============================================================
// JB Network Rules Plist Storage
// ============================================================

static NSString *jbNetworkRulesPlistPath(void)
{
	static NSString *path = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		path = [NSString stringWithUTF8String:
		        JBROOT_PATH_CSTRING("/var/mobile/Library/Preferences/.jb_ne_rules.plist")];
	});
	return path;
}

static void saveJBRules(NSArray *jbRules)
{
	if (!jbRules.count) {
		[[NSFileManager defaultManager] removeItemAtPath:jbNetworkRulesPlistPath() error:nil];
		NE_LOG("saveJBRules: no JB rules, removed plist");
		return;
	}

	NSData *archivedData = nil;
	@try {
		archivedData = [NSKeyedArchiver archivedDataWithRootObject:jbRules
		                              requiringSecureCoding:NO
		                                             error:nil];
	} @catch (NSException *e) {
		NE_LOG("saveJBRules: archive exception: %s", e.reason.UTF8String);
		return;
	}

	if (!archivedData) {
		NE_LOG("saveJBRules: NSKeyedArchiver failed, nil data");
		return;
	}

	NSDictionary *plistDict = @{ @"rules": archivedData };
	NSError *err = nil;
	NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:plistDict
	                                                              format:NSPropertyListXMLFormat_v1_0
	                                                             options:0
	                                                               error:&err];
	if (!plistData) {
		NE_LOG("saveJBRules: plist serialization error: %s", err.localizedDescription.UTF8String);
		return;
	}

	NSString *dir = [jbNetworkRulesPlistPath() stringByDeletingLastPathComponent];
	[[NSFileManager defaultManager] createDirectoryAtPath:dir
	                          withIntermediateDirectories:YES
	                                         attributes:nil
	                                              error:nil];

	BOOL ok = [plistData writeToFile:jbNetworkRulesPlistPath() atomically:YES];
	NE_LOG("saveJBRules: wrote %lu JB rules to plist: %s", (unsigned long)jbRules.count, ok ? "OK" : "FAILED");
}

static NSArray *loadJBRules(void)
{
	NSString *path = jbNetworkRulesPlistPath();
	if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return nil;

	NSError *err = nil;
	NSData *plistData = [NSData dataWithContentsOfFile:path options:0 error:&err];
	if (!plistData) {
		NE_LOG("loadJBRules: read error: %s", err.localizedDescription.UTF8String);
		return nil;
	}

	NSDictionary *plistDict = [NSPropertyListSerialization propertyListWithData:plistData
	                                                                    options:0
	                                                                     format:nil
	                                                                      error:&err];
	if (![plistDict isKindOfClass:[NSDictionary class]]) {
		NE_LOG("loadJBRules: plist parse error");
		return nil;
	}

	NSData *archivedData = plistDict[@"rules"];
	if (![archivedData isKindOfClass:[NSData class]]) {
		NE_LOG("loadJBRules: no 'rules' data key");
		return nil;
	}

	NSArray *rules = nil;
	@try {
		NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:archivedData error:&err];
		if (unarchiver) {
			unarchiver.requiresSecureCoding = NO;
			rules = [unarchiver decodeObjectForKey:NSKeyedArchiveRootObjectKey];
			[unarchiver finishDecoding];
		}
	} @catch (NSException *e) {
		NE_LOG("loadJBRules: unarchive exception: %s", e.reason.UTF8String);
		return nil;
	}

	if (![rules isKindOfClass:[NSArray class]]) {
		NE_LOG("loadJBRules: unarchived object is not NSArray");
		return nil;
	}

	NE_LOG("loadJBRules: loaded %lu JB rules from plist", (unsigned long)rules.count);
	return rules;
}

// ============================================================
// NSKeyedArchiver / NSKeyedUnarchiver Hooks
// (Read-Write Separation for NE config-aggregate-rules)
// ============================================================

static __thread BOOL gIsRoutingNE;

static void (*orig_encode_object_forKey)(id self, SEL _cmd, id obj, NSString *key);
static void hook_encode_object_forKey(id self, SEL _cmd, id obj, NSString *key)
{
	if (!gIsRoutingNE &&
	    [key isEqualToString:@"config-aggregate-rules"] &&
	    [obj isKindOfClass:[NSArray class]])
	{
		NSArray *allRules = (NSArray *)obj;
		NSMutableArray *systemRules = [NSMutableArray array];
		NSMutableArray *jbRules     = [NSMutableArray array];

		for (id rule in allRules) {
			NSString *bid = nil;
			if ([rule respondsToSelector:@selector(matchSigningIdentifier)]) {
				bid = [rule valueForKey:@"matchSigningIdentifier"];
			}
			if (bid && isJBBundleID(bid)) {
				[jbRules addObject:rule];
			} else {
				[systemRules addObject:rule];
			}
		}

		NE_LOG("ENCODE config-aggregate-rules: total=%lu, JB=%lu, system=%lu",
		       (unsigned long)allRules.count,
		       (unsigned long)jbRules.count,
		       (unsigned long)systemRules.count);

		// Save JB rules to JB-specific plist
		gIsRoutingNE = YES;
		saveJBRules(jbRules);
		gIsRoutingNE = NO;

		// Write ONLY system rules to system plist (read-write separation)
		orig_encode_object_forKey(self, _cmd, systemRules, key);
		return;
	}

	orig_encode_object_forKey(self, _cmd, obj, key);
}

static id (*orig_decode_object_forKey)(id self, SEL _cmd, NSString *key);
static id hook_decode_object_forKey(id self, SEL _cmd, NSString *key)
{
	id obj = orig_decode_object_forKey(self, _cmd, key);

	// Merge JB rules back in on decode
	if (!gIsRoutingNE &&
	    ([key isEqualToString:@"Rules"] || [key isEqualToString:@"config-aggregate-rules"]) &&
	    [obj isKindOfClass:[NSArray class]])
	{
		gIsRoutingNE = YES;
		NSArray *jbRules = loadJBRules();
		gIsRoutingNE = NO;

		if (jbRules.count) {
			NSMutableArray *merged = [obj mutableCopy];
			[merged addObjectsFromArray:jbRules];
			NE_LOG("DECODE %s: system=%lu + JB=%lu = total=%lu",
			       key.UTF8String,
			       (unsigned long)((NSArray *)obj).count,
			       (unsigned long)jbRules.count,
			       (unsigned long)merged.count);
			return [merged copy];
		} else {
			NE_LOG("DECODE %s: no JB rules to merge, total=%lu",
			       key.UTF8String, (unsigned long)((NSArray *)obj).count);
		}
	}

	return obj;
}

// ============================================================
// LSApplicationProxy Hook — Fix UUID Resolution for JB Apps
//
// Architecture:
//   nesessionmanager → XPC → nehelper → LSApplicationProxy → LaunchServices
//
// When nehelper queries LaunchServices for a JB app bundleID,
// it calls [LSApplicationProxy applicationProxyForIdentifier:].
// For JB apps NOT in MobileInstallation, this returns a proxy
// with nil bundleURL, causing "Failed to find XXX in LaunchServices".
//
// Our hook intercepts this in nehelper's process space and
// returns a proxy with a valid bundleURL for JB apps, so
// nehelper can resolve the UUID to return to nesessionmanager.
// ============================================================

// Hook -[LSApplicationProxy bundleURL]
// For JB apps, return the actual jbroot .app path as a URL
static id (*orig_LSProxy_bundleURL)(id self, SEL _cmd);
static id hook_LSProxy_bundleURL(id self, SEL _cmd)
{
	id result = orig_LSProxy_bundleURL(self, _cmd);
	if (!result) {
		// bundleURL is nil — might be a JB app
		NSString *bid = nil;
		@try {
			bid = [self valueForKey:@"applicationIdentifier"];
			if (!bid) bid = [self valueForKey:@"bundleIdentifier"];
		} @catch (NSException *e) {
			// ignore
		}
		if (bid && [cachedJBBundleIDs() containsObject:bid]) {
			// Find the actual .app path in jbroot
			NSString *jbAppsPath = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/Applications")];
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

// Hook -[LSApplicationProxy bundleContainerURL]
// For JB apps, return a valid container URL (same as bundle path parent)
static id (*orig_LSProxy_bundleContainerURL)(id self, SEL _cmd);
static id hook_LSProxy_bundleContainerURL(id self, SEL _cmd)
{
	id result = orig_LSProxy_bundleContainerURL(self, _cmd);
	if (!result) {
		NSString *bid = nil;
		@try {
			bid = [self valueForKey:@"applicationIdentifier"];
			if (!bid) bid = [self valueForKey:@"bundleIdentifier"];
		} @catch (NSException *e) {}
		if (bid && [cachedJBBundleIDs() containsObject:bid]) {
			result = [NSURL fileURLWithPath:
			          [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/Applications")]
			                    isDirectory:YES];
			NE_LOG("LSProxy_bundleContainerURL: injected JB container for '%s'", bid.UTF8String);
		}
	}
	return result;
}

// Hook +[LSApplicationProxy applicationProxyForIdentifier:]
// For JB apps that return nil proxy, create a minimal proxy
static id (*orig_LSProxy_proxyForIdentifier)(id self, SEL _cmd, NSString *bundleID);
static id hook_LSProxy_proxyForIdentifier(id self, SEL _cmd, NSString *bundleID)
{
	id result = orig_LSProxy_proxyForIdentifier(self, _cmd, bundleID);

	if (result && bundleID) {
		// Check if the proxy has a valid bundleURL
		NSURL *bundleURL = nil;
		@try {
			bundleURL = [result valueForKey:@"bundleURL"];
		} @catch (NSException *e) {}

		if (!bundleURL && [cachedJBBundleIDs() containsObject:bundleID]) {
			NE_LOG("LSProxy_proxyForIdentifier: proxy for '%s' has nil bundleURL, "
			       "instance hook will inject JB path", bundleID.UTF8String);
		}
	} else if (!result && bundleID && [cachedJBBundleIDs() containsObject:bundleID]) {
		// Proxy itself is nil — try calling original with bundleID anyway,
		// the instance hooks on bundleURL will fill in the path
		NE_LOG("LSProxy_proxyForIdentifier: nil proxy for JB app '%s'", bundleID.UTF8String);
	}

	return result;
}

// ============================================================
// nehelperInit — called by main.x %ctor when process is nehelper
// ============================================================

void nehelperInit(void)
{
	NE_LOG("nehelperInit() called in process: %s (pid=%d)", getprogname(), getpid());

	// Pre-cache JB bundle IDs
	(void)cachedJBBundleIDs();

	// --- Hook 1: NSKeyedArchiver -encodeObject:forKey: ---
	Class archiverClass = objc_getClass("NSKeyedArchiver");
	if (archiverClass) {
		MSHookMessageEx(archiverClass,
		    @selector(encodeObject:forKey:),
		    (IMP)hook_encode_object_forKey,
		    (IMP *)&orig_encode_object_forKey);
		NE_LOG("nehelperInit: NSKeyedArchiver hook installed");
	} else {
		NE_LOG("nehelperInit: WARNING - NSKeyedArchiver class not found");
	}

	// --- Hook 2: NSKeyedUnarchiver -decodeObjectForKey: ---
	Class unarchiverClass = objc_getClass("NSKeyedUnarchiver");
	if (unarchiverClass) {
		MSHookMessageEx(unarchiverClass,
		    @selector(decodeObjectForKey:),
		    (IMP)hook_decode_object_forKey,
		    (IMP *)&orig_decode_object_forKey);
		NE_LOG("nehelperInit: NSKeyedUnarchiver hook installed");
	} else {
		NE_LOG("nehelperInit: WARNING - NSKeyedUnarchiver class not found");
	}

	// --- Hook 3: LSApplicationProxy hooks (UUID resolution fix) ---
	Class lsProxyClass = objc_getClass("LSApplicationProxy");
	if (lsProxyClass) {
		// Hook instance method -bundleURL
		MSHookMessageEx(lsProxyClass,
		    NSSelectorFromString(@"bundleURL"),
		    (IMP)hook_LSProxy_bundleURL,
		    (IMP *)&orig_LSProxy_bundleURL);

		// Hook instance method -bundleContainerURL
		if ([lsProxyClass instancesRespondToSelector:NSSelectorFromString(@"bundleContainerURL")]) {
			MSHookMessageEx(lsProxyClass,
			    NSSelectorFromString(@"bundleContainerURL"),
			    (IMP)hook_LSProxy_bundleContainerURL,
			    (IMP *)&orig_LSProxy_bundleContainerURL);
		}

		// Hook class method +applicationProxyForIdentifier:
		Class lsProxyMetaClass = object_getClass(lsProxyClass);
		if (lsProxyMetaClass) {
			MSHookMessageEx(lsProxyMetaClass,
			    NSSelectorFromString(@"applicationProxyForIdentifier:"),
			    (IMP)hook_LSProxy_proxyForIdentifier,
			    (IMP *)&orig_LSProxy_proxyForIdentifier);
		}

		NE_LOG("nehelperInit: LSApplicationProxy hooks installed (bundleURL, bundleContainerURL, applicationProxyForIdentifier:)");
	} else {
		NE_LOG("nehelperInit: WARNING - LSApplicationProxy class not found");
	}

	NE_LOG("nehelperInit: all hooks installed. JB rules plist: %s",
	       jbNetworkRulesPlistPath().UTF8String);
}

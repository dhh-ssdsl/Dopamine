#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>
#import <objc/runtime.h>
#import <objc/message.h>

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
// JB App Detection
// ============================================================

static BOOL isJBBundleID(NSString *bundleID)
{
	if (!bundleID.length) return NO;

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

// ============================================================
// JB Network Rules Plist Storage
//
// Stores JB network rules as a plain plist dictionary:
// {
//   "rules" = <NSData: NSKeyedArchiver-encoded NSArray of NEPathRule>
// }
//
// Using NSKeyedArchiver is NOT encryption — it's the standard
// binary serialization used by iOS itself. No custom crypto involved.
// The file uses normal plist format readable by plutil/Xcode.
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

// Save a JB rules array to the JB plist.
// The array items are private NEPathRule objects — we archive the whole
// NSArray with NSKeyedArchiver (valid in nehelper's process space where
// the private classes are already loaded) and store the resulting NSData
// in a plain plist dictionary under the "rules" key.
static void saveJBRules(NSArray *jbRules)
{
	if (!jbRules.count) {
		// Remove the file if there are no JB rules
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

	BOOL ok = [plistData writeToFile:jbNetworkRulesPlistPath() atomically:YES];
	NE_LOG("saveJBRules: wrote %lu JB rules to plist: %s", (unsigned long)jbRules.count, ok ? "OK" : "FAILED");
}

// Load previously saved JB rules from the JB plist.
// Returns nil if the file doesn't exist or can't be read.
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
		// Must disable requiresSecureCoding because NEPathRule is a private class
		// not registered for secure coding. We authored this data ourselves, so it's safe.
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
// ============================================================

// Thread-local re-entrancy guard (prevents recursive hook calls when
// saveJBRules/loadJBRules internally call NSKeyedArchiver/Unarchiver)
static __thread BOOL gIsRoutingNE;

static void (*orig_encode_object_forKey)(id self, SEL _cmd, id obj, NSString *key);
static void hook_encode_object_forKey(id self, SEL _cmd, id obj, NSString *key)
{
	// Only intercept the final "config-aggregate-rules" key — this is the key
	// that nehelper uses when writing the consolidated config to disk.
	// We split out JB rules and save them separately; only system rules continue.
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

		// Persist JB rules to the JB plist (replaces any previous snapshot)
		if (jbRules.count) {
			gIsRoutingNE = YES;
			saveJBRules(jbRules);
			gIsRoutingNE = NO;
		}

		// Encode only system rules into the system config
		orig_encode_object_forKey(self, _cmd, systemRules, key);
		return;
	}

	orig_encode_object_forKey(self, _cmd, obj, key);
}

static id (*orig_decode_object_forKey)(id self, SEL _cmd, NSString *key);
static id hook_decode_object_forKey(id self, SEL _cmd, NSString *key)
{
	id obj = orig_decode_object_forKey(self, _cmd, key);

	// Intercept Rules and config-aggregate-rules on decode:
	// merge in any JB rules that were saved separately.
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
// nehelperInit — called by main.x %ctor when process is nehelper
// ============================================================

void nehelperInit(void)
{
	NE_LOG("nehelperInit() called in process: %s (pid=%d)", getprogname(), getpid());

	// Hook NSKeyedArchiver -encodeObject:forKey:
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

	// Hook NSKeyedUnarchiver -decodeObjectForKey:
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

	NE_LOG("nehelperInit: all hooks installed. JB rules plist: %s",
	       jbNetworkRulesPlistPath().UTF8String);
}

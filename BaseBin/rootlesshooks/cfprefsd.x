#import <Foundation/Foundation.h>
#import <substrate.h>
#import <libroot.h>

BOOL preferencePlistNeedsRedirection(NSString *plistPath)
{
	if ([plistPath hasPrefix:@"/private/var/mobile/Containers"] || [plistPath hasPrefix:@"/var/db"] || [plistPath hasPrefix:@"/var/jb"]) return NO;

	NSString *plistName = plistPath.lastPathComponent;

	if ([plistName hasPrefix:@"com.apple."] || [plistName hasPrefix:@"systemgroup.com.apple."] || [plistName hasPrefix:@"group.com.apple."]) return NO;

	NSArray *additionalSystemPlistNames = @[
		@".GlobalPreferences.plist",
		@".GlobalPreferences_m.plist",
		@"bluetoothaudiod.plist",
		@"NetworkInterfaces.plist",
		@"OSThermalStatus.plist",
		@"preferences.plist",
		@"osanalyticshelper.plist",
		@"UserEventAgent.plist",
		@"wifid.plist",
		@"dprivacyd.plist",
		@"silhouette.plist",
		@"nfcd.plist",
		@"kNPProgressTrackerDomain.plist",
		@"siriknowledged.plist",
		@"UITextInputContextIdentifiers.plist",
		@"mobile_storage_proxy.plist",
		@"splashboardd.plist",
		@"mobile_installation_proxy.plist",
		@"languageassetd.plist",
		@"ptpcamerad.plist",
		@"com.google.gmp.measurement.monitor.plist",
		@"com.google.gmp.measurement.plist",
	];

	return ![additionalSystemPlistNames containsObject:plistName];
}

%hookf(BOOL, _CFPrefsGetPathForTriplet, CFStringRef bundleIdentifier, CFStringRef user, BOOL byHost, CFStringRef path, UInt8 *buffer)
{
	BOOL orig = %orig(bundleIdentifier, user, byHost, path, buffer);

	if(orig && buffer && !access("/var/jb", F_OK))
	{
		NSString* origPath = [NSString stringWithUTF8String:(char*)buffer];
		BOOL needsRedirection = preferencePlistNeedsRedirection(origPath);
		if (needsRedirection) {
			//NSLog(@"Plist redirected to /var/jb: %@", origPath);
			strcpy((char*)buffer, "/var/jb");
			strcat((char*)buffer, origPath.UTF8String);
		}
	}

	return orig;
}

// ---------------------------------------------------------------------------
// Mirror com.apple.networkextension.plist writes to JB path so that
// per-app cellular rules for JB apps survive across jailbreak sessions.
//
// nehelper writes the NE plist via CFPreferences XPC -> cfprefsd -> disk.
// cfprefsd is the actual process that calls NSData -writeToFile:*.
// We hook both write variants here and make an additional copy at the JB path.
// ---------------------------------------------------------------------------

static NSString *gJBNEPlistPath = nil;
static dispatch_once_t gJBNEPlistOnce;

static NSString *jbNEPlistPath(void)
{
	dispatch_once(&gJBNEPlistOnce, ^{
		// Mirror path inside JB root: <jbroot>/Library/Preferences/com.apple.networkextension.plist
		gJBNEPlistPath = [NSString stringWithUTF8String:
		    JBROOT_PATH_CSTRING("/Library/Preferences/com.apple.networkextension.plist")];
	});
	return gJBNEPlistPath;
}

static BOOL isNEPlist(NSString *path)
{
	return [path hasSuffix:@"com.apple.networkextension.plist"];
}

// Prevent recursive hook calls when we write the mirror file ourselves.
static __thread BOOL gCFMirroring = NO;

static BOOL (*orig_cfprefsd_writeToFile_options_error)(NSData *self, SEL _cmd, NSString *path, NSDataWritingOptions opts, NSError **error);
static BOOL hook_cfprefsd_writeToFile_options_error(NSData *self, SEL _cmd, NSString *path, NSDataWritingOptions opts, NSError **error)
{
	BOOL result = orig_cfprefsd_writeToFile_options_error(self, _cmd, path, opts, error);
	if (!gCFMirroring && isNEPlist(path)) {
		gCFMirroring = YES;
		NSString *mirrorPath = jbNEPlistPath();
		// Ensure parent directory exists
		NSString *dir = [mirrorPath stringByDeletingLastPathComponent];
		[[NSFileManager defaultManager] createDirectoryAtPath:dir
		                      withIntermediateDirectories:YES
		                                       attributes:nil
		                                           error:nil];
		BOOL ok = [self writeToFile:mirrorPath options:NSDataWritingAtomic error:nil];
		(void)ok; // Mirror failure is non-fatal
		gCFMirroring = NO;
	}
	return result;
}

static BOOL (*orig_cfprefsd_writeToFile_atomically)(NSData *self, SEL _cmd, NSString *path, BOOL atomically);
static BOOL hook_cfprefsd_writeToFile_atomically(NSData *self, SEL _cmd, NSString *path, BOOL atomically)
{
	BOOL result = orig_cfprefsd_writeToFile_atomically(self, _cmd, path, atomically);
	if (!gCFMirroring && isNEPlist(path)) {
		gCFMirroring = YES;
		NSString *mirrorPath = jbNEPlistPath();
		NSString *dir = [mirrorPath stringByDeletingLastPathComponent];
		[[NSFileManager defaultManager] createDirectoryAtPath:dir
		                      withIntermediateDirectories:YES
		                                       attributes:nil
		                                           error:nil];
		[self writeToFile:mirrorPath atomically:YES];
		gCFMirroring = NO;
	}
	return result;
}

void cfprefsdInit(void)
{
	MSImageRef coreFoundationImage = MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
	if (coreFoundationImage) {
		%init(_CFPrefsGetPathForTriplet = MSFindSymbol(coreFoundationImage, "__CFPrefsGetPathForTriplet"));
	}

	// Hook NSData write methods in cfprefsd to mirror NE plist writes to JB path.
	MSHookMessageEx(
		objc_getClass("NSData"),
		@selector(writeToFile:options:error:),
		(IMP)hook_cfprefsd_writeToFile_options_error,
		(IMP *)&orig_cfprefsd_writeToFile_options_error
	);
	MSHookMessageEx(
		objc_getClass("NSData"),
		@selector(writeToFile:atomically:),
		(IMP)hook_cfprefsd_writeToFile_atomically,
		(IMP *)&orig_cfprefsd_writeToFile_atomically
	);
}
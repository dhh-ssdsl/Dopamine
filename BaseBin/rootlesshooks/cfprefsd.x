#import <Foundation/Foundation.h>
#import <substrate.h>
#import <limits.h>
#import <string.h>
#import "perm_router.h"

BOOL preferencePlistNeedsRedirection(NSString *plistPath)
{
	if ([plistPath hasPrefix:@"/private/var/mobile/Containers"] ||
	    [plistPath hasPrefix:@"/var/db"] ||
	    perm_is_path_under_jbroot(plistPath)) {
		return NO;
	}

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

	if(orig && buffer)
	{
		NSString* origPath = [NSString stringWithUTF8String:(char*)buffer];
		BOOL needsRedirection = preferencePlistNeedsRedirection(origPath);
		if (needsRedirection) {
			char mirroredPath[PATH_MAX];
			if (perm_jb_mirror_path_c(origPath.UTF8String, mirroredPath, sizeof(mirroredPath)) == 0) {
				strlcpy((char *)buffer, mirroredPath, PATH_MAX);
			}
		}
	}

	return orig;
}

void cfprefsdInit(void)
{
	MSImageRef coreFoundationImage = MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
	if (coreFoundationImage) {
		%init(_CFPrefsGetPathForTriplet = MSFindSymbol(coreFoundationImage, "__CFPrefsGetPathForTriplet"));
	}
}

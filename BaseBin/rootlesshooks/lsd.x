#import <Foundation/Foundation.h>
#import <libjailbreak/util.h>
#import <libroot.h>
#import <notify.h>

%hookf(NSURL *, _LSGetInboxURLForBundleIdentifier, NSString *bundleIdentifier)
{
	NSURL *origURL = %orig;
	if (![bundleIdentifier hasPrefix:@"com.apple"] && [origURL.path hasPrefix:@"/var/mobile/Library/Application Support/Containers/"]) {
		return [NSURL fileURLWithPath:JBROOT_PATH_NSSTRING(origURL.path)];
	}
	return origURL;
}

%hookf(int, _LSServer_RebuildApplicationDatabases)
{
	int r = %orig;

	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		// Ensure jailbreak apps are readded to icon cache after the system reloads it
		// A bit hacky, but works
		const char *uicachePath = JBROOT_PATH_CSTRING("/usr/bin/uicache");
		if (!access(uicachePath, F_OK)) {
			exec_cmd(uicachePath, "-a", NULL);
			// After uicache finishes, notify SpringBoard to reload its icon model
			// This ensures jailbreak app icons appear on the home screen immediately
			notify_post("com.apple.mobile.application_installed");
		}
	});

	return r;
}

void lsdInit(void)
{
	MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
	if (coreServicesImage) {
		%init(_LSGetInboxURLForBundleIdentifier = MSFindSymbol(coreServicesImage, "__LSGetInboxURLForBundleIdentifier"),
		  _LSServer_RebuildApplicationDatabases = MSFindSymbol(coreServicesImage, "__LSServer_RebuildApplicationDatabases"));
	}
}
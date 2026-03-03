#import <Foundation/Foundation.h>
#import <libjailbreak/util.h>
#import <libroot.h>
#import <notify.h>
#import <fcntl.h>
#import <unistd.h>

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

	// This function is called when lsd rebuilds its database from scratch.
	// This happens during userspace reboot (NOT during respring).
	// The rebuild WIPES any earlier app registrations (e.g. from jbctl startup),
	// so we must re-run uicache AFTER this rebuild completes.

	// Delete SpringBoard session marker so it knows this is userspace reboot.
	const char *sbSessionFlag = JBROOT_PATH_CSTRING("/basebin/.sb_session");
	unlink(sbSessionFlag);

	// Invalidate any premature .uicache_done from jbctl startup
	// (those registrations were wiped by the rebuild above).
	const char *uicacheDoneFlagPath = JBROOT_PATH_CSTRING("/basebin/.uicache_done");
	unlink(uicacheDoneFlagPath);

	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		const char *uicachePath = JBROOT_PATH_CSTRING("/usr/bin/uicache");
		if (!access(uicachePath, F_OK)) {
			exec_cmd(uicachePath, "-a", NULL);
		}

		// Signal that all jailbreak apps are now registered.
		// SpringBoard is waiting for this in its constructor (before UI loads).
		int fd = open(uicacheDoneFlagPath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) close(fd);

		// Notify SpringBoard to reload icon model in one batch.
		notify_post("com.apple.mobile.application_installed");
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
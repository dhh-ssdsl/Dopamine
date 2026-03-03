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
	// Place a lock BEFORE calling orig — this tells SpringBoard that a
	// database rebuild is in progress and any existing .uicache_done is stale.
	const char *rebuildLockPath = JBROOT_PATH_CSTRING("/basebin/.lsd_rebuilding");
	int lockFd = open(rebuildLockPath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (lockFd >= 0) close(lockFd);

	int r = %orig;

	// The rebuild WIPES any earlier app registrations (e.g. from jbctl startup),
	// so we must re-run uicache AFTER this rebuild completes.

	// Delete SpringBoard session marker so it knows this is userspace reboot.
	const char *sbSessionFlag = JBROOT_PATH_CSTRING("/basebin/.sb_session");
	unlink(sbSessionFlag);

	// Invalidate any premature .uicache_done from jbctl startup.
	const char *uicacheDoneFlagPath = JBROOT_PATH_CSTRING("/basebin/.uicache_done");
	unlink(uicacheDoneFlagPath);

	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		const char *uicachePath = JBROOT_PATH_CSTRING("/usr/bin/uicache");
		if (!access(uicachePath, F_OK)) {
			exec_cmd(uicachePath, "-a", NULL);
		}

		// Remove the rebuild lock, then signal done.
		unlink(rebuildLockPath);

		int fd = open(uicacheDoneFlagPath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) close(fd);

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
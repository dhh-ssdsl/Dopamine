#import <Foundation/Foundation.h>
#import <libjailbreak/util.h>
#import <libroot.h>
#import <notify.h>
#import <fcntl.h>
#import <unistd.h>

static void _lsd_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _lsd_log(const char *fmt, ...) {
	FILE *f = fopen(JBROOT_PATH_CSTRING("/basebin/hook_debug.log"), "a");
	if (!f) return;
	time_t t = time(NULL);
	struct tm tm; localtime_r(&t, &tm);
	fprintf(f, "%02d:%02d:%02d [LSD] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
	va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
	fprintf(f, "\n"); fclose(f);
}
#define LSD_LOG(fmt, ...) _lsd_log(fmt, ##__VA_ARGS__)

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
	LSD_LOG("_LSServer_RebuildApplicationDatabases CALLED");

	// Place a lock BEFORE calling orig — this tells SpringBoard that a
	// database rebuild is in progress and any existing .uicache_done is stale.
	const char *rebuildLockPath = JBROOT_PATH_CSTRING("/basebin/.lsd_rebuilding");
	int lockFd = open(rebuildLockPath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (lockFd >= 0) close(lockFd);

	int r = %orig;
	LSD_LOG("_LSServer_RebuildApplicationDatabases orig returned %d", r);

	// The rebuild WIPES any earlier app registrations (e.g. from jbctl startup),
	// so we must re-run uicache AFTER this rebuild completes.

	// Delete SpringBoard session marker so it knows this is userspace reboot.
	const char *sbSessionFlag = JBROOT_PATH_CSTRING("/basebin/.sb_session");
	unlink(sbSessionFlag);

	// Invalidate any premature .uicache_done from jbctl startup.
	const char *uicacheDoneFlagPath = JBROOT_PATH_CSTRING("/basebin/.uicache_done");
	unlink(uicacheDoneFlagPath);

	LSD_LOG("Dispatching async uicache after rebuild");
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		const char *uicachePath = JBROOT_PATH_CSTRING("/usr/bin/uicache");
		if (!access(uicachePath, F_OK)) {
			LSD_LOG("Running uicache -a");
			exec_cmd(uicachePath, "-a", NULL);
			LSD_LOG("uicache -a completed");
		} else {
			LSD_LOG("ERROR: uicache not found at %s", uicachePath);
		}

		// Remove the rebuild lock, then signal done.
		unlink(rebuildLockPath);

		int fd = open(uicacheDoneFlagPath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) close(fd);
		LSD_LOG("Created .uicache_done, removed .lsd_rebuilding");

		notify_post("com.apple.mobile.application_installed");
	});

	return r;
}

void lsdInit(void)
{
	LSD_LOG("lsdInit() called (pid=%d)", getpid());
	MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
	if (coreServicesImage) {
		void *inboxSym = MSFindSymbol(coreServicesImage, "__LSGetInboxURLForBundleIdentifier");
		void *rebuildSym = MSFindSymbol(coreServicesImage, "__LSServer_RebuildApplicationDatabases");
		LSD_LOG("CoreServices found. _LSGetInboxURL=%p, _LSServer_RebuildAppDB=%p", inboxSym, rebuildSym);

		if (!rebuildSym) {
			// Symbol not found in CoreServices, try lsd main binary
			MSImageRef lsdImage = MSGetImageByName("/usr/libexec/lsd");
			if (lsdImage) {
				rebuildSym = MSFindSymbol(lsdImage, "__LSServer_RebuildApplicationDatabases");
				LSD_LOG("Tried lsd binary: _LSServer_RebuildAppDB=%p", rebuildSym);
			}
		}

		%init(_LSGetInboxURLForBundleIdentifier = inboxSym,
		  _LSServer_RebuildApplicationDatabases = rebuildSym);
		LSD_LOG("Hooks installed");
	} else {
		LSD_LOG("ERROR: CoreServices.framework not found!");
	}
}
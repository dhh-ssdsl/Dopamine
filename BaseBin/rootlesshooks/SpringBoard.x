#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/objc.h>
#import <objc/runtime.h>
#import <libroot.h>
#import <libjailbreak/util.h>
#import <fcntl.h>
#import <unistd.h>
#import <notify.h>

static void _sb_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _sb_log(const char *fmt, ...) {
	FILE *f = fopen(JBROOT_PATH_CSTRING("/var/mobile/hook_debug.log"), "a");
	if (!f) return;
	time_t t = time(NULL);
	struct tm tm; localtime_r(&t, &tm);
	fprintf(f, "%02d:%02d:%02d [SpringBoard] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
	va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
	fprintf(f, "\n"); fclose(f);
}
#define SB_LOG(fmt, ...) _sb_log(fmt, ##__VA_ARGS__)

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

@interface XBSnapshotContainerIdentity : NSObject <NSCopying>
@property (nonatomic, readonly, copy) NSString* bundleIdentifier;
- (NSString*)snapshotContainerPath;
@end

%hook XBSnapshotContainerIdentity

- (NSString *)snapshotContainerPath
{
	NSString *path = %orig;
	if([path hasPrefix:@"/var/mobile/Library/SplashBoard/Snapshots/"] && ![self.bundleIdentifier hasPrefix:@"com.apple."]) {
		return JBROOT_PATH_NSSTRING(path);
	}
	return path;
}

%end

%hookf(int, fcntl, int fildes, int cmd, ...) {
	if (cmd == F_SETPROTECTIONCLASS) {
		char filePath[PATH_MAX];
		if (fcntl(fildes, F_GETPATH, filePath) != -1) {
			// Skip setting protection class on jailbreak apps, this doesn't work and causes snapshots to not be saved correctly
			if (string_has_prefix(filePath, JBROOT_PATH_CSTRING("/var/mobile/Library/SplashBoard/Snapshots"))) {
				return 0;
			}
		}
	}

	va_list a;
	va_start(a, cmd);
	const char *arg1 = va_arg(a, void *);
	const void *arg2 = va_arg(a, void *);
	const void *arg3 = va_arg(a, void *);
	const void *arg4 = va_arg(a, void *);
	const void *arg5 = va_arg(a, void *);
	const void *arg6 = va_arg(a, void *);
	const void *arg7 = va_arg(a, void *);
	const void *arg8 = va_arg(a, void *);
	const void *arg9 = va_arg(a, void *);
	const void *arg10 = va_arg(a, void *);
	va_end(a);
	return %orig(fildes, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

void springboardInit(void)
{
	SB_LOG("springboardInit() called (pid=%d)", getpid());

	const char *uicacheDoneFlagPath = "/private/var/tmp/.uicache_done";
	const char *rebuildLockPath = "/private/var/tmp/.lsd_rebuilding";
	// Stored in /private/var/tmp/ which is cleared on userspace reboot but
	// preserved across resprings — no need for lsd to manually delete it.
	const char *sbSessionFlag = "/private/var/tmp/.sb_session";

	bool isRespring = (access(sbSessionFlag, F_OK) == 0);
	SB_LOG("isRespring=%d sbSessionFlag=%s", isRespring, sbSessionFlag);

	if (!isRespring) {
		// Userspace reboot or first activation: icons are lost after lsd rebuild.
		//
		// CRITICAL: jbctl startup creates .uicache_done BEFORE lsd starts.
		// But then lsd's _LSServer_RebuildApplicationDatabases WIPES all
		// registrations. We must wait for lsd's POST-rebuild uicache, not
		// jbctl's premature one.
		//
		// Delete any stale .uicache_done from jbctl, then wait for lsd
		// to create a fresh one after its rebuild + re-uicache.
		unlink(uicacheDoneFlagPath);
		SB_LOG("Deleted stale .uicache_done, entering wait loop");

		// NEVER run uicache from SpringBoard synchronously — it can deadlock
		// if lsd isn't ready, causing ldrestart to freeze the device.
		//
		// Wait up to 25s. SpringBoard watchdog is ~30s, leave margin.
		bool gotSignal = false;
		for (int i = 0; i < 250; i++) {
			// If lsd is rebuilding, any existing .uicache_done is stale — keep waiting.
			if (access(rebuildLockPath, F_OK) == 0) {
				usleep(100000);
				continue;
			}
			if (access(uicacheDoneFlagPath, F_OK) == 0) {
				SB_LOG("Got .uicache_done signal after %d iterations (%dms)", i, i * 100);
				unlink(uicacheDoneFlagPath);
				gotSignal = true;
				break;
			}
			usleep(100000); // 100ms
		}

		if (!gotSignal) {
			// Timeout — lsd hook may not have fired. Run uicache ASYNC as
			// fallback. Async is safe: SpringBoard's run loop will be active
			// so uicache can communicate with lsd normally. No deadlock risk.
			SB_LOG("WARNING: Timed out waiting for lsd signal, dispatching fallback uicache");
			dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
				const char *uicachePath = JBROOT_PATH_CSTRING("/usr/bin/uicache");
				if (!access(uicachePath, F_OK)) {
					SB_LOG("Running fallback uicache -a");
					exec_cmd(uicachePath, "-a", NULL);
					SB_LOG("Fallback uicache completed");
					notify_post("com.apple.mobile.application_installed");
				}
			});
		}
	}
	// else: respring — lsd still running, icon cache intact, skip.

	// Mark session. lsd.x deletes this on userspace reboot.
	int fd = open(sbSessionFlag, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) close(fd);

	%init();
}

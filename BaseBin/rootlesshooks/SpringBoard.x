#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/objc.h>
#import <objc/runtime.h>
#import <libroot.h>
#import <libjailbreak/util.h>
#import <fcntl.h>
#import <unistd.h>
#import <notify.h>

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
	const char *uicacheDoneFlagPath = JBROOT_PATH_CSTRING("/basebin/.uicache_done");
	const char *rebuildLockPath = JBROOT_PATH_CSTRING("/basebin/.lsd_rebuilding");
	// Created by SpringBoard, deleted by lsd.x when _LSServer_RebuildApplicationDatabases
	// fires (which only happens during userspace reboot, not respring).
	const char *sbSessionFlag = JBROOT_PATH_CSTRING("/basebin/.sb_session");

	bool isRespring = (access(sbSessionFlag, F_OK) == 0);

	if (!isRespring) {
		// Userspace reboot or first activation: icons are lost.
		// Wait for uicache to complete (run by lsd.x after DB rebuild).
		// We are in %ctor — UI and run loop are NOT active yet.
		//
		// NEVER run uicache from SpringBoard — it can deadlock if lsd isn't
		// ready, causing ldrestart to freeze the device.
		//
		// Wait up to 25s. SpringBoard watchdog is ~30s, leave margin.
		for (int i = 0; i < 250; i++) {
			// If lsd is rebuilding, any existing .uicache_done is stale — keep waiting.
			if (access(rebuildLockPath, F_OK) == 0) {
				usleep(100000);
				continue;
			}
			if (access(uicacheDoneFlagPath, F_OK) == 0) {
				unlink(uicacheDoneFlagPath);
				break;
			}
			usleep(100000); // 100ms
		}
	}
	// else: respring — lsd still running, icon cache intact, skip.

	// Mark session. lsd.x deletes this on userspace reboot.
	int fd = open(sbSessionFlag, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) close(fd);

	%init();
}

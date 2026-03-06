#import "internal.h"
#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <pwd.h>
#import <fcntl.h>
#import <unistd.h>
#import <stdarg.h>
#import <time.h>
#import <stdio.h>

SInt32 CFUserNotificationDisplayAlert(CFTimeInterval timeout, CFOptionFlags flags, CFURLRef iconURL, CFURLRef soundURL, CFURLRef localizationURL, CFStringRef alertHeader, CFStringRef alertMessage, CFStringRef defaultButtonTitle, CFStringRef alternateButtonTitle, CFStringRef otherButtonTitle, CFOptionFlags *responseFlags) API_AVAILABLE(ios(3.0));

static void internal_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void internal_log(const char *fmt, ...)
{
	FILE *f = fopen(JBROOT_PATH("/var/mobile/hook_debug.log"), "a");
	if (!f) return;

	time_t t = time(NULL);
	struct tm tm;
	localtime_r(&t, &tm);
	fprintf(f, "%02d:%02d:%02d [jbctl] ", tm.tm_hour, tm.tm_min, tm.tm_sec);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fprintf(f, "\n");
	fclose(f);
}

void execute_unsandboxed(void (^block)(void))
{
	uint64_t credBackup = 0;
	jbclient_root_steal_ucred(0, &credBackup);
	block();
	jbclient_root_steal_ucred(credBackup, NULL);
}

int mount_unsandboxed(const char *type, const char *dir, int flags, void *data)
{
	__block int r = 0;
	execute_unsandboxed(^{
		r = mount(type, dir, flags, data);
	});
	return r;
}

int unmount_unsandboxed(const char *dir, int flags)
{
	__block int r = 0;
	execute_unsandboxed(^{
		r = unmount(dir, flags);
	});
	return r;
}

bool is_protected(const char *path)
{
	struct statfs sb;
	statfs(path, &sb);
	return strcmp(path, sb.f_mntonname) == 0;
}

int ensure_protected(const char *path)
{
	if (!is_protected(path)) {
		return mount_unsandboxed("bindfs", path, 0, (void *)path);
	}
	return 0;
}

int ensure_unprotected(const char *path)
{
	if (is_protected(path)) {
		return unmount_unsandboxed(path, MNT_FORCE);
	}
	return 0;
}

int protection_set_active(bool active)
{
	int r = 0;
	if (active) {
		// Protect /private/preboot/UUID/<System, usr> from being modified by bind mounting them on top of themselves
		// This protects dumb users from accidentally deleting these, which would induce a recovery loop after rebooting
		r |= ensure_protected(prebootUUIDPath("/System"));
		r |= ensure_protected(prebootUUIDPath("/usr"));
	}
	else {
		r |= ensure_unprotected(prebootUUIDPath("/System"));
		r |= ensure_unprotected(prebootUUIDPath("/usr"));
	}
	return r;
}

bool fakelib_is_mounted(void)
{
	struct statfs fsb;
    if (statfs("/usr/lib", &fsb) != 0) return NO;
    return strcmp(fsb.f_mntonname, "/usr/lib") == 0;
}

int fakelib_set_mounted(bool mounted)
{
	int r = 0;
	if (mounted != fakelib_is_mounted()) {
		if (mounted) {
			r = mount_unsandboxed("bindfs", "/usr/lib", MNT_RDONLY, (void *)JBROOT_PATH("/basebin/.fakelib"));
		}
		else {
			r = unmount_unsandboxed("/usr/lib", MNT_FORCE);
		}
	}
	return r;
}

int jbctl_handle_internal(const char *command, int argc, char* argv[])
{
	if (!strcmp(command, "launchd_stash_port")) {
		mach_port_t *selfInitPorts = NULL;
		mach_msg_type_number_t selfInitPortsCount = 0;
		if (mach_ports_lookup(mach_task_self(), &selfInitPorts, &selfInitPortsCount) != 0) {
			printf("ERROR: Failed port lookup on self\n");
			return -1;
		}
		if (selfInitPortsCount < 3) {
			printf("ERROR: Unexpected initports count on self\n");
			return -1;
		}
		if (selfInitPorts[2] == MACH_PORT_NULL) {
			printf("ERROR: Port to stash not set\n");
			return -1;
		}

		printf("Port to stash: %u\n", selfInitPorts[2]);

		mach_port_t launchdTaskPort;
		if (task_for_pid(mach_task_self(), 1, &launchdTaskPort) != 0) {
			printf("task_for_pid on launchd failed\n");
			return -1;
		}
		mach_port_t *launchdInitPorts = NULL;
		mach_msg_type_number_t launchdInitPortsCount = 0;
		if (mach_ports_lookup(launchdTaskPort, &launchdInitPorts, &launchdInitPortsCount) != 0) {
			printf("mach_ports_lookup on launchd failed\n");
			return -1;
		}
		if (launchdInitPortsCount < 3) {
			printf("ERROR: Unexpected initports count on launchd\n");
			return -1;
		}
		launchdInitPorts[2] = selfInitPorts[2]; // Transfer port to launchd
		if (mach_ports_register(launchdTaskPort, launchdInitPorts, launchdInitPortsCount) != 0) {
			printf("ERROR: Failed stashing port into launchd\n");
			return -1;
		}
		mach_port_deallocate(mach_task_self(), launchdTaskPort);
		return 0;
	}
	else if (!strcmp(command, "protection")) {
		bool toSet = false;
		if (argc > 1) {
			if (!strcmp(argv[1], "activate")) {
				toSet = true;
			}
			else if (!strcmp(argv[1], "deactivate")) {
				toSet = false;
			}
			else {
				return -1;
			}

			return protection_set_active(toSet);
		}
		return -1;
	}
	else if (!strcmp(command, "fakelib")) {
		bool toMount = false;
		if (argc > 1) {
			if (!strcmp(argv[1], "mount")) {
				toMount = true;
			}
			else if (!strcmp(argv[1], "unmount")) {
				toMount = false;
			}
			else {
				return -1;
			}

			return fakelib_set_mounted(toMount);
		}
		return -1;
	}
	else if (!strcmp(command, "startup")) {
		protection_set_active(true);

		// Ensure the JB-side directory for CommCenter cellular routing exists
		// and mirrors the system-side owner/layout before the privileged writer starts.
		{
			const char *wirelessDir = JBROOT_PATH("/var/wireless");
			const char *wirelessLibraryDir = JBROOT_PATH("/var/wireless/Library");
			const char *wirelessPrefsDir = JBROOT_PATH("/var/wireless/Library/Preferences");
			const char *wirelessDbDir = JBROOT_PATH("/var/wireless/Library/Databases");
			const char *wirelessCellularDbPath = JBROOT_PATH("/var/wireless/Library/Databases/CellularUsage.db");
			const char *wirelessPaths[] = { wirelessDir, wirelessLibraryDir, wirelessPrefsDir, wirelessDbDir };
			struct passwd *pw = getpwnam("_wireless");

			for (size_t i = 0; i < sizeof(wirelessPaths) / sizeof(wirelessPaths[0]); i++) {
				const char *path = wirelessPaths[i];
				[[NSFileManager defaultManager]
					createDirectoryAtPath:[NSString stringWithUTF8String:path]
					withIntermediateDirectories:YES
					attributes:nil
					error:nil];

				// Existing directories may already be present with root ownership.
				// Always repair owner/mode so the mirror matches the system-side layout.
				if (pw) {
					chown(path, pw->pw_uid, pw->pw_gid);
					chmod(path, 0755);
				}
			}

			// Pre-create the JB mirror cellular DB so CommCenter can ATTACH it
			// even on first boot before any routing write path has run.
			int dbfd = open(wirelessCellularDbPath, O_CREAT | O_RDWR, 0644);
			if (dbfd >= 0) close(dbfd);
			if (pw) {
				chown(wirelessCellularDbPath, pw->pw_uid, pw->pw_gid);
				chmod(wirelessCellularDbPath, 0644);
			}
		}

		// Avoid blocking the watchdog-sensitive startup path on launchctl kickstart.
		// CommCenter and its helper will still be injected when launchd starts them.
		internal_log("startup: skipping CommCenter kickstart to avoid blocking startup");

		char *panicMessage = NULL;
		if (jbclient_watchdog_get_last_userspace_panic(&panicMessage) == 0) {
			NSString *printMessage = [NSString stringWithFormat:@"Dopamine has protected you from a userspace panic by temporarily disabling tweak injection and triggering a userspace reboot instead. A log is available under Analytics in the Preferences app. You can reenable tweak injection in the Dopamine app.\n\nPanic message: \n%s", panicMessage];
			CFUserNotificationDisplayAlert(0, 2/*kCFUserNotificationCautionAlertLevel*/, NULL, NULL, NULL, CFSTR("Watchdog Timeout"), (__bridge CFStringRef)printMessage, NULL, NULL, NULL, NULL);
			free(panicMessage);
		}

		exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);

		const char *uicacheDoneFlagPath = "/private/var/tmp/.uicache_done";
		int fd = open(uicacheDoneFlagPath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) close(fd);
	}
	else if (!strcmp(command, "install_pkg")) {
		if (argc > 1) {
			extern char **environ;
			const char *dpkg = JBROOT_PATH("/usr/bin/dpkg");
			int r = execve(dpkg, (char *const *)(const char *[]){dpkg, "-i", argv[1], NULL}, environ);
			return r;
		}
		return -1;
	}
	return -1;
}

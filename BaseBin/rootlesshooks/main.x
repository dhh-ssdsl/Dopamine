#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <stdlib.h>
#import <libroot.h>
#import <time.h>
#import <stdio.h>

static void rootlesshooks_log(const char *tag, NSString *processName, NSString *executablePath)
{
	FILE *f = fopen(JBROOT_PATH_CSTRING("/var/mobile/hook_debug.log"), "a");
	if (!f) return;

	time_t t = time(NULL);
	struct tm tm;
	localtime_r(&t, &tm);
	const char *tagValue = tag ? tag : "rootlesshooks";
	const char *processValue = processName.UTF8String ? processName.UTF8String : "(null)";
	const char *pathValue = executablePath.UTF8String ? executablePath.UTF8String : "(null)";
	fprintf(f, "%02d:%02d:%02d [%s] process=%s path=%s\n",
	        tm.tm_hour,
	        tm.tm_min,
	        tm.tm_sec,
	        tagValue,
	        processValue,
	        pathValue);
	fclose(f);
}

NSString* safe_getExecutablePath()
{
	char executablePathC[PATH_MAX];
	uint32_t executablePathCSize = sizeof(executablePathC);
	if (_NSGetExecutablePath(&executablePathC[0], &executablePathCSize) == 0) {
		return [NSString stringWithUTF8String:executablePathC];
	}
	const char *progName = getprogname();
	return progName ? [NSString stringWithUTF8String:progName] : @"";
}

NSString* getProcessName()
{
	NSString *exePath = safe_getExecutablePath();
	return exePath.lastPathComponent ?: exePath;
}

%ctor
{
	NSString *executablePath = safe_getExecutablePath();
	NSString *processName = getProcessName();
	/*if ([processName isEqualToString:@"installd"]) {
		extern void installdInit(void);
		installdInit();
	}
	else*/ if ([processName isEqualToString:@"cfprefsd"]) {
		extern void cfprefsdInit(void);
		cfprefsdInit();
	}
	else if ([processName isEqualToString:@"SpringBoard"]) {
		extern void bulletinboarddInit(void);
		bulletinboarddInit();
		extern void springboardInit(void);
		springboardInit();
	}
	else if ([processName isEqualToString:@"lsd"]) {
		extern void lsdInit(void);
		lsdInit();
	}
	else if ([processName isEqualToString:@"tccd"]) {
		extern void tccdInit(void);
		tccdInit();
	}
	else if ([processName hasPrefix:@"CommCenter"] ||
	         [executablePath isEqualToString:@"/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter"] ||
	         [executablePath isEqualToString:@"/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenterMobileHelper"] ||
	         [executablePath containsString:@"/CommCenter"]) {
		rootlesshooks_log("rootlesshooks", processName, executablePath);
		extern void commcenterInit(void);
		commcenterInit();
	}
	else if ([processName isEqualToString:@"nehelper"] ||
	         [processName isEqualToString:@"symptomsd"] ||
	         [processName isEqualToString:@"networkd"] ||
	         [processName isEqualToString:@"nesessionmanager"]) {
		extern void nehelperInit(void);
		nehelperInit();
	}
}

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <stdlib.h>

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
		extern void commcenterInit(void);
		commcenterInit();
		extern void nehelperInit(void);
		nehelperInit();
	}
	else if ([processName isEqualToString:@"nehelper"] ||
	         [processName isEqualToString:@"symptomsd"] ||
	         [processName isEqualToString:@"networkd"] ||
	         [processName isEqualToString:@"nesessionmanager"]) {
		extern void nehelperInit(void);
		nehelperInit();
	}
}

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>

NSString* safe_getExecutablePath()
{
	char executablePathC[PATH_MAX];
	uint32_t executablePathCSize = sizeof(executablePathC);
	_NSGetExecutablePath(&executablePathC[0], &executablePathCSize);
	return [NSString stringWithUTF8String:executablePathC];
}

NSString* getProcessName()
{
	return safe_getExecutablePath().lastPathComponent;
}

%ctor
{
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
	else if ([processName hasPrefix:@"CommCenter"]) {
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

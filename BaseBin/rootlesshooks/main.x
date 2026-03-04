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
	else if ([processName isEqualToString:@"CommCenter"] || [processName isEqualToString:@"CommCenterMobileHelper"]) {
		extern void commcenterInit(void);
		commcenterInit();
	}
	else if ([processName isEqualToString:@"nehelper"]) {
		extern void nehelperInit(void);
		nehelperInit();
	}
	else if ([processName isEqualToString:@"Preferences"]) {
		// Settings.app runs as its own process named "Preferences".
		// It reads BulletinBoard plists directly via NSData to show
		// "Settings → Notifications". Install read-only hooks so it
		// sees merged JB app notification entries from the JB-side plist.
		// (Confirmed via ps aux: /Applications/Preferences.app/Preferences
		//  runs as a standalone process; no bulletind/usernoted on this device.)
		extern void bulletinboarddReadOnlyInit(void);
		bulletinboarddReadOnlyInit();
	}
}
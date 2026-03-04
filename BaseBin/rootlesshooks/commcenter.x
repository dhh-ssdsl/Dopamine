#import <Foundation/Foundation.h>
#import <libroot.h>

// CommCenter cellular routing removed.
// Per-app cellular data (联网权限) on iOS is managed by nehelper
// via com.apple.networkextension.plist, not CellularUsage.db.
// See nehelper.x for the actual implementation.

void commcenterInit(void)
{
	// No-op
}

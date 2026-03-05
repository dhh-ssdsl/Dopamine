#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, PERMBundleClass) {
	PERMBundleClassSystem = 0,
	PERMBundleClassJailbreak = 1,
};

NSString * _Nullable perm_jb_root_prefix_ns(void);
NSString * _Nullable perm_jb_mirror_path_ns(NSString * _Nullable systemPath);
int perm_jb_mirror_path_c(const char * _Nullable systemPath, char * _Nonnull outPath, size_t outSize);

BOOL perm_is_path_under_jbroot(NSString * _Nullable path);
PERMBundleClass perm_classify_bundle_id(NSString * _Nullable bundleID);
BOOL perm_is_jailbreak_bundle_id(NSString * _Nullable bundleID);

NSArray *perm_merge_array_jb_first(NSArray * _Nullable systemRecords,
                                   NSArray * _Nullable jbRecords,
                                   NSString * _Nullable (^ _Nullable keyBlock)(id record));

BOOL perm_migration_is_done(NSString * _Nullable domainKey);
void perm_migration_mark_done(NSString * _Nullable domainKey);
void perm_ensure_parent_dir_for_path(NSString * _Nullable path);

NS_ASSUME_NONNULL_END

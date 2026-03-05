#import <Foundation/Foundation.h>
#import <substrate.h>
#import <sqlite3.h>
#import <limits.h>
#import <libroot.h>
#import <string.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import "perm_router.h"

// sqlite3_db_filename is available on iOS 6+.
extern const char *sqlite3_db_filename(sqlite3 *db, const char *zDbName);

static void _cc_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _cc_log(const char *fmt, ...)
{
	FILE *f = fopen(JBROOT_PATH_CSTRING("/var/mobile/hook_debug.log"), "a");
	if (!f) return;
	time_t t = time(NULL);
	struct tm tm; localtime_r(&t, &tm);
	fprintf(f, "%02d:%02d:%02d [CommCenter] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
	va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
	fprintf(f, "\n"); fclose(f);
}
#define CC_LOG(fmt, ...) _cc_log(fmt, ##__VA_ARGS__)

static sqlite3 *gCellularDB = NULL;
static NSString *gJBCellularPath = nil;
static BOOL gRoutingReady = NO;
static __thread BOOL gBypassRewrite = NO;

static int (*orig_sqlite3_open)(const char *filename, sqlite3 **ppDb);
static int (*orig_sqlite3_open_v2)(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
static int (*orig_sqlite3_prepare_v2)(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
static int (*orig_sqlite3_exec)(sqlite3 *db, const char *sql, int (*callback)(void*, int, char**, char**), void *arg, char **errmsg);

static BOOL isCellularUsageDBPath(const char *filename)
{
	return (filename && strstr(filename, "CellularUsage.db"));
}

static bool isJailbreakBundleID(const char *bundleID)
{
	if (!bundleID) return false;
	NSString *bid = [NSString stringWithUTF8String:bundleID];
	if (!bid.length) return false;
	return perm_is_jailbreak_bundle_id(bid);
}

static void sqlite_jb_is_client(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	if (argc != 1) {
		sqlite3_result_int(context, 0);
		return;
	}
	const unsigned char *client = sqlite3_value_text(argv[0]);
	sqlite3_result_int(context, isJailbreakBundleID((const char *)client) ? 1 : 0);
}

static NSString *legacyJBCellularDBPath(void)
{
	static NSString *path = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		path = perm_jb_mirror_path_ns(@"/var/wireless/Library/Databases/.jb_cellular.db");
	});
	return path;
}

static void migrateLegacyJBCellularDBIfNeeded(NSString *targetPath)
{
	if (!targetPath.length) return;

	NSString *legacyPath = legacyJBCellularDBPath();
	if (!legacyPath.length || [legacyPath isEqualToString:targetPath]) return;

	NSFileManager *fm = [NSFileManager defaultManager];
	if (![fm fileExistsAtPath:legacyPath]) return;

	if ([fm fileExistsAtPath:targetPath]) {
		CC_LOG("migrateLegacyJBCellularDBIfNeeded: target exists, keeping legacy file");
		return;
	}

	perm_ensure_parent_dir_for_path(targetPath);
	NSError *moveErr = nil;
	BOOL moved = [fm moveItemAtPath:legacyPath toPath:targetPath error:&moveErr];
	if (moved) {
		CC_LOG("migrateLegacyJBCellularDBIfNeeded: moved legacy db to mirror path");
	} else {
		CC_LOG("migrateLegacyJBCellularDBIfNeeded: move failed: %s",
		       moveErr.localizedDescription.UTF8String ?: "unknown");
	}
}

static NSString *resolveJBCellularDBPath(const char *systemFilename)
{
	NSString *systemPath = nil;
	if (systemFilename) {
		systemPath = [NSString stringWithUTF8String:systemFilename];
	}

	if (!systemPath.length) {
		systemPath = @"/var/wireless/Library/Databases/CellularUsage.db";
	}

	NSString *mirrored = perm_jb_mirror_path_ns(systemPath);
	if (!mirrored.length) {
		mirrored = perm_jb_mirror_path_ns(@"/var/wireless/Library/Databases/CellularUsage.db");
	}
	return mirrored;
}

static int cc_exec_raw(sqlite3 *db, const char *sql)
{
	if (!db || !sql) return SQLITE_ERROR;

	char *errmsg = NULL;
	int rc;

	if (orig_sqlite3_exec) {
		rc = orig_sqlite3_exec(db, sql, NULL, NULL, &errmsg);
	} else {
		gBypassRewrite = YES;
		rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
		gBypassRewrite = NO;
	}

	if (rc != SQLITE_OK && errmsg) {
		CC_LOG("SQL failed rc=%d err=%s sql=%.140s", rc, errmsg, sql);
	}
	if (errmsg) sqlite3_free(errmsg);
	return rc;
}

static BOOL ensureJBCellularAttached(sqlite3 *db)
{
	if (!gJBCellularPath.length) return NO;

	NSString *escapedPath = [gJBCellularPath stringByReplacingOccurrencesOfString:@"'" withString:@"''"];
	NSString *attachSQL = [NSString stringWithFormat:@"ATTACH DATABASE '%@' AS jbcellular", escapedPath];
	int attachRC = cc_exec_raw(db, attachSQL.UTF8String);
	if (attachRC != SQLITE_OK) {
		const char *alreadyAttachedPath = sqlite3_db_filename(db, "jbcellular");
		if (!alreadyAttachedPath) {
			CC_LOG("ensureJBCellularAttached: attach failed rc=%d path=%s",
			       attachRC, gJBCellularPath.UTF8String);
			return NO;
		}
	}
	return YES;
}

static void ensureJBCellularFileExists(void)
{
	if (!gJBCellularPath.length) return;

	int fd = open(gJBCellularPath.fileSystemRepresentation, O_CREAT | O_RDWR, 0644);
	if (fd >= 0) {
		close(fd);
		return;
	}

	CC_LOG("ensureJBCellularFileExists: open failed errno=%d path=%s",
	       errno,
	       gJBCellularPath.UTF8String ?: "(null)");
}

static void migrateCellularRowsIfNeeded(sqlite3 *db)
{
	if (perm_migration_is_done(@"commcenter_cellular")) return;

	int rc1 = cc_exec_raw(db,
		"INSERT OR REPLACE INTO jbcellular.bundle_info "
		"SELECT * FROM main.bundle_info WHERE jb_is_client(bundle_id)=1;");
	int rc2 = cc_exec_raw(db,
		"DELETE FROM main.bundle_info WHERE jb_is_client(bundle_id)=1;");

	if (rc1 == SQLITE_OK && rc2 == SQLITE_OK) {
		perm_migration_mark_done(@"commcenter_cellular");
		CC_LOG("migrateCellularRowsIfNeeded: migration complete");
	} else {
		CC_LOG("migrateCellularRowsIfNeeded: failed rc1=%d rc2=%d", rc1, rc2);
	}
}

static BOOL initializeCellularRouting(sqlite3 *db)
{
	if (!ensureJBCellularAttached(db)) return NO;

	if (cc_exec_raw(db,
		"CREATE TABLE IF NOT EXISTS jbcellular.bundle_info AS "
		"SELECT * FROM main.bundle_info WHERE 0") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating jb table");
		return NO;
	}

	migrateCellularRowsIfNeeded(db);

	cc_exec_raw(db, "DROP VIEW IF EXISTS temp.jb_bundle_info_router");
	cc_exec_raw(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_insert_main");
	cc_exec_raw(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_insert_jb");
	cc_exec_raw(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_update_main");
	cc_exec_raw(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_update_jb");
	cc_exec_raw(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_delete_router");

	if (cc_exec_raw(db,
		"CREATE TEMP VIEW IF NOT EXISTS jb_bundle_info_router AS "
		"SELECT m.* FROM main.bundle_info AS m "
		"WHERE NOT EXISTS ("
		"  SELECT 1 FROM jbcellular.bundle_info AS j WHERE j.bundle_id=m.bundle_id"
		") "
		"UNION ALL "
		"SELECT * FROM jbcellular.bundle_info") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating temp view");
		return NO;
	}

	cc_exec_raw(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_insert_main "
		"INSTEAD OF INSERT ON jb_bundle_info_router "
		"WHEN jb_is_client(NEW.bundle_id)=0 "
		"BEGIN "
		"INSERT OR REPLACE INTO main.bundle_info(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
		"END;");

	cc_exec_raw(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_insert_jb "
		"INSTEAD OF INSERT ON jb_bundle_info_router "
		"WHEN jb_is_client(NEW.bundle_id)=1 "
		"BEGIN "
		"INSERT OR REPLACE INTO jbcellular.bundle_info(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
		"END;");

	cc_exec_raw(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_update_main "
		"INSTEAD OF UPDATE ON jb_bundle_info_router "
		"WHEN jb_is_client(NEW.bundle_id)=0 "
		"BEGIN "
		"DELETE FROM jbcellular.bundle_info WHERE bundle_id=OLD.bundle_id; "
		"DELETE FROM main.bundle_info WHERE bundle_id=OLD.bundle_id; "
		"INSERT OR REPLACE INTO main.bundle_info(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
		"END;");

	cc_exec_raw(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_update_jb "
		"INSTEAD OF UPDATE ON jb_bundle_info_router "
		"WHEN jb_is_client(NEW.bundle_id)=1 "
		"BEGIN "
		"DELETE FROM main.bundle_info WHERE bundle_id=OLD.bundle_id; "
		"DELETE FROM jbcellular.bundle_info WHERE bundle_id=OLD.bundle_id; "
		"INSERT OR REPLACE INTO jbcellular.bundle_info(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
		"END;");

	cc_exec_raw(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_delete_router "
		"INSTEAD OF DELETE ON jb_bundle_info_router "
		"BEGIN "
		"DELETE FROM main.bundle_info WHERE bundle_id=OLD.bundle_id; "
		"DELETE FROM jbcellular.bundle_info WHERE bundle_id=OLD.bundle_id; "
		"END;");

	CC_LOG("initializeCellularRouting: TEMP view/triggers installed");
	return YES;
}

static NSString *rewriteSQLForRouter(NSString *sql)
{
	NSError *error = nil;
	NSRegularExpression *selectRegex =
		[NSRegularExpression regularExpressionWithPattern:@"\\bFROM\\s+(?:main\\.)?bundle_info\\b"
		                                          options:NSRegularExpressionCaseInsensitive
		                                            error:&error];
	if (!error && selectRegex) {
		sql = [selectRegex stringByReplacingMatchesInString:sql
		                                            options:0
		                                              range:NSMakeRange(0, sql.length)
		                                       withTemplate:@"FROM jb_bundle_info_router"];
	}

	error = nil;
	NSRegularExpression *insertRegex =
		[NSRegularExpression regularExpressionWithPattern:@"\\bINSERT\\s+(OR\\s+\\w+\\s+)?INTO\\s+(?:main\\.)?bundle_info\\b"
		                                          options:NSRegularExpressionCaseInsensitive
		                                            error:&error];
	if (!error && insertRegex) {
		sql = [insertRegex stringByReplacingMatchesInString:sql
		                                            options:0
		                                              range:NSMakeRange(0, sql.length)
		                                       withTemplate:@"INSERT $1INTO jb_bundle_info_router"];
	}

	error = nil;
	NSRegularExpression *updateRegex =
		[NSRegularExpression regularExpressionWithPattern:@"\\bUPDATE\\s+(?:main\\.)?bundle_info\\b"
		                                          options:NSRegularExpressionCaseInsensitive
		                                            error:&error];
	if (!error && updateRegex) {
		sql = [updateRegex stringByReplacingMatchesInString:sql
		                                            options:0
		                                              range:NSMakeRange(0, sql.length)
		                                       withTemplate:@"UPDATE jb_bundle_info_router"];
	}

	error = nil;
	NSRegularExpression *deleteRegex =
		[NSRegularExpression regularExpressionWithPattern:@"\\bDELETE\\s+FROM\\s+(?:main\\.)?bundle_info\\b"
		                                          options:NSRegularExpressionCaseInsensitive
		                                            error:&error];
	if (!error && deleteRegex) {
		sql = [deleteRegex stringByReplacingMatchesInString:sql
		                                            options:0
		                                              range:NSMakeRange(0, sql.length)
		                                       withTemplate:@"DELETE FROM jb_bundle_info_router"];
	}

	return sql;
}

static void setupCellularDB(sqlite3 *db, const char *filename)
{
	if (!db) return;

	if (gCellularDB != db) {
		gCellularDB = db;
		gRoutingReady = NO;
	}
	if (gRoutingReady) return;

	gJBCellularPath = resolveJBCellularDBPath(filename);
	if (!gJBCellularPath.length) {
		CC_LOG("setupCellularDB: mirror path unavailable");
		return;
	}

	perm_ensure_parent_dir_for_path(gJBCellularPath);
	ensureJBCellularFileExists();
	migrateLegacyJBCellularDBIfNeeded(gJBCellularPath);

	sqlite3_create_function(db,
	                        "jb_is_client",
	                        1,
	                        SQLITE_UTF8 | SQLITE_DETERMINISTIC,
	                        NULL,
	                        sqlite_jb_is_client,
	                        NULL,
	                        NULL);

	gRoutingReady = initializeCellularRouting(db);
	CC_LOG("setupCellularDB: system=%s mirror=%s ready=%d",
	       filename ?: "(null)",
	       gJBCellularPath.UTF8String ?: "(null)",
	       gRoutingReady);
}

static int hook_sqlite3_open(const char *filename, sqlite3 **ppDb)
{
	int r = orig_sqlite3_open(filename, ppDb);
	if (r == SQLITE_OK && isCellularUsageDBPath(filename)) {
		setupCellularDB(*ppDb, filename);
	}
	return r;
}

static int hook_sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs)
{
	int r = orig_sqlite3_open_v2(filename, ppDb, flags, zVfs);
	if (r == SQLITE_OK && isCellularUsageDBPath(filename)) {
		setupCellularDB(*ppDb, filename);
	}
	return r;
}

static int hook_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail)
{
	if (gBypassRewrite || !zSql) {
		return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
	}

	if (db != gCellularDB || !gRoutingReady) {
		const char *filename = sqlite3_db_filename(db, "main");
		if (isCellularUsageDBPath(filename)) {
			setupCellularDB(db, filename);
		} else {
			return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
		}
	}

	if (db != gCellularDB || !gRoutingReady) {
		return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
	}

	NSString *sql = [NSString stringWithUTF8String:zSql];
	if (!sql) {
		return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
	}

	NSString *rewritten = rewriteSQLForRouter(sql);
	if (![rewritten isEqualToString:sql]) {
		return orig_sqlite3_prepare_v2(db, rewritten.UTF8String, -1, ppStmt, pzTail);
	}

	return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
}

static int hook_sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*, int, char**, char**), void *arg, char **errmsg)
{
	if (gBypassRewrite || !db || !sql) {
		return orig_sqlite3_exec(db, sql, callback, arg, errmsg);
	}

	if (db != gCellularDB || !gRoutingReady) {
		const char *filename = sqlite3_db_filename(db, "main");
		if (isCellularUsageDBPath(filename)) {
			setupCellularDB(db, filename);
		}
	}

	if (db == gCellularDB && gRoutingReady) {
		NSString *sqlStr = [NSString stringWithUTF8String:sql];
		if (sqlStr) {
			NSString *rewritten = rewriteSQLForRouter(sqlStr);
			if (![rewritten isEqualToString:sqlStr]) {
				return orig_sqlite3_exec(db, rewritten.UTF8String, callback, arg, errmsg);
			}
		}
	}

	return orig_sqlite3_exec(db, sql, callback, arg, errmsg);
}

void commcenterInit(void)
{
	CC_LOG("commcenterInit() called in process: %s (pid=%d)", getprogname(), getpid());
	MSHookFunction(sqlite3_open, (void *)hook_sqlite3_open, (void **)&orig_sqlite3_open);
	MSHookFunction(sqlite3_open_v2, (void *)hook_sqlite3_open_v2, (void **)&orig_sqlite3_open_v2);
	MSHookFunction(sqlite3_prepare_v2, (void *)hook_sqlite3_prepare_v2, (void **)&orig_sqlite3_prepare_v2);
	MSHookFunction(sqlite3_exec, (void *)hook_sqlite3_exec, (void **)&orig_sqlite3_exec);
	CC_LOG("commcenterInit: sqlite3 hooks installed");
}

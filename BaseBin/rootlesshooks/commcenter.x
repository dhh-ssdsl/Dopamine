#import <Foundation/Foundation.h>
#import <substrate.h>
#import <sqlite3.h>
#import <limits.h>
#import <libroot.h>
#import <string.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <libjailbreak/jbclient_xpc.h>
#import "perm_router.h"

// sqlite3_db_filename is available on iOS 6+.
extern const char *sqlite3_db_filename(sqlite3 *db, const char *zDbName);

static void _cc_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _cc_log(const char *fmt, ...)
{
	FILE *f = fopen(JBROOT_PATH_CSTRING("/var/mobile/hook_debug.log"), "a");
	if (!f) {
		f = fopen(JBROOT_PATH_CSTRING("/var/wireless/Library/Preferences/hook_debug.log"), "a");
	}
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

static int cc_exec_direct(sqlite3 *db, const char *sql)
{
	if (!db || !sql) return SQLITE_ERROR;

	char *errmsg = NULL;
	gBypassRewrite = YES;
	int rc = orig_sqlite3_exec ? orig_sqlite3_exec(db, sql, NULL, NULL, &errmsg)
	                           : sqlite3_exec(db, sql, NULL, NULL, &errmsg);
	gBypassRewrite = NO;

	if (rc != SQLITE_OK && errmsg) {
		CC_LOG("DIRECT SQL failed rc=%d err=%s sql=%.140s", rc, errmsg, sql);
	}
	if (errmsg) sqlite3_free(errmsg);
	return rc;
}

static int cc_prepare_direct(sqlite3 *db, const char *sql, sqlite3_stmt **stmt)
{
	if (!db || !sql || !stmt) return SQLITE_ERROR;

	gBypassRewrite = YES;
	int rc = orig_sqlite3_prepare_v2 ? orig_sqlite3_prepare_v2(db, sql, -1, stmt, NULL)
	                                 : sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
	gBypassRewrite = NO;
	if (rc != SQLITE_OK) {
		CC_LOG("DIRECT prepare failed rc=%d err=%s sql=%.140s",
		       rc,
		       sqlite3_errmsg(db),
		       sql);
	}
	return rc;
}

static xpc_object_t cc_proxy_load_rows(void)
{
	xpc_object_t rows = NULL;
	int rc = jbclient_platform_cellular_usage_load(&rows);
	if (rc != 0) {
		CC_LOG("proxy load failed rc=%d", rc);
		if (rows) xpc_release(rows);
		return NULL;
	}
	return rows;
}

static int cc_proxy_upsert(const char *bundleID, sqlite3_int64 flags)
{
	int rc = jbclient_platform_cellular_usage_upsert(bundleID, (uint64_t)flags);
	if (rc != 0) {
		CC_LOG("proxy upsert failed bundle=%s flags=%lld rc=%d",
		       bundleID ?: "(null)",
		       flags,
		       rc);
	}
	return rc;
}

static int cc_proxy_delete(const char *bundleID)
{
	int rc = jbclient_platform_cellular_usage_delete(bundleID);
	if (rc != 0) {
		CC_LOG("proxy delete failed bundle=%s rc=%d", bundleID ?: "(null)", rc);
	}
	return rc;
}

static void sqlite_jb_proxy_upsert(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	if (argc != 2) {
		sqlite3_result_error(context, "jb_proxy_upsert argc", -1);
		return;
	}

	const unsigned char *bundleID = sqlite3_value_text(argv[0]);
	sqlite3_int64 flags = sqlite3_value_int64(argv[1]);
	if (!bundleID || !bundleID[0]) {
		sqlite3_result_error(context, "jb_proxy_upsert bundle", -1);
		return;
	}

	int rc = cc_proxy_upsert((const char *)bundleID, flags);
	if (rc != 0) {
		sqlite3_result_error(context, "jb_proxy_upsert failed", -1);
		return;
	}

	sqlite3_result_int(context, 1);
}

static void sqlite_jb_proxy_delete(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	if (argc != 1) {
		sqlite3_result_error(context, "jb_proxy_delete argc", -1);
		return;
	}

	const unsigned char *bundleID = sqlite3_value_text(argv[0]);
	if (!bundleID || !bundleID[0]) {
		sqlite3_result_error(context, "jb_proxy_delete bundle", -1);
		return;
	}

	int rc = cc_proxy_delete((const char *)bundleID);
	if (rc != 0) {
		sqlite3_result_error(context, "jb_proxy_delete failed", -1);
		return;
	}

	sqlite3_result_int(context, 1);
}

static NSUInteger migrateSystemJBRowsToProxy(sqlite3 *db)
{
	if (!db) return 0;

	sqlite3_stmt *selectStmt = NULL;
	if (cc_prepare_direct(db,
	                      "SELECT bundle_id, flags FROM main.bundle_info WHERE jb_is_client(bundle_id)=1",
	                      &selectStmt) != SQLITE_OK) {
		return 0;
	}

	NSMutableArray<NSString *> *bundleIDsToDelete = [NSMutableArray array];
	NSUInteger scanned = 0;
	NSUInteger proxied = 0;

	for (;;) {
		int stepRC = sqlite3_step(selectStmt);
		if (stepRC == SQLITE_DONE) break;
		if (stepRC != SQLITE_ROW) {
			CC_LOG("migrateSystemJBRowsToProxy: select step rc=%d", stepRC);
			break;
		}

		const unsigned char *bundleIDText = sqlite3_column_text(selectStmt, 0);
		sqlite3_int64 flags = sqlite3_column_int64(selectStmt, 1);
		if (!bundleIDText || !bundleIDText[0]) continue;

		scanned++;
		if (cc_proxy_upsert((const char *)bundleIDText, flags) == 0) {
			NSString *bundleID = [NSString stringWithUTF8String:(const char *)bundleIDText];
			if (bundleID.length) {
				[bundleIDsToDelete addObject:bundleID];
				proxied++;
			}
		}
	}
	sqlite3_finalize(selectStmt);

	if (!bundleIDsToDelete.count) {
		if (scanned) {
			CC_LOG("migrateSystemJBRowsToProxy: scanned=%lu proxied=0",
			       (unsigned long)scanned);
		}
		return 0;
	}

	sqlite3_stmt *deleteStmt = NULL;
	if (cc_prepare_direct(db, "DELETE FROM main.bundle_info WHERE bundle_id=?", &deleteStmt) != SQLITE_OK) {
		return 0;
	}

	NSUInteger deleted = 0;
	for (NSString *bundleID in bundleIDsToDelete) {
		sqlite3_reset(deleteStmt);
		sqlite3_clear_bindings(deleteStmt);
		sqlite3_bind_text(deleteStmt, 1, bundleID.UTF8String, -1, SQLITE_TRANSIENT);
		int stepRC = sqlite3_step(deleteStmt);
		if (stepRC == SQLITE_DONE) {
			deleted++;
		} else {
			CC_LOG("migrateSystemJBRowsToProxy: delete failed bundle=%s rc=%d",
			       bundleID.UTF8String,
			       stepRC);
		}
	}
	sqlite3_finalize(deleteStmt);

	CC_LOG("migrateSystemJBRowsToProxy: scanned=%lu proxied=%lu deleted=%lu",
	       (unsigned long)scanned,
	       (unsigned long)proxied,
	       (unsigned long)deleted);
	return deleted;
}

static NSUInteger loadProxyRowsIntoOverlay(sqlite3 *db)
{
	if (!db) return 0;

	xpc_object_t rows = cc_proxy_load_rows();
	if (!rows || xpc_get_type(rows) != XPC_TYPE_ARRAY) {
		if (rows) xpc_release(rows);
		return 0;
	}

	sqlite3_stmt *insertStmt = NULL;
	if (cc_prepare_direct(db,
	                      "INSERT INTO temp.jb_bundle_info_overlay(bundle_id, flags) VALUES(?, ?)",
	                      &insertStmt) != SQLITE_OK) {
		xpc_release(rows);
		return 0;
	}

	NSUInteger loaded = 0;
	size_t rowCount = xpc_array_get_count(rows);
	for (size_t i = 0; i < rowCount; i++) {
		xpc_object_t row = xpc_array_get_value(rows, i);
		if (!row || xpc_get_type(row) != XPC_TYPE_DICTIONARY) continue;

		const char *bundleID = xpc_dictionary_get_string(row, "bundle-id");
		int64_t flags = xpc_dictionary_get_int64(row, "flags");
		if (!bundleID || !bundleID[0]) continue;

		sqlite3_reset(insertStmt);
		sqlite3_clear_bindings(insertStmt);
		sqlite3_bind_text(insertStmt, 1, bundleID, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int64(insertStmt, 2, flags);
		int stepRC = sqlite3_step(insertStmt);
		if (stepRC == SQLITE_DONE) {
			loaded++;
		} else {
			CC_LOG("loadProxyRowsIntoOverlay: insert failed bundle=%s rc=%d", bundleID, stepRC);
		}
	}

	sqlite3_finalize(insertStmt);
	xpc_release(rows);
	CC_LOG("loadProxyRowsIntoOverlay: loaded=%lu", (unsigned long)loaded);
	return loaded;
}

static BOOL initializeCellularRouting(sqlite3 *db)
{
	if (cc_exec_direct(db,
	                   "CREATE TEMP TABLE IF NOT EXISTS jb_bundle_info_overlay AS SELECT * FROM main.bundle_info WHERE 0") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating overlay table");
		return NO;
	}

	cc_exec_direct(db, "DELETE FROM temp.jb_bundle_info_overlay");
	migrateSystemJBRowsToProxy(db);
	loadProxyRowsIntoOverlay(db);

	cc_exec_direct(db, "DROP VIEW IF EXISTS temp.jb_bundle_info_router");
	cc_exec_direct(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_insert_main");
	cc_exec_direct(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_insert_jb");
	cc_exec_direct(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_update_main");
	cc_exec_direct(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_update_jb");
	cc_exec_direct(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_delete_main");
	cc_exec_direct(db, "DROP TRIGGER IF EXISTS temp.jb_cellular_delete_jb");

	if (cc_exec_direct(db,
	                   "CREATE TEMP VIEW IF NOT EXISTS jb_bundle_info_router AS "
	                   "SELECT m.* FROM main.bundle_info AS m "
	                   "WHERE NOT EXISTS ("
	                   "  SELECT 1 FROM temp.jb_bundle_info_overlay AS j WHERE j.bundle_id=m.bundle_id"
	                   ") "
	                   "UNION ALL "
	                   "SELECT * FROM temp.jb_bundle_info_overlay") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating temp view");
		return NO;
	}

	if (cc_exec_direct(db,
	                   "CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_insert_main "
	                   "INSTEAD OF INSERT ON jb_bundle_info_router "
	                   "WHEN jb_is_client(NEW.bundle_id)=0 "
	                   "BEGIN "
	                   "DELETE FROM jb_bundle_info_overlay WHERE bundle_id=NEW.bundle_id; "
	                   "INSERT OR REPLACE INTO bundle_info(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
	                   "END;") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating jb_cellular_insert_main");
		return NO;
	}

	if (cc_exec_direct(db,
	                   "CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_insert_jb "
	                   "INSTEAD OF INSERT ON jb_bundle_info_router "
	                   "WHEN jb_is_client(NEW.bundle_id)=1 "
	                   "BEGIN "
	                   "SELECT jb_proxy_upsert(NEW.bundle_id, NEW.flags); "
	                   "DELETE FROM bundle_info WHERE bundle_id=NEW.bundle_id; "
	                   "DELETE FROM jb_bundle_info_overlay WHERE bundle_id=NEW.bundle_id; "
	                   "INSERT INTO jb_bundle_info_overlay(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
	                   "END;") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating jb_cellular_insert_jb");
		return NO;
	}

	if (cc_exec_direct(db,
	                   "CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_update_main "
	                   "INSTEAD OF UPDATE ON jb_bundle_info_router "
	                   "WHEN jb_is_client(NEW.bundle_id)=0 "
	                   "BEGIN "
	                   "DELETE FROM jb_bundle_info_overlay WHERE bundle_id=OLD.bundle_id; "
	                   "DELETE FROM bundle_info WHERE bundle_id=OLD.bundle_id; "
	                   "INSERT OR REPLACE INTO bundle_info(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
	                   "END;") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating jb_cellular_update_main");
		return NO;
	}

	if (cc_exec_direct(db,
	                   "CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_update_jb "
	                   "INSTEAD OF UPDATE ON jb_bundle_info_router "
	                   "WHEN jb_is_client(NEW.bundle_id)=1 "
	                   "BEGIN "
	                   "SELECT jb_proxy_upsert(NEW.bundle_id, NEW.flags); "
	                   "SELECT CASE WHEN OLD.bundle_id != NEW.bundle_id THEN jb_proxy_delete(OLD.bundle_id) ELSE 0 END; "
	                   "DELETE FROM bundle_info WHERE bundle_id=OLD.bundle_id; "
	                   "DELETE FROM bundle_info WHERE bundle_id=NEW.bundle_id; "
	                   "DELETE FROM jb_bundle_info_overlay WHERE bundle_id=OLD.bundle_id; "
	                   "DELETE FROM jb_bundle_info_overlay WHERE bundle_id=NEW.bundle_id; "
	                   "INSERT INTO jb_bundle_info_overlay(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
	                   "END;") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating jb_cellular_update_jb");
		return NO;
	}

	if (cc_exec_direct(db,
	                   "CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_delete_main "
	                   "INSTEAD OF DELETE ON jb_bundle_info_router "
	                   "WHEN jb_is_client(OLD.bundle_id)=0 "
	                   "BEGIN "
	                   "DELETE FROM bundle_info WHERE bundle_id=OLD.bundle_id; "
	                   "DELETE FROM jb_bundle_info_overlay WHERE bundle_id=OLD.bundle_id; "
	                   "END;") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating jb_cellular_delete_main");
		return NO;
	}

	if (cc_exec_direct(db,
	                   "CREATE TEMP TRIGGER IF NOT EXISTS jb_cellular_delete_jb "
	                   "INSTEAD OF DELETE ON jb_bundle_info_router "
	                   "WHEN jb_is_client(OLD.bundle_id)=1 "
	                   "BEGIN "
	                   "SELECT jb_proxy_delete(OLD.bundle_id); "
	                   "DELETE FROM bundle_info WHERE bundle_id=OLD.bundle_id; "
	                   "DELETE FROM jb_bundle_info_overlay WHERE bundle_id=OLD.bundle_id; "
	                   "END;") != SQLITE_OK) {
		CC_LOG("initializeCellularRouting: failed creating jb_cellular_delete_jb");
		return NO;
	}

	CC_LOG("initializeCellularRouting: proxy-backed TEMP view/triggers installed");
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

	sqlite3_create_function(db,
	                        "jb_is_client",
	                        1,
	                        SQLITE_UTF8 | SQLITE_DETERMINISTIC,
	                        NULL,
	                        sqlite_jb_is_client,
	                        NULL,
	                        NULL);

	sqlite3_create_function(db,
	                        "jb_proxy_upsert",
	                        2,
	                        SQLITE_UTF8,
	                        NULL,
	                        sqlite_jb_proxy_upsert,
	                        NULL,
	                        NULL);

	sqlite3_create_function(db,
	                        "jb_proxy_delete",
	                        1,
	                        SQLITE_UTF8,
	                        NULL,
	                        sqlite_jb_proxy_delete,
	                        NULL,
	                        NULL);

	gRoutingReady = initializeCellularRouting(db);
	CC_LOG("setupCellularDB: system=%s mirror=%s ready=%d mode=proxy-overlay",
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
	CC_LOG("commcenterInit() called in process: %s (pid=%d uid=%d gid=%d)",
	       getprogname(),
	       getpid(),
	       getuid(),
	       getgid());

	NSString *preflightMirror = perm_jb_mirror_path_ns(@"/var/wireless/Library/Databases/CellularUsage.db");
	if (preflightMirror.length) {
		gJBCellularPath = preflightMirror;
		CC_LOG("commcenterInit preflight: mirror=%s mode=proxy-overlay",
		       gJBCellularPath.UTF8String ?: "(null)");
	}

	MSHookFunction(sqlite3_open, (void *)hook_sqlite3_open, (void **)&orig_sqlite3_open);
	MSHookFunction(sqlite3_open_v2, (void *)hook_sqlite3_open_v2, (void **)&orig_sqlite3_open_v2);
	MSHookFunction(sqlite3_prepare_v2, (void *)hook_sqlite3_prepare_v2, (void **)&orig_sqlite3_prepare_v2);
	MSHookFunction(sqlite3_exec, (void *)hook_sqlite3_exec, (void **)&orig_sqlite3_exec);
	CC_LOG("commcenterInit: sqlite3 hooks installed");
}

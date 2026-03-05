#import <Foundation/Foundation.h>
#import <substrate.h>
#import <sqlite3.h>
#import <libroot.h>
#import <limits.h>
#import "perm_router.h"

// sqlite3_db_filename available since SQLite 3.7.10 / iOS 6+
extern const char *sqlite3_db_filename(sqlite3 *db, const char *zDbName);

static void _tc_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _tc_log(const char *fmt, ...)
{
	FILE *f = fopen(JBROOT_PATH_CSTRING("/var/mobile/hook_debug.log"), "a");
	if (!f) return;
	time_t t = time(NULL);
	struct tm tm; localtime_r(&t, &tm);
	fprintf(f, "%02d:%02d:%02d [TCCD] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
	va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
	fprintf(f, "\n"); fclose(f);
}
#define TC_LOG(fmt, ...) _tc_log(fmt, ##__VA_ARGS__)

static sqlite3 *gTCCDB = NULL;
static NSString *gJBTCCPath = nil;

static int (*orig_sqlite3_open_v2)(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
static int (*orig_sqlite3_prepare_v2)(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
static int (*orig_sqlite3_exec)(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg);

static bool isJailbreakBundleID(const char *bundleID)
{
	if (!bundleID) return false;
	NSString *bid = [NSString stringWithUTF8String:bundleID];
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

static void migrateTCCRowsIfNeeded(sqlite3 *db)
{
	if (perm_migration_is_done(@"tcc")) return;

	int rc1 = sqlite3_exec(db,
		"INSERT OR REPLACE INTO jbtcc.access "
		"SELECT * FROM main.access WHERE jb_is_client(client)=1;",
		NULL, NULL, NULL);
	int rc2 = sqlite3_exec(db,
		"DELETE FROM main.access WHERE jb_is_client(client)=1;",
		NULL, NULL, NULL);

	if (rc1 == SQLITE_OK && rc2 == SQLITE_OK) {
		perm_migration_mark_done(@"tcc");
		TC_LOG("migrateTCCRowsIfNeeded: migration complete");
	} else {
		TC_LOG("migrateTCCRowsIfNeeded: failed rc1=%d rc2=%d", rc1, rc2);
	}
}

static void initializeTCCRouting(sqlite3 *db)
{
	if (!gJBTCCPath.length) {
		gJBTCCPath = perm_jb_mirror_path_ns(@"/var/mobile/Library/TCC/TCC.db");
	}
	if (!gJBTCCPath.length) {
		TC_LOG("initializeTCCRouting: mirror path unavailable, skipping");
		return;
	}
	perm_ensure_parent_dir_for_path(gJBTCCPath);

	char attachSQL[PATH_MAX + 64];
	snprintf(attachSQL, sizeof(attachSQL), "ATTACH DATABASE '%s' AS jbtcc", gJBTCCPath.UTF8String);
	int rc = sqlite3_exec(db, attachSQL, NULL, NULL, NULL);
	TC_LOG("initializeTCCRouting: ATTACH -> rc=%d, jbTCCPath=%s", rc, gJBTCCPath.UTF8String);

	// Cleanup legacy persistent objects in main DB.
	sqlite3_exec(db, "DROP VIEW IF EXISTS main.jb_access_router", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_insert_main", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_insert_jb", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_update_main", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_update_jb", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_delete_main", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_delete_jb", NULL, NULL, NULL);

	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS jbtcc.access AS SELECT * FROM main.access WHERE 0", NULL, NULL, NULL);
	migrateTCCRowsIfNeeded(db);

	// Read merge with JB precedence: main rows are hidden when same key exists in jbtcc.
	sqlite3_exec(db,
		"CREATE TEMP VIEW IF NOT EXISTS jb_access_router AS "
		"SELECT m.* FROM main.access AS m "
		"WHERE NOT EXISTS ("
		"  SELECT 1 FROM jbtcc.access AS j "
		"  WHERE j.service=m.service "
		"    AND j.client=m.client "
		"    AND j.client_type=m.client_type "
		"    AND IFNULL(j.indirect_object_identifier,'')=IFNULL(m.indirect_object_identifier,'')"
		") "
		"UNION ALL "
		"SELECT * FROM jbtcc.access",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_router_insert_main "
		"INSTEAD OF INSERT ON jb_access_router "
		"WHEN jb_is_client(NEW.client)=0 "
		"BEGIN "
		"INSERT OR REPLACE INTO main.access VALUES(NEW.service, NEW.client, NEW.client_type, NEW.auth_value, NEW.auth_reason, NEW.auth_version, NEW.csreq, NEW.policy_id, NEW.indirect_object_identifier_type, NEW.indirect_object_identifier, NEW.indirect_object_code_identity, NEW.flags, NEW.last_modified); "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_router_insert_jb "
		"INSTEAD OF INSERT ON jb_access_router "
		"WHEN jb_is_client(NEW.client)=1 "
		"BEGIN "
		"INSERT OR REPLACE INTO jbtcc.access VALUES(NEW.service, NEW.client, NEW.client_type, NEW.auth_value, NEW.auth_reason, NEW.auth_version, NEW.csreq, NEW.policy_id, NEW.indirect_object_identifier_type, NEW.indirect_object_identifier, NEW.indirect_object_code_identity, NEW.flags, NEW.last_modified); "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_router_update_main "
		"INSTEAD OF UPDATE ON jb_access_router "
		"WHEN jb_is_client(OLD.client)=0 "
		"BEGIN "
		"UPDATE main.access SET "
		"service=NEW.service, client=NEW.client, client_type=NEW.client_type, auth_value=NEW.auth_value, auth_reason=NEW.auth_reason, auth_version=NEW.auth_version, csreq=NEW.csreq, policy_id=NEW.policy_id, indirect_object_identifier_type=NEW.indirect_object_identifier_type, indirect_object_identifier=NEW.indirect_object_identifier, indirect_object_code_identity=NEW.indirect_object_code_identity, flags=NEW.flags, last_modified=NEW.last_modified "
		"WHERE service=OLD.service AND client=OLD.client AND client_type=OLD.client_type AND indirect_object_identifier=OLD.indirect_object_identifier; "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_router_update_jb "
		"INSTEAD OF UPDATE ON jb_access_router "
		"WHEN jb_is_client(OLD.client)=1 "
		"BEGIN "
		"UPDATE jbtcc.access SET "
		"service=NEW.service, client=NEW.client, client_type=NEW.client_type, auth_value=NEW.auth_value, auth_reason=NEW.auth_reason, auth_version=NEW.auth_version, csreq=NEW.csreq, policy_id=NEW.policy_id, indirect_object_identifier_type=NEW.indirect_object_identifier_type, indirect_object_identifier=NEW.indirect_object_identifier, indirect_object_code_identity=NEW.indirect_object_code_identity, flags=NEW.flags, last_modified=NEW.last_modified "
		"WHERE service=OLD.service AND client=OLD.client AND client_type=OLD.client_type AND indirect_object_identifier=OLD.indirect_object_identifier; "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_router_delete_main "
		"INSTEAD OF DELETE ON jb_access_router "
		"WHEN jb_is_client(OLD.client)=0 "
		"BEGIN "
		"DELETE FROM main.access WHERE service=OLD.service AND client=OLD.client AND client_type=OLD.client_type AND indirect_object_identifier=OLD.indirect_object_identifier; "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TEMP TRIGGER IF NOT EXISTS jb_router_delete_jb "
		"INSTEAD OF DELETE ON jb_access_router "
		"WHEN jb_is_client(OLD.client)=1 "
		"BEGIN "
		"DELETE FROM jbtcc.access WHERE service=OLD.service AND client=OLD.client AND client_type=OLD.client_type AND indirect_object_identifier=OLD.indirect_object_identifier; "
		"END;",
		NULL, NULL, NULL);

	TC_LOG("initializeTCCRouting: TEMP views/triggers installed");
}

static NSString *rewriteSQLForRouter(NSString *sql)
{
	NSError *error = nil;
	NSRegularExpression *selectRegex = [NSRegularExpression regularExpressionWithPattern:@"\\bFROM\\s+access\\b" options:NSRegularExpressionCaseInsensitive error:&error];
	if (!error && selectRegex) {
		sql = [selectRegex stringByReplacingMatchesInString:sql options:0 range:NSMakeRange(0, sql.length) withTemplate:@"FROM jb_access_router"];
	}

	error = nil;
	NSRegularExpression *insertRegex = [NSRegularExpression regularExpressionWithPattern:@"\\bINSERT\\s+INTO\\s+access\\b" options:NSRegularExpressionCaseInsensitive error:&error];
	if (!error && insertRegex) {
		sql = [insertRegex stringByReplacingMatchesInString:sql options:0 range:NSMakeRange(0, sql.length) withTemplate:@"INSERT INTO jb_access_router"];
	}

	error = nil;
	NSRegularExpression *updateRegex = [NSRegularExpression regularExpressionWithPattern:@"\\bUPDATE\\s+access\\b" options:NSRegularExpressionCaseInsensitive error:&error];
	if (!error && updateRegex) {
		sql = [updateRegex stringByReplacingMatchesInString:sql options:0 range:NSMakeRange(0, sql.length) withTemplate:@"UPDATE jb_access_router"];
	}

	error = nil;
	NSRegularExpression *deleteRegex = [NSRegularExpression regularExpressionWithPattern:@"\\bDELETE\\s+FROM\\s+access\\b" options:NSRegularExpressionCaseInsensitive error:&error];
	if (!error && deleteRegex) {
		sql = [deleteRegex stringByReplacingMatchesInString:sql options:0 range:NSMakeRange(0, sql.length) withTemplate:@"DELETE FROM jb_access_router"];
	}

	return sql;
}

static void setupTCCDB(sqlite3 *db, const char *filename)
{
	gTCCDB = db;
	if (filename) {
		NSString *systemPath = [NSString stringWithUTF8String:filename];
		gJBTCCPath = perm_jb_mirror_path_ns(systemPath);
	}
	if (!gJBTCCPath.length) {
		gJBTCCPath = perm_jb_mirror_path_ns(@"/var/mobile/Library/TCC/TCC.db");
	}

	TC_LOG("setupTCCDB: system=%s mirror=%s", filename ?: "(null)", gJBTCCPath.UTF8String ?: "(null)");
	sqlite3_create_function(db, "jb_is_client", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sqlite_jb_is_client, NULL, NULL);
	initializeTCCRouting(db);
}

static int hook_sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs)
{
	int r = orig_sqlite3_open_v2(filename, ppDb, flags, zVfs);
	if (r == SQLITE_OK && filename && strstr(filename, "TCC.db")) {
		setupTCCDB(*ppDb, filename);
	}
	return r;
}

static int hook_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail)
{
	if (!zSql) {
		return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
	}

	if (db != gTCCDB) {
		const char *filename = sqlite3_db_filename(db, "main");
		if (filename && strstr(filename, "TCC.db")) {
			setupTCCDB(db, filename);
		} else {
			return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
		}
	}

	NSString *sql = [NSString stringWithUTF8String:zSql];
	if (!sql) {
		return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
	}

	NSString *rewritten = rewriteSQLForRouter(sql);
	if (![rewritten isEqualToString:sql]) {
		if ([sql containsString:@"MobileData"] || [sql containsString:@"mobiledata"]) {
			TC_LOG("prepare_v2 MobileData SQL rewritten: %.150s", rewritten.UTF8String);
		}
		return orig_sqlite3_prepare_v2(db, rewritten.UTF8String, -1, ppStmt, pzTail);
	}

	return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
}

static int hook_sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg)
{
	if (db && db != gTCCDB) {
		const char *filename = sqlite3_db_filename(db, "main");
		if (filename && strstr(filename, "TCC.db")) {
			setupTCCDB(db, filename);
		}
	}

	if (db == gTCCDB && sql) {
		NSString *sqlStr = [NSString stringWithUTF8String:sql];
		if (sqlStr) {
			NSString *rewritten = rewriteSQLForRouter(sqlStr);
			if (![rewritten isEqualToString:sqlStr]) {
				if ([sqlStr containsString:@"MobileData"] || [sqlStr containsString:@"mobiledata"]) {
					TC_LOG("exec MobileData SQL rewritten: %.150s", rewritten.UTF8String);
				}
				return orig_sqlite3_exec(db, rewritten.UTF8String, callback, arg, errmsg);
			}
		}
	}

	return orig_sqlite3_exec(db, sql, callback, arg, errmsg);
}

void tccdInit(void)
{
	TC_LOG("tccdInit() called in process: %s (pid=%d)", getprogname(), getpid());
	MSHookFunction(sqlite3_open_v2, (void *)hook_sqlite3_open_v2, (void **)&orig_sqlite3_open_v2);
	MSHookFunction(sqlite3_prepare_v2, (void *)hook_sqlite3_prepare_v2, (void **)&orig_sqlite3_prepare_v2);
	MSHookFunction(sqlite3_exec, (void *)hook_sqlite3_exec, (void **)&orig_sqlite3_exec);
	TC_LOG("tccdInit: sqlite3 hooks installed");
}

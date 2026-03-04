#import <Foundation/Foundation.h>
#import <substrate.h>
#import <sqlite3.h>
#import <libroot.h>

// LSApplicationProxy forward declaration (MobileCoreServices private)
@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier;
@property (nonatomic, readonly) NSURL *bundleURL;
@end

// sqlite3_db_filename available since SQLite 3.7.10 / iOS 6+
extern const char *sqlite3_db_filename(sqlite3 *db, const char *zDbName);

static void _tc_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _tc_log(const char *fmt, ...) {
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

// JB root path prefix (e.g. /private/preboot/.../procursus/)
static NSString *gJBRootPrefix = nil;
static dispatch_once_t gJBRootOnce;

static NSString *jbRootPrefix(void)
{
	dispatch_once(&gJBRootOnce, ^{
		gJBRootPrefix = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/")];
		if (![gJBRootPrefix hasSuffix:@"/"])
			gJBRootPrefix = [gJBRootPrefix stringByAppendingString:@"/"];
	});
	return gJBRootPrefix;
}

// Returns true if bundleID belongs to a JB-installed app.
// Uses LSApplicationProxy to check if the app's bundle path is under the JB root prefix.
// Falls back to /Applications directory scan if LSApplicationProxy is unavailable.
static bool isJailbreakBundleID(const char *bundleID)
{
	if (!bundleID) return false;
	NSString *bid = [NSString stringWithUTF8String:bundleID];
	if (!bid.length) return false;

	Class LSProxy = NSClassFromString(@"LSApplicationProxy");
	if (LSProxy) {
		id proxy = [LSProxy applicationProxyForIdentifier:bid];
		NSURL *bundleURL = [proxy valueForKey:@"bundleURL"];
		NSString *bundlePath = bundleURL.path;
		if (bundlePath.length) {
			return [bundlePath hasPrefix:jbRootPrefix()];
		}
	}

	// Fallback: /Applications directory scan
	NSString *jbAppsPath = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/Applications")];
	NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbAppsPath error:nil];
	for (NSString *item in contents) {
		if (![item hasSuffix:@".app"]) continue;
		NSString *appPath = [jbAppsPath stringByAppendingPathComponent:item];
		NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[appPath stringByAppendingPathComponent:@"Info.plist"]];
		if ([info[@"CFBundleIdentifier"] isEqualToString:bid]) return true;
	}
	return false;
}

static int (*orig_sqlite3_open_v2)(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
static int (*orig_sqlite3_prepare_v2)(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
static int (*orig_sqlite3_exec)(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg);

static void sqlite_jb_is_client(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	if (argc != 1) {
		sqlite3_result_int(context, 0);
		return;
	}
	const unsigned char *client = sqlite3_value_text(argv[0]);
	sqlite3_result_int(context, isJailbreakBundleID((const char *)client) ? 1 : 0);
}

static void initializeTCCRouting(sqlite3 *db)
{
	const char *jbTCCDir = JBROOT_PATH_CSTRING("/var/mobile/Library/TCC");
	NSString *tccDir = [NSString stringWithUTF8String:jbTCCDir];
	if (![[NSFileManager defaultManager] fileExistsAtPath:tccDir]) {
		[[NSFileManager defaultManager] createDirectoryAtPath:tccDir withIntermediateDirectories:YES attributes:nil error:nil];
	}

	const char *jbTCCPath = JBROOT_PATH_CSTRING("/var/mobile/Library/TCC/.jb_tcc.db");
	char attachSQL[1024];
	snprintf(attachSQL, sizeof(attachSQL), "ATTACH DATABASE '%s' AS jbtcc", jbTCCPath);
	int rc = sqlite3_exec(db, attachSQL, NULL, NULL, NULL);
	TC_LOG("initializeTCCRouting: ATTACH -> rc=%d, jbTCCPath=%s", rc, jbTCCPath);

	// 1. Clean up legacy persistent views/triggers from main DB to prevent schema bloat
	sqlite3_exec(db, "DROP VIEW IF EXISTS main.jb_access_router", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_insert_main", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_insert_jb", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_update_main", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_update_jb", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_delete_main", NULL, NULL, NULL);
	sqlite3_exec(db, "DROP TRIGGER IF EXISTS main.jb_router_delete_jb", NULL, NULL, NULL);

	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS jbtcc.access AS SELECT * FROM main.access WHERE 0", NULL, NULL, NULL);

	// 2. Create session-only (TEMP) view and triggers so we don't pollute TCC.db on disk
	sqlite3_exec(db,
		"CREATE TEMP VIEW IF NOT EXISTS jb_access_router AS "
		"SELECT * FROM main.access UNION ALL SELECT * FROM jbtcc.access",
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

	TC_LOG("initializeTCCRouting: TEMP triggers/views created, legacy ones cleaned up");
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
	TC_LOG("setupTCCDB: %s", filename ?: "(null)");
	gTCCDB = db;
	sqlite3_create_function(db, "jb_is_client", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sqlite_jb_is_client, NULL, NULL);
	initializeTCCRouting(db);
	TC_LOG("setupTCCDB: done");
}

static int hook_sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs)
{
	int r = orig_sqlite3_open_v2(filename, ppDb, flags, zVfs);
	TC_LOG("open_v2: %s -> %d", filename ?: "(null)", r);
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

	// Late-init: detect TCC.db if already open before hook installed
	if (db != gTCCDB) {
		const char *filename = sqlite3_db_filename(db, "main");
		if (filename && strstr(filename, "TCC.db")) {
			TC_LOG("prepare_v2: late-init TCC.db: %s", filename);
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
		// Log cellular data permission queries specifically
		if ([sql containsString:@"MobileData"] || [sql containsString:@"mobiledata"]) {
			TC_LOG("MobileData SQL rewritten: %.150s", rewritten.UTF8String);
		}
		return orig_sqlite3_prepare_v2(db, rewritten.UTF8String, -1, ppStmt, pzTail);
	}

	return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
}

static int hook_sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg)
{
	// Late-init via exec (in case TCC.db opened before hook)
	if (db && db != gTCCDB) {
		const char *filename = sqlite3_db_filename(db, "main");
		if (filename && strstr(filename, "TCC.db")) {
			TC_LOG("exec: late-init TCC.db: %s", filename);
			setupTCCDB(db, filename);
		}
	}

	// Rewrite SQL for TCC.db exec calls
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
	TC_LOG("tccdInit: sqlite3 hooks installed (open_v2 + prepare_v2 + exec)");
}

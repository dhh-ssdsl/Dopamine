#import <Foundation/Foundation.h>
#import <substrate.h>
#import <sqlite3.h>
#import <libroot.h>

// LSApplicationProxy forward declaration (MobileCoreServices private)
@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier;
@property (nonatomic, readonly) NSURL *bundleURL;
@end

// sqlite3_db_filename is available since SQLite 3.7.10 / iOS 6+
// Declare it explicitly in case the SDK header is too old
extern const char *sqlite3_db_filename(sqlite3 *db, const char *zDbName);

static void _cc_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void _cc_log(const char *fmt, ...) {
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

// JB root path prefix
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
// Uses LSApplicationProxy to check if the app's bundle path is under the JB root.
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
static int (*orig_sqlite3_open)(const char *filename, sqlite3 **ppDb);
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

static void initializeCellularRouting(sqlite3 *db)
{
	const char *jbCellularDir = JBROOT_PATH_CSTRING("/var/wireless/Library/Databases");
	NSString *cellularDir = [NSString stringWithUTF8String:jbCellularDir];
	if (![[NSFileManager defaultManager] fileExistsAtPath:cellularDir]) {
		NSError *mkdirError = nil;
		BOOL ok = [[NSFileManager defaultManager] createDirectoryAtPath:cellularDir withIntermediateDirectories:YES attributes:nil error:&mkdirError];
		if (!ok) {
			CC_LOG("ERROR creating cellular dir %s: %s", jbCellularDir,
				   mkdirError.localizedDescription.UTF8String ?: "unknown");
		} else {
			CC_LOG("Created cellular dir: %s", jbCellularDir);
		}
	} else {
		CC_LOG("Cellular dir already exists: %s", jbCellularDir);
	}

	const char *jbCellularPath = JBROOT_PATH_CSTRING("/var/wireless/Library/Databases/.jb_cellular.db");
	char attachSQL[1024];
	snprintf(attachSQL, sizeof(attachSQL), "ATTACH DATABASE '%s' AS jbcellular", jbCellularPath);
	char *attachErr = NULL;
	int attachRc = sqlite3_exec(db, attachSQL, NULL, NULL, &attachErr);
	if (attachRc != SQLITE_OK) {
		CC_LOG("ERROR: ATTACH DATABASE failed (rc=%d): %s", attachRc, attachErr ?: "(null)");
		sqlite3_free(attachErr);
		return; // No point setting up views/triggers if attach failed
	}
	CC_LOG("ATTACH DATABASE jbcellular OK: %s", jbCellularPath);

	// Create bundle_info table in jbcellular if not exists
	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS jbcellular.bundle_info AS SELECT * FROM main.bundle_info WHERE 0", NULL, NULL, NULL);

	// Create routing view
	sqlite3_exec(db,
		"CREATE VIEW IF NOT EXISTS jb_bundle_info_router AS "
		"SELECT * FROM main.bundle_info UNION ALL SELECT * FROM jbcellular.bundle_info",
		NULL, NULL, NULL);

	// INSERT triggers
	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_cellular_insert_main "
		"INSTEAD OF INSERT ON jb_bundle_info_router "
		"WHEN jb_is_client(NEW.bundle_id)=0 "
		"BEGIN "
		"INSERT OR REPLACE INTO main.bundle_info(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_cellular_insert_jb "
		"INSTEAD OF INSERT ON jb_bundle_info_router "
		"WHEN jb_is_client(NEW.bundle_id)=1 "
		"BEGIN "
		"INSERT OR REPLACE INTO jbcellular.bundle_info(bundle_id, flags) VALUES(NEW.bundle_id, NEW.flags); "
		"END;",
		NULL, NULL, NULL);

	// UPDATE triggers
	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_cellular_update_main "
		"INSTEAD OF UPDATE ON jb_bundle_info_router "
		"WHEN jb_is_client(OLD.bundle_id)=0 "
		"BEGIN "
		"UPDATE main.bundle_info SET bundle_id=NEW.bundle_id, flags=NEW.flags WHERE bundle_id=OLD.bundle_id; "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_cellular_update_jb "
		"INSTEAD OF UPDATE ON jb_bundle_info_router "
		"WHEN jb_is_client(OLD.bundle_id)=1 "
		"BEGIN "
		"UPDATE jbcellular.bundle_info SET bundle_id=NEW.bundle_id, flags=NEW.flags WHERE bundle_id=OLD.bundle_id; "
		"END;",
		NULL, NULL, NULL);

	// DELETE triggers
	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_cellular_delete_main "
		"INSTEAD OF DELETE ON jb_bundle_info_router "
		"WHEN jb_is_client(OLD.bundle_id)=0 "
		"BEGIN "
		"DELETE FROM main.bundle_info WHERE bundle_id=OLD.bundle_id; "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_cellular_delete_jb "
		"INSTEAD OF DELETE ON jb_bundle_info_router "
		"WHEN jb_is_client(OLD.bundle_id)=1 "
		"BEGIN "
		"DELETE FROM jbcellular.bundle_info WHERE bundle_id=OLD.bundle_id; "
		"END;",
		NULL, NULL, NULL);
}

static NSString *rewriteSQLForCellularRouter(NSString *sql)
{
	NSError *error = nil;
	NSRegularExpression *selectRegex = [NSRegularExpression regularExpressionWithPattern:@"\\bFROM\\s+bundle_info\\b" options:NSRegularExpressionCaseInsensitive error:&error];
	if (!error && selectRegex) {
		sql = [selectRegex stringByReplacingMatchesInString:sql options:0 range:NSMakeRange(0, sql.length) withTemplate:@"FROM jb_bundle_info_router"];
	}

	error = nil;
	NSRegularExpression *insertRegex = [NSRegularExpression regularExpressionWithPattern:@"\\bINSERT\\s+(OR\\s+\\w+\\s+)?INTO\\s+bundle_info\\b" options:NSRegularExpressionCaseInsensitive error:&error];
	if (!error && insertRegex) {
		sql = [insertRegex stringByReplacingMatchesInString:sql options:0 range:NSMakeRange(0, sql.length) withTemplate:@"INSERT $1INTO jb_bundle_info_router"];
	}

	error = nil;
	NSRegularExpression *updateRegex = [NSRegularExpression regularExpressionWithPattern:@"\\bUPDATE\\s+bundle_info\\b" options:NSRegularExpressionCaseInsensitive error:&error];
	if (!error && updateRegex) {
		sql = [updateRegex stringByReplacingMatchesInString:sql options:0 range:NSMakeRange(0, sql.length) withTemplate:@"UPDATE jb_bundle_info_router"];
	}

	error = nil;
	NSRegularExpression *deleteRegex = [NSRegularExpression regularExpressionWithPattern:@"\\bDELETE\\s+FROM\\s+bundle_info\\b" options:NSRegularExpressionCaseInsensitive error:&error];
	if (!error && deleteRegex) {
		sql = [deleteRegex stringByReplacingMatchesInString:sql options:0 range:NSMakeRange(0, sql.length) withTemplate:@"DELETE FROM jb_bundle_info_router"];
	}

	return sql;
}

static void setupCellularDB(sqlite3 *db, const char *filename)
{
	CC_LOG("CellularUsage.db detected: %s", filename ?: "(null)");
	gCellularDB = db;
	sqlite3_create_function(db, "jb_is_client", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sqlite_jb_is_client, NULL, NULL);
	initializeCellularRouting(db);
	CC_LOG("Cellular routing initialized");
}

static int hook_sqlite3_open(const char *filename, sqlite3 **ppDb)
{
	int r = orig_sqlite3_open(filename, ppDb);
	CC_LOG("sqlite3_open: %s -> %d", filename ?: "(null)", r);
	if (r == SQLITE_OK && filename && strstr(filename, "CellularUsage.db")) {
		setupCellularDB(*ppDb, filename);
	}
	return r;
}

static int hook_sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs)
{
	int r = orig_sqlite3_open_v2(filename, ppDb, flags, zVfs);
	CC_LOG("sqlite3_open_v2: %s -> %d", filename ?: "(null)", r);
	if (r == SQLITE_OK && filename && strstr(filename, "CellularUsage.db")) {
		setupCellularDB(*ppDb, filename);
	}
	return r;
}

static int hook_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail)
{
	if (!zSql) {
		return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
	}

	// CommCenter keeps CellularUsage.db open permanently.
	// If the DB was already open before our hook fired (gCellularDB == NULL),
	// detect it here via sqlite3_db_filename() on every prepare call until found.
	if (db != gCellularDB) {
		const char *filename = sqlite3_db_filename(db, "main");
		static int diagCount = 0;
		if (diagCount < 20) {
			diagCount++;
			CC_LOG("prepare_v2[%d]: db=%p filename=%s sql=%.80s", diagCount, (void*)db, filename ?: "(null)", zSql);
		}
		if (filename && strstr(filename, "CellularUsage.db")) {
			CC_LOG("CellularUsage.db found via prepare hook (already open): %s", filename);
			gCellularDB = db;
			sqlite3_create_function(db, "jb_is_client", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sqlite_jb_is_client, NULL, NULL);
			initializeCellularRouting(db);
			CC_LOG("Cellular routing late-initialized");
		} else {
			return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
		}
	}

	NSString *sql = [NSString stringWithUTF8String:zSql];
	if (!sql) {
		return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
	}

	NSString *rewritten = rewriteSQLForCellularRouter(sql);
	if (![rewritten isEqualToString:sql]) {
		return orig_sqlite3_prepare_v2(db, rewritten.UTF8String, -1, ppStmt, pzTail);
	}

	return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
}

static int hook_sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg)
{
	if (db && db != gCellularDB) {
		const char *filename = sqlite3_db_filename(db, "main");
		if (filename && strstr(filename, "CellularUsage.db")) {
			CC_LOG("CellularUsage.db found via exec hook: %s", filename);
			gCellularDB = db;
			sqlite3_create_function(db, "jb_is_client", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sqlite_jb_is_client, NULL, NULL);
			initializeCellularRouting(db);
			CC_LOG("Cellular routing late-initialized via exec");
		}
	}

	// Also rewrite SQL for exec calls (previously only prepare_v2 was rewritten)
	if (db == gCellularDB && sql) {
		NSString *sqlStr = [NSString stringWithUTF8String:sql];
		if (sqlStr) {
			NSString *rewritten = rewriteSQLForCellularRouter(sqlStr);
			if (![rewritten isEqualToString:sqlStr]) {
				CC_LOG("exec SQL rewritten: %.120s", rewritten.UTF8String);
				return orig_sqlite3_exec(db, rewritten.UTF8String, callback, arg, errmsg);
			}
		}
	}

	return orig_sqlite3_exec(db, sql, callback, arg, errmsg);
}

void commcenterInit(void)
{
	CC_LOG("commcenterInit() called (pid=%d)", getpid());

	MSHookFunction(sqlite3_open, (void *)hook_sqlite3_open, (void **)&orig_sqlite3_open);
	MSHookFunction(sqlite3_open_v2, (void *)hook_sqlite3_open_v2, (void **)&orig_sqlite3_open_v2);
	MSHookFunction(sqlite3_prepare_v2, (void *)hook_sqlite3_prepare_v2, (void **)&orig_sqlite3_prepare_v2);
	MSHookFunction(sqlite3_exec, (void *)hook_sqlite3_exec, (void **)&orig_sqlite3_exec);
	CC_LOG("sqlite3 hooks installed (open + open_v2 + prepare_v2 + exec)");
}

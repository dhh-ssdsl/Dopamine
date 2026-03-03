#import <Foundation/Foundation.h>
#import <substrate.h>
#import <sqlite3.h>
#import <libroot.h>

static sqlite3 *gCellularDB = NULL;
static NSSet<NSString *> *gJailbreakBundleIDs = nil;
static time_t gLastBundleRefresh = 0;

static int (*orig_sqlite3_open_v2)(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
static int (*orig_sqlite3_prepare_v2)(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);

static void refreshJBBundleIDs(void)
{
	NSMutableSet *bundleIDs = [NSMutableSet set];
	NSString *jbAppsPath = [NSString stringWithUTF8String:JBROOT_PATH_CSTRING("/Applications")];
	NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbAppsPath error:nil];
	for (NSString *item in contents) {
		if (![item hasSuffix:@".app"]) continue;
		NSString *appPath = [jbAppsPath stringByAppendingPathComponent:item];
		NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[appPath stringByAppendingPathComponent:@"Info.plist"]];
		NSString *bundleID = info[@"CFBundleIdentifier"];
		if (bundleID) {
			[bundleIDs addObject:bundleID];
		}
	}
	gJailbreakBundleIDs = [bundleIDs copy];
	gLastBundleRefresh = time(NULL);
}

static void refreshJBBundleIDsIfNeeded(void)
{
	time_t now = time(NULL);
	if (!gJailbreakBundleIDs || (now - gLastBundleRefresh) >= 10) {
		refreshJBBundleIDs();
	}
}

static bool isJailbreakBundleID(const char *bundleID)
{
	if (!bundleID) return false;
	refreshJBBundleIDsIfNeeded();
	return [gJailbreakBundleIDs containsObject:[NSString stringWithUTF8String:bundleID]];
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

static void initializeCellularRouting(sqlite3 *db)
{
	const char *jbCellularDir = JBROOT_PATH_CSTRING("/var/wireless/Library/Databases");
	NSString *cellularDir = [NSString stringWithUTF8String:jbCellularDir];
	if (![[NSFileManager defaultManager] fileExistsAtPath:cellularDir]) {
		[[NSFileManager defaultManager] createDirectoryAtPath:cellularDir withIntermediateDirectories:YES attributes:nil error:nil];
	}

	const char *jbCellularPath = JBROOT_PATH_CSTRING("/var/wireless/Library/Databases/.jb_cellular.db");
	char attachSQL[1024];
	snprintf(attachSQL, sizeof(attachSQL), "ATTACH DATABASE '%s' AS jbcellular", jbCellularPath);
	sqlite3_exec(db, attachSQL, NULL, NULL, NULL);

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

static int hook_sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs)
{
	int r = orig_sqlite3_open_v2(filename, ppDb, flags, zVfs);
	if (r == SQLITE_OK && filename && strstr(filename, "CellularUsage.db")) {
		gCellularDB = *ppDb;
		sqlite3_create_function(gCellularDB, "jb_is_client", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sqlite_jb_is_client, NULL, NULL);
		initializeCellularRouting(gCellularDB);
	}
	return r;
}

static int hook_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail)
{
	if (db != gCellularDB || !zSql) {
		return orig_sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
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

void commcenterInit(void)
{
	refreshJBBundleIDs();

	MSHookFunction(sqlite3_open_v2, (void *)hook_sqlite3_open_v2, (void **)&orig_sqlite3_open_v2);
	MSHookFunction(sqlite3_prepare_v2, (void *)hook_sqlite3_prepare_v2, (void **)&orig_sqlite3_prepare_v2);
}

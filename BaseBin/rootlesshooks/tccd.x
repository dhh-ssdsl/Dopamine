#import <Foundation/Foundation.h>
#import <substrate.h>
#import <sqlite3.h>
#import <libroot.h>

static sqlite3 *gTCCDB = NULL;
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

static void initializeTCCRouting(sqlite3 *db)
{
	const char *jbTCCPath = JBROOT_PATH_CSTRING("/basebin/.jb_tcc.db");
	char attachSQL[1024];
	snprintf(attachSQL, sizeof(attachSQL), "ATTACH DATABASE '%s' AS jbtcc", jbTCCPath);
	sqlite3_exec(db, attachSQL, NULL, NULL, NULL);

	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS jbtcc.access AS SELECT * FROM main.access WHERE 0", NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE VIEW IF NOT EXISTS jb_access_router AS "
		"SELECT * FROM main.access UNION ALL SELECT * FROM jbtcc.access",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_router_insert_main "
		"INSTEAD OF INSERT ON jb_access_router "
		"WHEN jb_is_client(NEW.client)=0 "
		"BEGIN "
		"INSERT OR REPLACE INTO main.access VALUES(NEW.service, NEW.client, NEW.client_type, NEW.auth_value, NEW.auth_reason, NEW.auth_version, NEW.csreq, NEW.policy_id, NEW.indirect_object_identifier_type, NEW.indirect_object_identifier, NEW.indirect_object_code_identity, NEW.flags, NEW.last_modified); "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_router_insert_jb "
		"INSTEAD OF INSERT ON jb_access_router "
		"WHEN jb_is_client(NEW.client)=1 "
		"BEGIN "
		"INSERT OR REPLACE INTO jbtcc.access VALUES(NEW.service, NEW.client, NEW.client_type, NEW.auth_value, NEW.auth_reason, NEW.auth_version, NEW.csreq, NEW.policy_id, NEW.indirect_object_identifier_type, NEW.indirect_object_identifier, NEW.indirect_object_code_identity, NEW.flags, NEW.last_modified); "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_router_update_main "
		"INSTEAD OF UPDATE ON jb_access_router "
		"WHEN jb_is_client(OLD.client)=0 "
		"BEGIN "
		"UPDATE main.access SET "
		"service=NEW.service, client=NEW.client, client_type=NEW.client_type, auth_value=NEW.auth_value, auth_reason=NEW.auth_reason, auth_version=NEW.auth_version, csreq=NEW.csreq, policy_id=NEW.policy_id, indirect_object_identifier_type=NEW.indirect_object_identifier_type, indirect_object_identifier=NEW.indirect_object_identifier, indirect_object_code_identity=NEW.indirect_object_code_identity, flags=NEW.flags, last_modified=NEW.last_modified "
		"WHERE service=OLD.service AND client=OLD.client AND client_type=OLD.client_type AND indirect_object_identifier=OLD.indirect_object_identifier; "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_router_update_jb "
		"INSTEAD OF UPDATE ON jb_access_router "
		"WHEN jb_is_client(OLD.client)=1 "
		"BEGIN "
		"UPDATE jbtcc.access SET "
		"service=NEW.service, client=NEW.client, client_type=NEW.client_type, auth_value=NEW.auth_value, auth_reason=NEW.auth_reason, auth_version=NEW.auth_version, csreq=NEW.csreq, policy_id=NEW.policy_id, indirect_object_identifier_type=NEW.indirect_object_identifier_type, indirect_object_identifier=NEW.indirect_object_identifier, indirect_object_code_identity=NEW.indirect_object_code_identity, flags=NEW.flags, last_modified=NEW.last_modified "
		"WHERE service=OLD.service AND client=OLD.client AND client_type=OLD.client_type AND indirect_object_identifier=OLD.indirect_object_identifier; "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_router_delete_main "
		"INSTEAD OF DELETE ON jb_access_router "
		"WHEN jb_is_client(OLD.client)=0 "
		"BEGIN "
		"DELETE FROM main.access WHERE service=OLD.service AND client=OLD.client AND client_type=OLD.client_type AND indirect_object_identifier=OLD.indirect_object_identifier; "
		"END;",
		NULL, NULL, NULL);

	sqlite3_exec(db,
		"CREATE TRIGGER IF NOT EXISTS jb_router_delete_jb "
		"INSTEAD OF DELETE ON jb_access_router "
		"WHEN jb_is_client(OLD.client)=1 "
		"BEGIN "
		"DELETE FROM jbtcc.access WHERE service=OLD.service AND client=OLD.client AND client_type=OLD.client_type AND indirect_object_identifier=OLD.indirect_object_identifier; "
		"END;",
		NULL, NULL, NULL);
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

static int hook_sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs)
{
	int r = orig_sqlite3_open_v2(filename, ppDb, flags, zVfs);
	if (r == SQLITE_OK && filename && strstr(filename, "TCC.db")) {
		gTCCDB = *ppDb;
		sqlite3_create_function(gTCCDB, "jb_is_client", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sqlite_jb_is_client, NULL, NULL);
		initializeTCCRouting(gTCCDB);
	}
	return r;
}

static int hook_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail)
{
	if (db != gTCCDB || !zSql) {
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

void tccdInit(void)
{
	refreshJBBundleIDs();

	MSHookFunction(sqlite3_open_v2, (void *)hook_sqlite3_open_v2, (void **)&orig_sqlite3_open_v2);
	MSHookFunction(sqlite3_prepare_v2, (void *)hook_sqlite3_prepare_v2, (void **)&orig_sqlite3_prepare_v2);
}

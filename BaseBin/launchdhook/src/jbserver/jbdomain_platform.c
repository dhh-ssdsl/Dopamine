#include "jbserver_global.h"
#include "jbsettings.h"

#include <libjailbreak/codesign.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbroot.h>
#include <sqlite3.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern void systemwide_domain_set_enabled(bool enabled);

static void platform_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void platform_log(const char *fmt, ...)
{
	FILE *f = fopen(JBROOT_PATH("/var/mobile/hook_debug.log"), "a");
	if (!f) return;

	time_t t = time(NULL);
	struct tm tm;
	localtime_r(&t, &tm);
	fprintf(f, "%02d:%02d:%02d [jbserver-platform] ", tm.tm_hour, tm.tm_min, tm.tm_sec);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fprintf(f, "\n");
	fclose(f);
}

static const char *platform_cellular_db_path(void)
{
	return JBROOT_PATH("/var/wireless/Library/Databases/CellularUsage.db");
}

static const char *platform_legacy_cellular_db_path(void)
{
	return JBROOT_PATH("/var/wireless/Library/Databases/.jb_cellular.db");
}

static const char *platform_system_cellular_db_path(void)
{
	return "/var/wireless/Library/Databases/CellularUsage.db";
}

static void platform_ensure_parent_dir(const char *path)
{
	if (!path || path[0] != '/') return;

	char dir[PATH_MAX];
	strlcpy(dir, path, sizeof(dir));

	char *slash = strrchr(dir, '/');
	if (!slash || slash == dir) return;
	*slash = '\0';

	for (char *p = dir + 1; *p; p++) {
		if (*p != '/') continue;
		*p = '\0';
		mkdir(dir, 0755);
		*p = '/';
	}
	mkdir(dir, 0755);
}

static int platform_sql_exec(sqlite3 *db, const char *sql, const char *tag)
{
	char *errmsg = NULL;
	int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
	if (rc != SQLITE_OK) {
		platform_log("%s rc=%d err=%s sql=%.160s",
		             tag,
		             rc,
		             errmsg ? errmsg : "unknown",
		             sql ? sql : "(null)");
	}
	if (errmsg) sqlite3_free(errmsg);
	return rc;
}

static void platform_migrate_legacy_cellular_db_if_needed(void)
{
	const char *legacyPath = platform_legacy_cellular_db_path();
	const char *targetPath = platform_cellular_db_path();
	if (access(legacyPath, F_OK) != 0) return;
	if (access(targetPath, F_OK) == 0) return;

	platform_ensure_parent_dir(targetPath);
	if (rename(legacyPath, targetPath) == 0) {
		platform_log("migrated legacy cellular db to %s", targetPath);
	} else {
		platform_log("failed moving legacy cellular db errno=%d", errno);
	}
}

static int platform_query_single_text(sqlite3 *db, const char *sql, char **textOut)
{
	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) return rc;

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		const unsigned char *text = sqlite3_column_text(stmt, 0);
		if (text && textOut) *textOut = strdup((const char *)text);
		rc = SQLITE_OK;
	}
	else if (rc == SQLITE_DONE) {
		rc = SQLITE_OK;
	}

	sqlite3_finalize(stmt);
	return rc;
}

static char *platform_make_create_table_if_needed(const char *createSQL)
{
	if (!createSQL) return NULL;

	const char *prefix = "CREATE TABLE ";
	size_t prefixLen = strlen(prefix);
	if (strncasecmp(createSQL, prefix, prefixLen) != 0) {
		return strdup(createSQL);
	}

	if (strcasestr(createSQL, "IF NOT EXISTS")) {
		return strdup(createSQL);
	}

	const char *suffix = createSQL + prefixLen;
	const char *inject = "CREATE TABLE IF NOT EXISTS ";
	size_t outLen = strlen(inject) + strlen(suffix) + 1;
	char *out = malloc(outLen);
	if (!out) return NULL;
	snprintf(out, outLen, "%s%s", inject, suffix);
	return out;
}

static int platform_ensure_cellular_schema(sqlite3 *db)
{
	char *tableExists = NULL;
	int rc = platform_query_single_text(db,
		"SELECT name FROM sqlite_master WHERE type='table' AND name='bundle_info'",
		&tableExists);
	if (rc == SQLITE_OK && tableExists) {
		free(tableExists);
		return 0;
	}
	if (tableExists) free(tableExists);

	char *createSQL = NULL;
	sqlite3 *systemDB = NULL;
	if (sqlite3_open_v2(platform_system_cellular_db_path(), &systemDB, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
		platform_query_single_text(systemDB,
			"SELECT sql FROM sqlite_master WHERE type='table' AND name='bundle_info'",
			&createSQL);
		sqlite3_close(systemDB);
	}

	char *createIfNeeded = platform_make_create_table_if_needed(createSQL);
	if (createSQL) free(createSQL);

	if (createIfNeeded) {
		rc = platform_sql_exec(db, createIfNeeded, "ensure_cellular_schema(create)");
		free(createIfNeeded);
		if (rc == SQLITE_OK) {
			platform_log("ensured bundle_info schema from system db");
			return 0;
		}
	}

	rc = platform_sql_exec(db,
		"CREATE TABLE IF NOT EXISTS bundle_info (bundle_id TEXT PRIMARY KEY, flags INTEGER)",
		"ensure_cellular_schema(fallback)");
	if (rc == SQLITE_OK) {
		platform_log("ensured bundle_info schema via fallback");
	}
	return rc == SQLITE_OK ? 0 : -1;
}

static int platform_open_cellular_db(sqlite3 **dbOut, bool createIfMissing)
{
	if (!dbOut) return -1;
	*dbOut = NULL;

	platform_migrate_legacy_cellular_db_if_needed();
	const char *path = platform_cellular_db_path();

	if (!createIfMissing && access(path, F_OK) != 0) {
		return 1;
	}

	platform_ensure_parent_dir(path);
	int flags = createIfMissing ? (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) : SQLITE_OPEN_READONLY;
	int rc = sqlite3_open_v2(path, dbOut, flags, NULL);
	if (rc != SQLITE_OK) {
		platform_log("open cellular db failed rc=%d path=%s", rc, path);
		if (*dbOut) sqlite3_close(*dbOut);
		*dbOut = NULL;
		return rc;
	}

	if (createIfMissing) {
		rc = platform_ensure_cellular_schema(*dbOut);
		if (rc != 0) {
			sqlite3_close(*dbOut);
			*dbOut = NULL;
			return rc;
		}
	}
	return 0;
}

static int platform_cellular_usage_load(xpc_object_t *rowsOut)
{
	if (!rowsOut) return -1;

	*rowsOut = xpc_array_create_empty();
	sqlite3 *db = NULL;
	int openRC = platform_open_cellular_db(&db, false);
	if (openRC == 1) {
		platform_log("cellular load: mirror db missing, returning empty");
		return 0;
	}
	if (openRC != 0 || !db) {
		return -1;
	}

	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, "SELECT bundle_id, flags FROM bundle_info", -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		platform_log("cellular load prepare failed rc=%d", rc);
		sqlite3_close(db);
		return -1;
	}

	size_t rowCount = 0;
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		const unsigned char *bundleID = sqlite3_column_text(stmt, 0);
		int64_t flags = sqlite3_column_int64(stmt, 1);
		if (!bundleID) continue;

		xpc_object_t row = xpc_dictionary_create_empty();
		xpc_dictionary_set_string(row, "bundle-id", (const char *)bundleID);
		xpc_dictionary_set_int64(row, "flags", flags);
		xpc_array_append_value(*rowsOut, row);
		xpc_release(row);
		platform_log("cellular load row bundle=%s flags=%lld", (const char *)bundleID, flags);
		rowCount++;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	platform_log("cellular load returned %zu rows", rowCount);
	return 0;
}

static int platform_cellular_usage_upsert(const char *bundleID, uint64_t flags)
{
	if (!bundleID || bundleID[0] == '\0') return -1;

	sqlite3 *db = NULL;
	if (platform_open_cellular_db(&db, true) != 0 || !db) {
		return -1;
	}

	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db,
		"INSERT OR REPLACE INTO bundle_info(bundle_id, flags) VALUES(?, ?)",
		-1,
		&stmt,
		NULL);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(stmt, 1, bundleID, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int64(stmt, 2, (sqlite3_int64)flags);
		rc = sqlite3_step(stmt);
	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if (rc != SQLITE_DONE) {
		platform_log("cellular upsert failed bundle=%s flags=%llu rc=%d",
		             bundleID,
		             flags,
		             rc);
		return -1;
	}

	platform_log("cellular upsert bundle=%s flags=%llu", bundleID, flags);
	return 0;
}

static int platform_cellular_usage_delete(const char *bundleID)
{
	if (!bundleID || bundleID[0] == '\0') return -1;

	sqlite3 *db = NULL;
	if (platform_open_cellular_db(&db, true) != 0 || !db) {
		return -1;
	}

	sqlite3_stmt *stmt = NULL;
	int rc = sqlite3_prepare_v2(db, "DELETE FROM bundle_info WHERE bundle_id=?", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(stmt, 1, bundleID, -1, SQLITE_TRANSIENT);
		rc = sqlite3_step(stmt);
	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if (rc != SQLITE_DONE) {
		platform_log("cellular delete failed bundle=%s rc=%d", bundleID, rc);
		return -1;
	}

	platform_log("cellular delete bundle=%s", bundleID);
	return 0;
}

static bool platform_domain_allowed(audit_token_t clientToken)
{
	pid_t pid = audit_token_to_pid(clientToken);
	uint32_t csflags = 0;
	if (csops_audittoken(pid, CS_OPS_STATUS, &csflags, sizeof(csflags), &clientToken) != 0) return false;
	return (csflags & CS_PLATFORM_BINARY);
}

int platform_set_process_debugged(uint64_t pid, bool fullyDebugged)
{
	uint64_t proc = proc_find(pid);
	if (!proc) return -1;
	cs_allow_invalid(proc, fullyDebugged);
	return 0;
}

static int platform_stage_jailbreak_update(const char *updateTar)
{
	if (!access(updateTar, F_OK)) {
		setenv("STAGED_JAILBREAK_UPDATE", updateTar, 1);
		return 0;
	}
	return 1;
}

struct jbserver_domain gPlatformDomain = {
	.permissionHandler = platform_domain_allowed,
	.actions = {
		// JBS_PLATFORM_SET_PROCESS_DEBUGGED
		{
			.handler = platform_set_process_debugged,
			.args = (jbserver_arg[]){
				{ .name = "pid", .type = JBS_TYPE_UINT64, .out = false },
				{ .name = "fully-debugged", .type = JBS_TYPE_BOOL, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_STAGE_JAILBREAK_UPDATE
		{
			.handler = platform_stage_jailbreak_update,
			.args = (jbserver_arg[]){
				{ .name = "update-tar", .type = JBS_TYPE_STRING, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_JBSETTINGS_SET
		{
			.handler = jbsettings_set,
			.args = (jbserver_arg[]){
				{ .name = "key", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "value", .type = JBS_TYPE_XPC_GENERIC, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_SET_SYSTEMWIDE_DOMAIN_ENABLED
		{
			.handler = systemwide_domain_set_enabled,
			.args = (jbserver_arg[]){
				{ .name = "enabled", .type = JBS_TYPE_BOOL, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_CELLULAR_USAGE_LOAD
		{
			.handler = platform_cellular_usage_load,
			.args = (jbserver_arg[]){
				{ .name = "rows", .type = JBS_TYPE_ARRAY, .out = true },
				{ 0 },
			},
		},
		// JBS_PLATFORM_CELLULAR_USAGE_UPSERT
		{
			.handler = platform_cellular_usage_upsert,
			.args = (jbserver_arg[]){
				{ .name = "bundle-id", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "flags", .type = JBS_TYPE_UINT64, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_CELLULAR_USAGE_DELETE
		{
			.handler = platform_cellular_usage_delete,
			.args = (jbserver_arg[]){
				{ .name = "bundle-id", .type = JBS_TYPE_STRING, .out = false },
				{ 0 },
			},
		},
		{ 0 },
	},
};

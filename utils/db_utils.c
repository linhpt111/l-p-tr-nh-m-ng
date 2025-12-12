#include "utils.h"

static int exec_simple(sqlite3 *db, const char *sql) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("SQLite error: %s", errmsg ? errmsg : "unknown");
        sqlite3_free(errmsg);
        return -1;
    }
    return 0;
}

int db_init(DbContext *ctx, const char *path) {
    if (!ctx || !path) return -1;

    if (sqlite3_open(path, &ctx->db) != SQLITE_OK) {
        LOG_ERROR("Failed to open DB at %s: %s", path, sqlite3_errmsg(ctx->db));
        return -1;
    }

    pthread_mutex_init(&ctx->lock, NULL);

    const char *create_online =
        "CREATE TABLE IF NOT EXISTS online_users ("
        "username TEXT PRIMARY KEY, "
        "last_seen DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";
    const char *create_messages =
        "CREATE TABLE IF NOT EXISTS messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "sender TEXT NOT NULL, "
        "receiver TEXT, "
        "body TEXT NOT NULL, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";
    const char *create_groups =
        "CREATE TABLE IF NOT EXISTS group_members ("
        "groupname TEXT NOT NULL, "
        "username TEXT NOT NULL, "
        "joined_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "PRIMARY KEY (groupname, username)"
        ");";

    if (exec_simple(ctx->db, create_online) != 0) {
        db_close(ctx);
        return -1;
    }
    if (exec_simple(ctx->db, create_messages) != 0) {
        db_close(ctx);
        return -1;
    }
    if (exec_simple(ctx->db, create_groups) != 0) {
        db_close(ctx);
        return -1;
    }

    return 0;
}

void db_close(DbContext *ctx) {
    if (!ctx) return;
    if (ctx->db) {
        sqlite3_close(ctx->db);
        ctx->db = NULL;
    }
    pthread_mutex_destroy(&ctx->lock);
}

int db_set_user_online(DbContext *ctx, const char *username) {
    if (!ctx || !ctx->db || !username) return -1;

    pthread_mutex_lock(&ctx->lock);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO online_users (username, last_seen) VALUES (?1, CURRENT_TIMESTAMP);";
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&ctx->lock);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_set_user_offline(DbContext *ctx, const char *username) {
    if (!ctx || !ctx->db || !username) return -1;

    pthread_mutex_lock(&ctx->lock);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM online_users WHERE username = ?1;";
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&ctx->lock);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_save_message(DbContext *ctx, const char *sender, const char *receiver, const char *body) {
    if (!ctx || !ctx->db || !sender || !body) return -1;

    pthread_mutex_lock(&ctx->lock);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO messages (sender, receiver, body) VALUES (?1, ?2, ?3);";
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_TRANSIENT);
        if (receiver) {
            sqlite3_bind_text(stmt, 2, receiver, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 2);
        }
        sqlite3_bind_text(stmt, 3, body, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&ctx->lock);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_group_join(DbContext *ctx, const char *username, const char *groupname) {
    if (!ctx || !ctx->db || !username || !groupname) return -1;

    pthread_mutex_lock(&ctx->lock);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO group_members (groupname, username) VALUES (?1, ?2);";
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, groupname, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&ctx->lock);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_group_leave(DbContext *ctx, const char *username, const char *groupname) {
    if (!ctx || !ctx->db || !username || !groupname) return -1;
    pthread_mutex_lock(&ctx->lock);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM group_members WHERE groupname = ?1 AND username = ?2;";
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, groupname, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&ctx->lock);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_group_leave_all(DbContext *ctx, const char *username) {
    if (!ctx || !ctx->db || !username) return -1;
    pthread_mutex_lock(&ctx->lock);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM group_members WHERE username = ?1;";
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&ctx->lock);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

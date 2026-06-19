#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <microhttpd.h>

#include "docs/docs_ui.h"
#include "http/response.h"
#include "http/routes_meta.h"

#define DEFAULT_PORT 8080
#define DEFAULT_DB_PATH "./data/app.db"
#define DEFAULT_KEY_FILE "./data/user_key.b64"
#define DEFAULT_SESSION_TTL_HOURS 12
#define DEFAULT_ADMIN_USERNAME "admin"
#define DEFAULT_ADMIN_PASSWORD "Admin@123456"

#define MAX_BODY_SIZE (1024 * 1024)
#define RAW_TOKEN_BYTES 32
#define TOKEN_HASH_HEX_LEN (crypto_generichash_BYTES * 2)

typedef struct {
    int port;
    int session_ttl_hours;
    const char *db_path;
    const char *key_file;
} ServerConfig;

typedef struct {
    int user_id;
    char username[128];
    char role[32];
} AuthUser;

static ServerConfig g_cfg;
static sqlite3 *g_db = NULL;
static pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned char g_user_key[crypto_secretbox_KEYBYTES];
static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static char *dup_cstr(const char *src) {
    if (src == NULL) {
        return NULL;
    }
    const size_t len = strlen(src);
    char *dst = (char *)malloc(len + 1);
    if (dst == NULL) {
        return NULL;
    }
    memcpy(dst, src, len + 1);
    return dst;
}

static int env_to_int(const char *name, int fallback) {
    const char *v = getenv(name);
    if (v == NULL || *v == '\0') {
        return fallback;
    }

    char *end = NULL;
    errno = 0;
    long n = strtol(v, &end, 10);
    if (errno != 0 || end == v || *end != '\0' || n <= 0 || n > INT_MAX) {
        return fallback;
    }
    return (int)n;
}

static void bytes_to_hex(const unsigned char *in, size_t in_len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; ++i) {
        out[i * 2] = hex[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
}

static int hash_token(const char *token, char out_hex[TOKEN_HASH_HEX_LEN + 1]) {
    unsigned char hash[crypto_generichash_BYTES];
    if (crypto_generichash(hash, sizeof(hash), (const unsigned char *)token,
                           strlen(token), NULL, 0) != 0) {
        return -1;
    }
    bytes_to_hex(hash, sizeof(hash), out_hex);
    return 0;
}

static int generate_access_token(char *out, size_t out_size) {
    const size_t needed =
        sodium_base64_encoded_len(RAW_TOKEN_BYTES,
                                  sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (out_size < needed) {
        return -1;
    }

    unsigned char raw[RAW_TOKEN_BYTES];
    randombytes_buf(raw, sizeof(raw));
    sodium_bin2base64(out, out_size, raw, sizeof(raw),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return 0;
}

static time_t now_epoch(void) { return time(NULL); }

static int ensure_parent_dir(const char *path) {
    if (path == NULL) {
        return -1;
    }

    char *copy = dup_cstr(path);
    if (copy == NULL) {
        return -1;
    }

    for (char *p = copy + 1; *p != '\0'; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
                free(copy);
                return -1;
            }
            *p = '/';
        }
    }

    free(copy);
    return 0;
}

static int load_or_create_key(void) {
    const char *env_key = getenv("USER_DATA_KEY_B64");
    if (env_key != NULL && *env_key != '\0') {
        size_t bin_len = 0;
        if (sodium_base642bin(g_user_key, sizeof(g_user_key), env_key,
                              strlen(env_key), NULL, &bin_len, NULL,
                              sodium_base64_VARIANT_ORIGINAL) == 0 &&
            bin_len == sizeof(g_user_key)) {
            return 0;
        }
        fprintf(stderr,
                "[WARN] USER_DATA_KEY_B64 无效，将尝试从密钥文件加载。\n");
    }

    FILE *f = fopen(g_cfg.key_file, "rb");
    if (f != NULL) {
        char line[256];
        if (fgets(line, sizeof(line), f) != NULL) {
            line[strcspn(line, "\r\n")] = '\0';
            size_t bin_len = 0;
            if (sodium_base642bin(g_user_key, sizeof(g_user_key), line,
                                  strlen(line), NULL, &bin_len, NULL,
                                  sodium_base64_VARIANT_ORIGINAL) == 0 &&
                bin_len == sizeof(g_user_key)) {
                fclose(f);
                return 0;
            }
        }
        fclose(f);
    }

    randombytes_buf(g_user_key, sizeof(g_user_key));
    const size_t enc_len = sodium_base64_encoded_len(
        sizeof(g_user_key), sodium_base64_VARIANT_ORIGINAL);
    char *b64 = (char *)malloc(enc_len + 2);
    if (b64 == NULL) {
        return -1;
    }

    sodium_bin2base64(b64, enc_len + 2, g_user_key, sizeof(g_user_key),
                      sodium_base64_VARIANT_ORIGINAL);

    if (ensure_parent_dir(g_cfg.key_file) != 0) {
        free(b64);
        return -1;
    }

    f = fopen(g_cfg.key_file, "wb");
    if (f == NULL) {
        free(b64);
        return -1;
    }

    fprintf(f, "%s\n", b64);
    fclose(f);
    chmod(g_cfg.key_file, 0600);
    free(b64);

    fprintf(stdout,
            "[INFO] 已自动生成新的用户字段加密密钥: %s\n"
            "[INFO] 请妥善备份该文件，丢失后将无法解密已有用户信息。\n",
            g_cfg.key_file);

    return 0;
}

static int encrypt_text(const char *plain, char **out_b64) {
    if (plain == NULL) {
        plain = "";
    }

    const size_t plain_len = strlen(plain);
    const size_t boxed_len = crypto_secretbox_NONCEBYTES +
                             crypto_secretbox_MACBYTES + plain_len;

    unsigned char *boxed = (unsigned char *)malloc(boxed_len);
    if (boxed == NULL) {
        return -1;
    }

    unsigned char *nonce = boxed;
    unsigned char *cipher = boxed + crypto_secretbox_NONCEBYTES;
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_easy(cipher, (const unsigned char *)plain, plain_len,
                              nonce, g_user_key) != 0) {
        free(boxed);
        return -1;
    }

    const size_t enc_len =
        sodium_base64_encoded_len(boxed_len, sodium_base64_VARIANT_ORIGINAL);
    char *b64 = (char *)malloc(enc_len + 1);
    if (b64 == NULL) {
        free(boxed);
        return -1;
    }

    sodium_bin2base64(b64, enc_len + 1, boxed, boxed_len,
                      sodium_base64_VARIANT_ORIGINAL);

    free(boxed);
    *out_b64 = b64;
    return 0;
}

static int decrypt_text(const char *b64, char **out_plain) {
    if (b64 == NULL || *b64 == '\0') {
        *out_plain = dup_cstr("");
        return *out_plain == NULL ? -1 : 0;
    }

    const size_t max_len = strlen(b64) * 3 / 4 + 4;
    unsigned char *boxed = (unsigned char *)malloc(max_len);
    if (boxed == NULL) {
        return -1;
    }

    size_t boxed_len = 0;
    if (sodium_base642bin(boxed, max_len, b64, strlen(b64), NULL, &boxed_len,
                          NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
        free(boxed);
        return -1;
    }

    if (boxed_len <
        crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        free(boxed);
        return -1;
    }

    const unsigned char *nonce = boxed;
    const unsigned char *cipher = boxed + crypto_secretbox_NONCEBYTES;
    const size_t cipher_len = boxed_len - crypto_secretbox_NONCEBYTES;
    const size_t plain_len = cipher_len - crypto_secretbox_MACBYTES;

    unsigned char *plain = (unsigned char *)malloc(plain_len + 1);
    if (plain == NULL) {
        free(boxed);
        return -1;
    }

    if (crypto_secretbox_open_easy(plain, cipher, cipher_len, nonce,
                                   g_user_key) != 0) {
        free(boxed);
        free(plain);
        return -1;
    }

    plain[plain_len] = '\0';
    free(boxed);
    *out_plain = (char *)plain;
    return 0;
}

static int db_exec(const char *sql) {
    char *err = NULL;
    const int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        if (err != NULL) {
            fprintf(stderr, "[DB] SQL执行失败: %s\n", err);
            sqlite3_free(err);
        }
        return -1;
    }
    return 0;
}

static int db_init(void) {
    if (ensure_parent_dir(g_cfg.db_path) != 0) {
        fprintf(stderr, "[DB] 无法创建数据库目录: %s\n", g_cfg.db_path);
        return -1;
    }

    if (sqlite3_open_v2(g_cfg.db_path, &g_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        fprintf(stderr, "[DB] 打开数据库失败: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_busy_timeout(g_db, 5000);

    const char *schema_sql =
        "PRAGMA foreign_keys = ON;"
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = NORMAL;"

        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT NOT NULL UNIQUE,"
        "  password_hash TEXT NOT NULL,"
        "  role TEXT NOT NULL CHECK(role IN ('admin','staff')),"
        "  full_name_enc TEXT,"
        "  email_enc TEXT,"
        "  phone_enc TEXT,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"

        "CREATE TABLE IF NOT EXISTS sessions ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  user_id INTEGER NOT NULL,"
        "  token_hash TEXT NOT NULL UNIQUE,"
        "  expires_at INTEGER NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE"
        ");"

        "CREATE TABLE IF NOT EXISTS products ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  sku TEXT NOT NULL UNIQUE,"
        "  name TEXT NOT NULL,"
        "  unit TEXT NOT NULL DEFAULT '瓶',"
        "  stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK(stock_quantity >= 0),"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"

        "CREATE TABLE IF NOT EXISTS stock_movements ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  product_id INTEGER NOT NULL,"
        "  movement_type TEXT NOT NULL CHECK(movement_type IN ('IN','OUT')),"
        "  quantity INTEGER NOT NULL CHECK(quantity > 0),"
        "  unit_price_cents INTEGER NOT NULL CHECK(unit_price_cents >= 0),"
        "  note TEXT,"
        "  operator_user_id INTEGER NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(product_id) REFERENCES products(id),"
        "  FOREIGN KEY(operator_user_id) REFERENCES users(id)"
        ");"

        "CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);"
        "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);"
        "CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);"
        "CREATE INDEX IF NOT EXISTS idx_movements_product_id ON "
        "stock_movements(product_id);"
        "CREATE INDEX IF NOT EXISTS idx_movements_created_at ON "
        "stock_movements(created_at);"

        "CREATE TABLE IF NOT EXISTS devices ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  code TEXT NOT NULL UNIQUE,"
        "  name TEXT NOT NULL,"
        "  device_type TEXT NOT NULL CHECK(device_type IN ('COLD','NORMAL','HOT')),"
        "  min_temp_c REAL NOT NULL,"
        "  max_temp_c REAL NOT NULL,"
        "  current_temp_c REAL,"
        "  is_suspended INTEGER NOT NULL DEFAULT 0 CHECK(is_suspended IN (0,1)),"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"

        "CREATE TABLE IF NOT EXISTS device_products ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  device_id INTEGER NOT NULL,"
        "  product_id INTEGER NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,"
        "  FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,"
        "  UNIQUE(device_id, product_id)"
        ");"

        "CREATE TABLE IF NOT EXISTS temperature_alerts ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  device_id INTEGER NOT NULL,"
        "  alert_type TEXT NOT NULL CHECK(alert_type IN ('OVERHEAT','UNDERHEAT')),"
        "  start_time TEXT NOT NULL,"
        "  end_time TEXT,"
        "  affected_products TEXT,"
        "  is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),"
        "  start_temp_c REAL NOT NULL,"
        "  end_temp_c REAL,"
        "  note TEXT,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  FOREIGN KEY(device_id) REFERENCES devices(id)"
        ");"

        "CREATE INDEX IF NOT EXISTS idx_devices_code ON devices(code);"
        "CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);"
        "CREATE INDEX IF NOT EXISTS idx_device_products_device ON device_products(device_id);"
        "CREATE INDEX IF NOT EXISTS idx_device_products_product ON device_products(product_id);"
        "CREATE INDEX IF NOT EXISTS idx_alerts_device ON temperature_alerts(device_id);"
        "CREATE INDEX IF NOT EXISTS idx_alerts_active ON temperature_alerts(is_active);"

        "INSERT OR IGNORE INTO products (sku, name, unit, stock_quantity) VALUES "
        "('SEED-WATER-550', '系统示例矿泉水550ml', '瓶', 50);"

        "INSERT OR IGNORE INTO devices (code, name, device_type, min_temp_c, max_temp_c, current_temp_c) VALUES "
        "('DEV-COLD-001', '冷藏柜1号', 'COLD', 2.0, 8.0, 5.0),"
        "('DEV-NORMAL-001', '常温柜1号', 'NORMAL', 10.0, 30.0, 22.0),"
        "('DEV-HOT-001', '加热柜1号', 'HOT', 55.0, 65.0, 60.0);";

    if (db_exec(schema_sql) != 0) {
        return -1;
    }

    return 0;
}

static int append_body(ConnectionInfo *ci, const char *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    if (ci->body_size + size > MAX_BODY_SIZE) {
        return -1;
    }

    char *new_buf = (char *)realloc(ci->body, ci->body_size + size + 1);
    if (new_buf == NULL) {
        return -1;
    }

    ci->body = new_buf;
    memcpy(ci->body + ci->body_size, data, size);
    ci->body_size += size;
    ci->body[ci->body_size] = '\0';
    return 0;
}

static int is_method_with_body(const char *method) {
    return strcmp(method, MHD_HTTP_METHOD_POST) == 0 ||
           strcmp(method, MHD_HTTP_METHOD_PUT) == 0 ||
           strcmp(method, MHD_HTTP_METHOD_PATCH) == 0 ||
           strcmp(method, MHD_HTTP_METHOD_DELETE) == 0;
}

static int parse_json_body(ConnectionInfo *ci, json_t **out,
                           char err_msg[256]) {
    if (ci->body_size == 0) {
        snprintf(err_msg, 256, "请求体不能为空");
        return -1;
    }

    json_error_t jerr;
    json_t *obj = json_loadb(ci->body, ci->body_size, 0, &jerr);
    if (obj == NULL || !json_is_object(obj)) {
        if (obj != NULL) {
            json_decref(obj);
        }
        snprintf(err_msg, 256, "JSON 格式错误: %s", jerr.text);
        return -1;
    }

    *out = obj;
    return 0;
}

static const char *safe_col_text(sqlite3_stmt *stmt, int col) {
    const unsigned char *text = sqlite3_column_text(stmt, col);
    return text == NULL ? "" : (const char *)text;
}

static int db_user_count(int *count_out) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM users;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    *count_out = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return 0;
}

static int ensure_default_admin_user(void) {
    int user_count = 0;
    if (db_user_count(&user_count) != 0) {
        fprintf(stderr, "[DB] 查询用户数量失败，无法初始化默认管理员\n");
        return -1;
    }
    if (user_count > 0) {
        return 0;
    }

    const char *admin_username = getenv("DEFAULT_ADMIN_USERNAME");
    if (admin_username == NULL || *admin_username == '\0') {
        admin_username = DEFAULT_ADMIN_USERNAME;
    }

    const char *admin_password = getenv("DEFAULT_ADMIN_PASSWORD");
    if (admin_password == NULL || *admin_password == '\0') {
        admin_password = DEFAULT_ADMIN_PASSWORD;
    }

    char password_hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(password_hash, admin_password, strlen(admin_password),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        fprintf(stderr, "[SECURITY] 默认管理员密码哈希失败\n");
        return -1;
    }

    char *full_name_enc = NULL;
    char *email_enc = NULL;
    char *phone_enc = NULL;
    if (encrypt_text("系统管理员", &full_name_enc) != 0 ||
        encrypt_text("admin@local", &email_enc) != 0 ||
        encrypt_text("", &phone_enc) != 0) {
        free(full_name_enc);
        free(email_enc);
        free(phone_enc);
        fprintf(stderr, "[SECURITY] 默认管理员信息加密失败\n");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO users (username, password_hash, role, full_name_enc, "
        "email_enc, phone_enc) VALUES (?, ?, 'admin', ?, ?, ?);";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        free(full_name_enc);
        free(email_enc);
        free(phone_enc);
        fprintf(stderr, "[DB] 默认管理员插入预编译失败\n");
        return -1;
    }

    sqlite3_bind_text(stmt, 1, admin_username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, full_name_enc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, email_enc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, phone_enc, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(full_name_enc);
    free(email_enc);
    free(phone_enc);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[DB] 默认管理员创建失败\n");
        return -1;
    }

    fprintf(stdout,
            "[INFO] 已初始化默认管理员账号: %s\n"
            "[INFO] 默认管理员密码可通过环境变量 DEFAULT_ADMIN_PASSWORD 覆盖\n",
            admin_username);
    return 0;
}

static int ensure_seed_stock_movement_consistency(void) {
    sqlite3_stmt *stmt = NULL;
    int admin_user_id = 0;
    int rc = sqlite3_prepare_v2(
        g_db, "SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1;", -1,
        &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DB] 查询管理员失败，无法修复种子库存流水\n");
        return -1;
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        admin_user_id = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    if (admin_user_id <= 0) {
        return 0;
    }

    int product_id = 0;
    int stock_quantity = 0;
    rc = sqlite3_prepare_v2(
        g_db, "SELECT id, stock_quantity FROM products WHERE sku=? LIMIT 1;", -1,
        &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DB] 查询种子商品失败，无法修复种子库存流水\n");
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "SEED-WATER-550", -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        product_id = sqlite3_column_int(stmt, 0);
        stock_quantity = sqlite3_column_int(stmt, 1);
    }
    sqlite3_finalize(stmt);
    if (product_id <= 0) {
        return 0;
    }

    int in_total = 0;
    int out_total = 0;
    rc = sqlite3_prepare_v2(
        g_db,
        "SELECT "
        "COALESCE(SUM(CASE WHEN movement_type='IN' THEN quantity ELSE 0 END), 0), "
        "COALESCE(SUM(CASE WHEN movement_type='OUT' THEN quantity ELSE 0 END), 0) "
        "FROM stock_movements WHERE product_id=?;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DB] 查询种子商品流水失败，无法修复种子库存流水\n");
        return -1;
    }
    sqlite3_bind_int(stmt, 1, product_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "[DB] 读取种子商品流水失败，无法修复种子库存流水\n");
        return -1;
    }
    in_total = sqlite3_column_int(stmt, 0);
    out_total = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);

    if (in_total > 0) {
        return 0;
    }

    int inferred_initial_in = stock_quantity + out_total;
    if (inferred_initial_in <= 0) {
        return 0;
    }

    rc = sqlite3_prepare_v2(
        g_db,
        "INSERT INTO stock_movements "
        "(product_id, movement_type, quantity, unit_price_cents, note, "
        "operator_user_id) "
        "VALUES (?, 'IN', ?, 0, '系统初始化库存补录', ?);",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DB] 补录种子库存流水预编译失败\n");
        return -1;
    }
    sqlite3_bind_int(stmt, 1, product_id);
    sqlite3_bind_int(stmt, 2, inferred_initial_in);
    sqlite3_bind_int(stmt, 3, admin_user_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[DB] 补录种子库存流水失败\n");
        return -1;
    }

    fprintf(stdout, "[INFO] 已修复种子商品库存流水: sku=SEED-WATER-550, in=%d\n",
            inferred_initial_in);
    return 0;
}

static int authenticate_request(struct MHD_Connection *connection,
                                AuthUser *out_user,
                                char token_hash_hex[TOKEN_HASH_HEX_LEN + 1]) {
    const char *auth_header =
        MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
    if (auth_header == NULL || strncmp(auth_header, "Bearer ", 7) != 0) {
        return 0;
    }

    const char *token = auth_header + 7;
    if (*token == '\0') {
        return 0;
    }

    if (hash_token(token, token_hash_hex) != 0) {
        return 0;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT u.id, u.username, u.role "
        "FROM sessions s "
        "JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ? "
        "LIMIT 1;";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, token_hash_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now_epoch());

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    out_user->user_id = sqlite3_column_int(stmt, 0);
    snprintf(out_user->username, sizeof(out_user->username), "%s",
             safe_col_text(stmt, 1));
    snprintf(out_user->role, sizeof(out_user->role), "%s", safe_col_text(stmt, 2));

    sqlite3_finalize(stmt);
    return 1;
}

static int is_admin_role(const AuthUser *user) {
    return strcmp(user->role, "admin") == 0;
}

static int parse_int_field(json_t *obj, const char *key, int min, int max,
                           int *out) {
    json_t *v = json_object_get(obj, key);
    if (!json_is_integer(v)) {
        return -1;
    }

    json_int_t n = json_integer_value(v);
    if (n < min || n > max) {
        return -1;
    }

    *out = (int)n;
    return 0;
}

static int parse_real_field(json_t *obj, const char *key, double min, double max,
                            double *out) {
    json_t *v = json_object_get(obj, key);
    if (!json_is_number(v)) {
        return -1;
    }

    double n = json_real_value(v);
    if (n < min || n > max) {
        return -1;
    }

    *out = n;
    return 0;
}

static int require_string_field(json_t *obj, const char *key, size_t max_len,
                                const char **out) {
    json_t *v = json_object_get(obj, key);
    if (!json_is_string(v)) {
        return -1;
    }

    const char *s = json_string_value(v);
    if (s == NULL) {
        return -1;
    }

    size_t len = strlen(s);
    if (len == 0 || len > max_len) {
        return -1;
    }

    *out = s;
    return 0;
}

static const char *optional_string_field(json_t *obj, const char *key,
                                         size_t max_len) {
    json_t *v = json_object_get(obj, key);
    if (v == NULL || json_is_null(v)) {
        return "";
    }
    if (!json_is_string(v)) {
        return NULL;
    }

    const char *s = json_string_value(v);
    if (s == NULL || strlen(s) > max_len) {
        return NULL;
    }
    return s;
}

static enum MHD_Result handle_health(struct MHD_Connection *connection) {
    json_t *data = json_object();
    json_object_set_new(data, "service", json_string("jinxiaocun-backend-c"));
    json_object_set_new(data, "status", json_string("ok"));
    json_object_set_new(data, "timestamp", json_integer((json_int_t)now_epoch()));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_register(struct MHD_Connection *connection,
                                       ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *username = NULL;
    const char *password = NULL;
    if (require_string_field(body, "username", 64, &username) != 0 ||
        require_string_field(body, "password", 128, &password) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "username/password 必填，且长度必须合法");
    }

    const char *full_name = optional_string_field(body, "full_name", 128);
    const char *email = optional_string_field(body, "email", 128);
    const char *phone = optional_string_field(body, "phone", 64);
    if (full_name == NULL || email == NULL || phone == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "full_name/email/phone 必须是字符串且长度合法");
    }

    const char *role_input = optional_string_field(body, "role", 16);
    if (role_input == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "role 必须是字符串");
    }

    pthread_mutex_lock(&g_db_mutex);

    int user_count = 0;
    if (db_user_count(&user_count) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询用户数量失败");
    }

    AuthUser creator;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    const int first_user = (user_count == 0);
    if (!first_user) {
        if (!authenticate_request(connection, &creator, token_hash)) {
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_UNAUTHORIZED,
                                "UNAUTHORIZED", "需要管理员身份创建用户");
        }
        if (!is_admin_role(&creator)) {
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_FORBIDDEN, "FORBIDDEN",
                                "仅管理员可创建用户");
        }
    }

    const char *role = "staff";
    if (first_user) {
        role = "admin";
    } else if (role_input != NULL && *role_input != '\0') {
        if (strcmp(role_input, "admin") != 0 && strcmp(role_input, "staff") != 0) {
            pthread_mutex_unlock(&g_db_mutex);
            json_decref(body);
            return respond_error(connection, MHD_HTTP_BAD_REQUEST,
                                "INVALID_INPUT", "role 仅支持 admin/staff");
        }
        role = role_input;
    }

    char username_copy[65];
    char role_copy[17];
    snprintf(username_copy, sizeof(username_copy), "%s", username);
    snprintf(role_copy, sizeof(role_copy), "%s", role);

    char password_hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(password_hash, password, strlen(password),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "密码加密失败");
    }

    char *full_name_enc = NULL;
    char *email_enc = NULL;
    char *phone_enc = NULL;
    if (encrypt_text(full_name, &full_name_enc) != 0 ||
        encrypt_text(email, &email_enc) != 0 ||
        encrypt_text(phone, &phone_enc) != 0) {
        free(full_name_enc);
        free(email_enc);
        free(phone_enc);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "用户信息加密失败");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO users (username, password_hash, role, full_name_enc, "
        "email_enc, phone_enc) VALUES (?, ?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        free(full_name_enc);
        free(email_enc);
        free(phone_enc);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建用户预编译失败");
    }

    sqlite3_bind_text(stmt, 1, username_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, role_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, full_name_enc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, email_enc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, phone_enc, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(full_name_enc);
    free(email_enc);
    free(phone_enc);
    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            return respond_error(connection, MHD_HTTP_CONFLICT, "CONFLICT",
                                "用户名已存在");
        }
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建用户失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "username", json_string(username_copy));
    json_object_set_new(data, "role", json_string(role_copy));
    json_object_set_new(data, "first_user", first_user ? json_true() : json_false());
    return respond_success(connection, MHD_HTTP_CREATED, data);
}

static enum MHD_Result handle_login(struct MHD_Connection *connection,
                                    ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *username = NULL;
    const char *password = NULL;
    if (require_string_field(body, "username", 64, &username) != 0 ||
        require_string_field(body, "password", 128, &password) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "username/password 必填");
    }

    char username_copy[65];
    snprintf(username_copy, sizeof(username_copy), "%s", username);

    pthread_mutex_lock(&g_db_mutex);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT id, password_hash, role FROM users WHERE username = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "数据库查询失败");
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "用户名或密码错误");
    }

    int user_id = sqlite3_column_int(stmt, 0);
    const char *password_hash = safe_col_text(stmt, 1);
    char role_copy[32];
    snprintf(role_copy, sizeof(role_copy), "%s", safe_col_text(stmt, 2));

    if (crypto_pwhash_str_verify(password_hash, password, strlen(password)) != 0) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "用户名或密码错误");
    }
    sqlite3_finalize(stmt);

    char token[128] = {0};
    if (generate_access_token(token, sizeof(token)) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "生成令牌失败");
    }

    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (hash_token(token, token_hash) != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "处理令牌失败");
    }

    const time_t expires_at = now_epoch() + (time_t)g_cfg.session_ttl_hours * 3600;

    if (db_exec("DELETE FROM sessions WHERE expires_at <= strftime('%s', 'now');") != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "会话清理失败");
    }

    const char *insert_sql =
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(g_db, insert_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "会话创建失败");
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, token_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)expires_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    if (rc != SQLITE_DONE) {
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "会话创建失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "access_token", json_string(token));
    json_object_set_new(data, "token_type", json_string("Bearer"));
    json_object_set_new(data, "expires_at", json_integer((json_int_t)expires_at));
    json_object_set_new(data, "user_id", json_integer(user_id));
    json_object_set_new(data, "username", json_string(username_copy));
    json_object_set_new(data, "role", json_string(role_copy));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_logout(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "未登录或令牌无效");
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, "DELETE FROM sessions WHERE token_hash = ?;", -1,
                           &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "退出登录失败");
    }

    sqlite3_bind_text(stmt, 1, token_hash, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_db_mutex);

    json_t *data = json_object();
    json_object_set_new(data, "message", json_string("已退出登录"));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_auth_me(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "未登录或令牌无效");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT full_name_enc, email_enc, phone_enc, created_at "
        "FROM users WHERE id = ? LIMIT 1;";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询用户详情失败");
    }

    sqlite3_bind_int(stmt, 1, user.user_id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "用户不存在");
    }

    const char *full_name_enc = safe_col_text(stmt, 0);
    const char *email_enc = safe_col_text(stmt, 1);
    const char *phone_enc = safe_col_text(stmt, 2);
    char created_at[64];
    snprintf(created_at, sizeof(created_at), "%s", safe_col_text(stmt, 3));

    char *full_name = NULL;
    char *email = NULL;
    char *phone = NULL;

    int ok = decrypt_text(full_name_enc, &full_name) == 0 &&
             decrypt_text(email_enc, &email) == 0 &&
             decrypt_text(phone_enc, &phone) == 0;

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (!ok) {
        free(full_name);
        free(email);
        free(phone);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "SECURITY_ERROR", "解密用户信息失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "user_id", json_integer(user.user_id));
    json_object_set_new(data, "username", json_string(user.username));
    json_object_set_new(data, "role", json_string(user.role));
    json_object_set_new(data, "full_name", json_string(full_name));
    json_object_set_new(data, "email", json_string(email));
    json_object_set_new(data, "phone", json_string(phone));
    json_object_set_new(data, "created_at", json_string(created_at));

    free(full_name);
    free(email);
    free(phone);

    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_create_product(struct MHD_Connection *connection,
                                             ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *sku = NULL;
    const char *name = NULL;
    if (require_string_field(body, "sku", 64, &sku) != 0 ||
        require_string_field(body, "name", 128, &name) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "sku/name 必填");
    }

    const char *unit = optional_string_field(body, "unit", 16);
    if (unit == NULL || *unit == '\0') {
        unit = "瓶";
    }

    char sku_copy[65];
    char name_copy[129];
    char unit_copy[17];
    snprintf(sku_copy, sizeof(sku_copy), "%s", sku);
    snprintf(name_copy, sizeof(name_copy), "%s", name);
    snprintf(unit_copy, sizeof(unit_copy), "%s", unit);

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (!is_admin_role(&user)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_FORBIDDEN, "FORBIDDEN",
                            "仅管理员可新增商品");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO products (sku, name, unit, stock_quantity) VALUES (?, ?, ?, 0);";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "新增商品失败");
    }

    sqlite3_bind_text(stmt, 1, sku_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, name_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, unit_copy, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            return respond_error(connection, MHD_HTTP_CONFLICT, "CONFLICT",
                                "商品 SKU 已存在");
        }
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "新增商品失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "sku", json_string(sku_copy));
    json_object_set_new(data, "name", json_string(name_copy));
    json_object_set_new(data, "unit", json_string(unit_copy));
    return respond_success(connection, MHD_HTTP_CREATED, data);
}

static enum MHD_Result handle_list_products(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT id, sku, name, unit, stock_quantity, created_at, updated_at "
        "FROM products ORDER BY id DESC;";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询商品列表失败");
    }

    json_t *items = json_array();
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *item = json_object();
        json_object_set_new(item, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(item, "sku", json_string(safe_col_text(stmt, 1)));
        json_object_set_new(item, "name", json_string(safe_col_text(stmt, 2)));
        json_object_set_new(item, "unit", json_string(safe_col_text(stmt, 3)));
        json_object_set_new(item, "stock_quantity",
                            json_integer(sqlite3_column_int(stmt, 4)));
        json_object_set_new(item, "created_at", json_string(safe_col_text(stmt, 5)));
        json_object_set_new(item, "updated_at", json_string(safe_col_text(stmt, 6)));
        json_array_append_new(items, item);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(items);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取商品列表失败");
    }

    return respond_success(connection, MHD_HTTP_OK, items);
}

static int begin_transaction(void) {
    return db_exec("BEGIN IMMEDIATE TRANSACTION;");
}

static void rollback_transaction(void) { db_exec("ROLLBACK;"); }

static int commit_transaction(void) { return db_exec("COMMIT;"); }

static enum MHD_Result handle_inbound(struct MHD_Connection *connection,
                                      ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *sku = NULL;
    if (require_string_field(body, "sku", 64, &sku) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "sku 必填");
    }

    int quantity = 0;
    int unit_cost = 0;
    if (parse_int_field(body, "quantity", 1, 1000000, &quantity) != 0 ||
        parse_int_field(body, "unit_cost_cents", 0, 100000000, &unit_cost) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "quantity/unit_cost_cents 必须为合法整数");
    }

    const char *note = optional_string_field(body, "note", 256);
    if (note == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "note 需为字符串且不超过256字符");
    }

    char sku_copy[65];
    snprintf(sku_copy, sizeof(sku_copy), "%s", sku);

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    sqlite3_stmt *stmt = NULL;
    int product_id = 0;
    int current_stock = 0;

    const char *find_sql =
        "SELECT id, stock_quantity FROM products WHERE sku = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, find_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询商品失败");
    }

    sqlite3_bind_text(stmt, 1, sku_copy, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "商品不存在");
    }

    product_id = sqlite3_column_int(stmt, 0);
    current_stock = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);

    const int new_stock = current_stock + quantity;

    const char *update_sql =
        "UPDATE products SET stock_quantity = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE id = ?;";
    if (sqlite3_prepare_v2(g_db, update_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新库存失败");
    }

    sqlite3_bind_int(stmt, 1, new_stock);
    sqlite3_bind_int(stmt, 2, product_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新库存失败");
    }

    const char *ins_sql =
        "INSERT INTO stock_movements "
        "(product_id, movement_type, quantity, unit_price_cents, note, "
        "operator_user_id) "
        "VALUES (?, 'IN', ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(g_db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "写入流水失败");
    }

    sqlite3_bind_int(stmt, 1, product_id);
    sqlite3_bind_int(stmt, 2, quantity);
    sqlite3_bind_int(stmt, 3, unit_cost);
    sqlite3_bind_text(stmt, 4, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, user.user_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE || commit_transaction() != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交入库事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "sku", json_string(sku_copy));
    json_object_set_new(data, "movement_type", json_string("IN"));
    json_object_set_new(data, "quantity", json_integer(quantity));
    json_object_set_new(data, "new_stock", json_integer(new_stock));
    json_object_set_new(data, "operator", json_string(user.username));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_sales(struct MHD_Connection *connection,
                                    ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *sku = NULL;
    if (require_string_field(body, "sku", 64, &sku) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "sku 必填");
    }

    int quantity = 0;
    int sale_price = 0;
    if (parse_int_field(body, "quantity", 1, 1000000, &quantity) != 0 ||
        parse_int_field(body, "unit_price_cents", 0, 100000000, &sale_price) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "quantity/unit_price_cents 必须为合法整数");
    }

    const char *note = optional_string_field(body, "note", 256);
    if (note == NULL) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "note 需为字符串且不超过256字符");
    }

    char sku_copy[65];
    snprintf(sku_copy, sizeof(sku_copy), "%s", sku);

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (begin_transaction() != 0) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "开启事务失败");
    }

    sqlite3_stmt *stmt = NULL;
    int product_id = 0;
    int current_stock = 0;

    const char *find_sql =
        "SELECT id, stock_quantity FROM products WHERE sku = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, find_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询商品失败");
    }

    sqlite3_bind_text(stmt, 1, sku_copy, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "商品不存在");
    }

    product_id = sqlite3_column_int(stmt, 0);
    current_stock = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);

    if (current_stock < quantity) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_CONFLICT, "INSUFFICIENT_STOCK",
                            "库存不足，无法出库");
    }

    const int new_stock = current_stock - quantity;

    const char *update_sql =
        "UPDATE products SET stock_quantity = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE id = ?;";
    if (sqlite3_prepare_v2(g_db, update_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新库存失败");
    }

    sqlite3_bind_int(stmt, 1, new_stock);
    sqlite3_bind_int(stmt, 2, product_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新库存失败");
    }

    const char *ins_sql =
        "INSERT INTO stock_movements "
        "(product_id, movement_type, quantity, unit_price_cents, note, "
        "operator_user_id) "
        "VALUES (?, 'OUT', ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(g_db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "写入流水失败");
    }

    sqlite3_bind_int(stmt, 1, product_id);
    sqlite3_bind_int(stmt, 2, quantity);
    sqlite3_bind_int(stmt, 3, sale_price);
    sqlite3_bind_text(stmt, 4, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, user.user_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE || commit_transaction() != 0) {
        rollback_transaction();
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "提交出库事务失败");
    }

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    json_t *data = json_object();
    json_object_set_new(data, "sku", json_string(sku_copy));
    json_object_set_new(data, "movement_type", json_string("OUT"));
    json_object_set_new(data, "quantity", json_integer(quantity));
    json_object_set_new(data, "new_stock", json_integer(new_stock));
    json_object_set_new(data, "operator", json_string(user.username));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_inventory(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    sqlite3_stmt *summary_stmt = NULL;
    const char *summary_sql =
        "SELECT "
        "  (SELECT COUNT(*) FROM products),"
        "  (SELECT COALESCE(SUM(stock_quantity), 0) FROM products),"
        "  (SELECT COALESCE(SUM(quantity), 0) FROM stock_movements WHERE "
        "movement_type='IN'),"
        "  (SELECT COALESCE(SUM(quantity), 0) FROM stock_movements WHERE "
        "movement_type='OUT');";

    if (sqlite3_prepare_v2(g_db, summary_sql, -1, &summary_stmt, NULL) !=
        SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询库存汇总失败");
    }

    int rc = sqlite3_step(summary_stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(summary_stmt);
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询库存汇总失败");
    }

    int product_count = sqlite3_column_int(summary_stmt, 0);
    int total_stock = sqlite3_column_int(summary_stmt, 1);
    int total_in = sqlite3_column_int(summary_stmt, 2);
    int total_out = sqlite3_column_int(summary_stmt, 3);
    sqlite3_finalize(summary_stmt);

    sqlite3_stmt *list_stmt = NULL;
    const char *list_sql =
        "SELECT sku, name, unit, stock_quantity, updated_at "
        "FROM products ORDER BY stock_quantity DESC, id ASC;";
    if (sqlite3_prepare_v2(g_db, list_sql, -1, &list_stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询库存明细失败");
    }

    json_t *products = json_array();
    while ((rc = sqlite3_step(list_stmt)) == SQLITE_ROW) {
        json_t *item = json_object();
        json_object_set_new(item, "sku", json_string(safe_col_text(list_stmt, 0)));
        json_object_set_new(item, "name", json_string(safe_col_text(list_stmt, 1)));
        json_object_set_new(item, "unit", json_string(safe_col_text(list_stmt, 2)));
        json_object_set_new(item, "stock_quantity",
                            json_integer(sqlite3_column_int(list_stmt, 3)));
        json_object_set_new(item, "updated_at",
                            json_string(safe_col_text(list_stmt, 4)));
        json_array_append_new(products, item);
    }

    sqlite3_finalize(list_stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(products);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取库存明细失败");
    }

    json_t *data = json_object();
    json_t *summary = json_object();
    json_object_set_new(summary, "product_count", json_integer(product_count));
    json_object_set_new(summary, "total_stock_quantity", json_integer(total_stock));
    json_object_set_new(summary, "total_in_quantity", json_integer(total_in));
    json_object_set_new(summary, "total_out_quantity", json_integer(total_out));

    json_object_set_new(data, "summary", summary);
    json_object_set_new(data, "products", products);

    return respond_success(connection, MHD_HTTP_OK, data);
}

static int parse_limit_query(struct MHD_Connection *connection) {
    const char *limit_s =
        MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "limit");
    if (limit_s == NULL || *limit_s == '\0') {
        return 50;
    }

    char *end = NULL;
    errno = 0;
    long v = strtol(limit_s, &end, 10);
    if (errno != 0 || end == limit_s || *end != '\0') {
        return 50;
    }
    if (v < 1) {
        v = 1;
    }
    if (v > 200) {
        v = 200;
    }
    return (int)v;
}

static void format_current_time(char *buf, size_t buf_size) {
    time_t t = now_epoch();
    struct tm *tm_info = localtime(&t);
    strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

static char *get_device_affected_products(int device_id) {
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT p.sku || ':' || p.name "
        "FROM device_products dp "
        "JOIN products p ON p.id = dp.product_id "
        "WHERE dp.device_id = ? "
        "ORDER BY p.id;";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }

    sqlite3_bind_int(stmt, 1, device_id);

    json_t *products = json_array();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json_array_append_new(products, json_string(safe_col_text(stmt, 0)));
    }
    sqlite3_finalize(stmt);

    char *result = json_dumps(products, JSON_COMPACT);
    json_decref(products);
    return result;
}

static int check_temperature_alert(int device_id, double current_temp,
                                   double min_temp, double max_temp) {
    sqlite3_stmt *stmt = NULL;
    int has_active_alert = 0;
    char active_alert_type[16] = {0};

    const char *check_sql =
        "SELECT alert_type FROM temperature_alerts "
        "WHERE device_id = ? AND is_active = 1 "
        "ORDER BY id DESC LIMIT 1;";

    if (sqlite3_prepare_v2(g_db, check_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, device_id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            has_active_alert = 1;
            snprintf(active_alert_type, sizeof(active_alert_type), "%s",
                     safe_col_text(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }

    int is_overheat = current_temp > max_temp;
    int is_underheat = current_temp < min_temp;
    int is_out_of_range = is_overheat || is_underheat;

    char now_str[32];
    format_current_time(now_str, sizeof(now_str));

    if (is_out_of_range && !has_active_alert) {
        char *affected = get_device_affected_products(device_id);
        const char *alert_type = is_overheat ? "OVERHEAT" : "UNDERHEAT";

        const char *insert_sql =
            "INSERT INTO temperature_alerts "
            "(device_id, alert_type, start_time, affected_products, "
            "is_active, start_temp_c, note) "
            "VALUES (?, ?, ?, ?, 1, ?, '温度超限自动记录');";

        if (sqlite3_prepare_v2(g_db, insert_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, device_id);
            sqlite3_bind_text(stmt, 2, alert_type, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, now_str, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, affected ? affected : "[]", -1,
                              SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 5, current_temp);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        const char *update_sql =
            "UPDATE devices SET is_suspended = 1, updated_at = CURRENT_TIMESTAMP "
            "WHERE id = ?;";
        if (sqlite3_prepare_v2(g_db, update_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, device_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        free(affected);
        return 1;
    }

    if (!is_out_of_range && has_active_alert) {
        const char *update_sql =
            "UPDATE temperature_alerts "
            "SET end_time = ?, end_temp_c = ?, is_active = 0 "
            "WHERE device_id = ? AND is_active = 1;";

        if (sqlite3_prepare_v2(g_db, update_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, now_str, -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(stmt, 2, current_temp);
            sqlite3_bind_int(stmt, 3, device_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        const char *update_dev_sql =
            "UPDATE devices SET is_suspended = 0, updated_at = CURRENT_TIMESTAMP "
            "WHERE id = ?;";
        if (sqlite3_prepare_v2(g_db, update_dev_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, device_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        return -1;
    }

    return 0;
}

static enum MHD_Result handle_create_device(struct MHD_Connection *connection,
                                            ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *code = NULL;
    const char *name = NULL;
    const char *device_type = NULL;
    if (require_string_field(body, "code", 32, &code) != 0 ||
        require_string_field(body, "name", 64, &name) != 0 ||
        require_string_field(body, "device_type", 16, &device_type) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "code/name/device_type 必填");
    }

    if (strcmp(device_type, "COLD") != 0 && strcmp(device_type, "NORMAL") != 0 &&
        strcmp(device_type, "HOT") != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "device_type 仅支持 COLD/NORMAL/HOT");
    }

    double min_temp = 0.0, max_temp = 0.0;
    if (parse_real_field(body, "min_temp_c", -50.0, 150.0, &min_temp) != 0 ||
        parse_real_field(body, "max_temp_c", -50.0, 150.0, &max_temp) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "min_temp_c/max_temp_c 必须为合法温度值");
    }

    if (min_temp >= max_temp) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "min_temp_c 必须小于 max_temp_c");
    }

    char code_copy[33];
    char name_copy[65];
    char type_copy[17];
    snprintf(code_copy, sizeof(code_copy), "%s", code);
    snprintf(name_copy, sizeof(name_copy), "%s", name);
    snprintf(type_copy, sizeof(type_copy), "%s", device_type);

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (!is_admin_role(&user)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_FORBIDDEN, "FORBIDDEN",
                            "仅管理员可创建设备");
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO devices (code, name, device_type, min_temp_c, max_temp_c) "
        "VALUES (?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建设备失败");
    }

    sqlite3_bind_text(stmt, 1, code_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, name_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, type_copy, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 4, min_temp);
    sqlite3_bind_double(stmt, 5, max_temp);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            return respond_error(connection, MHD_HTTP_CONFLICT, "CONFLICT",
                                "设备编号已存在");
        }
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "创建设备失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "code", json_string(code_copy));
    json_object_set_new(data, "name", json_string(name_copy));
    json_object_set_new(data, "device_type", json_string(type_copy));
    json_object_set_new(data, "min_temp_c", json_real(min_temp));
    json_object_set_new(data, "max_temp_c", json_real(max_temp));
    return respond_success(connection, MHD_HTTP_CREATED, data);
}

static enum MHD_Result handle_list_devices(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT id, code, name, device_type, min_temp_c, max_temp_c, "
        "current_temp_c, is_suspended, created_at, updated_at "
        "FROM devices ORDER BY id ASC;";

    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询设备列表失败");
    }

    json_t *items = json_array();
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *item = json_object();
        json_object_set_new(item, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(item, "code", json_string(safe_col_text(stmt, 1)));
        json_object_set_new(item, "name", json_string(safe_col_text(stmt, 2)));
        json_object_set_new(item, "device_type", json_string(safe_col_text(stmt, 3)));
        json_object_set_new(item, "min_temp_c", json_real(sqlite3_column_double(stmt, 4)));
        json_object_set_new(item, "max_temp_c", json_real(sqlite3_column_double(stmt, 5)));
        if (sqlite3_column_type(stmt, 6) == SQLITE_NULL) {
            json_object_set_new(item, "current_temp_c", json_null());
        } else {
            json_object_set_new(item, "current_temp_c", json_real(sqlite3_column_double(stmt, 6)));
        }
        json_object_set_new(item, "is_suspended",
                            json_integer(sqlite3_column_int(stmt, 7)));
        json_object_set_new(item, "created_at", json_string(safe_col_text(stmt, 8)));
        json_object_set_new(item, "updated_at", json_string(safe_col_text(stmt, 9)));
        json_array_append_new(items, item);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(items);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取设备列表失败");
    }

    return respond_success(connection, MHD_HTTP_OK, items);
}

static enum MHD_Result handle_report_temperature(struct MHD_Connection *connection,
                                                 ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *code = NULL;
    if (require_string_field(body, "code", 32, &code) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "设备编号 code 必填");
    }

    double temperature = 0.0;
    if (parse_real_field(body, "temperature_c", -50.0, 150.0, &temperature) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "temperature_c 必须为合法温度值");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    sqlite3_stmt *stmt = NULL;
    int device_id = 0;
    double min_temp = 0.0, max_temp = 0.0;
    int was_suspended = 0;

    const char *find_sql =
        "SELECT id, min_temp_c, max_temp_c, is_suspended FROM devices "
        "WHERE code = ? LIMIT 1;";

    if (sqlite3_prepare_v2(g_db, find_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询设备失败");
    }

    sqlite3_bind_text(stmt, 1, code, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "设备不存在");
    }

    device_id = sqlite3_column_int(stmt, 0);
    min_temp = sqlite3_column_double(stmt, 1);
    max_temp = sqlite3_column_double(stmt, 2);
    was_suspended = sqlite3_column_int(stmt, 3);
    sqlite3_finalize(stmt);

    const char *update_sql =
        "UPDATE devices SET current_temp_c = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE id = ?;";
    if (sqlite3_prepare_v2(g_db, update_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新温度失败");
    }

    sqlite3_bind_double(stmt, 1, temperature);
    sqlite3_bind_int(stmt, 2, device_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "更新温度失败");
    }

    int alert_status = check_temperature_alert(device_id, temperature, min_temp, max_temp);

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    int is_out_of_range = (temperature > max_temp) || (temperature < min_temp);
    int is_now_suspended = is_out_of_range || (alert_status == 0 && was_suspended == 1);

    json_t *data = json_object();
    json_object_set_new(data, "device_code", json_string(code));
    json_object_set_new(data, "temperature_c", json_real(temperature));
    json_object_set_new(data, "min_temp_c", json_real(min_temp));
    json_object_set_new(data, "max_temp_c", json_real(max_temp));
    json_object_set_new(data, "is_out_of_range", is_out_of_range ? json_true() : json_false());
    json_object_set_new(data, "is_suspended", is_now_suspended ? json_true() : json_false());

    if (alert_status == 1) {
        json_object_set_new(data, "alert_triggered", json_true());
        json_object_set_new(data, "alert_type",
                            json_string(temperature > max_temp ? "OVERHEAT" : "UNDERHEAT"));
    } else if (alert_status == -1) {
        json_object_set_new(data, "alert_resolved", json_true());
    } else {
        json_object_set_new(data, "alert_triggered", json_false());
    }

    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_add_device_product(struct MHD_Connection *connection,
                                                 ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *device_code = NULL;
    const char *sku = NULL;
    if (require_string_field(body, "device_code", 32, &device_code) != 0 ||
        require_string_field(body, "sku", 64, &sku) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "device_code/sku 必填");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (!is_admin_role(&user)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_FORBIDDEN, "FORBIDDEN",
                            "仅管理员可配置设备商品");
    }

    sqlite3_stmt *stmt = NULL;
    int device_id = 0;
    int product_id = 0;

    const char *find_dev_sql = "SELECT id FROM devices WHERE code = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, find_dev_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询设备失败");
    }
    sqlite3_bind_text(stmt, 1, device_code, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "设备不存在");
    }
    device_id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    const char *find_prod_sql = "SELECT id FROM products WHERE sku = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, find_prod_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询商品失败");
    }
    sqlite3_bind_text(stmt, 1, sku, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "商品不存在");
    }
    product_id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    const char *insert_sql =
        "INSERT OR IGNORE INTO device_products (device_id, product_id) "
        "VALUES (?, ?);";
    if (sqlite3_prepare_v2(g_db, insert_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "添加关联失败");
    }
    sqlite3_bind_int(stmt, 1, device_id);
    sqlite3_bind_int(stmt, 2, product_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    if (rc != SQLITE_DONE) {
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "添加关联失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "device_code", json_string(device_code));
    json_object_set_new(data, "sku", json_string(sku));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_remove_device_product(struct MHD_Connection *connection,
                                                    ConnectionInfo *ci) {
    char err[256];
    json_t *body = NULL;
    if (parse_json_body(ci, &body, err) != 0) {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_JSON", err);
    }

    const char *device_code = NULL;
    const char *sku = NULL;
    if (require_string_field(body, "device_code", 32, &device_code) != 0 ||
        require_string_field(body, "sku", 64, &sku) != 0) {
        json_decref(body);
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "device_code/sku 必填");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    if (!is_admin_role(&user)) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_FORBIDDEN, "FORBIDDEN",
                            "仅管理员可配置设备商品");
    }

    sqlite3_stmt *stmt = NULL;
    int device_id = 0;
    int product_id = 0;

    const char *find_dev_sql = "SELECT id FROM devices WHERE code = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, find_dev_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询设备失败");
    }
    sqlite3_bind_text(stmt, 1, device_code, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "设备不存在");
    }
    device_id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    const char *find_prod_sql = "SELECT id FROM products WHERE sku = ? LIMIT 1;";
    if (sqlite3_prepare_v2(g_db, find_prod_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询商品失败");
    }
    sqlite3_bind_text(stmt, 1, sku, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "商品不存在");
    }
    product_id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    const char *delete_sql =
        "DELETE FROM device_products WHERE device_id = ? AND product_id = ?;";
    if (sqlite3_prepare_v2(g_db, delete_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        json_decref(body);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "移除关联失败");
    }
    sqlite3_bind_int(stmt, 1, device_id);
    sqlite3_bind_int(stmt, 2, product_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&g_db_mutex);
    json_decref(body);

    if (rc != SQLITE_DONE) {
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "移除关联失败");
    }

    json_t *data = json_object();
    json_object_set_new(data, "device_code", json_string(device_code));
    json_object_set_new(data, "sku", json_string(sku));
    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_device_status(struct MHD_Connection *connection) {
    const char *code =
        MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "code");

    if (code == NULL || *code == '\0') {
        return respond_error(connection, MHD_HTTP_BAD_REQUEST, "INVALID_INPUT",
                            "设备编号 code 必填");
    }

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    sqlite3_stmt *stmt = NULL;
    int device_id = 0;
    char device_code[33] = {0};
    char device_name[65] = {0};
    char device_type[17] = {0};
    double min_temp = 0.0, max_temp = 0.0, current_temp = 0.0;
    int is_suspended = 0;
    int has_current_temp = 0;

    const char *find_sql =
        "SELECT id, code, name, device_type, min_temp_c, max_temp_c, "
        "current_temp_c, is_suspended "
        "FROM devices WHERE code = ? LIMIT 1;";

    if (sqlite3_prepare_v2(g_db, find_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询设备失败");
    }

    sqlite3_bind_text(stmt, 1, code, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND",
                            "设备不存在");
    }

    device_id = sqlite3_column_int(stmt, 0);
    snprintf(device_code, sizeof(device_code), "%s", safe_col_text(stmt, 1));
    snprintf(device_name, sizeof(device_name), "%s", safe_col_text(stmt, 2));
    snprintf(device_type, sizeof(device_type), "%s", safe_col_text(stmt, 3));
    min_temp = sqlite3_column_double(stmt, 4);
    max_temp = sqlite3_column_double(stmt, 5);
    if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
        current_temp = sqlite3_column_double(stmt, 6);
        has_current_temp = 1;
    }
    is_suspended = sqlite3_column_int(stmt, 7);
    sqlite3_finalize(stmt);

    int is_out_of_range = 0;
    const char *temp_status = "NORMAL";
    if (has_current_temp) {
        if (current_temp > max_temp) {
            is_out_of_range = 1;
            temp_status = "OVERHEAT";
        } else if (current_temp < min_temp) {
            is_out_of_range = 1;
            temp_status = "UNDERHEAT";
        }
    }

    json_t *products = json_array();
    const char *prod_sql =
        "SELECT p.id, p.sku, p.name, p.unit, p.stock_quantity "
        "FROM device_products dp "
        "JOIN products p ON p.id = dp.product_id "
        "WHERE dp.device_id = ? "
        "ORDER BY p.id;";

    if (sqlite3_prepare_v2(g_db, prod_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, device_id);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json_t *item = json_object();
            json_object_set_new(item, "id", json_integer(sqlite3_column_int(stmt, 0)));
            json_object_set_new(item, "sku", json_string(safe_col_text(stmt, 1)));
            json_object_set_new(item, "name", json_string(safe_col_text(stmt, 2)));
            json_object_set_new(item, "unit", json_string(safe_col_text(stmt, 3)));
            json_object_set_new(item, "stock_quantity",
                                json_integer(sqlite3_column_int(stmt, 4)));
            json_object_set_new(item, "can_sell",
                                is_suspended ? json_false() : json_true());
            if (is_suspended) {
                json_object_set_new(item, "unsellable_reason",
                                    json_string("设备温度超限，暂停售卖"));
            }
            json_array_append_new(products, item);
        }
        sqlite3_finalize(stmt);
    }

    json_t *active_alert = json_null();
    const char *alert_sql =
        "SELECT id, alert_type, start_time, start_temp_c, affected_products "
        "FROM temperature_alerts "
        "WHERE device_id = ? AND is_active = 1 "
        "ORDER BY id DESC LIMIT 1;";

    if (sqlite3_prepare_v2(g_db, alert_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, device_id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            active_alert = json_object();
            json_object_set_new(active_alert, "id",
                                json_integer(sqlite3_column_int(stmt, 0)));
            json_object_set_new(active_alert, "alert_type",
                                json_string(safe_col_text(stmt, 1)));
            json_object_set_new(active_alert, "start_time",
                                json_string(safe_col_text(stmt, 2)));
            json_object_set_new(active_alert, "start_temp_c",
                                json_real(sqlite3_column_double(stmt, 3)));
            json_error_t jerr;
            json_t *affected = json_loads(safe_col_text(stmt, 4), 0, &jerr);
            json_object_set_new(active_alert, "affected_products",
                                affected ? affected : json_array());
        }
        sqlite3_finalize(stmt);
    }

    pthread_mutex_unlock(&g_db_mutex);

    json_t *data = json_object();
    json_object_set_new(data, "id", json_integer(device_id));
    json_object_set_new(data, "code", json_string(device_code));
    json_object_set_new(data, "name", json_string(device_name));
    json_object_set_new(data, "device_type", json_string(device_type));
    json_object_set_new(data, "min_temp_c", json_real(min_temp));
    json_object_set_new(data, "max_temp_c", json_real(max_temp));
    if (has_current_temp) {
        json_object_set_new(data, "current_temp_c", json_real(current_temp));
    } else {
        json_object_set_new(data, "current_temp_c", json_null());
    }
    json_object_set_new(data, "temperature_status", json_string(temp_status));
    json_object_set_new(data, "is_out_of_range",
                        is_out_of_range ? json_true() : json_false());
    json_object_set_new(data, "is_suspended",
                        is_suspended ? json_true() : json_false());
    json_object_set_new(data, "active_alert", active_alert);
    json_object_set_new(data, "products", products);

    return respond_success(connection, MHD_HTTP_OK, data);
}

static enum MHD_Result handle_list_alerts(struct MHD_Connection *connection) {
    const char *device_code =
        MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "device_code");
    const char *active_only =
        MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "active_only");
    int limit = parse_limit_query(connection);

    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    sqlite3_stmt *stmt = NULL;
    char base_sql[1024];
    int use_device = (device_code != NULL && *device_code != '\0');
    int use_active = (active_only != NULL && strcmp(active_only, "1") == 0);

    snprintf(base_sql, sizeof(base_sql),
        "SELECT a.id, d.code, d.name, a.alert_type, a.start_time, "
        "a.end_time, a.is_active, a.start_temp_c, a.end_temp_c, "
        "a.affected_products, a.note, a.created_at "
        "FROM temperature_alerts a "
        "JOIN devices d ON d.id = a.device_id ");

    char where_clause[256] = "";
    int cond_count = 0;

    if (use_device) {
        strcat(where_clause, "WHERE d.code = ? ");
        cond_count++;
    }
    if (use_active) {
        if (cond_count > 0) {
            strcat(where_clause, "AND ");
        } else {
            strcat(where_clause, "WHERE ");
        }
        strcat(where_clause, "a.is_active = 1 ");
    }

    strcat(base_sql, where_clause);
    strcat(base_sql, "ORDER BY a.id DESC LIMIT ?;");

    if (sqlite3_prepare_v2(g_db, base_sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询告警失败");
    }

    int idx = 1;
    if (use_device) {
        sqlite3_bind_text(stmt, idx++, device_code, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, idx, limit);

    json_t *items = json_array();
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *item = json_object();
        json_object_set_new(item, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(item, "device_code", json_string(safe_col_text(stmt, 1)));
        json_object_set_new(item, "device_name", json_string(safe_col_text(stmt, 2)));
        json_object_set_new(item, "alert_type", json_string(safe_col_text(stmt, 3)));
        json_object_set_new(item, "start_time", json_string(safe_col_text(stmt, 4)));
        if (sqlite3_column_type(stmt, 5) == SQLITE_NULL) {
            json_object_set_new(item, "end_time", json_null());
        } else {
            json_object_set_new(item, "end_time", json_string(safe_col_text(stmt, 5)));
        }
        json_object_set_new(item, "is_active",
                            json_integer(sqlite3_column_int(stmt, 6)));
        json_object_set_new(item, "start_temp_c",
                            json_real(sqlite3_column_double(stmt, 7)));
        if (sqlite3_column_type(stmt, 8) == SQLITE_NULL) {
            json_object_set_new(item, "end_temp_c", json_null());
        } else {
            json_object_set_new(item, "end_temp_c",
                                json_real(sqlite3_column_double(stmt, 8)));
        }
        json_error_t jerr;
        json_t *affected = json_loads(safe_col_text(stmt, 9), 0, &jerr);
        json_object_set_new(item, "affected_products",
                            affected ? affected : json_array());
        json_object_set_new(item, "note", json_string(safe_col_text(stmt, 10)));
        json_object_set_new(item, "created_at", json_string(safe_col_text(stmt, 11)));
        json_array_append_new(items, item);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(items);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取告警失败");
    }

    return respond_success(connection, MHD_HTTP_OK, items);
}

static enum MHD_Result handle_movements(struct MHD_Connection *connection) {
    pthread_mutex_lock(&g_db_mutex);

    AuthUser user;
    char token_hash[TOKEN_HASH_HEX_LEN + 1] = {0};
    if (!authenticate_request(connection, &user, token_hash)) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_UNAUTHORIZED, "UNAUTHORIZED",
                            "需要登录");
    }

    const char *type =
        MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "type");
    int use_type = 0;
    if (type != NULL && *type != '\0') {
        if (strcmp(type, "IN") == 0 || strcmp(type, "OUT") == 0) {
            use_type = 1;
        } else {
            pthread_mutex_unlock(&g_db_mutex);
            return respond_error(connection, MHD_HTTP_BAD_REQUEST,
                                "INVALID_INPUT", "type 仅支持 IN 或 OUT");
        }
    }

    int limit = parse_limit_query(connection);

    sqlite3_stmt *stmt = NULL;
    const char *sql_all =
        "SELECT m.id, p.sku, p.name, m.movement_type, m.quantity, "
        "m.unit_price_cents, m.note, u.username, m.created_at "
        "FROM stock_movements m "
        "JOIN products p ON p.id = m.product_id "
        "JOIN users u ON u.id = m.operator_user_id "
        "ORDER BY m.id DESC LIMIT ?;";

    const char *sql_type =
        "SELECT m.id, p.sku, p.name, m.movement_type, m.quantity, "
        "m.unit_price_cents, m.note, u.username, m.created_at "
        "FROM stock_movements m "
        "JOIN products p ON p.id = m.product_id "
        "JOIN users u ON u.id = m.operator_user_id "
        "WHERE m.movement_type = ? "
        "ORDER BY m.id DESC LIMIT ?;";

    if (sqlite3_prepare_v2(g_db, use_type ? sql_type : sql_all, -1, &stmt, NULL) !=
        SQLITE_OK) {
        pthread_mutex_unlock(&g_db_mutex);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "查询流水失败");
    }

    int idx = 1;
    if (use_type) {
        sqlite3_bind_text(stmt, idx++, type, -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, idx, limit);

    json_t *items = json_array();
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *it = json_object();
        json_object_set_new(it, "id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(it, "sku", json_string(safe_col_text(stmt, 1)));
        json_object_set_new(it, "product_name", json_string(safe_col_text(stmt, 2)));
        json_object_set_new(it, "movement_type", json_string(safe_col_text(stmt, 3)));
        json_object_set_new(it, "quantity", json_integer(sqlite3_column_int(stmt, 4)));
        json_object_set_new(it, "unit_price_cents",
                            json_integer(sqlite3_column_int(stmt, 5)));
        json_object_set_new(it, "note", json_string(safe_col_text(stmt, 6)));
        json_object_set_new(it, "operator", json_string(safe_col_text(stmt, 7)));
        json_object_set_new(it, "created_at", json_string(safe_col_text(stmt, 8)));
        json_array_append_new(items, it);
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_db_mutex);

    if (rc != SQLITE_DONE) {
        json_decref(items);
        return respond_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "DB_ERROR", "读取流水失败");
    }

    return respond_success(connection, MHD_HTTP_OK, items);
}

static enum MHD_Result route_health(struct MHD_Connection *connection,
                                    ConnectionInfo *ci) {
    (void)ci;
    return handle_health(connection);
}

static enum MHD_Result route_register(struct MHD_Connection *connection,
                                      ConnectionInfo *ci) {
    return handle_register(connection, ci);
}

static enum MHD_Result route_login(struct MHD_Connection *connection,
                                   ConnectionInfo *ci) {
    return handle_login(connection, ci);
}

static enum MHD_Result route_logout(struct MHD_Connection *connection,
                                    ConnectionInfo *ci) {
    (void)ci;
    return handle_logout(connection);
}

static enum MHD_Result route_auth_me(struct MHD_Connection *connection,
                                     ConnectionInfo *ci) {
    (void)ci;
    return handle_auth_me(connection);
}

static enum MHD_Result route_create_product(struct MHD_Connection *connection,
                                            ConnectionInfo *ci) {
    return handle_create_product(connection, ci);
}

static enum MHD_Result route_list_products(struct MHD_Connection *connection,
                                           ConnectionInfo *ci) {
    (void)ci;
    return handle_list_products(connection);
}

static enum MHD_Result route_inbound(struct MHD_Connection *connection,
                                     ConnectionInfo *ci) {
    return handle_inbound(connection, ci);
}

static enum MHD_Result route_sales(struct MHD_Connection *connection,
                                   ConnectionInfo *ci) {
    return handle_sales(connection, ci);
}

static enum MHD_Result route_inventory(struct MHD_Connection *connection,
                                       ConnectionInfo *ci) {
    (void)ci;
    return handle_inventory(connection);
}

static enum MHD_Result route_movements(struct MHD_Connection *connection,
                                       ConnectionInfo *ci) {
    (void)ci;
    return handle_movements(connection);
}

static enum MHD_Result route_create_device(struct MHD_Connection *connection,
                                           ConnectionInfo *ci) {
    return handle_create_device(connection, ci);
}

static enum MHD_Result route_list_devices(struct MHD_Connection *connection,
                                          ConnectionInfo *ci) {
    (void)ci;
    return handle_list_devices(connection);
}

static enum MHD_Result route_report_temperature(struct MHD_Connection *connection,
                                                ConnectionInfo *ci) {
    return handle_report_temperature(connection, ci);
}

static enum MHD_Result route_add_device_product(struct MHD_Connection *connection,
                                                ConnectionInfo *ci) {
    return handle_add_device_product(connection, ci);
}

static enum MHD_Result route_remove_device_product(struct MHD_Connection *connection,
                                                   ConnectionInfo *ci) {
    return handle_remove_device_product(connection, ci);
}

static enum MHD_Result route_device_status(struct MHD_Connection *connection,
                                           ConnectionInfo *ci) {
    (void)ci;
    return handle_device_status(connection);
}

static enum MHD_Result route_list_alerts(struct MHD_Connection *connection,
                                         ConnectionInfo *ci) {
    (void)ci;
    return handle_list_alerts(connection);
}

static enum MHD_Result route_openapi_doc(struct MHD_Connection *connection,
                                         ConnectionInfo *ci);

static enum MHD_Result route_swagger_ui(struct MHD_Connection *connection,
                                        ConnectionInfo *ci) {
    (void)ci;
    return docs_send_swagger_ui(connection);
}

static enum MHD_Result route_home(struct MHD_Connection *connection,
                                  ConnectionInfo *ci) {
    (void)ci;
    return docs_send_home(connection);
}

static const ApiRoute g_api_routes[] = {
    {MHD_HTTP_METHOD_GET, "/", route_home, "Home", "服务首页", "System", 0, 0, 0},
    {MHD_HTTP_METHOD_GET, "/api/v1/health", route_health, "Health Check",
     "服务健康检查", "System", 0, 0, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/auth/register", route_register, "Create User",
     "创建用户（需管理员鉴权）", "Auth", 1, 1, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/auth/login", route_login, "Login",
     "用户登录并获取访问令牌", "Auth", 0, 1, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/auth/logout", route_logout, "Logout",
     "当前令牌退出登录", "Auth", 1, 0, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/auth/me", route_auth_me, "Current User",
     "获取当前登录用户信息", "Auth", 1, 0, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/products", route_create_product,
     "Create Product", "新增商品（管理员）", "Product", 1, 1, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/products", route_list_products, "List Products",
     "查询商品列表", "Product", 0, 0, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/inbound", route_inbound, "Inbound",
     "入库（进货）", "Inventory", 1, 1, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/sales", route_sales, "Sales",
     "销售出库", "Inventory", 1, 1, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/inventory", route_inventory, "Inventory Summary",
     "库存汇总与明细", "Inventory", 0, 0, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/movements", route_movements, "Movement History",
     "库存流水查询", "Inventory", 1, 0, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/devices", route_create_device,
     "Create Device", "创建设备（管理员）", "Temperature", 1, 1, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/devices", route_list_devices,
     "List Devices", "查询设备列表", "Temperature", 0, 0, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/devices/temperature", route_report_temperature,
     "Report Temperature", "上报设备温度，自动检测超限", "Temperature", 1, 1, 1},
    {MHD_HTTP_METHOD_POST, "/api/v1/devices/products", route_add_device_product,
     "Add Device Product", "给设备添加商品（管理员）", "Temperature", 1, 1, 1},
    {MHD_HTTP_METHOD_DELETE, "/api/v1/devices/products", route_remove_device_product,
     "Remove Device Product", "移除设备商品（管理员）", "Temperature", 1, 1, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/devices/status", route_device_status,
     "Device Status", "设备状态查询，补货员查看不可售卖商品", "Temperature", 1, 0, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/temperature/alerts", route_list_alerts,
     "Temperature Alerts", "温度异常记录查询", "Temperature", 1, 0, 1},
    {MHD_HTTP_METHOD_GET, "/api/v1/openapi.json", route_openapi_doc,
     "OpenAPI Document", "自动生成的 OpenAPI 文档", "System", 0, 0, 1},
    {MHD_HTTP_METHOD_GET, "/docs", route_swagger_ui, "Swagger UI",
     "Swagger 交互式文档页面", "System", 0, 0, 1},
};

static const size_t g_api_routes_count =
    sizeof(g_api_routes) / sizeof(g_api_routes[0]);

static enum MHD_Result route_openapi_doc(struct MHD_Connection *connection,
                                         ConnectionInfo *ci) {
    (void)ci;
    return docs_send_openapi(connection, g_api_routes, g_api_routes_count);
}

static enum MHD_Result handle_options(struct MHD_Connection *connection) {
    struct MHD_Response *response =
        MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
    if (response == NULL) {
        return MHD_NO;
    }

    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Headers",
                            "Content-Type, Authorization");
    MHD_add_response_header(response, "Access-Control-Allow-Methods",
                            "GET, POST, DELETE, OPTIONS");

    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_NO_CONTENT, response);
    MHD_destroy_response(response);
    return ret;
}

static enum MHD_Result route_request(struct MHD_Connection *connection,
                                     const char *url, const char *method,
                                     ConnectionInfo *ci) {
    if (strcmp(method, MHD_HTTP_METHOD_OPTIONS) == 0) {
        return handle_options(connection);
    }

    for (size_t i = 0; i < g_api_routes_count; ++i) {
        if (strcmp(method, g_api_routes[i].method) == 0 &&
            strcmp(url, g_api_routes[i].path) == 0) {
            return g_api_routes[i].handler(connection, ci);
        }
    }

    return respond_error(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND", "接口不存在");
}

static enum MHD_Result request_handler(void *cls,
                                       struct MHD_Connection *connection,
                                       const char *url, const char *method,
                                       const char *version,
                                       const char *upload_data,
                                       size_t *upload_data_size, void **con_cls) {
    (void)cls;
    (void)version;

    ConnectionInfo *ci = (ConnectionInfo *)(*con_cls);
    if (ci == NULL) {
        ci = (ConnectionInfo *)calloc(1, sizeof(ConnectionInfo));
        if (ci == NULL) {
            return MHD_NO;
        }
        *con_cls = ci;
        return MHD_YES;
    }

    if (is_method_with_body(method) && *upload_data_size != 0) {
        if (append_body(ci, upload_data, *upload_data_size) != 0) {
            *upload_data_size = 0;
            return respond_error(connection, MHD_HTTP_CONTENT_TOO_LARGE,
                                "PAYLOAD_TOO_LARGE", "请求体超过限制");
        }

        *upload_data_size = 0;
        return MHD_YES;
    }

    if (ci->processed) {
        return MHD_YES;
    }
    ci->processed = 1;

    return route_request(connection, url, method, ci);
}

static void request_completed_callback(void *cls, struct MHD_Connection *connection,
                                       void **con_cls,
                                       enum MHD_RequestTerminationCode toe) {
    (void)cls;
    (void)connection;
    (void)toe;

    ConnectionInfo *ci = (ConnectionInfo *)(*con_cls);
    if (ci != NULL) {
        free(ci->body);
        free(ci);
        *con_cls = NULL;
    }
}

static void load_config(void) {
    g_cfg.port = env_to_int("PORT", DEFAULT_PORT);
    g_cfg.session_ttl_hours =
        env_to_int("SESSION_TTL_HOURS", DEFAULT_SESSION_TTL_HOURS);
    g_cfg.db_path = getenv("DB_PATH");
    if (g_cfg.db_path == NULL || *g_cfg.db_path == '\0') {
        g_cfg.db_path = DEFAULT_DB_PATH;
    }

    g_cfg.key_file = getenv("USER_DATA_KEY_FILE");
    if (g_cfg.key_file == NULL || *g_cfg.key_file == '\0') {
        g_cfg.key_file = DEFAULT_KEY_FILE;
    }
}

int main(void) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    load_config();

    if (sodium_init() < 0) {
        fprintf(stderr, "[FATAL] libsodium 初始化失败\n");
        return 1;
    }

    if (db_init() != 0) {
        fprintf(stderr, "[FATAL] 数据库初始化失败\n");
        return 1;
    }

    if (load_or_create_key() != 0) {
        fprintf(stderr, "[FATAL] 用户字段加密密钥初始化失败\n");
        sqlite3_close(g_db);
        return 1;
    }

    if (ensure_default_admin_user() != 0) {
        fprintf(stderr, "[FATAL] 默认管理员初始化失败\n");
        sqlite3_close(g_db);
        return 1;
    }

    if (ensure_seed_stock_movement_consistency() != 0) {
        fprintf(stderr, "[FATAL] 种子库存流水修复失败\n");
        sqlite3_close(g_db);
        return 1;
    }

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD, (uint16_t)g_cfg.port, NULL, NULL,
        &request_handler, NULL, MHD_OPTION_NOTIFY_COMPLETED,
        request_completed_callback, NULL, MHD_OPTION_END);

    if (daemon == NULL) {
        fprintf(stderr, "[FATAL] HTTP 服务启动失败\n");
        sqlite3_close(g_db);
        return 1;
    }

    fprintf(stdout,
            "[INFO] 服务启动成功\n"
            "[INFO] 端口: %d\n"
            "[INFO] 数据库: %s\n"
            "[INFO] 会话时长(小时): %d\n",
            g_cfg.port, g_cfg.db_path, g_cfg.session_ttl_hours);

    while (g_running) {
        sleep(1);
    }

    MHD_stop_daemon(daemon);
    sqlite3_close(g_db);
    pthread_mutex_destroy(&g_db_mutex);

    fprintf(stdout, "[INFO] 服务已停止\n");
    return 0;
}

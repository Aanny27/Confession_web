import sqlite3
import time
from contextlib import contextmanager
from app.config import settings

@contextmanager
def get_db():
    conn = sqlite3.connect(settings.DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db() -> None:
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS otp_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_hash TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                used INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_otp_email ON otp_codes(email_hash);")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS verified_sessions (
                token_hash TEXT PRIMARY KEY,
                email_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS confessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL DEFAULT 'Tâm sự',
                title TEXT NOT NULL DEFAULT 'Tâm sự ẩn danh',
                content TEXT NOT NULL,
                email_hash TEXT NOT NULL DEFAULT '',
                likes_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
                created_at INTEGER NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_confessions_status ON confessions(status, created_at DESC);")

        # Tự động thêm cột mới nếu file confessions.db cũ chưa có
        existing_cols = {
            row["name"] for row in conn.execute("PRAGMA table_info(confessions);").fetchall()
        }
        if "category" not in existing_cols:
            conn.execute("ALTER TABLE confessions ADD COLUMN category TEXT NOT NULL DEFAULT 'Tâm sự';")
        if "title" not in existing_cols:
            conn.execute("ALTER TABLE confessions ADD COLUMN title TEXT NOT NULL DEFAULT 'Tâm sự ẩn danh';")
        if "email_hash" not in existing_cols:
            conn.execute("ALTER TABLE confessions ADD COLUMN email_hash TEXT NOT NULL DEFAULT '';")
        if "likes_count" not in existing_cols:
            conn.execute("ALTER TABLE confessions ADD COLUMN likes_count INTEGER NOT NULL DEFAULT 0;")

        # Bảng lưu lượt thả tim (chống spam thả tim trùng lặp theo IP/phiên)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS confession_likes (
                confession_id INTEGER NOT NULL,
                actor_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (confession_id, actor_hash),
                FOREIGN KEY(confession_id) REFERENCES confessions(id) ON DELETE CASCADE
            )
        """)

        # Bảng lưu bình luận ẩn danh
        conn.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                confession_id INTEGER NOT NULL,
                author_alias TEXT NOT NULL DEFAULT 'Một người bạn ẩn danh',
                content TEXT NOT NULL,
                likes INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(confession_id) REFERENCES confessions(id) ON DELETE CASCADE
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_comments_confession ON comments(confession_id, created_at ASC);")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_limits_id_time ON rate_limits(identifier, created_at);")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('owner', 'moderator')),
                is_locked INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                last_login_at INTEGER
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_lockouts (
                identifier TEXT PRIMARY KEY,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_sessions (
                session_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES admin_users(id) ON DELETE CASCADE
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_username TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_logs_time ON activity_logs(created_at DESC);")

def cleanup_expired_records() -> None:
    now = int(time.time())
    ten_mins_ago = now - 600
    with get_db() as conn:
        conn.execute("DELETE FROM otp_codes WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM verified_sessions WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM rate_limits WHERE created_at < ?", (ten_mins_ago,))
        conn.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (now,))
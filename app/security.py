import hashlib
import hmac
import logging
import math
import secrets
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, Request, status
from app.config import settings
from app.database import get_db

logger = logging.getLogger("security_audit")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [SECURITY] %(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

ph = PasswordHasher()
DUMMY_ARGON2_HASH = ph.hash("dummy_password_for_constant_time_check")

def hash_password(plain_password: str) -> str:
    return ph.hash(plain_password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return ph.verify(password_hash, plain_password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False

def hash_email(email: str) -> str:
    normalized = email.strip().lower().encode("utf-8")
    salt = settings.EMAIL_HASH_SALT.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", normalized, salt, 100_000)
    return dk.hex()

def hash_token(raw_value: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        raw_value.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def generate_otp() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(6))

def verify_otp_constant_time(input_otp: str, stored_otp_hash: str) -> bool:
    input_hash = hash_token(input_otp.strip())
    return secrets.compare_digest(input_hash, stored_otp_hash)

def get_client_ip(request: Request) -> str:
    if settings.TRUST_PROXY:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def log_admin_activity(
    conn,
    actor_username: str,
    actor_role: str,
    action: str,
    details: str,
    ip_address: str
) -> None:
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO activity_logs (actor_username, actor_role, action, details, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (actor_username, actor_role, action, details, ip_address, now)
    )
    logger.info(f"AUDIT | User={actor_username} ({actor_role}) | Action={action} | Details={details} | IP={ip_address}")

def seed_initial_owner() -> None:
    """
    Khởi tạo hoặc đồng bộ tài khoản tối cao của Người code dự án (owner) từ tệp .env.
    Nếu bạn sửa ADMIN_USERNAME hoặc ADMIN_PASSWORD trong .env, hệ thống tự động cập nhật theo.
    """
    username = settings.ADMIN_USERNAME
    password = settings.ADMIN_PASSWORD
    if not username or len(password) < 6:
        raise RuntimeError(
            "Vui lòng thiết lập ADMIN_USERNAME và ADMIN_PASSWORD (tối thiểu 6 ký tự) trong tệp .env"
        )

    now = int(time.time())
    pw_hash = hash_password(password)

    with get_db() as conn:
        existing_owner = conn.execute(
            "SELECT id, username FROM admin_users WHERE role = 'owner' LIMIT 1"
        ).fetchone()

        if not existing_owner:
            conn.execute(
                """
                INSERT INTO admin_users (username, password_hash, role, is_locked, created_at)
                VALUES (?, ?, 'owner', 0, ?)
                """,
                (username, pw_hash, now)
            )
            log_admin_activity(
                conn,
                actor_username="SYSTEM",
                actor_role="system",
                action="INIT_ROOT_OWNER",
                details=f"Khởi tạo tài khoản Quản trị tối cao ({username}) từ .env",
                ip_address="127.0.0.1"
            )
        else:
            conn.execute(
                "UPDATE admin_users SET username = ?, password_hash = ?, is_locked = 0 WHERE id = ?",
                (username, pw_hash, existing_owner["id"])
            )

def create_csrf_pair() -> tuple[str, str]:
    raw_token = secrets.token_urlsafe(32)
    signature = hash_token(f"csrf:{raw_token}")
    return raw_token, f"{raw_token}.{signature}"

def verify_csrf(request: Request) -> None:
    cookie_val = request.cookies.get("csrf_cookie")
    header_val = request.headers.get("X-CSRF-Token")

    if not cookie_val or not header_val or "." not in cookie_val:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Phiên bảo mật (CSRF) không hợp lệ. Vui lòng tải lại trang."
        )

    raw_cookie_token, cookie_sig = cookie_val.split(".", 1)
    expected_sig = hash_token(f"csrf:{raw_cookie_token}")

    if not (
        secrets.compare_digest(cookie_sig, expected_sig)
        and secrets.compare_digest(header_val, raw_cookie_token)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Mã bảo mật CSRF không khớp. Vui lòng tải lại trang."
        )

RATE_LIMIT_MAX_REQUESTS = 5
RATE_LIMIT_WINDOW_SECONDS = 600

def check_and_record_rate_limit(ip_address: str, email_hash: str) -> None:
    now = int(time.time())
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    ip_key = f"ip:{ip_address}"
    email_key = f"email:{email_hash}"

    with get_db() as conn:
        for key, label in [(ip_key, f"IP {ip_address}"), (email_key, f"EmailHash {email_hash[:8]}...")]:
            rows = conn.execute(
                "SELECT created_at FROM rate_limits WHERE identifier = ? AND created_at > ? ORDER BY created_at ASC",
                (key, window_start)
            ).fetchall()

            if len(rows) >= RATE_LIMIT_MAX_REQUESTS:
                oldest_timestamp = rows[0]["created_at"]
                retry_after_seconds = max(1, (oldest_timestamp + RATE_LIMIT_WINDOW_SECONDS) - now)
                retry_minutes = max(1, math.ceil(retry_after_seconds / 60))

                logger.warning(f"Vượt giới hạn tần suất (429): {label}, chờ {retry_after_seconds}s")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "message": f"Vui lòng thử lại sau {retry_minutes} phút",
                        "retry_after_seconds": retry_after_seconds
                    }
                )

        conn.execute("INSERT INTO rate_limits (identifier, created_at) VALUES (?, ?)", (ip_key, now))
        conn.execute("INSERT INTO rate_limits (identifier, created_at) VALUES (?, ?)", (email_key, now))

def require_admin(request: Request) -> dict:
    """Kiểm tra quyền đăng nhập cho cả Quản trị tối cao (owner) và Admin duyệt bài (moderator)."""
    raw_session = request.cookies.get("admin_session")
    if not raw_session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Vui lòng đăng nhập để tiếp tục.")

    session_hash = hash_token(raw_session)
    now = int(time.time())
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT s.session_hash, s.user_id, s.expires_at,
                   u.username, u.role, u.is_locked
            FROM admin_sessions s
            JOIN admin_users u ON s.user_id = u.id
            WHERE s.session_hash = ?
            """,
            (session_hash,)
        ).fetchone()

        if not row or row["expires_at"] < now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Phiên đăng nhập đã hết hạn.")

        if row["is_locked"] == 1:
            conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (row["user_id"],))
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tài khoản của bạn đã bị khoá.")

        return dict(row)

def require_owner(request: Request) -> dict:
    """Chỉ cho phép tài khoản tối cao của bạn (role = 'owner') thực hiện."""
    admin_user = require_admin(request)
    if admin_user["role"] != "owner":
        logger.warning(f"Chặn Admin thường '{admin_user['username']}' truy cập chức năng Quản trị tối cao")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chỉ Quản trị viên tối cao (Chủ dự án) mới có quyền thực hiện thao tác này."
        )
    return admin_user
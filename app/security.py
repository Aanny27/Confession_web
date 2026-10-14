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

def hash_identifier(raw_id: str) -> str:
    """
    Băm địa chỉ IP / mã thiết bị kèm muối bí mật để đếm giới hạn 5 bài/ngày
    mà không lưu IP thật của người gửi vào cơ sở dữ liệu.
    """
    normalized = raw_id.strip().lower().encode("utf-8")
    salt = settings.EMAIL_HASH_SALT.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", normalized, salt, 50_000)
    return dk.hex()

def hash_token(raw_value: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        raw_value.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

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
            "SELECT id FROM admin_users WHERE role = 'owner' LIMIT 1"
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
                details=f"Khởi tạo tài khoản Quản trị tối cao ({username})",
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

# --- GIỚI HẠN MỖI NGƯỜI DÙNG TỐI ĐA 5 BÀI / 1 NGÀY (24 GIỜ) ---
DAILY_MAX_POSTS = 5
DAILY_WINDOW_SECONDS = 86400  # 24 giờ = 86.400 giây

def check_and_record_daily_limit(ip_address: str, device_token: str) -> int:
    """
    Kiểm tra mỗi người dùng (theo mã băm IP hoặc mã thiết bị) chỉ được đăng tối đa 5 bài trong 24 giờ.
    Trả về số bài còn lại được phép đăng trong ngày.
    """
    now = int(time.time())
    window_start = now - DAILY_WINDOW_SECONDS

    ip_key = f"ip:{hash_identifier(ip_address)}"
    dev_key = f"dev:{hash_token(device_token)}"

    with get_db() as conn:
        for key in (ip_key, dev_key):
            rows = conn.execute(
                "SELECT created_at FROM rate_limits WHERE identifier = ? AND created_at > ? ORDER BY created_at ASC",
                (key, window_start)
            ).fetchall()

            if len(rows) >= DAILY_MAX_POSTS:
                oldest_timestamp = rows[0]["created_at"]
                retry_after_seconds = max(1, (oldest_timestamp + DAILY_WINDOW_SECONDS) - now)
                hours = retry_after_seconds // 3600
                minutes = math.ceil((retry_after_seconds % 3600) / 60)

                time_str = f"{hours} giờ {minutes} phút" if hours > 0 else f"{minutes} phút"
                logger.warning(f"Chạm giới hạn 5 bài/ngày (429), cần chờ {retry_after_seconds}s")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "message": f"Bạn đã đăng đủ 5 bài trong ngày hôm nay. Vui lòng thử lại sau {time_str}.",
                        "retry_after_seconds": retry_after_seconds
                    }
                )

        conn.execute("INSERT INTO rate_limits (identifier, created_at) VALUES (?, ?)", (ip_key, now))
        if dev_key != ip_key:
            conn.execute("INSERT INTO rate_limits (identifier, created_at) VALUES (?, ?)", (dev_key, now))

        used_count = conn.execute(
            "SELECT COUNT(*) AS cnt FROM rate_limits WHERE identifier = ? AND created_at > ?",
            (ip_key, window_start)
        ).fetchone()["cnt"]

    return max(0, DAILY_MAX_POSTS - used_count)

def require_admin(request: Request) -> dict:
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
    admin_user = require_admin(request)
    if admin_user["role"] != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chỉ Quản trị viên mới có quyền thực hiện thao tác này."
        )
    return admin_user
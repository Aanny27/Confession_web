import base64
import hashlib
import hmac
import io
import logging
import math
import secrets
import time
import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, Request, status
from app.config import settings
from app.database import get_db

# [OWASP A09:2021 - Security Logging and Monitoring Failures]
logger = logging.getLogger("security_audit")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [SECURITY] %(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# [OWASP A02:2021 - Cryptographic Failures] Băm mật khẩu bằng Argon2id
ph = PasswordHasher()
# Mã băm giả dùng để cân bằng thời gian phản hồi khi tên đăng nhập không tồn tại (chống dò username)
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

# --- NHẬT KÝ HOẠT ĐỘNG QUẢN TRỊ (AUDIT LOG) ---
def log_admin_activity(
    conn,
    actor_username: str,
    actor_role: str,
    action: str,
    details: str,
    ip_address: str
) -> None:
    """
    [OWASP A09:2021 - Security Logging and Monitoring Failures]
    Ghi nhận đầy đủ ai làm gì, lúc nào vào bảng activity_logs và console.
    Không ghi nội dung confession hay mật khẩu/email gốc.
    """
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO activity_logs (actor_username, actor_role, action, details, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (actor_username, actor_role, action, details, ip_address, now)
    )
    logger.info(f"AUDIT | User={actor_username} ({actor_role}) | Action={action} | Details={details} | IP={ip_address}")

# --- KHỞI TẠO TÀI KHOẢN "CHỦ" LẦN ĐẦU TIÊN ---
def seed_initial_owner() -> None:
    """
    Tạo tài khoản Chủ (owner) ở lần chạy đầu tiên từ biến môi trường ADMIN_USERNAME và ADMIN_PASSWORD.
    Bắt buộc đổi mật khẩu ở lần đăng nhập đầu tiên (must_change_password = 1).
    """
    with get_db() as conn:
        existing_owner = conn.execute(
            "SELECT id FROM admin_users WHERE role = 'owner' LIMIT 1"
        ).fetchone()

        if existing_owner:
            return

        username = settings.ADMIN_USERNAME
        password = settings.ADMIN_PASSWORD
        if not username or len(password) < 8:
            raise RuntimeError(
                "Lần chạy đầu tiên chưa có tài khoản Chủ: Nhóm quản lý cần thiết lập "
                "ADMIN_USERNAME và ADMIN_PASSWORD (tối thiểu 8 ký tự) trong tệp .env"
            )

        now = int(time.time())
        pw_hash = hash_password(password)
        conn.execute(
            """
            INSERT INTO admin_users (
                username, password_hash, role, must_change_password,
                totp_enabled, is_locked, created_at
            )
            VALUES (?, ?, 'owner', 1, 0, 0, ?)
            """,
            (username, pw_hash, now)
        )
        log_admin_activity(
            conn,
            actor_username="SYSTEM",
            actor_role="system",
            action="INIT_OWNER",
            details=f"Khởi tạo tài khoản Chủ đầu tiên ({username}) từ biến môi trường, yêu cầu đổi mật khẩu lần đầu.",
            ip_address="127.0.0.1"
        )

# --- XÁC THỰC HAI BƯỚC (TOTP - ỨNG DỤNG TẠO MÃ) ---
def generate_totp_secret() -> str:
    return pyotp.random_base32()

def generate_totp_qr_svg_data_uri(username: str, secret: str) -> str:
    """
    [OWASP A10:2021 - SSRF & Privacy]
    Tạo mã QR dạng SVG ngay trên máy chủ (offline), không gửi khoá bí mật TOTP ra dịch vụ bên ngoài.
    """
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name=settings.TOTP_ISSUER_NAME)
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    img.save(buffer)
    svg_base64 = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{svg_base64}"

def verify_totp_code(secret: str, code: str, last_used_step: int) -> tuple[bool, int]:
    """
    [OWASP A07:2021 - Identification and Authentication Failures]
    Kiểm tra mã TOTP 6 số (cho phép lệch tối đa ±1 bước 30 giây) và chống dùng lại mã cũ (Replay Attack).
    """
    if not secret or not code or not code.isdigit() or len(code) != 6:
        return False, last_used_step

    totp = pyotp.TOTP(secret)
    current_step = int(time.time()) // 30

    for offset in (-1, 0, 1):
        candidate_step = current_step + offset
        if candidate_step <= last_used_step:
            continue
        expected_code = totp.at(candidate_step * 30)
        if secrets.compare_digest(code, expected_code):
            return True, candidate_step

    return False, last_used_step

# --- CHỐNG GIẢ MẠO YÊU CẦU (CSRF) ---
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

# --- GIỚI HẠN SỐ LẦN GỬI CONFESSION (RATE LIMITING) ---
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

# --- KIỂM SOÁT TRUY CẬP & PHÂN QUYỀN (RBAC) ---
def get_pre_auth_session(request: Request) -> dict:
    """
    Lấy phiên đăng nhập bước 1 (đã qua mật khẩu, đang chờ đổi mật khẩu lần đầu hoặc xác thực 2FA).
    """
    raw_session = request.cookies.get("admin_session")
    if not raw_session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Phiên đăng nhập không tồn tại.")

    session_hash = hash_token(raw_session)
    now = int(time.time())
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT s.session_hash, s.user_id, s.is_fully_authenticated, s.totp_attempts, s.expires_at,
                   u.username, u.password_hash, u.role, u.must_change_password,
                   u.totp_secret, u.pending_totp_secret, u.totp_enabled, u.last_totp_step, u.is_locked
            FROM admin_sessions s
            JOIN admin_users u ON s.user_id = u.id
            WHERE s.session_hash = ?
            """,
            (session_hash,)
        ).fetchone()

        if not row or row["expires_at"] < now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại.")

        if row["is_locked"] == 1:
            conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (row["user_id"],))
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tài khoản của bạn đã bị Chủ khoá.")

        return dict(row)

def require_admin(request: Request) -> dict:
    """
    [OWASP A01:2021 - Broken Access Control]
    Bắt buộc người dùng phải hoàn tất:
    1. Đổi mật khẩu lần đầu (must_change_password == 0)
    2. Đã kích hoạt 2FA (totp_enabled == 1)
    3. Đã xác thực mã 2FA trong phiên hiện tại (is_fully_authenticated == 1)
    4. Tài khoản không bị khoá (is_locked == 0)
    Áp dụng cho cả Chủ ('owner') và Người duyệt ('moderator').
    """
    session_data = get_pre_auth_session(request)
    if (
        session_data["is_fully_authenticated"] != 1
        or session_data["must_change_password"] != 0
        or session_data["totp_enabled"] != 1
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Vui lòng hoàn tất đổi mật khẩu bắt buộc và xác thực hai bước (2FA) để tiếp tục."
        )
    return session_data

def require_owner(request: Request) -> dict:
    """
    [OWASP A01:2021 - Broken Access Control]
    Chỉ cho phép tài khoản có vai trò 'owner' (Chủ) thực hiện quản lý người dùng và xem nhật ký hoạt động.
    """
    admin_user = require_admin(request)
    if admin_user["role"] != "owner":
        logger.warning(f"Cố gắng truy cập trái phép quyền Chủ bởi User={admin_user['username']} từ IP={get_client_ip(request)}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chỉ tài khoản 'Chủ' mới có quyền thực hiện thao tác này."
        )
    return admin_user
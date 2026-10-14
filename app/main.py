import mimetypes
import secrets
import time
from pathlib import Path
from typing import Literal, Optional
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from app.config import settings
from app.database import cleanup_expired_records, get_db, init_db
from app.notifications import notify_admin_new_confession, send_otp_email, verify_turnstile_token
from app.security import (
    DUMMY_ARGON2_HASH,
    check_and_record_rate_limit,
    create_csrf_pair,
    generate_otp,
    get_client_ip,
    hash_email,
    hash_password,
    hash_token,
    log_admin_activity,
    logger,
    require_admin,
    require_owner,
    seed_initial_owner,
    verify_csrf,
    verify_otp_constant_time,
    verify_password,
)

mimetypes.init()
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("application/javascript", ".js")

settings.validate()
init_db()
seed_initial_owner()

app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

MAX_BODY_SIZE = 32 * 1024  # 32 KB
VERIFIED_SESSION_TTL = 7200  # Phiên người dùng sau khi xác thực OTP có hiệu lực 2 giờ

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_SIZE:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Dữ liệu gửi lên vượt quá kích thước cho phép."}
        )

    body = await request.body()
    if len(body) > MAX_BODY_SIZE:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Dữ liệu gửi lên vượt quá kích thước cho phép."}
        )

    try:
        response: Response = await call_next(request)
    except Exception as exc:
        logger.error(f"Lỗi hệ thống không mong muốn: {type(exc).__name__}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Đã xảy ra lỗi hệ thống. Vui lòng thử lại sau."}
        )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://challenges.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "frame-src https://challenges.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    return response

# --- MÔ HÌNH DỮ LIỆU ĐẦU VÀO ---
class OTPRequestPayload(BaseModel):
    email: EmailStr
    website_url: str = Field(default="", max_length=200)
    turnstile_token: str = Field(default="", max_length=2048)

class OTPVerifyPayload(BaseModel):
    email: EmailStr
    otp_code: Optional[str] = Field(default=None, max_length=6)
    otp: Optional[str] = Field(default=None, max_length=6)
    code: Optional[str] = Field(default=None, max_length=6)

class ConfessionSubmitPayload(BaseModel):
    category: str = Field(default="Tâm sự", max_length=50)
    title: str = Field(default="Tâm sự ẩn danh", max_length=120)
    content: str = Field(..., min_length=20, max_length=3000)
    website_url: str = Field(default="", max_length=200)

class CommentSubmitPayload(BaseModel):
    content: str = Field(..., min_length=1, max_length=800)
    author_alias: str = Field(default="Một người bạn ẩn danh", max_length=60)

class AdminLoginPayload(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=1, max_length=256)

class CreateSubAdminPayload(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=6, max_length=256)

class ResetSubAdminPasswordPayload(BaseModel):
    new_password: str = Field(..., min_length=6, max_length=256)

class AdminStatusUpdatePayload(BaseModel):
    status: Literal["approved", "rejected"]

class LockUserPayload(BaseModel):
    is_locked: bool

# --- HÀM HỖ TRỢ LẤY EMAIL_HASH TỪ PHIÊN NGƯỜI DÙNG ---
def get_verified_email_hash(request: Request, require: bool = False) -> Optional[str]:
    raw_token = request.cookies.get("verified_submission_token")
    auth_header = request.headers.get("Authorization", "")
    if not raw_token and auth_header.startswith("Bearer "):
        raw_token = auth_header.removeprefix("Bearer ").strip()

    if not raw_token:
        if require:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Bạn cần xác nhận email bằng mã OTP trước khi thực hiện thao tác này."
            )
        return None

    token_hash = hash_token(raw_token)
    now = int(time.time())
    with get_db() as conn:
        row = conn.execute(
            "SELECT email_hash, expires_at FROM verified_sessions WHERE token_hash = ?",
            (token_hash,)
        ).fetchone()

        if not row or row["expires_at"] < now:
            if require:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Phiên xác nhận email đã hết hạn. Vui lòng xác nhận lại email."
                )
            return None
        return row["email_hash"]

# --- ĐƯỜNG DẪN TĨNH ---
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
async def index_page():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/admin")
async def admin_page():
    return FileResponse(STATIC_DIR / "admin.html")

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)

@app.get("/api/csrf")
async def get_csrf_token(response: Response):
    cleanup_expired_records()
    raw_token, cookie_val = create_csrf_pair()
    response.set_cookie(
        key="csrf_cookie",
        value=cookie_val,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        max_age=7200,
        path="/"
    )
    return {"csrf_token": raw_token}

# =====================================================================
# PHẦN 1: API XÁC THỰC OTP & CONFESSION CÔNG KHAI
# =====================================================================
@app.post("/api/otp/request", dependencies=[Depends(verify_csrf)])
@app.post("/api/auth/send-otp", dependencies=[Depends(verify_csrf)])
async def request_otp(payload: OTPRequestPayload, request: Request):
    client_ip = get_client_ip(request)
    if payload.website_url.strip() != "":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Yêu cầu không hợp lệ.")

    if not verify_turnstile_token(payload.turnstile_token, client_ip):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Xác thực chống robot không thành công.")

    email_hash = hash_email(payload.email)
    check_and_record_rate_limit(client_ip, email_hash)

    otp_code = generate_otp()
    otp_hash = hash_token(otp_code)
    now = int(time.time())

    with get_db() as conn:
        conn.execute("UPDATE otp_codes SET used = 1 WHERE email_hash = ? AND used = 0", (email_hash,))
        conn.execute(
            "INSERT INTO otp_codes (email_hash, otp_hash, expires_at, attempts, used, created_at) VALUES (?, ?, ?, 0, 0, ?)",
            (email_hash, otp_hash, now + 600, now)
        )

    try:
        send_otp_email(payload.email, otp_code)
    except Exception as exc:
        logger.error(f"Không thể gửi email SMTP: {type(exc).__name__}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Không thể gửi email xác nhận lúc này. Vui lòng thử lại sau."
        )

    return {"message": "Mã xác nhận gồm 6 chữ số đã được gửi tới email của bạn (hiệu lực 10 phút)."}

@app.post("/api/otp/verify", dependencies=[Depends(verify_csrf)])
@app.post("/api/auth/verify-otp", dependencies=[Depends(verify_csrf)])
async def verify_otp(payload: OTPVerifyPayload, request: Request, response: Response):
    code_str = (payload.otp_code or payload.otp or payload.code or "").strip()
    if len(code_str) != 6 or not code_str.isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Mã OTP phải gồm 6 chữ số.")

    email_hash = hash_email(payload.email)
    now = int(time.time())

    with get_db() as conn:
        row = conn.execute(
            "SELECT id, otp_hash, expires_at, attempts FROM otp_codes WHERE email_hash = ? AND used = 0 ORDER BY id DESC LIMIT 1",
            (email_hash,)
        ).fetchone()

        if not row or row["expires_at"] < now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mã xác nhận không tồn tại hoặc đã hết hạn (quá 10 phút). Vui lòng lấy mã mới."
            )

        otp_id = row["id"]
        new_attempts = row["attempts"] + 1
        is_valid = verify_otp_constant_time(code_str, row["otp_hash"])

        if not is_valid:
            if new_attempts >= 5:
                conn.execute("UPDATE otp_codes SET attempts = ?, used = 1 WHERE id = ?", (new_attempts, otp_id))
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Bạn đã nhập sai mã quá 5 lần. Mã xác nhận đã bị huỷ, vui lòng gửi lại mã mới."
                )
            conn.execute("UPDATE otp_codes SET attempts = ? WHERE id = ?", (new_attempts, otp_id))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Mã xác nhận chưa đúng. Bạn còn {5 - new_attempts} lần thử."
            )

        conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_id,))
        submission_token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO verified_sessions (token_hash, email_hash, expires_at, used) VALUES (?, ?, ?, 0)",
            (hash_token(submission_token), email_hash, now + VERIFIED_SESSION_TTL)
        )

    response.set_cookie(
        key="verified_submission_token",
        value=submission_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        max_age=VERIFIED_SESSION_TTL,
        path="/"
    )
    return {
        "message": "Xác nhận email thành công! Bạn có thể viết câu chuyện của mình ngay bây giờ.",
        "token": submission_token
    }

@app.get("/api/confessions")
@app.get("/api/confessions/public")
async def list_public_confessions(
    request: Request,
    category: str = Query(default="", max_length=50),
    sort: str = Query(default="newest", max_length=20),
    q: str = Query(default="", max_length=100),
    page: int = Query(default=1, ge=1, le=1000),
    page_size: int = Query(default=20, ge=1, le=50)
):
    offset = (page - 1) * page_size
    client_ip = get_client_ip(request)
    actor_hash = hash_token(f"like:{client_ip}")

    conditions = ["c.status = 'approved'"]
    params: list = []

    if category.strip() and category.strip() != "all":
        conditions.append("c.category = ?")
        params.append(category.strip())

    if q.strip():
        conditions.append("(c.title LIKE ? OR c.content LIKE ?)")
        kw = f"%{q.strip()}%"
        params.extend([kw, kw])

    where_clause = " AND ".join(conditions)
    order_clause = "c.likes_count DESC, c.created_at DESC" if sort == "popular" else "c.created_at DESC, c.id DESC"

    with get_db() as conn:
        total_row = conn.execute(
            f"SELECT COUNT(*) AS cnt FROM confessions c WHERE {where_clause}",
            tuple(params)
        ).fetchone()

        rows = conn.execute(
            f"""
            SELECT c.id, c.category, c.title, c.content, c.status, c.likes_count, c.created_at,
                   (SELECT COUNT(*) FROM comments cm WHERE cm.confession_id = c.id) AS comments_count,
                   EXISTS(SELECT 1 FROM confession_likes cl WHERE cl.confession_id = c.id AND cl.actor_hash = ?) AS liked
            FROM confessions c
            WHERE {where_clause}
            ORDER BY {order_clause}
            LIMIT ? OFFSET ?
            """,
            tuple([actor_hash] + params + [page_size, offset])
        ).fetchall()

    items = []
    for r in rows:
        d = dict(r)
        d["liked"] = bool(d["liked"])
        items.append(d)

    return {
        "items": items,
        "total": total_row["cnt"],
        "page": page,
        "page_size": page_size
    }

@app.get("/api/my-confessions")
async def list_my_confessions(request: Request):
    email_hash = get_verified_email_hash(request, require=False)
    if not email_hash:
        return {"items": []}

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT c.id, c.category, c.title, c.content, c.status, c.likes_count, c.created_at,
                   (SELECT COUNT(*) FROM comments cm WHERE cm.confession_id = c.id) AS comments_count
            FROM confessions c
            WHERE c.email_hash = ?
            ORDER BY c.created_at DESC, c.id DESC
            """,
            (email_hash,)
        ).fetchall()

    return {"items": [dict(r) for r in rows]}

@app.get("/api/confessions/{confession_id}")
async def get_confession_detail(confession_id: int, request: Request):
    email_hash = get_verified_email_hash(request, require=False)
    client_ip = get_client_ip(request)
    actor_hash = hash_token(f"like:{client_ip}")

    with get_db() as conn:
        row = conn.execute(
            """
            SELECT id, category, title, content, email_hash, status, likes_count, created_at
            FROM confessions
            WHERE id = ?
            """,
            (confession_id,)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy bài viết.")

        is_owner = bool(email_hash and row["email_hash"] == email_hash)
        if row["status"] != "approved" and not is_owner:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bài viết chưa được công khai.")

        comments = conn.execute(
            """
            SELECT id, author_alias, content, likes, created_at
            FROM comments
            WHERE confession_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (confession_id,)
        ).fetchall()

        liked_row = conn.execute(
            "SELECT 1 FROM confession_likes WHERE confession_id = ? AND actor_hash = ?",
            (confession_id, actor_hash)
        ).fetchone()

    result = {
        "id": row["id"],
        "category": row["category"],
        "title": row["title"],
        "content": row["content"],
        "status": row["status"],
        "likes_count": row["likes_count"],
        "liked": bool(liked_row),
        "created_at": row["created_at"],
        "is_owner": is_owner,
        "can_edit": is_owner and row["status"] == "pending",
        "comments": [dict(c) for c in comments],
        "comments_count": len(comments)
    }
    return result

@app.post("/api/confessions", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
async def submit_confession(
    payload: ConfessionSubmitPayload,
    request: Request,
    background_tasks: BackgroundTasks
):
    client_ip = get_client_ip(request)
    if payload.website_url.strip() != "":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Yêu cầu không hợp lệ.")

    email_hash = get_verified_email_hash(request, require=True)
    check_and_record_rate_limit(client_ip, email_hash)

    allowed_categories = {"Tâm sự", "Tình yêu", "Học tập", "Cuộc sống", "Khác"}
    cleaned_cat = payload.category.strip() if payload.category.strip() in allowed_categories else "Tâm sự"
    cleaned_title = payload.title.strip() or "Tâm sự ẩn danh"
    cleaned_content = payload.content.strip()

    if len(cleaned_content) < 20 or len(cleaned_content) > 3000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nội dung câu chuyện phải từ 20 đến 3000 ký tự."
        )

    now = int(time.time())
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO confessions (category, title, content, email_hash, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
            """,
            (cleaned_cat, cleaned_title, cleaned_content, email_hash, now)
        )
        confession_id = cursor.lastrowid

    background_tasks.add_task(notify_admin_new_confession, confession_id)
    return {"message": "Confession đang chờ duyệt", "id": confession_id}

@app.put("/api/confessions/{confession_id}", dependencies=[Depends(verify_csrf)])
async def update_own_confession(
    confession_id: int,
    payload: ConfessionSubmitPayload,
    request: Request
):
    email_hash = get_verified_email_hash(request, require=True)
    allowed_categories = {"Tâm sự", "Tình yêu", "Học tập", "Cuộc sống", "Khác"}
    cleaned_cat = payload.category.strip() if payload.category.strip() in allowed_categories else "Tâm sự"
    cleaned_title = payload.title.strip() or "Tâm sự ẩn danh"
    cleaned_content = payload.content.strip()

    with get_db() as conn:
        row = conn.execute(
            "SELECT email_hash, status FROM confessions WHERE id = ?",
            (confession_id,)
        ).fetchone()
        if not row or row["email_hash"] != email_hash:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bạn không có quyền sửa bài viết này.")
        if row["status"] != "pending":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Chỉ có thể chỉnh sửa bài viết khi đang chờ duyệt.")

        conn.execute(
            "UPDATE confessions SET category = ?, title = ?, content = ? WHERE id = ?",
            (cleaned_cat, cleaned_title, cleaned_content, confession_id)
        )

    return {"message": "Đã cập nhật bài viết thành công!", "id": confession_id}

@app.delete("/api/confessions/{confession_id}", dependencies=[Depends(verify_csrf)])
async def delete_own_confession(confession_id: int, request: Request):
    email_hash = get_verified_email_hash(request, require=True)
    with get_db() as conn:
        row = conn.execute(
            "SELECT email_hash FROM confessions WHERE id = ?",
            (confession_id,)
        ).fetchone()
        if not row or row["email_hash"] != email_hash:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bạn không có quyền xoá bài viết này.")

        conn.execute("DELETE FROM confessions WHERE id = ?", (confession_id,))
    return {"message": "Đã xoá bài viết của bạn."}

@app.post("/api/confessions/{confession_id}/like", dependencies=[Depends(verify_csrf)])
async def toggle_like_confession(confession_id: int, request: Request):
    client_ip = get_client_ip(request)
    actor_hash = hash_token(f"like:{client_ip}")
    now = int(time.time())

    with get_db() as conn:
        row = conn.execute(
            "SELECT id, likes_count FROM confessions WHERE id = ? AND status = 'approved'",
            (confession_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy bài viết.")

        existing = conn.execute(
            "SELECT 1 FROM confession_likes WHERE confession_id = ? AND actor_hash = ?",
            (confession_id, actor_hash)
        ).fetchone()

        if existing:
            conn.execute(
                "DELETE FROM confession_likes WHERE confession_id = ? AND actor_hash = ?",
                (confession_id, actor_hash)
            )
            new_likes = max(0, row["likes_count"] - 1)
            liked = False
        else:
            conn.execute(
                "INSERT INTO confession_likes (confession_id, actor_hash, created_at) VALUES (?, ?, ?)",
                (confession_id, actor_hash, now)
            )
            new_likes = row["likes_count"] + 1
            liked = True

        conn.execute("UPDATE confessions SET likes_count = ? WHERE id = ?", (new_likes, confession_id))

    return {"liked": liked, "likes_count": new_likes}

@app.post("/api/confessions/{confession_id}/comments", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
async def add_comment(confession_id: int, payload: CommentSubmitPayload, request: Request):
    cleaned_content = payload.content.strip()
    if not cleaned_content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nội dung bình luận không được để trống.")

    now = int(time.time())
    with get_db() as conn:
        row = conn.execute(
            "SELECT id FROM confessions WHERE id = ? AND status = 'approved'",
            (confession_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không thể bình luận vào bài viết này.")

        conn.execute(
            "INSERT INTO comments (confession_id, author_alias, content, created_at) VALUES (?, ?, ?, ?)",
            (confession_id, payload.author_alias.strip() or "Một người bạn ẩn danh", cleaned_content, now)
        )

    return {"message": "Đã gửi bình luận ẩn danh."}

# =====================================================================
# PHẦN 2: ĐĂNG NHẬP QUẢN TRỊ
# =====================================================================
ADMIN_MAX_FAILED_ATTEMPTS = 5
ADMIN_LOCKOUT_SECONDS = 900

@app.get("/api/admin/me")
async def admin_current_status(admin_user: dict = Depends(require_admin)):
    return {
        "authenticated": True,
        "username": admin_user["username"],
        "role": admin_user["role"]
    }

@app.post("/api/admin/login", dependencies=[Depends(verify_csrf)])
async def admin_login(payload: AdminLoginPayload, request: Request, response: Response):
    client_ip = get_client_ip(request)
    now = int(time.time())
    username_clean = payload.username.strip()
    lock_key = f"login:{client_ip}:{username_clean.lower()}"

    with get_db() as conn:
        lock_row = conn.execute(
            "SELECT failed_attempts, locked_until FROM admin_lockouts WHERE identifier = ?",
            (lock_key,)
        ).fetchone()

        if lock_row and lock_row["locked_until"] > now:
            wait_mins = max(1, (lock_row["locked_until"] - now + 59) // 60)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Tài khoản đang tạm khoá do nhập sai nhiều lần. Vui lòng thử lại sau {wait_mins} phút."
            )

        user_row = conn.execute(
            "SELECT * FROM admin_users WHERE username = ?",
            (username_clean,)
        ).fetchone()

        target_hash = user_row["password_hash"] if user_row else DUMMY_ARGON2_HASH
        password_ok = verify_password(payload.password, target_hash)

        if not user_row or not password_ok:
            fails = (lock_row["failed_attempts"] if lock_row else 0) + 1
            locked_until = (now + ADMIN_LOCKOUT_SECONDS) if fails >= ADMIN_MAX_FAILED_ATTEMPTS else 0
            conn.execute(
                """
                INSERT INTO admin_lockouts (identifier, failed_attempts, locked_until)
                VALUES (?, ?, ?)
                ON CONFLICT(identifier) DO UPDATE SET
                    failed_attempts = excluded.failed_attempts,
                    locked_until = excluded.locked_until
                """,
                (lock_key, fails, locked_until)
            )
            log_admin_activity(
                conn,
                actor_username=username_clean,
                actor_role=user_row["role"] if user_row else "unknown",
                action="LOGIN_FAILED",
                details=f"Sai mật khẩu ({fails}/{ADMIN_MAX_FAILED_ATTEMPTS})",
                ip_address=client_ip
            )
            if locked_until > 0:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Nhập sai quá 5 lần. Đã tạm khoá đăng nhập trong 15 phút."
                )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Tên đăng nhập hoặc mật khẩu không đúng. Còn {ADMIN_MAX_FAILED_ATTEMPTS - fails} lần thử."
            )

        if user_row["is_locked"] == 1:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tài khoản Admin này đã bị Quản trị viên tối cao khoá."
            )

        conn.execute("DELETE FROM admin_lockouts WHERE identifier = ?", (lock_key,))
        conn.execute("UPDATE admin_users SET last_login_at = ? WHERE id = ?", (now, user_row["id"]))

        raw_session = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO admin_sessions (session_hash, user_id, ip_address, expires_at) VALUES (?, ?, ?, ?)",
            (hash_token(raw_session), user_row["id"], client_ip, now + 14400)
        )

        log_admin_activity(
            conn,
            actor_username=user_row["username"],
            actor_role=user_row["role"],
            action="LOGIN_SUCCESS",
            details="Đăng nhập hệ thống quản trị thành công",
            ip_address=client_ip
        )

    response.set_cookie(
        key="admin_session",
        value=raw_session,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        max_age=14400,
        path="/"
    )
    return {
        "message": "Đăng nhập thành công!",
        "username": user_row["username"],
        "role": user_row["role"]
    }

@app.post("/api/admin/logout", dependencies=[Depends(verify_csrf)])
async def admin_logout(request: Request, response: Response):
    raw_session = request.cookies.get("admin_session")
    if raw_session:
        with get_db() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE session_hash = ?", (hash_token(raw_session),))
    response.delete_cookie("admin_session", path="/")
    return {"message": "Đã đăng xuất."}

# =====================================================================
# PHẦN 3: DUYỆT / TỪ CHỐI / XOÁ CONFESSION
# =====================================================================
@app.get("/api/admin/confessions")
async def admin_list_confessions(
    admin_user: dict = Depends(require_admin),
    status_filter: Literal["all", "pending", "approved", "rejected"] = Query(default="all"),
    q: str = Query(default="", max_length=100),
    page: int = Query(default=1, ge=1, le=1000),
    page_size: int = Query(default=10, ge=1, le=50)
):
    offset = (page - 1) * page_size
    conditions = []
    params: list = []

    if status_filter != "all":
        conditions.append("status = ?")
        params.append(status_filter)

    if q.strip():
        conditions.append("(title LIKE ? OR content LIKE ?)")
        kw = f"%{q.strip()}%"
        params.extend([kw, kw])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_db() as conn:
        total_row = conn.execute(
            f"SELECT COUNT(*) AS cnt FROM confessions {where_clause}",
            tuple(params)
        ).fetchone()

        rows = conn.execute(
            f"""
            SELECT id, category, title, content, status, created_at
            FROM confessions
            {where_clause}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [page_size, offset])
        ).fetchall()

    return {
        "items": [dict(r) for r in rows],
        "total": total_row["cnt"],
        "page": page,
        "page_size": page_size
    }

@app.patch("/api/admin/confessions/{confession_id}", dependencies=[Depends(verify_csrf)])
async def admin_update_confession(
    confession_id: int,
    payload: AdminStatusUpdatePayload,
    request: Request,
    admin_user: dict = Depends(require_admin)
):
    client_ip = get_client_ip(request)
    action_name = "APPROVE_CONFESSION" if payload.status == "approved" else "REJECT_CONFESSION"
    action_vn = "Duyệt đăng" if payload.status == "approved" else "Từ chối"

    with get_db() as conn:
        cursor = conn.execute(
            "UPDATE confessions SET status = ? WHERE id = ?",
            (payload.status, confession_id)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy Confession.")

        log_admin_activity(
            conn,
            actor_username=admin_user["username"],
            actor_role=admin_user["role"],
            action=action_name,
            details=f"{action_vn} Confession #{confession_id}",
            ip_address=client_ip
        )

    return {"message": f"Đã {action_vn.lower()} Confession #{confession_id}."}

@app.delete("/api/admin/confessions/{confession_id}", dependencies=[Depends(verify_csrf)])
async def admin_delete_confession(
    confession_id: int,
    request: Request,
    admin_user: dict = Depends(require_admin)
):
    client_ip = get_client_ip(request)
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM confessions WHERE id = ?", (confession_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy Confession.")

        log_admin_activity(
            conn,
            actor_username=admin_user["username"],
            actor_role=admin_user["role"],
            action="DELETE_CONFESSION",
            details=f"Xoá vĩnh viễn Confession #{confession_id}",
            ip_address=client_ip
        )

    return {"message": f"Đã xoá vĩnh viễn Confession #{confession_id}."}

# =====================================================================
# PHẦN 4: QUẢN LÝ ADMIN & LOG HOẠT ĐỘNG (CHỈ OWNER)
# =====================================================================
@app.get("/api/admin/users")
async def owner_list_users(owner: dict = Depends(require_owner)):
    with get_db() as conn:
        users = conn.execute(
            """
            SELECT id, username, role, is_locked, created_at, last_login_at
            FROM admin_users
            ORDER BY role DESC, id ASC
            """
        ).fetchall()
    return {"users": [dict(u) for u in users]}

@app.post("/api/admin/users", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
async def owner_create_sub_admin(
    payload: CreateSubAdminPayload,
    request: Request,
    owner: dict = Depends(require_owner)
):
    username_clean = payload.username.strip()
    now = int(time.time())
    client_ip = get_client_ip(request)

    with get_db() as conn:
        existing = conn.execute(
            "SELECT id FROM admin_users WHERE LOWER(username) = LOWER(?)",
            (username_clean,)
        ).fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tên tài khoản này đã tồn tại. Vui lòng chọn tên khác."
            )

        pw_hash = hash_password(payload.password)
        conn.execute(
            """
            INSERT INTO admin_users (username, password_hash, role, is_locked, created_at)
            VALUES (?, ?, 'moderator', 0, ?)
            """,
            (username_clean, pw_hash, now)
        )
        log_admin_activity(
            conn,
            actor_username=owner["username"],
            actor_role=owner["role"],
            action="GRANT_ADMIN",
            details=f"Cấp quyền Admin duyệt bài cho tài khoản '{username_clean}'",
            ip_address=client_ip
        )

    return {"message": f"Đã tạo và cấp quyền Admin cho tài khoản '{username_clean}' thành công!"}

@app.patch("/api/admin/users/{target_user_id}/password", dependencies=[Depends(verify_csrf)])
async def owner_reset_sub_admin_password(
    target_user_id: int,
    payload: ResetSubAdminPasswordPayload,
    request: Request,
    owner: dict = Depends(require_owner)
):
    client_ip = get_client_ip(request)
    with get_db() as conn:
        target = conn.execute("SELECT id, username, role FROM admin_users WHERE id = ?", (target_user_id,)).fetchone()
        if not target or target["role"] == "owner":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Không thể thao tác trên tài khoản này.")

        conn.execute(
            "UPDATE admin_users SET password_hash = ? WHERE id = ?",
            (hash_password(payload.new_password), target_user_id)
        )
        conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (target_user_id,))
        log_admin_activity(
            conn,
            actor_username=owner["username"],
            actor_role=owner["role"],
            action="RESET_ADMIN_PASSWORD",
            details=f"Đặt lại mật khẩu cho Admin '{target['username']}'",
            ip_address=client_ip
        )

    return {"message": f"Đã đổi mật khẩu cho Admin '{target['username']}'."}

@app.patch("/api/admin/users/{target_user_id}/lock", dependencies=[Depends(verify_csrf)])
async def owner_toggle_lock_user(
    target_user_id: int,
    payload: LockUserPayload,
    request: Request,
    owner: dict = Depends(require_owner)
):
    client_ip = get_client_ip(request)
    with get_db() as conn:
        target = conn.execute("SELECT id, username, role FROM admin_users WHERE id = ?", (target_user_id,)).fetchone()
        if not target or target["role"] == "owner":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Không thể khoá tài khoản Quản trị tối cao.")

        lock_val = 1 if payload.is_locked else 0
        conn.execute("UPDATE admin_users SET is_locked = ? WHERE id = ?", (lock_val, target_user_id))
        if lock_val == 1:
            conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (target_user_id,))

        action_str = "LOCK_ADMIN" if lock_val == 1 else "UNLOCK_ADMIN"
        desc = f"{'Tước quyền tạm thời (Khoá)' if lock_val == 1 else 'Mở khoá quyền'} Admin '{target['username']}'"
        log_admin_activity(conn, owner["username"], owner["role"], action_str, desc, client_ip)

    return {"message": f"Đã {'khoá' if payload.is_locked else 'mở khoá'} tài khoản '{target['username']}'."}

@app.delete("/api/admin/users/{target_user_id}", dependencies=[Depends(verify_csrf)])
async def owner_delete_user(
    target_user_id: int,
    request: Request,
    owner: dict = Depends(require_owner)
):
    client_ip = get_client_ip(request)
    with get_db() as conn:
        target = conn.execute("SELECT id, username, role FROM admin_users WHERE id = ?", (target_user_id,)).fetchone()
        if not target or target["role"] == "owner":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Không thể xoá tài khoản Quản trị tối cao.")

        conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (target_user_id,))
        conn.execute("DELETE FROM admin_users WHERE id = ?", (target_user_id,))

        log_admin_activity(
            conn,
            actor_username=owner["username"],
            actor_role=owner["role"],
            action="REVOKE_ADMIN",
            details=f"Thu hồi quyền và xoá vĩnh viễn Admin '{target['username']}'",
            ip_address=client_ip
        )

    return {"message": f"Đã thu hồi quyền và xoá tài khoản '{target['username']}'."}

@app.get("/api/admin/logs")
async def owner_list_activity_logs(
    owner: dict = Depends(require_owner),
    page: int = Query(default=1, ge=1, le=1000),
    page_size: int = Query(default=20, ge=1, le=50)
):
    offset = (page - 1) * page_size
    with get_db() as conn:
        total_row = conn.execute("SELECT COUNT(*) AS cnt FROM activity_logs").fetchone()
        rows = conn.execute(
            """
            SELECT id, actor_username, actor_role, action, details, ip_address, created_at
            FROM activity_logs
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (page_size, offset)
        ).fetchall()

    return {
        "items": [dict(r) for r in rows],
        "total": total_row["cnt"],
        "page": page,
        "page_size": page_size
    }
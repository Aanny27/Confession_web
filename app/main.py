import mimetypes
import secrets
import time
from pathlib import Path
from typing import Literal
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.config import settings
from app.database import cleanup_expired_records, get_db, init_db
from app.notifications import notify_admin_new_confession, verify_turnstile_token
from app.security import (
    DUMMY_ARGON2_HASH,
    check_and_record_daily_limit,
    create_csrf_pair,
    get_client_ip,
    hash_password,
    hash_token,
    log_admin_activity,
    logger,
    require_admin,
    require_owner,
    seed_initial_owner,
    verify_csrf,
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
class ConfessionSubmitPayload(BaseModel):
    content: str = Field(..., min_length=20, max_length=3000)
    website_url: str = Field(default="", max_length=200)  # Ô ẩn Honeypot chống robot
    turnstile_token: str = Field(default="", max_length=2048)

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
async def get_csrf_token(request: Request, response: Response):
    cleanup_expired_records()
    raw_token, cookie_val = create_csrf_pair()
    response.set_cookie(
        key="csrf_cookie",
        value=cookie_val,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        max_age=86400,
        path="/"
    )
    # Gắn mã định danh thiết bị ẩn danh để đếm giới hạn 5 bài/ngày chính xác hơn
    if not request.cookies.get("anon_device_id"):
        response.set_cookie(
            key="anon_device_id",
            value=secrets.token_urlsafe(24),
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite="strict",
            max_age=86400 * 30,
            path="/"
        )
    return {"csrf_token": raw_token}

# =====================================================================
# PHẦN 1: API GỬI CONFESSION TRỰC TIẾP (TỐI ĐA 5 BÀI / NGÀY)
# =====================================================================
@app.post("/api/confessions", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
async def submit_confession(
    payload: ConfessionSubmitPayload,
    request: Request,
    background_tasks: BackgroundTasks
):
    client_ip = get_client_ip(request)

    # Chống robot bằng ô ẩn Honeypot
    if payload.website_url.strip() != "":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Yêu cầu không hợp lệ.")

    if not verify_turnstile_token(payload.turnstile_token, client_ip):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Xác thực chống robot không thành công.")

    cleaned_content = payload.content.strip()
    if len(cleaned_content) < 20 or len(cleaned_content) > 3000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nội dung câu chuyện phải từ 20 đến 3000 ký tự."
        )

    device_token = request.cookies.get("anon_device_id") or client_ip

    # Kiểm tra giới hạn tối đa 5 bài / 1 ngày (24 giờ)
    remaining_today = check_and_record_daily_limit(client_ip, device_token)

    now = int(time.time())
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO confessions (content, status, created_at) VALUES (?, 'pending', ?)",
            (cleaned_content, now)
        )
        confession_id = cursor.lastrowid

    background_tasks.add_task(notify_admin_new_confession, confession_id)
    logger.info(f"Đã nhận Confession mới #{confession_id} (ẩn danh hoàn toàn)")
    return {
        "message": "Confession đang chờ duyệt",
        "id": confession_id,
        "remaining_today": remaining_today
    }

@app.get("/api/confessions/public")
async def list_public_confessions(
    page: int = Query(default=1, ge=1, le=1000),
    page_size: int = Query(default=10, ge=1, le=50)
):
    offset = (page - 1) * page_size
    with get_db() as conn:
        total_row = conn.execute("SELECT COUNT(*) AS cnt FROM confessions WHERE status = 'approved'").fetchone()
        rows = conn.execute(
            "SELECT id, content, created_at FROM confessions WHERE status = 'approved' ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (page_size, offset)
        ).fetchall()

    return {
        "items": [dict(r) for r in rows],
        "total": total_row["cnt"],
        "page": page,
        "page_size": page_size
    }

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
        conditions.append("content LIKE ?")
        params.append(f"%{q.strip()}%")

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_db() as conn:
        total_row = conn.execute(
            f"SELECT COUNT(*) AS cnt FROM confessions {where_clause}",
            tuple(params)
        ).fetchone()

        rows = conn.execute(
            f"""
            SELECT id, content, status, created_at
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
# PHẦN 4: QUYỀN TỐI CAO CỦA BẠN (CẤP QUYỀN ADMIN, ĐỔI MK, KHOÁ, XOÁ, XEM LOG)
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
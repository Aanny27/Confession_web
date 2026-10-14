import smtplib
from email.message import EmailMessage
from urllib.parse import urlparse
import httpx
from app.config import settings
from app.security import logger

def send_otp_email(recipient_email: str, otp_code: str) -> None:
    """
    Gửi mã xác nhận 6 số qua SMTP.
    Nếu chưa cấu hình SMTP_USER trong .env (chế độ thử nghiệm nội bộ), in mã OTP ra màn hình console.
    """
    if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        print(f"\n[CHẾ ĐỘ THỬ NGHIỆM - CHƯA CẤU HÌNH SMTP] Mã OTP vừa sinh là: {otp_code}\n")
        return

    msg = EmailMessage()
    msg["Subject"] = f"[{otp_code}] Mã xác nhận gửi Confession ẩn danh"
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_USER}>"
    msg["To"] = recipient_email
    msg.set_content(
        f"Xin chào,\n\n"
        f"Mã xác nhận để gửi Confession của bạn là: {otp_code}\n\n"
        f"Mã này có hiệu lực trong vòng 10 phút và chỉ sử dụng được một lần.\n"
        f"Lưu ý: Địa chỉ email của bạn được băm một chiều (ẩn danh hoàn toàn) và không ai biết bạn là người gửi.\n\n"
        f"Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email."
    )

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.send_message(msg)

def verify_turnstile_token(token: str, client_ip: str) -> bool:
    """
    [OWASP A04:2021 - Insecure Design] & [OWASP A10:2021 - SSRF]
    Kiểm tra Cloudflare Turnstile chống bot (nếu bật).
    Chỉ gọi tới địa chỉ cố định của Cloudflare, không nhận URL từ người dùng.
    """
    if not settings.TURNSTILE_SECRET_KEY:
        return True
    if not token:
        return False

    try:
        resp = httpx.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": settings.TURNSTILE_SECRET_KEY,
                "response": token,
                "remoteip": client_ip
            },
            timeout=5.0
        )
        data = resp.json()
        return bool(data.get("success", False))
    except Exception as exc:
        logger.error(f"Lỗi kết nối Cloudflare Turnstile: {type(exc).__name__}")
        return False

def notify_admin_new_confession(confession_id: int) -> None:
    """
    [OWASP A10:2021 - Server-Side Request Forgery (SSRF)]
    Chỉ gửi thông báo đến Webhook cố định đọc từ biến môi trường (.env) và kiểm tra tên miền hợp lệ.
    Tuyệt đối không cho phép người dùng truyền URL vào yêu cầu.
    [OWASP A09:2021] Không gửi nội dung bài viết qua kênh bên thứ 3 nếu không cần thiết để giữ kín đáo.
    """
    notification_text = f"📬 Có Confession mới (#{confession_id}) đang chờ duyệt trên hệ thống!"

    # 1. Gửi qua Discord Webhook
    if settings.DISCORD_WEBHOOK_URL:
        parsed = urlparse(settings.DISCORD_WEBHOOK_URL)
        if parsed.scheme == "https" and parsed.netloc in ("discord.com", "discordapp.com"):
            try:
                httpx.post(
                    settings.DISCORD_WEBHOOK_URL,
                    json={"content": notification_text},
                    timeout=5.0
                )
            except Exception as exc:
                logger.error(f"Lỗi gửi thông báo Discord: {type(exc).__name__}")

    # 2. Gửi qua Telegram Bot
    if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
        tg_url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
        try:
            httpx.post(
                tg_url,
                json={"chat_id": settings.TELEGRAM_CHAT_ID, "text": notification_text},
                timeout=5.0
            )
        except Exception as exc:
            logger.error(f"Lỗi gửi thông báo Telegram: {type(exc).__name__}")
import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # [OWASP A02:2021 - Cryptographic Failures] Đọc cấu hình nhạy cảm từ biến môi trường
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    EMAIL_HASH_SALT: str = os.getenv("EMAIL_HASH_SALT", "")

    # Thông tin khởi tạo tài khoản Chủ ở lần chạy đầu tiên
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "").strip()
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "")
    TOTP_ISSUER_NAME: str = os.getenv("TOTP_ISSUER_NAME", "Confession Ẩn Danh").strip()

    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_NAME: str = os.getenv("SMTP_FROM_NAME", "Confession Ẩn Danh")

    TRUST_PROXY: bool = os.getenv("TRUST_PROXY", "false").lower() == "true"
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"

    TURNSTILE_SECRET_KEY: str = os.getenv("TURNSTILE_SECRET_KEY", "").strip()

    # Cấu hình nhóm nhận thông báo bài mới của ban quản lý
    DISCORD_WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "").strip()

    DB_PATH: str = os.getenv("DB_PATH", "confessions.db")

    def validate(self) -> None:
        if len(self.SECRET_KEY) < 32 or len(self.EMAIL_HASH_SALT) < 16:
            raise RuntimeError(
                "Cấu hình lỗi: SECRET_KEY (tối thiểu 32 ký tự) và EMAIL_HASH_SALT (tối thiểu 16 ký tự) phải được thiết lập trong tệp .env"
            )

settings = Settings()
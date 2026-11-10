import logging
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent
TEMPLATE_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"
UPDATE_SCRIPT = PROJECT_DIR / "update.sh"

load_dotenv(PROJECT_DIR / ".env")
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("webssh")


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        return max(minimum, int(value))
    except ValueError:
        logger.warning("Ignoring invalid integer for %s: %r", name, value)
        return default


SESSION_SECRET = os.environ.get("WEBSSH_SESSION_SECRET") or ""
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(32)
    logger.warning("WEBSSH_SESSION_SECRET is unset; sessions will not survive application restarts")

COOKIE_SECURE = _env_bool("WEBSSH_COOKIE_SECURE", True)
SESSION_IDLE_SECONDS = _env_int("WEBSSH_SESSION_IDLE_MINUTES", 30) * 60
TERMINAL_GRACE_SECONDS = _env_int("WEBSSH_TERMINAL_GRACE_SECONDS", 300, minimum=0)
MAX_TERMINALS = _env_int("WEBSSH_MAX_TERMINALS", 8)
MAX_UPLOAD_BYTES = _env_int("WEBSSH_MAX_UPLOAD_MB", 100) * 1024 * 1024
ALLOW_UPDATE = _env_bool("WEBSSH_ALLOW_UPDATE", True)

LOGIN_FREE_ATTEMPTS = _env_int("WEBSSH_LOGIN_FREE_ATTEMPTS", 3)
LOGIN_MAX_LOCKOUT_SECONDS = _env_int("WEBSSH_LOGIN_MAX_LOCKOUT_SECONDS", 15 * 60)
AUDIT_LOG_FILE = os.environ.get("WEBSSH_AUDIT_LOG", "").strip()

# Popped so the credentials are not inherited by shells or git subprocesses.
OTP_SENDER_EMAIL = os.environ.pop("SENDER_EMAIL", "").strip()
# Gmail displays app passwords in groups of four separated by spaces.
OTP_SMTP_PASSWORD = os.environ.pop("PASSWORD", "").replace(" ", "")
OTP_RECEIVER_EMAIL = os.environ.pop("RECEIVER_EMAIL", "").strip()
OTP_SMTP_HOST = os.environ.get("WEBSSH_SMTP_HOST", "smtp.gmail.com")
OTP_SMTP_PORT = _env_int("WEBSSH_SMTP_PORT", 587)
OTP_TTL_SECONDS = _env_int("WEBSSH_OTP_TTL_MINUTES", 5) * 60

_otp_settings = (OTP_SENDER_EMAIL, OTP_SMTP_PASSWORD, OTP_RECEIVER_EMAIL)
OTP_ENABLED = all(_otp_settings)
if any(_otp_settings) and not OTP_ENABLED:
    raise RuntimeError("Email sign-in codes need SENDER_EMAIL, PASSWORD and RECEIVER_EMAIL all set")
if not OTP_ENABLED:
    logger.warning("Email sign-in codes are disabled; set SENDER_EMAIL, PASSWORD and RECEIVER_EMAIL to enable them")

IO_CHUNK_BYTES = 1024 * 1024

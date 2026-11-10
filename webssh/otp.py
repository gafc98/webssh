import hmac
import secrets
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage

from fastapi import HTTPException

from .config import (
    OTP_RECEIVER_EMAIL,
    OTP_SENDER_EMAIL,
    OTP_SMTP_HOST,
    OTP_SMTP_PASSWORD,
    OTP_SMTP_PORT,
    OTP_TTL_SECONDS,
)


OTP_MAX_ATTEMPTS = 5


@dataclass
class PendingLogin:
    username: str
    home: str
    shell: str
    code: str = field(default_factory=lambda: f"{secrets.randbelow(10**6):06d}")
    expires: float = field(default_factory=lambda: time.monotonic() + OTP_TTL_SECONDS)
    attempts: int = 0


pending_logins: dict[str, PendingLogin] = {}


def create_pending(username: str, home: str, shell: str) -> tuple[str, PendingLogin]:
    token = secrets.token_urlsafe(32)
    pending = PendingLogin(username=username, home=home, shell=shell)
    pending_logins[token] = pending
    return token, pending


def discard_pending(token: object) -> None:
    if isinstance(token, str):
        pending_logins.pop(token, None)


def verify_code(token: object, code: str) -> PendingLogin:
    pending = pending_logins.get(token) if isinstance(token, str) else None
    if pending is None or time.monotonic() > pending.expires:
        discard_pending(token)
        raise HTTPException(status_code=410, detail="The sign-in code expired. Sign in again.")
    if not hmac.compare_digest(pending.code.encode(), code.encode()):
        pending.attempts += 1
        if pending.attempts >= OTP_MAX_ATTEMPTS:
            discard_pending(token)
            raise HTTPException(status_code=410, detail="Too many incorrect codes. Sign in again.")
        raise HTTPException(status_code=401, detail="Incorrect sign-in code")
    discard_pending(token)
    return pending


def send_code(pending: PendingLogin, ip: str) -> None:
    minutes = OTP_TTL_SECONDS // 60
    sent_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    message = EmailMessage()
    message["Subject"] = f"WebSSH sign-in code: {pending.code}"
    message["From"] = OTP_SENDER_EMAIL
    message["To"] = OTP_RECEIVER_EMAIL
    message.set_content(
        f"Your WebSSH sign-in code is {pending.code}\n\n"
        f"It expires in {minutes} minutes.\n\n"
        f"Account: {pending.username}\nIP address: {ip}\nTime: {sent_at}\n\n"
        "If you did not just sign in, your Linux password is known to someone else. Change it now.\n"
    )
    context = ssl.create_default_context()
    if OTP_SMTP_PORT == 465:
        smtp = smtplib.SMTP_SSL(OTP_SMTP_HOST, OTP_SMTP_PORT, context=context, timeout=20)
    else:
        smtp = smtplib.SMTP(OTP_SMTP_HOST, OTP_SMTP_PORT, timeout=20)
    with smtp:
        if OTP_SMTP_PORT != 465:
            smtp.starttls(context=context)
        smtp.login(OTP_SENDER_EMAIL, OTP_SMTP_PASSWORD)
        smtp.send_message(message)


def prune() -> None:
    now = time.monotonic()
    for token in [token for token, pending in pending_logins.items() if now > pending.expires]:
        del pending_logins[token]

import hmac
import json
import logging
import math
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from fastapi import HTTPException, Request
from starlette.requests import HTTPConnection

from .config import AUDIT_LOG_FILE, LOGIN_FREE_ATTEMPTS, LOGIN_MAX_LOCKOUT_SECONDS


audit_logger = logging.getLogger("webssh.audit")
audit_logger.setLevel(logging.INFO)
if AUDIT_LOG_FILE:
    _handler = logging.FileHandler(AUDIT_LOG_FILE)
    _handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    audit_logger.addHandler(_handler)


def client_ip(connection: HTTPConnection) -> str:
    return connection.client.host if connection.client else "unknown"


def audit(connection: HTTPConnection, action: str, user: str | None = None, **details: Any) -> None:
    # repr() keeps user-controlled values (file names, usernames) on a single log line.
    extras = "".join(f" {key}={value!r}" for key, value in details.items())
    audit_logger.info("%s ip=%s user=%r%s", action, client_ip(connection), user, extras)


def verify_csrf(request: Request) -> None:
    expected = request.session.get("csrf_token")
    supplied = request.headers.get("x-csrf-token", "")
    if not isinstance(expected, str) or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Invalid request token")


async def read_json_object(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Expected a JSON request body") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON request body")
    return body


@dataclass
class _Attempts:
    failures: int = 0
    last_failure: float = 0.0
    locked_until: float = 0.0


class LoginThrottle:
    """Per-IP exponential lockout after repeated failed sign-ins."""

    def __init__(self) -> None:
        self._attempts: dict[str, _Attempts] = {}
        self._in_flight: set[str] = set()
        self._reset_after = max(3600, LOGIN_MAX_LOCKOUT_SECONDS)

    def retry_after(self, ip: str) -> int:
        state = self._attempts.get(ip)
        if state is None:
            return 0
        now = time.monotonic()
        if now - state.last_failure > self._reset_after:
            del self._attempts[ip]
            return 0
        return max(0, math.ceil(state.locked_until - now))

    @contextmanager
    def attempt(self, ip: str) -> Iterator[None]:
        wait = self.retry_after(ip)
        if wait:
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed sign-ins. Try again in {wait} seconds.",
                headers={"Retry-After": str(wait)},
            )
        if ip in self._in_flight:
            raise HTTPException(status_code=429, detail="A sign-in is already in progress")
        self._in_flight.add(ip)
        try:
            yield
        finally:
            self._in_flight.discard(ip)

    def record_failure(self, ip: str) -> None:
        now = time.monotonic()
        state = self._attempts.setdefault(ip, _Attempts())
        state.failures += 1
        state.last_failure = now
        excess = state.failures - LOGIN_FREE_ATTEMPTS
        if excess >= 0:
            state.locked_until = now + min(LOGIN_MAX_LOCKOUT_SECONDS, 5 * 2 ** min(excess, 16))

    def record_success(self, ip: str) -> None:
        self._attempts.pop(ip, None)

    def prune(self) -> None:
        now = time.monotonic()
        stale = [
            ip
            for ip, state in self._attempts.items()
            if now - state.last_failure > self._reset_after and now >= state.locked_until
        ]
        for ip in stale:
            del self._attempts[ip]


login_throttle = LoginThrottle()

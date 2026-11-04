import asyncio
import logging
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from ..security import audit, client_ip, login_throttle, read_json_object, verify_csrf
from ..sessions import end_session, require_local_session, start_session


logger = logging.getLogger("webssh.auth")
router = APIRouter()


def authenticate_local_user(username: str, password: str) -> tuple[str, str, str]:
    get_euid = getattr(os, "geteuid", None)
    if not callable(get_euid):
        raise HTTPException(status_code=503, detail="Local account login is supported on Linux only")
    effective_uid = get_euid()
    if effective_uid == 0:
        raise HTTPException(status_code=503, detail="Run WebSSH as a non-root account")

    try:
        import pam
        import pwd
    except ImportError as exc:
        logger.exception("Local PAM authentication dependencies are unavailable")
        raise HTTPException(status_code=503, detail="Install the WebSSH Linux authentication dependencies") from exc

    try:
        account = pwd.getpwnam(username)
        current_account = pwd.getpwuid(effective_uid)
    except KeyError as exc:
        raise HTTPException(status_code=401, detail="Local login was rejected") from exc

    if account.pw_uid != current_account.pw_uid:
        raise HTTPException(status_code=403, detail=f"Run WebSSH as {username} to access that account")
    if not account.pw_shell or account.pw_shell.endswith(("/nologin", "/false")):
        raise HTTPException(status_code=403, detail="This account does not have an interactive shell")

    try:
        authenticated = pam.pam().authenticate(username, password, service="login")
    except Exception as exc:
        logger.exception("PAM authentication failed unexpectedly")
        raise HTTPException(status_code=503, detail="Local account authentication failed") from exc
    if not authenticated:
        raise HTTPException(status_code=401, detail="Local login was rejected")

    return account.pw_name, account.pw_dir, account.pw_shell


@router.get("/api/session")
async def session_info(request: Request) -> dict[str, str]:
    local = require_local_session(request)
    return {"username": local.username, "home": local.home}


@router.post("/api/login")
async def login(request: Request) -> JSONResponse:
    verify_csrf(request)
    body = await read_json_object(request)
    username = body.get("username")
    password = body.get("password")
    if (
        not isinstance(username, str)
        or not username.strip()
        or len(username) > 256
        or not isinstance(password, str)
        or not password
        or len(password) > 4096
    ):
        raise HTTPException(status_code=400, detail="Enter a valid username and password")
    username = username.strip()

    ip = client_ip(request)
    with login_throttle.attempt(ip):
        try:
            account_name, home, shell = await asyncio.to_thread(authenticate_local_user, username, password)
        except HTTPException as exc:
            if exc.status_code in {401, 403}:
                login_throttle.record_failure(ip)
                audit(request, "login.failed", username, reason=exc.detail)
            raise
    login_throttle.record_success(ip)

    await end_session(request.session.get("session_id"))
    request.session["session_id"] = start_session(account_name, home, shell)
    audit(request, "login", account_name)
    return JSONResponse({"username": account_name, "home": home})


@router.post("/api/logout")
async def logout(request: Request) -> JSONResponse:
    verify_csrf(request)
    local = await end_session(request.session.pop("session_id", None))
    if local is not None:
        audit(request, "logout", local.username)
    return JSONResponse({"ok": True})

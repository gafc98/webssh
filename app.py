import asyncio
import errno
import hmac
import json
import logging
import mimetypes
import os
import posixpath
import secrets
import stat
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncGenerator, AsyncIterator
from urllib.parse import quote, urlsplit

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware


load_dotenv()
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("webssh")

SESSION_SECRET = os.environ.get("WEBSSH_SESSION_SECRET")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(32)
    logger.warning("WEBSSH_SESSION_SECRET is unset; sessions will not survive application restarts")

COOKIE_SECURE = os.environ.get("WEBSSH_COOKIE_SECURE", "1").lower() not in {"0", "false", "no"}
SESSION_IDLE_SECONDS = 30 * 60
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


@dataclass
class LocalSession:
    username: str
    home: str
    last_activity: float
    terminal: Any | None = None
    terminal_active: bool = False


local_sessions: dict[str, LocalSession] = {}


def close_terminal(session: LocalSession) -> None:
    process = session.terminal
    session.terminal = None
    if process is not None and not process.closed:
        process.close(force=True)


async def expire_idle_sessions() -> None:
    while True:
        await asyncio.sleep(60)
        now = time.monotonic()
        expired = [
            session_id
            for session_id, local in local_sessions.items()
            if now - local.last_activity >= SESSION_IDLE_SECONDS
        ]
        for session_id in expired:
            local = local_sessions.pop(session_id, None)
            if local is not None:
                close_terminal(local)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    cleanup_task = asyncio.create_task(expire_idle_sessions())
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        sessions = list(local_sessions.values())
        local_sessions.clear()
        for session in sessions:
            close_terminal(session)


app = FastAPI(title="WebSSH", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="webssh_session",
    max_age=12 * 60 * 60,
    same_site="lax",
    https_only=COOKIE_SECURE,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Any:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


def normalize_local_path(path: str) -> str:
    if "\x00" in path or len(path) > 4096 or not path.startswith("/"):
        raise HTTPException(status_code=400, detail="A valid absolute path is required")
    return "/" + posixpath.normpath(path).lstrip("/")


def get_local_session(request: Request) -> LocalSession:
    session_id = request.session.get("session_id")
    local = local_sessions.get(session_id) if isinstance(session_id, str) else None
    if local is None:
        raise HTTPException(status_code=401, detail="Please sign in again")
    local.last_activity = time.monotonic()
    return local


def verify_csrf(request: Request) -> None:
    expected = request.session.get("csrf_token")
    supplied = request.headers.get("x-csrf-token", "")
    if not isinstance(expected, str) or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Invalid request token")


def local_file_error(exc: OSError) -> HTTPException:
    logger.info("Local file operation failed: %s", exc)
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail="The requested file or directory was not found")
    if isinstance(exc, PermissionError):
        return HTTPException(status_code=403, detail="Permission denied")
    return HTTPException(status_code=500, detail="The local file operation failed")


def authenticate_local_user(username: str, password: str) -> tuple[str, str, str]:
    get_euid = getattr(os, "geteuid", None)
    if not callable(get_euid):
        raise HTTPException(status_code=503, detail="Local account login is supported on Linux only")
    effective_uid = get_euid()
    if effective_uid == 0:
        raise HTTPException(status_code=503, detail="Run WebSSH as a non-root account")

    try:
        import pwd
        import pam
    except ImportError as exc:
        logger.exception("Local PAM authentication dependencies are unavailable")
        raise HTTPException(status_code=503, detail="Install the WebSSH Linux authentication dependencies") from exc

    try:
        account = pwd.getpwnam(username)
        current_account = pwd.getpwuid(effective_uid)
    except KeyError as exc:
        raise HTTPException(status_code=401, detail="Local login was rejected") from exc

    if account.pw_uid != current_account.pw_uid:
        raise HTTPException(
            status_code=403,
            detail=f"Run WebSSH as {username} to access that account",
        )
    if not account.pw_shell or account.pw_shell.endswith("/nologin") or account.pw_shell.endswith("/false"):
        raise HTTPException(status_code=403, detail="This account does not have an interactive shell")

    try:
        authenticated = pam.pam().authenticate(username, password, service="login")
    except Exception as exc:
        logger.exception("PAM authentication failed unexpectedly")
        raise HTTPException(status_code=503, detail="Local account authentication failed") from exc
    if not authenticated:
        raise HTTPException(status_code=401, detail="Local login was rejected")

    return account.pw_name, account.pw_dir, account.pw_shell


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    csrf_token = request.session.get("csrf_token")
    if not isinstance(csrf_token, str):
        csrf_token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = csrf_token
    nonce = secrets.token_urlsafe(18)
    html = PAGE.replace("__CSRF_TOKEN__", csrf_token).replace("__NONCE__", nonce)
    response = HTMLResponse(html)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' https://cdn.jsdelivr.net 'nonce-{nonce}'; "
        f"style-src 'self' https://cdn.jsdelivr.net 'nonce-{nonce}'; "
        "style-src-attr 'unsafe-inline'; "
        "font-src 'self' https://cdn.jsdelivr.net data:; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/api/session")
async def session_info(request: Request) -> dict[str, str]:
    local = get_local_session(request)
    return {"username": local.username, "home": local.home}


@app.post("/api/login")
async def login(request: Request) -> JSONResponse:
    verify_csrf(request)
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Expected a JSON login request") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON login request")
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

    authenticated_username, home, _ = await asyncio.to_thread(
        authenticate_local_user,
        username.strip(),
        password,
    )
    old_session_id = request.session.get("session_id")
    if isinstance(old_session_id, str):
        old_local = local_sessions.pop(old_session_id, None)
        if old_local is not None:
            close_terminal(old_local)

    session_id = secrets.token_urlsafe(32)
    local_sessions[session_id] = LocalSession(
        username=authenticated_username,
        home=home,
        last_activity=time.monotonic(),
    )
    request.session["session_id"] = session_id
    return JSONResponse({"username": authenticated_username, "home": home})


@app.post("/api/logout")
async def logout(request: Request) -> JSONResponse:
    verify_csrf(request)
    session_id = request.session.pop("session_id", None)
    if isinstance(session_id, str):
        local = local_sessions.pop(session_id, None)
        if local is not None:
            close_terminal(local)
    return JSONResponse({"ok": True})


@app.get("/api/files")
async def list_files(request: Request, path: str = "/") -> dict[str, Any]:
    get_local_session(request)
    directory = normalize_local_path(path)
    try:
        entries = await asyncio.to_thread(lambda: list(os.scandir(directory)))
    except OSError as exc:
        logger.exception("Unable to list local directory %s", directory)
        raise local_file_error(exc) from exc

    files = []
    for entry in entries:
        name = entry.name
        if not name or name in {".", ".."}:
            continue
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            logger.info("Unable to inspect local file %s: %s", entry.path, exc)
            continue
        mode = metadata.st_mode
        if stat.S_ISDIR(mode):
            kind = "directory"
        elif stat.S_ISLNK(mode):
            kind = "link"
        elif stat.S_ISREG(mode):
            kind = "file"
        else:
            kind = "other"
        files.append(
            {
                "name": name,
                "path": posixpath.join(directory, name),
                "type": kind,
                "size": metadata.st_size,
                "modified": metadata.st_mtime,
            }
        )
    files.sort(key=lambda item: (item["type"] != "directory", item["name"].casefold()))
    return {"path": directory, "entries": files}


@app.get("/api/download")
async def download_file(request: Request, path: str) -> StreamingResponse:
    local = get_local_session(request)
    local_path = normalize_local_path(path)
    try:
        metadata = await asyncio.to_thread(os.stat, local_path)
        if not stat.S_ISREG(metadata.st_mode):
            raise HTTPException(status_code=400, detail="Only regular files can be downloaded")
        local_file = await asyncio.to_thread(open, local_path, "rb")
    except OSError as exc:
        raise local_file_error(exc) from exc

    async def stream_file() -> AsyncIterator[bytes]:
        try:
            try:
                while True:
                    chunk = await asyncio.to_thread(local_file.read, 64 * 1024)
                    if not chunk:
                        break
                    local.last_activity = time.monotonic()
                    yield chunk
            finally:
                await asyncio.to_thread(local_file.close)
        except OSError as exc:
            logger.exception("Local download failed during transfer")
            raise local_file_error(exc) from exc

    filename = posixpath.basename(local_path) or "download"
    media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return StreamingResponse(
        stream_file(),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"},
    )


@app.post("/api/upload")
async def upload_file(
    request: Request,
    path: str,
    file: UploadFile = File(...),
) -> dict[str, str]:
    verify_csrf(request)
    local = get_local_session(request)
    directory = normalize_local_path(path)
    raw_name = (file.filename or "").replace("\\", "/")
    filename = posixpath.basename(raw_name)
    if not filename or filename in {".", ".."} or "\x00" in filename:
        raise HTTPException(status_code=400, detail="Choose a valid file name")

    destination = Path(directory) / filename
    temporary_path = Path(directory) / f".webssh-upload-{secrets.token_hex(16)}"
    total_bytes = 0
    try:
        target = await asyncio.to_thread(open, temporary_path, "xb")
        try:
            while chunk := await file.read(64 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="File exceeds the 100 MB upload limit")
                await asyncio.to_thread(target.write, chunk)
            await asyncio.to_thread(target.close)
        except BaseException:
            await asyncio.to_thread(target.close)
            raise
        await asyncio.to_thread(os.replace, temporary_path, destination)
    except HTTPException:
        try:
            await asyncio.to_thread(temporary_path.unlink, missing_ok=True)
        except OSError:
            logger.exception("Unable to remove a partial local upload")
        raise
    except OSError as exc:
        try:
            await asyncio.to_thread(temporary_path.unlink, missing_ok=True)
        except OSError:
            logger.exception("Unable to remove a partial local upload")
        raise local_file_error(exc) from exc
    finally:
        await file.close()

    local.last_activity = time.monotonic()
    return {"name": filename, "path": str(destination)}


@app.websocket("/ws/terminal")
async def terminal(websocket: WebSocket) -> None:
    origin = websocket.headers.get("origin", "")
    host = websocket.headers.get("host", "")
    if not origin or urlsplit(origin).netloc.casefold() != host.casefold():
        await websocket.close(code=4403)
        return

    session_id = websocket.session.get("session_id")
    local = local_sessions.get(session_id) if isinstance(session_id, str) else None
    if local is None:
        await websocket.close(code=4401)
        return
    if local.terminal_active:
        await websocket.close(code=4409)
        return

    local.terminal_active = True
    process: Any | None = None
    loop = asyncio.get_running_loop()
    output_queue: asyncio.Queue[bytes | None | Exception] = asyncio.Queue(maxsize=64)
    master_fd: int | None = None
    output_task: asyncio.Task[bytes | None | Exception] | None = None
    input_task: asyncio.Task[str] | None = None
    output_paused = False

    def read_terminal() -> None:
        nonlocal output_paused
        assert master_fd is not None
        if output_queue.full():
            loop.remove_reader(master_fd)
            output_paused = True
            return
        try:
            output_queue.put_nowait(os.read(master_fd, 4096))
        except BlockingIOError:
            return
        except OSError as exc:
            if exc.errno == errno.EIO:
                output_queue.put_nowait(None)
            else:
                output_queue.put_nowait(exc)

    try:
        await websocket.accept()
        try:
            import pwd
            from ptyprocess import PtyProcess
        except ImportError as exc:
            raise HTTPException(status_code=503, detail="A Linux pseudo-terminal is required") from exc
        account = await asyncio.to_thread(pwd.getpwnam, local.username)
        environment = os.environ.copy()
        environment.update(
            HOME=local.home,
            LOGNAME=local.username,
            SHELL=account.pw_shell,
            TERM="xterm-256color",
            USER=local.username,
        )
        process = PtyProcess.spawn(
            [account.pw_shell, "-l"],
            cwd=local.home,
            env=environment,
            dimensions=(32, 120),
        )
        local.terminal = process
        master_fd = process.fd
        os.set_blocking(master_fd, False)
        loop.add_reader(master_fd, read_terminal)

        output_task = asyncio.create_task(output_queue.get())
        input_task = asyncio.create_task(websocket.receive_text())
        while True:
            assert output_task is not None
            assert input_task is not None
            done, _ = await asyncio.wait(
                (output_task, input_task), return_when=asyncio.FIRST_COMPLETED
            )

            if output_task in done:
                output = output_task.result()
                if isinstance(output, Exception):
                    raise output
                if output is None or output == b"":
                    await websocket.close(code=1000)
                    break
                if output_paused and master_fd is not None:
                    output_paused = False
                    loop.add_reader(master_fd, read_terminal)
                local.last_activity = time.monotonic()
                await websocket.send_json({"type": "output", "data": output.decode("utf-8", errors="replace")})
                output_task = asyncio.create_task(output_queue.get())

            if input_task in done:
                message = json.loads(input_task.result())
                input_task = asyncio.create_task(websocket.receive_text())
                if not isinstance(message, dict):
                    continue
                if message.get("type") == "input" and isinstance(message.get("data"), str):
                    data = message["data"].encode("utf-8")
                    if len(data) > 65536:
                        await websocket.close(code=1009)
                        break
                    await asyncio.to_thread(process.write, data)
                    local.last_activity = time.monotonic()
                elif message.get("type") == "resize":
                    cols = message.get("cols")
                    rows = message.get("rows")
                    if (
                        isinstance(cols, int)
                        and isinstance(rows, int)
                        and not isinstance(cols, bool)
                        and not isinstance(rows, bool)
                    ):
                        process.setwinsize(
                            max(5, min(rows, 200)),
                            max(20, min(cols, 400)),
                        )
    except WebSocketDisconnect:
        pass
    except (OSError, json.JSONDecodeError, RuntimeError, HTTPException):
        logger.exception("Terminal session ended with an error")
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            logger.debug("Terminal WebSocket was already closed")
    finally:
        pending_tasks = [
            task for task in (output_task, input_task) if task is not None and not task.done()
        ]
        for task in pending_tasks:
            task.cancel()
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)
        if master_fd is not None:
            loop.remove_reader(master_fd)
        close_terminal(local)
        local.terminal_active = False


PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WebSSH</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fontsource/jetbrains-mono@5.2.6/latin-400.css">
  <style nonce="__NONCE__">
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #0b1020; color: #e5e7eb; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: radial-gradient(ellipse at top, #17213a, #0b1020 55%); }
    button, input { font: inherit; }
    button { cursor: pointer; }
    .hidden { display: none !important; }
    .login-wrap { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
    .login-card { width: min(420px, 100%); background: #121a2b; border: 1px solid #26334b; border-radius: 16px; padding: 32px; box-shadow: 0 24px 80px #0006; }
    .brand { display: flex; align-items: center; gap: 12px; font-size: 21px; font-weight: 700; letter-spacing: -.03em; }
    .brand-mark { width: 38px; height: 38px; display: grid; place-items: center; border-radius: 11px; color: #07111e; background: #67e8c1; font-family: ui-monospace, monospace; font-weight: 900; }
    .muted { color: #94a3b8; font-size: 14px; line-height: 1.55; }
    .field { display: grid; gap: 8px; margin-top: 20px; }
    label { color: #cbd5e1; font-size: 13px; font-weight: 600; }
    input { width: 100%; padding: 12px 13px; color: #f8fafc; background: #0c1322; border: 1px solid #334155; border-radius: 8px; outline: none; }
    input:focus { border-color: #67e8c1; box-shadow: 0 0 0 3px #67e8c122; }
    .primary { width: 100%; margin-top: 24px; padding: 12px; border: 0; border-radius: 8px; color: #07111e; background: #67e8c1; font-weight: 700; }
    .primary:hover { background: #8af3d2; }
    .error { min-height: 20px; margin-top: 14px; color: #fda4af; font-size: 13px; }
    .app-shell { height: 100vh; min-height: 520px; display: flex; flex-direction: column; padding: 18px; gap: 14px; }
    header { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    .header-meta { display: flex; align-items: center; gap: 14px; color: #94a3b8; font-size: 13px; }
    .status { display: flex; align-items: center; gap: 8px; }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: #67e8c1; box-shadow: 0 0 12px #67e8c1aa; }
    .quiet-button { padding: 8px 11px; color: #cbd5e1; background: #121a2b; border: 1px solid #29364d; border-radius: 7px; }
    .quiet-button:hover { border-color: #67e8c1; color: #fff; }
    .workspace { flex: 1; min-height: 0; display: grid; grid-template-columns: minmax(240px, 29%) 1fr; gap: 14px; }
    .panel { min-width: 0; background: #0d1422; border: 1px solid #27334a; border-radius: 12px; overflow: hidden; display: flex; flex-direction: column; }
    .panel-head { min-height: 52px; padding: 0 14px; display: flex; align-items: center; justify-content: space-between; gap: 10px; border-bottom: 1px solid #27334a; }
    .panel-title { color: #e2e8f0; font-size: 13px; font-weight: 700; }
    .path-bar { padding: 7px 13px; border-bottom: 1px solid #1e293b; }
    .path-input { width: 100%; padding: 4px 0; color: #94a3b8; background: transparent; border: 0; border-radius: 0; outline: none; box-shadow: none; font: 12px ui-monospace, monospace; }
    .path-input:focus { color: #e2e8f0; border: 0; box-shadow: none; }
    .file-list { overflow: auto; flex: 1; padding: 5px 8px; }
    .file-row { min-height: 38px; display: flex; align-items: center; gap: 9px; padding: 5px 8px; border-radius: 6px; color: #dbe4f0; font-size: 13px; }
    .file-row:hover { background: #172338; }
    .file-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: inherit; text-align: left; background: none; border: 0; padding: 4px 0; }
    .file-name.dir { color: #8bd5ff; }
    .file-size { color: #64748b; font-size: 11px; white-space: nowrap; }
    .download { padding: 5px 7px; color: #94a3b8; background: transparent; border: 0; border-radius: 5px; }
    .download:hover { color: #67e8c1; background: #1e293b; }
    .file-actions { display: flex; gap: 6px; }
    .upload-button { position: relative; overflow: hidden; padding: 7px 9px; color: #b6c4d6; background: #162033; border: 1px solid #2b3a53; border-radius: 6px; font-size: 12px; }
    .upload-button:hover, .upload-button:focus-within { border-color: #67e8c1; color: #fff; background: #1b2b3e; }
    .upload-button input { position: absolute; inset: 0; opacity: 0; cursor: pointer; }
    .terminal-panel { background: #080d16; }
    #terminal { flex: 1; min-height: 0; padding: 10px; }
    #terminal .xterm { height: 100%; }
    .terminal-tools { display: flex; align-items: center; gap: 10px; }
    .quiet-button:disabled { opacity: .45; cursor: not-allowed; }
    .terminal-note { color: #64748b; font-size: 11px; }
    .empty { padding: 16px 10px; color: #64748b; font-size: 13px; }
    @media (max-width: 760px) {
      .app-shell { height: auto; min-height: 100vh; }
      .workspace { grid-template-columns: 1fr; grid-template-rows: minmax(260px, 38vh) minmax(380px, 1fr); }
      .header-meta .status { display: none; }
    }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.js" crossorigin="anonymous"></script>
</head>
<body>
  <main id="loginView" class="login-wrap">
    <section class="login-card">
      <div class="brand"><div class="brand-mark">&gt;_</div><span>WebSSH</span></div>
      <p class="muted">Sign in with the Linux account running this app. Your password is checked locally and never stored.</p>
      <form id="loginForm">
        <div class="field"><label for="username">Linux username</label><input id="username" name="username" autocomplete="username" required autofocus></div>
        <div class="field"><label for="password">Linux password</label><input id="password" name="password" type="password" autocomplete="current-password" required></div>
        <button class="primary" type="submit">Sign in</button>
        <div id="loginError" class="error" role="alert"></div>
      </form>
    </section>
  </main>
  <main id="appView" class="app-shell hidden">
    <header>
      <div class="brand"><div class="brand-mark">&gt;_</div><span>WebSSH</span></div>
      <div class="header-meta">
        <div class="status"><span class="dot"></span><span id="connectionLabel">Connected</span></div>
        <span id="userLabel"></span>
        <button id="logoutButton" class="quiet-button">Disconnect</button>
      </div>
    </header>
    <section class="workspace">
      <aside class="panel">
        <div class="panel-head">
          <span class="panel-title">System files</span>
          <div class="file-actions">
            <button id="upButton" class="quiet-button" title="Parent directory">Up</button>
            <button id="uploadButton" class="quiet-button" type="button">Upload</button>
            <input id="uploadInput" class="hidden" type="file" multiple>
          </div>
        </div>
        <form id="pathForm" class="path-bar">
          <input id="pathInput" class="path-input" type="text" value="/" aria-label="Current directory path" autocomplete="off" spellcheck="false">
        </form>
        <div id="fileList" class="file-list"><div class="empty">Loading files…</div></div>
      </aside>
      <section class="panel terminal-panel">
        <div class="panel-head">
          <span class="panel-title">Terminal</span>
          <div class="terminal-tools">
            <button id="copyTerminalButton" class="quiet-button" type="button" disabled title="Select terminal text, then copy">Copy selection</button>
            <span class="terminal-note">Local shell · xterm-256color</span>
          </div>
        </div>
        <div id="terminal"></div>
      </section>
    </section>
  </main>
  <script nonce="__NONCE__">
    const csrfToken = "__CSRF_TOKEN__";
    const styleNonce = document.currentScript ? document.currentScript.nonce : "";
    const loginView = document.getElementById("loginView");
    const appView = document.getElementById("appView");
    const loginError = document.getElementById("loginError");
    const fileList = document.getElementById("fileList");
    let currentPath = "/";
    let homePath = "/";
    let terminal;
    let fitAddon;
    let terminalSocket;

    function withStyleNonce(callback) {
      const createElement = document.createElement;
      document.createElement = function (tagName, options) {
        const element = createElement.call(this, tagName, options);
        if (element isinstanceof HTMLStyleElement) element.setAttribute("nonce", styleNonce);
        return element;
      };
      try {
        callback();
      } finally {
        document.createElement = createElement;
      }
    }

    async function api(url, options = {}) {
      const response = await fetch(url, {
        credentials: "same-origin",
        ...options,
        headers: { ...(options.headers || {}) }
      });
      if (!response.ok) {
        let detail = `Request failed (${response.status})`;
        try { detail = (await response.json()).detail || detail; } catch {}
        throw new Error(detail);
      }
      return response;
    }

    function showLogin(message = "") {
      appView.classList.add("hidden");
      loginView.classList.remove("hidden");
      loginError.textContent = message;
    }

    function formatSize(size) {
      if (size < 1024) return `${size} B`;
      if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
      if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
      return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    }

    async function loadFiles(path = currentPath) {
      const result = await api(`/api/files?path=${encodeURIComponent(path)}`).then(response => response.json());
      currentPath = result.path;
      document.getElementById("pathInput").value = currentPath;
      fileList.replaceChildren();
      if (!result.entries.length) {
        fileList.innerHTML = '<div class="empty">This directory is empty.</div>';
        return;
      }
      for (const entry of result.entries) {
        const row = document.createElement("div");
        row.className = "file-row";
        const icon = document.createElement("span");
        icon.textContent = entry.type === "directory" ? "▰" : entry.type === "link" ? "↗" : "·";
        icon.setAttribute("aria-hidden", "true");
        const name = document.createElement("button");
        name.className = `file-name${entry.type === "directory" ? " dir" : ""}`;
        name.textContent = entry.name;
        if (entry.type === "directory") name.addEventListener("click", () => loadFiles(entry.path).catch(showError));
        const size = document.createElement("span");
        size.className = "file-size";
        size.textContent = entry.type === "file" ? formatSize(entry.size) : "";
        row.append(icon, name, size);
        if (entry.type === "file") {
          const download = document.createElement("button");
          download.className = "download";
          download.textContent = "↓";
          download.title = "Download";
          download.setAttribute("aria-label", `Download ${entry.name}`);
          download.addEventListener("click", () => {
            const link = document.createElement("a");
            link.href = `/api/download?path=${encodeURIComponent(entry.path)}`;
            link.download = entry.name;
            link.click();
          });
          row.append(download);
        }
        fileList.append(row);
      }
    }

    function showError(error) {
      fileList.replaceChildren();
      const message = document.createElement("div");
      message.className = "empty";
      message.textContent = error.message || "An unexpected error occurred.";
      fileList.append(message);
    }

    async function connectTerminal() {
      await document.fonts.load('14px "JetBrains Mono"').catch(() => {});
      terminal = new Terminal({
        cursorBlink: false,
        cursorStyle: "bar",
        cursorWidth: 4,
        cursorInactiveStyle: "bar",
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 14,
        lineHeight: 1.25,
        theme: {
          background: "#080d16",
          foreground: "#dbe4f0",
          cursor: "#ffffff",
          cursorAccent: "#080d16",
          selectionBackground: "#2864a3",
          selectionForeground: "#ffffff",
          selectionInactiveBackground: "#2864a3"
        }
      });
      fitAddon = new FitAddon.FitAddon();
      terminal.loadAddon(fitAddon);
      withStyleNonce(() => terminal.open(document.getElementByID("terminal")));
      fitAddon.fit();
      terminal.focus();
      terminal.element.addEventListener("pointerdown", () => terminal.focus());

      const copyButton = document.getElementById("copyTerminalButton");
      terminal.onSelectionChange(() => {
        copyButton.disabled = !terminal.hasSelection();
      });

      const scheme = location.protocol === "https:" ? "wss:" : "ws:";
      terminalSocket = new WebSocket(`${scheme}//${location.host}/ws/terminal`);
      terminalSocket.addEventListener("open", () => {
        fitAddon.fit();
        terminalSocket.send(JSON.stringify({ type: "resize", cols: terminal.cols, rows: terminal.rows }));
        terminal.focus();
      });
      terminalSocket.addEventListener("message", event => {
        const message = JSON.parse(event.data);
        if (message.type === "output") {
          terminal.write(message.data);
        }
      });
      terminalSocket.addEventListener("close", () => {
        document.getElementById("connectionLabel").textContent = "Terminal disconnected";
      });
      terminal.onData(data => {
        if (terminalSocket.readyState === WebSocket.OPEN) {
          terminalSocket.send(JSON.stringify({ type: "input", data }));
        }
      });
      copyButton.addEventListener("click", async () => {
        const selection = terminal.getSelection();
        if (!selection) return;
        try {
          if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(selection);
          } else {
            const copyBuffer = document.createElement("textarea");
            copyBuffer.value = selection;
            copyBuffer.style.position = "fixed";
            copyBuffer.style.opacity = "0";
            document.body.append(copyBuffer);
            copyBuffer.select();
            const copied = document.execCommand("copy");
            copyBuffer.remove();
            if (!copied) throw new Error("Clipboard access was denied by the browser");
          }
          document.querySelector(".terminal-note").textContent = "Copied to clipboard";
          setTimeout(() => {
            document.querySelector(".terminal-note").textContent = "Local shell · xterm-256color";
          }, 1500);
        } catch (error) {
          document.querySelector(".terminal-note").textContent = error.message;
        }
      });
      window.addEventListener("resize", () => {
        if (!fitAddon || !terminal) return;
        fitAddon.fit();
        if (terminalSocket.readyState === WebSocket.OPEN) {
          terminalSocket.send(JSON.stringify({ type: "resize", cols: terminal.cols, rows: terminal.rows }));
        }
      });
    }

    async function showApp(info) {
      loginView.classList.add("hidden");
      appView.classList.remove("hidden");
      document.getElementById("userLabel").textContent = info.username;
      homePath = info.home || "/";
      await loadFiles(homePath).catch(showError);
      await connectTerminal();
    }

    document.getElementById("loginForm").addEventListener("submit", async event => {
      event.preventDefault();
      loginError.textContent = "";
      const form = new FormData(event.currentTarget);
      try {
        const response = await api("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
          body: JSON.stringify({ username: form.get("username"), password: form.get("password") })
        });
        const info = await response.json();
        document.getElementById("password").value = "";
        await showApp(info);
      } catch (error) {
        loginError.textContent = error.message;
      }
    });

    document.getElementById("upButton").addEventListener("click", () => {
      if (currentPath !== "/") loadFiles(currentPath.slice(0, currentPath.lastIndexOf("/")) || "/").catch(showError);
    });

    document.getElementById("pathForm").addEventListener("submit", event => {
      event.preventDefault();
      const requestedPath = document.getElementById("pathInput").value.trim();
      if (!requestedPath) {
        document.getElementById("pathInput").value = currentPath;
        return;
      }
      let path = requestedPath;
      if (path === "~") path = homePath;
      else if (path.startsWith("~/")) path = `${homePath}/${path.slice(2)}`;
      else if (!path.startsWith("/")) path = `${currentPath.replace(/\/$/, "")}/${path}`;
      loadFiles(path.replace(/\/{2,}/g, "/")).catch(showError);
    });

    document.getElementById("uploadButton").addEventListener("click", () => {
      document.getElementById("uploadInput").click();
    });

    document.getElementById("uploadInput").addEventListener("change", async event => {
      const files = Array.from(event.target.files || []);
      for (const file of files) {
        const data = new FormData();
        data.append("file", file);
        try {
          await api(`/api/upload?path=${encodeURIComponent(currentPath)}`, {
            method: "POST",
            headers: { "X-CSRF-Token": csrfToken },
            body: data
          });
        } catch (error) {
          showError(error);
          event.target.value = "";
          return;
        }
      }
      event.target.value = "";
      await loadFiles();
    });

    document.getElementById("logoutButton").addEventListener("click", async () => {
      try {
        await api("/api/logout", { method: "POST", headers: { "X-CSRF-Token": csrfToken } });
      } finally {
        if (terminalSocket) terminalSocket.close();
        if (terminal) terminal.dispose();
        showLogin();
      }
    });

    api("/api/session")
      .then(response => response.json())
      .then(showApp)
      .catch(() => showLogin());
  </script>
</body>
</html>"""

import asyncio
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
from typing import Any, AsyncGenerator, AsyncIterator
from urllib.parse import quote, urlsplit

import asyncssh
from fastapi import FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware


logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("webssh")

SSH_HOST = os.environ.get("SSH_HOST", "").strip()
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
SSH_KNOWN_HOSTS = os.environ.get("SSH_KNOWN_HOSTS")
SESSION_SECRET = os.environ.get("WEBSSH_SESSION_SECRET")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(32)
    logger.warning("WEBSSH_SESSION_SECRET is unset; sessions will not survive application restarts")

COOKIE_SECURE = os.environ.get("WEBSSH_COOKIE_SECURE", "1").lower() not in {"0", "false", "no"}
SESSION_IDLE_SECONDS = 30 * 60
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


@dataclass
class RemoteSession:
    connection: asyncssh.SSHClientConnection
    sftp: asyncssh.SFTPClient
    username: str
    last_activity: float


remote_sessions: dict[str, RemoteSession] = {}


async def close_connection(connection: asyncssh.SSHClientConnection) -> None:
    connection.close()
    try:
        await connection.wait_closed()
    except (asyncssh.Error, OSError):
        logger.exception("Error while closing an SSH connection")


async def expire_idle_sessions() -> None:
    while True:
        await asyncio.sleep(60)
        now = time.monotonic()
        expired = [
            session_id
            for session_id, remote in remote_sessions.items()
            if now - remote.last_activity >= SESSION_IDLE_SECONDS
        ]
        for session_id in expired:
            remote = remote_sessions.pop(session_id, None)
            if remote is not None:
                await close_connection(remote.connection)


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
        sessions = list(remote_sessions.values())
        remote_sessions.clear()
        await asyncio.gather(
            *(close_connection(remote.connection) for remote in sessions)
        )


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


def normalize_remote_path(path: str) -> str:
    if "\x00" in path or len(path) > 4096 or not path.startswith("/"):
        raise HTTPException(status_code=400, detail="A valid absolute remote path is required")
    return "/" + posixpath.normpath(path).lstrip("/")


def get_remote_session(request: Request) -> RemoteSession:
    session_id = request.session.get("session_id")
    remote = remote_sessions.get(session_id) if isinstance(session_id, str) else None
    if remote is None:
        raise HTTPException(status_code=401, detail="Please sign in again")
    remote.last_activity = time.monotonic()
    return remote


def verify_csrf(request: Request) -> None:
    expected = request.session.get("csrf_token")
    supplied = request.headers.get("x-csrf-token", "")
    if not isinstance(expected, str) or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Invalid request token")


def remote_file_error(exc: asyncssh.SFTPError) -> HTTPException:
    logger.info("Remote SFTP operation failed: %s", exc)
    return HTTPException(status_code=502, detail="The remote file operation failed")


async def connect_to_target(username: str, password: str) -> RemoteSession:
    if not SSH_HOST:
        raise HTTPException(status_code=503, detail="Set SSH_HOST before signing in")

    connect_options: dict[str, Any] = {
        "host": SSH_HOST,
        "port": SSH_PORT,
        "username": username,
        "password": password,
        "login_timeout": 20,
        "keepalive_interval": 30,
        "keepalive_count_max": 3,
    }
    if SSH_KNOWN_HOSTS:
        connect_options["known_hosts"] = SSH_KNOWN_HOSTS

    connection: asyncssh.SSHClientConnection | None = None
    try:
        connection = await asyncssh.connect(**connect_options)
        sftp = await connection.start_sftp_client()
    except asyncssh.PermissionDenied as exc:
        if connection is not None:
            await close_connection(connection)
        raise HTTPException(status_code=401, detail="SSH login was rejected") from exc
    except (asyncssh.Error, OSError) as exc:
        if connection is not None:
            await close_connection(connection)
        logger.warning("Unable to establish SSH session: %s", exc)
        raise HTTPException(status_code=502, detail="Unable to connect to the SSH server") from exc

    return RemoteSession(
        connection=connection,
        sftp=sftp,
        username=username,
        last_activity=time.monotonic(),
    )


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
        "font-src 'self' https://cdn.jsdelivr.net data:; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/api/session")
async def session_info(request: Request) -> dict[str, str]:
    remote = get_remote_session(request)
    return {"username": remote.username, "host": SSH_HOST}


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

    remote = await connect_to_target(username.strip(), password)
    old_session_id = request.session.get("session_id")
    if isinstance(old_session_id, str):
        old_remote = remote_sessions.pop(old_session_id, None)
        if old_remote is not None:
            await close_connection(old_remote.connection)

    session_id = secrets.token_urlsafe(32)
    remote_sessions[session_id] = remote
    request.session["session_id"] = session_id
    return JSONResponse({"username": remote.username, "host": SSH_HOST})


@app.post("/api/logout")
async def logout(request: Request) -> JSONResponse:
    verify_csrf(request)
    session_id = request.session.pop("session_id", None)
    if isinstance(session_id, str):
        remote = remote_sessions.pop(session_id, None)
        if remote is not None:
            await close_connection(remote.connection)
    return JSONResponse({"ok": True})


@app.get("/api/files")
async def list_files(request: Request, path: str = "/") -> dict[str, Any]:
    remote = get_remote_session(request)
    directory = normalize_remote_path(path)
    try:
        entries = await remote.sftp.listdir_attr(directory)
    except asyncssh.SFTPError as exc:
        raise remote_file_error(exc) from exc

    files = []
    for entry in entries:
        name = entry.filename
        if not name or name in {".", ".."}:
            continue
        mode = entry.permissions or 0
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
                "size": entry.size or 0,
                "modified": entry.mtime or 0,
            }
        )
    files.sort(key=lambda item: (item["type"] != "directory", item["name"].casefold()))
    return {"path": directory, "entries": files}


@app.get("/api/download")
async def download_file(request: Request, path: str) -> StreamingResponse:
    remote = get_remote_session(request)
    remote_path = normalize_remote_path(path)
    try:
        remote_file = await remote.sftp.open(remote_path, "rb")
    except asyncssh.SFTPError as exc:
        raise remote_file_error(exc) from exc

    async def stream_file() -> AsyncIterator[bytes]:
        try:
            async with remote_file:
                while True:
                    chunk = await remote_file.read(64 * 1024)
                    if not chunk:
                        break
                    remote.last_activity = time.monotonic()
                    yield chunk
        except asyncssh.SFTPError:
            logger.exception("Remote download failed during transfer")
            raise

    filename = posixpath.basename(remote_path) or "download"
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
    remote = get_remote_session(request)
    directory = normalize_remote_path(path)
    raw_name = (file.filename or "").replace("\\", "/")
    filename = posixpath.basename(raw_name)
    if not filename or filename in {".", ".."} or "\x00" in filename:
        raise HTTPException(status_code=400, detail="Choose a valid file name")

    destination = posixpath.join(directory, filename)
    temporary_path = posixpath.join(directory, f".webssh-upload-{secrets.token_hex(16)}")
    total_bytes = 0
    try:
        async with await remote.sftp.open(temporary_path, "wb") as target:
            while chunk := await file.read(64 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="File exceeds the 100 MB upload limit")
                await target.write(chunk)
        await remote.sftp.posix_rename(temporary_path, destination)
    except HTTPException:
        try:
            await remote.sftp.remove(temporary_path)
        except asyncssh.SFTPError:
            logger.exception("Unable to remove a partial remote upload")
        raise
    except asyncssh.SFTPError as exc:
        try:
            await remote.sftp.remove(temporary_path)
        except asyncssh.SFTPError:
            logger.exception("Unable to remove a partial remote upload")
        raise remote_file_error(exc) from exc
    finally:
        await file.close()

    remote.last_activity = time.monotonic()
    return {"name": filename, "path": destination}


@app.websocket("/ws/terminal")
async def terminal(websocket: WebSocket) -> None:
    origin = websocket.headers.get("origin", "")
    host = websocket.headers.get("host", "")
    if not origin or urlsplit(origin).netloc.casefold() != host.casefold():
        await websocket.close(code=4403)
        return

    session_id = websocket.session.get("session_id")
    remote = remote_sessions.get(session_id) if isinstance(session_id, str) else None
    if remote is None:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    process: asyncssh.SSHClientProcess[str] | None = None
    output_task: asyncio.Task[None] | None = None
    try:
        process = await remote.connection.create_process(
            term_type="xterm-256color",
            term_size=(120, 32),
            encoding="utf-8",
        )

        async def forward_output() -> None:
            assert process is not None
            while True:
                data = await process.stdout.read(4096)
                if not data:
                    await websocket.close(code=1000)
                    break
                remote.last_activity = time.monotonic()
                await websocket.send_json({"type": "output", "data": data})

        output_task = asyncio.create_task(forward_output())
        while True:
            message = json.loads(await websocket.receive_text())
            if not isinstance(message, dict):
                continue
            if message.get("type") == "input" and isinstance(message.get("data"), str):
                process.stdin.write(message["data"])
                await process.stdin.drain()
                remote.last_activity = time.monotonic()
            elif message.get("type") == "resize":
                cols = message.get("cols")
                rows = message.get("rows")
                if (
                    isinstance(cols, int)
                    and isinstance(rows, int)
                    and not isinstance(cols, bool)
                    and not isinstance(rows, bool)
                ):
                    process.change_terminal_size(
                        max(20, min(cols, 400)),
                        max(5, min(rows, 200)),
                    )
    except WebSocketDisconnect:
        pass
    except (asyncssh.Error, OSError, json.JSONDecodeError, RuntimeError):
        logger.exception("Terminal session ended with an error")
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            logger.debug("Terminal WebSocket was already closed")
    finally:
        if output_task is not None:
            output_task.cancel()
            task_results = await asyncio.gather(output_task, return_exceptions=True)
            for result in task_results:
                if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError):
                    logger.error("Terminal output task failed: %s", result)
        if process is not None:
            process.close()


PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WebSSH</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css">
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
    .path-bar { padding: 10px 13px; color: #94a3b8; font: 12px ui-monospace, monospace; border-bottom: 1px solid #1e293b; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
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
    .upload-button input { position: absolute; inset: 0; opacity: 0; cursor: pointer; }
    .terminal-panel { background: #080d16; }
    #terminal { flex: 1; min-height: 0; padding: 10px; }
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
      <p class="muted">Connect to your Debian system with your SSH account. Credentials are used only to establish this session.</p>
      <form id="loginForm">
        <div class="field"><label for="username">SSH username</label><input id="username" name="username" autocomplete="username" required autofocus></div>
        <div class="field"><label for="password">SSH password</label><input id="password" name="password" type="password" autocomplete="current-password" required></div>
        <button class="primary" type="submit">Connect securely</button>
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
          <span class="panel-title">Remote files</span>
          <div class="file-actions">
            <button id="upButton" class="quiet-button" title="Parent directory">Up</button>
            <label class="upload-button">Upload<input id="uploadInput" type="file" multiple></label>
          </div>
        </div>
        <div id="pathBar" class="path-bar">/</div>
        <div id="fileList" class="file-list"><div class="empty">Loading files…</div></div>
      </aside>
      <section class="panel terminal-panel">
        <div class="panel-head">
          <span class="panel-title">Terminal</span>
          <span class="terminal-note">SSH · xterm-256color</span>
        </div>
        <div id="terminal"></div>
      </section>
    </section>
  </main>
  <script nonce="__NONCE__">
    const csrfToken = "__CSRF_TOKEN__";
    const loginView = document.getElementById("loginView");
    const appView = document.getElementById("appView");
    const loginError = document.getElementById("loginError");
    const fileList = document.getElementById("fileList");
    let currentPath = "/";
    let terminal;
    let fitAddon;
    let terminalSocket;

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
      document.getElementById("pathBar").textContent = currentPath;
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

    function connectTerminal() {
      terminal = new Terminal({
        cursorBlink: true,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        fontSize: 13,
        theme: { background: "#080d16", foreground: "#dbe4f0", cursor: "#67e8c1" }
      });
      fitAddon = new FitAddon.FitAddon();
      terminal.loadAddon(fitAddon);
      terminal.open(document.getElementById("terminal"));
      fitAddon.fit();
      const scheme = location.protocol === "https:" ? "wss:" : "ws:";
      terminalSocket = new WebSocket(`${scheme}//${location.host}/ws/terminal`);
      terminalSocket.addEventListener("open", () => {
        fitAddon.fit();
        terminalSocket.send(JSON.stringify({ type: "resize", cols: terminal.cols, rows: terminal.rows }));
        terminal.focus();
      });
      terminalSocket.addEventListener("message", event => {
        const message = JSON.parse(event.data);
        if (message.type === "output") terminal.write(message.data);
      });
      terminalSocket.addEventListener("close", () => {
        document.getElementById("connectionLabel").textContent = "Terminal disconnected";
      });
      terminal.onData(data => {
        if (terminalSocket.readyState === WebSocket.OPEN) {
          terminalSocket.send(JSON.stringify({ type: "input", data }));
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
      document.getElementById("userLabel").textContent = `${info.username}@${info.host}`;
      await loadFiles("/").catch(showError);
      connectTerminal();
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

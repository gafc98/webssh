import asyncio
import secrets
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import COOKIE_SECURE, SESSION_SECRET, STATIC_DIR, TEMPLATE_DIR
from .routes import auth, files, system, terminals
from .sessions import end_all_sessions, housekeeping


INDEX_TEMPLATE = (TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    housekeeping_task = asyncio.create_task(housekeeping())
    try:
        yield
    finally:
        housekeeping_task.cancel()
        try:
            await housekeeping_task
        except asyncio.CancelledError:
            pass
        await end_all_sessions()


app = FastAPI(title="WebSSH", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
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
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-cache" if request.url.path.startswith("/static/") else "no-store"
    return response


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    csrf_token = request.session.get("csrf_token")
    if not isinstance(csrf_token, str):
        csrf_token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = csrf_token
    nonce = secrets.token_urlsafe(18)
    html = INDEX_TEMPLATE.replace("__CSRF_TOKEN__", csrf_token).replace("__NONCE__", nonce)
    response = HTMLResponse(html)
    # xterm.js injects <style> elements at runtime, which the nonce allows.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "style-src-attr 'unsafe-inline'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    return response


app.include_router(auth.router)
app.include_router(files.router)
app.include_router(terminals.router)
app.include_router(system.router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

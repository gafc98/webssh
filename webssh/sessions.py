import asyncio
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Coroutine

from fastapi import HTTPException
from starlette.requests import HTTPConnection

from . import otp
from .config import MAX_TERMINALS, SESSION_IDLE_SECONDS, TERMINAL_GRACE_SECONDS
from .security import login_throttle
from .terminal import Terminal


logger = logging.getLogger("webssh.sessions")

HOUSEKEEPING_INTERVAL_SECONDS = 15


@dataclass
class LocalSession:
    username: str
    home: str
    shell: str
    last_activity: float = field(default_factory=time.monotonic)
    terminals: dict[str, Terminal] = field(default_factory=dict)
    terminal_count: int = 0

    def touch(self) -> None:
        self.last_activity = time.monotonic()


local_sessions: dict[str, LocalSession] = {}
_background_tasks: set[asyncio.Task[Any]] = set()


def run_in_background(coroutine: Coroutine[Any, Any, Any]) -> None:
    task = asyncio.create_task(coroutine)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


def find_local_session(connection: HTTPConnection) -> LocalSession | None:
    session_id = connection.session.get("session_id")
    return local_sessions.get(session_id) if isinstance(session_id, str) else None


def require_local_session(connection: HTTPConnection, touch: bool = True) -> LocalSession:
    local = find_local_session(connection)
    if local is None:
        raise HTTPException(status_code=401, detail="Please sign in again")
    if touch:
        local.touch()
    return local


def start_session(username: str, home: str, shell: str) -> str:
    session_id = secrets.token_urlsafe(32)
    local_sessions[session_id] = LocalSession(username=username, home=home, shell=shell)
    return session_id


async def close_session(local: LocalSession) -> None:
    terminals = list(local.terminals.values())
    local.terminals.clear()
    await asyncio.gather(*(terminal.close() for terminal in terminals), return_exceptions=True)


async def end_session(session_id: Any) -> LocalSession | None:
    if not isinstance(session_id, str):
        return None
    local = local_sessions.pop(session_id, None)
    if local is not None:
        await close_session(local)
    return local


async def end_all_sessions() -> None:
    sessions = list(local_sessions.values())
    local_sessions.clear()
    await asyncio.gather(*(close_session(local) for local in sessions), return_exceptions=True)


def create_terminal(local: LocalSession) -> Terminal:
    if len(local.terminals) >= MAX_TERMINALS:
        raise HTTPException(status_code=409, detail=f"At most {MAX_TERMINALS} terminals can be open")
    try:
        from ptyprocess import PtyProcess
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="A Linux pseudo-terminal is required") from exc

    environment = os.environ.copy()
    environment.pop("WEBSSH_SESSION_SECRET", None)
    environment.update(
        HOME=local.home,
        LOGNAME=local.username,
        SHELL=local.shell,
        TERM="xterm-256color",
        USER=local.username,
    )
    try:
        process = PtyProcess.spawn(
            [local.shell, "-l"],
            cwd=local.home,
            env=environment,
            dimensions=(32, 120),
        )
    except OSError as exc:
        logger.exception("Unable to start a shell")
        raise HTTPException(status_code=500, detail="Unable to start a shell") from exc

    def on_exit(terminal: Terminal) -> None:
        if local.terminals.get(terminal.id) is terminal:
            del local.terminals[terminal.id]
        run_in_background(terminal.close())

    local.terminal_count += 1
    terminal = Terminal(secrets.token_urlsafe(9), f"Shell {local.terminal_count}", process, on_exit)
    local.terminals[terminal.id] = terminal
    return terminal


async def housekeeping() -> None:
    while True:
        await asyncio.sleep(HOUSEKEEPING_INTERVAL_SECONDS)
        try:
            now = time.monotonic()
            for session_id, local in list(local_sessions.items()):
                if now - local.last_activity >= SESSION_IDLE_SECONDS:
                    logger.info("Session for %s expired after inactivity", local.username)
                    await end_session(session_id)
                    continue
                for terminal in list(local.terminals.values()):
                    if terminal.detached_at is not None and now - terminal.detached_at >= TERMINAL_GRACE_SECONDS:
                        local.terminals.pop(terminal.id, None)
                        await terminal.close()
            login_throttle.prune()
            otp.prune()
        except Exception:
            logger.exception("Session housekeeping failed")

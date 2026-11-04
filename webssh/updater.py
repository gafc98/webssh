import asyncio
import logging
import os
import secrets
import subprocess
import time
from typing import Any

from fastapi import HTTPException

from .config import ALLOW_UPDATE, PROJECT_DIR, UPDATE_SCRIPT


logger = logging.getLogger("webssh.updater")

BOOT_ID = secrets.token_urlsafe(8)
FETCH_INTERVAL_SECONDS = 10 * 60
MIN_FORCED_FETCH_SECONDS = 15
UPDATE_TIMEOUT_SECONDS = 5 * 60

_fetch_lock = asyncio.Lock()
_last_fetch: float | None = None
_update_process: subprocess.Popen[bytes] | None = None
_update_started: float | None = None


async def _git(*args: str, timeout: float = 30) -> tuple[int, str, str]:
    try:
        process = await asyncio.create_subprocess_exec(
            "git",
            *args,
            cwd=PROJECT_DIR,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except FileNotFoundError:
        return 127, "", "git is not installed"
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return 124, "", "git timed out"
    return (
        process.returncode or 0,
        stdout.decode("utf-8", errors="replace").strip(),
        stderr.decode("utf-8", errors="replace").strip(),
    )


def _update_state() -> tuple[bool, str | None]:
    """Returns (in_progress, last_error)."""
    global _update_process, _update_started
    if _update_process is not None:
        code = _update_process.poll()
        if code is not None:
            _update_process = None
            _update_started = None
            if code != 0:
                return False, f"The last update failed (exit code {code}); see update.log"
    if _update_started is not None and time.monotonic() - _update_started > UPDATE_TIMEOUT_SECONDS:
        _update_started = None
    return _update_started is not None, None


async def get_status(refresh: bool = False) -> dict[str, Any]:
    global _last_fetch
    if not ALLOW_UPDATE:
        return {"enabled": False, "reason": "Updates are disabled (WEBSSH_ALLOW_UPDATE)"}
    if not (PROJECT_DIR / ".git").exists():
        return {"enabled": False, "reason": "This installation is not a git checkout"}
    code, upstream, _ = await _git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if code:
        return {"enabled": False, "reason": "The current branch has no upstream branch"}

    fetch_error = None
    async with _fetch_lock:
        since_fetch = None if _last_fetch is None else time.monotonic() - _last_fetch
        limit = MIN_FORCED_FETCH_SECONDS if refresh else FETCH_INTERVAL_SECONDS
        if since_fetch is None or since_fetch > limit:
            code, _, error = await _git("fetch", "--quiet", timeout=120)
            if code:
                fetch_error = error or "git fetch failed"
                logger.warning("Update check failed: %s", fetch_error)
            else:
                _last_fetch = time.monotonic()

    code, counts, _ = await _git("rev-list", "--left-right", "--count", "HEAD...@{u}")
    ahead, behind = (int(value) for value in counts.split()) if code == 0 else (0, 0)
    _, current, _ = await _git("rev-parse", "--short", "HEAD")
    _, changes, _ = await _git("status", "--porcelain", "--untracked-files=no")
    commits: list[str] = []
    if behind:
        _, log, _ = await _git("log", "--format=%h %s", "-n", "20", "HEAD..@{u}")
        commits = log.splitlines()
    updating, update_error = _update_state()
    return {
        "enabled": True,
        "upstream": upstream,
        "current": current,
        "ahead": ahead,
        "behind": behind,
        "dirty": bool(changes),
        "commits": commits,
        "updating": updating,
        "error": update_error or fetch_error,
    }


async def start_update() -> None:
    global _update_process, _update_started
    status = await get_status(refresh=True)
    if not status["enabled"]:
        raise HTTPException(status_code=409, detail=status["reason"])
    if status["updating"]:
        raise HTTPException(status_code=409, detail="An update is already in progress")
    if not status["behind"]:
        raise HTTPException(status_code=409, detail="WebSSH is already up to date")
    if status["dirty"]:
        raise HTTPException(status_code=409, detail="The installation has local changes; update it manually")
    if status["ahead"]:
        raise HTTPException(status_code=409, detail="The installation has local commits; update it manually")
    if not UPDATE_SCRIPT.is_file():
        raise HTTPException(status_code=500, detail="The update script is missing")

    # A new session keeps the script alive after it stops this server process.
    _update_process = subprocess.Popen(
        ["/bin/bash", str(UPDATE_SCRIPT), str(os.getpid())],
        cwd=PROJECT_DIR,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    _update_started = time.monotonic()

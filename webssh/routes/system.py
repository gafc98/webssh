import asyncio
from typing import Any

from fastapi import APIRouter, Request

from .. import sysinfo, updater
from ..security import audit, verify_csrf
from ..sessions import require_local_session


router = APIRouter()


@router.get("/api/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "boot": updater.BOOT_ID}


@router.get("/api/stats")
async def stats(request: Request) -> dict[str, Any]:
    local = require_local_session(request, touch=False)
    return await asyncio.to_thread(sysinfo.collect, local.home)


@router.get("/api/update")
async def update_status(request: Request, refresh: bool = False) -> dict[str, Any]:
    require_local_session(request, touch=refresh)
    return await updater.get_status(refresh=refresh)


@router.post("/api/update")
async def start_update(request: Request) -> dict[str, Any]:
    verify_csrf(request)
    local = require_local_session(request)
    await updater.start_update()
    audit(request, "update.start", local.username)
    return {"ok": True, "boot": updater.BOOT_ID}

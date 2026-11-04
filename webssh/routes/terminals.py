import asyncio
import json
import logging
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect

from ..config import MAX_TERMINALS
from ..security import audit, verify_csrf
from ..sessions import create_terminal, find_local_session, require_local_session
from ..terminal import EXITED, REPLACED, Terminal


logger = logging.getLogger("webssh.terminals")
router = APIRouter()

MAX_INPUT_BYTES = 64 * 1024

# Custom WebSocket close codes understood by the browser client.
CLOSE_UNAUTHORIZED = 4401
CLOSE_NOT_FOUND = 4404
CLOSE_REPLACED = 4409


def terminal_info(terminal: Terminal) -> dict[str, Any]:
    return {"id": terminal.id, "title": terminal.title, "attached": terminal.attached}


@router.get("/api/terminals")
async def list_terminals(request: Request) -> dict[str, Any]:
    local = require_local_session(request)
    return {
        "terminals": [terminal_info(terminal) for terminal in local.terminals.values() if not terminal.exited],
        "max": MAX_TERMINALS,
    }


@router.post("/api/terminals")
async def open_terminal(request: Request) -> dict[str, Any]:
    verify_csrf(request)
    local = require_local_session(request)
    terminal = create_terminal(local)
    audit(request, "terminal.open", local.username, terminal=terminal.title)
    return terminal_info(terminal)


@router.delete("/api/terminals/{terminal_id}")
async def close_terminal(request: Request, terminal_id: str) -> dict[str, bool]:
    verify_csrf(request)
    local = require_local_session(request)
    terminal = local.terminals.pop(terminal_id, None)
    if terminal is None:
        raise HTTPException(status_code=404, detail="That terminal is no longer open")
    await terminal.close()
    audit(request, "terminal.close", local.username, terminal=terminal.title)
    return {"ok": True}


@router.websocket("/ws/terminals/{terminal_id}")
async def terminal_socket(websocket: WebSocket, terminal_id: str) -> None:
    origin = websocket.headers.get("origin", "")
    host = websocket.headers.get("host", "")
    if not origin or urlsplit(origin).netloc.casefold() != host.casefold():
        await websocket.close(code=1008)
        return

    await websocket.accept()
    local = find_local_session(websocket)
    if local is None:
        await websocket.close(code=CLOSE_UNAUTHORIZED)
        return
    terminal = local.terminals.get(terminal_id)
    if terminal is None or terminal.exited:
        await websocket.close(code=CLOSE_NOT_FOUND)
        return

    local.touch()
    queue = terminal.attach()
    output_task: asyncio.Task[object] = asyncio.create_task(queue.get())
    input_task: asyncio.Task[str] = asyncio.create_task(websocket.receive_text())
    try:
        while True:
            done, _ = await asyncio.wait((output_task, input_task), return_when=asyncio.FIRST_COMPLETED)

            if output_task in done:
                item = output_task.result()
                if item is EXITED:
                    await websocket.close(code=1000)
                    break
                if item is REPLACED:
                    await websocket.close(code=CLOSE_REPLACED)
                    break
                terminal.consumed(queue)
                local.touch()
                await websocket.send_bytes(item)  # type: ignore[arg-type]
                output_task = asyncio.create_task(queue.get())

            if input_task in done:
                message = json.loads(input_task.result())
                input_task = asyncio.create_task(websocket.receive_text())
                if not isinstance(message, dict):
                    continue
                if message.get("type") == "input" and isinstance(message.get("data"), str):
                    data = message["data"].encode("utf-8", errors="replace")
                    if len(data) > MAX_INPUT_BYTES:
                        await websocket.close(code=1009)
                        break
                    await terminal.write(data)
                    local.touch()
                elif message.get("type") == "resize":
                    cols = message.get("cols")
                    rows = message.get("rows")
                    if type(cols) is int and type(rows) is int:
                        terminal.resize(max(5, min(rows, 200)), max(20, min(cols, 400)))
    except WebSocketDisconnect:
        pass
    except (OSError, ValueError, RuntimeError):
        logger.exception("Terminal connection ended with an error")
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            logger.debug("Terminal WebSocket was already closed")
    finally:
        pending = [task for task in (output_task, input_task) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        terminal.detach(queue)

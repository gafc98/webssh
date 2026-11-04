import asyncio
import errno
import logging
import mimetypes
import os
import posixpath
import secrets
import shutil
import stat
from typing import Any, AsyncIterator
from urllib.parse import quote

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse

from ..config import IO_CHUNK_BYTES, MAX_UPLOAD_BYTES
from ..security import audit, read_json_object, verify_csrf
from ..sessions import require_local_session


logger = logging.getLogger("webssh.files")
router = APIRouter()


def normalize_local_path(path: Any) -> str:
    if not isinstance(path, str) or "\x00" in path or len(path) > 4096 or not path.startswith("/"):
        raise HTTPException(status_code=400, detail="A valid absolute path is required")
    return "/" + posixpath.normpath(path).lstrip("/")


def validate_name(name: Any) -> str:
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
        or len(name.encode("utf-8", errors="surrogateescape")) > 255
    ):
        raise HTTPException(status_code=400, detail="Enter a valid file or folder name")
    return name


def require_not_root(path: str) -> str:
    if path == "/":
        raise HTTPException(status_code=400, detail="The root directory cannot be changed")
    return path


def local_file_error(exc: OSError) -> HTTPException:
    logger.info("Local file operation failed: %s", exc)
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail="The requested file or directory was not found")
    if isinstance(exc, FileExistsError):
        return HTTPException(status_code=409, detail="A file or folder with that name already exists")
    if isinstance(exc, PermissionError):
        return HTTPException(status_code=403, detail="Permission denied")
    if isinstance(exc, NotADirectoryError):
        return HTTPException(status_code=400, detail="That path is not a directory")
    if isinstance(exc, IsADirectoryError):
        return HTTPException(status_code=400, detail="That path is a directory")
    if exc.errno == errno.ENOTEMPTY:
        return HTTPException(status_code=409, detail="The directory is not empty")
    if exc.errno == errno.ENOSPC:
        return HTTPException(status_code=507, detail="The disk is full")
    return HTTPException(status_code=500, detail="The local file operation failed")


async def run_file_operation(function: Any, *args: Any) -> Any:
    try:
        return await asyncio.to_thread(function, *args)
    except OSError as exc:
        raise local_file_error(exc) from exc


def scan_directory(directory: str) -> list[dict[str, Any]]:
    files = []
    with os.scandir(directory) as entries:
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
    return files


def ensure_absent(path: str) -> None:
    if os.path.lexists(path):
        raise FileExistsError(errno.EEXIST, "Destination exists", path)


def rename_path(source: str, target: str) -> None:
    ensure_absent(target)
    os.rename(source, target)


def delete_path(path: str) -> None:
    if stat.S_ISDIR(os.lstat(path).st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def transfer_path(source: str, target: str, move: bool) -> None:
    ensure_absent(target)
    is_directory = stat.S_ISDIR(os.lstat(source).st_mode)
    if is_directory and (target + "/").startswith(source + "/"):
        raise HTTPException(status_code=400, detail="A folder cannot be placed inside itself")
    if move:
        shutil.move(source, target)
    elif is_directory:
        shutil.copytree(source, target, symlinks=True)
    else:
        shutil.copy2(source, target, follow_symlinks=False)


def copy_upload(source: Any, target_path: str) -> None:
    total_bytes = 0
    with open(target_path, "xb") as target:
        while chunk := source.read(IO_CHUNK_BYTES):
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit",
                )
            target.write(chunk)


def lstat_or_none(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


@router.get("/api/files")
async def list_files(request: Request, path: str = "/") -> dict[str, Any]:
    require_local_session(request)
    directory = normalize_local_path(path)
    files = await run_file_operation(scan_directory, directory)
    return {"path": directory, "entries": files}


@router.get("/api/download")
async def download_file(request: Request, path: str) -> StreamingResponse:
    local = require_local_session(request)
    local_path = normalize_local_path(path)
    metadata = await run_file_operation(os.stat, local_path)
    if not stat.S_ISREG(metadata.st_mode):
        raise HTTPException(status_code=400, detail="Only regular files can be downloaded")
    local_file = await run_file_operation(open, local_path, "rb")
    audit(request, "file.download", local.username, path=local_path)

    async def stream_file() -> AsyncIterator[bytes]:
        try:
            while chunk := await asyncio.to_thread(local_file.read, IO_CHUNK_BYTES):
                local.touch()
                yield chunk
        except OSError:
            logger.exception("Local download failed during transfer")
            raise
        finally:
            await asyncio.to_thread(local_file.close)

    filename = posixpath.basename(local_path) or "download"
    media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return StreamingResponse(
        stream_file(),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"},
    )


@router.post("/api/upload")
async def upload_file(
    request: Request,
    path: str,
    overwrite: bool = False,
    file: UploadFile = File(...),
) -> dict[str, str]:
    verify_csrf(request)
    local = require_local_session(request)
    try:
        directory = normalize_local_path(path)
        filename = validate_name(posixpath.basename((file.filename or "").replace("\\", "/")))
        destination = posixpath.join(directory, filename)

        existing = await run_file_operation(lstat_or_none, destination)
        if existing is not None:
            if stat.S_ISDIR(existing.st_mode):
                raise HTTPException(status_code=400, detail=f"A folder named {filename} already exists here")
            if not overwrite:
                raise HTTPException(status_code=409, detail=f"{filename} already exists")

        temporary_path = posixpath.join(directory, f".webssh-upload-{secrets.token_hex(16)}")
        try:
            await file.seek(0)
            await asyncio.to_thread(copy_upload, file.file, temporary_path)
            await asyncio.to_thread(os.replace, temporary_path, destination)
        except BaseException as exc:
            try:
                await asyncio.to_thread(os.unlink, temporary_path)
            except FileNotFoundError:
                pass
            except OSError:
                logger.exception("Unable to remove a partial local upload")
            if isinstance(exc, OSError):
                raise local_file_error(exc) from exc
            raise
    finally:
        await file.close()

    local.touch()
    audit(request, "file.upload", local.username, path=destination, replaced=existing is not None)
    return {"name": filename, "path": destination}


@router.post("/api/files/mkdir")
async def make_directory(request: Request) -> dict[str, str]:
    verify_csrf(request)
    local = require_local_session(request)
    body = await read_json_object(request)
    target = posixpath.join(normalize_local_path(body.get("path")), validate_name(body.get("name")))
    await run_file_operation(os.mkdir, target)
    audit(request, "file.mkdir", local.username, path=target)
    return {"path": target}


@router.post("/api/files/rename")
async def rename_file(request: Request) -> dict[str, str]:
    verify_csrf(request)
    local = require_local_session(request)
    body = await read_json_object(request)
    source = require_not_root(normalize_local_path(body.get("path")))
    target = posixpath.join(posixpath.dirname(source), validate_name(body.get("name")))
    if target != source:
        await run_file_operation(rename_path, source, target)
        audit(request, "file.rename", local.username, source=source, target=target)
    return {"path": target}


@router.post("/api/files/delete")
async def delete_file(request: Request) -> dict[str, bool]:
    verify_csrf(request)
    local = require_local_session(request)
    body = await read_json_object(request)
    target = require_not_root(normalize_local_path(body.get("path")))
    await run_file_operation(delete_path, target)
    audit(request, "file.delete", local.username, path=target)
    return {"ok": True}


async def _transfer(request: Request, move: bool) -> dict[str, str]:
    verify_csrf(request)
    local = require_local_session(request)
    body = await read_json_object(request)
    source = require_not_root(normalize_local_path(body.get("source")))
    destination = normalize_local_path(body.get("destination"))
    target = posixpath.join(destination, posixpath.basename(source))
    await run_file_operation(transfer_path, source, target, move)
    audit(request, "file.move" if move else "file.copy", local.username, source=source, target=target)
    return {"path": target}


@router.post("/api/files/move")
async def move_file(request: Request) -> dict[str, str]:
    return await _transfer(request, move=True)


@router.post("/api/files/copy")
async def copy_file(request: Request) -> dict[str, str]:
    return await _transfer(request, move=False)

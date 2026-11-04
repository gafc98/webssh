import asyncio
import errno
import logging
import os
import time
from typing import Any, Callable


logger = logging.getLogger("webssh.terminal")

PTY_READ_BYTES = 64 * 1024
SCROLLBACK_BYTES = 256 * 1024
QUEUE_HIGH_WATER = 64
QUEUE_LOW_WATER = 16

EXITED = object()
REPLACED = object()


class Terminal:
    """A shell on a PTY that outlives individual WebSocket connections.

    Output is always drained into a bounded scrollback so the shell never blocks
    while detached; an attached client receives the scrollback, then live output.
    """

    def __init__(
        self,
        terminal_id: str,
        title: str,
        process: Any,
        on_exit: Callable[["Terminal"], None],
    ) -> None:
        self.id = terminal_id
        self.title = title
        self.process = process
        self.fd: int = process.fd
        self.exited = False
        self.closed = False
        self.detached_at: float | None = time.monotonic()
        self._on_exit = on_exit
        self._loop = asyncio.get_running_loop()
        self._scrollback = bytearray()
        self._client: asyncio.Queue[object] | None = None
        self._reading = False
        os.set_blocking(self.fd, False)
        self._resume_reading()

    @property
    def attached(self) -> bool:
        return self._client is not None

    def _resume_reading(self) -> None:
        if not self._reading and not self.exited:
            self._loop.add_reader(self.fd, self._on_readable)
            self._reading = True

    def _pause_reading(self) -> None:
        if self._reading:
            self._loop.remove_reader(self.fd)
            self._reading = False

    def _on_readable(self) -> None:
        client = self._client
        if client is not None and client.qsize() >= QUEUE_HIGH_WATER:
            self._pause_reading()
            return
        try:
            data = os.read(self.fd, PTY_READ_BYTES)
        except BlockingIOError:
            return
        except OSError as exc:
            if exc.errno != errno.EIO:
                logger.warning("Terminal %s read failed: %s", self.id, exc)
            data = b""
        if not data:
            self._finish()
            return
        self._scrollback += data
        excess = len(self._scrollback) - SCROLLBACK_BYTES
        if excess > 0:
            del self._scrollback[:excess]
        if client is not None:
            client.put_nowait(data)

    def _finish(self) -> None:
        if self.exited:
            return
        self._pause_reading()
        self.exited = True
        if self._client is not None:
            self._client.put_nowait(EXITED)
        self._on_exit(self)

    def attach(self) -> asyncio.Queue[object]:
        if self._client is not None:
            self._client.put_nowait(REPLACED)
        queue: asyncio.Queue[object] = asyncio.Queue()
        if self._scrollback:
            queue.put_nowait(bytes(self._scrollback))
        if self.exited:
            queue.put_nowait(EXITED)
        self._client = queue
        self.detached_at = None
        self._resume_reading()
        return queue

    def detach(self, queue: asyncio.Queue[object]) -> None:
        if self._client is queue:
            self._client = None
            self.detached_at = time.monotonic()
            self._resume_reading()

    def consumed(self, queue: asyncio.Queue[object]) -> None:
        if self._client is queue and queue.qsize() <= QUEUE_LOW_WATER:
            self._resume_reading()

    async def write(self, data: bytes) -> None:
        view = memoryview(data)
        while view and not self.exited:
            try:
                written = os.write(self.fd, view)
            except BlockingIOError:
                ready = self._loop.create_future()
                self._loop.add_writer(self.fd, lambda: ready.done() or ready.set_result(None))
                try:
                    await ready
                finally:
                    self._loop.remove_writer(self.fd)
                continue
            view = view[written:]

    def resize(self, rows: int, cols: int) -> None:
        if not self.exited:
            self.process.setwinsize(rows, cols)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._pause_reading()
        if not self.exited:
            self.exited = True
            if self._client is not None:
                self._client.put_nowait(EXITED)
        await asyncio.to_thread(self._terminate)

    def _terminate(self) -> None:
        try:
            if not self.process.closed:
                self.process.close(force=True)
        except Exception:
            logger.exception("Unable to stop terminal %s", self.id)

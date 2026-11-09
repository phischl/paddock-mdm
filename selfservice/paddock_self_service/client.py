"""Client of paddockd's self-service socket: JSON over HTTP/1.1 on an AF_UNIX stream socket (plan M13b §6.2).

The agent authenticates the caller by its peer credentials, so the client sends nothing but the request itself.
"""

from __future__ import annotations

import http.client
import json
import math
import socket
import threading
import time
from collections import deque
from typing import Any, Callable

from .model import AppView, Operation, Status, parse_apps, plain, valid_id

SOCKET_PATH = "/run/paddock/selfservice.sock"
TIMEOUT = 10.0
# The agent's replies are small; the bound stops a broken peer from filling memory.
MAX_BODY = 1 << 20
# The server's limit of a catalog icon (software.MaxIconBytes, plan M13b amendment A10-14).
MAX_ICON = 64 * 1024
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
# The compiler's limit of an icon's dimensions (software.ValidateIcon); the agent checks only magic and size, and a
# small PNG can declare a huge canvas that GdkTexture would allocate in full.
MAX_ICON_SIDE = 512
# The agent allows RatePerMinute = 60 requests per UID and minute (agent/internal/selfservice/server.go). Requests the
# app makes on its own (polling, icons) stay within BACKGROUND_PER_MINUTE, so that what the user clicks still fits.
RATE_WINDOW = 60.0
BACKGROUND_PER_MINUTE = 40
DEFAULT_RETRY_AFTER = 60
MAX_RETRY_AFTER = 300


class AgentUnavailable(Exception):
    """The socket is missing, refuses the connection or answers with something that is not the agent's protocol
    (plan M13b §3.7 F1)."""


class TooLarge(AgentUnavailable):
    """The reply exceeds the bound of its endpoint."""


class Problem(Exception):
    """A problem object {code, detail} the agent answered with; retry_after is set for 429."""

    def __init__(self, status: int, code: str, detail: str, retry_after: int = 0) -> None:
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code
        self.detail = detail
        self.retry_after = retry_after


class Budget:
    """Counts the app's requests in a sliding window and remembers a 429's Retry-After. A sliding window of at most
    n requests per RATE_WINDOW never puts more than n into one of the agent's fixed one-minute windows."""

    def __init__(self, clock: Callable[[], float], background: int = BACKGROUND_PER_MINUTE) -> None:
        self._clock = clock
        self._background = background
        self._sent: deque[float] = deque()
        self._blocked_until = 0.0
        self._lock = threading.Lock()

    def _forget(self, now: float) -> None:
        while self._sent and now - self._sent[0] >= RATE_WINDOW:
            self._sent.popleft()

    def record(self) -> None:
        with self._lock:
            now = self._clock()
            self._forget(now)
            self._sent.append(now)

    def block(self, seconds: int) -> None:
        with self._lock:
            self._blocked_until = max(self._blocked_until, self._clock() + seconds)

    def wait(self) -> int:
        """Seconds until a background request may be sent; 0 when it may be sent now."""
        with self._lock:
            now = self._clock()
            self._forget(now)
            delay = max(0.0, self._blocked_until - now)
            if len(self._sent) >= self._background:
                delay = max(delay, self._sent[len(self._sent) - self._background] + RATE_WINDOW - now)
            return math.ceil(delay)


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


class Client:
    """Talks to paddockd; one connection per request, so a restarted agent is picked up without state."""

    def __init__(
        self, path: str = SOCKET_PATH, timeout: float = TIMEOUT, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._path = path
        self._timeout = timeout
        self.budget = Budget(clock)

    def _request(self, method: str, path: str, limit: int = MAX_BODY) -> tuple[int, str, bytes, int]:
        """Send one request; returns status, content type, body and, for 429, the Retry-After seconds."""
        conn = _UnixConnection(self._path, self._timeout)
        try:
            self.budget.record()
            conn.request(method, path, body=b"" if method == "POST" else None, headers={"Accept": "application/json"})
            resp = conn.getresponse()
            retry_after = 0
            # Only the rate limit sends Retry-After; a full queue (busy) is also 429 but must not pause the app.
            if resp.status == 429 and resp.getheader("Retry-After") is not None:
                retry_after = _retry_after(resp.getheader("Retry-After"))
                self.budget.block(retry_after)
            body = resp.read(limit + 1)
            if len(body) > limit:
                raise TooLarge(f"{method} {path}: the reply exceeds {limit} bytes")
            return resp.status, resp.getheader("Content-Type", "") or "", body, retry_after
        except (OSError, http.client.HTTPException) as exc:
            raise AgentUnavailable(f"{method} {path}: {exc}") from exc
        finally:
            conn.close()

    def _json(self, method: str, path: str, ok: int = 200) -> Any:
        status, _, body, retry_after = self._request(method, path)
        data = _decode(body)
        if status != ok:
            raise _problem(status, data, retry_after)
        if data is None:
            raise AgentUnavailable(f"{method} {path}: the reply is not JSON")
        return data

    def status(self) -> Status:
        return Status.parse(self._json("GET", "/v1/status"))

    def apps(self) -> list[AppView]:
        return parse_apps(self._json("GET", "/v1/apps"))

    def app(self, entry_id: str) -> AppView | None:
        _check_id(entry_id)
        return AppView.parse(self._json("GET", f"/v1/apps/{entry_id}"))

    def icon(self, entry_id: str) -> bytes | None:
        """Return the PNG of an entry, or None when the agent has none (404) or what it sent is not a PNG of at most
        MAX_ICON bytes and MAX_ICON_SIDE pixels a side; the app then shows the category glyph. Both are final. Any
        other answer raises (Problem, AgentUnavailable), so that the caller tries again later."""
        _check_id(entry_id)
        try:
            status, content_type, body, retry_after = self._request("GET", f"/v1/apps/{entry_id}/icon", limit=MAX_ICON)
        except TooLarge:
            return None
        if status == 404:
            return None
        if status != 200:
            raise _problem(status, _decode(body), retry_after)
        if content_type.split(";")[0].strip() != "image/png" or not _png_within(body, MAX_ICON_SIDE):
            return None
        return body

    def act(self, entry_id: str, action: str) -> str:
        """Queue install, remove or update of an entry and return the operation ID."""
        _check_id(entry_id)
        if action not in ("install", "remove", "update"):
            raise ValueError(f"unknown action {action!r}")
        data = self._json("POST", f"/v1/apps/{entry_id}/{action}", ok=202)
        op_id = data.get("operation_id") if isinstance(data, dict) else None
        if not valid_id(op_id):
            raise AgentUnavailable("the reply names no operation")
        return op_id

    def operation(self, op_id: str) -> Operation:
        _check_id(op_id)
        op = Operation.parse(self._json("GET", f"/v1/operations/{op_id}"))
        if op is None:
            raise AgentUnavailable("the reply is not an operation")
        return op


def _check_id(value: str) -> None:
    if not valid_id(value):
        raise ValueError("invalid ID")


def _png_within(body: bytes, side: int) -> bool:
    """Report whether body is a PNG whose IHDR declares at most side pixels in width and height."""
    if len(body) < 24 or not body.startswith(PNG_MAGIC) or body[12:16] != b"IHDR":
        return False
    width = int.from_bytes(body[16:20], "big")
    height = int.from_bytes(body[20:24], "big")
    return 0 < width <= side and 0 < height <= side


def _retry_after(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError:
        return DEFAULT_RETRY_AFTER
    return min(max(seconds, 1), MAX_RETRY_AFTER)


def _decode(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None


def _problem(status: int, data: Any, retry_after: int = 0) -> Problem:
    d = data if isinstance(data, dict) else {}
    return Problem(status, plain(d.get("code"), 64) or "internal", plain(d.get("detail"), 500), retry_after)

"""A fake paddockd self-service socket for the tests: the endpoints of plan M13b §6.2 on a real AF_UNIX socket."""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import struct
import tempfile
import threading
import zlib


def png(width: int, height: int) -> bytes:
    """The signature and IHDR chunk of a 1-bit grayscale PNG of the given size, padded; enough for the client's
    checks, which read only the header."""
    ihdr = struct.pack(">IIBBBBB", width, height, 1, 0, 0, 0, 0)
    chunk = struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    return b"\x89PNG\r\n\x1a\n" + chunk + b"\x00" * 16


PNG = png(48, 48)


def app(entry_id: str, name: str, **kw) -> dict:
    base = {
        "entry_id": entry_id,
        "name": name,
        "description": "",
        "category": "",
        "kind": "apt",
        "scope": "system",
        "intent": "available",
        "managed": False,
        "installable": False,
        "removable": False,
        "updatable": False,
        "state": "absent",
        "icon": False,
    }
    base.update(kw)
    return base


class FakeAgent:
    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="paddock-ss-")
        self.path = os.path.join(self.dir, "selfservice.sock")
        self.status = {
            "agent_version": "0.10.0",
            "bundle_version": 7,
            "notice": "",
            "user": {"name": "alice@example.org", "directory": True},
            "queue": 0,
        }
        self.apps: list[dict] = []
        self.icons: dict[str, tuple[str, bytes]] = {}
        self.refusals: dict[str, tuple[int, str]] = {}
        self.no_bundle = False
        self.op_states: list[str] = ["queued", "running", "succeeded"]
        self.op_reason = ""
        self.ops: dict[str, dict] = {}
        self.requests: list[tuple[str, str]] = []
        self.raw: bytes | None = None
        self.problem: tuple[int, str] | None = None
        # The agent's per-UID rate limit (server.go allow): a fixed window that starts with the first request after
        # the previous one ended, refused requests counted too. None disables it; clock is the time source.
        self.rate_limit: int | None = None
        self.clock = None
        self.limited = 0
        self._window: list[float] | None = None
        self._server: socketserver.UnixStreamServer | None = None

    def start(self) -> FakeAgent:
        agent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:  # the default logs the client address, which a unix socket lacks
                pass

            def do_GET(self) -> None:
                agent._handle(self, "GET")

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                agent._handle(self, "POST")

        self._server = socketserver.ThreadingUnixStreamServer(self.path, Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, args=(0.02,), daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if os.path.exists(self.path):
            os.unlink(self.path)

    def app_by_id(self, entry_id: str) -> dict | None:
        return next((a for a in self.apps if a["entry_id"] == entry_id), None)

    def _reply(self, h, status: int, body, content_type: str = "application/json", headers: dict | None = None) -> None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.send_response(status)
        for name, value in (headers or {}).items():
            h.send_header(name, value)
        h.send_header("Content-Type", content_type)
        h.send_header("Content-Length", str(len(data)))
        h.end_headers()
        h.wfile.write(data)

    def _problem(self, h, status: int, code: str) -> None:
        self._reply(h, status, {"code": code, "detail": code.replace("_", " ")})

    def _rate_limited(self) -> bool:
        if self.rate_limit is None:
            return False
        now = self.clock()
        if self._window is None or now - self._window[0] >= 60:
            self._window = [now, 0]
        self._window[1] += 1
        return self._window[1] > self.rate_limit

    def _handle(self, h, method: str) -> None:
        self.requests.append((method, h.path))
        if self._rate_limited():
            self.limited += 1
            self._reply(h, 429, {"code": "rate_limited", "detail": "too many requests"}, headers={"Retry-After": "60"})
            return
        if self.problem is not None:
            self._problem(h, *self.problem)
            return
        if self.raw is not None:
            self._reply(h, 200, self.raw)
            return
        if self.no_bundle:
            self._problem(h, 503, "no_bundle")
            return
        parts = h.path.strip("/").split("/")
        if method == "GET" and h.path == "/v1/status":
            self._reply(h, 200, self.status)
        elif method == "GET" and h.path == "/v1/apps":
            self._reply(h, 200, {"apps": self.apps})
        elif method == "GET" and len(parts) == 3 and parts[1] == "apps":
            a = self.app_by_id(parts[2])
            self._reply(h, 200, a) if a else self._problem(h, 404, "unknown_entry")
        elif method == "GET" and len(parts) == 4 and parts[3] == "icon":
            if parts[2] in self.icons:
                ctype, data = self.icons[parts[2]]
                self._reply(h, 200, data, ctype)
            else:
                self._problem(h, 404, "not_found")
        elif method == "POST" and len(parts) == 4 and parts[1] == "apps":
            entry_id, action = parts[2], parts[3]
            if entry_id in self.refusals:
                status, code = self.refusals[entry_id]
                self._problem(h, status, code)
                return
            op_id = f"op{len(self.ops) + 1}"
            self.ops[op_id] = {"entry_id": entry_id, "action": action, "polls": 0}
            self._reply(h, 202, {"operation_id": op_id})
        elif method == "GET" and len(parts) == 3 and parts[1] == "operations":
            op = self.ops.get(parts[2])
            if op is None:
                self._problem(h, 404, "not_found")
                return
            state = self.op_states[min(op["polls"], len(self.op_states) - 1)]
            op["polls"] += 1
            if state == "succeeded":
                a = self.app_by_id(op["entry_id"])
                if a is not None:
                    a.update(
                        state="installed" if op["action"] != "remove" else "absent",
                        installable=False,
                        removable=op["action"] != "remove",
                        updatable=op["action"] != "remove",
                    )
            self._reply(
                h,
                200,
                {
                    "id": parts[2],
                    "entry_id": op["entry_id"],
                    "action": op["action"],
                    "state": state,
                    "position": 2 if state == "queued" else 0,
                    "reason": self.op_reason if state in ("failed", "refused") else "",
                    "started_at": None,
                    "finished_at": None,
                },
            )
        else:
            self._problem(h, 404, "not_found")

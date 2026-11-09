"""Typed views of the socket's JSON (plan M13b §6.2), parsed defensively: the agent is trusted to authorize, but
names, descriptions and reasons originate from the organization's catalog and are only ever displayed as plain text.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

# Bounds keep a hostile or broken catalog from blowing up the layout; the portal enforces tighter limits already.
MAX_NAME = 200
MAX_DESCRIPTION = 4000
MAX_SHORT = 200
MAX_NOTICE = 4000

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

ACTIONS = ("install", "remove", "update")
ACTIVE_STATES = ("queued", "running")


def plain(value: Any, limit: int, multiline: bool = False) -> str:
    """Return value as display text: strings only, control and format characters (bidi overrides included)
    removed, at most limit characters."""
    if not isinstance(value, str):
        return ""
    out = []
    for ch in value:
        if ch == "\n" and multiline:
            out.append(ch)
            continue
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co"):
            continue
        out.append(ch)
        if len(out) >= limit:
            break
    return "".join(out).strip()


def valid_id(value: Any) -> bool:
    """Report whether value can be used as an entry or operation ID in a request path."""
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _bool(value: Any) -> bool:
    return value is True


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _obj(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class AppView:
    """One application as the agent shows it to the calling user."""

    entry_id: str
    name: str
    description: str
    category: str
    kind: str
    scope: str
    intent: str
    managed: bool
    installable: bool
    removable: bool
    updatable: bool
    state: str
    version: str
    reason: str
    icon: bool

    @classmethod
    def parse(cls, data: Any) -> AppView | None:
        """Return the app of one JSON object, or None when it has no usable entry ID."""
        d = _obj(data)
        if not valid_id(d.get("entry_id")):
            return None
        return cls(
            entry_id=d["entry_id"],
            name=plain(d.get("name"), MAX_NAME),
            description=plain(d.get("description"), MAX_DESCRIPTION, multiline=True),
            category=plain(d.get("category"), MAX_SHORT),
            kind=plain(d.get("kind"), MAX_SHORT),
            scope=plain(d.get("scope"), MAX_SHORT),
            intent=plain(d.get("intent"), MAX_SHORT),
            managed=_bool(d.get("managed")),
            installable=_bool(d.get("installable")),
            removable=_bool(d.get("removable")),
            updatable=_bool(d.get("updatable")),
            state=plain(d.get("state"), MAX_SHORT),
            version=plain(d.get("version"), MAX_SHORT),
            reason=plain(d.get("reason"), MAX_SHORT),
            icon=_bool(d.get("icon")),
        )


def parse_apps(data: Any) -> list[AppView]:
    """Return the apps of GET /v1/apps, dropping entries without a usable ID."""
    items = _obj(data).get("apps")
    if not isinstance(items, list):
        return []
    apps = [AppView.parse(item) for item in items]
    return [a for a in apps if a is not None]


@dataclass(frozen=True)
class Status:
    """GET /v1/status."""

    agent_version: str
    bundle_version: int
    notice: str
    user_name: str
    directory: bool
    queue: int

    @classmethod
    def parse(cls, data: Any) -> Status:
        d = _obj(data)
        user = _obj(d.get("user"))
        return cls(
            agent_version=plain(d.get("agent_version"), MAX_SHORT),
            bundle_version=_int(d.get("bundle_version")),
            notice=plain(d.get("notice"), MAX_NOTICE, multiline=True),
            user_name=plain(user.get("name"), MAX_SHORT),
            directory=_bool(user.get("directory")),
            queue=_int(d.get("queue")),
        )


@dataclass(frozen=True)
class Operation:
    """GET /v1/operations/{id}."""

    id: str
    entry_id: str
    action: str
    state: str
    position: int
    reason: str

    @property
    def active(self) -> bool:
        return self.state in ACTIVE_STATES

    @classmethod
    def parse(cls, data: Any) -> Operation | None:
        d = _obj(data)
        if not valid_id(d.get("id")):
            return None
        return cls(
            id=d["id"],
            entry_id=plain(d.get("entry_id"), MAX_SHORT),
            action=plain(d.get("action"), MAX_SHORT),
            state=plain(d.get("state"), MAX_SHORT),
            position=_int(d.get("position")),
            reason=plain(d.get("reason"), MAX_SHORT),
        )

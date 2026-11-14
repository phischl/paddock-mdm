"""The first-start transparency notice (plan M13b §3.5, §6.5): shown once per notice text, remembered in
`~/.config/paddock-self-service/state.json` — the only place the app writes to."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile

from .i18n import _

# The agent's default text (agent/internal/selfservice DefaultNotice); while the organization sets none, a German
# session shows the German default instead of the English one.
DEFAULT_NOTICE = (
    "Your organization offers applications through Paddock. Installing, updating or removing an application here is "
    "recorded with your user name. Nothing else about how you use this device is collected."
)


def config_dir() -> str:
    """`$XDG_CONFIG_HOME/paddock-self-service`, by default `~/.config/paddock-self-service`."""
    base = os.environ.get("XDG_CONFIG_HOME") or ""
    if not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "paddock-self-service")


def display_text(notice: str) -> str:
    """The notice to show: the organization's text, the localized default for the agent's default or no text."""
    if not notice or notice == DEFAULT_NOTICE:
        return _(DEFAULT_NOTICE)
    return notice


class NoticeState:
    """Remembers which notice text the user has acknowledged; a changed text is shown again."""

    def __init__(self, directory: str | None = None) -> None:
        self._dir = directory or config_dir()
        self._path = os.path.join(self._dir, "state.json")

    def _load(self) -> dict:
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def needs(self, text: str) -> bool:
        """Report whether text has not been acknowledged yet."""
        return self._load().get("notice_sha256") != self._digest(text)

    def acknowledge(self, text: str) -> None:
        """Record text as acknowledged (atomic replace, 0600 in a 0700 directory)."""
        os.makedirs(self._dir, mode=0o700, exist_ok=True)
        data = self._load()
        data["notice_sha256"] = self._digest(text)
        fd, tmp = tempfile.mkstemp(dir=self._dir, prefix=".state-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

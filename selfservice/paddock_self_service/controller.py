"""The app's behaviour without GTK: loading, the first-start notice, operations with polling, icons, and the banner
for an agent that is not running (F1) or has no policy yet (F2) — plan M13b §3.5, §3.7.

Socket calls run through a Scheduler so that the window never blocks on the agent; the GTK view runs them on a
worker thread, the tests synchronously. Polling and icon loads are the app's own requests: one at a time each, and
only while Client.budget allows them, so that they stay below the agent's rate limit (plan M13b §6.2).
"""

from __future__ import annotations

from typing import Any, Callable, Protocol

from .client import AgentUnavailable, Client, Problem
from .i18n import _
from .model import AppView, Operation, Status
from .notice import DEFAULT_NOTICE, NoticeState, display_text
from .presenter import Activity, Card, card, reason_text

# One poll every POLL_SECONDS for all active operations together, round robin: 30 requests a minute however many
# operations the agent queued (MaxQueuedPerUser = 5).
POLL_SECONDS = 2
RETRY_SECONDS = 10


class Scheduler(Protocol):
    def submit(self, work: Callable[[], Any], done: Callable[[Any, BaseException | None], None]) -> None:
        """Run work off the UI thread, then done(result, error) on it."""

    def later(self, seconds: int, fn: Callable[[], None]) -> object:
        """Run fn on the UI thread after seconds; returns a handle for cancel."""

    def cancel(self, handle: object) -> None: ...


class View(Protocol):
    def show_banner(self, text: str) -> None:
        """Show text in the banner; an empty text hides it."""

    def show_apps(self, cards: list[Card]) -> None: ...

    def show_activity(self, rows: list[Activity]) -> None: ...

    def show_notice(self, text: str) -> None:
        """Show the first-start notice; the view calls Controller.acknowledge_notice when the user closes it."""

    def show_message(self, text: str) -> None:
        """A short message about the last action (a refusal with its reason)."""


class Controller:
    def __init__(self, client: Client, view: View, scheduler: Scheduler, notice_state: NoticeState) -> None:
        self._client = client
        self._view = view
        self._sched = scheduler
        self._notice_state = notice_state
        self._retry: object | None = None
        self._polling = False
        self._turn = 0
        self._notice_raw = ""
        self._acting: set[str] = set()
        self.status: Status | None = None
        self.apps: list[AppView] = []
        self.activity: list[Activity] = []

    def app(self, entry_id: str) -> AppView | None:
        return next((a for a in self.apps if a.entry_id == entry_id), None)

    def refresh(self) -> None:
        """Load status and apps; on F1/F2 show the banner and try again every RETRY_SECONDS."""
        if self._retry is not None:
            self._sched.cancel(self._retry)
            self._retry = None
        self._sched.submit(lambda: (self._client.status(), self._client.apps()), self._loaded)

    def _loaded(self, result: Any, error: BaseException | None) -> None:
        if error is not None:
            self._unavailable(error)
            return
        status, apps = result
        self._view.show_banner("")
        self.status, self.apps = status, apps
        self._view.show_apps([card(a) for a in apps])
        raw = status.notice or DEFAULT_NOTICE
        if raw != self._notice_raw and self._notice_state.needs(raw):
            self._notice_raw = raw
            self._view.show_notice(display_text(status.notice))

    def _unavailable(self, error: BaseException) -> None:
        self._view.show_banner(banner_text(error))
        self._retry = self._sched.later(retry_seconds(error), self.refresh)

    def acknowledge_notice(self) -> None:
        if self._notice_raw:
            self._notice_state.acknowledge(self._notice_raw)

    def act(self, entry_id: str, action: str) -> None:
        """Ask the agent for action on entry_id; a refusal is shown with its reason, an accepted operation polled.

        Ignored while entry_id has a request in flight or an active operation: the agent does not deduplicate, so a
        double click would queue a second apt run for the same intent."""
        if entry_id in self._acting or any(r.entry_id == entry_id and r.op_id and r.active for r in self.activity):
            return
        app = self.app(entry_id)
        name = app.name if app is not None and app.name else entry_id

        def done(op_id: Any, error: BaseException | None) -> None:
            self._acting.discard(entry_id)
            if isinstance(error, Problem) and error.status in (403, 404, 409, 429):
                row = Activity(
                    op_id="", entry_id=entry_id, name=name, action=action, state="refused", reason=error.code
                )
                self.activity.insert(0, row)
                self._view.show_activity(list(self.activity))
                self._view.show_message(_("{name}: {reason}").format(name=name, reason=reason_text(error.code)))
                return
            if error is not None:
                self._view.show_message(_("{name}: {reason}").format(name=name, reason=banner_text(error)))
                self._unavailable(error)
                return
            self.activity.insert(0, Activity(op_id=op_id, entry_id=entry_id, name=name, action=action, state="queued"))
            self._view.show_activity(list(self.activity))
            self._start_polling()

        self._acting.add(entry_id)
        self._sched.submit(lambda: self._client.act(entry_id, action), done)

    def _start_polling(self) -> None:
        """Poll at once for a new operation unless the poll timer already runs; it then joins the rotation."""
        if not self._polling:
            self._polling = True
            self._tick()

    def _tick(self) -> None:
        active = [r for r in reversed(self.activity) if r.op_id and r.active]
        if not active:
            self._polling = False
            return
        wait = self._client.budget.wait()
        if wait > 0:
            self._sched.later(wait, self._tick)
            return
        row = active[self._turn % len(active)]
        self._turn += 1

        def done(op: Operation | None, error: BaseException | None) -> None:
            delay = POLL_SECONDS
            if isinstance(error, Problem) and error.status == 404:
                # The agent restarted and forgot the operation (F4): its fate shows in the app's state.
                row.state, row.reason = "failed", "interrupted"
                self._view.show_activity(list(self.activity))
                self.refresh()
            elif isinstance(error, Problem) and error.code == "rate_limited":
                self._view.show_banner(reason_text(error.code))
                delay = max(POLL_SECONDS, error.retry_after)
            elif error is not None:
                self._view.show_banner(banner_text(error))
                delay = retry_seconds(error)
            else:
                assert op is not None
                self._view.show_banner("")
                row.update(op)
                self._view.show_activity(list(self.activity))
                if not row.active:
                    self.refresh()
            if any(r.op_id and r.active for r in self.activity):
                self._sched.later(delay, self._tick)
            else:
                self._polling = False

        self._sched.submit(lambda: self._client.operation(row.op_id), done)


class IconLoader:
    """Loads catalog icons one at a time within the budget. A PNG or a final None (no icon, not a usable PNG) is kept
    for the session; a refused or failed load is tried again later instead of being remembered as missing."""

    def __init__(self, client: Client, scheduler: Scheduler) -> None:
        self._client = client
        self._sched = scheduler
        self._done: dict[str, bytes | None] = {}
        self._waiting: dict[str, list[Callable[[bytes | None], None]]] = {}
        self._queue: list[str] = []
        self._busy = False

    def request(self, entry_id: str, deliver: Callable[[bytes | None], None]) -> None:
        """Call deliver with the icon of entry_id once it is known (at once when it is)."""
        if entry_id in self._done:
            deliver(self._done[entry_id])
            return
        if entry_id not in self._waiting:
            self._waiting[entry_id] = []
            self._queue.append(entry_id)
        self._waiting[entry_id].append(deliver)
        if not self._busy:
            self._busy = True
            self._next()

    def _next(self) -> None:
        if not self._queue:
            self._busy = False
            return
        wait = self._client.budget.wait()
        if wait > 0:
            self._sched.later(wait, self._next)
            return
        entry_id = self._queue.pop(0)

        def done(data: bytes | None, error: BaseException | None) -> None:
            if error is not None:
                if not isinstance(error, (AgentUnavailable, Problem)):
                    raise error
                self._queue.append(entry_id)
                self._sched.later(retry_seconds(error), self._next)
                return
            self._done[entry_id] = data
            for deliver in self._waiting.pop(entry_id, []):
                deliver(data)
            self._next()

        self._sched.submit(lambda: self._client.icon(entry_id), done)


def banner_text(error: BaseException) -> str:
    """The banner for a failed request: F1 only when the agent cannot be reached, a Problem as itself."""
    if isinstance(error, AgentUnavailable):
        return _("Paddock is not running. Trying again…")
    if not isinstance(error, Problem):
        raise error
    if error.code == "no_bundle":
        return _("Waiting for your organization's policy")
    if error.code in ("rate_limited", "unauthenticated"):
        return reason_text(error.code)
    return _("Paddock reported an error ({code}). Trying again…").format(code=error.code)


def retry_seconds(error: BaseException) -> int:
    if isinstance(error, Problem) and error.retry_after > 0:
        return max(RETRY_SECONDS, error.retry_after)
    return RETRY_SECONDS

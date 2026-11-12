"""Test doubles of the controller's scheduler and view."""

from __future__ import annotations

from typing import Any, Callable


class FakeClock:
    """A monotonic clock the tests advance; shared by the scheduler, the client's budget and the fake agent."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class SyncScheduler:
    """Runs work immediately and keeps timers until the test fires them."""

    def __init__(self, clock: FakeClock | None = None) -> None:
        self.clock = clock or FakeClock()
        self.timers: list[tuple[int, Callable[[], None], object, float]] = []

    def submit(self, work: Callable[[], Any], done: Callable[[Any, BaseException | None], None]) -> None:
        try:
            result = work()
        except Exception as exc:  # the GTK scheduler hands every error to done as well
            done(None, exc)
            return
        done(result, None)

    def later(self, seconds: int, fn: Callable[[], None]) -> object:
        handle = object()
        self.timers.append((seconds, fn, handle, self.clock.now + seconds))
        return handle

    def cancel(self, handle: object) -> None:
        self.timers = [t for t in self.timers if t[2] is not handle]

    def fire(self) -> list[int]:
        """Run the pending timers once; returns their delays."""
        timers, self.timers = self.timers, []
        for t in timers:
            t[1]()
        return [t[0] for t in timers]

    def run_for(self, seconds: float) -> None:
        """Advance the clock by seconds, running each timer at its due time, earliest first."""
        end = self.clock.now + seconds
        while self.timers:
            first = min(self.timers, key=lambda t: t[3])
            if first[3] > end:
                break
            self.timers.remove(first)
            self.clock.now = max(self.clock.now, first[3])
            first[1]()
        self.clock.now = end


class FakeView:
    def __init__(self) -> None:
        self.banner = ""
        self.banners: list[str] = []
        self.cards: list = []
        self.activity: list = []
        self.notices: list[str] = []
        self.messages: list[str] = []

    def show_banner(self, text: str) -> None:
        self.banner = text
        self.banners.append(text)

    def show_apps(self, cards: list) -> None:
        self.cards = cards

    def show_activity(self, rows: list) -> None:
        self.activity = rows

    def show_notice(self, text: str) -> None:
        self.notices.append(text)

    def show_message(self, text: str) -> None:
        self.messages.append(text)

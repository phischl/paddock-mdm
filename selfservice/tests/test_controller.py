"""The app's behaviour against a fake socket (ticket PDK-802 acceptance criteria; plan M13b §3.5, §3.7 F1, F2)."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest

from paddock_self_service import i18n
from paddock_self_service.client import Client
from paddock_self_service.client import BACKGROUND_PER_MINUTE
from paddock_self_service.controller import POLL_SECONDS, RETRY_SECONDS, Controller, IconLoader
from paddock_self_service.notice import DEFAULT_NOTICE, NoticeState

from fakeagent import PNG, FakeAgent, app
from support import FakeView, SyncScheduler


class ControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        i18n.setup(languages=["en"])
        self.agent = FakeAgent().start()
        self.addCleanup(self.agent.stop)
        self.addCleanup(shutil.rmtree, self.agent.dir, True)
        self.config = tempfile.mkdtemp(prefix="paddock-ss-config-")
        self.addCleanup(shutil.rmtree, self.config, True)
        self.view = FakeView()
        self.sched = SyncScheduler()

    def controller(self, path: str | None = None) -> Controller:
        state = NoticeState(os.path.join(self.config, "paddock-self-service"))
        return Controller(self.client(path), self.view, self.sched, state)

    def client(self, path: str | None = None) -> Client:
        return Client(path or self.agent.path, timeout=5, clock=self.sched.clock)

    def enforce_agent_rate(self) -> None:
        """The agent's limits from agent/internal/selfservice/server.go: RatePerMinute = 60 per UID."""
        self.agent.rate_limit = 60
        self.agent.clock = self.sched.clock

    def test_list_renders_each_state(self) -> None:
        self.agent.apps = [
            app("e-absent", "gimp", installable=True),
            app("e-installed", "code", state="installed", removable=True, updatable=True, version="1.2"),
            app("e-pending", "vlc", state="pending"),
            app("e-failed", "inkscape", state="failed", reason="source_unreachable", installable=True),
            app("e-managed", "firefox", state="installed", intent="required", managed=True),
        ]
        c = self.controller()
        c.refresh()
        cards = {card.entry_id: card for card in self.view.cards}
        self.assertEqual(len(cards), 5)
        self.assertEqual((cards["e-absent"].chip, cards["e-absent"].actions), ("Not installed", ("install",)))
        self.assertEqual((cards["e-installed"].chip, cards["e-installed"].actions), ("Installed", ("update", "remove")))
        self.assertEqual((cards["e-pending"].chip, cards["e-pending"].actions), ("In progress", ()))
        self.assertEqual(cards["e-failed"].chip, "Failed")
        self.assertEqual(cards["e-failed"].detail, "The package source cannot be reached")
        self.assertEqual(cards["e-failed"].actions, ("install",))
        self.assertEqual(cards["e-managed"].actions, ())
        self.assertEqual(cards["e-managed"].managed_text, "Managed by your organization")
        self.assertEqual(self.view.banner, "")

    def test_install_polls_until_succeeded(self) -> None:
        self.agent.apps = [app("e1", "gimp", installable=True)]
        c = self.controller()
        c.refresh()
        c.act("e1", "install")
        self.assertEqual(self.view.activity[0].text(), "Queued (position 2)")
        self.assertEqual(self.view.activity[0].title(), "Install gimp")
        self.assertEqual(self.sched.fire(), [POLL_SECONDS])
        self.assertEqual(self.view.activity[0].text(), "Running")
        self.assertEqual(self.sched.fire(), [POLL_SECONDS])
        self.assertEqual(self.view.activity[0].text(), "Done")
        self.assertEqual(self.sched.timers, [], "no polling after the operation finished")
        self.assertEqual(self.view.cards[0].chip, "Installed", "the list is reloaded after the operation")
        polls = [p for m, p in self.agent.requests if p.startswith("/v1/operations/")]
        self.assertEqual(polls, ["/v1/operations/op1"] * 3)
        self.assertIn(("POST", "/v1/apps/e1/install"), self.agent.requests)

    def test_failed_operation_shows_its_reason(self) -> None:
        self.agent.apps = [app("e1", "gimp", installable=True)]
        self.agent.op_states = ["running", "failed"]
        self.agent.op_reason = "dpkg_locked"
        c = self.controller()
        c.refresh()
        c.act("e1", "install")
        self.sched.fire()
        self.assertEqual(self.view.activity[0].text(), "Failed: Another installation is running; try again")

    def test_refusal_is_shown_with_its_reason(self) -> None:
        self.agent.apps = [app("e1", "firefox", state="installed", removable=True)]
        self.agent.refusals["e1"] = (403, "required_by_policy")
        c = self.controller()
        c.refresh()
        c.act("e1", "remove")
        self.assertEqual(self.view.messages, ["firefox: Required by your organization"])
        self.assertEqual(self.view.activity[0].state, "refused")
        self.assertEqual(self.view.activity[0].text(), "Refused: Required by your organization")
        self.assertEqual(self.sched.timers, [], "a refused operation is not polled")

    def test_queue_limit_refusal(self) -> None:
        self.agent.apps = [app("e1", "gimp", installable=True)]
        self.agent.refusals["e1"] = (429, "busy")
        c = self.controller()
        c.refresh()
        c.act("e1", "install")
        self.assertEqual(self.view.messages, ["gimp: Too many operations are queued; try again later"])

    def test_notice_is_shown_once(self) -> None:
        self.agent.status["notice"] = "Our <b>works council</b> agreed."
        c = self.controller()
        c.refresh()
        self.assertEqual(self.view.notices, ["Our <b>works council</b> agreed."], "the text is passed on unchanged")
        c.acknowledge_notice()
        c.refresh()
        self.controller().refresh()
        self.assertEqual(len(self.view.notices), 1, "an acknowledged notice is not shown again, also after a restart")
        state_dir = os.path.join(self.config, "paddock-self-service")
        self.assertEqual(os.listdir(state_dir), ["state.json"])
        self.assertEqual(stat.S_IMODE(os.stat(state_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(state_dir, "state.json")).st_mode), 0o600)

    def test_notice_not_acknowledged_is_shown_again_at_next_start(self) -> None:
        self.controller().refresh()
        self.controller().refresh()
        self.assertEqual(self.view.notices, [DEFAULT_NOTICE, DEFAULT_NOTICE])

    def test_changed_notice_is_shown_again(self) -> None:
        c = self.controller()
        c.refresh()
        c.acknowledge_notice()
        self.agent.status["notice"] = "New text."
        self.controller().refresh()
        self.assertEqual(self.view.notices, [DEFAULT_NOTICE, "New text."])

    def test_agent_not_running_shows_banner_and_reconnects(self) -> None:
        missing = os.path.join(self.agent.dir, "later.sock")
        self.agent.apps = [app("e1", "gimp", installable=True)]
        c = self.controller(missing)
        c.refresh()
        self.assertEqual(self.view.banner, "Paddock is not running. Trying again…")
        self.assertEqual(self.view.cards, [])
        self.assertEqual(self.sched.fire(), [RETRY_SECONDS])
        self.assertEqual(self.view.banner, "Paddock is not running. Trying again…", "still down: still the banner")
        os.symlink(self.agent.path, missing)
        self.assertEqual(self.sched.fire(), [RETRY_SECONDS])
        self.assertEqual(self.view.banner, "")
        self.assertEqual([card.entry_id for card in self.view.cards], ["e1"])
        self.assertEqual(self.sched.timers, [])

    def test_no_bundle_shows_waiting_banner(self) -> None:
        self.agent.no_bundle = True
        c = self.controller()
        c.refresh()
        self.assertEqual(self.view.banner, "Waiting for your organization's policy")
        self.agent.no_bundle = False
        self.sched.fire()
        self.assertEqual(self.view.banner, "")

    def test_manual_refresh_does_not_stack_retries(self) -> None:
        c = self.controller(os.path.join(self.agent.dir, "missing.sock"))
        c.refresh()
        c.refresh()
        self.assertEqual(len(self.sched.timers), 1)

    def test_second_click_does_not_queue_a_duplicate_operation(self) -> None:
        self.agent.apps = [app("e1", "gimp", installable=True)]
        c = self.controller()
        c.refresh()
        c.act("e1", "install")
        c.act("e1", "install")
        self.sched.fire()
        c.act("e1", "install")
        posts = [p for m, p in self.agent.requests if m == "POST"]
        self.assertEqual(posts, ["/v1/apps/e1/install"], "one intent, one operation while it is active")
        self.assertEqual(len(self.view.activity), 1)

        self.sched.fire()
        self.assertEqual(self.view.activity[0].text(), "Done")
        c.act("e1", "update")
        posts = [p for m, p in self.agent.requests if m == "POST"]
        self.assertEqual(posts, ["/v1/apps/e1/install", "/v1/apps/e1/update"], "a new act after the operation ended")

    def test_click_while_the_request_is_in_flight_is_ignored(self) -> None:
        self.agent.apps = [app("e1", "gimp", installable=True)]
        c = self.controller()
        c.refresh()
        held: list = []
        run = self.sched.submit
        self.sched.submit = lambda work, done: held.append((work, done))
        c.act("e1", "install")
        c.act("e1", "install")
        self.sched.submit = run
        self.assertEqual(len(held), 1, "the second click is not sent while the first is in flight")
        run(*held[0])
        self.assertEqual(self.view.activity[0].state, "queued")

    def test_failed_request_leaves_a_message(self) -> None:
        self.agent.apps = [app("e1", "gimp", installable=True)]
        c = self.controller()
        c.refresh()
        self.agent.problem = (500, "internal")
        c.act("e1", "install")
        self.assertEqual(self.view.messages, ["gimp: Paddock reported an error (internal). Trying again…"])
        self.agent.problem = None
        self.sched.fire()
        self.assertEqual(self.view.banner, "")
        c.act("e1", "install")
        posts = [p for m, p in self.agent.requests if m == "POST"]
        self.assertEqual(posts, ["/v1/apps/e1/install"] * 2, "a failed request does not block the next click")

    def test_agent_restart_forgets_the_operation(self) -> None:
        self.agent.apps = [app("e1", "gimp", installable=True)]
        c = self.controller()
        c.refresh()
        c.act("e1", "install")
        self.agent.ops.clear()
        self.sched.fire()
        self.assertEqual(self.view.activity[0].text(), "Failed: Interrupted; try again")

    def test_agent_down_while_polling_keeps_polling(self) -> None:
        self.agent.apps = [app("e1", "gimp", installable=True)]
        c = self.controller()
        c.refresh()
        c.act("e1", "install")
        self.agent.stop()
        self.assertEqual(self.sched.fire(), [POLL_SECONDS])
        self.assertEqual(self.view.banner, "Paddock is not running. Trying again…")
        self.assertEqual([t[0] for t in self.sched.timers], [RETRY_SECONDS])

    def test_five_operations_stay_within_the_agent_rate(self) -> None:
        self.enforce_agent_rate()
        self.agent.apps = [app(f"e{i}", f"app{i}", installable=True) for i in range(6)]
        self.agent.op_states = ["queued"] * 40 + ["running"] * 10 + ["succeeded"]
        c = self.controller()
        c.refresh()
        for i in range(5):  # MaxQueuedPerUser = 5
            c.act(f"e{i}", "install")
        self.sched.run_for(300)
        self.assertEqual(self.agent.limited, 0, "no request was refused with rate_limited")
        self.assertNotIn("Paddock is not running. Trying again…", self.view.banners)
        polls = [p for _, p in self.agent.requests if p.startswith("/v1/operations/")]
        self.assertEqual({f"/v1/operations/op{i}" for i in range(1, 6)}, set(polls), "every operation is polled")
        self.assertLessEqual(len(polls), 300 // POLL_SECONDS + 5, "one poll per tick, not one per operation")
        timers = [t for t in self.sched.timers if t[1] == c._tick]
        self.assertEqual(len(timers), 1, "one poll timer for all operations")
        c.act("e5", "install")
        self.assertEqual(self.view.messages, [], "the user's click still fits into the rate")
        self.sched.run_for(900)
        self.assertEqual(self.agent.limited, 0)
        self.assertTrue(all(row.text() == "Done" for row in self.view.activity))
        self.assertEqual([t for t in self.sched.timers if t[1] == c._tick], [], "no polling after all finished")

    def test_rate_limited_poll_shows_the_hint_and_backs_off(self) -> None:
        self.agent.apps = [app("e1", "gimp", installable=True)]
        self.agent.op_states = ["queued", "running", "succeeded"]
        c = self.controller()
        c.refresh()
        c.act("e1", "install")
        self.enforce_agent_rate()
        self.agent.rate_limit = 0
        self.assertEqual(self.sched.fire(), [POLL_SECONDS])
        self.assertEqual(self.agent.limited, 1)
        self.assertEqual(self.view.banner, "Too many requests; try again in a minute")
        self.assertEqual([t[0] for t in self.sched.timers], [60], "the next poll waits for Retry-After")
        self.agent.rate_limit = 60
        self.sched.run_for(59)
        self.assertEqual(self.agent.limited, 1, "nothing is sent before Retry-After passed")
        self.sched.run_for(1)
        self.assertEqual(self.view.banner, "", "the next successful poll clears the hint")
        self.sched.run_for(2 * POLL_SECONDS)
        self.assertEqual(self.view.activity[0].text(), "Done")
        self.assertNotIn("Paddock is not running. Trying again…", self.view.banners)

    def test_problems_are_shown_as_themselves(self) -> None:
        cases = [
            ((429, "rate_limited"), "Too many requests; try again in a minute"),
            ((403, "unauthenticated"), "Paddock could not identify you"),
            ((500, "internal"), "Paddock reported an error (internal). Trying again…"),
        ]
        for problem, banner in cases:
            with self.subTest(problem=problem):
                self.agent.problem = problem
                self.sched.timers.clear()
                self.controller().refresh()
                self.assertEqual(self.view.banner, banner)
                self.assertEqual([t[0] for t in self.sched.timers], [RETRY_SECONDS])

    def test_rate_limited_refresh_waits_for_retry_after(self) -> None:
        self.enforce_agent_rate()
        self.agent.rate_limit = 0
        self.controller().refresh()
        self.assertEqual(self.view.banner, "Too many requests; try again in a minute")
        self.assertEqual([t[0] for t in self.sched.timers], [60])


class IconLoaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = FakeAgent().start()
        self.addCleanup(self.agent.stop)
        self.addCleanup(shutil.rmtree, self.agent.dir, True)
        self.sched = SyncScheduler()
        self.client = Client(self.agent.path, timeout=5, clock=self.sched.clock)
        self.loader = IconLoader(self.client, self.sched)
        self.got: dict[str, list] = {}

    def load(self, entry_id: str) -> None:
        self.loader.request(entry_id, lambda data: self.got.setdefault(entry_id, []).append(data))

    def icon_requests(self, entry_id: str) -> int:
        return self.agent.requests.count(("GET", f"/v1/apps/{entry_id}/icon"))

    def test_png_and_missing_icon_are_final(self) -> None:
        self.agent.icons = {"e1": ("image/png", PNG)}
        self.load("e1")
        self.load("e2")
        self.load("e1")
        self.load("e2")
        self.assertEqual(self.got, {"e1": [PNG, PNG], "e2": [None, None]})
        self.assertEqual((self.icon_requests("e1"), self.icon_requests("e2")), (1, 1), "kept for the session")

    def test_refused_icon_is_tried_again_not_cached_as_missing(self) -> None:
        self.agent.icons = {"e1": ("image/png", PNG)}
        self.agent.rate_limit, self.agent.clock = 0, self.sched.clock
        self.load("e1")
        self.assertEqual(self.got, {}, "a 429 is not delivered as no icon")
        self.assertEqual([t[0] for t in self.sched.timers], [60])
        self.agent.rate_limit = 60
        self.sched.run_for(60)
        self.assertEqual(self.got, {"e1": [PNG]})

    def test_unreachable_agent_is_tried_again(self) -> None:
        self.agent.icons = {"e1": ("image/png", PNG)}
        self.agent.problem = (503, "internal")
        self.load("e1")
        self.assertEqual(self.got, {})
        self.agent.problem = None
        self.sched.run_for(RETRY_SECONDS)
        self.assertEqual(self.got, {"e1": [PNG]})

    def test_many_icons_are_spread_within_the_rate(self) -> None:
        self.agent.rate_limit, self.agent.clock = 60, self.sched.clock
        self.agent.icons = {f"e{i}": ("image/png", PNG) for i in range(150)}
        for i in range(150):
            self.load(f"e{i}")
        self.assertEqual(len(self.got), BACKGROUND_PER_MINUTE, "the first minute's share of the budget")
        self.sched.run_for(240)
        self.assertEqual(len(self.got), 150)
        self.assertEqual(self.agent.limited, 0)


if __name__ == "__main__":
    unittest.main()

"""The socket client against a fake agent: parsing, problems, icons and what it refuses to send."""

from __future__ import annotations

import os
import shutil
import unittest

from paddock_self_service.client import BACKGROUND_PER_MINUTE, MAX_ICON, AgentUnavailable, Budget, Client, Problem

from fakeagent import PNG, FakeAgent, app, png
from support import FakeClock


class ClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = FakeAgent().start()
        self.addCleanup(self.agent.stop)
        self.addCleanup(shutil.rmtree, self.agent.dir, True)
        self.client = Client(self.agent.path, timeout=5)

    def test_status(self) -> None:
        st = self.client.status()
        self.assertEqual(
            (st.agent_version, st.bundle_version, st.user_name, st.directory), ("0.10.0", 7, "alice@example.org", True)
        )

    def test_apps_drop_entries_without_usable_id(self) -> None:
        self.agent.apps = [app("e1", "gimp"), app("../../v1/status", "evil"), {"name": "no id"}, "junk"]
        self.assertEqual([a.entry_id for a in self.client.apps()], ["e1"])

    def test_problem_carries_status_and_code(self) -> None:
        self.agent.refusals["e1"] = (403, "not_in_audience")
        with self.assertRaises(Problem) as ctx:
            self.client.act("e1", "install")
        self.assertEqual((ctx.exception.status, ctx.exception.code), (403, "not_in_audience"))

    def test_act_returns_operation_and_posts_once(self) -> None:
        self.assertEqual(self.client.act("e1", "install"), "op1")
        self.assertEqual(self.agent.requests, [("POST", "/v1/apps/e1/install")])
        op = self.client.operation("op1")
        self.assertEqual((op.state, op.position, op.active), ("queued", 2, True))

    def test_ids_and_actions_are_checked_before_sending(self) -> None:
        for bad in ("../status", "a/b", "", "e1?x=1", "e 1"):
            with self.assertRaises(ValueError):
                self.client.act(bad, "install")
        with self.assertRaises(ValueError):
            self.client.act("e1", "purge")
        self.assertEqual(self.agent.requests, [])

    def test_missing_socket_is_agent_unavailable(self) -> None:
        with self.assertRaises(AgentUnavailable):
            Client(os.path.join(self.agent.dir, "missing.sock")).status()

    def test_non_json_reply_is_agent_unavailable(self) -> None:
        self.agent.raw = b"<html>not the agent</html>"
        with self.assertRaises(AgentUnavailable):
            self.client.status()

    def test_icon_accepts_only_png_within_limit(self) -> None:
        self.agent.icons = {
            "ok": ("image/png", PNG),
            "svg": ("image/svg+xml", b"<svg/>"),
            "fake": ("image/png", b"GIF89a"),
            "big": ("image/png", PNG + b"\x00" * MAX_ICON),
        }
        self.assertEqual(self.client.icon("ok"), PNG)
        for entry in ("svg", "fake", "big", "none"):
            self.assertIsNone(self.client.icon(entry), entry)

    def test_icon_rejects_canvas_larger_than_512(self) -> None:
        self.agent.icons = {
            "max": ("image/png", png(512, 512)),
            "wide": ("image/png", png(513, 16)),
            "huge": ("image/png", png(22000, 22000)),
            "zero": ("image/png", png(0, 16)),
            "no-ihdr": ("image/png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32),
        }
        self.assertEqual(self.client.icon("max"), png(512, 512))
        for entry in ("wide", "huge", "zero", "no-ihdr"):
            self.assertIsNone(self.client.icon(entry), entry)

    def test_icon_refusal_raises_instead_of_none(self) -> None:
        self.agent.problem = (503, "no_bundle")
        with self.assertRaises(Problem):
            self.client.icon("e1")
        os.unlink(self.agent.path)
        with self.assertRaises(AgentUnavailable):
            self.client.icon("e1")

    def test_rate_limit_sets_retry_after_and_pauses_background_requests(self) -> None:
        clock = FakeClock()
        client = Client(self.agent.path, timeout=5, clock=clock)
        self.agent.rate_limit, self.agent.clock = 0, clock
        with self.assertRaises(Problem) as ctx:
            client.status()
        self.assertEqual(
            (ctx.exception.status, ctx.exception.code, ctx.exception.retry_after), (429, "rate_limited", 60)
        )
        self.assertEqual(client.budget.wait(), 60)
        clock.now += 60
        self.assertEqual(client.budget.wait(), 0)

    def test_full_queue_does_not_pause_the_app(self) -> None:
        self.agent.refusals["e1"] = (429, "busy")
        with self.assertRaises(Problem) as ctx:
            self.client.act("e1", "install")
        self.assertEqual((ctx.exception.code, ctx.exception.retry_after), ("busy", 0))
        self.assertEqual(self.client.budget.wait(), 0)

    def test_deeply_nested_reply_is_agent_unavailable(self) -> None:
        self.agent.raw = b"[" * 200000 + b"]" * 200000
        with self.assertRaises(AgentUnavailable):
            self.client.status()


class BudgetTest(unittest.TestCase):
    def test_sliding_window(self) -> None:
        clock = FakeClock()
        budget = Budget(clock)
        for _ in range(BACKGROUND_PER_MINUTE - 1):
            budget.record()
            clock.now += 0.5
        self.assertEqual(budget.wait(), 0)
        budget.record()
        self.assertEqual(budget.wait(), 41, "until the first request leaves the window")
        clock.now += 41
        self.assertEqual(budget.wait(), 0)


if __name__ == "__main__":
    unittest.main()

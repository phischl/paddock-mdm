"""Requests for applications that need approval (ticket PDK-811; plan M13c decision 9, maintainer answer Q7,
architect decision A10-27): the Request button and dialog, the pending and denied states, withdrawal, and the
justification and denial reason as untrusted plain text."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from paddock_self_service import i18n
from paddock_self_service.client import Client
from paddock_self_service.controller import Controller
from paddock_self_service.model import MAX_JUSTIFICATION, AppView, clean_justification, justification_ok
from paddock_self_service.notice import NoticeState
from paddock_self_service.presenter import card, details, request_form

from fakeagent import FakeAgent, app
from support import FakeView, SyncScheduler

SCRIPT = "<script>alert(1)</script><b>x</b> &amp;"


def approval_app(**kw) -> dict:
    base = app("e1", "gimp", approval="required", requestable=True)
    base.update(kw)
    return base


class RequestPresenterTest(unittest.TestCase):
    def setUp(self) -> None:
        i18n.setup(languages=["en"])

    def test_requestable_app_shows_request_instead_of_install(self) -> None:
        c = card(AppView.parse(approval_app()))
        self.assertEqual(
            (c.chip, c.actions, c.detail), ("Not installed", ("request",), "Needs your organization's approval")
        )

    def test_pending_request(self) -> None:
        a = AppView.parse(approval_app(requestable=False, request={"state": "requested"}))
        c = card(a)
        self.assertEqual((c.chip, c.chip_kind, c.actions), ("Requested", "accent", ("withdraw",)))
        self.assertIn(("Approval", "Requested"), details(a))

    def test_denied_request_shows_the_reason_as_plain_text(self) -> None:
        a = AppView.parse(approval_app(requestable=False, request={"state": "denied", "reason": SCRIPT + "‮\x1b"}))
        c = card(a)
        self.assertEqual((c.chip, c.chip_kind, c.actions, c.detail), ("Denied", "error", (), SCRIPT))
        self.assertIn(("Approval", "Denied: " + SCRIPT), details(a))

    def test_denied_without_reason(self) -> None:
        a = AppView.parse(approval_app(requestable=False, request={"state": "denied"}))
        self.assertIn(("Approval", "Denied"), details(a))

    def test_approved_app_installs(self) -> None:
        c = card(AppView.parse(approval_app(requestable=False, installable=True)))
        self.assertEqual((c.chip, c.actions, c.detail), ("Not installed", ("install",), ""))

    def test_local_account_cannot_ask(self) -> None:
        c = card(AppView.parse(approval_app(requestable=False)))
        self.assertEqual((c.actions, c.detail), ((), "Needs your organization's approval"))

    def test_reason_is_bounded(self) -> None:
        a = AppView.parse(approval_app(request={"state": "denied", "reason": "x" * 2000}))
        self.assertEqual(len(a.request_reason), 500)


class RequestFormTest(unittest.TestCase):
    def setUp(self) -> None:
        i18n.setup(languages=["en"])

    def test_counter_and_limit(self) -> None:
        self.assertEqual(request_form(""), request_form(" \n "))
        self.assertTrue(request_form("").can_send, "the justification is optional")
        self.assertEqual(request_form("abc").counter, "3 of 500 characters")
        self.assertTrue(request_form("ä" * MAX_JUSTIFICATION).can_send)
        self.assertFalse(request_form("ä" * (MAX_JUSTIFICATION + 1)).can_send)

    def test_cleaning_keeps_newlines_only(self) -> None:
        self.assertEqual(clean_justification("  a\r\nb\rc\td\x1b\x00e  "), "a\nb\ncde")
        self.assertTrue(justification_ok("x" * MAX_JUSTIFICATION + "\x00\x01"))


class RequestControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        i18n.setup(languages=["en"])
        self.agent = FakeAgent().start()
        self.addCleanup(self.agent.stop)
        self.addCleanup(shutil.rmtree, self.agent.dir, True)
        config = tempfile.mkdtemp(prefix="paddock-ss-config-")
        self.addCleanup(shutil.rmtree, config, True)
        self.view = FakeView()
        self.sched = SyncScheduler()
        client = Client(self.agent.path, timeout=5, clock=self.sched.clock)
        self.c = Controller(client, self.view, self.sched, NoticeState(os.path.join(config, "paddock-self-service")))
        self.agent.apps = [approval_app()]
        self.c.refresh()

    def test_request_sends_the_cleaned_justification_and_shows_requested(self) -> None:
        self.c.request("e1", "  Für das\r\nDesign-Review \x1b ")
        self.assertIn(("POST", "/v1/apps/e1/request"), self.agent.requests)
        self.assertEqual(json.loads(self.agent.bodies[-1].decode("utf-8")), {"justification": "Für das\nDesign-Review"})
        self.assertIn("Für".encode(), self.agent.bodies[-1], "UTF-8, not escapes")
        self.assertEqual(self.view.messages[-1], "gimp: approval requested")
        self.assertEqual((self.view.cards[0].chip, self.view.cards[0].actions), ("Requested", ("withdraw",)))

    def test_withdraw_clears_the_state(self) -> None:
        self.c.request("e1", "")
        self.c.withdraw("e1")
        self.assertIn(("DELETE", "/v1/apps/e1/request"), self.agent.requests)
        self.assertEqual(self.view.messages[-1], "gimp: request withdrawn")
        self.assertEqual(self.view.cards[0].actions, ("request",))

    def test_refusal_is_shown_with_its_reason(self) -> None:
        self.agent.refusals["e1"] = (409, "already_requested")
        self.c.request("e1", "")
        self.assertEqual(self.view.messages[-1], "gimp: Already requested")
        self.assertEqual(self.view.banner, "")

    def test_unavailable_agent_gets_the_banner_and_a_retry(self) -> None:
        self.agent.refusals["e1"] = (503, "login_paused")
        self.c.request("e1", "")
        self.assertEqual(self.view.banner, "Paddock reported an error (login_paused). Trying again…")
        self.assertTrue(self.sched.timers, "the list is loaded again later")

    def test_too_long_justification_is_not_sent(self) -> None:
        self.c.request("e1", "x" * (MAX_JUSTIFICATION + 1))
        self.assertNotIn(("POST", "/v1/apps/e1/request"), self.agent.requests)


if __name__ == "__main__":
    unittest.main()

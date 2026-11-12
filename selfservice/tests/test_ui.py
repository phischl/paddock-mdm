"""The GTK window shows socket data as plain text. Needs PyGObject with GTK 4 and libadwaita and a display; skipped
without them (the CI runner has neither), the controller tests cover the behaviour headless."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from paddock_self_service import i18n

from fakeagent import FakeAgent, app


def _gtk():
    if not (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")):
        return None
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw, Gio, Gtk

        if not Gtk.init_check():
            return None
        Adw.init()
        return Gtk, Gio
    except (ImportError, ValueError):
        return None


Gtk, Gio = _gtk() or (None, None)


def _labels(widget) -> list:
    found = []
    child = widget.get_first_child()
    while child is not None:
        if isinstance(child, Gtk.Label):
            found.append(child)
        found += _labels(child)
        child = child.get_next_sibling()
    return found


_APPLICATIONS: list = []


def _application(cls, client):
    """One registered application for the whole module: GApplication exports its D-Bus object once per process."""
    if not _APPLICATIONS:
        application = cls(client)
        application.set_flags(application.get_flags() | Gio.ApplicationFlags.NON_UNIQUE)
        application.register(None)
        _APPLICATIONS.append(application)
    return _APPLICATIONS[0]


@unittest.skipIf(Gtk is None, "no GTK 4 / libadwaita display")
class WindowTest(unittest.TestCase):
    def setUp(self) -> None:
        i18n.setup(languages=["en"])
        self.agent = FakeAgent().start()
        self.addCleanup(self.agent.stop)
        self.addCleanup(shutil.rmtree, self.agent.dir, True)
        config = tempfile.mkdtemp(prefix="paddock-ss-config-")
        self.addCleanup(shutil.rmtree, config, True)
        old = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = config
        self.addCleanup(
            lambda: os.environ.pop("XDG_CONFIG_HOME") if old is None else os.environ.update(XDG_CONFIG_HOME=old)
        )

    def test_catalog_text_is_not_markup(self) -> None:
        from paddock_self_service.client import Client
        from paddock_self_service.ui import Application, Window

        from support import SyncScheduler

        self.agent.apps = [app("e1", "<b>bold</b> & <i>x", installable=True)]
        window = Window(_application(Application, Client(self.agent.path)), Client(self.agent.path), SyncScheduler())
        window.controller.refresh()
        window.controller.acknowledge_notice()
        texts = {label.get_label(): label for label in _labels(window)}
        self.assertIn("<b>bold</b> & <i>x", texts)
        self.assertFalse(texts["<b>bold</b> & <i>x"].get_use_markup())
        self.assertIn("Install", texts)
        window.destroy()

    def _window(self):
        from paddock_self_service.client import Client
        from paddock_self_service.ui import Application, Window

        from support import SyncScheduler

        window = Window(_application(Application, Client(self.agent.path)), Client(self.agent.path), SyncScheduler())
        window.controller.refresh()
        window.controller.acknowledge_notice()
        self.addCleanup(window.destroy)
        return window

    def test_denial_reason_is_not_markup(self) -> None:
        script = "<script>alert(1)</script><b>x</b>"
        self.agent.apps = [
            app("e1", "gimp", approval="required", request={"state": "denied", "reason": script}),
        ]
        texts = {label.get_label(): label for label in _labels(self._window())}
        self.assertIn(script, texts)
        self.assertFalse(texts[script].get_use_markup())
        self.assertIn("Denied", texts)

    def test_request_dialog_limits_the_justification(self) -> None:
        self.agent.apps = [app("e1", "gimp", approval="required", requestable=True)]
        window = self._window()
        self.assertIn("Request", {label.get_label() for label in _labels(window)})
        dialog = window.request_dialog("e1")
        self.assertEqual(dialog.get_heading(), "Request gimp")
        buffer = dialog.text_view.get_buffer()
        self.assertTrue(dialog.get_response_enabled("request"), "the justification is optional")
        buffer.set_text("x" * 501)
        self.assertFalse(dialog.get_response_enabled("request"))
        buffer.set_text("<b>for work</b>")
        self.assertTrue(dialog.get_response_enabled("request"))
        dialog.emit("response", "request")
        self.assertIn(("POST", "/v1/apps/e1/request"), self.agent.requests)
        self.assertIn(b"<b>for work</b>", self.agent.bodies[-1])


if __name__ == "__main__":
    unittest.main()

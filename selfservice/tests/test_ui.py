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
        application = Application(Client(self.agent.path))
        application.set_flags(application.get_flags() | Gio.ApplicationFlags.NON_UNIQUE)
        application.register(None)
        window = Window(application, Client(self.agent.path), SyncScheduler())
        window.controller.refresh()
        window.controller.acknowledge_notice()
        texts = {label.get_label(): label for label in _labels(window)}
        self.assertIn("<b>bold</b> & <i>x", texts)
        self.assertFalse(texts["<b>bold</b> & <i>x"].get_use_markup())
        self.assertIn("Install", texts)
        window.destroy()


if __name__ == "__main__":
    unittest.main()

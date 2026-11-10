"""German and English texts are complete: every source string has a German translation with the same
placeholders, the catalog has no stale entries, and the compiled catalog is what gettext loads."""

from __future__ import annotations

import ast
import glob
import os
import re
import shutil
import sys
import tempfile
import unittest

from paddock_self_service import i18n
from paddock_self_service.notice import DEFAULT_NOTICE, display_text
from paddock_self_service.presenter import Activity

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import msgfmt  # noqa: E402

PO = os.path.join(ROOT, "po", "de.po")


def source_strings() -> set[str]:
    found = {DEFAULT_NOTICE}
    for path in glob.glob(os.path.join(ROOT, "paddock_self_service", "*.py")):
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
    return found


class I18nTest(unittest.TestCase):
    def setUp(self) -> None:
        with open(PO, encoding="utf-8") as f:
            self.catalog = msgfmt.parse(f.read())
        self.localedir = tempfile.mkdtemp(prefix="paddock-ss-locale-")
        self.addCleanup(shutil.rmtree, self.localedir, True)
        self.addCleanup(i18n.setup, None, ["en"])
        mo = os.path.join(self.localedir, "de", "LC_MESSAGES", i18n.DOMAIN + ".mo")
        msgfmt.main(["msgfmt.py", PO, mo])

    def test_every_string_is_translated(self) -> None:
        strings = source_strings()
        self.assertGreater(len(strings), 50)
        missing = sorted(s for s in strings if not self.catalog.get(s))
        self.assertEqual(missing, [])

    def test_no_stale_translations(self) -> None:
        stale = sorted(set(self.catalog) - source_strings() - {""})
        self.assertEqual(stale, [])

    def test_placeholders_match(self) -> None:
        for msgid, msgstr in self.catalog.items():
            self.assertEqual(sorted(re.findall(r"\{\w+\}", msgid)), sorted(re.findall(r"\{\w+\}", msgstr)), msgid)

    def test_german_session(self) -> None:
        i18n.setup(self.localedir, ["de"])
        row = Activity(op_id="op1", entry_id="e1", name="gimp", action="install", state="queued", position=3)
        self.assertEqual((row.title(), row.text()), ("gimp installieren", "In der Warteschlange (Position 3)"))
        self.assertTrue(display_text("").startswith("Ihre Organisation bietet Anwendungen"))
        self.assertEqual(display_text("Eigener Text."), "Eigener Text.", "the organization's text is never translated")

    def test_unknown_language_falls_back_to_english(self) -> None:
        i18n.setup(self.localedir, ["fr"])
        self.assertEqual(display_text(""), DEFAULT_NOTICE)

    def test_fuzzy_and_empty_entries_are_left_out(self) -> None:
        po = '#, fuzzy\nmsgid "a"\nmsgstr "x"\n\nmsgid "b"\nmsgstr ""\n\nmsgid "c"\nmsgstr "y"\n"z"\n'
        self.assertEqual(msgfmt.parse(po), {"c": "yz"})


if __name__ == "__main__":
    unittest.main()

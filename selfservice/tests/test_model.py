"""Untrusted socket data becomes plain display text."""

from __future__ import annotations

import unittest

from paddock_self_service import i18n
from paddock_self_service.model import MAX_NAME, AppView, Operation, Status, plain, valid_id
from paddock_self_service.presenter import card, details, glyph


class ModelTest(unittest.TestCase):
    def setUp(self) -> None:
        i18n.setup(languages=["en"])

    def test_plain_removes_control_and_bidi_characters(self) -> None:
        self.assertEqual(plain("evil‮gnp.exe\x00\x1b[31m", 100), "evilgnp.exe[31m")
        self.assertEqual(plain("a\nb", 100), "ab")
        self.assertEqual(plain("a\nb", 100, multiline=True), "a\nb")
        self.assertEqual(plain(42, 100), "")
        self.assertEqual(len(plain("x" * 1000, MAX_NAME)), MAX_NAME)

    def test_markup_stays_literal_text(self) -> None:
        a = AppView.parse({"entry_id": "e1", "name": "<b>bold</b> &amp;", "description": "<a href='x'>link</a>"})
        self.assertEqual(card(a).title, "<b>bold</b> &amp;")
        self.assertIn(("Description", "<a href='x'>link</a>"), details(a))

    def test_wrong_types_are_ignored(self) -> None:
        a = AppView.parse({"entry_id": "e1", "name": ["x"], "managed": "true", "installable": 1, "icon": "yes"})
        self.assertEqual((a.name, a.managed, a.installable, a.icon), ("", False, False, False))
        st = Status.parse({"bundle_version": "7", "queue": -1, "user": "alice"})
        self.assertEqual((st.bundle_version, st.queue, st.user_name), (0, 0, ""))
        self.assertIsNone(Operation.parse({"id": "../x"}))
        self.assertIsNone(AppView.parse(None))

    def test_valid_id_matches_the_whole_value(self) -> None:
        self.assertTrue(valid_id("abc"))
        self.assertTrue(valid_id("a" * 128))
        for bad in ("abc\n", "abc\r", "\nabc", "a" * 129, "-abc", "", None, 1):
            self.assertFalse(valid_id(bad), repr(bad))
        self.assertIsNone(AppView.parse({"entry_id": "e1\n"}))

    def test_unknown_reason_is_shown_as_code(self) -> None:
        a = AppView.parse({"entry_id": "e1", "state": "failed", "reason": "something_new"})
        self.assertEqual(card(a).detail, "something_new")

    def test_details_of_managed_app(self) -> None:
        a = AppView.parse(
            {
                "entry_id": "e1",
                "name": "firefox",
                "managed": True,
                "state": "installed",
                "kind": "flatpak",
                "scope": "user",
                "version": "128.0",
            }
        )
        rows = dict(details(a))
        self.assertEqual(rows["Managed by your organization"], "Required on this device")
        self.assertEqual((rows["Source"], rows["Installed for"], rows["Version"]), ("Flatpak", "Only you", "128.0"))

    def test_glyph_by_category(self) -> None:
        self.assertEqual(glyph("Graphics"), "applications-graphics-symbolic")
        self.assertEqual(glyph("<script>"), "application-x-executable-symbolic")


if __name__ == "__main__":
    unittest.main()

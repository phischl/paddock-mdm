"""The app never runs as root."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from unittest import mock

from paddock_self_service import main


class MainTest(unittest.TestCase):
    def test_refuses_root(self) -> None:
        err = io.StringIO()
        with mock.patch("os.geteuid", return_value=0), redirect_stderr(err):
            self.assertEqual(main.main(["paddock-self-service"]), 1)
        self.assertIn("does not run as root", err.getvalue())


if __name__ == "__main__":
    unittest.main()

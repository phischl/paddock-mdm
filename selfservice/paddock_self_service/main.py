"""Entry point of `paddock-self-service`."""

from __future__ import annotations

import os
import sys

from . import i18n
from .client import Client
from .i18n import _


def main(argv: list[str] | None = None) -> int:
    i18n.setup()
    # The app acts only through the agent's socket as the logged-in user (ADR 0049); as root it would act for no one.
    if os.geteuid() == 0:
        print(_("Paddock Self-Service does not run as root; start it as the logged-in user."), file=sys.stderr)
        return 1
    from .ui import Application

    return Application(Client()).run(sys.argv if argv is None else argv)

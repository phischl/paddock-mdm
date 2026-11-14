"""Translations through gettext: English source strings, German catalog `po/de.po`, compiled at package build time
into `<install dir>/locale/de/LC_MESSAGES/paddock-self-service.mo`. The language follows the session's locale
(LANGUAGE, LC_ALL, LC_MESSAGES, LANG)."""

from __future__ import annotations

import gettext
import os

DOMAIN = "paddock-self-service"


def default_localedir() -> str:
    """The locale directory next to the installed package (`/usr/lib/paddock-self-service/locale`)."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "locale")


class _State:
    translation: gettext.NullTranslations = gettext.NullTranslations()


def setup(localedir: str | None = None, languages: list[str] | None = None) -> None:
    """Load the catalog for the session's language (or languages); English when there is none."""
    _State.translation = gettext.translation(
        DOMAIN, localedir or default_localedir(), languages=languages, fallback=True
    )


def _(message: str) -> str:
    """Translate message."""
    return _State.translation.gettext(message)

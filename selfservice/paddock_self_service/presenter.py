"""What the screens show for the socket's data, independent of GTK so that it is tested without a display."""

from __future__ import annotations

from dataclasses import dataclass

from .i18n import _
from .model import MAX_JUSTIFICATION, AppView, Operation, clean_justification, justification_ok


def reason_text(reason: str) -> str:
    """A refusal or failure reason in words; an unknown code is shown as the code itself."""
    texts = {
        "required_by_policy": _("Required by your organization"),
        "not_in_audience": _("Not offered to you"),
        "offline": _("The device is offline"),
        "busy": _("Too many operations are queued; try again later"),
        "unknown_entry": _("This application is no longer offered"),
        "rate_limited": _("Too many requests; try again in a minute"),
        "unauthenticated": _("Paddock could not identify you"),
        "interrupted": _("Interrupted; try again"),
        "timeout": _("Took too long and was stopped"),
        "source_unreachable": _("The package source cannot be reached"),
        "dpkg_locked": _("Another installation is running; try again"),
        "no_candidate": _("The package is not available for this device"),
        "fingerprint_mismatch": _("The package source's key does not match"),
        "would_remove_dependents": _("Removing it would remove other software"),
        "protected_package_affected": _("It would change software Paddock protects"),
        "conflicting_source": _("Another package source provides this package"),
        "apt_failed": _("The package manager reported an error"),
        "flatpak_missing": _("Flatpak is not installed yet"),
        "flatpak_failed": _("Flatpak reported an error"),
        "deferred_offline": _("Waits until the device is online"),
        "outside_window": _("Waits for the maintenance window"),
        "not_yet_applied": _("Not applied yet"),
        "approval_required": _("Needs your organization's approval"),
        "not_required": _("No approval is needed"),
        "already_requested": _("Already requested"),
        "denied": _("Your request was denied"),
        "invalid_request": _("The justification is not plain text of at most 500 characters"),
    }
    return texts.get(reason, reason)


def state_text(state: str) -> str:
    texts = {
        "installed": _("Installed"),
        "absent": _("Not installed"),
        "pending": _("In progress"),
        "failed": _("Failed"),
        "held": _("Installed (held)"),
    }
    return texts.get(state, state)


def action_label(action: str) -> str:
    return {
        "install": _("Install"),
        "remove": _("Remove"),
        "update": _("Update"),
        "request": _("Request"),
        "withdraw": _("Withdraw request"),
    }[action]


def request_text(app: AppView) -> str:
    """The request state of an app that needs approval, empty for any other app. A denial's reason comes from an
    administrator and is shown as plain text."""
    if app.request_state == "requested":
        return _("Requested")
    if app.request_state == "denied":
        if app.request_reason:
            return _("Denied: {reason}").format(reason=app.request_reason)
        return _("Denied")
    return ""


@dataclass(frozen=True)
class RequestForm:
    """What the request dialog shows for the justification typed so far."""

    counter: str
    can_send: bool


def request_form(text: str) -> RequestForm:
    """The counter and whether the dialog may send: the justification is optional and at most MAX_JUSTIFICATION
    characters once cleaned."""
    return RequestForm(
        counter=_("{count} of {limit} characters").format(
            count=len(clean_justification(text)), limit=MAX_JUSTIFICATION
        ),
        can_send=justification_ok(text),
    )


def needs_approval(app: AppView) -> bool:
    """Report whether the user cannot install app without an administrator's approval."""
    return not app.managed and app.approval == "required" and not app.installable and app.state != "installed"


_GLYPHS = {
    "office": "x-office-document-symbolic",
    "graphics": "applications-graphics-symbolic",
    "multimedia": "applications-multimedia-symbolic",
    "audiovideo": "applications-multimedia-symbolic",
    "network": "web-browser-symbolic",
    "internet": "web-browser-symbolic",
    "development": "utilities-terminal-symbolic",
    "games": "applications-games-symbolic",
    "game": "applications-games-symbolic",
    "science": "applications-science-symbolic",
    "education": "applications-science-symbolic",
    "utility": "applications-utilities-symbolic",
    "utilities": "applications-utilities-symbolic",
    "system": "applications-system-symbolic",
}


def glyph(category: str) -> str:
    """The themed icon shown for an app without an icon: the category's, else a generic one."""
    return _GLYPHS.get(category.strip().lower(), "application-x-executable-symbolic")


@dataclass(frozen=True)
class Card:
    """One tile of the Apps grid."""

    entry_id: str
    title: str
    chip: str
    chip_kind: str
    actions: tuple[str, ...]
    managed_text: str
    detail: str


def card(app: AppView) -> Card:
    """The tile of app: a managed app has no buttons and says why it is there."""
    actions: tuple[str, ...] = ()
    managed = ""
    if app.managed:
        managed = _("Managed by your organization")
    else:
        actions = tuple(
            a
            for a, allowed in (
                ("install", app.installable),
                ("update", app.updatable),
                ("remove", app.removable),
                ("request", app.requestable),
                ("withdraw", app.request_state == "requested"),
            )
            if allowed
        )
    detail = ""
    if app.state in ("failed", "pending") and app.reason:
        detail = reason_text(app.reason)
    chip = state_text(app.state)
    chip_kind = {"installed": "success", "failed": "error", "pending": "accent"}.get(app.state, "dim")
    if needs_approval(app):
        # The card stays small: the denial's reason, up to 500 characters, goes into the wrapping detail line.
        if app.request_state == "requested":
            chip, chip_kind = _("Requested"), "accent"
        elif app.request_state == "denied":
            chip, chip_kind = _("Denied"), "error"
            detail = app.request_reason
        else:
            detail = reason_text("approval_required")
    return Card(
        entry_id=app.entry_id,
        title=app.name or app.entry_id,
        chip=chip,
        chip_kind=chip_kind,
        actions=actions,
        managed_text=managed,
        detail=detail,
    )


def details(app: AppView) -> list[tuple[str, str]]:
    """The Details rows: label and plain value, empty values left out."""
    kind = {"apt": _("Debian package"), "flatpak": _("Flatpak")}.get(app.kind, app.kind)
    scope = {"system": _("All users of this device"), "user": _("Only you")}.get(app.scope, app.scope)
    rows = [
        (_("Description"), app.description),
        (_("Version"), app.version),
        (_("Source"), kind),
        (_("Installed for"), scope),
        (_("State"), state_text(app.state)),
    ]
    if needs_approval(app):
        rows.append((_("Approval"), request_text(app) or reason_text("approval_required")))
    if app.managed:
        rows.append((_("Managed by your organization"), app.reason or _("Required on this device")))
    elif app.reason:
        rows.append((_("Reason"), reason_text(app.reason)))
    return [(label, value) for label, value in rows if value]


@dataclass
class Activity:
    """One operation the user started in this session (the agent offers no list of past operations)."""

    op_id: str
    entry_id: str
    name: str
    action: str
    state: str
    position: int = 0
    reason: str = ""

    def update(self, op: Operation) -> None:
        self.state, self.position, self.reason = op.state, op.position, op.reason

    @property
    def active(self) -> bool:
        return self.state in ("queued", "running")

    def text(self) -> str:
        """The state line of the Activity screen."""
        if self.state == "queued":
            if self.position > 0:
                return _("Queued (position {position})").format(position=self.position)
            return _("Queued")
        texts = {
            "running": _("Running"),
            "succeeded": _("Done"),
            "failed": _("Failed"),
            "refused": _("Refused"),
        }
        text = texts.get(self.state, self.state)
        if self.reason and self.state in ("failed", "refused"):
            text = _("{state}: {reason}").format(state=text, reason=reason_text(self.reason))
        return text

    def title(self) -> str:
        texts = {
            "install": _("Install {name}"),
            "remove": _("Remove {name}"),
            "update": _("Update {name}"),
        }
        return texts.get(self.action, "{name}").format(name=self.name)

"""The GTK 4 / libadwaita window: Apps grid, Details, Activity, the banner and the first-start notice.

Everything from the socket is set as plain text: labels through set_text, rows, banners and toasts with use-markup
off, so a catalog name such as "<b>x</b>" is shown as typed and never parsed as Pango markup.
"""

from __future__ import annotations

import concurrent.futures
from typing import Any, Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk, Pango  # noqa: E402

from . import APP_ID  # noqa: E402
from .client import Client  # noqa: E402
from .controller import Controller, IconLoader  # noqa: E402
from .i18n import _  # noqa: E402
from .notice import NoticeState  # noqa: E402
from .presenter import Activity, Card, action_label, details, glyph, request_form  # noqa: E402

ICON_SIZE = 48


class GtkScheduler:
    """Runs socket calls on a worker thread and hands their results back to the GTK main loop."""

    def __init__(self) -> None:
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="paddock-socket")
        self._sources: dict[object, int] = {}

    def submit(self, work: Callable[[], Any], done: Callable[[Any, BaseException | None], None]) -> None:
        def deliver(future: concurrent.futures.Future) -> bool:
            error = future.exception()
            done(None if error else future.result(), error)
            return GLib.SOURCE_REMOVE

        self._pool.submit(work).add_done_callback(lambda f: GLib.idle_add(deliver, f))

    def later(self, seconds: int, fn: Callable[[], None]) -> object:
        handle = object()

        def fire() -> bool:
            self._sources.pop(handle, None)
            fn()
            return GLib.SOURCE_REMOVE

        self._sources[handle] = GLib.timeout_add_seconds(seconds, fire)
        return handle

    def cancel(self, handle: object) -> None:
        source = self._sources.pop(handle, None)
        if source is not None:
            GLib.source_remove(source)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def _label(text: str, *classes: str, wrap: bool = False) -> Gtk.Label:
    label = Gtk.Label(xalign=0, use_markup=False, wrap=wrap)
    label.set_text(text)
    for c in classes:
        label.add_css_class(c)
    return label


def _scrolled(child: Gtk.Widget) -> Gtk.ScrolledWindow:
    return Gtk.ScrolledWindow(child=child, vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)


def _row(title: str, subtitle: str = "") -> Adw.ActionRow:
    row = Adw.ActionRow(use_markup=False)
    row.set_title(title)
    if subtitle:
        row.set_subtitle(subtitle)
    return row


class Window(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application, client: Client, scheduler: GtkScheduler) -> None:
        super().__init__(application=app, title=_("Paddock Self-Service"), default_width=900, default_height=640)
        self._textures: dict[str, Gdk.Texture | None] = {}
        self._icons = IconLoader(client, scheduler)
        self.controller = Controller(client, self, scheduler, NoticeState())

        self._toasts = Adw.ToastOverlay()
        self._nav = Adw.NavigationView()
        self._toasts.set_child(self._nav)
        self.set_content(self._toasts)

        self._stack = Adw.ViewStack()
        self._grid = Gtk.FlowBox(
            valign=Gtk.Align.START,
            selection_mode=Gtk.SelectionMode.NONE,
            homogeneous=True,
            min_children_per_line=1,
            max_children_per_line=6,
            row_spacing=12,
            column_spacing=12,
            margin_top=18,
            margin_bottom=18,
            margin_start=18,
            margin_end=18,
        )
        self._grid.connect("child-activated", self._on_card_activated)
        self._apps_stack = Gtk.Stack()
        self._apps_stack.add_named(_scrolled(self._grid), "grid")
        self._apps_stack.add_named(
            Adw.StatusPage(title=_("No applications are offered to you"), icon_name="view-app-grid-symbolic"), "empty"
        )
        self._stack.add_titled_with_icon(self._apps_stack, "apps", _("Apps"), "view-app-grid-symbolic")

        self._activity = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        self._activity_stack = Gtk.Stack()
        activity_group = Adw.PreferencesGroup()
        activity_group.add(self._activity)
        activity_page = Adw.PreferencesPage()
        activity_page.add(activity_group)
        self._activity_stack.add_named(activity_page, "list")
        self._activity_stack.add_named(
            Adw.StatusPage(
                title=_("Nothing yet"),
                description=_("Operations you start appear here."),
                icon_name="document-open-recent-symbolic",
            ),
            "empty",
        )
        self._activity_stack.set_visible_child_name("empty")
        self._stack.add_titled_with_icon(
            self._activity_stack, "activity", _("Activity"), "document-open-recent-symbolic"
        )

        header = Adw.HeaderBar(title_widget=Adw.ViewSwitcher(stack=self._stack, policy=Adw.ViewSwitcherPolicy.WIDE))
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_("Refresh"))
        refresh.connect("clicked", lambda _b: self.controller.refresh())
        header.pack_end(refresh)
        self._banner = Adw.Banner(use_markup=False, revealed=False)
        toolbar = Adw.ToolbarView(content=self._stack)
        toolbar.add_top_bar(header)
        toolbar.add_top_bar(self._banner)
        self._nav.add(Adw.NavigationPage(child=toolbar, title=_("Paddock Self-Service"), tag="main"))

    # View protocol of the controller.

    def show_banner(self, text: str) -> None:
        self._banner.set_title(text)
        self._banner.set_revealed(bool(text))

    def show_apps(self, cards: list[Card]) -> None:
        self._grid.remove_all()
        for c in cards:
            self._grid.append(self._card(c))
        self._apps_stack.set_visible_child_name("grid" if cards else "empty")

    def show_activity(self, rows: list[Activity]) -> None:
        self._activity.remove_all()
        for r in rows:
            self._activity.append(_row(r.title(), r.text()))
        self._activity_stack.set_visible_child_name("list" if rows else "empty")

    def show_notice(self, text: str) -> None:
        dialog = Adw.AlertDialog(
            heading=_("About Paddock Self-Service"), heading_use_markup=False, body_use_markup=False
        )
        dialog.set_body(text)
        dialog.add_response("ok", _("Understood"))
        dialog.set_default_response("ok")
        dialog.set_close_response("ok")
        dialog.connect("response", lambda _d, _r: self.controller.acknowledge_notice())
        dialog.present(self)

    def show_message(self, text: str) -> None:
        toast = Adw.Toast(use_markup=False, timeout=6)
        toast.set_title(text)
        self._toasts.add_toast(toast)

    # Widgets.

    def _icon(self, entry_id: str, category: str, has_icon: bool) -> Gtk.Image:
        image = Gtk.Image(pixel_size=ICON_SIZE, icon_name=glyph(category))
        if not has_icon:
            return image
        if entry_id in self._textures:
            texture = self._textures[entry_id]
            if texture is not None:
                image.set_from_paintable(texture)
            return image

        def deliver(data: bytes | None) -> None:
            if entry_id not in self._textures:
                texture = None
                if data:
                    try:
                        texture = Gdk.Texture.new_from_bytes(GLib.Bytes.new(data))
                    except GLib.Error:
                        texture = None
                self._textures[entry_id] = texture
            if self._textures[entry_id] is not None:
                image.set_from_paintable(self._textures[entry_id])

        self._icons.request(entry_id, deliver)
        return image

    def _card(self, c: Card) -> Gtk.FlowBoxChild:
        app = self.controller.app(c.entry_id)
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=6,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12,
        )
        box.append(self._icon(c.entry_id, app.category if app else "", bool(app and app.icon)))
        title = _label(c.title, "heading")
        title.set_xalign(0.5)
        title.set_ellipsize(Pango.EllipsizeMode.END)
        box.append(title)
        chip = _label(c.chip, "caption", c.chip_kind if c.chip_kind != "dim" else "dim-label")
        chip.set_xalign(0.5)
        box.append(chip)
        if c.detail:
            detail = _label(c.detail, "caption", "dim-label", wrap=True)
            detail.set_xalign(0.5)
            box.append(detail)
        if c.managed_text:
            managed = _label(c.managed_text, "caption", "dim-label", wrap=True)
            managed.set_xalign(0.5)
            box.append(managed)
        buttons = Gtk.Box(spacing=6, halign=Gtk.Align.CENTER)
        for action in c.actions:
            button = Gtk.Button(label=action_label(action))
            button.add_css_class("destructive-action" if action == "remove" else "suggested-action")
            button.connect("clicked", self._on_action, c.entry_id, action)
            buttons.append(button)
        box.append(buttons)
        frame = Gtk.Frame(child=box, css_classes=["card"])
        child = Gtk.FlowBoxChild(child=frame)
        child.entry_id = c.entry_id
        return child

    def _on_action(self, _button: Gtk.Button, entry_id: str, action: str) -> None:
        if action == "request":
            self.request_dialog(entry_id).present(self)
            return
        if action == "withdraw":
            self.controller.withdraw(entry_id)
            return
        if action != "remove":
            self.controller.act(entry_id, action)
            return
        app = self.controller.app(entry_id)
        dialog = Adw.AlertDialog(heading_use_markup=False, body_use_markup=False)
        dialog.set_heading(_("Remove {name}?").format(name=app.name if app else entry_id))
        dialog.set_body(_("The application is removed from this device."))
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("remove", _("Remove"))
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.connect("response", lambda _d, r: r == "remove" and self.controller.act(entry_id, "remove"))
        dialog.present(self)

    def request_dialog(self, entry_id: str) -> Adw.AlertDialog:
        """The dialog that asks for an approval with an optional justification of at most 500 characters."""
        app = self.controller.app(entry_id)
        dialog = Adw.AlertDialog(heading_use_markup=False, body_use_markup=False)
        dialog.set_heading(_("Request {name}").format(name=app.name if app else entry_id))
        dialog.set_body(
            _(
                "An administrator of your organization decides. You can add a justification; it is sent with your "
                "user name."
            )
        )
        text = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR, accepts_tab=False, top_margin=6, bottom_margin=6)
        text.update_property([Gtk.AccessibleProperty.LABEL], [_("Justification (optional)")])
        counter = _label("", "caption", "dim-label")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.append(Gtk.ScrolledWindow(child=text, min_content_height=96, hscrollbar_policy=Gtk.PolicyType.NEVER))
        box.append(counter)
        dialog.set_extra_child(box)
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("request", _("Send request"))
        dialog.set_response_appearance("request", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("request")
        dialog.set_close_response("cancel")

        def typed() -> str:
            buffer = text.get_buffer()
            return buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)

        def changed(_buffer: Gtk.TextBuffer | None = None) -> None:
            form = request_form(typed())
            counter.set_text(form.counter)
            dialog.set_response_enabled("request", form.can_send)

        text.get_buffer().connect("changed", changed)
        changed()
        dialog.connect("response", lambda _d, r: r == "request" and self.controller.request(entry_id, typed()))
        dialog.text_view = text
        return dialog

    def _on_card_activated(self, _grid: Gtk.FlowBox, child: Gtk.FlowBoxChild) -> None:
        app = self.controller.app(getattr(child, "entry_id", ""))
        if app is None:
            return
        group = Adw.PreferencesGroup()
        for label, value in details(app):
            row = _row(label)
            row.set_subtitle(value)
            row.set_subtitle_selectable(True)
            row.add_css_class("property")
            group.add(row)
        header = Gtk.Box(spacing=12)
        header.append(self._icon(app.entry_id, app.category, app.icon))
        name = _label(app.name or app.entry_id, "title-2", wrap=True)
        name.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        name.set_hexpand(True)
        header.append(name)
        header_group = Adw.PreferencesGroup()
        header_group.add(header)
        content = Adw.PreferencesPage()
        content.add(header_group)
        content.add(group)
        toolbar = Adw.ToolbarView(content=content)
        toolbar.add_top_bar(Adw.HeaderBar())
        page = Adw.NavigationPage(child=toolbar, title=_("Details"))
        self._nav.push(page)


class Application(Adw.Application):
    def __init__(self, client: Client) -> None:
        super().__init__(application_id=APP_ID)
        self._client = client
        self._sched = GtkScheduler()
        self.connect("activate", self._on_activate)
        self.connect("shutdown", lambda _a: self._sched.shutdown())

    def _on_activate(self, _app: Adw.Application) -> None:
        window = self.get_active_window()
        if window is None:
            window = Window(self, self._client, self._sched)
            window.controller.refresh()
        window.present()

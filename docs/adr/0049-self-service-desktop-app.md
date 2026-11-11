# 0049 — Self-service desktop app, the local channel, Flatpak and user targets (M13b)
Status: Proposed (architect, 2026-11-05; the toolkit and the per-user status reporting are maintainer decisions
marked below — plan M13b plans with the recommendation, "pending")

## Context

ADR 0042 decided the shape of self-service (option E2): a desktop app that Paddock installs talks to `paddockd`
over `/run/paddock/selfservice.sock`, the agent authenticates the caller with `SO_PEERCRED` and authorizes it
against the signed bundle, and the agent is the only executor. It also decided user and user-group targets
through `device_owner` (F2) and reserved RR-79 for Flathub. M13a shipped the catalog (`software_source`,
`software_catalog_entry`, `software_assignment` with `device_group_id`), the bundle section `software`, the
reconciler `reconcile.Software` (APT only; `apt-get -s` simulation, the 15-minute removal rule, the record of
installed packages), `health.software` and `device_software_status`. M12 shipped `agent/internal/desktop/notify.go`
(`systemd-run --machine=<user>@.host --user notify-send`). The maintainer's decisions of 2026-10-20 bind: APT for
system software, Flatpak for desktop apps, no Snap; targets device groups first, users and user groups later;
no approval workflow in this step (M13c adds it).

What is still open and decided here: the toolkit of the app, the wire protocol on the socket, how Flatpak
remotes and apps enter the catalog and the device, how the audience of an `available` entry is resolved and
checked, what the device reports about self-service actions, and the state machine of one operation.

## Options

### Toolkit and language of the desktop app
- **Go with GTK4 bindings (`gotk4`).** + One language in the repository. − A cgo build with the GTK development
  headers in the deb build image, a very large generated binding module as a new dependency, slow builds, and
  the agent's `lint-supervisor-budget` discipline does not apply to a GUI. Rejected.
- **Qt (C++ or PySide).** − A second toolkit next to GNOME's on Ubuntu; PySide is not in Ubuntu main for every
  release. Rejected.
- **A web view (`webkitgtk`) with the UI served by the agent.** − The agent would serve HTML and a browser engine
  runs as the user with a full web platform; the health socket precedent is JSON, not HTML. Rejected.
- **Python 3 with GTK 4 and libadwaita through PyGObject, packaged as `paddock-self-service.deb` depending only on
  Ubuntu's own packages (`python3-gi`, `gir1.2-gtk-4.0`, `gir1.2-adw-1`) (recommended, pending maintainer).**
  + GNOME-native on Ubuntu 24.04/26.04, no compiled toolchain, no vendored library, LGPL only through the
  distribution's packages, a small code base (list, detail, progress, refresh), tests with `pytest` and a fake
  socket. − A second language in the repository (lint `ruff`, tests `pytest` in the agent CI job; both are
  development tools, not shipped), and Python on every device that gets self-service (Ubuntu ships it).

### Wire protocol on the socket
- **D-Bus service.** − A system bus policy file is a protected area of its own; the agent would carry a D-Bus
  library. Rejected.
- **JSON over HTTP on the unix socket, the health socket's shape (chosen).** + Already in the agent; the app
  needs only `http.client` over `AF_UNIX`; `SO_PEERCRED` from the accepted connection; long operations are
  polled by ID. − No push; the app polls every 2 s while an operation runs.

### Where Flatpak apps are installed
- **User scope only (`--user`).** + No root involvement at install time. − The agent is the executor by decision;
  per-user installs are invisible to other users and to the device-wide status; the agent would have to act in
  every user's context.
- **System scope by the agent (`--system`), with the user's session informed (chosen); user scope only for
  `available` entries whose catalog entry says `scope: user`, executed by the agent in the user's context
  (`systemd-run --machine=<user>@.host --user --wait flatpak install --user`).** + Required apps are device-wide
  and reportable; the executor stays the agent; a user who wants a personal install gets it without root.
  − Two code paths for Flatpak; user-scope apps are reported per user (privacy row).

### Audience of an `available` entry
- **The agent asks the server at request time.** − Breaks the offline contract and the pull model. Rejected.
- **The compiler renders the audience into the bundle: `all` (device-wide) or the UPNs of the device's owners that
  the assignment targets (user or user-group targets ∩ `device_owner`) (chosen, ADR 0042 F2).** + Deterministic,
  signed, offline. − A user who is not an owner of the device sees device-wide apps only (RR-84 reserved: a shared
  device without owners offers nothing user-targeted).

### Per-user status reporting
- **Report nothing per user.** − The administrator cannot see that a user installed an app, which the works
  council may prefer, but the organization cannot answer "which devices run X" for self-service apps.
- **Report per device × entry × user: state and version, no timestamps of use (recommended, pending maintainer;
  works-council relevant).** The event `software.self_service` carries the user name; the status item carries the
  user name of a user-scope install. Both are listed in `privacy.md`.

## Decision

1. **App.** `paddock-self-service` (Python 3, GTK 4, libadwaita; `packaging/nfpm/paddock-self-service.yaml`;
   source under `selfservice/`), installed by Paddock as a catalog entry of the organization with intent
   `required` for every device group that gets self-service (the entry is created by the organization
   administrator from the release's packages; the package comes from `bundles.<domain>/packages/<version>/` like
   the agent packages and is signed with the agent release key). Pending maintainer: the language and toolkit.
2. **Channel.** `/run/paddock/selfservice.sock` (mode 0666, directory 0755), JSON over HTTP/1.1, served by
   `paddockd` (`agent/internal/selfservice`), endpoints `GET /v1/apps`, `GET /v1/apps/{entry_id}`, `POST
   /v1/apps/{entry_id}/install`, `POST /v1/apps/{entry_id}/remove`, `POST /v1/apps/{entry_id}/update`, `GET
   /v1/operations/{id}`, `GET /v1/status`. The caller is identified by `SO_PEERCRED` (UID, PID); the UID is
   resolved to a user name with `getent passwd <uid>`; UIDs in Himmelblau's idmap range (200000–999999999) are
   directory users whose name is the UPN; every other UID is a local account. UID 0 has no extra rights. Each
   request is answered within 2 s; operations run asynchronously with an ID; one operation per device at a time
   (a second is queued, at most 5 per user); a request from a user with no `available` entry in their audience
   gets an empty list, never an error that reveals other users' entries.
3. **Authorization** (from the signed bundle only): a user may list and install an `available` entry whose
   audience is `all` or contains their UPN; may remove or update only an app that self-service installed for
   that user (user scope) or on the device (system scope) and that is not `required`; `required`, `hold`,
   `forbid` and `uninstall` entries are visible as read-only state. Every other request → 403
   `required_by_policy` / 404.
4. **Flatpak.** `software_source.kind` (`apt` | `flatpak`); a Flatpak source is a remote (`name`, `url`, armored
   GPG key, fingerprint; `flatpak remote-add --if-not-exists --gpg-import`); a catalog entry's package list gains
   `flatpak_ref` (application ID) with `scope` (`system` | `user`); intents apply to Flatpak refs as to packages
   (`required` → `flatpak install -y --system`, `uninstall`/`forbid` → `flatpak uninstall -y`, `hold` → `flatpak
   mask`); the agent installs the distribution's `flatpak` package as a required package whenever a Flatpak
   source is in the bundle. The remote list is a protected area: a remote named `paddock-*` that the spec does
   not name is removed and reported `tamper.protected_file_changed{file: "flatpak:remote/<name>"}`; a managed
   remote whose URL or key differs is restored. Flathub is an external trust anchor (RR-79).
5. **User and user-group targets.** `software_assignment` gains `user_id` and `user_group_id` (exactly one of
   `device_group_id`, `user_id`, `user_group_id`, or none = organization-wide). For `required`, `uninstall`,
   `hold` and `forbid`, a user-targeted assignment applies to every device that has a targeted owner; for
   `available`, the compiler renders `audience` per package: `{"all": true}` or `{"users": [<upn>…]}` (the
   targeted owners of the device). Devices without owners get no user-targeted entry.
6. **Operation state machine** (`agent/internal/selfservice`): `queued → running → succeeded | failed |
   refused`; `failed` carries the reconciler's reason (`no_candidate`, `would_remove_dependents`,
   `dpkg_locked`, `source_unreachable`, `flatpak_failed`); `refused` carries `required_by_policy`,
   `not_in_audience`, `offline` (an APT install needs the source; a self-service removal needs no check-in, the
   user asked for it), `busy`. A restart of the agent while `running` marks the operation `failed/interrupted`
   and the next drift pass reconciles the device; the app shows the outcome.
7. **Events and audit.** `software.self_service{user, entry_id, package | flatpak_ref, scope, action
   (install | remove | update), outcome (succeeded | failed | refused), reason, version}` (one per operation),
   audit `device.software_self_service`. Pending maintainer: per-user status items (`health.software.items[]`
   gain `user` for user-scope installs).
8. **Desktop notifications.** The agent tells the user's session through `desktop.Notify` when a required app was
   installed or reinstalled on their device, when a self-service operation finished, and when a restart is needed
   (`/var/run/reboot-required`), at most once per event, never more than 5 per hour per session.
9. **Privacy.** `privacy.md` gains the rows: self-service operations (user name, app, action, outcome) and
   user-scope status (user name, app, state, version); the app shows the organization's transparency notice
   text on first start; no usage data of any kind is read (the negative list binds).

## Consequences

- + The maintainer's seven decisions are implemented; the agent stays the only executor; the audience is signed
  and offline-safe; Flatpak joins with the same intents and the same protected-area rule.
- − A second language in the repository (Python for the app), a new deb, and per-user data in the status
  (listed, works-council relevant). Flathub as a trust anchor stays a residual risk.
- Follow-ups: M13c's approval workflow uses the same channel (`POST /v1/apps/{id}/request`); the shared catalog
  (M13c) and the stored packages (ADR 0050) feed the same bundle section.

## Amendment 2026-11-11 — requests for approval-required entries on the self-service channel (PDK-811, PDK-811b)

The follow-up named under Consequences is built. Decision 2's channel gains `POST /v1/apps/{entry_id}/request`
(body `{"justification": string}`, 202) and `DELETE /v1/apps/{entry_id}/request` (200), and the app views gain
`approval`, `requestable` and `request{state, reason}`. Decision 3's authorization gains: a directory user may
request an `available` entry that requires approval and may install it only while the signed bundle lists that
user in `approved[]` (otherwise 403 `approval_required`); a local account cannot request (403 `not_in_audience`),
because an approval names a UPN.

- **Per-caller answers.** The caller is the socket's peer UID, as in decision 2. A denial (`denied[]` of the
  bundle, with the administrator's reason) is returned only to the user it names; no answer reveals another user's
  request, approval or denial.
- **Untrusted text in both directions.** The justification is plain text of at most 500 characters without
  control characters except newlines; the agent refuses anything else and never logs it. A denial's reason is
  stripped of control and format characters and shown by the app as plain text.
- **Limits.** One pending request per user and entry; at most 10 requests per user and hour (429 `busy`); a new
  request is refused with 409 `denied` while the bundle names the user as denied (24 hours).
- **State.** Pending requests (entry, UPN, time; no justification) are kept in the agent's root-only self-service
  state file until the bundle reflects a decision or 30 days passed.
- **Withdrawal.** The user can withdraw a pending request. The agent reports it to the server
  (`software.request_withdrawn`) only while the bundle's software section carries `request_withdraw`, which only a
  server that understands the event renders; otherwise the withdrawal stays on the device.

The codes, the bundle fields and the server side are specified in plan M13c, amendments 2026-11-11 and
2026-11-11 b. This ADR's status and its open maintainer points are unchanged.

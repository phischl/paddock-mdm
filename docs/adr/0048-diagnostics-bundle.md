# 0048 — Diagnostics bundle (`collect_status`): a closed content list, sealed upload, gated download
Status: Accepted (2026-11-04 — the maintainer: the content list including `/var/log/apt/history.log`, the notice
text without the administrator's name, download by `org_admin` and `org_operator` with step-up; roadmap decision 3
is thereby taken)

## Context

Architecture §11.4 reserves the command `collect_status` (planned since the concept) and §11.3 a `collect_status`
playbook step. Today an operator who must understand a device that does not behave asks the user to run
`journalctl` and paste the output; there is no audited, bounded way to get the agent's own state off a device.
`docs/compliance/privacy.md` binds a negative list (no commands, process lists, connections, browser data,
keystrokes, screen content, location) and keeps free disk space and uptime in Fleet only. The roadmap (M12, F-16)
fixes the frame: a closed content list, audited request and download, only the hash in the WORM trail, 7-day
purge, a notice to the user, no auditor access.

The LUKS header escrow (plan M4b decision 10, `POST /v1/escrow` with `luks_header`) already moves a large sealed
object from a device into the escrow bucket with a presigned PUT and lets an administrator download it after a
step-up through the escrow-reader, which alone can unwrap the object key. The command runner
(`agent/internal/commands`) dispatches by type to a `Handler`; results are bounded to 4 KiB.

## Options

### What leaves the device
- **An open "collect what helps" list.** − Breaks the negative list on the first `ps` line.
- **A closed list in code, versioned, with every entry named in `privacy.md` (chosen).** + Auditable, testable
  (the agent test asserts the archive holds nothing else); a change is a privacy change with a document amendment.
  − Operators sometimes need more; they ask for a new list entry, not for a free command.

### Where the bundle is stored and who can read it
- **Plain object in the bundles or escrow bucket, downloaded by the api.** − Code execution in the api reads every
  device's logs.
- **Sealed on the device with a random key wrapped to `escrow-wrap`; the escrow-reader unwraps it after a step-up
  (chosen).** + The same guard as a recovery key: nothing without a fresh WebAuthn step-up and one audit event;
  no new key, no new role. − A download needs a step-up every time (the bundle is decrypted per download).
- **A new Transit key `diagnostics-wrap` decryptable by the api.** − Weaker than the escrow path for data that may
  contain user names, for no gain.

### Transport from the device
- **The command result.** − 4 KiB.
- **The events channel.** − 1 MiB batches, spooled, replayed; wrong tool.
- **A new device endpoint `POST /v1/diagnostics` that answers a presigned PUT, the shape of the header upload
  (chosen).** + Bounded (32 MiB), verified by size and SHA-256 by the worker, additive protocol change
  (ADR 0013). − One more device endpoint.

### How the user learns of it
- **Nothing.** − Not acceptable for a works council.
- **A desktop notification in every active graphical session, best effort, plus the audit event (chosen).**
  + Transparent at the moment it happens. − Needs `notify-send` in the user's session bus (`systemd-run
  --machine=<user>@.host --user`); a device without a desktop gets the event only.

## Decision

1. **Command.** `collect_status` (lifetime 1 h, `pkg/command.TypeCollectStatus`), params `{request_id,
   reason}`; `reason` is the administrator's text (2–500 characters), shown to the user.
2. **Content list (closed; `agent/internal/diagnostics/manifest.go` `Entries()`).** Paddock's own state:
   the health report of the agent socket, `state.json` without `identity`, `managed.json`, `probation.json`,
   `update-result.json`, `updates-result.json`, the supervisor upgrade result, `bundle.dsse` (signed, public),
   `trust.json`, `agent.yml`; the journals of `paddock-supervisor`, `paddockd`, `paddock-encrypt`,
   `paddock-uninstall`, `himmelblaud` and `himmelblaud-tasks` of the last 7 days (newest first, cut at 8 MiB per
   unit); `systemctl status` of those units and of `orbit`, `systemctl list-units --failed`; the Paddock-managed
   configuration: `/etc/sudoers`, `/etc/sudoers.d/*`, `/etc/pam.d/common-*`, `/etc/nsswitch.conf`,
   `/etc/himmelblau/himmelblau.conf` with the values of keys matching `(?i)secret|password|key` replaced by
   `<redacted>`, `/etc/apt/sources.list.d/paddock-*`, `/etc/apt/preferences.d/5*paddock*`, `/etc/crypttab`,
   `/etc/fstab`; the system facts `os-release`, `uname -a`, `timedatectl show`, `df -h / /boot /boot/efi`,
   `uptime -p`, `lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT`, `cryptsetup luksDump` of every LUKS volume the agent
   manages, the presence of `/dev/tpm0` and `/dev/tpmrm0`, `dpkg -l 'paddock*' 'himmelblau*' 'fleet*'`, `ip -brief
   link` (link state, no addresses), `resolvectl status` (resolver configuration), `/var/log/apt/history.log`
   (package operations: names and versions, no users), and the result of one `GET
   <server_url>/healthz`. Never: process lists, `auth.log`, other units' journals, home directories, shell history,
   network connections, addresses, user files. Every entry is a file in a tar.gz with a `manifest.json` (entry,
   bytes, SHA-256, `truncated`), the archive is cut at 32 MiB sealed.
3. **Sealing and upload.** The agent seals the archive as it seals a LUKS header (`escrow.SealObject`: AES-256-GCM
   with a random 32-byte key, the diagnostics ID as additional data, the key RSA-OAEP-wrapped to the bundle's
   `escrow_wrap` key), calls `POST /v1/diagnostics` `{command_id, sha256, size, nonce, wrapped_dek}` → `{upload_url}`
   (presigned PUT, 10 minutes, object key `org/<org>/devices/<device>/diagnostics/<command_id>.bin` in the escrow
   bucket), uploads, and posts the command result `{uploaded: true, files, bytes, truncated_entries,
   notified_sessions}`. The worker verifies size and SHA-256 and marks the row `stored` (the escrow round's shape).
4. **Server.** Organization table `device_diagnostics` (plan M12 §6.5). `POST /api/v1/devices/{id}/diagnostics`
   (`org_admin`, `org_operator`; body `{reason}`; audit `device.diagnostics_requested`), `GET
   /api/v1/devices/{id}/diagnostics` and `GET /api/v1/diagnostics` (lists, the same two roles — **never**
   `org_auditor`), `GET /api/v1/diagnostics/{id}/download` (`org_admin`, `org_operator`, `RequiresStepUp`; the
   escrow-reader unwraps the key for purpose `diagnostics` under the same step-up proof as a header; audit
   `device.diagnostics_downloaded` with `sha256` and `bytes`), `POST /api/v1/diagnostics/{id}/purge` (`org_admin`;
   audit `device.diagnostics_purged`). The device's event `diagnostics.collected` becomes
   `device.diagnostics_collected` (params `request_id`, `files`, `bytes`, `sha256`, `truncated_entries`,
   `notified_sessions`). The bundle's content never enters an audit event, a log or the WORM store: only the hash.
5. **Retention.** The worker's retention round deletes the object and clears `nonce`, `wrapped_dek` and
   `object_key` 7 days after `stored_at` (`retention.purged`, store `device_diagnostics`); the row's metadata (who,
   when, hash, downloads) stays for the action retention (ADR 0032). A `purge` does the same at once.
6. **Notice to the user.** Before the upload the agent sends to every active graphical session (`loginctl
   list-sessions`, `Type` `wayland` or `x11`, `State` `active`) the notification *"Paddock collected diagnostic
   data from this device for your administrator. Reason: <reason>. What was collected: Paddock's own logs and
   configuration, no personal files."* (localized by the device's `LANG` for `de` and `en`); the count of sessions
   reached is reported. The administrator's name is not shown (maintainer decision 2026-11-04).
7. **Privacy document.** `docs/compliance/privacy.md` gains the section *Diagnostics bundle (on request only)*
   listing decision 2 verbatim, the retention, who can request and download it and that auditors cannot read it;
   the row "free disk space, uptime" of the Fleet table gains "on request also in a diagnostics bundle".

## Consequences

- + An operator gets a device's Paddock state in one audited step; a user sees when it happens; an auditor sees
  that it happened (request, collection, download) and never the content.
- + No new dependency; the escrow bucket, the escrow-reader and the presigned-upload path are reused.
- − Every download costs a step-up; a device without a desktop session reports `notified_sessions: 0`.
- − The content list is closed: extending it is a privacy change with a document amendment and a release note.
- Follow-ups: the playbook step of architecture §11.3 stays unscheduled; M13b's desktop notification mechanism is
  the same `systemd-run --machine` call and reuses `agent/internal/desktop/notify.go`.

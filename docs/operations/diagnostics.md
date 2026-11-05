# Diagnostics bundle

A diagnostics bundle is Paddock's own state, journals and managed configuration of one device, collected on request
and downloaded by an organization administrator or operator (ADR 0048, plan M12). It replaces asking a user to run
`journalctl` and paste the output. What it holds, and what it never holds, is binding in
[privacy.md](../compliance/privacy.md#diagnostics-bundle-on-request-only); read that section before you request one.

## When to use it

Request a bundle when a device does not behave and the portal does not tell you why: a bundle that is not applied, an
agent update that rolled back, a login that fails through Himmelblau, a disk conversion that stops, a device that
reports a health error. Do not use it to look at what a user does: it holds nothing of that, and every request is
shown to the user and recorded.

## Request a bundle

1. Open the device, tab **Diagnostics**, and choose **Request diagnostics**.
2. Enter the reason (2 to 500 characters). The user of the device reads it in the notice, and it is recorded in
   `device.diagnostics_requested`. Write it for the user, for example *"Logins fail since Monday, ticket 4711"*.
3. The bundle appears in the list as `requested`. The device receives the `collect_status` command at its next
   check-in (within 5 minutes); the command expires after 1 hour.

`POST /api/v1/devices/{id}/diagnostics` with `{"reason": "…"}` does the same (`org_admin`, `org_operator`, also with an
API token). A device that is not active, or that has a collection `requested` already, answers 409 `invalid_state`.

On the device the agent then:

1. shows the notice in every active graphical session (the text is in
   [privacy.md](../compliance/privacy.md#diagnostics-bundle-on-request-only)); without such a session it logs
   `no active graphical session to notify of the diagnostics collection`;
2. collects the closed list into `/var/lib/paddock/diagnostics/<id>.tar.gz` (root only), seals it to the
   organization's escrow key, uploads it to the escrow bucket and deletes the local file;
3. reports the result with the next check-in.

The worker verifies the uploaded object's size and SHA-256 and marks the bundle `stored`, with `files`, `size`,
`sha256`, `truncated_entries` and `notified_sessions`.

The page **Diagnostics** (navigation, under *Devices*; `GET /api/v1/diagnostics`) lists the bundles of every device of
the organization.

## States

| State | Meaning |
| --- | --- |
| `requested` | the command is waiting for the device or the device is collecting |
| `uploaded` | the device reported the upload; the worker has not verified it yet |
| `stored` | verified; downloadable until `expires_at` |
| `failed` | see `failed_reason` below |
| `expired` | the 7 days ended, or the device never answered; the object and its key are deleted |
| `purged` | an administrator deleted it |

| `failed_reason` | Cause | What to do |
| --- | --- | --- |
| `invalid_params` | the device refused the command's parameters | request again; report it if it repeats |
| `collect_failed` | the device could not collect or seal (no escrow key in its bundle, a full queue of four collections) | check that the device applied a bundle with the escrow key (*Apply status*), request again later |
| `too_large` | the sealed archive exceeded 32 MiB | should not happen (the content is cut at about 24 MiB); report it |
| `upload_refused` | the server refused the announcement | check that the command was still pending (1 hour) and request again |
| `upload_failed` | the network, the gateway or the escrow bucket failed during the upload | check the device's connectivity and `docs/operations/disk-recovery.md` (the escrow bucket), request again |
| `size_mismatch`, `sha256_mismatch` | the uploaded object is not the announced one | request again; repeated mismatches on one device are a reason to inspect it |
| `missing` | no object arrived within 15 minutes of the announcement | as `upload_failed` |
| `unknown` | the device sent a reason Paddock does not know, or an agent older than the diagnostics bundle answered `unsupported_type` | update the agent |

## Download

**Download** (or `GET /api/v1/diagnostics/{id}/download`) needs a fresh step-up every time
([step-up.md](step-up.md)): the escrow-reader unwraps the bundle's key for the purpose `diagnostics` only for an
`org_admin` or `org_operator` with a step-up, and the bundle is decrypted for this one download. An API token cannot
download. Before anything is served, the api checks the stored object against the size and SHA-256 the worker
verified; a replaced or missing object answers 409 and nothing is unwrapped. Every attempt is
`device.diagnostics_downloaded` with the bundle's SHA-256.

The file is `paddock-diagnostics-<hostname>-<id>.tar.gz`. Keep it only as long as you need it and do not attach it to
tickets outside your organization: it is personal data of the device's users (RR-108).

## Read the archive

```sh
mkdir bundle && tar -xzf paddock-diagnostics-<hostname>-<id>.tar.gz -C bundle
jq . bundle/manifest.json
```

`manifest.json` (`schema: paddock.diagnostics.v1`) comes first and lists every entry of the closed list in order,
with `bytes`, `sha256`, `truncated` and `error`. An entry with several files (`etc/sudoers.d`, `etc/pam.d`, the two apt
directories, `system/luksDump`) has a `files` list instead of its own hash. An `error` means the device lacks the
source (no `/etc/crypttab` on an unencrypted device, no Himmelblau on a device without directory login) or the
command failed; it is not a fault of the collection. `truncated: true` means the cap was hit: journals keep their
newest lines.

`systemd/status.txt` is `systemctl show` of the units `paddock-supervisor`, `paddock-supervisor-upgrade`,
`paddock-encrypt-resume`, `paddock-uninstall`, `himmelblaud`, `himmelblaud-tasks` and `orbit`, one block per unit in
this order, separated by a blank line, with only `ActiveState`, `SubState`, `Result`, `ExecMainStatus` and the state change,
start and exit timestamps. It holds no processes, command lines or journal lines; for the log of a unit read its
journal file (`orbit` has none in the bundle).

Where to look first:

| Question | Files |
| --- | --- |
| What does the agent think of itself? | `paddock/health.json`, `paddock/state.json`, `systemd/status.txt` |
| Why was a bundle not applied? | `journal/paddockd.log` (newest first), `paddock/bundle-redacted.json`, `paddock/managed.json` |
| Did an update roll back? | `paddock/update-result.json`, `paddock/probation.json`, `paddock/supervisor-upgrade-result.json`, `journal/paddock-supervisor.log` |
| Package updates and sources | `paddock/updates-result.json`, `system/apt-history.log`, `etc/apt/`, `system/dpkg.txt` |
| Logins and sudo | `journal/himmelblaud.log`, `journal/himmelblaud-tasks.log`, `etc/himmelblau/himmelblau.conf`, `etc/pam.d/`, `etc/nsswitch.conf`, `etc/sudoers*` |
| Disk encryption | `journal/paddock-encrypt.log`, `system/luksDump-<uuid>.txt`, `system/lsblk.txt`, `etc/crypttab`, `system/tpm.txt` |
| Can the device reach the server? | `system/server-healthz.txt`, `system/resolvectl.txt`, `system/ip-link.txt`, `system/timedatectl.txt` |

`<redacted>` marks a removed secret. `paddock/bundle-redacted.json` is a rendering of the applied bundle with every
field that is not known to be public replaced; it is not the signed envelope and its signatures do not verify.

## Purge and retention

A stored bundle is deleted 7 days after it was stored: the worker's retention round deletes the object and its key
material and records `retention.purged` (store `device_diagnostics`). An organization administrator can delete it
earlier with **Purge** (a confirmation dialog; `POST /api/v1/diagnostics/{id}/purge`), recorded as
`device.diagnostics_purged`. A purge also deletes, at the end of the upload window, an object a device might still
upload with a URL issued before the purge. The record of the request (who, when, reason, hash, downloads) stays for
the retention of the organization's actions.

## Roles

| | `org_admin` | `org_operator` | `org_auditor` | API token (`org_admin`/`org_operator`) |
| --- | --- | --- | --- | --- |
| Request, list, read | yes | yes | no (403; no tab, no page) | yes |
| Download (step-up) | yes | yes | no | no (step-up is not possible for a token) |
| Purge | yes | no | no | yes (`org_admin` token) |

Platform administrators have no access to an organization's bundles.

## Audit codes

| Code | When |
| --- | --- |
| `device.diagnostics_requested` | a request, with the reason and the command ID |
| `device.diagnostics_collected` | the worker verified the upload (success, with `sha256`, `bytes`, `files`, `truncated_entries`, `notified_sessions`), or the bundle failed (failure, with `reason`) |
| `device.diagnostics_downloaded` | every download attempt, with `sha256` and `bytes` on success |
| `device.diagnostics_purged` | a purge |
| `retention.purged` (store `device_diagnostics`) | the 7-day deletion |

The descriptions are in [audit-codes.md](../compliance/audit-codes.md). No event, log line or WORM object holds the
content of a bundle, only its hash.

## Residual risks

RR-108 (journals name users) and RR-109 (the notice is best effort) in
[residual-risks.md](../compliance/residual-risks.md).

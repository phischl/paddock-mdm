# Implementierungsplan: M5a — Inventory and vulnerabilities (Fleet integration)

Status: Ready for implementation · 2026-10-07 · Author: architect
Basis: architecture v1.7 §15 (Fleet, A10), §4.1 (hostnames), §11.5 (mutual watch), §14 privacy table; concept F4, C9,
"Privacy by design" (negative list), ADR 0009; M4b (Debian packages in the artifact bucket, autoinstall)

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**. M5 is split: **M5a** (this plan) brings Fleet,
fleetd, inventory and vulnerabilities; **M5b** brings update management (holds, schedules, immediate install) and
staleness alerts.

## 1. Goal
Every Paddock device runs fleetd/osquery; the portal shows each device's installed packages and matching
vulnerabilities, and fleet-wide views per package and per CVE — strictly per organization, with Fleet hidden behind
Paddock. Agent and fleetd watch each other.

## 2. Context
- Fleet free edition requires MySQL 8 and Redis. Its UI and admin API MUST NOT be reachable publicly; only the device
  endpoints `/api/osquery/*`, `/api/fleet/orbit/*` (and the fleetd update endpoints if fleetd needs them) are
  published under `fleet.<domain>` (architecture §4.1).
- Fleet has no organization concept in the free edition (ADR 0009): Paddock maps hosts to devices by hardware UUID
  and stores everything under the device's organization (RLS).
- The concept's negative list (binding): never collect executed commands, process lists, network connections,
  browser or application data, keystrokes, screen content, location.

## 3. Binding decisions
1. **Stack:** services `fleet` (image `fleetdm/fleet`, newest stable, pinned by digest — approved), `fleet-mysql`
   (`mysql:8.4`, approved), `fleet-redis` (`valkey/valkey:8`, the already pinned image — Fleet speaks the Redis
   protocol; if Fleet refuses Valkey, use `redis:7` pinned, approved as fallback, and record it). Fleet is initialized
   by a bootstrap script: admin user (secret file), an **API-only** user for Paddock (token in a secret file),
   global enroll secret (secret file), server settings below. Caddy publishes only the device paths under
   `fleet.<domain>`; any other path → 404 at the proxy.
2. **Data minimization (C9):** Fleet settings `features.enable_host_users = false`, `enable_software_inventory = true`;
   no scheduled queries, no query packs, no live queries by Paddock; activity webhooks off. Paddock defines **policies
   only** (pass/fail): they return a boolean per host, never row data. The bootstrap verifies the settings at every
   start (worker reconcile, decision 6) and resets drift.
3. **fleetd package:** built per Paddock agent release with `fleetctl package --type deb --fleet-url
   https://fleet.<domain> --enable-scripts=false --disable-open-folder ...` (image `fleetdm/fleetctl` pinned, approved)
   **without** an enroll secret, published into the artifact bucket like the agent packages (`packages/<version>/
   fleet-osquery_<fleetd version>_amd64.deb`, plus SHA-256). Fleet desktop is disabled (no tray UI); auto-updates of
   fleetd from Fleet's TUF server are **disabled** (Paddock delivers fleetd versions). If `fleetctl package` cannot
   disable updates or scripts, stop (S1).
4. **Bundle (schema v2, additive):** `inventory: {fleet_url, enroll_secret, package: {version, url_path, sha256}}`.
   The enroll secret is delivered in the signed bundle in plain text; rationale: it only allows enrolling a host into
   Fleet, Paddock ignores hosts it cannot map, bundles are fetched only by their device over TLS with presigned URLs.
   (HPKE encryption of bundle secrets stays a later improvement — record it in §12 of this plan's report.)
5. **Agent `inventory` reconciler:** install the fleetd package from `https://bundles.<domain>/<url_path>` (SHA-256
   checked, through the M4b.1 bounded apt/dpkg path), write the enroll secret to the path fleetd reads
   (`/opt/orbit/secret.txt`, 0600), ensure `orbit.service` enabled+active. fleetd and its paths become a protected area
   (concept protected areas item 3 already names `fleetd`). The agent watches `orbit.service`
   (`tamper.service_stopped {unit}`).
6. **Mapping and sync (worker):** every 5 minutes the worker pages through Fleet hosts changed since the last cursor
   (`ListHostsChangedSince`), maps `hardware_uuid` → device (unique per organization; ambiguous or unmapped hosts →
   metric `paddock_inventory_unmapped_hosts`, never stored), and for mapped hosts stores: OS version, osquery/fleetd
   version, last seen, software list, vulnerabilities, policy results. Removed software rows are deleted
   (`ON CONFLICT` upsert + delete-missing per device in one transaction). Fleet IDs only in
   `device_inventory_ref.external_id`.
7. **Entities** (organization-scoped, RLS): `device_inventory_ref(device_id PK, external_id, last_seen_at, os_version,
   fleetd_version)`, `installed_software(device_id, name, version, source, PRIMARY KEY(device_id,name,version,source))`,
   `vulnerability_finding(device_id, cve, software_name, software_version, cvss_score numeric null, severity
   text null, fixed_version text null, first_seen_at, PRIMARY KEY(device_id,cve,software_name,software_version))`,
   `inventory_policy_result(device_id, policy_key, passing bool, updated_at)`.
8. **Policies** (`server/internal/inventory/policies/*.sql`, pushed through the Fleet API by the worker, idempotent):
   - `paddock_agent_running`: `SELECT 1 FROM processes WHERE name = 'paddockd' AND path LIKE '/opt/paddock/agent/%';`
     (returns pass/fail only — a policy, not a process list; this distinction is documented in the privacy docs);
   - `disk_encrypted`: root on dm-crypt (osquery `block_devices`/`disk_encryption`);
   - `ntp_synchronized`: `timedatectl`-equivalent via osquery if available, else omitted.
   A failing `paddock_agent_running` for a device whose last Paddock check-in is older than 15 min raises audit
   `device.tamper_agent_not_running` (mutual watch).
9. **Admin API** (list contract everywhere): `GET /api/v1/devices/{id}/software` (search name; sort name, version),
   `GET /api/v1/devices/{id}/vulnerabilities` (filters severity; sort cvss, cve), `GET /api/v1/software` (aggregated:
   name, version, device_count; search; filter has_vulnerabilities), `GET /api/v1/vulnerabilities` (aggregated per
   CVE: severity, cvss, affected device count, fixed version; filters severity, cve search), `GET
   /api/v1/vulnerabilities/{cve}/devices`. Read-only; no audit events for reads.
10. **Portal:** device detail tabs *Software* and *Vulnerabilities*; top-level pages *Software* and
    *Vulnerabilities* (DataList); dashboard tile on the start page: devices with critical/high findings.
11. **Privacy documentation:** `docs/compliance/privacy.md` lists exactly what Paddock and Fleet collect (with Fleet's
    detail queries named) and the negative list; it states that policies return pass/fail only.

## 4. Non-goals
Update management, holds, immediate installs, staleness alerts (M5b); Fleet premium features; live queries; software
uninstall; Fleet UI access for anyone but platform operators via local port-forward (documented).

## 5. Steps
0. **M4c review follow-ups** (one commit each):
   a) Himmelblau's NSS module answers `getent passwd` for **any** name (synthesised entries). Audit every place where the
      agent or its package scripts decide "does this user exist / which UID" (sudo UID resolution, deny-list short
      names, local admin, session detection, postinst scripts) and make each one either use the local files
      (`/etc/passwd`, `/etc/group`) or require an entry that Himmelblau marks as a real directory user. Document the
      result in `docs/operations/device-login.md`; add unit tests for the corrected spots. CHANGELOG `Fixed` if behaviour
      changes. **Amended 2026-11-10:** the synthesis also breaks the maintainer scripts of other packages; see
      "Amendment 2026-11-10" at the end of this plan.
   b) Dead man's switch: when the self-lock token is deleted (switch disabled), the agent removes its pending warnings
      (desktop notification state and `/etc/issue.d/80-paddock-dms.issue`) immediately, not only after the next bundle.
      Unit test.
1. Stack + bootstrap + Caddy restrictions + settings check. Gate F0: from outside, `fleet.<domain>/api/latest/fleet/*`
   and the UI return 404; device paths work.
2. fleetd package build into the release pipeline; agent `inventory` reconciler; bundle field. Gate F1 (both VMs, in
   parallel): fleetd installed from Paddock's package store, host enrolled, mapped to the device within one sync round.
3. Worker sync + entities + policies + mutual watch. Gate F2: stopping paddockd on a VM → `device.tamper_agent_not_running`;
   stopping orbit → `tamper.service_stopped`.
4. Admin API + portal + privacy doc. Gates F3: software and vulnerability lists per device and fleet-wide, isolation
   (acme never sees globex inventory), list contract; F4: an intentionally old package version on a VM
   (e.g. `apt install <pkg>=<older version>`) shows its CVE.
5. Regression from reset (acceptance, e2e, system tests on both VMs in parallel).
One commit per step.

## 6. Acceptance criteria
| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given an enrolled device, then within 10 minutes the portal lists its installed packages and known vulnerabilities | F4 | Org admin |
| AC2 | Given two organizations, then neither sees the other's inventory, and Fleet's own UI/API is not reachable publicly | F10, ADR 0009 | Org admin, platform operator |
| AC3 | Given someone stops the agent or fleetd, then the other reports it | F9 | Org admin (audit) |
| AC4 | Given the privacy doc, then everything collected is listed and nothing from the negative list is collected | C9 | Auditor |

## 7. Stop conditions
S1 fleetd cannot be packaged without auto-update/scripts; S2 Fleet's free API lacks per-host software or
vulnerabilities; S3 Fleet cannot be configured to skip host-user collection; plus M0 §11 S2/S6/S7/S8.

## Amendment 2026-11-10 — the agent holds himmelblaud around its own package transactions (PDK-983; `decisions-alpha10.md` §45 and §47)

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**. Tickets: PDK-983 (N1–N8), PDK-985 (N9). N1–N5,
N7 and N8 record the implementation of PDK-983 as reviewed at `a75204af`; N6 (the regular updates run) is decided by
§47 and not implemented at that commit.

### Why

Step 0a established that Himmelblau's NSS module answers `getent passwd` for any name, and made the agent and
Paddock's own package scripts decide from the local files. It missed the packages of others: Debian's `adduser`
and shadow's `useradd` ask NSS before they create an account. On an enrolled device, while `himmelblaud` runs and
has reached the identity provider, Himmelblau 4.0.8 returns a synthetic directory user for the new name (also for a
name in a foreign domain; groups are not synthesized), and the maintainer script fails: `adduser --system` with exit
13 "already exists, but is not a system user", `useradd` with exit 9. Measured on Ubuntu 24.04 and 26.04: the same
command succeeds before enrollment and with `himmelblaud` stopped. Every package that creates a system account is
affected (`flatpak` with `_flatpak`, database and other daemon packages). The row "Package scripts: no user or group
lookups" of `docs/operations/device-login.md` covers Paddock's own packages only.

Options: (a) `cn_name_mapping = false`: the bare name is still synthesized, and every directory user's name and home
change. (b) nsswitch order or `[NOTFOUND=return]`: `files` is first already; glibc cannot select a source by name.
(c) a `name_mapping_script`: changes the names and homes of existing users and cannot tell a system account from a
directory user. (d) a global dpkg hook that stops `himmelblaud`: also pauses logins for every apt run of anybody and
puts a new writer into the protected identity configuration. (e) an upstream option that synthesizes only full UPNs
of the tenant domain, then a pin bump. (f) a hold around the agent's **own** transactions.
**Decision: (f) for alpha.10, (e) as the fix** (maintainer decision §45). ADR 0019 and the pinned version are
**not** changed now; the pin bump, the rendered option and the removal of the hold follow with the upstream fix.

### N1 Vocabulary

- **Transaction** = one `apt-get` call with the verb `install`, `reinstall`, `remove`, `purge`, `upgrade`,
  `dist-upgrade`, `full-upgrade`, `autoremove` or `autopurge`, or one `dpkg` call with `-i`, `--install`,
  `--unpack`, `--configure`, `-r`, `--remove`, `-P`, `--purge` or `--triggers-only`. A call with `-s`, `--simulate`,
  `--just-print`, `--dry-run`, `--recon`, `--no-act`, `-d` or `--download-only`, `apt-get update` and every query
  are no transactions.
- **Hold** = the time `himmelblaud.service` is stopped by Paddock around one transaction.
- **Foreign stop** = `himmelblaud.service` inactive or failed without a hold.

### N2 The hold (`reconcile.NSSShield`, `agent/internal/reconcile/shield.go`)

1. Every transaction the agent process runs MUST run under the hold: the applier (login and Himmelblau packages,
   required and forbidden software, updates), fleetd, self-service installs and removals, and *Install now*
   (`reconcile.Shielded` wraps the `System` these receive). One hold at a time; transactions are serialized.
2. When `himmelblaud.service` is not active, the transaction runs without a hold and no event is emitted. A device
   without directory logins is not touched, and a stopped daemon is never started by the shield.
3. Order before the transaction, binding: write the marker `/var/lib/paddock/state/nss-shield.json` (mode 0600;
   action and start time); remove a stale safety timer; arm the safety timer (N3); `systemctl stop
   himmelblaud.service`. When the marker or the timer fails, the daemon is not stopped, the transaction runs with
   the daemon running and the outcome is `hold_failed`. `himmelblaud-tasks.service` is never stopped explicitly.
4. The restore (`systemctl start himmelblaud.service himmelblaud-tasks.service`) MUST run on every path: success,
   error, panic (which still propagates) and a cancelled context (it runs on its own context with a timeout of
   2 minutes).
5. **Maximum hold: 10 minutes** (`NSSShieldMaxHold`). When a transaction is still running then, the daemons are
   started while it runs, the fact is logged, and the outcome is `max_hold`. The transaction is not interrupted.
6. The marker is removed after the hold's event was emitted. The safety timer is cancelled only when the start
   succeeded; otherwise it stays armed.
   **Corrected 2026-11-10 (`decisions-alpha10.md` §48 point 2):** after a failed restore the marker is **kept**. The
   event with the outcome `restore_failed` is emitted once, and the marker records that it was. The agent retries
   the start at its next start and in every login reconciler pass, without a second event, and removes the marker
   and cancels the timer once the start succeeded. Reason: with the marker gone, a daemon that stayed down would
   look like a foreign stop and never be started again by the agent (N3.3, N5).

### N3 Recovery without the agent

1. **Safety timer:** the transient systemd timer `paddock-nss-shield-restore` (`systemd-run --unit=… --on-active=…
   --timer-property=AccuracySec=1s`) runs `systemctl start himmelblaud.service himmelblaud-tasks.service`
   **12 minutes** after the hold began (maximum hold plus `NSSShieldTimerGrace` of 2 minutes). It depends on nothing
   of Paddock, so a killed agent or supervisor cannot leave directory logins stopped.
2. **Marker recovery:** at its start, before the first pass, the agent calls `NSSShield.Recover`: a marker means a
   hold whose process died. The agent starts both daemons (the timer may have done so already), cancels the timer
   and reports the hold once with the outcome `recovered` (`restore_failed` when the start fails).
3. Without a marker a stopped `himmelblaud` is left alone (agent design contract 8, and N5).
4. A build with the tag `paddock_dev` uses 4 minutes and 1 minute (timer after 5 minutes) so that the system gate
   can wait for the timer. These values MUST NOT reach a release build.

### N4 One event per hold

- Device event `login.nss_shield` (`pkg/protocol`), audit code **`device.login_nss_shield`** (closed registry,
  outcome `success`), params `action` (the transaction, for example `apt-get install`), `duration_s`, `outcome`,
  `error`. Exactly one event per hold; a transaction without a hold (N2.2) emits none.
- `outcome`: `restored`, `max_hold`, `recovered`, `restore_failed` (the safety timer retries), `hold_failed`.
- No package names, no user names and no secrets in the params. `api/openapi/device.yaml` lists the event type; an
  older server refuses the batch like every earlier new event type (server-first upgrade order).

### N5 A foreign stop is reported, never repaired

- The login reconciler reports a foreign stop once per stop as the existing event `tamper.service_stopped`
  (audit code `device.tamper_service_stopped`, params `unit` = `himmelblaud.service`, `state` = `inactive` or
  `failed`), and again only after the daemon ran in between. No new audit code.
- It MUST NOT report the daemon while a hold of Paddock is in progress, and it MUST NOT start the daemon: a local
  administrator's stop around an installation (the documented workaround) is not undone, and the agent does not
  heal on its own initiative.
- The registry note of `device.tamper_service_stopped` in `server/internal/domain/audit/codes.go` MUST name
  `himmelblaud.service` as a covered unit that is reported only (§47; `docs/compliance/audit-codes.md` is
  regenerated).
- `/etc/himmelblau/`, PAM and NSS configuration are not written by the hold. Protected area 4 is unchanged.

### N6 The regular updates run (`paddockd updates run`; §47 point 1)

`paddockd updates run` is a process of its own (`osupdates.RunRegular`: `apt-get update`, then `apt-get
dist-upgrade`, and `dpkg --configure -a` after an interrupted installation). It is one of the agent's own
transactions and MUST run under the same hold. A second process changes three things, decided here:

1. **One hold per run**, around the `dist-upgrade` step with its `dpkg --configure -a` and retry, with the action
   `apt-get dist-upgrade`. `apt-get update` runs before the hold. N2.2–N2.6 and N3.1 apply unchanged, with the same
   marker, timer name and durations.
2. **Mutual exclusion between processes:** a hold is held under an exclusive `flock` on
   `/var/lib/paddock/state/nss-shield.lock`, taken before the check of N2.2 and released after the marker is gone. A
   process that finds the lock taken waits for it. The lock, not the marker, says that a hold is in progress.
3. **Recovery and tamper detection use the lock:** `NSSShield.Recover` (N3.2) takes the lock without waiting; when
   it is taken, another process holds and nothing is recovered. The agent MUST run the same check in every login
   reconciler pass, so that a hold whose process died is reported as `recovered` while the agent runs. The login
   reconciler (N5) treats a stopped daemon as held while the lock is taken or the marker exists.
   (Amended 2026-11-11: only a marker younger than 12 minutes counts; "Amendment 2026-11-11 b", P2.)
4. **Event:** the updates process cannot emit device events. Under the lock, after its restore, it appends one
   record `{action, duration_s, outcome, error}` to the JSON array in
   `/var/lib/paddock/state/nss-shield-report.json` (mode 0600, atomic replace, at most 16 records, the oldest
   dropped) and removes the marker. The agent emits every record as `login.nss_shield` in its next pass, under the
   lock, and removes the file. N4's "exactly one event per hold" holds across both processes.
5. Effect: directory logins and screen unlocks wait during every regular updates run, at most 10 minutes per run.
6. **Accepted bound (added 2026-11-11): the hold can end before the run does.** The hold covers the run only while
   `himmelblaud` stays stopped. Two cases start it mid-run: a `dist-upgrade` that outlasts the maximum hold of 10
   minutes (N2.5; outcome `max_hold`), and a run that upgrades the Himmelblau packages themselves, whose maintainer
   scripts start the daemon. A package configured **after** that point that creates a system account fails as it
   did without a hold ("already exists, but is not a system user"). The run is not interrupted; it reports the
   failure in its result (`updates.run` with the result and error of the run), and the next regular run finishes
   the installation (`dpkg --configure -a`, then `dist-upgrade`) under a new hold. N6 does not extend the hold
   beyond 10 minutes and does not stop the daemon a second time within one run: a longer or repeated stop would
   widen the login pause for a case that the next run repairs. Named in RR-133.

### N7 Effect on users (binding content for the operator documents)

While the agent runs a transaction on a device with directory logins, **new logins and screen unlocks of directory
users wait** until the hold ends: seconds, minutes for large packages, at most 10 minutes per transaction. Running
sessions continue; local accounts, the managed local administrator included, are not affected. Offline logins wait
as well, because the daemon that serves them is stopped.

**Corrected 2026-11-10 (`decisions-alpha10.md` §48 point 1):** "running sessions continue" means that no session is
ended. During a hold directory users and groups may not resolve through NSS, by name or by ID. Observed effects in
a running session of a directory user: `ls -l` and `id` show numeric IDs in place of names, and `sudo` by a
directory user can fail until the hold ends. Local accounts and the managed local administrator resolve from the
local files and are not affected. The operator documents and RR-133 MUST say this in these terms. The effect is
confirmed by the logging step of the system gates on both VMs and recorded with PDK-983.

**Corrected 2026-11-11 (`decisions-alpha10.md` §52; replaces the correction of 2026-11-10 above and with it §48
point 1).** Final wording, confirmed by the system gates on Ubuntu 24.04 and 26.04: **running sessions continue;
signed-in directory users resolve by name and UID during a hold.** `ls -l`, `id` and `sudo` in such a session
behave as without a hold; the earlier statements about numeric IDs and failing `sudo` are withdrawn. Local accounts
and the managed local administrator are not affected. The operator documents and RR-133 MUST use this wording.

One caveat stays, because it is measured and is the mechanism of the hold itself: a name the device has never seen
does not resolve while the daemon is stopped (PDK-983's probe on both releases: `getent passwd <unknown name>`
answers with a synthetic user while `himmelblaud` runs and "not found" while it is stopped; that is why `adduser`
then succeeds). A directory user who has never signed in on the device is such a name. It matters only for a
lookup of that user during a hold, not for anybody who is signed in.

**Design note 2026-11-11 — users are named, never numbered.** On an enrolled device Himmelblau synthesizes a user
for any unknown name, a string of digits included: `208071` passed where a tool accepts a user **name** can resolve
to a synthetic user with another UID than the number meant. Code, package scripts and tests MUST therefore switch
to and address a user by name wherever a tool accepts a name or a number: `setpriv --reuid`, `id`, `sudo -u`,
`chown`, `install -o`, `systemd-run --uid`. Where only a UID is at hand, it is first resolved to its name from the
local files or from the session, or passed in a form the tool defines as numeric only (`sudo -u '#<uid>'`).

### N8 Tests and gates (names as implemented in PDK-983)

- Unit, `agent/internal/reconcile/shield_test.go`: the call order of N2.3; restore on error, panic and cancel;
  maximum hold; the skip of N2.2; a failed restore keeps the timer; `hold_failed` stops nothing; `Recover` with and
  without a marker; the classification of N1; own hold against foreign stop in the login reconciler (reported once,
  never started, reported again after a restart). `agent_test.go` `TestRunRecoversNSSShield`;
  `devicereports_test.go` `TestLoginNSSShieldEvent`.
- N6 adds: two processes contend for the lock (the second waits and holds afterwards); `Recover` with the lock taken
  recovers nothing; a record file with two records yields two events and is removed; a dead holder is reported as
  `recovered` by a running agent.
- System gates: plan M13b, amendment 2026-11-10 (SV5, SV6, SV10, SV11). `TestIdentityGates` MUST stay green on both
  VMs, because the login reconciler changed. For N6: a regular updates run that installs a package creating a
  system account succeeds on an enrolled device and yields one `device.login_nss_shield`.
  **Corrected 2026-11-10 (`decisions-alpha10.md` §48 point 3):** that system gate for N6 is a ticket of its own in
  alpha.10 (PDK-988) and MUST be green before the release tag. Until it lands, the unit tests of N6 above carry the
  rule. PDK-983 is not blocked by it.
  **Added 2026-11-11 — accepted test-scope limit of that gate (SV12, PDK-988).** SV12 runs in
  `TestSelfServiceGates`, the gate with an enrolled device. For the length of its run it restricts apt to the
  gate's own package source with a temporary `/etc/apt/apt.conf.d/99paddock-gate-sv12` (`Dir::Etc::sourcelist` =
  the gate source, no `sourceparts`, no list cleanup), removed when the step ends. Without it the `dist-upgrade`
  would also pull distribution and Himmelblau updates, which trigger exactly the two cases of N6.6 and make the
  gate depend on the day's archive. SV12 therefore proves the hold for one package that creates a system account,
  not a full distribution upgrade; N6.6's bound is covered by the unit tests of the maximum hold, not by a gate.

### N9 Open in PDK-985 (not decided here)

**Decided 2026-11-11: no hold for either path; see "Amendment 2026-11-11 b", P1.**

`paddockd supervisor-upgrade` (`dpkg -i paddock-supervisor`) and the uninstall helper run outside the agent process
and are **not** under the hold. PDK-985 decides whether they need it: the supervisor path only if its packages can
create a system account; the uninstall helper purges the Himmelblau packages itself. Until then RR-133 names them.

### Stop conditions

- The unit that runs `paddockd updates run` may not call `systemctl stop`/`start`, `systemd-run`, or write
  `/var/lib/paddock/state/` (sandboxing): stop and report, do not loosen the unit without a decision.
- Any need to write `/etc/nsswitch.conf`, `/etc/pam.d/` or `/etc/himmelblau/` for the hold.
- Any path on which the daemons are started without a marker, a lock or a report of Paddock's own.

### Residual risks and documents

- `docs/compliance/residual-risks.md`: **RR-133** (new, written with this amendment) and RR-07 (updated).
- `docs/operations/device-login.md`, section "Package installations pause directory logins" (PDK-983): N7, the
  bounds of N2.5 and N3.1, the event of N4, N5 and the workaround for a local administrator's own apt run
  (`systemctl stop himmelblaud.service` before, `systemctl start himmelblaud.service himmelblaud-tasks.service`
  after). PDK-983 adds the regular updates run to its list when N6 is implemented.
- `docs/operations/software.md`: "What the device does", "Self-service app", "Residual risks" (written with this
  amendment) and the troubleshooting row (PDK-983).

**Addendum 2026-11-17 (PDK-1126).** Himmelblau 4.0.8's `himmelblaud.socket` stops with the daemon (`PartOf`) but keeps
its socket file (`RemoveOnStop=no`), so during a hold `pam_himmelblau` prints "connection refused" to the standard
output of every PAM caller; with the file missing, account and session checks (`sudo -u` or `sudo -n` without a
password prompt) print nothing, while a password authentication still waits about 1 s, shows two Himmelblau
messages at the login prompt (PAM conversation) and prints one "timed out waiting for himmelblaud socket" line on
standard output, also for local users. The login reconciler therefore
manages the drop-in `/etc/systemd/system/himmelblaud.socket.d/90-paddock.conf` (`RemoveOnStop=yes`, nothing else), and
the same drop-in for `himmelblaud-tasks.socket` and `himmelblaud-broker.socket`, like `himmelblau.conf`: written
before the installation, rewritten on drift with a `daemon-reload` and reported as `login.applied` (`config`); a
failed reload is retried by the next pass, and a failure after the deny list is reported only after the sessions of a
lock were handled. The `reset` removal takes them out again together with the socket files and the `himmelblau`
sources nss-himmelblau's postinst appended to `/etc/nsswitch.conf`. The PAM wait of about 1 s per password
authentication during a hold is recorded in RR-133.

## Amendment 2026-11-11 b — the remaining points of the hold (PDK-985, PDK-990, PDK-991; architect decisions)

Three stubs left open by the amendment 2026-11-10 are decided. Binding language: **MUST** / **MUST NOT**. Where
this amendment contradicts N3, N5, N6.3 or N9, it wins.

### P1 PDK-985: the supervisor upgrade and the uninstall helper get **no** hold (replaces N9)

- **Supervisor upgrade** (`paddockd supervisor-upgrade`: `dpkg -i paddock-supervisor_<v>_<arch>.deb`). The package
  has no dependency it could pull in (`dpkg -i` installs exactly one file), and its maintainer scripts
  (`packaging/scripts/supervisor-postinst.sh`, `-prerm.sh`, `-postrm.sh`) create no user or group and look none up.
  Nothing in that transaction can fail on Himmelblau's synthetic users, so a hold would only pause logins.
- **Uninstall helper.** Its package calls are `apt-get update` and purges (the Himmelblau packages, fleetd,
  `paddock-revoke`, `paddock-agent`, `paddock-supervisor`). A purge creates no account, and the helper removes the
  cause itself when it purges Himmelblau. A hold here would also need a marker, a timer and a report from a
  process that is removing the agent that reports.
- **Guard (alpha.10, small):** a test MUST fail when a maintainer script of `paddock-supervisor` or `paddock-agent`
  gains a user or group creation or lookup (`adduser`, `addgroup`, `useradd`, `groupadd`, `getent`,
  `systemd-sysusers`), next to the packaging checks that `make test` runs. That keeps the reason for "no hold"
  true; a script that needs an account later reopens this decision.
- RR-133 no longer lists the two paths as a gap. **PDK-985 closes with this decision and the guard.**

### P2 PDK-990: only a fresh marker counts as a hold (replaces the last sentence of N6.3)

- **Finding.** N6.3 let the login reconciler treat a stopped `himmelblaud` as held "while the lock is taken or the
  marker exists". A local administrator can hold the lock file for ever (`flock … sleep infinity`), stop the
  daemon, and no `tamper.service_stopped` is ever reported; the agent's package transactions are deferred
  meanwhile and show only `pending` / `dpkg_locked`.
- **Rule.** A stopped `himmelblaud` counts as held **iff a marker exists whose start time is younger than the
  maximum hold plus the timer grace** (`NSSShieldMaxHold + NSSShieldTimerGrace`: 12 minutes; 5 minutes in a
  development build). The lock alone never counts. Reason: every legitimate hold writes its marker before it stops
  the daemon (N2.3) and ends at the maximum hold; the safety timer has fired by the bound.
- Outside the rule the stop is reported once as `tamper.service_stopped` (N5, unchanged event and params), whatever
  holds the lock. That includes a hold whose restore failed and whose marker is kept (N2.6): after the bound the
  device reports both the `restore_failed` hold and the stopped service, which is true.
- **A lock held without a hold.** When the agent cannot get the lock for a transaction within its wait, it MUST
  log at `Warn`, at most once an hour, that the shield lock is held by another process and for how long. No new
  event, no new status reason: the transaction stays `pending` / `dpkg_locked` as today.
- **Not closed:** a local administrator with root can also rewrite the marker, or stop the agent. That is the root
  bypass of RR-01; this rule removes the cheap, silent variant only.
- **Accepted bound (added 2026-11-11, PDK-990/991 review 2):** the marker's age is measured on the wall clock,
  across processes. When the device's clock steps forward by more than the bound (12 minutes) during a hold of the
  updates process, the agent sees an old marker and reports one false `tamper.service_stopped` for that hold. A
  step backward only lengthens the time a marker counts. One false report at a clock step is accepted over a
  cross-process monotonic clock; RR-133 names it.
- Tests (unit): lock taken, no marker, daemon stopped → reported once; fresh marker → not reported; marker older
  than the bound → reported once; the agent's own hold and a hold of the updates process inside the bound → not
  reported (the existing tests stay green).
- **Scope: 0.1.0-alpha.10** (PDK-990, implementer). It is one predicate in the login reconciler plus one log line.
  `TestIdentityGates` and `TestSelfServiceGates` (SV11, SV12) MUST stay green on both VMs.

### P3 PDK-991: no cross-process lock means no hold and no recovery (amends N2.3, N3.2, N6.2)

- **Finding.** When the lock file cannot be opened, `NSSShield.acquire` fell back to serializing within the process
  and still reported success. `Run` and `Recover` then treated the marker of a hold in **another** process as
  stale: they started `himmelblaud` in the middle of that process's transaction and reported its hold as
  `recovered` while the holder reported `restored` (two events for one hold, against N4).
- **Rule.** The cross-process lock is a precondition of every hold, like the marker and the timer (N2.3):
  - a process that cannot take it (the file cannot be opened or locked) MUST NOT stop the daemon, MUST NOT finish
    a marker as stale and MUST NOT send the report file's records;
  - `Run` runs the transaction without a hold and emits one `login.nss_shield` with the outcome `hold_failed` and
    the error; `Recover` and the per-pass check do nothing and log at `Warn`;
  - `acquire` MUST tell its callers whether it holds the cross-process lock; "process-local only" exists only
    where no lock file is configured (unit tests), never on a device.
- **The double report after a failed marker rewrite is accepted.** When the marker cannot be rewritten as reported
  (the state directory fails in the middle of a hold), the next recovery reports that hold a second time. N4's
  "exactly one event per hold" therefore holds while the state directory is writable. No further mechanism: a
  second event with the outcome `recovered` for a hold already reported is harmless and points at the failing
  directory.
- **A second accepted duplicate (added 2026-11-11, PDK-990/991 review 2).** When the updates process alone cannot
  take the cross-process lock, it writes its record to the report file without the lock while the agent may be
  sending that file. A record the updates process re-read and wrote back can then be sent twice. The direction is
  the harmless one: a duplicate event, never a lost one. Accepted for the same reason as the failed marker rewrite.
- Tests (unit): an unopenable lock file with a live marker → no start of the daemon, no `recovered` event, the
  marker kept, the transaction runs with one `hold_failed`.
- **Scope: 0.1.0-alpha.10** (PDK-991, implementer). Small, and since PDK-983 every package transaction passes this
  path, so the degraded mode must fail safe in the release that introduces the hold.

### P4 PDK-1005 (added 2026-11-11): a deferred restart of `himmelblaud` is warned about

- **Finding.** P2 made a package transaction deferred behind a shield lock held by another process log at `Warn`
  once an hour. The second user of the lock is not covered: the restart that applies a changed `himmelblau.conf`
  (`Login.restartAfterHolds`; for example a changed login allow list, which the daemon reads only at start). While
  another process keeps the lock, the restart is deferred on every pass and the only trace is an `Info` line. A
  changed login restriction then stays unapplied in the running daemon without a warning.
- **Rule.** A restart deferred because the shield lock was not obtained within its wait MUST log at `Warn`, with
  the same limit of once an hour and the same wording class as P2 (the lock is held by another process, since
  when, and that a configuration restart of `himmelblaud` is waiting). No new event and no status reason: the
  configuration file on disk is correct and re-verified, and who holds the lock for hours is root (RR-01).
- Test (unit): next to `TestNSSShieldWarnsLockHeldHourly`: a deferred restart warns once within an hour and again
  after it.
- **Scope: 0.1.0-alpha.10** (PDK-1005, implementer): one log call in the code PDK-990 changes.
- Considered for later, not decided: letting the restart go ahead when the lock is held but no fresh marker
  exists (P2's rule), so that a held lock cannot delay a login restriction at all. It touches the ordering between
  a restart and a hold that is about to begin and needs its own review.

## Amendment 2026-11-16 (architect, PDK-1122) — integrity of Paddock's own device components (ADR 0056)

The maintainer decided on 2026-11-16 (§137) that both options ship in 0.1.0-alpha.11, and confirmed it despite the
size (§142): C after PDK-1118 is merged, A in parallel to C. ADR 0056 records the decision. The architecture text
§11.5/§11.6 and the root `CLAUDE.md` item 3 are corrected in the same change. The new checks appear in §11.5 marked
"Planned (PDK-1122a/b), not yet implemented"; the merge commit of each ticket removes its marker.
Tickets: PDK-1122a (C) and PDK-1122b (A), under the umbrella PDK-1122. Both are risk high. Each needs positive and
negative tests, and among them a test that a regular update or rollback raises no event.

### C — agent-side baseline, report-only (PDK-1122a)

**C1 Where and when.** C is a new package, `agent/internal/integrity`. The agent runs `integrity.Check` once per
drift pass (`drift_interval_s`, at least 300 s in production), in the `drift.C` case of `Agent.loop`, after `a.drift(ctx)`. Two conditions apply:

- the device is enrolled, and the check runs in both enforcement modes;
- the check only reads. It never restores, stops or rewrites anything (design contract 8).

Each change is reported as `device.tamper_protected_file_changed` with the param `file` set to the absolute path. No
new event type, code or param is added.

**C2 Objects and their expected value.**

| Object (`file` param) | Expected value | Skipped while |
| --- | --- | --- |
| `/opt/paddock/agent/A/paddockd`, `/opt/paddock/agent/B/paddockd` | SHA-256 from the baseline (`""` = absent) | update not quiescent (C4) |
| `/opt/paddock/agent/current` | link target from the baseline (`A` or `B`) | update not quiescent (C4) |
| every regular file in the `md5sums` of `paddock-supervisor` (`/usr/sbin/paddock-supervisor`, `/usr/lib/systemd/system/paddock-supervisor.service`) | dpkg `md5sums`, or the rollback exception (C5) | dpkg busy, package not `installed`, supervisor upgrade marker present or result not yet processed |
| every regular file in the `md5sums` of `paddock-agent` (among them `/usr/lib/paddock/paddockd`, `/usr/lib/systemd/system/paddock-disk-setup.service`, `/usr/share/pam-configs/paddock-deny`), `paddock-revoke` (`/opt/paddock/revoke/paddock-revoke`) and `paddock-self-service` (`/usr/lib/paddock-self-service/…`, the desktop file and icon), except entries below `usr/share/doc/` and `usr/share/lintian/` | dpkg `md5sums` of the package | dpkg busy, package not `installed` (`paddock-self-service` is optional) |
| `/usr/bin/paddockd` (symlink of `paddock-agent`) | link target `/opt/paddock/agent/current/paddockd` | never |
| every `md5sums` entry of `fleet-osquery` below `opt/orbit/bin/` and the entry ending in `systemd/system/orbit.service` | dpkg `md5sums` of `fleet-osquery` | dpkg busy, package not `installed` |
| `/etc/paddock/agent.yml`, `/etc/paddock/trust.json`, `/etc/paddock/revoke-trust.json`, `/etc/paddock/disk-setup.json` | SHA-256 the agent last wrote (`""` = absent) | never |
| unit overrides and drop-ins of `paddock-supervisor.service`, `paddock-disk-setup.service`, `orbit.service`, `paddock-updates.service`, `paddock-updates.timer` (C6) | absent, except the allow list | never |

Not covered, as a documented residual:

- `/etc/paddock/enroll.json` and `/etc/paddock/autoinstall.marker`. The autoinstall writes them, not the agent, and
  they are read only at enrollment.
- `/etc/paddock/orbit.env` is not in C because the inventory reconciler already restores it and reports
  `device.tamper_protected_file_changed`.
- `/etc/paddock/login-deny`, `/etc/paddock/notice` and `/etc/paddock/sudo_lecture` are rewritten by their reconcilers
  only in enforce mode, and then only as drift (`device.config_drift_corrected`), never as a tamper event; in
  report-only mode a change stays unreported. `/etc/paddock/revoke-enabled` is re-created silently while the bundle
  enables revocation. These four are residuals named in RR-148, not C objects.
- Package symlinks are not in `md5sums` (dpkg lists regular files only). Only `current` (C4) and `/usr/bin/paddockd`
  are checked; the others, among them `/opt/orbit/bin/orbit/orbit`, are residuals named in RR-148.
- The supervisor's public key. It is compiled into the binary, and the binary is checked.

**C3 Baseline file.** The baseline is `/var/lib/paddock/state/integrity.json` (0600). Every read-modify-write holds
an exclusive `flock` on `/var/lib/paddock/state/integrity.lock`, because `paddockd enroll` writes from another
process. Taking the lock waits at most 10 s. On a timeout, the check skips this pass and logs one `Warn`; it never
blocks the agent. The baseline holds:

- the slot hashes, `current`, and the agent-written file hashes, each with its own "initialized" flag;
- the staged release `{version, sha256}`;
- the supervisor rollback exceptions;
- `reported`, the last reported observed value per path.

`reported` persists across restarts, so a restart repeats nothing.

**C4 Slots and `current`.**

- **Quiescent.** The update is quiescent when three conditions hold:
  - `update.Pending` is false;
  - `/var/lib/paddock/state/probation.json` does not exist;
  - `update-result.json` is absent or already processed (`state.ReportedUpdateAt` equals its `at`).

  Slots and `current` are checked only while the update is quiescent.
- **Initialization (trust on first use).** In the first quiescent pass without the slot flag, the agent records the
  observed hashes and target. This pass emits no event and logs one `Info` line.
- **Staging.** `Agent.handleUpdate` records `staged = {offer.Version, offer.SHA256}` before it calls `update.Stage`.
- **Update result.** `Agent.reportUpdate` moves the baseline before it spools the result event, once per result:
  - **The result names the staged version.** For each slot, an observed hash equal to the slot's baseline or to
    `staged.sha256` becomes the slot's baseline. The observed `current` becomes the baseline when it equals the old
    one, or when the slot it points to now has the baseline `staged.sha256`. Anything else stays and is reported by
    the next pass. `staged` is cleared.
  - **No `staged`, or `staged` names another version.** This happens after a rollback to an agent older than C. The
    agent re-initializes slots and `current` from what it observes, logs one `Warn`, and emits no event. Residual
    RR-148: root can forge the result.
  - This one rule covers every outcome: `updated`, `rolled_back`, `rollback_failed`, `self_test_failed`,
    `signature_invalid` and `downgrade_refused`.
- **Observed values.** `current` that is not a symlink is observed as `"!symlink"`. A missing `current` is observed as
  `"!absent"`. A slot without `paddockd` is observed as `""`, which is the normal baseline for slot B after the
  package installed only slot A.

**C5 dpkg-installed files.** The packages are `paddock-agent`, `paddock-supervisor`, `paddock-revoke`,
`paddock-self-service` and `fleet-osquery`, with the entry filters of C2.

- **md5sums file.** The expected MD5 comes from `/var/lib/dpkg/info/<pkg>:<arch>.md5sums`, where `<arch>` is the
  Debian name of `runtime.GOARCH`. When that file is missing, it comes from `/var/lib/dpkg/info/<pkg>.md5sums`. A
  dpkg upgrade rewrites `md5sums` under dpkg's lock, so a regular package upgrade moves the baseline with no alarm.
- **Race guard.** Per package, the agent applies four checks:
  1. dpkg's locks (`/var/lib/dpkg/lock-frontend`, `/var/lib/dpkg/lock`) are tested with `F_GETLK`. The agent never
     takes them, because apt would fail on them. Any lock held means the agent skips all packages this pass.
  2. `dpkg-query -W -f='${db:Status-Status}' <pkg>` must print `installed`.
  3. The agent reads `md5sums`, hashes the files, and then reads `md5sums` and the locks again.
  4. If anything changed, the agent skips the package this pass.

  A package that is not installed is skipped silently. Its absence is visible elsewhere: the agent stops, or
  `tamper.service_stopped` reports a missing unit.
- **Supervisor rollback exception.** The upgrade helper restores the binary and unit by copying them, so dpkg's
  `md5sums` then describe the failed new version. In `Agent.reportSupervisorUpgrade`, before `saveState`, the agent
  handles every processed result whose outcome is not `updated` or `deferred` (`rolled_back`,
  `rolled_back_unreachable`, `install_failed`, including the agent-written stale `install_failed`). For
  `/usr/sbin/paddock-supervisor` and the unit, it records `{path, md5 from the current md5sums entry, sha256
  observed now}`. A file then counts as expected in either of two cases:
  - its MD5 equals the `md5sums` entry;
  - an exception exists whose recorded `md5sums` entry is still the current one, and whose SHA-256 equals the
    observed SHA-256.

  An exception whose `md5sums` entry changed is deleted.
- **Hashing cost.** Hashes are cached in memory per path by `(dev, inode, size, mtime_ns, ctime_ns)`. A file is
  rehashed only when its fingerprint changes, and every file is rehashed at agent start.

**C6 Unit drop-ins.** For each of the five units, the agent applies two checks:

1. **Override and drop-in files.** The files present as `/etc/systemd/system/<unit>`,
   `/run/systemd/system/<unit>`, `/etc/systemd/system/<unit>.d/*.conf` and `/run/systemd/system/<unit>.d/*.conf`.
   Exceptions: `/etc/systemd/system/paddock-updates.service` and `/etc/systemd/system/paddock-updates.timer`, which
   the updates reconciler owns.
2. **Effective paths.** `systemctl show -p FragmentPath -p DropInPaths -- <unit>`.

The allow list holds exactly one drop-in: `/etc/systemd/system/orbit.service.d/90-paddock.conf`. The expected
`FragmentPath` per unit is:

| Unit | Expected `FragmentPath` |
| --- | --- |
| `paddock-supervisor.service` | `/usr/lib/systemd/system/paddock-supervisor.service` |
| `paddock-disk-setup.service` | `/usr/lib/systemd/system/paddock-disk-setup.service` |
| `orbit.service` | the unit path from `fleet-osquery`'s `md5sums` |
| `paddock-updates.service` | `/etc/systemd/system/paddock-updates.service` |
| `paddock-updates.timer` | `/etc/systemd/system/paddock-updates.timer` |

Paths are compared after `filepath.EvalSymlinks` of their directory, because `/lib` is a symlink to `/usr/lib`.

The value observed for a foreign file or path is `"present:" + SHA-256 of its content`. A unit that systemd does not
know (`LoadState=not-found`), or whose `show` fails, is skipped. Its absence is reported elsewhere.

**C7 Agent-written configuration files.**

- **Writers re-baseline.** After each write by Paddock, the writer calls `integrity.SyncFiles(l, paths...)`, which
  sets the baseline of the given paths to their current state:
  - `enroll.Run`, after it wrote `agent.yml`, `trust.json` and `revoke-trust.json`. This also covers
    `paddockd enroll`.
  - `Agent` revocation trust-on-first-use (`agent/internal/agent/revocation.go`), after `SaveRevokeTrust`.
  - `agent/internal/agent/encrypt.go`, for `disk-setup.json`, after every return of `Preparer.Prepare` (it writes
    the file and, on a failure, runs `encrypt.RunCleanup`), of both `encrypt.Abort` calls (an abort runs
    `RunCleanup`, and `encrypt.Cleanup` removes the file), and of `encrypt.RunCleanup` in `retryCleanup`.
- **Initialization.** It applies in the first pass without the file flag. Every one of the four paths that has no
  baseline yet is recorded as observed, with `""` for an absent file. The autoinstall's `disk-setup.json` is
  covered this way.
- **After initialization.** A file that appears, changes or disappears without a sync is a change.

**C8 One event per change.**

- An event is emitted when the observed value differs from the expected value, and `reported[path]` differs from
  the observed value. After the event, `reported[path]` is set to the observed value.
- When the observed value equals the expected value, `reported[path]` is deleted.
- When the baseline of a path moves, its `reported` entry is deleted.

As a consequence:

- A→X reports once.
- X→Y reports again.
- X→A reports nothing.
- A→X after a restore reports again.
- Events are spooled like every device event. A spool failure is logged, and `reported` is still set.

**C9 Fail safe.** Every error is logged at `Warn` at most once an hour per object, and the object is skipped for this
pass. The affected errors are: a read error, a lock timeout, a hashing error, a corrupt baseline file, and a
`systemctl` failure. A corrupt `integrity.json` is renamed to `integrity.json.corrupt` and re-initialized with
trust on first use, with one `Warn` and no event. No error stops the drift tick or the agent.

**C10 Runbook.** `docs/operations/agent-releases.md`, section "An update that waits for the active agent" (PDK-1118),
names `device.tamper_protected_file_changed` for `/opt/paddock/agent/current` (step 1) and for
`/opt/paddock/agent/<slot>/paddockd` (step 2). That event is expected after the manual repair, and the operator
resolves the finding.

### A — server-generated hash policy (PDK-1122b)

**A1 Policy.** Key `paddock_agent_binary_known` (`inventory.PolicyAgentBinaryKnown`), built by
`inventory.AgentBinaryPolicy(hashes []string) ports.PolicyDefinition` from the hashes in the hash set (A2). The query
for a non-empty set:

```sql
SELECT 1 WHERE NOT EXISTS (
  SELECT 1 FROM processes p LEFT JOIN hash h ON h.path = p.path
  WHERE p.name = 'paddockd' AND p.path LIKE '/opt/paddock/agent/%' AND p.on_disk = 1
    AND (h.sha256 IS NULL OR h.sha256 NOT IN ('<hash 1>', '<hash 2>')));
```

- The hashes are sorted and deduplicated, and each one must match `^[0-9a-f]{64}$`. A value that does not match is
  dropped and logged at `Error`, which is defense in depth before the value is interpolated into SQL. For an empty
  set, the query is `SELECT 1;`.
- No `paddockd` running passes. The not-running case belongs to `paddock_agent_running`, so the two policies never
  report the same stop twice.
- A process whose binary was replaced by a rename (`on_disk = 0`) is not judged. C reports the slot change; residual
  RR-149.
- The description says that the policy returns pass or fail, never a hash.

**A2 Hash set and sync.**

- **Hash set.** The hash set is every `agent_artifact.sha256` of every release with `status = 'published'`, for all
  architectures (query `ListPublishedAgentHashes`, platform pool).
- **Every round.** `worker.Inventory.Round` reads the hash set first, appends the policy to the static policies and
  calls `ApplyPolicies`. Applying is idempotent: Fleet's policy spec updates by name. When the fingerprint of the
  hash set (SHA-256 of the sorted, newline-joined hashes) differs from the last one this process applied, the worker
  sets `binaryAppliedAt = now` after the apply succeeds. A new leader or a restarted worker starts with no
  fingerprint and so sets it on its first apply. That only delays reports, so it is conservative.
- **Publish.** There is no separate trigger: a publish reaches Fleet in the next round, at most 5 minutes later. A
  device that runs a new release before then fails only an evaluation older than `binaryAppliedAt`, which A3 never
  reports.
- **Yank.** Paddock has no yank. ADR 0056 decision 4 binds a future yank to keep the hashes.

**A3 Report.**

- **Who is reported.** After `reportAgents`, the worker calls
  `InventorySync.ReportAgentBinaryUnknown(ctx, evaluatedAfter, knownHashes)` per organization, with
  `evaluatedAfter = binaryAppliedAt + 2 min`. It reports every active device that meets three conditions:
  - its `paddock_agent_binary_known` result fails;
  - `alerted_at` is null;
  - `device_inventory_ref.policy_updated_at >= evaluatedAfter`. This is Fleet's `policy_updated_at` of the host,
    stored in a new column.
- **Once per failure.** The code is `device.tamper_agent_binary_changed`. Recording the event, setting `alerted_at`
  (`MarkAgentNotRunningReported` with the new key) and opening the tamper finding happen in one `ActionRunner.RunTx`.
  A passing result clears `alerted_at`, which the existing `UpsertPolicyResult` already does.
- **No check-in silence rule.** It fires as soon as the evaluation gate holds.
- **Publish race.** Before reporting, the round reads the hash set again. If its fingerprint changed during the
  round, binary reports are skipped for this round and an `Info` line is logged.
- **Skipped entirely.** The round reports nothing for the binary policy in two cases:
  - the hash set is empty;
  - `ApplyPolicies` failed. The round fails as today and is retried in the next round.

**A4 Registry entry** (`server/internal/domain/audit/codes.go`, next to `CodeDeviceTamperAgentNotRunning`):

```go
CodeDeviceTamperAgentBinaryChanged Code = "device.tamper_agent_binary_changed"

CodeDeviceTamperAgentBinaryChanged: {
	Code: CodeDeviceTamperAgentBinaryChanged, Emitted: true,
	Description: "fleetd reports that a Paddock agent running from /opt/paddock/agent/ has a binary that matches no published agent release: it was replaced or modified on the device (actor: system; the inventory system's policy paddock_agent_binary_known). evaluated_at is when the host last evaluated its policies; agent_version is the version the agent last reported, which a replaced agent may forge; known_hashes is the number of published hashes the policy accepts. A genuine older published release passes (RR-149).",
	Params:   []string{"policy", "evaluated_at", "agent_version", "known_hashes"},
	Outcomes: []Outcome{OutcomeSuccess},
	Note:     "Recorded once per failure; the policy passing again ends it. No hash of the device's binary is recorded: the policy returns pass or fail only.",
},
```

Alongside the entry:

- **MSGID alias.** `msgid.go` gets the alias `CodeDeviceTamperAgentBinaryChanged: "device.tamper_agent_bin_changed"`.
- **Tamper finding.** `tamperFindingCodes` gets the entry `audit.CodeDeviceTamperAgentBinaryChanged: ""`.
- **Portal messages.** Message keys `audit.device.tamper_agent_binary_changed` in `en.json` and `de.json`:
  - EN: "fleetd reports an agent binary on {target} that matches no published release"
  - DE: "fleetd meldet auf {target} ein Agent-Binary, das zu keinem veröffentlichten Release passt"
- **Generated files.** `make gen` regenerates `auditCodes.gen.ts` and `docs/compliance/audit-codes.md`.
- **Secrets and personal data.** None in the params.

**A5 Downgrade: decided A2 (any published hash).** Fleet policies are global and return pass or fail, and the expected
version of a device is ambiguous during waves, holds, the manual policy and rollbacks. Comparing per device would
raise false alarms on regular flows. The residual RR-149 is that a root user who installs a genuine older published
`paddockd` is not reported by A. Three things reduce it:

- C reports the slot or `current` change.
- The fleet view counts the device as outdated (`components_outdated`).
- The supervisor refuses downgrades through Paddock's own channel.

**A6 Test harness.** The system-test VMs install locally built packages. Before installing, `test/system` MUST publish
the exact `bin/agent/amd64/paddockd` that is inside the installed `paddock-agent` package. It publishes this binary as
a release without a rollout, next to `PublishFleetd`. Otherwise A reports every VM. `devicesim.FleetHost` gains a
switch that fails the queries containing `FROM processes p LEFT JOIN hash`, for the acceptance gate.

### Residual risks (added to `docs/compliance/residual-risks.md`)

- **RR-148** (C): device-side baselines are only as trustworthy as root on the device. Root can do any of the
  following, and none is detected:
  - rewrite `integrity.json`, dpkg's `md5sums` or an update result, or corrupt `integrity.json` to force a
    re-initialization (C4, C9);
  - change a file between a Paddock write and its sync.

  Not checked by C at all: `enroll.json`, `autoinstall.marker`; `login-deny`, `notice` and `sudo_lecture` (drift
  only in enforce mode, unreported in report-only mode); `revoke-enabled` (re-created silently); package symlinks
  other than `current` and `/usr/bin/paddockd`.

  Paddock's own regular paths never raise an event.
- **RR-149** (A): a genuine older published `paddockd` passes `paddock_agent_binary_known`. A process whose binary
  was replaced by a rename is not judged until it restarts.

If either number is taken when the ticket merges, the next free number is used, and this amendment and ADR 0056 are
updated in the same commit.

## Amendment 2026-11-16 (architect, PDK-1122b review round 1) — unanswered policies, the judged process set, harness and gate timing

Both reviews of PDK-1122b (commit `c0f4ddf6`) are not approved. This amendment decides their findings. It changes
the query of A1 and the residual RR-149, which ADR 0056 records in its amendment of the same date. A2, A3 (except the
storage rule A7), A4's params and messages, A5 and A6 stay in force. The ticket stays PDK-1122b, risk high.

### Decisions

**A7 Unanswered policy results keep a reported failure (internal B1, external 2).** Fleet v4.94.1
(`server/datastore/mysql/policies.go`, `ApplyPolicySpecs`) deletes a policy's `policy_membership` when its query
changes, so every publish turns each host's `paddock_agent_binary_known` answer into `""` until the host evaluates
again. Fleet also stores a NULL result (`""`) when the query did not execute on the host
(`RecordPolicyQueryExecutions`). Today the adapter drops `""`, and `DeleteMissingPolicyResults` deletes the row
together with `alerted_at`, so the next failure is reported a second time.

- The adapter MUST report every policy that Fleet lists for the host with a response other than `pass` or `fail` in
  the new field `ports.HostInventory.UnansweredPolicies` (keys, in Fleet's order).
- `StoreHost` MUST pass these keys to `DeleteMissingPolicyResults`. A row whose key is unanswered **and** whose
  `alerted_at` is set is kept unchanged. A row whose key is unanswered and whose `alerted_at` is null is deleted, as
  today. A row whose key Fleet does not list is deleted, as today. Unanswered keys are never upserted.
- Why not keep every unanswered row (the reviewer's variant): a kept, not yet reported failure of the old definition
  would meet `ListAgentBinaryUnknown` as soon as the host's `policy_updated_at` passes the gate while its new answer
  is a NULL (query error). Keeping only reported rows can never create an event, because every report query requires
  `alerted_at IS NULL`.
- `paddock_agent_running` is not affected by publishes: its query is static, and Fleet clears memberships only when
  the query text changes. It is affected the same way when a Paddock release changes its query text and when the query
  fails on the host; both used to repeat `device.tamper_agent_not_running` for the same stop. A7 is generic in
  `StoreHost` and covers it.

**A8 The judged process set replaces A1's query (external 1).** The query of A1 judged only a `paddockd` running from
`/opt/paddock/agent/` and hashed the path osquery sees. Redirecting `current` to another directory, a
`BindReadOnlyPaths=` drop-in, or a process name changed with `prctl` defeated it, and C runs inside the replaced agent.
The policy MUST be, for a non-empty hash set, exactly:

```sql
SELECT 1 WHERE NOT EXISTS (
  SELECT 1 FROM processes p
  WHERE p.path != ''
    AND (p.name = 'paddockd' OR p.path LIKE '%/paddockd' OR p.path LIKE '%/paddockd (deleted)'
      OR p.path LIKE '/opt/paddock/agent/%'
      OR (p.parent IN (SELECT pid FROM processes WHERE path = '/usr/sbin/paddock-supervisor')
        AND p.path != '/usr/sbin/paddock-supervisor'))
    AND COALESCE((SELECT sha256 FROM hash WHERE path = '/proc/' || p.pid || '/exe'),
      (SELECT sha256 FROM hash WHERE path = p.path), '') NOT IN ('<hash 1>', '<hash 2>'));
```

`<hash n>` are the sorted, deduplicated, validated hashes of A1; the empty set stays `SELECT 1;`. Each clause has
one purpose:

| Clause | Purpose |
| --- | --- |
| `p.path != ''` | A zombie or exiting process has no readable executable; judging it would raise a false alarm. |
| `p.name = 'paddockd'`, `p.path LIKE '%/paddockd'` (and its `(deleted)` form) | A `paddockd` anywhere: a redirected `current`, a copy elsewhere, the uninstall helper `/root/paddock-uninstall/paddockd` (genuine, passes). |
| `p.path LIKE '/opt/paddock/agent/%'` | Anything that runs from the slots, whatever its name. |
| child of `/usr/sbin/paddock-supervisor`, except a child whose executable is the supervisor itself | Whatever the supervisor started, whatever its name or path (`prctl`, a script as `current/paddockd`). The exception covers the instant between `fork` and `exec`. |
| hash of `/proc/<pid>/exe` | The executable the process actually runs, also in another mount namespace (bind mount) and after a rename over the file (`on_disk = 0` is now judged, and passes while the old genuine image runs). |
| fallback hash of `p.path` | A short-lived genuine process (`paddockd version`, `self-test`) that exits between the process scan and the hash: its slot file is still there. |

False-alarm safety (each MUST hold and is covered by section "Tests"):

- Regular update and rollback: the supervisor runs only slot binaries (`run`, `self-test`, `version`), whose
  releases are published; the evaluation gate of A3 covers the lag. Unchanged.
- No `paddockd` running: no judged process, the policy passes; the stop belongs to `paddock_agent_running`. Unchanged.
- The supervisor's `fork` before `exec`: excluded by the supervisor-path exception.
- A process that exits during the evaluation: excluded by `p.path != ''` or passes by the path fallback.
- Package installation and upgrade: `paddock-agent`'s postinst writes slot A only when `current` is absent; dpkg never
  replaces a running slot binary.
- Uninstall: the helper runs a copy of the genuine binary; it passes.
- A device that runs a `paddockd` built locally (a developer's machine, an unpublished build) fails. This is the
  intended meaning and is documented (A10, Low 5).

The description of the policy in `inventory.AgentBinaryPolicy` MUST read: "A running Paddock agent process runs a
published agent release (plan M5a amendments 2026-11-16, ADR 0056). The policy returns pass or fail only, never a
hash."

The registry description of `device.tamper_agent_binary_changed` (A4) MUST read:

```go
Description: "fleetd reports a running Paddock agent process whose executable matches no published agent release: the agent binary, the place it runs from, or the process the supervisor started was replaced or modified on the device (actor: system; the inventory system's policy paddock_agent_binary_known). evaluated_at is when the host last evaluated its policies; agent_version is the version the agent last reported, which a replaced agent may forge; known_hashes is the number of published hashes the policy accepts. A genuine older published release passes (RR-149).",
```

Code, params, outcomes, note, MSGID alias, finding entry and portal messages stay as in A4.

**A9 The harness publishes once per stack (internal M1).** `test/system/stack.go` gains the field
`publishMu sync.Mutex` on `Stack`. `PublishInstalledAgent` MUST hold it from before the `count(*)` query until after
`agentrelease` returned (`defer` unlock), after the lab guard. The second VM then sees the published hash and
publishes nothing.

**A10 Lows of the external review.**

| Low | Decision | Where |
| --- | --- | --- |
| 3 osquery hash cache, `touch -r` | Resolved by A8: the primary hash is keyed per process (`/proc/<pid>/exe`), and a running executable cannot be overwritten in place (`ETXTBSY`), so a cached entry cannot outlive a change. The remaining case (pid reuse with the same inode, size and mtime) is listed under "Risks". | this amendment; F5 step "rename over the running binary passes" proves the `/proc` hash |
| 4 old-definition results written late | Documented, not changed. A false alarm needs a device that already runs the new release before the apply, and a result posted more than 2 minutes after it was read. | doc comment of `binaryEvaluationLag` in `server/internal/worker/inventory.go`, text below |
| 5 devices installed from an unpublished build | Documented. | `docs/operations/fleet.md` step 5; `docs/operations/install.md`, appendix "installing from source" |
| 6 unbounded hash set | One `Info` log line when the fingerprint changes (`hashes=<n>`), plus one `Warn` line in the same round when `n > 1000`. No metric, no cap. | `server/internal/worker/inventory.go`; `docs/operations/fleet.md` step 5 |

Text for the `binaryEvaluationLag` doc comment (Low 4), appended to the existing comment: "Fleet's
policy_updated_at is when Fleet stored the result, not when the host evaluated: a host that read the previous
definition before the apply and posts its result more than binaryEvaluationLag later passes the gate with a result of
the previous definition. That needs a device that already runs a release the previous definition did not list, so it
is accepted (plan M5a amendment 2026-11-16, review round 1, A10)."

Text for `docs/operations/fleet.md` step 5 (append to the paragraph of `paddock_agent_binary_known`): "A device
installed from packages whose `paddockd` is not a published release (a local build or a draft release) fails this
policy as soon as any release is published; publish that build or install a published release. The worker logs the
number of accepted hashes whenever it changes and warns above 1,000, because Fleet must accept the whole query." The
same step MUST replace "a `paddockd` running from `/opt/paddock/agent/` has a binary that matches no published release"
by "a running agent process (named `paddockd`, running a file named `paddockd` or a file below `/opt/paddock/agent/`, or
started by `paddock-supervisor`) runs an executable that matches no published release", and add: "A failure that
Fleet resets after a new definition stays reported until the host answers again, so a publish does not repeat the
event."

Text for `docs/operations/install.md`, appendix "installing from source", appended to its first paragraph: "Once any
agent release is published, a device that runs such a locally built `paddockd` raises
`device.tamper_agent_binary_changed`."

**A11 Acceptance timing without wall-clock windows (internal review).** Phase 2 of
`TestInventoryAgentBinaryPolicy` MUST wait only on observed conditions. It MUST NOT sleep or answer for a fixed
duration, and it MUST NOT raise any deadline of the gate. The flake rule (`docs/operations/testing-strategy.md`) applies.

1. `devicesim.FleetHost` records, per hash, the first time `Answer` received a binary policy query that lists it:
   `func (h *FleetHost) BinaryPolicyListedAt(hash string) (time.Time, bool)`.
2. After the second publish, the gate answers until `hosts["updated"].BinaryPolicyListedAt(newHash)` returns true.
   That time is `bound`; Fleet held the new definition no later than then.
3. It answers until every gate device's `device_inventory_ref.policy_updated_at >= bound + 2 min` and the `updated`
   device's `paddock_agent_binary_known` row is passing.
4. It records each gate device's `device_inventory_ref.synced_at`, then answers until each device's `synced_at` has
   taken two further, increasing values (two worker rounds after the condition of step 3).
5. Then it asserts: `changed` 1 event, `genuine` 0, `updated` 0; the `changed` device's binary policy row has
   `alerted_at` set.

Steps 2 to 4 share one failure bound of 10 minutes from the second publish, the bound phase 1 already uses. Exceeding
it fails the gate with the unmet condition in the message. `devicesim.agentBinaryPolicyMarker` becomes
`"SELECT sha256 FROM hash WHERE path = '/proc/'"`.

### Files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/internal/ports/inventory.go` | change | `HostInventory.UnansweredPolicies []string` (A7) |
| `server/internal/adapters/fleet/hosts.go` | change | fill `UnansweredPolicies` (A7) |
| `server/internal/adapters/fleet/testdata/get_host.json`, `hosts_test.go` | change | a listed policy with response `""` (A7) |
| `server/internal/adapters/postgres/queries/inventory.sql` + generated `pgstore` | change | `DeleteMissingPolicyResults` keeps reported unanswered rows (A7) |
| `server/internal/app/inventory.go`, `inventory_integration_test.go` | change | `StoreHost` passes the unanswered keys; tests (A7) |
| `server/internal/worker/inventory.go`, `inventory_test.go` | change | Low 4 comment, Low 6 logs; tests (A7, A10) |
| `server/internal/inventory/inventory.go`, `inventory_test.go` | change | A8 query and description |
| `server/internal/domain/audit/codes.go` + `make gen` outputs | change | A8 registry description |
| `test/acceptance/devicesim/fleet.go`, `fleet_test.go` | change | new marker, `BinaryPolicyListedAt` (A11) |
| `test/acceptance/inventory_test.go` | change | phase 2 per A11 |
| `test/system/stack.go` | change | `publishMu` (A9) |
| `test/system/inventory_test.go` | change | F5 additions (section "Tests") |
| `docs/compliance/residual-risks.md` | change | RR-149 text below |
| `docs/compliance/privacy.md` | change | policy row text below |
| `docs/operations/fleet.md`, `docs/operations/install.md` | change | A8, A10 texts |
| `docs/architecture.md` §11.5 | change | row and mutual-watch sentence below |
| `changelog.d/pdk-1122b.security.md` | change | sentence below |

Not touched: `agent/` (no agent change; in particular `agent/internal/revoke/`), `server/internal/inventory/policies/`
(`paddock_agent_running` stays as it is), the migrations (A7 needs no schema change), ADR 0056 decisions other than its
amendment, and A3's gate and publish-race logic.

```sql
-- name: DeleteMissingPolicyResults :exec
DELETE FROM inventory_policy_result
WHERE device_id = @device_id AND NOT (policy_key = ANY(@keys::text[]))
  AND NOT (policy_key = ANY(@unanswered::text[]) AND alerted_at IS NOT NULL);
```

```go
// ports.HostInventory
// UnansweredPolicies are the keys of the policies the inventory system lists for the host without a pass or fail
// answer: not yet evaluated since the policy changed, or the query did not run (plan M5a amendment 2026-11-16,
// review round 1, A7).
UnansweredPolicies []string
```

Texts:

- RR-149 (replaces the row): "**The binary policy trusts every published release and judges only processes it
  recognizes as the agent.** The policy `paddock_agent_binary_known` accepts the SHA-256 of every published agent
  artifact, because Fleet policies are global and the expected version of a device is ambiguous during waves, holds,
  the manual update policy and rollbacks (ADR 0056, A2); a local root user who installs a genuine older published
  `paddockd` is not reported by it. It judges every process that is named `paddockd`, runs a file named `paddockd` or a
  file below `/opt/paddock/agent/`, or was started by `paddock-supervisor`, and hashes the executable the process
  actually runs. Not reported by it: a foreign program that is none of these and checks in for the device while the
  genuine agent is stopped (the mutual watch `paddock_agent_running` stays silent while the device checks in, plan M5a
  decision 8); a process that swaps its executable link (`PR_SET_MM_EXE_FILE`); code injected into the running genuine
  agent; a security policy that denies osquery access to `/proc`; a replaced osquery." Mitigation column: "The
  agent-side baseline reports a changed slot, `current` or unit drop-in (ADR 0056, C) while the agent itself is
  genuine; the fleet view counts the device as outdated (`components_outdated`); the supervisor refuses downgrades
  through Paddock's own channel." ISMS column: "Accept that these cases need a local root user with custom code;
  restrict root on devices and review tamper findings."
- `docs/compliance/privacy.md`, row `paddock_agent_binary_known`, second column: "no process that is named
  `paddockd`, runs a file named `paddockd` or below `/opt/paddock/agent/`, or was started by `paddock-supervisor` runs
  an executable whose SHA-256 is outside the published agent releases (ADR 0056). The query hashes those executables on
  the device to answer one yes/no question; no hash, path or process data is collected."
- `docs/architecture.md` §11.5, the row of `paddock_agent_binary_known`, first column: "The executable of every running
  agent process (named `paddockd`, running a file named `paddockd` or below `/opt/paddock/agent/`, or started by
  `paddock-supervisor`) is a published agent artifact (osquery policy `paddock_agent_binary_known`, regenerated by the
  worker from every published release; a genuine older release passes, RR-149)". In the mutual-watch sentence,
  "checks the running binary's SHA-256" becomes "checks the SHA-256 of the executable every running agent process
  runs".
- Changelog fragment, after the first sentence: "This includes an agent started from another location or under
  another name."

### Steps

1. **Probe (before any code).** On one system-test VM with the stack's fleetd, run as root with `osqueryi --json`:
   the A8 query with the genuine hash (expect 1 row); `SELECT sha256 FROM hash WHERE path = '/proc/<pid of paddockd>/exe'`
   (expect the slot file's SHA-256). Record both outputs in the result document. Check: outputs as expected; else stop.
2. **A7.** Port field, adapter, SQL, `make gen`, `StoreHost`. Check: `go test` of `adapters/fleet`, `app` (inventory
   tests), `worker` (`TestInventory*`).
3. **A8.** Query, description, registry text, `make gen`, devicesim marker. Check: `go test` of `inventory`,
   `domain/audit`, `test/acceptance/devicesim`; `make gen` leaves no diff.
4. **A9, A10.** Mutex, comment, logs, docs texts. Check: `go vet` in `test/system`; worker tests.
5. **A11.** devicesim recording, phase 2. Check: `make acceptance` runs `TestInventoryAgentBinaryPolicy` green.
6. **F5.** Additions below. Check: `make system-test VM=all` green, run serially to `make acceptance`.
7. Quality gate of the repository (`make typecheck`, the full Go test run with `nice -n 19`, `make lint test`).

### Tests

Each test named "regression" MUST fail without its fix (prove by mutation in the result document).

- **Adapter** `TestHostInventoryUnansweredPolicies` (regression A7): fixture lists `paddock_agent_binary_known` with
  response `""` and `paddock_agent_running` with `pass` → `UnansweredPolicies == ["paddock_agent_binary_known"]`,
  `Policies` holds only `paddock_agent_running`.
- **App** `TestStoreHostKeepsReportedUnansweredPolicy` (regression A7, Postgres): a failing row with `alerted_at` set
  and its key unanswered → row unchanged (`passing = false`, same `alerted_at`); a failing row with `alerted_at` null
  and its key unanswered → deleted; a row with `alerted_at` set whose key is neither answered nor unanswered →
  deleted; an unanswered key without a row → no row created.
- **Worker** `TestInventoryRoundAgentBinaryUnansweredAfterPublish` (regression A7): a device is reported (1 event);
  a new hash is published; the next round the source reports the binary policy unanswered; after the new
  `binaryAppliedAt + 3 min` it fails again → still exactly 1 event.
- **Worker** `TestInventoryRoundAgentBinaryUnansweredNotReported` (false-alarm guard A7): a failure older than the
  gate (0 events); a new hash; the binary policy unanswered with `policy_updated_at` past the new gate → 0 events; then
  passing → 0 events. It MUST fail when unanswered rows are kept regardless of `alerted_at`.
- **Worker or app** `TestReportAgentNotRunningKeepsMarkWhileUnanswered` (regression A7): `paddock_agent_running`
  reported once; one sync with it unanswered; failing again with no check-in → still 1
  `device.tamper_agent_not_running`.
- **Worker** `TestInventoryRoundAgentBinaryManyHashes` (A10 Low 6): 1,001 hashes → exactly one `WARN` line with
  `hashes=1001` in the round that applies them and none in the next round; 1,000 hashes → no `WARN`.
- **Inventory** `TestAgentBinaryPolicy`: pins the exact A8 query for `[b, a, a]`; the existing empty-set and
  invalid-hash tests stay.
- **devicesim** `TestFleetHostAgentBinaryPolicy`: the new marker; `BinaryPolicyListedAt` returns the first time only.
- **Acceptance** `TestInventoryAgentBinaryPolicy`: phase 2 per A11. Real Fleet resets the membership at the second
  publish, so this gate also proves A7 end to end.
- **System F5** (`test/system/inventory_test.go`, `gateF5`): keep every existing step; the osquery checks use the
  query Fleet holds (`agentBinaryQuery`).
  1. In the existing rename step, after the rename over the slot binary and **before** the supervisor restart, the
     query MUST return 1 row: the running image is genuine. This proves the `/proc/<pid>/exe` hash of a deleted
     executable. The existing step then restarts the supervisor as today.
  2. After the existing final check ("the agent binary policy passes again") and the existing event count of exactly
     1, F5 stops orbit (`systemctl stop orbit`) so that no further evaluation reaches Fleet, and runs `osqueryi`
     standalone as today. The modified binary is `/root/paddockd.genuine` with one byte appended, as today. Each case
     is followed by its restore and the check that the query returns 1 row again:
     - redirected `current`: the modified binary as `/var/lib/paddock-f5/paddockd`, `current` pointed at
       `/var/lib/paddock-f5`, supervisor restarted → 0 rows; restore `current` to the slot it pointed at before;
     - bind mount: a drop-in `/run/systemd/system/paddock-supervisor.service.d/99-f5.conf` with
       `BindReadOnlyPaths=/var/lib/paddock-f5/paddockd:<active slot>/paddockd`, `daemon-reload`, supervisor
       restarted → 0 rows; restore by deleting the drop-in, `daemon-reload`, restart;
     - renamed child: `current` pointed at a directory whose `paddockd` is the script `#!/bin/sh` + `exec sleep
       infinity`, supervisor restarted → 0 rows; restore `current`.
  3. F5 starts orbit again, waits until the stored binary policy result is passing with a `policy_updated_at` later
     than the orbit start, and asserts the event count is still exactly 1.

  Every wait is on a condition: the supervisor's child being present (`/proc/<MainPID>/task/<MainPID>/children`
  non-empty) or a stored result; never a fixed duration. Process checks use `pgrep -x`, never `pgrep -f`. The cleanup
  (`t.Cleanup`) MUST restore `current`, delete the drop-in and start orbit when a step fails.

### Acceptance criteria

- AC-A7 (org admin, audit log and findings of the device): Given a device reported once for an unknown binary, when a
  release is published and the device keeps failing, then the org admin sees exactly one
  `device.tamper_agent_binary_changed` for it (acceptance gate, F5).
- AC-A8 (org admin): Given a device whose supervisor runs a modified agent from outside `/opt/paddock/agent/`, through
  a bind mount, or under another name, then the policy fails on the device (F5 osquery checks), and a failure of the
  stored policy is reported as in A3.
- AC-A8-safe (org admin): Given a regular update, a rollback, a stopped agent or the genuine agent, then no event
  (existing worker tests, acceptance `genuine` and `updated`, F5's first 0-event check).
- AC-A9 (maintainer, system-test log): `make system-test VM=all` publishes the installed binary at most once per run.
- AC-A11 (maintainer, CI): the acceptance gate contains no fixed waiting window.

### Freedoms

Names of internal helpers; the order of clauses inside the A8 `OR` list as long as the pinned test string and this
amendment agree (update both); log message wording other than the `hashes` attribute.

### Stop conditions

- Step 1 shows no hash for `/proc/<pid>/exe`, or the A8 query does not return 1 row for the genuine agent.
- Fleet rejects the A8 query (the `||` operator or the subqueries).
- F5 step 1 returns 0 rows (osquery cannot hash a deleted executable through `/proc`).
- A regular Paddock flow (update, rollback, self-test, uninstall, enrollment) runs a judged process whose executable
  is not a published release.
- A7 would need a schema change.

### Risks

- Pid reuse within one evaluation could hash an unrelated executable (false alarm); pid space and timing make it
  negligible. Accepted.
- osquery's `hash` table reads at most `--read_max` (50 MiB by default); a `paddockd` above that size would fail
  everywhere. Today it is about 9 MB. Accepted; the stop condition of step 1 would show it.
- RR-149's first gap (a foreign program checking in while the genuine agent is stopped) is closed only by a change to
  the mutual watch (decision 8), which is proposed as PDK-1122c and needs the maintainer's approval.

### Addendum 2026-11-16 (architect, PDK-1122b review round 2)

External Review 2 of `8ac7ec76` found no code blocker. It found that RR-149 and the ADR 0056 amendment overstate what
A detects. Since review round 1, PDK-1122c (amendment 2026-11-16 b, the agent absent while the device checks in) and
PDK-1122d (amendment 2026-11-16 c, fleetd silent while the device checks in) were accepted for alpha.11 (§147, §148).
This addendum corrects the wording and gives the RR-149 text of all three tickets. It also hardens the parent clause
(A12), and decides Lows 2 to 5 (A13).

**What A claims.** At each evaluation, A judges only the processes it recognizes as the agent while they run. It
detects a replaced agent binary only while such a process runs it. A replaced agent that runs as an unrecognized
process, or that runs only between evaluations, is outside A. Two sentences of the review-round-1 amendment are
withdrawn:
- the ADR 0056 amendment's "the cheapest evasion, one symlink" claim;
- ADR 0056's original consequence "A replaced agent is caught independently of itself".

ADR 0056's amendment "PDK-1122b review round 2" states the qualified versions.

**Which check covers which evasion.** A is `paddock_agent_binary_known`. C is the agent-side baseline, which reports
only while the agent is genuine and can deliver. c is PDK-1122c and d is PDK-1122d.

| Shape (External Review 2 and round 1) | Covered by |
| --- | --- |
| Modified binary in a slot, redirected `current`, bind mount, changed process name, script or interpreter child of the supervisor, memfd child | A |
| `current` → a launcher that detaches the impostor (`setsid`) and exits | c: osquery sees no genuine agent while the device checks in. A misses it because no recognized process runs long enough. |
| The supervisor's own file renamed over itself, then a child that is neither `paddockd` nor below the slots | A, after A12 |
| The supervisor started from another file through a unit drop-in, with an impostor as its child | c: no genuine agent is seen. C reports the drop-in only while the agent is genuine. |
| fleetd stopped or masked | d, while at least half of the live devices reach Fleet; otherwise residual, with the suppression alert |
| osquery confined by an orbit drop-in (`PrivatePIDs=yes` and similar) | c: osquery sees no genuine agent. With a decoy in osquery's view: residual. |
| The genuine agent kept running but cut off (`PrivateNetwork=yes`, another mount namespace), an impostor checks in | residual (decoy, accepted in §147) |
| A genuine older published release | residual (A2) |
| `PR_SET_MM_EXE_FILE`, code injection into the genuine agent, an LSM policy against osquery, a replaced osquery, a program that answers Fleet with the device's node key | residual (RR-01) |
| A re-tamper after a repair whose pass Fleet reset before the worker stored it | residual until the policy passes again (A13, Low 2) |

**A12 Parent clause also matches a replaced supervisor file.** The parent clause of A8 becomes exactly the following.
Every other line of the A8 query stays as it is.

```sql
      OR (p.parent IN (SELECT pid FROM processes
            WHERE path IN ('/usr/sbin/paddock-supervisor', '/usr/sbin/paddock-supervisor (deleted)'))
        AND p.path NOT IN ('/usr/sbin/paddock-supervisor', '/usr/sbin/paddock-supervisor (deleted)')))
```

- Reason: a `cp` plus `mv` of the supervisor over itself leaves the running supervisor's executable `… (deleted)`.
  Its children were then no longer judged, although dpkg's `md5sums` saw identical content.
- False alarms: during a regular supervisor upgrade, the old supervisor runs from a deleted file until it is
  restarted. Its children are still only `paddockd run`, `self-test` and `version` from the slots, which are
  genuine and pass. The upgrade helper is not a supervisor child. The fork window of a deleted supervisor is excluded
  by the second line.
- Tests:
  - `TestAgentBinaryPolicy` pins the new string.
  - F5 gains two osquery cases, both run with orbit stopped like the round-1 cases, each followed by its restore and
    the 1-row check:
    1. `cp /usr/sbin/paddock-supervisor /usr/sbin/paddock-supervisor.new && mv /usr/sbin/paddock-supervisor.new
       /usr/sbin/paddock-supervisor`. Then kill the supervisor's child and wait for a new child, which is present in
       `/proc/<MainPID>/task/<MainPID>/children`. The query returns 1 row: this is the regular-upgrade window.
    2. In the same state, point `current` at the script directory of round 1 (`exec sleep infinity`). Kill the child
       and wait for a child whose executable is `/usr/bin/sleep`. The query returns 0 rows.

    Restore: `current` back, then `systemctl restart paddock-supervisor`. The `t.Cleanup` of F5 MUST also restart the
    supervisor.
- Stop condition: osquery reports neither form of the supervisor path for a supervisor whose file was renamed over.

**A13 Lows of External Review 2.**

- **Low 2 (A7 can miss a re-tamper after a repair): documented, not changed.** Sequence:
  1. A reported device is repaired.
  2. A publish resets the stored pass before the worker reads it.
  3. A second tamper is then reported only after the policy passes again.

  Changing this would need per-host evidence of a pass that Paddock does not have. Texts:
  - **`docs/operations/fleet.md` step 5**, appended to the sentence on resets: "If the device was repaired and a
    publish reset its passing result before the worker read it, a new tamper is reported only after the policy has
    passed again."
  - **RR-149:** the texts below include this case.
- **Low 3 (a policy that stays unanswered): a metric and one log line in this ticket.**
  - **What is tracked.** For each Paddock policy key, the worker remembers `definedAt[key]`, the time this process
    first applied the key's current query text. A changed text resets it.
  - **What is counted, in each full round only (`since.IsZero()`).** The mapped hosts that list the key in
    `UnansweredPolicies` with `PolicyUpdatedAt >= definedAt[key] + binaryEvaluationLag`. Such a host evaluated the
    current definition and returned no answer, which means the query failed there.
  - **Outputs:**
    - the gauge `paddock_inventory_policy_unanswered_hosts{policy}`, a `prometheus.GaugeVec` next to
      `metricUnmappedHosts`. Its label values are the fixed Paddock policy keys only;
    - one `Warn` per key with a count above 0: `"a Paddock policy did not run on hosts that evaluated it"` with
      `policy` and `hosts`.

    Changed-host rounds set nothing.
  - **Tests (worker):** `TestInventoryRoundPolicyUnansweredMetric`:
    - two hosts list `disk_encrypted` as unanswered in a full round, one evaluated after `definedAt + 2 min` and one
      before → gauge 1, exactly one `WARN`;
    - a changed-host round → gauge unchanged, no `WARN`;
    - the binary policy is unanswered right after a new hash was applied → not counted.

    Plus a metrics registration check in `server/internal/worker/metrics_test.go`, in the existing pattern.
  - **Docs:**
    - `docs/operations/monitoring.md` lists the gauge with the meaning "a value above 0 for more than one full round
      means a Paddock policy query fails on those hosts; detection by that policy stops there";
    - `docs/operations/fleet.md` step 5 names it in one sentence.
- **Low 4 (wrong false-alarm claim).** The A8 bullet "A process that exits during the evaluation" now reads: "A
  process that exits during the evaluation: excluded by `p.path != ''`, or passes by the path fallback while its
  executable is still on disk. A genuine process whose file was already replaced and that exits during the
  evaluation would fail. No regular flow produces it: slots are rewritten only while nothing runs from them, and the
  uninstall helper deletes its copy only after it stopped the services." The table row "fallback hash of `p.path`"
  gains "(not for a deleted executable)". No code change.
- **Low 5 (acceptance comment).** The comment before phase 2 in `test/acceptance/inventory_test.go` becomes exactly:
  "// Phase 2 waits on observed conditions only (plan M5a amendment 2026-11-16, review round 1, A11). The publish
  makes Fleet reset every host's binary policy result; a worker round that reads the changed host before it answers
  again exercises A7, which this gate does not assert. A7's regression test is
  TestInventoryRoundAgentBinaryUnansweredAfterPublish."

**RR-149: one text per merge.** All three texts share the mitigation and ISMS columns, which replace the
round-1 columns:
- **Mitigation:** "The agent-side baseline reports a changed slot, `current` or unit drop-in (ADR 0056, C) while the
  agent itself is genuine and can deliver its events; the fleet view counts the device as outdated
  (`components_outdated`); the supervisor refuses downgrades through Paddock's own channel."
- **ISMS:** "Accept that a local root user can evade these checks (RR-01); restrict root on devices and review tamper
  findings."

1. **Merged by PDK-1122b** (risk column):

   "**The binary policy trusts every published release and judges only the processes it recognizes as the agent
   while they run.** The policy `paddock_agent_binary_known` accepts the SHA-256 of every published agent artifact,
   because Fleet policies are global and the expected version of a device is ambiguous during waves, holds, the
   manual update policy and rollbacks (ADR 0056, A2); a local root user who installs a genuine older published
   `paddockd` is not reported by it. At each evaluation it judges every running process that is named `paddockd`,
   runs a file named `paddockd` or a file below `/opt/paddock/agent/`, or was started by `paddock-supervisor`, and
   hashes the executable the process actually runs; a replaced agent is detected only while such a process runs it.
   Not reported: a foreign program that checks in with the device's credentials while osquery sees no genuine
   agent (the agent stopped, crash-looping, replaced by a launcher that detaches the foreign program, or hidden from
   an osquery confined by a unit drop-in), because the mutual watch `paddock_agent_running` stays silent while the
   device checks in (plan M5a decision 8; PDK-1122c planned); a foreign program that checks in while a decoy keeps
   `paddock_agent_running` passing (for example the genuine `paddockd` kept running with its network blocked); a
   foreign program that checks in while fleetd is stopped (PDK-1122d proposed); a second tamper after a repair whose
   passing result a publish reset before the server stored it, until the policy passes again; a process that swaps
   its executable link (`PR_SET_MM_EXE_FILE`); code injected into the running genuine agent; a security policy that
   denies osquery access to `/proc`; a replaced osquery."
2. **Merged by PDK-1122c.** This **supersedes the RR-149 text in section 6 of amendment 2026-11-16 b**. In text 1,
   replace "Not reported: a foreign program that checks in with the device's credentials while osquery sees no
   genuine agent (the agent stopped, crash-looping, replaced by a launcher that detaches the foreign program, or
   hidden from an osquery confined by a unit drop-in), because the mutual watch `paddock_agent_running` stays silent
   while the device checks in (plan M5a decision 8; PDK-1122c planned);" with:

   "A foreign program that checks in with the device's credentials while osquery sees no genuine agent (the agent
   stopped, crash-looping, replaced by a launcher that detaches the foreign program, or hidden from an osquery
   confined by a unit drop-in) is reported by the mutual watch (`device.tamper_agent_not_running`) once
   `paddock_agent_running` failed in evaluations 15 minutes apart (plan M5a decision 8, amendment 2026-11-16 b). A
   check-in cannot prove that the genuine agent sends it: root holds the device key (ADR 0056, amendment b). Not
   reported:"

   Also change the bold lead to "**The binary policy trusts every published release and judges only the processes it
   recognizes as the agent while they run; the mutual watch sees only the absence of the agent.**" and the decoy
   example to "(for example the genuine `paddockd` kept running with its network blocked, or a decoy placed in the
   view of a confined osquery)". PDK-1122c's stop condition "its RR-149 text differs from the one quoted in the
   review-round-1 amendment" refers to text 1 of this addendum.
3. **Merged by PDK-1122d.** Amendment 2026-11-16 c's replacement applies unchanged to text 2: the phrase "a foreign
   program that checks in while fleetd is stopped (PDK-1122d proposed);" occurs there verbatim. Because d's
   replacement already names "a replaced osquery", d also MUST drop the final item "; a replaced osquery" of text 2
   and end the sentence after "access to `/proc`". "Stopped" includes a masked fleetd.

**Files.**

| Path | Action | Purpose |
| --- | --- | --- |
| `server/internal/inventory/inventory.go`, `inventory_test.go` | change | A12 |
| `server/internal/worker/inventory.go`, `inventory_test.go`, `metrics.go`, `metrics_test.go` | change | Low 3 |
| `test/acceptance/inventory_test.go` | change | Low 5 comment |
| `test/system/inventory_test.go` | change | A12 F5 cases |
| `docs/compliance/residual-risks.md` | change | RR-149 text 1 and columns |
| `docs/operations/fleet.md`, `docs/operations/monitoring.md` | change | Lows 2 and 3 |

No migration, no new dependency (`prometheus` is already used by the worker), no agent change.

**Size of the implementation delta:** about 200 lines, roughly half a day plus one F5 run on both VMs.
- A12: about 40 lines (query string plus two F5 cases).
- Low 3: about 120 lines (about 50 code, 70 test).
- Docs and comment: about 40 lines.

## Amendment 2026-11-16 b (architect, PDK-1122c) — the mutual watch reports an absent agent while the device checks in

Status: **accepted** (`decisions-alpha11.md` §147, maintainer and main, 2026-11-16: approved as designed, including
the reuse of `device.tamper_agent_not_running` with the new description and params, and the residuals of D8 and
section 12). Basis: branch state `c792e707` (PDK-1122b with the decisions of its
review round 1). ADR 0056 records the decision in its amendment of the same date ("b"). Ticket PDK-1122c, risk high.
Implementation starts only after PDK-1122b is merged into the cluster branch.

### 1. Goal

A local root user who stops the genuine agent and lets another program check in with the device's credentials is
reported to the organization admin as `device.tamper_agent_not_running`, although the device keeps checking in.
Nothing else changes: no lock, no block, no device API change.

### 2. Context

- **Decision 8 today.** The worker reports a failing `paddock_agent_running` only when the device's last check-in is
  older than 15 minutes (`app.AgentSilence`; `ListAgentNotRunning` in
  `server/internal/adapters/postgres/queries/inventory.sql`). A device that keeps checking in is never reported.
- **The gap (RR-149 as rewritten in PDK-1122b review round 1).** `paddock_agent_binary_known` judges only processes
  it recognizes as the agent (named `paddockd`, running a file named `paddockd` or below `/opt/paddock/agent/`, or
  started by `paddock-supervisor`). A program under another name and unit that checks in with the device key is not
  judged by it, and `paddock_agent_running` fails without a report.
- **Data the server already has.** `device_inventory_ref.policy_updated_at` (migration 00161, PDK-1122b) is Fleet's
  `policy_updated_at` of the host: when Fleet stored the host's latest policy results, in Fleet's clock. Fleet asks a
  host again only once that time is older than `FLEET_OSQUERY_POLICY_UPDATE_INTERVAL` (production default 10 min,
  development 30 s). The adapter counts `policy_updated_at` as a change (`host.changedAt`), so every evaluation is
  synced by the next worker round (5 min in production). `inventory_policy_result.updated_at` is the worker's time of
  the last flip and is not used here.
- **Device credentials.** The device key is a file key or a TPM key (`key_protection: tpm|file`). Root can read the
  file key and can use the TPM key; every request a genuine agent can sign, root can sign.

### 3. Binding decisions

**D1 A check-in cannot prove that the genuine agent runs; osquery carries the detection.** No device API change. The
directions examined, against a local root user who holds the device credentials:

| Direction | What root does against it | Verdict |
| --- | --- | --- |
| Proof derived from the published binary (a challenge in the check-in response that only the binary's code answers, white-box key, code hash) | Runs the genuine published binary as an oracle, or relays the genuine agent's signed requests through a local proxy and drops what it wants. Everything the binary computes, root can compute with it. | Rejected: proves nothing, costs a protocol change. |
| Process-identity binding between osquery and the check-in (the agent reports its pid or a nonce and osquery confirms it; or a policy "every process connected to `device.<domain>` runs a published binary") | Fleet policies are global and return pass or fail (decision 2), so no per-device value reaches osquery. A pid file or nonce file is written by root. The socket variant samples a connection that lives milliseconds every 300 s, breaks behind a proxy, is evaded by kernel NAT, and reads network connections, which the privacy negative list forbids. | Rejected. |
| TPM remote attestation (measured boot plus IMA, quote in the check-in) | Shows what was executed since boot, not what holds the key now: root starts the genuine agent, then the impostor. Needs IMA policy, kernel configuration and a protocol change. | Rejected for alpha; not scheduled. |
| **osquery side (chosen)**: report the agent's absence from evaluations that span 15 minutes, whatever the check-ins say | Root must also keep `paddock_agent_running` passing (a decoy, D7) or stop fleetd (D8). | Chosen: closes the naive case at no contract cost and states the rest as residual. |

**D2 Decision 8 changes (replaces its last sentence).** The worker reports `device.tamper_agent_not_running`, once
per failure, for an active device whose stored `paddock_agent_running` result fails, has `alerted_at` null, and meets
at least one of two conditions:

- **(a) silence, unchanged:** the device's last check-in is older than `app.AgentSilence` (15 min), or it has none;
- **(b) absence while checking in, new:** `device_inventory_ref.policy_updated_at - inventory_policy_result.failing_since
  >= app.AgentAbsence` (15 min), where `failing_since` is Fleet's `policy_updated_at` of the first stored failing
  evaluation of the current failure (D3).

Consequences of (b), each binding:

- **Duration and evaluations.** Both times are Fleet's clock, so device and server clocks play no part. `E - F >= 15
  min` with `E > F` normally means at least two distinct failing evaluations, 15 minutes apart, with no stored passing
  evaluation between them (a stored pass clears `failing_since`); Fleet may advance `policy_updated_at` on a partial
  result batch without evaluating this policy again, so it is not guaranteed (PDK-1122c external review, L2; RR-149).
  With the production interval of 10 min it takes the
  third failing evaluation; the report comes at most about 40 minutes after the stop (first failing evaluation within
  10 min, third 20 min later, sync within 5 min, plus Fleet's distributed-query delay).
- **No check-in condition in (b).** (b) does not look at check-ins. A device that stops checking in is reported by (a)
  no later than by (b), because its last check-in precedes the first failing evaluation; so (b) adds reports only for
  devices that keep checking in.
- **Interaction.** (a) and (b) are one query and one event per failure; `alerted_at` stops both until the policy
  passes again (unchanged). A7 (unanswered results keep a reported failure) applies unchanged.
- **Constants.** `app.AgentAbsence` is a new constant, independent of `app.AgentSilence`, because `AgentSilence` is
  tied to the contact state SQL (migration 00049). Both are 15 min. No environment variable, no development switch.

**D3 `failing_since` (new column, migration).** `inventory_policy_result.failing_since timestamptz NULL`, generic for
every policy:

- `UpsertPolicyResult` takes the host's `policy_updated_at` (`ports.HostInventory.PolicyUpdatedAt`, may be nil) as
  `evaluated_at`.
- Passing result: `failing_since = NULL`.
- Failing result: `failing_since = COALESCE(stored failing_since, evaluated_at)`. The first failing evaluation sets
  it; later failing evaluations keep it. A row that was failing before the migration gets it at its next sync, so (b)
  starts counting then (conservative, no backfill).
- `evaluated_at` nil: `failing_since` stays as it is (NULL for a new failure); (b) cannot fire, (a) still can.
- An unanswered result (A7) is never upserted; a deleted row loses `failing_since`, which only restarts the count.

**D4 No false alarm on regular flows (each MUST hold; tests in section 8).** (b) needs the genuine agent absent from
two evaluations 15 minutes apart. Every regular flow that removes the genuine agent for longer also stops its
check-ins and was already reported by (a):

| Flow | Why (b) stays silent |
| --- | --- |
| Agent restart, supervisor restart, crash with back-off (`MaxBackoff` 1 min) | Absent for seconds to a minute; the next evaluation passes and clears `failing_since`. |
| Agent update: staging, self-test in the inactive slot, flip, probation | The old agent runs until the flip; the self-test and the new agent are `paddockd` from a slot, which passes. |
| Rollback (probation failure, crash loop, self-test failure) | The supervisor runs a slot binary throughout; `rollback_failed` with no agent also stops check-ins. |
| Supervisor upgrade (`dpkg -i`) and its rollback | The supervisor restarts once; a hanging `dpkg` stops check-ins too. |
| Boot | One failing evaluation at most, if osquery evaluates before the agent starts; the next one passes. |
| Suspend and resume | No evaluation during suspend; both processes resume. |
| orbit or osquery restart, fleetd upgrade, Fleet query change | No evaluation while osquery is down; a changed query yields an unanswered result (A7). |
| Uninstall helper | Stops the agent and orbit first; it sends events, which do not update `last_contact_at`. |

Accepted, documented behavior: an agent that crash-loops so that fleetd never finds it in evaluations 15 minutes
apart is reported; it does not run, which is what the event says.

**D5 Fail safe (design contract 8).** The change only reports. No lock, block, wipe, command or quarantine follows
from it; the server-side tamper finding and the attention kind `agent_not_running` are the existing ones.

**D6 Audit code: reuse `device.tamper_agent_not_running`.** The meaning ("fleetd reports the agent not running") is
unchanged, so SIEM rules and the portal message keep working. A new code (option not chosen) would let a SIEM
escalate "absent while checking in" separately, but costs a registry entry, MSGID alias, finding entry and two
portal messages for information that the params already carry. Changes, additive:

```go
CodeDeviceTamperAgentNotRunning: {
	Code: CodeDeviceTamperAgentNotRunning, Emitted: true,
	Description: "fleetd reports that the Paddock agent does not run on a device (actor: system; the inventory system's policy paddock_agent_running): either the device has not checked in for 15 minutes, or the policy failed in evaluations at least 15 minutes apart while the device may have kept checking in, so something other than the genuine agent may use the device's credentials. last_contact_at is the device's last check-in; failing_since is when the inventory system stored the first failing evaluation of this failure and evaluated_at its latest evaluation, both in the inventory system's clock; a last_contact_at later than failing_since means the device checked in while fleetd found no agent.",
	Params:   []string{"policy", "last_contact_at", "failing_since", "evaluated_at"},
	Outcomes: []Outcome{OutcomeSuccess},
	Note:     "Recorded once per failure; the policy passing again ends it.",
},
```

`failing_since` and `evaluated_at` are set when known (RFC 3339 with nanoseconds, `audit.Timestamp`), like
`last_contact_at` today. Portal messages, MSGID, tamper finding entry and attention kind stay unchanged. No secret or
personal data.

**D7 `paddock_agent_running` stays as it is.** Its query text MUST NOT change: a change resets every host's result in
Fleet (A7) and the privacy text. Requiring the agent to be a child of `paddock-supervisor` (option not chosen) adds
little: root can run a decoy under the supervisor as well.

**D8 Residuals (RR-149, rewritten text in section 6).** Not reported: a decoy that keeps `paddock_agent_running`
passing (the genuine published `paddockd` kept running with its network blocked, in another mount namespace with a
fake configuration, or under the supervisor), and a stopped or blocked fleetd while the impostor checks in (the
genuine agent would report `tamper.service_stopped`; the impostor does not). The second is proposed as PDK-1122d
("fleetd silent while the device checks in"), not part of this ticket.

**D9 Contract and compatibility.**

- Device API (`api/openapi/device.yaml` 1.0.0, `pkg/protocol`): **unchanged**. Old agents against the new server and
  new agents against an old server behave as before; no agent change at all.
- Audit event contract: additive (two optional params, new description of an existing code); `make gen` regenerates
  `docs/compliance/audit-codes.md` and `auditCodes.gen.ts`.
- Database: one forward-only migration adding a nullable column (ADR 0047 decision 2; the file number is the next
  free one when the ticket merges, `00162` on `c792e707`). `./paddock rollback` to the previous release is a restore
  as for every schema change.
- Admin API, portal, bundle, Fleet settings, policies, privacy text: unchanged.

### 4. Non-goals

- No change to `agent/` (in particular `agent/internal/revoke/`), the supervisor (budget 865/865), `pkg/`,
  `api/openapi/device.yaml`, the policy SQL files, `paddock_agent_binary_known`, the Fleet settings.
- No detection of a silent fleetd (PDK-1122d), no attestation, no new portal text.
- No change to `app.AgentSilence`, the contact states or migration 00049.

### 5. Files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/00162_inventory_policy_failing_since.sql` (next free number) | new | column `failing_since` (D3) |
| `server/internal/adapters/postgres/queries/inventory.sql` | change | `UpsertPolicyResult`, `ListAgentNotRunning` (section 6) |
| `server/internal/adapters/postgres/pgstore/*` | generated | `make gen` |
| `server/internal/app/inventory.go` | change | `AgentAbsence`; `StoreHost` passes `EvaluatedAt`; `ReportAgentNotRunning` rule and params |
| `server/internal/domain/audit/codes.go` + `make gen` outputs | change | D6 |
| `server/internal/app/inventory_integration_test.go` | change | tests of section 8 |
| `server/internal/worker/inventory_test.go` | change | round test of section 8 |
| `test/acceptance/devicesim/fleet.go`, `fleet_test.go` | change | `FleetHost.AgentNotRunning` |
| `test/acceptance/inventory_test.go` | change | `TestInventoryAgentAbsentWhileCheckingIn` |
| `test/system/inventory_test.go` | change | gate F6 and the count check |
| `docs/compliance/residual-risks.md` | change | RR-149 text |
| `docs/architecture.md` §11.5 | change | row and mutual-watch sentence |
| `docs/operations/fleet.md` | change | step 5 |
| `changelog.d/pdk-1122c.security.md` | new | fragment |

Not touched: everything named in section 4, `server/internal/inventory/policies/`, `server/internal/worker/inventory.go`
(the round already calls `ReportAgentNotRunning` with `now`), `docs/compliance/privacy.md` (no new data: Fleet's
`policy_updated_at` is already stored).

### 6. Interfaces, data model and texts

```sql
-- 00162_inventory_policy_failing_since.sql
-- When the inventory system stored the first failing evaluation of the current failure of a policy, in its own clock
-- (Fleet's policy_updated_at of the host); NULL while the policy passes or the time is unknown (plan M5a amendment
-- 2026-11-16 b, D3). The mutual watch reports an agent absent from evaluations 15 minutes apart while the device
-- checks in. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE inventory_policy_result ADD COLUMN failing_since timestamptz;

-- +goose Down
```

```sql
-- name: UpsertPolicyResult :exec
INSERT INTO inventory_policy_result (device_id, organization_id, policy_key, passing, updated_at, failing_since)
VALUES (@device_id, @organization_id, @policy_key, @passing, now(),
        CASE WHEN @passing::boolean THEN NULL ELSE sqlc.narg(evaluated_at)::timestamptz END)
ON CONFLICT (device_id, policy_key) DO UPDATE
  SET passing = EXCLUDED.passing,
      updated_at = CASE WHEN inventory_policy_result.passing = EXCLUDED.passing THEN inventory_policy_result.updated_at ELSE now() END,
      alerted_at = CASE WHEN EXCLUDED.passing THEN NULL ELSE inventory_policy_result.alerted_at END,
      failing_since = CASE WHEN EXCLUDED.passing THEN NULL
                           ELSE COALESCE(inventory_policy_result.failing_since, EXCLUDED.failing_since) END;

-- Active devices whose agent-running policy fails, not yet reported, and that either have not checked in since before
-- or whose policy failed in evaluations at least absent_for_s apart (plan M5a decision 8 as amended 2026-11-16 b).
-- name: ListAgentNotRunning :many
SELECT r.device_id, s.last_contact_at, r.failing_since, i.policy_updated_at AS evaluated_at
FROM inventory_policy_result r JOIN device d ON d.id = r.device_id
     LEFT JOIN device_status s ON s.device_id = r.device_id
     LEFT JOIN device_inventory_ref i ON i.device_id = r.device_id
WHERE d.state = 'active' AND r.policy_key = @policy_key AND NOT r.passing AND r.alerted_at IS NULL
  AND (s.last_contact_at IS NULL OR s.last_contact_at < @before::timestamptz
       OR i.policy_updated_at >= r.failing_since + make_interval(secs => @absent_for_s::double precision))
ORDER BY r.device_id;
```

```go
// server/internal/app/inventory.go

// AgentAbsence is how far apart two failing evaluations of the agent-running policy must be for a report while the
// device keeps checking in (plan M5a decision 8 as amended 2026-11-16 b): a genuine agent is absent that long only
// when it does not check in either. Independent of AgentSilence, which the contact state shares.
const AgentAbsence = 15 * time.Minute

// StoreHost: UpsertPolicyResultParams gains EvaluatedAt: inv.PolicyUpdatedAt.
// ReportAgentNotRunning(ctx, now) keeps its signature; it passes AbsentForS: AgentAbsence.Seconds() and adds the params
// "failing_since" (r.FailingSince) and "evaluated_at" (r.EvaluatedAt) when non-nil, formatted like last_contact_at.
```

The doc comment of `ReportAgentNotRunning` MUST name both conditions. Generated names may differ from the ones above
(`sqlc`); the semantics MUST NOT.

Texts:

- **RR-149** (replaces the row as merged by PDK-1122b), risk column: "**The binary policy trusts every published
  release and judges only processes it recognizes as the agent; the mutual watch sees only the absence of the
  agent.** The policy `paddock_agent_binary_known` accepts the SHA-256 of every published agent artifact, because
  Fleet policies are global and the expected version of a device is ambiguous during waves, holds, the manual update
  policy and rollbacks (ADR 0056, A2); a local root user who installs a genuine older published `paddockd` is not
  reported by it. It judges every process that is named `paddockd`, runs a file named `paddockd` or a file below
  `/opt/paddock/agent/`, or was started by `paddock-supervisor`, and hashes the executable the process actually runs.
  A foreign program that checks in with the device's credentials while the genuine agent is stopped is reported by
  the mutual watch (`device.tamper_agent_not_running`) once `paddock_agent_running` failed in evaluations 15 minutes
  apart (plan M5a decision 8, amendment 2026-11-16 b). A check-in cannot prove that the genuine agent sends it: root
  holds the device key (ADR 0056, amendment b). Not reported: a foreign program that checks in while a decoy keeps
  `paddock_agent_running` passing (for example the genuine `paddockd` kept running with its network blocked); a
  foreign program that checks in while fleetd is stopped (PDK-1122d proposed); a process that swaps its executable
  link (`PR_SET_MM_EXE_FILE`); code injected into the running genuine agent; a security policy that denies osquery
  access to `/proc`; a replaced osquery." Mitigation and ISMS columns: as merged by PDK-1122b.
- **`docs/architecture.md` §11.5**, row `paddock_agent_running`, third column: "`device.tamper_agent_not_running`
  after 15 min without check-in, or when the policy failed in evaluations at least 15 min apart while the device keeps
  checking in". Mutual-watch paragraph, after "Disabling one is reported by the other.": "A check-in does not prove
  that the genuine agent sends it; a foreign program that checks in while the agent is stopped is reported through
  `paddock_agent_running` (plan M5a decision 8, ADR 0056 amendment b)."
- **`docs/operations/fleet.md` step 5**, first sentence becomes: "reports, once per failure,
  `device.tamper_agent_not_running` for every active device whose `paddock_agent_running` policy fails while it has
  not checked in for 15 minutes, or fails in evaluations at least 15 minutes apart although it keeps checking in —
  then something other than the genuine agent may check in with the device's credentials (fleetd's half of the mutual
  watch). With the default policy interval of 10 minutes the second case is reported within about 40 minutes."
- **Changelog** `changelog.d/pdk-1122c.security.md`: "The mutual watch now reports a stopped Paddock agent also when
  the device keeps checking in, which happens when another program uses the device's credentials."

### 7. Steps

1. **Migration and queries.** Do: migration, both queries, `make gen`. Result: generated `pgstore` with
   `UpsertPolicyResultParams.EvaluatedAt` and `ListAgentNotRunningRow.{FailingSince, EvaluatedAt}`. Check: `make
   gen` twice leaves no diff; `make lint-migrations-frozen` green.
2. **App.** Do: `AgentAbsence`, `StoreHost`, `ReportAgentNotRunning`. Check: `GOTOOLCHAIN=auto go test -count=1
   ./server/internal/app/ -run 'TestReportAgentNotRunning|TestStoreHostFailingSince|TestAttentionAgentNotRunning'`.
3. **Registry.** Do: D6, `make gen`. Check: `go test ./server/internal/domain/audit/`; `make gen` no diff.
4. **Worker test.** Check: `go test ./server/internal/worker/ -run TestInventoryRoundAgentAbsent`.
5. **devicesim and acceptance.** Check: `make acceptance` runs `TestInventoryAgentAbsentWhileCheckingIn` and
   `TestInventoryAgentBinaryPolicy` green.
6. **System gate F6.** Do first a probe on one VM: F6 steps 2 and 3 by hand; record in the result document that
   `pdk-f6-impostor` checks in and that `osqueryd -S` answers `paddock_agent_running` with 0 rows and the agent binary
   policy with 1 row. Then the gate. Check: `make system-test VM=all SUITE=misc` green, run serially to acceptance.
7. **Docs and changelog**, then the quality gate (`make typecheck`, full Go suite with `nice -n 19`, `make lint test`).

### 8. Tests

Each test named "regression" MUST fail without the change (prove by mutation in the result document). All times are
injected or seeded; no test sleeps for a duration.

- **App** `TestStoreHostFailingSince` (Postgres): failing with `PolicyUpdatedAt = t0` → `failing_since = t0`; failing
  again with `t0+10m` → still `t0`; passing → NULL; failing with nil `PolicyUpdatedAt` → NULL; a row failing with
  NULL `failing_since` (seeded) and a failing sync at `t1` → `t1`.
- **App** `TestReportAgentNotRunningWhileCheckingIn` (regression, Postgres), all devices with `last_contact_at = now -
  2 min`, `now` injected:
  - `impostor`: failing evaluations stored at `t0` and `t0+15m` → exactly 1 event with params `policy`,
    `last_contact_at`, `failing_since = t0`, `evaluated_at = t0+15m`; a tamper finding; a second call → still 1.
  - `oneEval`: one failing evaluation at `t0`, `policy_updated_at` unchanged → 0 (a single evaluation never counts).
  - `short`: failing at `t0` and `t0+14m59s` → 0 (boundary); a further failing at `t0+15m` → 1.
  - `restart`: failing at `t0`, passing at `t0+10m`, failing at `t0+20m` and `t0+30m` → 0 (the count restarts at
    `t0+20m`); failing at `t0+35m` → 1.
  - `noTime`: failing evaluations without `PolicyUpdatedAt` → 0.
  - `retired` device with the `impostor` sequence → 0; a device of another organization → not in this organization's
    result and no event in it.
- **App** `TestReportAgentNotRunning` (existing): unchanged and green (the silence rule).
- **App** `TestReportAgentNotRunningKeepsMarkWhileUnanswered` (existing, A7): unchanged and green.
- **Worker** `TestInventoryRoundAgentAbsentWhileCheckingIn`: the fake source reports the host failing with
  `policy_updated_at` advancing by 10 min per round while the device's contact stays fresh → no event after rounds 1
  and 2, one event after round 3, none after round 4; then passing, then failing again in two rounds 15 min apart → a
  second event.
- **devicesim** `TestFleetHostAgentNotRunning`: with `AgentNotRunning` the query containing
  `FROM processes WHERE name = 'paddockd'` returns no rows; every other policy, including the binary policy, is
  answered as before.
- **Acceptance** `TestInventoryAgentAbsentWhileCheckingIn` (`test/acceptance/inventory_test.go`), three acme devices
  with Fleet hosts; every loop iteration checks all three devices in (`Checkin`) and answers Fleet:
  1. `impostor` and `restart` set `AgentNotRunning`; `genuine` does not.
  2. Wait (condition) until the `paddock_agent_running` rows of `impostor` and `restart` are failing with
     `failing_since` set. Then set `restart.AgentNotRunning = false` and wait until its row passes with
     `failing_since` NULL.
  3. Seed elapsed time: `UPDATE inventory_policy_result SET failing_since = failing_since - interval '16 minutes'
     WHERE device_id = <impostor> AND policy_key = 'paddock_agent_running'` (owner DB, like
     `TestAttentionAgentNotRunning`). This shifts the start of the failure instead of waiting 15 minutes; the
     evaluation count is proven by the app tests.
  4. Wait until the org admin (`alice`) sees exactly one `device.tamper_agent_not_running` for `impostor` in the
     audit log, with `last_contact_at` later than `failing_since`.
  5. Record each device's `device_inventory_ref.synced_at`, answer until it took two further, increasing values,
     then assert: `impostor` 1 event and a tamper finding, `restart` 0, `genuine` 0; `carol` (globex) sees none of
     them.
  Steps 2–5 share one failure bound of 10 minutes (as A11).
- **System F6** (`gateF6`, run after F5 in `TestInventoryGates`):
  1. Wait until the stored `paddock_agent_running` result is passing (`paddockSQL`), record `n0` = number of
     `device.tamper_agent_not_running` events of the device.
  2. As root: copy the running slot binary to `/var/lib/paddock-f6/pdk-f6-impostor`, `systemctl stop
     paddock-supervisor`, assert `! pgrep -x paddockd`, start `systemd-run --unit=pdk-f6-impostor
     --property=RuntimeDirectory=paddock /var/lib/paddock-f6/pdk-f6-impostor run`. This is genuine code under a
     foreign name and unit: `paddock_agent_binary_known` does not judge it and passes, `paddock_agent_running` fails.
  3. Wait until `device_status.last_contact_at` is later than the impostor's start (it checks in), triggering with
     `pkill -HUP -x pdk-f6-impostor`.
  4. `WaitEvent(device.tamper_agent_not_running)` with match: `failing_since` present and `last_contact_at` later
     than `failing_since`; failure bound 30 min. Log the latency.
  5. Wait until the stored result has two further `policy_updated_at` values, then assert the count is `n0 + 1` and
     there is no `device.tamper_agent_binary_changed` for the device since F5's count.
  6. Restore (also as `t.Cleanup`): stop the unit, remove `/var/lib/paddock-f6`, start `paddock-supervisor`, wait
     until the stored `paddock_agent_running` result passes.
  Process checks use `pgrep -x`, never `pgrep -f`; every wait is on a condition.
- **System, count check** at the end of `TestInventoryGates` per VM: exactly 2 `device.tamper_agent_not_running`
  events (F2 and F6). F1, F4 and F5 restart orbit and the supervisor several times while osquery evaluates; any further
  event is a false alarm (stop condition, never relaxed).

### 9. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC-C1 | Given a device whose genuine agent is stopped while another program checks in with its credentials, when fleetd's `paddock_agent_running` fails in evaluations at least 15 minutes apart, then the org admin sees exactly one `device.tamper_agent_not_running` in the device's audit log, with `last_contact_at` later than `failing_since`, and a tamper finding; the device is not locked or blocked | F9, RR-149 | Org admin (audit log, findings, attention) |
| AC-C2 | Given a restart, update, rollback, supervisor upgrade, boot, suspend or orbit restart of a genuine device, then no `device.tamper_agent_not_running` is recorded (app and worker tests; F6 count check) | F9 | Org admin |
| AC-C3 | Given a device that does not check in, then it is reported as before (existing tests, F2) | F9 | Org admin |
| AC-C4 | Given an old agent and the new server, or the reverse, then check-ins behave as before; `device.yaml` is unchanged | ADR 0047 | Maintainer (CI `upgrade` job, diff) |
| AC-C5 | Given another organization, then its admin sees none of these events | F10 | Org admin of globex |

### 10. Freedoms

Names of test helpers; the order of the `OR` terms in `ListAgentNotRunning`; the cast syntax `sqlc` needs, as long as
the semantics of section 6 hold; log wording.

### 11. Stop conditions

- PDK-1122b is not merged into the cluster branch, or its RR-149 text differs from the one quoted in the
  review-round-1 amendment.
- The probe of F6 shows that `paddockd run` does not check in when started outside the supervisor (then the gate
  needs another impostor; report, do not change the agent).
- Fleet's `policy_updated_at` does not advance with each evaluation on the VM (the rule depends on it).
- The F6 count check or any existing gate shows an additional `device.tamper_agent_not_running`.
- The change would need an agent, supervisor, `pkg/` or device API change, or a new dependency.
- The migration number is taken; use the next free one and update this amendment in the same commit.

### 12. Risks and open points

- **Decoy and silent fleetd (D8)**: residual, RR-149; PDK-1122d proposed for the silent fleetd.
- **Unobserved passes**: continuity is judged on the evaluations the worker stored. When the worker misses rounds
  (Fleet API down, leader change) a pass between two failing evaluations can go unseen; a false alarm then needs two
  separate agent outages that each coincide with an evaluation 15 minutes apart. Accepted.
- **`/opt` outside the root file system through a symlink**: osquery then sees the agent at the resolved path and
  `paddock_agent_running` fails while the agent checks in, which (b) now reports. Unsupported layout; F6 and the count
  check run on the standard layout. Documented in `docs/operations/fleet.md` step 5 by the sentence: "The agent must
  run from `/opt/paddock/agent/` as installed; a device whose `/opt` is a symbolic link to another place fails
  `paddock_agent_running` and is reported."
- **Detection latency** up to about 40 minutes with the default interval; longer with a longer
  `FLEET_OSQUERY_POLICY_UPDATE_INTERVAL`. Accepted, documented.

### Size (estimate)

| Part | Lines | Files |
| --- | --- | --- |
| Production, hand-written (migration, 2 queries, app, registry) | about 60 | 4 |
| Generated (`pgstore`, audit doc, TS codes) | about 50 | 3 |
| Tests (app ~200, worker ~60, devicesim ~35, acceptance ~120, system ~110) | about 525 | 6 |
| Docs by the implementer (RR-149, architecture, fleet.md, changelog) | about 30 | 4 |
| Design docs (this amendment, ADR 0056 amendment b) | about 330 | 2 (this commit) |

Not protocol-breaking: no device API, bundle, command or event type change; one additive migration and an additive
audit description and params change. VM time: F6 adds about 20 minutes per VM (VMs run in parallel).

## Amendment 2026-11-16 c (architect, PDK-1122d) — the server reports a fleetd that falls silent while the device checks in

Status: **accepted** (`decisions-alpha11.md` §148, main within the maintainer's decision §147, 2026-11-16: approved
as designed, points 1–5; main added the alert rule E8; the attention kind follows as PDK-1122e in alpha.12). ADR 0056 records the decision in
its amendment "c" of the same date. Ticket PDK-1122d, risk high. Implementation starts after PDK-1122c is merged (it
extends gate F6, RR-149 and the migration sequence).

### 1. Goal

A local root user who replaces the agent with a foreign program **and** stops or cuts off fleetd is reported to the
organization admin as `device.tamper_fleetd_silent`. An outage, restart or upgrade of the inventory system raises no
event. Report only; no device API change.

### 2. Context

- **Gap after PDK-1122c (amendment b, D8).** The genuine agent reports a stopped `orbit.service`
  (`tamper.service_stopped`); an impostor does not. fleetd that does not talk to Fleet evaluates no policy, so
  amendment b's rule (b) never fires, and the silence rule (a) does not fire because the impostor checks in.
- **Data available in every round.** `Inventory.Round` already pages through **all** Fleet hosts each round
  (`fleet.Client.ListHostsChangedSince` fetches every page and filters client-side). Each listed host carries Fleet's
  `seen_time`: the last time osquery or orbit talked to Fleet, in Fleet's clock (osquery asks for distributed queries
  every few seconds). Today the adapter drops it for unchanged hosts.
- **Inventory is installation-wide.** One Fleet serves every organization; every device whose bundle has an
  `inventory` section installs fleetd (compiler `inventory`, the same for every organization). A device has a
  `device_inventory_ref` row once one of its hosts was mapped.
- **Contact.** `device_status.last_contact_at` is updated only by materialized check-ins (gateway → worker), not by
  events or the uninstall helper.

### 3. Binding decisions

**E1 Signal.** Per round, the worker computes, from the complete host list:

- `R` = the newest `seen_time` of any listed host (Fleet's clock); `seen(d)` = the newest `seen_time` of the hosts
  whose hardware UUID (lower case) equals the device's; a device with a ref and no listed host uses the stored
  `device_inventory_ref.last_seen_at` (host deleted in Fleet), and is stale when that is NULL.
- **fresh(d)**: `seen(d) >= R - FleetSilence`; otherwise **stale(d)**. `FleetSilence = 15 min`.
- **live(d)**: `last_contact_at >= now - app.AgentSilence` (15 min, server clock).

Comparing with `R` instead of the server clock keeps all freshness judgements in Fleet's clock and makes a Fleet that
stops recording contacts for every host look fresh, not silent (fail safe).

**E2 State machine (per device, stored, no in-memory state).** Two new columns on `device_inventory_ref`:
`fleet_silent_since` (server time of the first round that found the device stale and live) and
`fleet_silent_reported_at`. For every active device with a ref, each round:

| Condition | Transition |
| --- | --- |
| fresh | `fleet_silent_since = NULL`, `fleet_silent_reported_at = NULL` (the silence ended; a later one is reported again) |
| stale, live, `fleet_silent_since` NULL | `fleet_silent_since = now` (start) |
| stale, live, `fleet_silent_reported_at` NULL, `now - fleet_silent_since >= FleetSilenceConfirm` (15 min) | **due** |
| stale, not live | `fleet_silent_since = NULL` (the device stopped checking in too: network loss, suspend, shutdown); `fleet_silent_reported_at` stays |

A due device is reported only if the round's guards hold (E3). Reporting sets `fleet_silent_reported_at = now` in the
event's transaction (once per silence).

**E3 Guards against an alarm wave (installation-wide, per round).** Let `Live` = live devices with a ref, `Fresh` =
live and fresh devices, over all organizations (counts only; nothing crosses an organization boundary).

1. **Complete list.** The watch runs only after every page of the host list was read in this round; any Fleet API
   error fails the round before the watch (as today), so no transition and no report happens while Fleet's API is
   down, restarting or being upgraded.
2. **A fresh peer.** `Fresh >= 1`: some live device demonstrably reaches Fleet now.
3. **A fresh majority.** `2 × Fresh >= Live`: at least half of the live devices reach Fleet normally.

If 2 or 3 fails, no device is reported this round; transitions of E2 still apply; the worker logs one `Warn`
(`fleet silence watch suppressed`, attrs `reason` = `no_fresh_peer` | `fresh_minority`, `due`, `live`, `fresh`) and
sets the gauge `paddock_inventory_fleet_silent_suppressed` to the number of due devices (0 otherwise). A due device
stays due and is reported in the first round whose guards hold.

Option not chosen: a per-organization quorum (the maintainer's example). An organization with one device could never
be judged, an organization-wide outage is the same as an installation-wide one (one Fleet), and installation-wide
counts are stronger evidence. A health probe of Fleet's `/healthz` (not chosen) proves that Fleet's process runs, not
that devices reach `fleet.<domain>` (certificate, DNS, proxy), which the peer and majority guards do prove.

**E4 Why no false alarm (each MUST hold; tests in section 8).** A report needs: stale for 15 min relative to `R`,
live, for 15 more minutes of rounds (`since` is reset the moment the device is not live, and cleared the moment it is
fresh), with a fresh majority.

| Situation | Why no event |
| --- | --- |
| Fleet API down, Fleet restart or upgrade | The list fails → no watch. After the restart hosts reconnect within minutes; a host stale meanwhile gets `since` and is cleared when fresh, long before 15 min confirmation. While most hosts are still stale, guard 3 holds the reports back. |
| Devices cannot reach Fleet (certificate, DNS, Caddy route, Fleet's MySQL stalls `seen_time`) | Every host stops at about the same time → all fresh relative to `R`, or the fresh share drops below half → guard 3. |
| Worker restart, leader change, missed rounds | State is in the database; a restarted worker makes the same decisions. Missed rounds only delay. |
| Device suspend, shutdown, network loss | The device stops checking in → not live → `since` reset. |
| Resume or boot after a long time off | The agent checks in, orbit is stale until it reconnects (seconds to minutes) → `since` set, then cleared when fresh; never 15 min. |
| orbit restart, fleetd upgrade by Paddock's inventory reconciler | Seconds to minutes. A fleetd that does not come back after an upgrade is reported, which is correct (the genuine agent reports `tamper.service_stopped` too). |
| Enrollment before fleetd is installed | No `device_inventory_ref` → not watched. |
| Uninstall, retire, offboarding | The device leaves `active` or stops checking in. |

Accepted, documented: a site that blocks only `fleet.<domain>` while `device.<domain>` stays reachable raises the
event for its devices if they are a minority; the description names this cause.

**E5 Fail safe.** Report only: an audit event and a tamper finding. No command, lock, quarantine or bundle change.

**E6 New code in the closed registry** (`server/internal/domain/audit/codes.go`, next to
`CodeDeviceTamperAgentBinaryChanged`; 27 characters, no MSGID alias):

```go
CodeDeviceTamperFleetdSilent Code = "device.tamper_fleetd_silent"

CodeDeviceTamperFleetdSilent: {
	Code: CodeDeviceTamperFleetdSilent, Emitted: true,
	Description: "The inventory system has not heard from fleetd on a device for at least 15 minutes while the device kept checking in with Paddock, confirmed for 15 more minutes while most other devices reached the inventory system (actor: system). fleetd was stopped, removed or cut off from the inventory system's address only, or something other than the genuine agent checks in for the device. fleetd_seen_at is the device's last contact with the inventory system in its clock (absent when unknown); last_contact_at is the device's last check-in; silent_since is when the worker first found the silence.",
	Params:   []string{"fleetd_seen_at", "last_contact_at", "silent_since"},
	Outcomes: []Outcome{OutcomeSuccess},
	Note:     "Recorded once per silence; fleetd reaching the inventory system again ends it.",
},
```

- Tamper finding: `tamperFindingCodes` gets `audit.CodeDeviceTamperFleetdSilent: ""`; the finding is opened in the
  event's transaction (`UpsertTamperFinding`, `at = now`).
- Portal messages `audit.device.tamper_fleetd_silent`: EN "The inventory system no longer hears from fleetd on
  {target} while the device keeps checking in"; DE "Das Inventarsystem hört von fleetd auf {target} nichts mehr,
  während sich das Gerät weiter meldet".
- **No new attention kind** (option not chosen): it would rewrite the 157-line attention function in a migration and
  extend the admin API enum; `device.tamper_agent_binary_changed` set the precedent of a tamper finding without an
  attention kind, and the finding is listed on the device and in the findings list.
- No secret or personal data in the params.

**E8 Alert on a lasting suppression (added by main, §148).** A suppression that lasts means either that devices
cannot reach `fleet.<domain>` or that a root user controls more than half of the live devices; in both cases the watch
is blind and an operator MUST hear of it. `deploy/compose/prometheus/alerts.yml`, group `paddock-control-plane`,
after `PaddockOSVStale`:

```yaml
      # Plan M5a amendment 2026-11-16 c, E8: the fleetd silence watch holds back due devices because no or too few
      # live devices reach Fleet; the watch is blind until it clears.
      - alert: PaddockFleetSilenceWatchSuppressed
        expr: max(paddock_inventory_fleet_silent_suppressed{role="paddock-worker"}) > 0
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "The fleetd silence watch holds back {{ $value }} devices"
          description: "For 15 minutes the worker has held back reports of devices whose fleetd is silent while they check in, because no live device or fewer than half of them reach Fleet. Either devices cannot reach fleet.<domain> (certificate, DNS, proxy, Fleet's device endpoints) or more than half of the live devices were tampered with; until it clears, a silent fleetd is not reported (docs/operations/fleet.md, \"When the fleetd silence watch is suppressed\")."
```

- `critical`, because while it fires a mass tampering is invisible. `for: 15m` (three rounds) skips a single round
  during a Fleet restart; a due device already needs 30 minutes of silence.
- **Gauge semantics (binding).** Only the process that ran the round sets the gauge, in the watch step, to the
  number of due devices it held back (0 when it reported or nothing was due). `RunSync` MUST set the gauge to 0 when
  `WithLeaderLock` returns `false` (this process did not run the round), so a former leader never keeps a stale value.
  A round that fails before the watch leaves the value of the last watch.
- `make lint-prometheus` runs the rule tests (section 8).
- **Runbook**, new subsection in `docs/operations/fleet.md` after "Inventory sync and mutual watch", titled "When the
  fleetd silence watch is suppressed", text: "`PaddockFleetSilenceWatchSuppressed` fires when the worker has held
  back `device.tamper_fleetd_silent` for 15 minutes because no live device, or fewer than half of them, reach Fleet.
  The worker logs `fleet silence watch suppressed` with `reason` (`no_fresh_peer` or `fresh_minority`), `due`,
  `live` and `fresh` every round. 1. Check that devices reach `https://fleet.<domain>`: the certificate
  (`PaddockCertificateProbeFailing`), DNS, a proxy, and the Fleet service (`docker compose ps fleet`, its log). 2. If
  Fleet is reachable and most devices still look silent, treat it as a possible mass tampering: compare the devices'
  last contact with Fleet in Fleet's host list with their check-ins in the portal, and follow the incident process.
  3. The alert clears in the first round in which at least half of the live devices reach Fleet; the held-back
  devices are then reported."
- `docs/operations/monitoring.md`: a row in the alert table — "`PaddockFleetSilenceWatchSuppressed` | the fleetd
  silence watch has held back reports of silent fleetd for 15 minutes because no live device or fewer than half of
  them reach Fleet (`paddock_inventory_fleet_silent_suppressed`, `role="paddock-worker"`): devices cannot reach
  `fleet.<domain>`, or more than half of them were tampered with (`docs/operations/fleet.md`, *When the fleetd
  silence watch is suppressed*) | critical"; and a row in "Metrics Paddock adds for the alerts" — "`paddock_inventory_fleet_silent_suppressed` | worker, every inventory round of the leader (plan M5a amendment
  2026-11-16 c): devices whose silent fleetd the watch held back in the last round; 0 on a replica that did not run
  the round".

**E7 Contract and compatibility.**

- Device API (`api/openapi/device.yaml` 1.0.0, `pkg/protocol`): **unchanged**; no agent change; old and new agents
  behave the same against the new server.
- Admin API and generated client: unchanged. Audit event contract: one new code (additive, registry and
  `docs/compliance/audit-codes.md`, `auditCodes.gen.ts` by `make gen`).
- Internal port `ports.HostPage` gains a field (not a public contract).
- Database: one forward-only migration (next free number at merge; `00163` after PDK-1122c's `00162`): two nullable
  columns and one platform function.

### 4. Non-goals

No change to `agent/` (in particular `agent/internal/revoke/`), the supervisor, `pkg/`, `api/openapi/*.yaml`, the
Fleet settings and policies, the attention function; no detection of a replaced or simulated osquery; no
attention kind (PDK-1122e, alpha.12).

### 5. Files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/00163_fleet_silence_watch.sql` (next free number) | new | columns and function (section 6) |
| `server/internal/adapters/postgres/queries/inventory.sql` + generated `pgstore` | change | queries of section 6 |
| `server/internal/ports/inventory.go` | change | `HostPage.Seen` |
| `server/internal/adapters/fleet/hosts.go`, `hosts_test.go` | change | fill `Seen` for every listed host |
| `server/internal/inventory/fleetwatch.go`, `fleetwatch_test.go` | new | `WatchFleet` (pure decision function) |
| `server/internal/app/inventory.go`, `inventory_integration_test.go` | change | `FleetWatchDevices`, `ApplyFleetWatch` |
| `server/internal/app/findings.go` | change | finding entry |
| `server/internal/worker/inventory.go`, `inventory_test.go` | change | collect `seen`, call the watch, gauge, log |
| `server/internal/domain/audit/codes.go` + `make gen` outputs | change | E6 |
| `server/web/src/locales/en.json`, `de.json` | change | E6 messages |
| `test/acceptance/inventory_test.go` | change | `TestInventoryFleetdSilent` |
| `test/system/inventory_test.go` | change | gate F7 inside the impostor gate, peers, counts |
| `deploy/compose/prometheus/alerts.yml`, `alerts_test.yml` | change | E8 rule and its tests |
| `docs/compliance/residual-risks.md`, `docs/architecture.md` §11.5, `docs/operations/fleet.md`, `docs/operations/monitoring.md` | change | texts below and E8 |
| `changelog.d/pdk-1122d.security.md` | new | fragment |

### 6. Interfaces and data model

```sql
-- 00163_fleet_silence_watch.sql
-- The server-side watch of fleetd (plan M5a amendment 2026-11-16 c, E2): fleet_silent_since is the worker's time of
-- the first round that found the device's fleetd silent while the device checked in; fleet_silent_reported_at when
-- device.tamper_fleetd_silent was recorded for the current silence. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device_inventory_ref ADD COLUMN fleet_silent_since timestamptz,
                                 ADD COLUMN fleet_silent_reported_at timestamptz;

CREATE FUNCTION paddock_fleet_watch_devices()
  RETURNS TABLE (device_id uuid, organization_id uuid, hardware_uuid text, last_contact_at timestamptz,
                 last_seen_at timestamptz, fleet_silent_since timestamptz, fleet_silent_reported_at timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT d.id, d.organization_id, lower(d.hardware_uuid), s.last_contact_at, i.last_seen_at,
            i.fleet_silent_since, i.fleet_silent_reported_at
     FROM device d JOIN device_inventory_ref i ON i.device_id = d.id
          LEFT JOIN device_status s ON s.device_id = d.id
     WHERE d.state = 'active' $$;
REVOKE ALL ON FUNCTION paddock_fleet_watch_devices() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_fleet_watch_devices() TO paddock_platform;

-- +goose Down
```

```sql
-- name: FleetWatchDevices :many   (platform pool)
SELECT * FROM paddock_fleet_watch_devices() ORDER BY device_id;

-- name: StartFleetSilence :exec   (organization pool)
UPDATE device_inventory_ref SET fleet_silent_since = @at
WHERE device_id = ANY(@device_ids::uuid[]) AND fleet_silent_since IS NULL;

-- name: ResetFleetSilence :exec
UPDATE device_inventory_ref SET fleet_silent_since = NULL WHERE device_id = ANY(@device_ids::uuid[]);

-- name: ClearFleetSilence :exec
UPDATE device_inventory_ref SET fleet_silent_since = NULL, fleet_silent_reported_at = NULL
WHERE device_id = ANY(@device_ids::uuid[]);

-- name: MarkFleetSilentReported :execrows
UPDATE device_inventory_ref SET fleet_silent_reported_at = @at
WHERE device_id = @device_id AND fleet_silent_reported_at IS NULL;
```

```go
// server/internal/ports/inventory.go
// HostPage: Seen lists every host of the page that has a hardware UUID and a contact time, changed or not (plan M5a
// amendment 2026-11-16 c, E1).
Seen []HostSeen

// HostSeen is when a host last talked to the inventory system, in the inventory system's clock.
type HostSeen struct {
	HardwareUUID string
	SeenAt       time.Time
}

// server/internal/inventory/fleetwatch.go
const (
	FleetSilence        = 15 * time.Minute // stale relative to the newest contact of any host
	FleetSilenceConfirm = 15 * time.Minute // how long a stale, live device must stay so before it is due
)

// WatchedDevice is an active device with an inventory reference, as paddock_fleet_watch_devices returns it.
type WatchedDevice struct {
	DeviceID, OrganizationID uuid.UUID
	HardwareUUID             string // lower case
	LastContactAt, LastSeenAt, SilentSince, ReportedAt *time.Time
}

// SilentDevice is a device to report, with the contact time the decision used (nil when unknown).
type SilentDevice struct {
	WatchedDevice
	FleetdSeenAt *time.Time
}

// FleetWatch are the decisions of one round.
type FleetWatch struct {
	Start, Reset, Clear []uuid.UUID
	Report              []SilentDevice
	Due, Live, Fresh    int
	Suppressed          string // "", "no_fresh_peer" or "fresh_minority"
}

// WatchFleet decides one round (E1 to E3). seen maps lower-case hardware UUIDs to their newest contact; live is
// app.AgentSilence. It is pure: no clock, no I/O.
func WatchFleet(devices []WatchedDevice, seen map[string]time.Time, now time.Time, live time.Duration) FleetWatch

// server/internal/app/inventory.go
// FleetWatchDevices reads every active device with an inventory reference across organizations (platform pool).
func (s *InventorySync) FleetWatchDevices(ctx context.Context) ([]inventory.WatchedDevice, error)

// ApplyFleetWatch applies the decisions of w that concern the organization in ctx: Start, Reset and Clear in one
// transaction, then each report through ActionRunner.RunTx (MarkFleetSilentReported; a 0-row result skips the report
// as already done; UpsertTamperFinding). It returns the reported devices.
func (s *InventorySync) ApplyFleetWatch(ctx context.Context, w inventory.FleetWatch, now time.Time) ([]uuid.UUID, error)
```

Worker (`Inventory.Round`): `changedHosts` also collects `page.Seen` into `seen` (newest per UUID); after
`reportBinaries`, `watchFleet(ctx, seen, start)` reads `FleetWatchDevices`, calls `inventory.WatchFleet(devices, seen,
start, app.AgentSilence)`, logs and sets the gauge per E3, and calls `ApplyFleetWatch` once per organization that
has a device in `w` (org from `WatchedDevice.OrganizationID`, `systemContext`). An error fails the round like the
other report steps.

Texts:

- **RR-149**, in the text set by amendment b, replace "a foreign program that checks in while fleetd is stopped
  (PDK-1122d proposed);" by "a foreign program that checks in while fleetd is stopped, as long as fewer than half of
  the live devices reach the inventory system, or on an installation with a single live device (the server reports a
  silent fleetd as `device.tamper_fleetd_silent` only with a fresh majority, and a lasting suppression raises the
  alert `PaddockFleetSilenceWatchSuppressed`; amendment c); a replaced osquery, or a
  program that answers Fleet with the device's osquery node key;".
- **`docs/architecture.md` §11.5**, new row after `paddock_agent_binary_known`: "fleetd talks to Fleet while the
  device checks in (worker, from Fleet's `seen_time`; only while at least half of the live devices reach Fleet) |
  every inventory round | `device.tamper_fleetd_silent` after 15 min of silence confirmed for 15 more min". In the
  mutual-watch paragraph, after the sentence added by amendment b: "The server reports a fleetd that falls silent
  while the device keeps checking in (`device.tamper_fleetd_silent`)."
- **`docs/operations/fleet.md` step 5**, append: "It also reports, once per silence, `device.tamper_fleetd_silent` for
  an active device whose fleetd has not talked to Fleet for 15 minutes (measured against the newest contact of any
  host) while the device kept checking in, confirmed over 15 more minutes. Reports wait while fewer than half of the
  live devices reach Fleet or none does: the worker then logs `fleet silence watch suppressed` and sets
  `paddock_inventory_fleet_silent_suppressed`; a value above 0 for longer than a few rounds means devices cannot reach
  `fleet.<domain>` (certificate, DNS, proxy) and needs the operator. A site that blocks only `fleet.<domain>` raises
  the event for its devices."
- **Changelog** `changelog.d/pdk-1122d.security.md`: "Paddock now reports a device whose fleetd stops talking to the
  inventory system while the device keeps checking in. Outages of the inventory system do not raise it."

### 7. Steps

1. **Migration, queries, port, adapter.** Check: `go test ./server/internal/adapters/fleet/ -run TestListHosts`;
   `make gen` leaves no diff; `make lint-migrations-frozen` green.
2. **`WatchFleet`.** Check: `go test ./server/internal/inventory/ -run TestWatchFleet`.
3. **App, registry, finding, messages.** Check: `go test ./server/internal/app/ -run 'TestApplyFleetWatch|TestFleetWatchDevices'`,
   `go test ./server/internal/domain/audit/`, `make gen` no diff.
4. **Worker.** Check: `go test ./server/internal/worker/ -run 'TestInventoryRoundFleet'`.
5. **Acceptance.** Check: `make acceptance` runs `TestInventoryFleetdSilent` green.
6. **System gate F7.** Check: `make system-test VM=all SUITE=misc` green, serially to acceptance.
7. **Alert rule (E8).** Rule, rule tests, gauge reset in `RunSync`. Check: `make lint-prometheus` (the new tests
   run: the output counts them); `go test ./server/internal/worker/ -run TestInventoryFleetSuppressedGauge`.
8. Docs (including the runbook subsection and both monitoring rows), changelog, quality gate (`make typecheck`, full
   Go suite with `nice -n 19`, `make lint test`).

### 8. Tests

All times are injected or seeded; no test sleeps for a duration; "regression" tests are proven by mutation.

- **Unit** `TestWatchFleet` (table, `now` and `seen` injected), each row asserting `Start`, `Reset`, `Clear`,
  `Report`, `Suppressed`:
  - impostor: stale 16 min, live, `since = now - 15m` → reported; `since = now - 14m59s` → due not yet (boundary).
  - first sight: stale, live, no `since` → `Start`.
  - fresh again (marked reported) → `Clear`.
  - not live (suspend, network loss) → `Reset`, no report; reported mark kept.
  - resume: live, stale, `since` NULL → `Start` only; next round fresh → `Clear` (no report in either).
  - host missing from `seen`: stale by `LastSeenAt`; NULL `LastSeenAt` → stale.
  - duplicate hosts of one UUID: the newest `seen` counts.
  - **Fleet devices unreachable**: every host's `seen` frozen at the same instant → all fresh relative to `R` → nothing.
  - **Fleet restart**: one host reconnected (`R = now`), the others 20 min stale and live, `since` NULL → `Start` only;
    with `since = now - 15m` and 1 fresh of 4 live → `Suppressed = "fresh_minority"`, no report.
  - **no fresh peer**: one live device, stale and due → `no_fresh_peer`.
  - majority boundary: 2 fresh of 4 live → reported; 1 fresh of 3 live → suppressed.
  - empty `seen` → nothing reported.
- **Adapter** `TestListHostsSeen`: a page with a changed host, an unchanged host and a host without UUID → `Seen` has
  both UUID hosts with their `seen_time`, `Hosts` only the changed one; a zero `seen_time` is left out.
- **App** `TestApplyFleetWatch` (Postgres): `Start` keeps an existing `since`; `Clear` clears both columns; a report
  records exactly one event with the three params, sets the mark and opens a tamper finding; applying the same report
  again records nothing (0 rows); a device of another organization in `w` is not touched in this organization's call
  (RLS) and its own call reports it there only.
- **App** `TestFleetWatchDevices`: returns active devices with a ref of two organizations; a retired device and a
  device without a ref are absent.
- **Worker** `TestInventoryRoundFleetSilence` (fake source and clock, Postgres): rounds every 5 min; the device's host
  stops advancing `seen` while three peers advance and the device keeps `last_contact_at` fresh → no event until the
  round where both thresholds hold, then exactly one; further rounds none; the host advances again → mark cleared; a
  second silence → a second event.
- **Worker** `TestInventoryRoundFleetOutage` (regression for the guards): (1) `ListHostsChangedSince` fails for six
  rounds → no transition, no event, the round returns the error; (2) then every host reconnects in the same round
  except the watched device, which reconnects one round later → no event; (3) all hosts' `seen` frozen for 40 min
  with fresh check-ins → no event; (4) 3 of 4 live devices stale for 40 min → no event, the gauge is 3 and one
  `WARN` per round with `reason=fresh_minority`.
- **Worker** `TestInventoryFleetSuppressedGauge`: a round that holds back 2 devices sets the gauge to 2; a
  following round that reports them sets 0; `RunSync` of a process whose `WithLeaderLock` returns `false` sets 0.
- **Rules** (`alerts_test.yml`, `make lint-prometheus`): `PaddockFleetSilenceWatchSuppressed` — series
  `paddock_inventory_fleet_silent_suppressed{role="paddock-worker"}` at 3 from minute 1 → no alert at 15m, firing at
  16m with `severity: critical` and summary "The fleetd silence watch holds back 3 devices"; a series that returns
  to 0 at minute 10 → no alert at 20m; a standby series at 0 next to a leader at 0 → no alert.
- **Worker** `TestInventoryRoundFleetWorkerRestart`: a fresh `Inventory` instance over the same database continues
  the state: a device with `since = now - 16m` in the database is reported in the new instance's first round, exactly
  once across both instances.
- **Acceptance** `TestInventoryFleetdSilent` (`test/acceptance/inventory_test.go`), acme devices, 10-minute failure
  bound, waits on conditions only:
  1. Three peers: `activeDevice` + `enrollFleetHost`; every loop iteration checks them in and lets their hosts
     answer.
  2. `silent`: `activeDevice`, checking in every iteration, never enrolled in Fleet. Seed through the owner DB a
     `device_inventory_ref` row (`external_id` `'acceptance-missing'`, `last_seen_at = now() - interval '20
     minutes'`, `fleet_silent_since = now() - interval '16 minutes'`): the host-deleted branch of E1, already confirmed.
  3. `quiet`: like `silent` but `fleet_silent_since` NULL and `last_seen_at = now() - interval '20 minutes'`, and it
     stops checking in after step 1 (its last contact ages; it is live only until `AgentSilence` passes).
  4. Wait until alice sees exactly one `device.tamper_fleetd_silent` for `silent` with `fleetd_seen_at`,
     `last_contact_at`, `silent_since`, and its tamper finding. `quiet` gets `fleet_silent_since` set (it is still
     live) and no event within this test.
  5. Two further worker rounds (each peer's `synced_at` advanced twice): `silent` still 1 event, peers 0; carol
     (globex) sees none.
  6. Cleanup deletes the seeded refs.
- **System F7** (in the impostor gate of amendment b, after F6's assertions and **before** F6's restore):
  1. Start two simulated peers for the duration of F7: `devicesim` devices of the stack's organization with Fleet
     hosts (`devicesim.EnrollFleet` with the stack's enroll secret as `test/acceptance/fleethost.go` reads it),
     checking in and answering Fleet every 30 s in a goroutine stopped by `t.Cleanup`. Each VM starts its own peers,
     so the gate needs no other VM and both VMs can run F7 in parallel (2 stale VMs, 4 fresh peers).
  2. Record `m0` = `device.tamper_fleetd_silent` events of the device; `systemctl stop orbit.service`; the impostor
     keeps checking in; nobody reports the stop (the supervisor is stopped).
  3. `WaitEvent(device.tamper_fleetd_silent)` with match: `fleetd_seen_at` present and `last_contact_at` later than
     it; failure bound 50 min; log the latency.
  4. `systemctl start orbit.service`; wait until `device_inventory_ref.fleet_silent_reported_at` is NULL
     (`paddockSQL`); then two further `synced_at` values; assert `m0 + 1`.
  5. The F6 restore follows; `t.Cleanup` starts orbit if a step failed.
- **System counts** at the end of `TestInventoryGates`, per VM: `device.tamper_agent_not_running` 2 (F2, F6),
  `device.tamper_agent_binary_changed` 1 (F5), `device.tamper_fleetd_silent` 1 (F7); each simulated peer 0 of all
  three. F2 and F5 stop orbit for a few minutes, which MUST NOT raise `device.tamper_fleetd_silent`.

### 9. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC-D1 | Given a device whose fleetd stopped talking to Fleet while the device keeps checking in and most live devices reach Fleet, then after the silence is confirmed the org admin sees exactly one `device.tamper_fleetd_silent` and a tamper finding; nothing is locked or blocked | F9, RR-149 | Org admin (audit log, findings) |
| AC-D2 | Given a Fleet outage, restart or upgrade, a worker restart, or devices that cannot reach Fleet, then no event (worker tests); the operator sees the suppression in the log and the gauge | F9 | Org admin; platform operator (metrics) |
| AC-D3 | Given suspend, boot, network loss, orbit restart or a fleetd upgrade, then no event (unit tests; F2/F5 counts) | F9 | Org admin |
| AC-D4 | Given another organization, then its admin never sees the event | F10 | Org admin of globex |
| AC-D5 | Device API, admin API and agent unchanged | ADR 0047 | Maintainer (diff, CI `upgrade`) |
| AC-D6 | Given the watch holds back reports for 15 minutes, then `PaddockFleetSilenceWatchSuppressed` fires as critical and the operator finds the runbook in `docs/operations/fleet.md` (rule tests) | F9 | Platform operator (alerting) |

### 10. Freedoms

Internal helper names; how `seen` is accumulated across pages; whether `ApplyFleetWatch` groups the three updates in
one statement; log wording except the `reason`, `due`, `live`, `fresh` attributes.

### 11. Stop conditions

- PDK-1122c is not merged into the cluster branch.
- Fleet's list response does not carry `seen_time` for every host, or `seen_time` does not advance at least every
  2 minutes for a running fleetd on the VM (probe in step 6 before the gate: read the host twice 3 minutes apart).
- `paddock_fleet_watch_devices` does not return rows of every organization to the platform role (RLS); do not weaken
  any policy, report.
- An existing acceptance or system gate starts recording `device.tamper_fleetd_silent`, or the acceptance positive is
  suppressed by the guards through devices of other tests.
- The change would need an agent, supervisor, `pkg/`, device or admin API change, or a new dependency.

### 12. Risks and open points

- **Installations with one live device, or where most devices cannot reach Fleet,** are never judged (guards 2 and
  3). Accepted; RR-149.
- **A root user who controls more than half of the live devices** suppresses the per-device reports; the lasting
  suppression raises the critical alert `PaddockFleetSilenceWatchSuppressed` (E8). Accepted; RR-149.
- **A site that blocks only `fleet.<domain>`** raises the event for its devices; documented in fleet.md and the
  description.
- **A replaced osquery or a program that answers Fleet with the device's node key** keeps `seen_time` fresh. RR-01,
  RR-149.
- **Detection latency** about 35 minutes (15 min silence, up to one round, 15 min confirmation, one round).
- **Large installations:** one row per active device with a ref per round through the platform function; the same
  order as `MapHosts` today. Accepted.

### Size (estimate)

| Part | Lines | Files |
| --- | --- | --- |
| Production, hand-written (migration ~30, queries ~25, port/adapter ~25, `fleetwatch.go` ~110, app ~90, worker ~50, registry/finding/messages ~15, alert rule ~15) | about 360 | 11 |
| Generated (`pgstore`, audit doc, TS codes) | about 70 | 3 |
| Tests (unit ~260, adapter ~30, app ~150, worker ~230, rules ~45, acceptance ~130, system ~170) | about 1015 | 7 |
| Docs by the implementer (RR-149, architecture, fleet.md incl. runbook, monitoring.md, changelog) | about 60 | 5 |
| Design docs (this amendment, ADR 0056 amendment c) | about 420 | 2 |

Not protocol-breaking: no device API, admin API, bundle, command or event-type change; one new audit code, one
additive migration. VM time: F7 adds about 35 minutes per VM (VMs in parallel), on top of F6.

## Amendment 2026-11-16 (architect, PDK-1122a review round 1)

Scope: the fix round of PDK-1122a after the external review and review 1 of commit `9b285ad3` (both not approved),
under the guidance of `decisions-alpha11.md` §148. It amends part C of the amendment "2026-11-16 (architect,
PDK-1122)" above; where it differs, this amendment wins. ADR 0056 gets an amendment of the same date (the check now
reports its own suspension, and the supervisor rollback exception rule changes). Everything not named here stays as
implemented in `9b285ad3`.

### R0 Principle

An integrity check that cannot run MUST NOT go silent. Every reason for skipping an object or a whole pass is a
**suspension cause** from the closed table in R3. A cause that persists past its bound raises one event the server
records and shows: the existing code `device.tamper_protected_file_changed`, with `file` set to the path that blocks
the check and the new value `check_suspended` of the existing param `reason` (R4). A local `Warn` alone is not enough.
Regular flows MUST NOT reach a bound (R3 lists the longest regular duration per cause).

### R1 B1: observe outside the lock (replaces C3 "Every read-modify-write holds an exclusive flock" for `Check`)

`Checker.Check` MUST run in this order:

1. **Peek.** Read `integrity.json` without the lock through `readRegular` (R2) and keep its `generation` (R6) as
   `gen0`. A missing or unreadable file gives `gen0 = 0`; the pass continues.
2. **Observe, without the lock.** Evaluate the flow conditions (quiescence C4, supervisor busy, dpkg busy, the
   conversion skip), hash the slots, `current`, the four agent-written files and `/usr/bin/paddockd`, read the
   `md5sums` files, run `dpkg-query` and `systemctl show`, hash the package files and foreign unit files, and apply
   the md5sums race guard (C5). The result is an in-memory snapshot (type `snapshot`, unexported) that holds, per
   path, the observed value, and per package file additionally the observed MD5 and the `md5sums` entry. The snapshot
   also holds the set of active suspension causes (R3) of this pass.
3. **Classify, under the lock.** `store.update` takes `integrity.lock` (wait at most `LockWait` = 10 s, unchanged),
   loads the baseline, and:
   - if `b.Generation != gen0`, changes nothing and records the cause `baseline_raced` (another writer moved the
     baseline while this pass observed; the pass is dropped, no event);
   - otherwise applies the deferred re-syncs (R7), the initializations (C4, C7), the staged guard, the exceptions,
     `mark` (C8) and the exception pruning (C5) to the snapshot, merges the suspension state (R4), sets
     `b.CheckedAt` to `Now()` and saves.
4. **Release the lock, then emit**: first the change events of `mark`, then the suspension events of R4.

`Check` MUST NOT run `systemctl` or `dpkg-query`, hash any file, or read an `md5sums` file while it holds the lock;
under the lock it reads and writes only `integrity.json`. `SyncFiles`, `RecordStaged`, `UpdateResult`, `RecordSupervisorPre` and
`SupervisorResult` MUST likewise hash before they take the lock and hold it only for load, modify and save.

### R2 External M4: no TOCTOU between `Lstat` and `Open`

1. New unexported helper in `agent/internal/integrity/baseline.go`:

   ```go
   // openRegular opens path with O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC and Fstats the descriptor.
   // It returns (nil, info, nil) when the descriptor is not a regular file, so the caller observes its type.
   func openRegular(path string) (*os.File, fs.FileInfo, error)
   // readRegular reads a regular file of at most maxBytes through openRegular; a non-regular file or a larger
   // one is an error.
   func readRegular(path string, maxBytes int64) ([]byte, error)
   ```

2. `hasher.file` MUST: `Lstat` (absent → `""`; symlink → `"symlink:" + Readlink`; non-regular → `"!type:<mode>"`,
   unchanged); then `openRegular`. On `ELOOP` (swapped to a symlink after the `Lstat`) it returns
   `"symlink:" + Readlink`. When the descriptor is not regular it returns `"!type:" + <mode of the Fstat>`. The
   fingerprint for the cache MUST come from the `Fstat` of the descriptor, never from the `Lstat`, and the content
   MUST be read from that descriptor.
3. Every other file read of package `integrity` MUST go through `readRegular`: `integrity.json` (max 1 MiB) and the
   `md5sums` files (max 4 MiB). A FIFO, device node or oversized file there is a read error (R3 causes
   `baseline_read` or `object:<path>`), never a blocking read.
4. `update.ReadResult`, `supervisorpkg.ReadResult` and `supervisorpkg.ReadMarker` are not changed in this ticket (they
   are read by pre-existing agent code on the same loop; a FIFO there blocks the agent already today). Follow-up stub
   **PDK-1122f** (todo): FIFO-safe reads of the agent's state files.

### R3 Suspension causes and bounds (new, closed table)

Two bounds, in **observed time** (R4), as constants in `agent/internal/integrity/suspend.go`:

```go
const (
	// StateBound covers causes in the baseline itself; regular holders keep integrity.lock for milliseconds.
	StateBound = 15 * time.Minute
	// FlowBound covers causes that Paddock's own flows create; the longest regular one (a dpkg run of a release
	// upgrade) stays well below it.
	FlowBound = 6 * time.Hour
)
```

| Key | `file` param | Active in a pass when | Bound | Longest regular duration |
| --- | --- | --- | --- | --- |
| `lock` | `/var/lib/paddock/state/integrity.lock` | `store.lock` returned `ErrLockTimeout` | State | seconds (enroll, a sync) |
| `baseline_read` | `/var/lib/paddock/state/integrity.json` | load failed with an error other than not-exist (also non-regular, oversized). The pass is skipped; the baseline is NOT re-initialized (internal L2). A JSON parse error stays C9 (rename, re-initialize, no suspension cause) and is reported by R14. | State | never |
| `baseline_write` | `/var/lib/paddock/state/integrity.json` | the save of step 3 failed | State | never (full disk is not regular) |
| `baseline_raced` | `/var/lib/paddock/state/integrity.json` | generation mismatch in step 3 | State | one pass |
| `update_request` | `/var/lib/paddock/staging/request.json` | `update.Pending` | Flow | minutes (install); a PDK-1118 stall is an anomaly the runbook names |
| `probation` | `/var/lib/paddock/state/probation.json` | the file exists (any type) | Flow | 10 min probation; a pending rollback (ADR 0024) is an anomaly |
| `update_result` | `/var/lib/paddock/state/update-result.json` | the result is unreadable, or readable and not processed | Flow | one loop tick |
| `supervisor_marker` | `/var/lib/paddock/state/supervisor-upgrade.json` | the marker exists (any type) | Flow | 30 min (`supervisorpkg.StaleAfter`) |
| `supervisor_result` | `/var/lib/paddock/state/supervisor-upgrade-result.json` | the result is unreadable, or readable and not processed | Flow | one loop tick |
| `staged:<path>` | the slot path or `/opt/paddock/agent/current` | the staged guard of `checkSlots` skipped that path | Flow | install + 10 min probation |
| `conversion` | `/etc/paddock/disk-setup.json` | `Pass.SkipFiles` holds it | Flow | one preparation or cleanup run (minutes) |
| `dpkg_lock` | `/var/lib/dpkg/lock-frontend` | `DpkgBusy()` at the start or the end of the package check | Flow | one apt run, < 3 h for a release upgrade |
| `package:<name>` | `/var/lib/dpkg/info/<the md5sums file that was read>` | reading `md5sums` failed (not not-exist), `dpkg-query` failed, or the race guard skipped the package | Flow | one dpkg run |
| `object:<path>` | `<path>` | hashing or reading that checked path failed (slots: `/opt/paddock/agent`; `/usr/bin/paddockd`; an agent-written file; a package file; a foreign unit file) | Flow | never |
| `unit:<unit>` | `/etc/systemd/system/<unit>.d` | `systemctl show` failed or its `DropInPaths` did not parse (R9) | Flow | never |

No other cause exists. "Package not `installed`" and "unit not-found" stay silent skips (C5, C6: their absence is
reported elsewhere).

### R4 Observed time, one event per episode, persistence

1. **State.** `Baseline.Suspended map[string]Suspension` (`json:"suspended,omitempty"`), keyed by the cause key:

   ```go
   type Suspension struct {
       File     string    `json:"file"`
       Observed int64     `json:"observed_s"` // seconds the cause was seen active
       Last     time.Time `json:"last"`       // time of the last pass that saw it active
       Reported bool      `json:"reported"`
   }
   ```

   The `Checker` keeps the same map in memory (`Checker.suspended`). Memory is authoritative while the process runs;
   at each successful load (step 3) a persisted entry the memory lacks is adopted, and on a conflict the entry with
   the larger `Observed` wins, `Reported` is OR-ed. Every successful save writes the memory map.
2. **Accumulation.** `Pass.Interval time.Duration` (new field; the agent sets `a.d.Config.DriftInterval`). For every
   cause active in a pass: a new entry starts with `Observed = 0, Last = now`; an existing entry adds
   `min(now − Last, 2 × Pass.Interval)` seconds (0 when `now` is before `Last`) and sets `Last = now`. The cap makes a
   suspend, a shutdown or an agent restart count as at most two intervals, so a request that waits across a night
   of sleep does not reach `FlowBound` (no false alarm on laptops).
3. **Episode end.** A cause not active in a pass is deleted from the map. Causes of state (`lock`, `baseline_*`) are
   evaluated every pass; flow causes too, because R1 evaluates them before the lock. A pass that ends at `lock`
   still updates the memory map of every cause it evaluated.
4. **Report.** When `Observed ≥ bound` and `!Reported`, the pass emits once `device.tamper_protected_file_changed`
   with `{file: Suspension.File, reason: "check_suspended"}` and sets `Reported = true`. A new episode of the same
   cause reports again. The event is emitted even when the save failed (it is the point of `baseline_*`); the
   memory map then holds the dedup, so a restart while the baseline stays unwritable reports once more after a new
   `StateBound` (documented in RR-148).
5. **Fail safe.** Suspension changes nothing on the device and stops nothing; it only reports.

### R5 The event and the audit contract (needs main's approval, see "Approvals")

- `pkg/protocol/types.go`: `TamperProtectedFileChanged` gains `Reason string \`json:"reason,omitempty"\``, and a
  constant `TamperReasonCheckSuspended = "check_suspended"` next to it. A change event carries no `reason`.
- `Checker.Emit` becomes `func(file, reason string)`; `agent.New` maps it to
  `protocol.TamperProtectedFileChanged{File: file, Reason: reason}`.
- The server needs no code change: `reason` is already in `deviceEventParams` and in `eventParams`'
  string list (`server/internal/app/devicereports.go`), and the tamper finding's subject stays `file`
  (`server/internal/app/findings.go`), so a suspension opens its own finding per blocking path.
- **Audit contract text changes:** the `Description` of `CodeDeviceTamperProtectedFileChanged` in
  `server/internal/domain/audit/codes.go` MUST become exactly:
  "A device found a protected file changed that the agent does not restore itself, e.g. its PAM configuration or one
  of Paddock's own components (actor: the device). reason check_suspended: the agent could not check its own
  components for longer than a fixed bound, and file names the path that blocks the check." —
  and `docs/compliance/audit-codes.md` is regenerated with `make gen`. This is an additive change of the released
  code's contract: one new value of an existing param, no new code, no MSGID change, no new param name, no i18n key.
  The portal message (`audit.device.tamper_protected_file_changed`) is not changed.

### R6 Generation and `checked_at`

`Baseline` gains `Generation uint64` (`json:"generation"`) and `CheckedAt time.Time` (`json:"checked_at"`). Every save
by any writer increments `Generation` by one. `Check` sets `CheckedAt` on every successful classify, so every
completed pass writes the file (one small write per drift interval; the system gates wait on it, R12).

### R7 Lock timeout never raises a false report (low; B1 alone does not suffice)

B1 shortens every hold to milliseconds, but a stalled disk can still keep a save's fsync past `LockWait`. Therefore:

1. **Deferred re-sync.** New goroutine-safe method `func (c *Checker) Defer(paths ...string)` (mutex inside the
   `Checker`). `Agent.syncIntegrity` calls it with the same paths when `SyncFiles` returns an error. In step 3 of the
   next passes, each deferred path takes its snapshot value as its baseline (`b.expect`) and is not compared in that
   pass; it leaves the deferred set only after a successful save. RR-148 names the window between the write and the
   deferred re-sync.
2. **Bookkeeping before a flow.** One rule for the four hooks `RecordStaged` (`handleUpdate`), `RecordSupervisorPre`
   (R10), `UpdateResult` (`reportUpdate`) and `SupervisorResult` (R10): on an error, the agent returns from the hook's
   caller **before** the flow step it guards (staging; `Launch`; the event, `FailedUpdateVersion` and
   `ReportedUpdateAt`; the event, the retry bookkeeping and `ReportedSupervisorUpgradeAt`) and retries at the next
   tick, until the first failure for the same key is `StateBound` (wall clock, memory only) old. Then it proceeds
   with one `Warn` naming the missed bookkeeping. Keys: `staged:<version>`, `supervisor-pre:<version>`,
   `update-result:<at RFC3339Nano>`, `supervisor-result:<at RFC3339Nano>`. Helper in
   `agent/internal/agent/integrity.go`:

   ```go
   // integrityRetry reports whether the caller must stop and retry later: err is non-nil and the first failure
   // for key is younger than integrity.StateBound. A nil err forgets key.
   func (a *Agent) integrityRetry(key string, err error) bool
   ```

   Rationale for the bound: an unwritable baseline must not withhold update results or block agent and supervisor
   updates for good (design contract 8); it is reported by R3 `baseline_write` after the same bound.
3. This closes internal **B2**: `reportUpdate` calls `UpdateResult` first and, when `integrityRetry` says stop,
   returns before the event and before `ReportedUpdateAt`. While the result is unprocessed, the slots are not judged
   (C4), so no false report occurs.

### R8 External H1 and the guarded sync of `disk-setup.json`

1. `encryptDiskAbortCommand` and `handleAbortRequest` MUST sync `disk-setup.json` only when `encrypt.Abort` returned
   `aborted == true`.
2. All four `disk-setup.json` sync sites (both aborts, `Prepare` in `runConversions`, `RunCleanup` in
   `retryCleanup`) MUST use the guarded sync:

   ```go
   // Fingerprint returns the Lstat fingerprint (dev, inode, size, mtime_ns, ctime_ns, type) of a layout path;
   // an absent file has the zero Fingerprint.
   func Fingerprint(l paths.Layout, full string) Fingerprint
   // SyncFileIfChanged is SyncFiles for one file, applied only when its fingerprint differs from before.
   // changed is false when it did nothing.
   func SyncFileIfChanged(l paths.Layout, full string, before Fingerprint) (changed bool, err error)
   ```

   The agent takes `before` immediately before the call that may write (`Abort`, `Prepare`, `RunCleanup`). A call that
   did not write leaves the fingerprint unchanged (Paddock writes by temp file and rename, the cleanup removes the
   file last), so an edit made before the call is never laundered. An edit made during the call is accepted (RR-148,
   unchanged). On an error, `syncIntegrity` defers the path (R7.1) only when `changed` is true.

### R9 Drop-in paths with spaces (external L4)

systemd 255 quotes a `DropInPaths` element that needs it (verified on Ubuntu 24.04: a drop-in `a b.conf` prints as
`"…/a b.conf"`). `show` MUST split `DropInPaths` with a new unexported `splitQuoted(s string) ([]string, error)`:
elements are separated by single spaces; an element starting with `"` runs to the next unescaped `"`, and inside it
`\x` yields `x`; outside quotes `\x` yields `x` as well. An unterminated quote (a path with a newline splits the
line) is an error: the unit counts as failed (`complete = false`, cause `unit:<unit>`), never as clean.

### R10 External M3 / internal B3 marker: the rollback exception needs the pre-upgrade state

Replaces the rule "records `{path, md5 from the current md5sums entry, sha256 observed now}`" of C5.

1. **Capture.** In `Agent.handleSupervisorPackage`, after `supervisorpkg.Stage` succeeded and before
   `a.markerSeen.reset()` and `supervisorpkg.Launch`, the agent calls

   ```go
   // RecordSupervisorPre records, for the supervisor binary and unit, the SHA-256 of each file that is expected now
   // (its MD5 equals the md5sums entry, or a valid rollback exception covers it), bound to the version to install.
   func RecordSupervisorPre(l paths.Layout, arch, version string) error
   ```

   It stores `Baseline.SupervisorPre *SupervisorPre` (`json:"supervisor_pre,omitempty"`) with
   `{Version string; Files map[string]string /* path → sha256 */}`, replacing any earlier one. A file that is not
   expected at capture time is left out. On an error, R7.2 applies (no `Launch` this check-in).
2. **Result.** In `Agent.reportSupervisorUpgrade`, for every result that is not `deferred` (including the
   agent-synthesized stale `install_failed`), **before** the event:

   ```go
   // SupervisorResult consumes SupervisorPre. For an outcome other than updated it records an exception for a
   // supervisor file only when its observed SHA-256 equals SupervisorPre.Files[path] and SupervisorPre.Version equals
   // version; the exception holds the current md5sums entry and that SHA-256. Any other file gets no exception and
   // a Warn, and the next pass reports it.
   func SupervisorResult(l paths.Layout, arch, version, outcome string) error
   ```

   It clears `SupervisorPre` in every case. `SupervisorRolledBack` is removed. A planted stale marker with a replaced
   binary therefore yields no exception (no `SupervisorPre` of that version, or a different SHA-256), and the binary
   is reported once the supervisor is no longer busy. A chain of rollbacks works, because the capture accepts a file
   that an earlier exception covers.
3. No supervisor or `supervisorpkg/upgrade.go` line changes. The capture is entirely agent-side; the supervisor budget
   stays 865 of 865.

### R11 Internal lows

- **L2:** see R3 `baseline_read`: `load` returns the error, `Check` skips the pass, the writers return the error.
- **L3 (pending rollback):** `UpdateResult` moves `Staged` to `Baseline.LastStaged` (`json:"last_staged,omitempty"`)
  instead of dropping it; `RecordStaged` clears `LastStaged`. A result without `Staged` whose version equals
  `LastStaged.Version` uses `LastStaged` (no re-initialization, no `Warn`). The staged guard of `checkSlots` uses only
  `Staged`, never `LastStaged`. The rule for `current` in a result of the staged release becomes: the observed
  `current` becomes the baseline when it is `"A"` or `"B"` and the slot it points to has, after the slot rule, a
  baseline equal to its observed hash. This covers `rolled_back` after `rollback_failed` (the flip back to the old
  slot) and a crash between `UpdateResult` and `saveState`. RR-148 names the consequence: within one update result
  window, `current` may be pointed at the other slot's genuine baseline binary without an event.
- **L4 (runbook C10):** in `docs/operations/agent-releases.md`, replace "reports either step once as
  `device.tamper_protected_file_changed`: step 2 with `file` `/opt/paddock/agent/current`, step 3 with
  `/opt/paddock/agent/<slot>/paddockd`." with: "reports step 3 once as `device.tamper_protected_file_changed` with
  `file` `/opt/paddock/agent/<slot>/paddockd`. Step 2 is usually not reported, because the agent stages the release
  again and the supervisor's result moves the baseline; it is reported with `file` `/opt/paddock/agent/current` only
  when the re-staged release is refused." The rest of the paragraph stays.
- **L1 (real dpkg lock):** see T11.
- **L5:** see R12.

### R12 System gates and the harness hand edits

1. New helper in `test/system/integrity.go`:

   ```go
   // WaitIntegrityPass waits until checked_at in the device's integrity.json changed twice after the call, so that
   // one whole pass started after the call (ADR 0056).
   func (d *Device) WaitIntegrityPass(t *testing.T)
   ```

   It reads `checked_at` with `sudo grep -o '"checked_at":"[^"]*"' /var/lib/paddock/state/integrity.json`; timeout
   `3 × drift interval + 2 min`.
2. Every "no tamper" assertion (S4 in `agent_test.go`, A1 in `encrypt_test.go`) MUST call `WaitIntegrityPass` and
   then `Checkin` before it reads events.
3. **Harness hand edits** (`SetDriftInterval`, `pinTestKey`, `forgeBundle`, the uninstall gate's `agent.yml` edit)
   are genuine writes outside Paddock and stay reported; the harness MUST NOT suppress or re-baseline them. Binding
   scoping rule for every gate: a "no tamper" assertion takes its `seen` set after the last hand edit of a C object
   followed by `WaitIntegrityPass` and `Checkin`, and filters by path prefix; an exact-count assertion filters by
   `file`. `SetDriftInterval` gets a doc comment that it raises one `/etc/paddock/agent.yml` event once the first
   integrity pass ran.

### R13 Documents

- `docs/compliance/residual-risks.md`, RR-148: add, in this order:
  - **Short-lived changes:** a change that is made and reverted within one drift interval (at least 300 s) is not
    seen — for example a binary swapped, its service restarted, and the file restored while the process keeps running
    from the deleted inode; or a drop-in placed in a search path the file scan does not read
    (`/usr/lib/systemd/system/<unit>.d`, `/usr/local/lib/systemd/system`, `service.d/`, prefix directories,
    `system.control/`), activated by `daemon-reload` and a restart, and removed again.
  - **Windows:** a slot that holds the release the agent staged is not judged until its result (bounded by
    `FlowBound`); `disk-setup.json` is not judged while the conversion worker runs, and an edit made then is accepted
    at its sync; an edit between a Paddock write and a deferred re-sync (R7.1) is accepted; within an update result,
    `current` may point at the other slot's genuine binary (R11 L3).
  - **Suspension:** while a cause of R3 is active, changes are not reported individually; the suspension itself is
    reported after its bound (`check_suspended`). A change reverted before the suspension ends is not seen. With an
    unwritable baseline, an agent restart restarts the bound.
  - Replace "Treat a `Warn` … as a possible tamper event" in the last column by also naming: "Investigate every
    `device.tamper_protected_file_changed` with `reason` `check_suspended` (runbook: agent releases, 'When the
    integrity check is suspended')."
- `docs/operations/agent-releases.md`: the L4 wording (R11), and a new subsection "When the integrity check is
  suspended" after "An update that waits for the active agent": what the event means, the table of R3 (`file` →
  likely cause → what to check as root), and that the finding is resolved after the cause is removed and one drift
  pass ran.
- `docs/architecture.md` §11.5: one sentence after the integrity check's description: "A check that cannot run for
  longer than a fixed bound reports its suspension with the same code and `reason` `check_suspended`."
- `changelog.d/PDK-1122a.security.md`: append one sentence: "If the check cannot run for longer than a fixed bound,
  for example because a state file blocks it, the device reports that with the same code and `reason`
  `check_suspended`, naming the blocking file."
- ADR 0056: amendment of the same date (written with this amendment).

### R14 A baseline reset is reported (main §150; amends C9 "one `Warn` and no event")

Corrupting or deleting `integrity.json` makes the agent rebuild the baseline by trust on first use, and with it a
replaced binary would become the new baseline. A reset is therefore reported once per episode with the existing code
`device.tamper_protected_file_changed`, `file` `/var/lib/paddock/state/integrity.json` and the new `reason` value
`baseline_reset` (constant `protocol.TamperReasonBaselineReset = "baseline_reset"`).

1. **Reset kinds.**
   - `corrupt`: `load` finds a regular `integrity.json` that does not parse as JSON (C9: rename to
     `integrity.json.corrupt`, start an empty baseline). Any loader detects it: `Check` and every writer
     (`SyncFiles`, `SyncFileIfChanged`, `RecordStaged`, `UpdateResult`, `RecordSupervisorPre`, `SupervisorResult`).
   - `missing`: a `Check` pass on a device whose baseline was **established** finds no `current` in `Expected` — the
     file was deleted, or a writer recreated it without the slots. Established means the agent state holds
     `IntegrityEstablishedAt` (new field in `agent/internal/state/state.go`:
     `IntegrityEstablishedAt *time.Time \`json:"integrity_established_at,omitempty"\``). `Check` returns
     `established bool`: true after a successful save of a baseline whose `Expected` holds
     `/opt/paddock/agent/current`; `tickIntegrity` then sets the field once and calls `saveState`. A fresh
     installation and a re-enrollment after an uninstall (which removes `/var/lib/paddock`) are not established and
     initialize silently, as before.
2. **Persistence of the episode.** The loader that detects `corrupt` sets `Baseline.Reset = &Reset{Kind: "corrupt",
   At: now}` (`json:"reset,omitempty"`; `Reset{Kind string \`json:"kind"\`; At time.Time \`json:"at"\`}`) in the
   rebuilt baseline, so the reset survives a writer that runs before the next pass. `Check` sets `Kind: "missing"` the
   same way. Every writer keeps an existing `Reset` unchanged.
3. **Report.** A `Check` pass that loads a baseline with `Reset != nil` initializes the objects by trust on first use
   (as before), emits `{file: "/var/lib/paddock/state/integrity.json", reason: "baseline_reset"}` once and clears
   `Reset` in the same save. The `Warn` of C9 stays.
4. **One per episode.** The episode ends with the first successful save of that `Check` pass (a valid record). A new
   corruption or deletion after that is a new episode and reports again. If the save fails, or `integrity.json`
   cannot be renamed and stays corrupt, the `Checker` keeps the dedup in memory (`resetReported`, set when the event
   is emitted, cleared after a successful save without `Reset`), so later passes of the same process do not repeat
   it; an agent restart while the file stays corrupt and unwritable reports once more (RR-148, like R4.4).
5. **Not covered:** the re-initialization of the slots after an update result without a matching staged release
   (C4) stays a `Warn` without an event, because a rollback to an agent older than PDK-1122a causes it on a regular
   flow. RR-148 keeps naming it.
6. **Audit contract.** The `Description` of R5 MUST instead read exactly: "A device found a protected file changed
   that the agent does not restore itself, e.g. its PAM configuration or one of Paddock's own components (actor: the
   device). reason check_suspended: the agent could not check its own components for longer than a fixed bound, and
   file names the path that blocks the check. reason baseline_reset: the agent's baseline of its own components was
   corrupt or missing and was recorded anew, and file names the baseline file." Additive again: a second value of
   the existing param.
7. **RR-148:** move "corrupt `integrity.json` to force a re-initialization" from "none is detected" to the mitigation:
   "a corrupt or deleted baseline is reported as `baseline_reset`; the binary that becomes the new baseline is not
   judged against the old one". The runbook subsection of R13 gets one row for `baseline_reset`: check the slots
   against the published release hashes (PDK-1122b) and the packages with `dpkg --verify`.
8. **Residual: baseline and agent state reset together (main §150 follow-up, no R15).** `IntegrityEstablishedAt`
   lives in the agent's local `state.json`, which root can edit. Root who removes that field (or deletes `state.json`
   and re-creates its enrollment fields) together with `integrity.json` makes the device look like a first
   installation, and no `baseline_reset` is sent. A server-side anchor was weighed and rejected: the device sends no
   signal of a completed integrity pass today, so the server could only learn of one through a new event, a new
   report field or a new `reason` value on a regular pass, which is a protocol or audit-contract change; a heuristic
   on existing data (agent version, event history) cannot tell a reset from an upgrade of a pre-PDK-1122a agent. Any
   device-side anchor is editable by root (RR-01). RR-148 MUST name this case exactly as: "root resets the integrity
   baseline and the agent state together: the device looks freshly installed and no `baseline_reset` is sent; a
   replaced agent binary is still caught by the Fleet policy `paddock_agent_binary_known` (PDK-1122b), a stopped agent
   by the mutual watch (PDK-1122c), and a silenced fleetd by PDK-1122d."

### Files

| Path | Action | Purpose |
| --- | --- | --- |
| `agent/internal/integrity/integrity.go` | change | R1 order, snapshot, `Pass.Interval`, `Defer`, `Emit(file, reason)` |
| `agent/internal/integrity/baseline.go` | change | R2, R6, R7.1, R8, R10, R11 (`LastStaged`, `current` rule, `load` error) |
| `agent/internal/integrity/packages.go` | change | R1 split, R3 causes, R9 |
| `agent/internal/integrity/suspend.go` | new | R3 table and bounds, R4 tracker |
| `agent/internal/agent/integrity.go` | change | `Pass.Interval`, guarded sync, `Defer`, `integrityRetry` |
| `agent/internal/agent/encrypt.go` | change | R8 at the four sites |
| `agent/internal/agent/updates.go` | change | R7.2/R7.3 in `reportUpdate` and `handleUpdate` |
| `agent/internal/agent/supervisor.go` | change | R10 capture before `Launch`, `SupervisorResult` before the event |
| `agent/internal/agent/agent.go` | change | `Emit` mapping with `Reason` |
| `agent/internal/state/state.go` | change | R14 `IntegrityEstablishedAt` |
| `pkg/protocol/types.go` | change | R5 field, constants of R5 and R14 |
| `server/internal/domain/audit/codes.go` | change | R5 description only |
| `docs/compliance/audit-codes.md` | regenerate | `make gen` |
| tests: `agent/internal/integrity/*_test.go`, `agent/internal/agent/integrity_test.go`, `test/system/{integrity.go,agent_test.go,encrypt_test.go,device.go}` | change | T1–T14, R12 |
| `docs/compliance/residual-risks.md`, `docs/operations/agent-releases.md`, `docs/architecture.md`, `changelog.d/PDK-1122a.security.md` | change | R13 |

MUST NOT be touched: `agent/internal/supervisor/`, `agent/cmd/paddock-supervisor/`, `agent/internal/revoke/`,
`agent/cmd/paddock-revoke/`, `agent/internal/supervisorpkg/` (all files), `agent/internal/update/`, the OpenAPI
files, migrations, any other server file, `docs/adr/` (beyond the ADR 0056 amendment already written).

### Tests (each regression test MUST fail on `9b285ad3` and pass with its fix; the implementer verifies the failure
by running it against the unfixed code, or by `go test -overlay` with the fix reverted, and records it in the result
document)

- **T1 (H1)** `agent` package: hand-edit `disk-setup.json` after the baseline recorded it, send a refused
  `encrypt-abort` request (unknown conversion ID) and a refused `encrypt_disk_abort` command; the next pass reports
  the file exactly once.
- **T2 (R8 guard)** a `Prepare` and a `RunCleanup` that do not write leave a prior hand edit reported; a `Prepare`
  that writes raises no event.
- **T3 (M4 FIFO)** `integrity`: a FIFO at `/etc/paddock/trust.json` and at an `md5sums` path: `Check` returns within
  5 s (test deadline), the FIFO is observed as `!type:p` and reported once; the `md5sums` FIFO activates
  `package:<name>`.
- **T4 (M4 swap)** `hasher` gets an unexported test hook field `afterLstat func(path string)` (nil in production):
  the hook swaps a malicious regular file for the genuine one after the `Lstat`; the cached fingerprint MUST be the
  one of the file that was read, and a second pass with the malicious file back MUST report it.
- **T5 (B1)** a fake `System` whose `Systemctl` blocks until released; while `Check` blocks there, `SyncFiles` from
  another goroutine MUST succeed within `LockWait`; the sync happens after the peek, so after release the pass
  is dropped as `baseline_raced` and emits nothing; the next pass emits nothing for the synced file.
- **T6 (B2)** hold `integrity.lock` from a second open file description during `reportUpdate`: no update event, no
  `ReportedUpdateAt`; after release, the next tick emits the event once; then a second update (`v3`) produces no
  tamper event. Plus: lock held past `StateBound` (injected clock) → the event is sent with one `Warn`.
- **T7 (R7.1)** `SyncFiles` fails (lock held) after `Prepare` wrote the file: no event in the following passes; the
  deferred path is cleared after the first successful save.
- **T8 (M3)** planted stale marker of version `X` and a replaced `/usr/sbin/paddock-supervisor`: after the synthesized
  `install_failed`, no exception is recorded and the next pass reports the binary once. Regular rollback (capture,
  dpkg rewrites `md5sums`, restore by copy, `rolled_back`): no event. Chain: rollback of v2, then capture for v3 and
  rollback of v3: no event.
- **T9 (R3/R4 bounds)** per cause class, with an injected clock and `Pass.Interval = 5 min`: no event at
  `bound − 1 interval`, exactly one at the first pass `≥ bound`, none in later passes, a new one after the cause ended
  and came back; `request.json` present across a 12 h gap between two passes and gone at the third pass → no event;
  restart (new `Checker`, persisted state) continues the count; `integrity.json` made unwritable (read-only
  directory) → one event `{file: /var/lib/paddock/state/integrity.json, reason: check_suspended}` after 15 min.
  Covered causes at minimum: `lock`, `baseline_read`, `baseline_write`, `update_request`, `probation`,
  `update_result` (unparsable), `supervisor_marker`, `staged:<slot>`, `conversion`, `dpkg_lock`, `unit:<unit>`.
- **T10 (regular flows)** a normal update (request, 10 min probation, result), a 2 h conversion and a 2 h dpkg run
  raise no event.
- **T11 (L1)** the production `DpkgBusy` of `integrity.New`: a child process (the test binary re-executed with
  `-test.run=TestHelperHoldDpkgLock` and an env variable) holds `F_SETLK` on `<root>/var/lib/dpkg/lock`; the
  package check is skipped. Same for `lock-frontend`.
- **T12 (L2)** `integrity.json` unreadable with `EISDIR` (a directory): the pass is skipped, the file is not renamed or
  overwritten, `baseline_read` is active.
- **T13 (L3)** `rollback_failed` then `rolled_back` for the same version: no `Warn` "update result without a release",
  no event; crash replay (same result processed twice): no event.
- **T14 (R9)** `splitQuoted` table test: plain, quoted with space, escaped quote, two elements, unterminated → error;
  `checkUnits` with a quoted drop-in reports `file` with the space intact.
- **T15 (R14)** `integrity` and `agent` packages, each case failing on `9b285ad3` (which emits nothing on a reset):
  - corrupt `integrity.json` on an established device → exactly one event `{file:
    /var/lib/paddock/state/integrity.json, reason: baseline_reset}`; five later passes → no further event;
  - after that valid record, corrupt it again → a second event (new episode);
  - corrupt it, then `SyncFiles` runs before the next pass → the next pass still emits the one event;
  - corrupt it with the state directory read-only (rename and save fail) → one event across five passes of the same
    `Checker`;
  - delete `integrity.json` on an established device → one event; a writer recreates it without the slots before
    the pass → one event;
  - fresh device (no `IntegrityEstablishedAt`) without `integrity.json` → no event, and `IntegrityEstablishedAt` is
    set after the first pass that recorded `current`;
  - C4 result without a staged release → no event (unchanged).
- System gates: R12 (no new VM gate).

### Stop conditions

Stop and report to the lead, without working around it, when:

1. A fix needs a line in `agent/internal/supervisor/`, `agent/cmd/paddock-supervisor/` or
   `agent/internal/supervisorpkg/`.
2. Main does not approve R5 (the `reason` value). Fallback then: drop the `reason` field and `codes.go` change,
   emit the suspension with `file` only; everything else stays.
3. `systemctl show` on the VMs prints `DropInPaths` in a format `splitQuoted` does not parse, or the VMs ship
   distribution-wide drop-ins in `DropInPaths`.
4. A system gate reports a `check_suspended` event during a regular flow.
5. Net production lines of PDK-1122a exceed 1450.

### Size

Implemented on `9b285ad3`: 948 net production lines (952 added, 4 removed; Go files outside tests and
`test/system`). This round adds about: R1 +60, R2 +30, R3/R4 (`suspend.go` and the call sites) +110, R6 +5,
R7 +40, R8 +25, R9 +25, R10 +35 (net, `SupervisorRolledBack` replaced), R11 +10, R5 +2, R14 +45 (added under §150)
→ **about +385, about 1335 net production lines in total**, well past the ~900 that §148 names. Tests: about +750. This is reported to main for
transparency; it is not a stop below 1450 (stop condition 5).

### Approvals needed

All three were granted by main under §150 (2026-11-16), together with the order to add R14.


- **Main:** R5, the new value `check_suspended` of the param `reason` on the released code
  `device.tamper_protected_file_changed`, with the description text change (additive audit-contract change).
- **Main:** the size (about 1290 net production lines).
- **Main (default chosen, no stop):** R7.2 lets an unwritable baseline delay staging, supervisor upgrades and update
  results by up to 15 minutes before they proceed with a `Warn`.

### R15 Round 2 (main and user decision §152): close the gaps in code

Input: Review 2 (F1–F3, S1) and External Review 2 (E1–E6, N1, N2) of `70db3ecb`. All items below are code fixes. Where
R15 differs from R3, R4, R7 or R13, R15 wins.

1. **F1: writers return read errors.**
   - `UpdateResult` returns the wrapped error of `h.slots` instead of `nil`.
   - `observeSupervisor` returns the first hash error, so `RecordSupervisorPre` and `SupervisorResult` fail.
   - `SyncFiles` applies every file it could hash and then returns an error naming the files it could not hash.
   - The callers already apply R7.1 (`Defer` the failed paths) and R7.2 (`integrityRetry`).
   - `SyncFileIfChanged` reports `changed = true` together with such an error.
2. **E1 / N1: one episode per blocked object, not per cause.** The episode key of R4 becomes the **object** of this
   closed table. `file` is the path of the first active blocker, in the order of the column.

   | Object key | Blockers in order (each with its R3 `file`) | Bound |
   | --- | --- | --- |
   | `baseline` | `lock`, `baseline_read`, `baseline_write`, `baseline_raced` | `StateBound` 15 min |
   | `slots` | `update_request`, `probation`, `update_result`, `staged:<path>`, read error of a slot or `current` | `FlowBound` 6 h |
   | `package:<name>`, one per package of C5 | for `paddock-supervisor` only: `supervisor_marker`, `supervisor_result`; then for every package: `dpkg_lock`, the `package:<name>` errors of R3, a hash error of one of its files | `FlowBound` |
   | `file:<path>`, one per agent-written file and `/usr/bin/paddockd` | `conversion` (`disk-setup.json` only), then its read error | `FlowBound` |
   | `unit:<unit>`, one per unit of C6 | `systemctl show` failed or did not parse, a hash error of a foreign unit file | `FlowBound` |

   An object is blocked in a pass when at least one of its blockers is active. Its episode accumulates while it is
   blocked, whichever blocker is active, and ends only as described in point 4. Changing between blockers therefore
   never restarts the bound.
3. **E2 / N2: the suspension state lives in the agent state, not in `integrity.json`.**
   - New type and field in `agent/internal/state/state.go`:
     - `IntegritySuspension{File string; Observed int64 (json "observed_s"); Last time.Time; Reported bool}`;
     - `State.IntegritySuspended map[string]IntegritySuspension` (`json:"integrity_suspended,omitempty"`).
   - In `agent/internal/integrity`, `Suspension` becomes an alias of `state.IntegritySuspension`.
   - The field `Baseline.Suspended` is removed. An old file that still holds it parses, because the unknown key is
     ignored.
   - `Checker` takes the map from `Pass.Suspended` at its first `Check` of the process. `Check` returns
     `Result{Established bool; Suspended map[string]state.IntegritySuspension; SuspendedChanged bool}`.
   - `tickIntegrity` stores `Suspended` in `a.st` and calls `saveState` when `SuspendedChanged` is true.
   - A held lock or an unwritable `integrity.json` therefore no longer stops the bound from advancing, and an agent
     restart continues it. `adopt` and `persisted` are deleted.
   - Root who edits `state.json` resets the bounds. This is the same residual as R14.8, and RR-148 names it there.
4. **F2 / S1: one `track` call per pass.**
   - `Check` collects the active blockers of the pass (from `observe`, from `classify`, and the state blocker at
     which the pass ended) and calls `track` once.
   - An episode ends only in a pass that classified and saved, and in which its object had no active blocker.
   - A pass that ended at `lock`, `baseline_read`, `baseline_write` or `baseline_raced` ends no episode and starts
     only `baseline`. Every other existing episode continues to accumulate, because in that pass no object was
     judged.
5. **E3: the check has its own ticker, a cap and a pass at start.**
   - New constant `integrity.MaxInterval = 1 * time.Hour` and function
     `func Interval(drift time.Duration) time.Duration` returning `min(drift, MaxInterval)`.
   - `Agent.loop` gets its own ticker, `integrityTick`, with `integrity.Interval(a.d.Config.DriftInterval)`, and a
     one-shot timer of 0 so that a pass runs at loop start. `tickIntegrity` moves from the `drift.C` case to these two
     cases.
   - When the cap applies, the agent logs one `Warn` at start, with the configured and the used interval.
   - `Pass.Interval` is the used interval. The gap cap of R4.2 is therefore at most 2 h, and `FlowBound` needs at
     least three passes.
   - `drift_interval_s` itself and its validation do not change.
6. **E5 and N3: the staged guard applies only to a changed value.**
   - A slot is skipped only when `v != Expected[slot] && v == Staged.SHA256`.
   - `current` is skipped only when `v != Expected[current]` and the slot it points to holds `Staged.SHA256`.
   - An unchanged value is judged normally, so a stale `Staged` creates no blocker.
7. **E6: `peekGeneration` returns 0 when the content does not unmarshal into `Baseline`.** A corrupt file that still
   carries a `generation` is therefore rebuilt and reported as `baseline_reset` (R14), not dropped as raced.
8. **E4, F3 and the merged finding: runbook** (`docs/operations/agent-releases.md`, "When the integrity check is
   suspended").
   - Row for `/var/lib/dpkg/lock-frontend` and `/var/lib/dpkg/lock`: "Likely an apt or dpkg prompt left open in a
     terminal (users have administrator rights), or a long package run; finish or cancel it."
   - Closing sentence: "Close the tamper finding by hand once the cause is removed and an integrity pass ran without
     a new report."
   - Add: "A suspension of a path the check also judges (a slot, `current`, an agent-written file) counts on the same
     tamper finding as a change of that path; the audit event's `reason` tells them apart."
9. **Bound wording, binding for RR-148, the ADR 0056 amendment, the runbook and R3.** Each of these texts MUST say:
   - the bound holds **per blocked object**, in observed time while the agent runs;
   - a gap between passes counts at most twice the check's interval, and that interval is at most 1 h;
   - a pass runs at every agent start;
   - the bound survives agent restarts and an unwritable or locked baseline;
   - root who edits the agent state resets it (R14.8).

   Remove every claim that "a restart restarts the bound" for suspensions. The R14.4 sentence about `baseline_reset`
   after a restart stays, because its dedup is still memory-only.

   In R3, the dpkg row's "longest regular duration" becomes "one apt run; a prompt left open holds it indefinitely
   and is reported after 6 h (expected, runbook)".

   I write the ADR text in the same commit as this item. The implementer changes RR-148, the runbook and the
   architecture sentence of R13 where they contradict this.

**Regression tests.** Each MUST fail on `70db3ecb`, and the result document records the failing run.
- **T16 (E1):**
  - trojan in slot B, `probation.json` and `request.json` planted alternately every 5 h over 3 days (injected
    clock, interval 5 min): exactly one `check_suspended` for object `slots` once the observed time reaches 6 h;
  - the same with `dpkg_lock` alternating with a FIFO at `md5sums`, for `package:paddock-agent`;
  - the same with `supervisor_marker` alternating with an unparsable `supervisor-upgrade-result.json`, for
    `package:paddock-supervisor`.
- **T17 (E2):**
  - `integrity.lock` held by a second open file description, `probation.json` planted, and a new `Checker` every
    10 min, seeded from the previous `Result.Suspended`: `baseline` reports after 15 min and `slots` after 6 h;
  - an agent-level test that `IntegritySuspended` is saved to and loaded from `state.json`.
- **T18 (E3):**
  - `Interval(365 * 24 * time.Hour)` is 1 h, and the agent logs the clamp `Warn`;
  - an agent test with `DriftInterval` of 1 h sees a pass before any tick, so it ran at start.
- **T19 (E5):** `Staged` equals the hash already in the inactive slot, and staging keeps failing for 7 h: no event.
- **T20 (E6):** `{"generation":7,"expected":1}` with the state directory read-only: exactly one `baseline_reset`,
  and no `baseline_raced`.
- **T21 (F1):** one test per hook, each with a file made unreadable for exactly one call (`chmod 000` as non-root;
  skip as root):
  - `UpdateResult`: no event, `ReportedUpdateAt` unchanged, the next tick processes the result, and no
    `check_suspended` follows;
  - `RecordSupervisorPre` / `SupervisorResult`: a regular rollback raises no tamper event;
  - `SyncFiles`: the path is deferred, and no event follows.
- **F2:** covered by T17, where `staged:` blockers survive a lock-held pass.

**Size.** F1 +6, E3 +15, E6 +2, E5 ±0, E1/N1 (object table replaces cause keys) −5, E2/N2 (state type and `Result`
+18, `adopt`/`persisted`/`Baseline.Suspended` −30) −12, S1/F2 −10 → **about −4 net, flat**. The total stays about
1335, and the stop stays at 1450.

**Stop conditions (in addition to the earlier ones).**
1. Moving the suspension state into `state.json` collides with another writer of the agent state outside the loop
   goroutine.
2. The pass at loop start raises an event on a regular boot in a VM gate.

The remaining simplifications (S2–S9, N4, N5) are the alpha.12 stub PDK-1122g. They are not part of this round.

### R16 (PDK-1122j): update results keep the slot baseline

Processing an update result no longer adopts what `current` points at or what the slots hold. Each release this agent
staged settles at most once, and only a result that matches it can move the baseline.

**Persisted state (`integrity.json`).** `Staged` (version, sha256) stays as is. `LastStaged` and `RollbackPending` are
replaced by one record `LastResult *AppliedResult` with the fields `version` (string), `sha256` (string, the staged hash),
`at` (time, the `at` of the result), `outcome` (string) and `rollback_pending` (bool, `omitempty`). All fields are
`omitempty` additions to the baseline, so an older agent still reads it.

**Signature.** `integrity.UpdateResult(l paths.Layout, version, outcome string, at time.Time) (unstaged bool, err error)`.
The rules apply in this order; the first that matches decides.
1. No record of the slots (`Expected[current]` absent): nothing changes, `unstaged` is false, no event. This covers a
   device whose agent never recorded a staged release (update from a release without the check). On an established
   device the next pass reports the missing record as `baseline_reset` (R14), so this is not silent.
2. Replay: `LastResult` has the same `version`, `outcome` and `at`: nothing changes, `unstaged` is false. This is the
   repeat after a crash between the baseline and the state file.
3. Staged: `Staged` is set and its version equals `version`. The slot whose observed hash equals the staged hash is
   taken. `current` moves only on `updated` or `rollback_failed`, and only to that slot. `Staged` is cleared and
   `LastResult` is set with `rollback_pending` true only for `rollback_failed`; any earlier `LastResult` is replaced.
4. Completed rollback: `outcome` is `rolled_back`, `LastResult.rollback_pending` is true and `LastResult.version` equals
   `version`. `current` moves to the other slot only if that slot is unchanged against the baseline and the observed
   `current` slot is not the staged slot. `LastResult` is replaced with this result and `rollback_pending` false.
5. Anything else is unstaged: the whole baseline is kept, `Staged` and `LastResult` stay unchanged, `unstaged` is true.
   The caller emits `device.tamper_protected_file_changed` (`TamperProtectedFileChanged`) once per result `at`, with
   reason `update_result_unstaged` (`protocol.TamperReasonUpdateResultUnstaged`, next to `check_suspended` and
   `baseline_reset`) and `File` `integrity.UpdateResultFile`. The audit code description names the reason.

Every other outcome keeps `Expected[current]`, so the next quiescent pass reports a deviation. A result for a settled
release (second `updated`, `rollback_failed` or `rolled_back` with a new `at`) is unstaged. `RecordStaged` clears
`LastResult`. Residual, accepted: while a release is staged and not yet settled, one result for it can take effect, and
after a genuine `rollback_failed` one `rolled_back` can move `current` once to the other slot's genuine binary (R11 L3).
RR-148 states both and does not claim that rewritten results go undetected beyond what this rule detects. The comment at
`agent/internal/agent/updates.go:117` is updated to this rule.

**Gate.** The system gate retracts the releases of S4 in a shared step before S5 and then waits for two conditions, polling
with the existing helpers and without a fixed sleep: first a check-in of each VM carries no offer (the offer stays cached
for up to one rollout round of 60 s), then the device is quiet (no `request.json`, no `probation.json`, the last update
result processed) before S5 flips.

**Tests** (each fails without its rule; the first three fail on `a40549bd`).
- `updated` then a forged `rollback_failed`, a flip of `current` and a forged `rolled_back`: reported.
- `rolled_back`, a flip and a forged `updated`: reported. `self_test_failed`, a flip and a forged `rollback_failed`: reported.
- Repeating `rollback_failed`, `rolled_back` and `updated` for one version in several rounds (toggle): every round after
  the first reports, and no baseline move is silent.
- A genuine `rollback_failed` then `rolled_back` and a regular `updated`: no event.
- A first result without any baseline record (update from a release without the check): no event.
- A replay with the same `at`: no event; the same result with a different `at` after settlement: the event.

## Amendment 2026-11-16 d (architect, PDK-1122d) — osquery that stops evaluating, a failing agent-running query, and the speaking host

Status: **accepted** as reduced (2026-11-17, main, `decisions-alpha11.md` §159).
- Extends amendment c. Where the two differ, this amendment wins.
- ADR 0056 records the decision in its amendment "d" of the same date.
- Ticket PDK-1122d, risk high. Implementation starts after PDK-1123 (amendment 2026-11-17 e) is merged.
- The claim report, the hold and the binding of an earlier draft of this amendment moved to amendment e (PDK-1123).

### 1. Goal

1. Amendment c judges a device by its **speaking host** (amendment e, section 3, "Terms"), not by the newest of all
   hosts with its hardware UUID.
2. An osquery that stops storing policy results while orbit keeps talking to Fleet is reported as a silent fleetd
   (`reason` `policies`).
3. A `paddock_agent_running` query that stops answering counts as a failing evaluation.

Report only; no device API, admin API, agent or bundle change.

### 2. Context

- **Review of PDK-1122c, finding L1.**
  - (L1-A) A `paddock_agent_running` query that fails on the device (the `processes` table disabled, or the query on
    the watchdog denylist) yields `""`. The row is deleted every round (`DeleteMissingPolicyResults`), and rule (b)
    never fires.
  - (L1-B) An `osqueryd` stopped with SIGSTOP while orbit runs stops Fleet's `policy_updated_at`. If orbit's requests
    keep `seen_time` fresh, neither rule (b) nor amendment c fires.
- **Amendment c's E1** uses "the newest `seen_time` of the hosts whose hardware UUID equals the device's". After
  amendment e, only the speaking host's data counts for a device. The same must hold for its silence.
- **From amendment e:** `ports.HostSeen` (`Ref`, `HardwareUUID`, `SeenAt`, `EnrolledAt`), `HostPage.Seen`,
  `inventory.Targets` and the round order (bindings → store → claim watch → agent reports).

### 3. Binding decisions

**D-c1 Changes to amendment c.**

1. Migration: `server/migrations/paddock/00164_fleet_silence_watch.sql` (amendment e takes `00163`). Its content is
   amendment c's section 6. In addition, `paddock_fleet_watch_devices` returns `i.policy_updated_at` after
   `last_seen_at` (for F5).
2. E1: `seen(d)` is the `seen_time` of the device's speaking host, from amendment e's `Targets`: the bound host, or
   else the first-enrolled host of its UUID. A device whose speaking host is not listed uses the stored
   `device_inventory_ref.last_seen_at`, as amendment c's host-deleted branch does.
3. `ports.HostSeen` gains `PolicyUpdatedAt *time.Time` (nil when the host never stored policy results). The Fleet
   adapter fills it in `Seen`. Amendment c's own `Seen` adapter work is already done by amendment e.
4. `inventory.WatchFleet` gains the parameter `t inventory.Targets`. Its signature becomes
   `WatchFleet(devices []WatchedDevice, seen []ports.HostSeen, t Targets, now time.Time, live time.Duration) FleetWatch`.
5. The silence watch runs in the round directly after amendment e's claim watch, before `reportAgents`.
6. Amendment c's gauge `paddock_inventory_fleet_silent_suppressed`, alert `PaddockFleetSilenceWatchSuppressed` and
   runbook subsection keep their names. The claim watch has its own gauge and alert (amendment e, H9).
7. Amendment c's `TestWatchFleet` row "duplicate hosts of one UUID: the newest `seen` counts" is replaced by: "a
   speaking host 20 min stale and another claimant fresh, live, `since = now - 15m` → reported with `reason
   contact`" (regression).

**F5 Osquery that stops evaluating: a second reason for `device.tamper_fleetd_silent`.** Extend E1:

- `P` = the newest `policy_updated_at` of any listed host (Fleet's clock).
- **policy-stale(d)**: the speaking host's `PolicyUpdatedAt` is set and older than `P - PolicySilence`. If the
  speaking host is not listed, the stored `device_inventory_ref.policy_updated_at` is used.
  `PolicySilence = 30 min`, three times Fleet's default policy interval of 10 min.
- **contact-stale(d)** is amendment c's `stale(d)`.
- **stale(d)** = contact-stale(d) OR policy-stale(d). Amendment c's E2 state machine, E3 guards and E4 rows apply
  unchanged to this `stale(d)`. A device counts as `Fresh` in E3 only if it is neither contact-stale nor
  policy-stale.
- Param `reason` = `contact` if contact-stale, else `policies`.
- Comparing with `P`, not with the host's own `seen_time`, keeps a Fleet-wide stall of policy evaluation from looking
  like a device fault: the same argument as E1's `R`.
- A NULL `policy_updated_at` (a host that never stored results) is not policy-stale.

**F6 Unanswered agent-running query: counted as failing.** In `Round`, before `StoreHost`, the worker moves
`paddock_agent_running` from `UnansweredPolicies` to `Policies` as `{Passing: false}` when the host's
`PolicyUpdatedAt` is at least `binaryEvaluationLag` after this process first applied the policy definition. That is
the gate `countUnanswered` already uses.

- Only this key qualifies: D7 keeps its query text constant, so after the first evaluation an empty answer means that
  the query failed. The binary policy and `disk_encrypted` keep amendment A7.
- Rule (b)'s 15 minutes of continuous failure absorb a single empty answer: a policy just recreated after a Fleet
  reset, or a partial batch (L2).
- The gauge `paddock_inventory_policy_unanswered_hosts` keeps counting these hosts.
- Option not chosen: a separate signal or code. The event says what an operator needs to know (fleetd cannot confirm
  the agent), and the description names the cause.

**F7 Codes.**

- `device.tamper_fleetd_silent` (amendment c, not released):
  - Params become `fleetd_seen_at`, `policy_updated_at`, `last_contact_at`, `silent_since`, `reason`.
  - Description: "fleetd on a device stopped working with the inventory system for at least 15 minutes while the
    device kept checking in with Paddock, confirmed for 15 more minutes while most other devices reached the
    inventory system (actor: system). reason contact: the inventory system has not heard from the device's fleetd for
    15 minutes longer than from the most recent host; reason policies: fleetd still talks to it, but osquery has
    stored no policy results for 30 minutes longer than the most recent host (osquery stopped, frozen or broken while
    orbit runs). fleetd was stopped, frozen, removed or cut off from the inventory system's address only, or
    something other than the genuine agent checks in for the device. fleetd_seen_at and policy_updated_at are the
    device's last contact and last stored policy results in the inventory system's clock (absent when unknown);
    last_contact_at is the device's last check-in; silent_since is when the worker first found the silence."
  - Messages: EN "fleetd on {target} no longer works with the inventory system while the device keeps checking in";
    DE "fleetd auf {target} arbeitet nicht mehr mit dem Inventarsystem, während sich das Gerät weiter meldet".
- `device.tamper_agent_not_running` (released): the description gains, after "…while the device may have kept
  checking in", the text ", or its query stopped answering on a host that evaluates its policies". Params, messages,
  MSGID and finding are unchanged. This is additive, like amendment b's D6.

**F8 Contract.** Device API, admin API, agent, supervisor and bundle are unchanged. Audit event contract: the param
and description change of an unreleased code, and an additive description change of a released code. Database: one
migration, `00164`.

### 4. Non-goals

- Everything amendment e covers: binding, claims, hold, wave guard of claims, Fleet configuration.
- No change to `agent/` (in particular `agent/internal/revoke/`), the supervisor, `pkg/` or `api/openapi/*.yaml`.
- No change to the policy SQL files, the Fleet settings, or the attention function.

### 5. Files

Amendment c's table applies, with these changes:

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/00164_fleet_silence_watch.sql` | new (replaces c's `00163_…`) | D-c1 (1) |
| `server/internal/ports/inventory.go` | change | `HostSeen.PolicyUpdatedAt` |
| `server/internal/adapters/fleet/hosts.go`, `hosts_test.go` | change | `PolicyUpdatedAt` in `Seen` |
| `server/internal/inventory/fleetwatch.go`, `fleetwatch_test.go` | new (as c) | D-c1, F5 |
| `server/internal/inventory/inventory.go`, `inventory_test.go` | change | `UnansweredAgentRunningAsFailing` (F6) |
| `server/internal/worker/inventory.go`, `inventory_test.go` | change | c's step after the claim watch, F6 rewrite |
| `server/internal/domain/audit/codes.go` + `make gen` outputs | change | F7 |
| `server/web/src/locales/en.json`, `de.json` | change | F7 messages |
| `test/acceptance/devicesim/fleet.go`, `fleet_test.go` | change | `AgentRunningQueryFails` |
| `test/acceptance/inventory_test.go` | change | section 8 |
| `test/system/inventory_test.go` | change | c's F7 with the extension below, probes |

### 6. Interfaces and texts

```go
// server/internal/inventory/fleetwatch.go (amendment c), additionally
const PolicySilence = 30 * time.Minute // F5
// WatchedDevice gains PolicyUpdatedAt *time.Time; SilentDevice gains PolicyUpdatedAt *time.Time and Reason string
// ("contact" | "policies").

// server/internal/inventory/inventory.go
// UnansweredAgentRunningAsFailing returns inv with PolicyAgentRunning moved from UnansweredPolicies to Policies as
// failing when gateOpen; otherwise inv unchanged (F6).
func UnansweredAgentRunningAsFailing(inv ports.HostInventory, gateOpen bool) ports.HostInventory
```

Texts (applied after amendment c's texts and amendment e's):

- **RR-149**, not-reported list: replace the item that begins "a `paddock_agent_running` query made to fail on the
  device" and ends "(both follow-up PDK-1122d);" with "a `paddock_agent_running` query that never answered on the
  device since the server last started (an answer that stops later counts as failing, plan M5a amendment 2026-11-16
  d);". Before "Not reported:", add: "An `osqueryd` that stops storing policy results while orbit runs is reported as
  `device.tamper_fleetd_silent` with reason `policies` (amendment d)."
- **`docs/architecture.md` §11.5**: amendment c's row, third column: "`device.tamper_fleetd_silent` after 15 min of
  silence (no contact, or no stored policy results for 30 min) confirmed for 15 more min".
- **`docs/operations/fleet.md`**: the interval paragraph gains "Keep `FLEET_OSQUERY_POLICY_UPDATE_INTERVAL` at 15
  minutes or less: the worker reports a device whose policy results are 30 minutes older than the newest host's."
- **Changelog** `changelog.d/PDK-1122d.security.md`, after amendment c's text: "A frozen osquery and an agent check
  that stops answering are reported too."

### 7. Steps

Amendment c's steps, with these changes:
- Step 1 uses migration `00164`.
- After step 2: `go test ./server/internal/inventory/ -run 'TestWatchFleet|TestUnansweredAgentRunning'`.
- The worker step places the silence watch after amendment e's claim watch.
- The system step runs F7 with the extension and the probes below.

### 8. Tests

Amendment c's tests apply, with D-c1 (7). "Regression" tests MUST fail without the change.

- **Unit `TestWatchFleet`**, new rows:
  - D-c1 (7);
  - **policies**: speaking host fresh, `policy_updated_at = P - 31m`, live, confirmed → `reason policies`;
    `P - 29m` → not stale (boundary); NULL → not stale; a Fleet-wide stall (every host at `P - 40m`) → nothing.
- **Unit `TestUnansweredAgentRunningAsFailing`**: gate open → moved as failing; gate closed → unchanged; the binary and
  `disk_encrypted` keys are never moved.
- **Adapter**: `TestListHostsSeen` gains `policy_updated_at`.
- **Worker `TestInventoryRoundAgentRunningQueryFails`** (regression L1-A): `paddock_agent_running` is unanswered with
  `policy_updated_at` advancing 10 min per round past the gate, and the device checks in → one
  `device.tamper_agent_not_running` after the third round.
- **devicesim** `TestFleetHostAgentRunningQueryFails`: the agent-running query gets status 1 and no rows; other queries
  are answered as before.
- **Acceptance `TestInventoryAgentRunningQueryFails`**: a device whose host first passes, then sets
  `AgentRunningQueryFails`. Wait until the stored row is failing with `failing_since`, then seed it 16 minutes back.
  Wait until alice sees `device.tamper_agent_not_running`.
- **System, extension of c's F7** (while orbit is stopped):
  1. After step 2, the harness enrolls `EnrollFleetAs(identifier "pdk-f7-second"+suffix, uuid = the VM's UUID)`,
     which passes every policy, and answers every 30 s in a goroutine stopped by `t.Cleanup`.
  2. Step 3's `device.tamper_fleetd_silent` MUST still come, with `reason` `contact` (regression D-c1).
  3. Before step 4 of c, stop that host and delete it through Fleet's API. Amendment e's claim event for it is
     expected: per VM, `device.tamper_fleet_host_claimed` count +1.
- **System probes** (recorded in the result document, not gates):
  - **F7c**: `kill -STOP` every `osqueryd` (`pgrep -x osqueryd`) for 4 minutes, reading the host's `seen_time` and
    `policy_updated_at` at the start and the end, then `kill -CONT` (also in `t.Cleanup`). The probe answers whether
    orbit keeps `seen_time` fresh.
  - **Enrollment stability**: the VM host's `last_enrolled_at` at the start and the end of `TestInventoryGates`.

### 9. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC-d1 | Given a device whose fleetd is stopped while another host with its UUID stays fresh, then `device.tamper_fleetd_silent` is still reported (F7 extension) | D-c1 | Org admin |
| AC-d2 | Given an osquery that stores no policy results for 30 min longer than the newest host while fleetd is otherwise fresh, then `device.tamper_fleetd_silent` with `reason` `policies` (worker tests) | F5 | Org admin |
| AC-d3 | Given a `paddock_agent_running` query that stops answering while the device checks in, then `device.tamper_agent_not_running` after evaluations 15 min apart | F6 | Org admin |
| AC-d4 | Device API, admin API and agent unchanged | ADR 0047 | Maintainer (diff, CI `upgrade`) |

### 10. Freedoms

Amendment c's freedoms; and whether F5 shares a helper with E1.

### 11. Stop conditions

Amendment c's stop conditions, plus:

- The enrollment-stability probe shows a change across F1–F7.
- An existing acceptance or system gate starts recording `device.tamper_agent_not_running` through F6.
- The change would need an agent, supervisor, `pkg/`, device API or admin API change, or a new dependency.
- The production size exceeds about 480 lines.

### 12. Risks

- **`FLEET_OSQUERY_POLICY_UPDATE_INTERVAL` above 15 min** raises `reason policies` falsely; documented in fleet.md.
- **The F7c probe shows that orbit does not keep `seen_time` fresh** while osquery is frozen: then a frozen osquery
  is already contact-stale, and F5 is a second path to the same report. No change needed.

### 13. Size (estimate)

Amendment c's estimate was about 360 production and 1015 test lines. With D-c1 (amendment e already builds the
`Seen` adapter: about −25), F5 (~40), F6 (~25) and D-c1's other changes (~10):

| Part | Lines |
| --- | --- |
| Production, hand-written | about 410 |
| Generated | about 70 |
| Tests (c's ~1015 plus unit ~70, worker ~60, devicesim ~20, acceptance ~60, system ~40) | about 1265 |
| Docs by the implementer | about 70 |

## Amendment 2026-11-17 e (architect, PDK-1123) — inventory hosts bound to their device

Status: **accepted** (2026-11-17, main, `decisions-alpha11.md` §159, with the conditions of H13 and H14). ADR 0057
records the decision.
Ticket PDK-1123, risk high, release blocker for 0.1.0-alpha.11.
- Lands **before** PDK-1122d (amendments c and d). Amendment d lists what PDK-1122d changes on top of it.
- Builds on PDK-1122b (agent binary policy, migration 00161) and PDK-1122c (amendment b, migration 00162), both
  merged into the integration branch.

### 1. Goal

1. Each device names its inventory host over its signed device connection. From then on, the worker stores only that
   host's inventory, vulnerability findings, hardware facts and policy results for the device.
2. Until a device has named its host (agents before 0.1.0-alpha.11, devices without fleetd), only the host that Fleet
   enrolled first for the device's hardware UUID is stored.
3. The organization admin sees `device.tamper_fleet_host_claimed` when another inventory host claims a device or the
   device's host is enrolled again. Agent reports that the inventory system derives wait 60 minutes after a
   re-enrollment.
4. A second device with the same hardware UUID no longer stops a bound device's inventory.

### 2. Context

- **Mapping today.** The worker (`server/internal/worker/inventory.go`, `Inventory.Round`) lists Fleet's hosts in
  pages ordered by ID (`fleet.Client.ListHostsChangedSince`, `order_key=id`). It maps each changed host through its
  hardware UUID (`app.InventorySync.MapHosts` → `paddock_inventory_devices`, migration 00024: a UUID maps only if
  exactly one active or quarantined device has it). It stores every mapped host with `StoreHost`
  (`UpsertInventoryRef … ON CONFLICT (device_id) DO UPDATE`).
- **Fleet identity today.** `deploy/compose/compose.yaml` sets `FLEET_OSQUERY_HOST_IDENTIFIER: uuid`. The agent
  writes `/etc/paddock/orbit.env` (`agent/internal/reconcile/inventory.go`, `fleetdFiles`) without
  `ORBIT_HOST_IDENTIFIER`, so orbit uses its default `uuid`.
- **What Fleet free offers** (sources at tag `fleet-v4.94.1`; details in ADR 0057, Context):
  - `ORBIT_HOST_IDENTIFIER=instance`: orbit and osquery enroll under osquery's per-installation `instance_id`.
  - `osquery.host_identifier=provided`: an osquery enrollment uses the identifier osquery sends. orbit's enrollment
    always uses the identifier orbit sends.
  - orbit keeps a device token (a random UUID, lower case) in `/opt/orbit/identifier`, mode 0644. It registers the
    token for its own host (`POST /api/fleet/orbit/device_token`, authenticated by orbit's node key) and rotates it
    when it is one hour old.
  - `GET /api/latest/fleet/device/{token}` answers `{"host": {"id": …, "uuid": …, …}}` for a token registered within
    the last hour (`token = ? OR previous_token = ?` and `updated_at` within the TTL), and 401 otherwise. Device
    endpoints ban an IP address only after 1000 consecutive failures within one minute.
  - Fleet's host list carries `last_enrolled_at` and `seen_time`. An enrollment that matches an existing host keeps its
    ID and sets `last_enrolled_at = NOW()` (`EnrollOsquery`, `server/datastore/mysql/hosts.go`).
  - Teams and team enroll secrets need Fleet Premium. One-time enroll secrets exist only for Apple and Windows MDM.
- **Device API.** `pkg/protocol.CheckinRequest`; the gateway (`server/internal/transport/http/device/handlers.go`,
  `checkin`) publishes an `ingest.Heartbeat`. The worker's `Reports.heartbeat` (`server/internal/worker/reports.go`)
  coalesces heartbeats per device and `devicecache.HeartbeatInterval` (60 s) before `DeviceReports.RecordStatus`. The
  gateway ignores unknown request fields; an additive field is compatible in both directions (ADR 0047).
- **ADRs:** 0009 (no Fleet Premium features), 0041 (hostname; context statement on `--host_identifier=uuid`), 0047
  (upgrade guarantee), 0056 (integrity checks; amendments b and c accepted, amendment d proposed and reduced to
  PDK-1122d), **0057 (this design, proposed)**.

### 3. Binding decisions

**Terms** (used with exactly this meaning in this amendment, the code and the tests):

- **device token**: the content of `/opt/orbit/identifier`, a lower-case UUID.
- **binding**: a `device_fleet_binding` row whose `host_id` is set. A device with a binding is **bound**; its
  `host_id` is its **bound host**.
- **listed hosts**: every host of Fleet's host list that has a hardware UUID, from all pages of this round, in list
  order (ascending Fleet ID). `R` = the newest `seen_time` of any listed host (Fleet's clock).
- **first-enrolled host** of a hardware UUID: the first listed host with that lower-case UUID, among the listed hosts
  that are not bound to any device.
- **speaking host** of a device: its bound host if the device is bound, otherwise the first-enrolled host of its
  hardware UUID. `binding` mode `device` or `first` respectively.
- **claimant** of a device: a listed host whose lower-case hardware UUID equals the device's. A **live other
  claimant** is a claimant that is not the speaking host, with a non-zero `seen_time` and `R - seen_time <
  HostClaimLive` (10 min).

**H1 Fleet identifies hosts by the identifier that fleetd provides.**

- `deploy/compose/compose.yaml`: `FLEET_OSQUERY_HOST_IDENTIFIER: provided`. The comment above it becomes:
  "Hosts enroll under the identifier fleetd provides, osquery's per-installation instance ID (ADR 0057); Paddock maps
  hosts to devices through the binding the device reports."
- Why `provided` and not `instance`: orbit's enrollment always uses orbit's own identifier. With `instance` on the
  server, a device whose orbit still uses `uuid` gets two hosts. With `provided`, both settings of the device side stay
  on one host.

**H2 fleetd enrolls under its instance ID; the switch re-enrolls a device once.**

- `fleetdFiles` adds the line `ORBIT_HOST_IDENTIFIER=instance` to `orbit.env`, directly after
  `ORBIT_FLEET_DESKTOP=false`. The rendered file is then exactly:
  ```
  # Managed by Paddock. Do not edit: local changes are reverted.
  ORBIT_FLEET_URL=<fleet_url>
  ORBIT_ENROLL_SECRET_PATH=/opt/orbit/secret.txt
  ORBIT_FLEET_CERTIFICATE=/etc/ssl/certs/ca-certificates.crt
  ORBIT_DISABLE_UPDATES=true
  ORBIT_ENABLE_SCRIPTS=false
  ORBIT_FLEET_DESKTOP=false
  ORBIT_HOST_IDENTIFIER=instance
  ```
- **One-time enrollment reset.** In `Inventory.writeFiles`, before it writes `FleetdEnv`, the reconciler resets
  fleetd's enrollment when all of these hold:
  - the package `fleet-osquery` is installed;
  - `FleetdEnv` exists as a regular file;
  - its content has no line equal to `ORBIT_HOST_IDENTIFIER=instance`.
  The reset runs `systemctl stop orbit.service` and then removes `/opt/orbit/secret-orbit-node-key.txt`,
  `/opt/orbit/identifier` and the directory `/opt/orbit/osquery.db`, with its content. A path that does not exist is
  not an error. `writeFiles` then writes the files and restarts `orbit.service`, as it already does.
  - Why: orbit and osquery keep their existing node keys after a configuration change, so the host would keep its old
    identity. orbit does the same reset itself when it detects a hardware change (`orbit.go`, "detected hardware
    migration").
  - A fresh device (no `orbit.env`) and a device without fleetd need no reset: fleetd enrolls with the new
    configuration from the start.
- The reset emits no event of its own. A changed `orbit.env` while the same spec is applied is still reported as
  `tamper.protected_file_changed`, as today.
- `reconcile.System` gains `RemoveAll(path string) error` (`os.RemoveAll` below the root, like `Remove`).
  `agent/internal/reconcile/fakesys` implements it.
- New constants in `agent/internal/reconcile/inventory.go`:
  - `FleetdDeviceTokenFile = "/opt/orbit/identifier"`;
  - `fleetdOrbitNodeKey = "/opt/orbit/secret-orbit-node-key.txt"`;
  - `fleetdOsqueryDB = "/opt/orbit/osquery.db"`;
  - `fleetdHostIdentifierLine = "ORBIT_HOST_IDENTIFIER=instance"`.

**H3 The agent reports its device token over the device API.**

- `protocol.CheckinRequest` gains
  ``FleetDeviceToken string `json:"fleet_device_token,omitempty"` ``.
- `Agent.checkinRequest` reads `reconcile.FleetdDeviceTokenFile` through `a.d.Sys` (nil `Sys`: none) and trims ASCII
  whitespace. It sends the value when all of these hold:
  - it matches `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`;
  - it differs from `a.fleetTokenSent`, the token of the last check-in that returned HTTP 200.
  Otherwise the field stays empty.
- After a check-in returns HTTP 200, `a.fleetTokenSent` becomes the token that check-in carried, if it carried one.
  `fleetTokenSent` lives in memory only: after an agent restart, the token is sent once more.
- The token is never logged, never written to the agent's state, and never put into the health report.

**H4 Gateway and ingest record the token before heartbeat coalescing.**

- `ingest.Heartbeat` gains ``FleetDeviceToken string `json:"fleet_device_token,omitempty"` ``.
- The gateway sets it to `req.FleetDeviceToken` if that matches the regular expression of H3, and to `""` otherwise.
  An invalid value never fails the check-in.
- `Reports.heartbeat` calls `DeviceReports.RecordFleetDeviceToken` after `MarkDelivered` and before `ClaimHeartbeat`,
  only for a non-empty token, with `MarkDelivered`'s outcome handling: an unavailable organization is acked, any other
  error is retried. A coalesced heartbeat therefore never loses a token.
- `RecordFleetDeviceToken` upserts `pending_token` and `token_reported_at = hb.ReceivedAt` in the device's
  organization (`InOrg`). It writes only for an active device. An older heartbeat never overwrites a newer token
  (section 6).

**H5 Binding by the worker.** In every round, after the host list and before any `StoreHost`, the worker loads the
bindings of active and quarantined devices (`paddock_inventory_bindings`, platform pool). It decides each binding
with a pending token in ascending `token_reported_at` order:

| # | Condition (first that applies) | Action | `result` label |
| --- | --- | --- | --- |
| 1 | `now - token_reported_at >= TokenMaxAge` (50 min) | clear the token, no Fleet call | `expired` |
| 2 | bound, the bound host is listed with non-zero `seen_time` and `R - seen_time < BindingStale` (15 min) | clear the token, no Fleet call | `current` |
| 3 | `ResolvePerRound` (200) Fleet calls already made this round | keep the token for the next round | none |
| 4 | Fleet answers 401 or 404 (`problem.NotFound`) | clear the token | `unknown_token` |
| 5 | Fleet fails otherwise | keep the token; no further calls this round; the round continues | `unavailable` |
| 6 | the host's lower-case `uuid` differs from the device's hardware UUID | clear the token; `Warn` `inventory host binding refused` (`organization_id`, `device_id`, `host`) | `uuid_mismatch` |
| 7 | the host is the bound host | clear the token | `current` |
| 8 | the device is not bound | bind: `host_id`, `bound_at = now`, clear the token; `Info` `inventory host bound` | `bound` |
| 9 | otherwise | bind to the new host; `Info` `inventory host rebound` (`previous`, `host`) | `rebound` |

- Every clear and bind is a compare-and-set on `token_reported_at` (section 6), so a token reported meanwhile stays
  pending.
- Each decision increments `paddock_inventory_host_bindings_total{result}`.
- The binding needs no audit event: only the device's own signed connection can name its host, and the claim report
  (H8) covers what an organization admin must see.
- Rule 2 keeps Fleet calls to new devices, the one-time re-enrollment (H2) and real host changes. A bound host that
  keeps talking needs no new call per token rotation.

**H6 Only the speaking host is stored.** For every changed listed host `h`:

1. `h` is the bound host of exactly one device → stored for that device.
2. `h` is the bound host of two or more devices → stored for none, counted `unmapped`.
3. otherwise, `MapHosts` maps `h`'s UUID to device `d` (bound devices no longer count in `paddock_inventory_devices`,
   section 6), and `h` is the first-enrolled host of that UUID → stored for `d`.
4. otherwise, if `h`'s UUID equals the hardware UUID of any device that has a `device_fleet_binding` row, or `MapHosts`
   maps it → counted `ignored`, never stored.
5. otherwise → counted `unmapped`, as today.

- The gauge `paddock_inventory_unmapped_hosts` keeps its meaning.
- `inventory synced` gains the attributes `ignored`, `bound` (rule 8 and 9 decisions this round) and `claims`
  (reported claims).

**H7 The claim watch (state from ADR 0057 E).** For every **watched device** (an active device with a
`device_inventory_ref`; platform function `paddock_inventory_claim_devices`), each round:

- **second host**: at least one live other claimant is listed.
- **re-enrolled**: the speaking host is listed, its ID equals the stored `external_id`, its `last_enrolled_at` and
  the stored `fleet_enrolled_at` are both set, and they differ. A changed host ID is a rebinding and is not counted.
- `fleet_enrolled_at` is set to the speaking host's `last_enrolled_at` whenever the speaking host is listed. It is NULL
  after the upgrade, so the first round only records it.

| Condition | Transition |
| --- | --- |
| re-enrolled | `fleet_reenrolled_at = now` |
| second host or re-enrolled, `fleet_claim_since` NULL | `fleet_claim_since = now` (episode starts) |
| `fleet_claim_reported_at` NULL, and either `fleet_reenrolled_at >= fleet_claim_since`, or second host with `now - fleet_claim_since >= HostClaimConfirm` (15 min) | **due** |
| no second host, and `fleet_reenrolled_at` NULL or older than `now - ClaimQuiet` (60 min) | `fleet_claim_since = NULL`, `fleet_claim_reported_at = NULL` (episode ends) |

- A re-enrollment is due at once: Fleet recorded it, so it is not transient. A second host needs 15 minutes.
- The live window (10 min) is shorter than the confirmation (15 min). A host that stopped before the episode started,
  such as the previous host after the one-time re-enrollment (H2), can therefore never become due.
- `kind` = `reenrolled` if the episode saw a re-enrollment, else `second_host`.

**H8 Hold of Fleet-derived agent reports.** `ListAgentNotRunning` and `ListAgentBinaryUnknown` skip a device whose
`fleet_reenrolled_at >= now - ClaimQuiet`. Their rows keep `alerted_at` NULL, so a failure that is still there after
the hold is reported then. The claim watch runs **before** `reportAgents` and `reportBinaries` in the round. A second
host does not hold reports: H6 already keeps its data out.

**H9 Wave guard.** Let `Claimed` be the number of watched devices with `fleet_claim_since` set after this round's
transitions, and `Watched` the number of watched devices.

- If `Claimed >= 3` and `2 × Claimed > Watched`, the round reports no claim. The transitions still apply.
- The worker then logs one `Warn` `inventory claim watch suppressed` (`reason` `claim_majority`, `due`, `claimed`,
  `watched`) and sets the gauge `paddock_inventory_claim_watch_suppressed` to the number of due devices. Otherwise the
  gauge is 0.
- A process whose `WithLeaderLock` call did not run the round sets the gauge to 0.
- New critical alert `PaddockInventoryClaimWatchSuppressed`: `max(paddock_inventory_claim_watch_suppressed) > 0` for
  15m.
- Covered: a Fleet database restore re-enrolls every host whose node key changed after the backup. The H8 hold
  applies even while reports are suppressed.

**H10 Event `device.tamper_fleet_host_claimed`** (32 characters, no MSGID alias; next to
`CodeDeviceTamperAgentBinaryChanged`):

```go
CodeDeviceTamperFleetHostClaimed Code = "device.tamper_fleet_host_claimed"

CodeDeviceTamperFleetHostClaimed: {
	Code: CodeDeviceTamperFleetHostClaimed, Emitted: true,
	Description: "An inventory host other than the one that speaks for a device claims it (actor: system). kind second_host: another host reported the device's hardware UUID and kept contacting the inventory system for 15 minutes; kind reenrolled: the host that speaks for the device was enrolled again, which also happens when fleetd's local state on the device is lost. binding is device when the device named its inventory host over its device connection, first when it has not named one yet and the host the inventory system enrolled first for its hardware UUID speaks for it. Only the speaking host's data is stored for the device; after a re-enrollment, agent reports derived from the inventory system wait 60 minutes. bound_host is the inventory system's ID of the speaking host, other_hosts the IDs of the other live claimants (at most 10, ascending, comma-separated; absent when none), hosts the number of live claimants including the speaking host, enrolled_at the inventory system's time of the latest enrollment of the speaking host (absent when unknown), claim_since when the worker first saw the claim.",
	Params:   []string{"kind", "binding", "bound_host", "other_hosts", "hosts", "enrolled_at", "claim_since"},
	Outcomes: []Outcome{OutcomeSuccess},
	Note:     "Recorded once per claim episode; the episode ends when no other live host claims the device and no re-enrollment was seen for 60 minutes.",
},
```

- Tamper finding: `tamperFindingCodes[audit.CodeDeviceTamperFleetHostClaimed] = ""`, opened in the event's
  transaction. Same pattern as `ReportAgentBinaryUnknown`: `ActionRunner`, mark-reported in the event's transaction,
  0 rows → no event.
- Portal messages `audit.device.tamper_fleet_host_claimed`:
  - EN: "Another inventory enrollment claims {target}"
  - DE: "Eine weitere Anmeldung im Inventarsystem beansprucht {target}"
- No attention kind (as amendment c E6). No hostname or other host-reported text in the params. Fleet host IDs are
  installation-wide numbers.

**H11 Contract, compatibility and upgrade path.**

- **Device API**: one optional request field `fleet_device_token` in `CheckinRequest` (`api/openapi/device.yaml` and
  `pkg/protocol`). `info.version` stays `1.0.0`, and `protocol.Version` stays `paddock-v1`: additive fields have never
  bumped them (`os_release`, `health.software`).
  - An agent before alpha.11 never sends the field; its device stays in mode `first`.
  - An alpha.11 agent against an alpha.10 server sends a field that the gateway ignores.
- **Admin API, bundle format, commands, event types:** unchanged.
- **Audit event contract:** one new code (additive).
- **Database:** migration `00163_inventory_host_binding.sql`. `00163` is the next free number on every branch and
  worktree (checked 2026-11-17: only `00162` is used, by PDK-1122c). PDK-1122d moves amendment c's migration to
  `00164`.
- **Upgrade order (ADR 0047, server first):**
  1. The server upgrade restarts Fleet with `provided`. Existing hosts keep their node keys and their records; nothing
     re-enrolls. Every device is in mode `first`.
  2. Each device's agent updates in its rollout wave. Its first drift pass (at most 300 s) resets and re-enrolls
     fleetd under the instance ID; a new Fleet host appears.
  3. The next check-in (within one check-in interval) carries the new host's token; the next round (at most 5 min)
     binds it.
  4. The previous host stops talking. It stays in Fleet, is never stored, and never becomes due (H7).
  - Between steps 2 and 4, the first-enrolled host is the previous host, which no longer changes, so nothing new is
    stored for up to about two rounds.
- **Fleet host count:** each updated device leaves one stale host in Fleet until the follow-up cleanup (PDK-1123a).
  Fleet free has no host limit.

**H12 Fail safe and isolation.**
- Report only: no command, lock, quarantine or bundle change.
- `device_fleet_binding` is organization-scoped with forced RLS. The platform functions return rows across
  organizations to the worker's platform pool only, as `paddock_inventory_devices` does.
- The token is a credential for Fleet's device endpoints, which are not published (`Caddyfile`: only
  `/api/osquery/*`, `/api/v1/osquery/*`, `/api/fleet/orbit/*`). It is kept until the worker's next decision, at most
  `TokenMaxAge`. It MUST NOT appear in logs, errors, metrics, audit params or the admin API.

**H13 Conditions of acceptance (§159), binding.** They extend sections 5–13; where they differ, H13 wins.

1. **Interim state of older agents (ADR 0057 D1, approved).** RR-22 carries it as a residual, with the upgrade
   instruction (texts, section 6).
2. **The device token stays out of logs, audit params and error texts.** It lives in Postgres for at most
   `TokenMaxAge` (50 min) and is deleted after the decision.
   - `Reports.heartbeat` does not record a token whose `hb.ReceivedAt` is older than `inventory.TokenMaxAge`. Such a
     heartbeat is processed without its token.
   - Each round, before H5, the worker calls the platform function `paddock_expire_fleet_device_tokens(before)` with
     `before = now - TokenMaxAge`. It sets `pending_token = NULL` on every row of every device state whose
     `token_reported_at < before`, and returns the count. That also covers retired and pending devices, which H5 never
     sees.
   - In RabbitMQ the token is part of the heartbeat message. It stays there only until the worker consumes it,
     normally seconds. While the worker role is down, a queued heartbeat keeps its token. Fleet itself honours the
     token for at most one hour after orbit registered it, and orbit replaces it hourly. Accepted.
   - Test `TestFleetDeviceTokenNeverLogged` (worker package) captures `slog` output (a JSON handler on a buffer) and
     audit params while it runs, with one fixed token:
     - the gateway check-in;
     - `Reports.heartbeat`;
     - every H5 outcome (`bound`, `rebound`, `current`, `expired`, `unknown_token`, `unavailable`, `uuid_mismatch`);
     - an adapter transport error.
     It asserts that the token string occurs in none of the captured log records, returned errors or audit params.
     The adapter test `TestResolveDeviceToken` keeps its own error-text assertion.
3. **The re-enrollment wave follows the staged agent rollout, and the agent's own reset never raises a claim.** The
   reset happens only in the drift pass of an updated agent, so it follows the rollout waves. H14 makes the reset
   distinguishable from a re-enrollment of the device's host.
4. **Probes first.** Step 1 (probes (a)–(e), plus (f) of H14) runs before any code. A failing probe is a stop condition
   (section 11). Stop at about 1050 hand-written production lines.
5. **Review.** Before close, the external review re-runs the binding probes against the finished stack.

**H14 Announced enrollment reset.**

- **What it distinguishes.**
  - The agent's reset makes fleetd enroll under a **new** instance ID, so Fleet creates a **new host** with a new ID.
  - A re-enrollment of the device's speaking host keeps the host ID and changes its `last_enrolled_at`. H7 reports it
    as `reenrolled`, with or without an announcement.
  - Without an announcement, the new host could be counted as a live other claimant (`second_host`) in mode `first`.
    That happens if the binding of the new host is delayed for 15 minutes (Fleet's device endpoint unavailable, the
    token expired).
- **Agent.**
  - Before the reset of H2 removes anything, the reconciler stores the reset time in the agent state:
    `state.FleetResetAt *time.Time`, written through the existing state persistence before `systemctl stop
    orbit.service`.
  - `CheckinRequest` gains ``FleetEnrollmentResetAt *time.Time `json:"fleet_enrollment_reset_at,omitempty"` ``. The
    agent sends it in every check-in while `state.FleetResetAt` is set.
  - The agent clears `state.FleetResetAt` after a check-in that returned HTTP 200 and also carried a device token
    read after the reset time (`/opt/orbit/identifier` modification time later than `FleetResetAt`). It also clears it
    24 hours after `FleetResetAt`. The announcement thus reaches the server before or with the new host's token, and
    survives an agent restart.
- **Gateway and ingest.**
  - `ingest.Heartbeat` gains ``FleetEnrollmentResetAt *time.Time `json:"fleet_enrollment_reset_at,omitempty"` ``.
  - The gateway passes the value only if it is not later than the receive time plus 5 minutes and not older than
    24 hours; otherwise nil. An invalid value never fails the check-in.
  - `Reports.heartbeat` records it before coalescing, together with the token:
    `DeviceReports.RecordFleetDeviceToken` becomes `RecordFleetReport` and upserts either field. An older value never
    overwrites a newer one.
- **Data.** `device_fleet_binding` gains `reset_announced_at timestamptz`. `paddock_inventory_claim_devices` returns
  `b.reset_announced_at` and `b.bound_at` after `bound_host`. `inventory.ClaimDevice` gains
  `ResetAnnouncedAt, BoundAt *time.Time`.
- **Claim watch rule (extends H7).** A device is **resetting** while all of these hold:
  - `reset_announced_at` is set and `now - reset_announced_at < ClaimQuiet` (60 min);
  - it has no binding newer than the announcement (`bound_at` NULL or `bound_at < reset_announced_at`).
  For a resetting device, live other claimants do not count as **second host** (no episode starts, a running
  `second_host` episode is not due). **re-enrolled** counts unchanged. The worker logs one `Info` per round and
  device, `inventory claim held: enrollment reset announced` (`organization_id`, `device_id`).
- **Bounds of the window.**
  - The announcement comes over the device's own signed connection and applies to that device only.
  - It lasts at most 60 minutes and ends with the device's first binding after the announcement.
  - A host that the device does not name is never stored (H6).
  - A further host that keeps claiming the device after the window is reported by the normal rule.
- **Tests.**
  - Unit `TestWatchClaimsAnnouncedReset`:
    - mode `first`, a new live host with a higher ID, announced 20 min ago, not bound → no `ClaimStart`, no claim;
    - the same without an announcement and `since = now - 15m` → claim `second_host`;
    - announced 61 min ago → normal rule;
    - bound after the announcement → normal rule;
    - re-enrolled speaking host during the window → claim `reenrolled` (a reset never hides a re-enrollment).
  - Worker `TestInventoryRoundAnnouncedResetRaisesNoClaim` (regression): the new host's token resolution fails for
    20 minutes (`unavailable`), then succeeds → no claim event across the whole sequence, and the device ends bound
    to the new host.
  - Agent `TestInventoryEnrollmentResetAnnounced`: the state holds `FleetResetAt` before the first removal (fake
    `System` records the order); check-ins carry it; it is cleared after an acknowledged check-in with a newer token;
    it survives an agent restart; it is cleared after 24 hours.
  - Gateway `TestCheckinFleetEnrollmentResetAt`: valid passes; future beyond 5 min and older than 24 h → nil, HTTP
    200.
  - VM gate F8 step 3 asserts in addition that `device_fleet_binding.reset_announced_at` is set before the new host
    is bound.
- **Probe (f)** (step 1): on the VM, after the reset by hand, the new host's ID differs from the previous host's ID,
  and the previous host's `last_enrolled_at` is unchanged. If Fleet re-uses the previous record instead, stop: the
  reset would then look like a re-enrollment.
- **Contract.** One more optional request field. `api/openapi/device.yaml`, `CheckinRequest.properties`:
  ```yaml
        fleet_enrollment_reset_at:
          type: string
          format: date-time
          description: |
            When the agent reset fleetd's enrollment to enroll it under its instance identifier (ADR 0057), sent until a
            check-in with the new device token succeeded, at most 24 hours. Optional; agents before 0.1.0-alpha.11 leave
            it out.
  ```
- **Migration additions** (same file `00163_inventory_host_binding.sql`):
  ```sql
  -- device_fleet_binding's CREATE TABLE gains the column reset_announced_at timestamptz after bound_at
  -- (the agent's announced enrollment reset, H14).
  -- paddock_inventory_claim_devices additionally returns b.reset_announced_at, b.bound_at (after bound_host).
  -- +goose StatementBegin
  CREATE FUNCTION paddock_expire_fleet_device_tokens(before timestamptz) RETURNS bigint
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
    $$ WITH x AS (UPDATE public.device_fleet_binding SET pending_token = NULL
                  WHERE pending_token IS NOT NULL AND token_reported_at < before RETURNING 1)
       SELECT count(*) FROM x $$;
  -- +goose StatementEnd
  REVOKE ALL ON FUNCTION paddock_expire_fleet_device_tokens(timestamptz) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION paddock_expire_fleet_device_tokens(timestamptz) TO paddock_platform;
  ```
  ```sql
  -- name: RecordFleetEnrollmentReset :exec   (organization pool; an older announcement never overwrites a newer one)
  INSERT INTO device_fleet_binding (device_id, organization_id, reset_announced_at)
  SELECT d.id, d.organization_id, @reset_at::timestamptz FROM device d WHERE d.id = @device_id AND d.state = 'active'
  ON CONFLICT (device_id) DO UPDATE SET reset_announced_at = EXCLUDED.reset_announced_at
    WHERE device_fleet_binding.reset_announced_at IS NULL
       OR device_fleet_binding.reset_announced_at < EXCLUDED.reset_announced_at;

  -- name: ExpireFleetDeviceTokens :one   (platform pool)
  SELECT paddock_expire_fleet_device_tokens(@before::timestamptz);
  ```
- **Files** (additions to section 5): `agent/internal/agent/state.go` (or the file that defines the agent state;
  field `FleetResetAt`), and the reconciler's access to it. The reconciler gets it as a callback field
  `Inventory.AnnounceReset func(time.Time) error` that the agent sets; a nil callback skips the announcement in
  tests.

### 4. Non-goals

- No change to `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, the supervisor, or the bundle format.
- No change to the policy SQL files or to Fleet's settings (`EnsureSettings`).
- No deletion of Fleet hosts (follow-up PDK-1123a). No change to retention or offboarding host deletion
  (`paddock_fleet_host_in_use*`): a bound device's `device_inventory_ref.external_id` is its bound host after its
  first store, which those functions already see.
- No Fleet teams, team secrets or other Fleet Premium features (ADR 0009, ADR 0057 C).
- No attention kind, no portal view of the binding.
- Nothing of amendment c or d (silent fleetd, `policies` reason, unanswered agent-running query): PDK-1122d.

### 5. Files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/00163_inventory_host_binding.sql` | new | section 6 |
| `server/internal/adapters/postgres/queries/inventory.sql` | change | binding, claim and hold queries |
| `server/internal/adapters/postgres/queries/device.sql` | change | `RecordFleetDeviceToken` |
| `server/internal/adapters/postgres/pgstore/*` | regenerated | `make gen` |
| `server/internal/ports/inventory.go` | change | `HostSeen`, `HostPage.Seen`, `InventoryBinder` |
| `server/internal/adapters/fleet/hosts.go`, `hosts_test.go`, `testdata/get_hosts.json` | change | `Seen`, `last_enrolled_at`, `ResolveDeviceToken` |
| `server/internal/inventory/binding.go`, `binding_test.go` | new | `Binding`, `HostTargets`, `DecideBinding` |
| `server/internal/inventory/claims.go`, `claims_test.go` | new | `WatchClaims` |
| `server/internal/app/inventory.go`, `inventory_integration_test.go` | change | bindings, claims, hold |
| `server/internal/app/devicereports.go`, `devicereports_integration_test.go` | change | `RecordFleetDeviceToken` |
| `server/internal/app/findings.go` | change | finding entry |
| `server/internal/worker/inventory.go`, `inventory_test.go` | change | round order, H5, H6, H7, H9, metrics |
| `server/internal/worker/reports.go`, `reports_test.go` | change | H4 |
| `server/internal/ingest/ingest.go` | change | `Heartbeat.FleetDeviceToken` |
| `server/internal/transport/http/device/handlers.go`, `handlers_test.go` | change | H4 validation |
| `server/cmd/paddock-server/worker.go` | change | `.WithBinder(fleetClient)` |
| `server/internal/domain/audit/codes.go` + `make gen` outputs | change | H10 |
| `server/web/src/locales/en.json`, `de.json` | change | H10 messages |
| `pkg/protocol/types.go` | change | H3 field |
| `api/openapi/device.yaml` | change | H3 field |
| `agent/internal/agent/agent.go`, `agent_test.go` (or the existing check-in test file) | change | H3 |
| `agent/internal/reconcile/inventory.go`, `inventory_test.go` | change | H2 |
| `agent/internal/reconcile/reconcile.go`, `system.go`, `fakesys/fakesys.go` | change | `RemoveAll` |
| `deploy/compose/compose.yaml` | change | H1 |
| `deploy/compose/prometheus/alerts.yml`, `alerts_test.yml` | change | H9 alert |
| `test/acceptance/devicesim/fleet.go`, `fleet_test.go`, `devicesim.go` | change | section 8 helpers |
| `test/acceptance/fleethost.go` | change | `fleetHostIDs` |
| `test/acceptance/inventory_test.go` | change | `TestInventoryHostBinding` |
| `test/system/inventory_test.go` | change | gate F8, `fleetHostByUUID` picks the most recently seen host |
| `docs/compliance/residual-risks.md`, `docs/architecture.md` (§11.5, §15), `docs/operations/fleet.md`, `docs/operations/monitoring.md`, `docs/operations/upgrade.md` | change | section 6 texts |
| `changelog.d/PDK-1123.security.md` | new | section 6 text |

**Not touched:**
- `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `agent/cmd/paddock-supervisor/` and the supervisor
  packages;
- `pkg/bundle/`, `api/openapi/admin.yaml`, `server/internal/inventory/policies/`;
- the offboarding and retention code;
- `docs/adr/`.

### 6. Interfaces, data model and texts

```sql
-- 00163_inventory_host_binding.sql
-- Inventory hosts bound to their device (ADR 0057; plan M5a amendment 2026-11-17 e).
-- device_fleet_binding: per device, the inventory host the device named over its device connection (host_id, the
-- inventory system's host ID as text, like device_inventory_ref.external_id; bound_at when the worker bound it) and the
-- latest device token the agent reported that the worker has not decided yet (pending_token, token_reported_at; the
-- token is cleared after the decision).
-- device_inventory_ref, the claim watch: fleet_enrolled_at is the inventory system's latest enrollment time of the
-- stored host as last observed; fleet_reenrolled_at the worker's time of the last round that saw that host enrolled
-- again; fleet_claim_since the worker's time when the current claim episode started; fleet_claim_reported_at when
-- device.tamper_fleet_host_claimed was recorded for it.
-- paddock_inventory_devices no longer counts bound devices, so a bound device never makes a hardware UUID ambiguous.
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE device_fleet_binding (
  device_id uuid PRIMARY KEY REFERENCES device(id),
  organization_id uuid NOT NULL,
  pending_token text CHECK (pending_token ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  token_reported_at timestamptz,
  host_id text CHECK (host_id ~ '^[0-9]{1,19}$'),
  bound_at timestamptz,
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_fleet_binding_host ON device_fleet_binding (host_id) WHERE host_id IS NOT NULL;
ALTER TABLE device_fleet_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_fleet_binding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_fleet_binding TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON device_fleet_binding TO paddock_worker;
INSERT INTO offboarding_table (table_name, delete_order) VALUES ('device_fleet_binding', 165);

ALTER TABLE device_inventory_ref ADD COLUMN fleet_enrolled_at timestamptz,
                                 ADD COLUMN fleet_reenrolled_at timestamptz,
                                 ADD COLUMN fleet_claim_since timestamptz,
                                 ADD COLUMN fleet_claim_reported_at timestamptz;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION paddock_inventory_devices(uuids text[])
  RETURNS TABLE (hardware_uuid text, device_id uuid, organization_id uuid)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT lower(d.hardware_uuid), min(d.id::text)::uuid, min(d.organization_id::text)::uuid
     FROM device d
     WHERE lower(d.hardware_uuid) = ANY (SELECT lower(u) FROM unnest(uuids) u)
       AND d.state IN ('active','quarantined')
       AND NOT EXISTS (SELECT 1 FROM device_fleet_binding b WHERE b.device_id = d.id AND b.host_id IS NOT NULL)
     GROUP BY lower(d.hardware_uuid)
     HAVING count(*) = 1 $$;

CREATE FUNCTION paddock_inventory_bindings()
  RETURNS TABLE (device_id uuid, organization_id uuid, hardware_uuid text, host_id text, pending_token text,
                 token_reported_at timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT d.id, d.organization_id, lower(d.hardware_uuid), b.host_id, b.pending_token, b.token_reported_at
     FROM public.device_fleet_binding b JOIN public.device d ON d.id = b.device_id
     WHERE d.state IN ('active','quarantined') $$;

CREATE FUNCTION paddock_inventory_claim_devices()
  RETURNS TABLE (device_id uuid, organization_id uuid, hardware_uuid text, external_id text, bound_host text,
                 fleet_enrolled_at timestamptz, fleet_reenrolled_at timestamptz, fleet_claim_since timestamptz,
                 fleet_claim_reported_at timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT d.id, d.organization_id, lower(d.hardware_uuid), i.external_id, b.host_id, i.fleet_enrolled_at,
            i.fleet_reenrolled_at, i.fleet_claim_since, i.fleet_claim_reported_at
     FROM public.device d JOIN public.device_inventory_ref i ON i.device_id = d.id
          LEFT JOIN public.device_fleet_binding b ON b.device_id = d.id
     WHERE d.state = 'active' $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_inventory_bindings() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_inventory_bindings() TO paddock_platform;
REVOKE ALL ON FUNCTION paddock_inventory_claim_devices() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_inventory_claim_devices() TO paddock_platform;

-- +goose Down
```

`CREATE OR REPLACE` keeps the existing grants of `paddock_inventory_devices`. If the project's migration lint
requires the pinned `search_path` for a replaced function, use `pg_catalog, public, pg_temp` with qualified tables, as
in the two new functions.

```sql
-- device.sql
-- name: RecordFleetDeviceToken :exec   (organization pool; an older heartbeat never overwrites a newer token)
INSERT INTO device_fleet_binding (device_id, organization_id, pending_token, token_reported_at)
SELECT d.id, d.organization_id, @token::text, @reported_at::timestamptz FROM device d
WHERE d.id = @device_id AND d.state = 'active'
ON CONFLICT (device_id) DO UPDATE
  SET pending_token = EXCLUDED.pending_token, token_reported_at = EXCLUDED.token_reported_at
  WHERE device_fleet_binding.token_reported_at IS NULL
     OR device_fleet_binding.token_reported_at < EXCLUDED.token_reported_at;

-- inventory.sql
-- name: InventoryBindings :many   (platform pool)
SELECT * FROM paddock_inventory_bindings() ORDER BY token_reported_at NULLS LAST, device_id;

-- name: BindInventoryHost :execrows   (organization pool; compare-and-set on the reported token)
UPDATE device_fleet_binding SET host_id = @host_id, bound_at = @at, pending_token = NULL
WHERE device_id = @device_id AND token_reported_at = @token_reported_at;

-- name: ClearFleetDeviceToken :execrows
UPDATE device_fleet_binding SET pending_token = NULL
WHERE device_id = @device_id AND token_reported_at = @token_reported_at;

-- name: InventoryClaimDevices :many   (platform pool)
SELECT * FROM paddock_inventory_claim_devices() ORDER BY device_id;

-- name: SetFleetEnrolledAt :exec   (organization pool)
UPDATE device_inventory_ref SET fleet_enrolled_at = @enrolled_at WHERE device_id = @device_id;

-- name: MarkFleetReenrolled :exec
UPDATE device_inventory_ref SET fleet_reenrolled_at = @at WHERE device_id = ANY(@device_ids::uuid[]);

-- name: StartFleetClaim :exec
UPDATE device_inventory_ref SET fleet_claim_since = @at
WHERE device_id = ANY(@device_ids::uuid[]) AND fleet_claim_since IS NULL;

-- name: ClearFleetClaim :exec
UPDATE device_inventory_ref SET fleet_claim_since = NULL, fleet_claim_reported_at = NULL
WHERE device_id = ANY(@device_ids::uuid[]);

-- name: MarkFleetClaimReported :execrows
UPDATE device_inventory_ref SET fleet_claim_reported_at = @at
WHERE device_id = @device_id AND fleet_claim_reported_at IS NULL;

-- ListAgentNotRunning and ListAgentBinaryUnknown: add to the WHERE clause
--   AND (i.fleet_reenrolled_at IS NULL OR i.fleet_reenrolled_at < @held_before::timestamptz)
```

```go
// pkg/protocol/types.go, CheckinRequest
	// FleetDeviceToken is fleetd's current device token (/opt/orbit/identifier), sent when it changed since the last
	// successful check-in (ADR 0057). Agents before 0.1.0-alpha.11 leave it out.
	FleetDeviceToken string `json:"fleet_device_token,omitempty"`

// server/internal/ports/inventory.go
// HostSeen is one listed host of the inventory system that has a hardware UUID (ADR 0057).
type HostSeen struct {
	Ref          HostRef
	HardwareUUID string
	SeenAt       time.Time  // zero when the inventory system reports none
	EnrolledAt   *time.Time // the host's latest enrollment; nil when unknown
}
// HostPage gains: Seen []HostSeen — every host of the page with a hardware UUID, changed or not, in list order.

// InventoryBinder resolves a device token to the host that registered it (ADR 0057).
type InventoryBinder interface {
	// ResolveDeviceToken returns the host the token identifies and its hardware UUID. An error wrapping
	// problem.NotFound means the inventory system knows no host for the token (unknown or older than its lifetime);
	// problem.UpstreamUnavailable that it failed or could not be reached. Errors never contain the token.
	ResolveDeviceToken(ctx context.Context, token string) (HostRef, string, error)
}

// server/internal/adapters/fleet/hosts.go
// ResolveDeviceToken implements ports.InventoryBinder with GET /api/latest/fleet/device/{token}?exclude_software=true,
// one attempt (the next round retries). It refuses a token that does not match the device token format without a
// request. 401 and 404 are problem.NotFound; a 200 without host.id is problem.UpstreamUnavailable.
func (c *Client) ResolveDeviceToken(ctx context.Context, token string) (ports.HostRef, string, error)

// server/internal/inventory/binding.go
const (
	TokenMaxAge     = 50 * time.Minute
	BindingStale    = 15 * time.Minute
	ResolvePerRound = 200
)

// Binding is a device's row of paddock_inventory_bindings.
type Binding struct {
	DeviceID, OrganizationID uuid.UUID
	HardwareUUID             string        // lower case
	Host                     ports.HostRef // "" when the device is not bound
	PendingToken             string
	TokenReportedAt          *time.Time
}

// Decision is the outcome of rules 1, 2, 6, 7, 8 and 9 of H5 for one binding.
type Decision int
const (
	DecideResolve Decision = iota // call ResolveDeviceToken (rules 3–5 are the worker's)
	DecideExpired
	DecideCurrent
	DecideUUIDMismatch
	DecideBind
	DecideRebind
)

// DecideBinding returns the decision before a Fleet call (resolved == nil: rules 1, 2 or DecideResolve) or after it
// (resolved: the host and its hardware UUID; rules 6–9). It is pure.
func DecideBinding(b Binding, seen map[ports.HostRef]ports.HostSeen, r, now time.Time, resolved *ports.HostSeen) Decision

// Targets says which listed hosts may be stored (H6).
type Targets struct {
	Bound    map[ports.HostRef]Binding // hosts bound to exactly one device
	Excluded map[ports.HostRef]bool    // hosts bound to two or more devices
	First    map[string]ports.HostRef  // lower-case hardware UUID → first-enrolled host
	BindingUUIDs map[string]bool       // lower-case hardware UUIDs of devices with a binding row (H6 rule 4)
}

// HostTargets computes Targets from the listed hosts (list order) and the bindings. It is pure.
func HostTargets(seen []ports.HostSeen, bindings []Binding) Targets

// server/internal/inventory/claims.go
const (
	HostClaimLive     = 10 * time.Minute
	HostClaimConfirm  = 15 * time.Minute
	ClaimQuiet        = 60 * time.Minute
	ClaimMajorityMin  = 3
	ClaimHostsInParam = 10
)

// ClaimDevice is one watched device (paddock_inventory_claim_devices).
type ClaimDevice struct {
	DeviceID, OrganizationID uuid.UUID
	HardwareUUID             string        // lower case
	ExternalID               ports.HostRef // the stored host
	BoundHost                ports.HostRef // "" when not bound (binding mode first)
	EnrolledAt, ReenrolledAt, ClaimSince, ClaimReportedAt *time.Time
}

// ClaimedDevice is a device to report.
type ClaimedDevice struct {
	ClaimDevice
	Kind       string // "second_host" | "reenrolled"
	Binding    string // "device" | "first"
	Bound      ports.HostRef
	Others     []ports.HostRef // ascending; the param is capped at ClaimHostsInParam
	Hosts      int
	EnrolledAt *time.Time      // the speaking host's
}

// ClaimWatch is one round's decision.
type ClaimWatch struct {
	Enrolled                         map[uuid.UUID]*time.Time // fleet_enrolled_at to store
	Reenrolled, ClaimStart, ClaimClear []uuid.UUID
	Claims                           []ClaimedDevice // empty when Suppressed
	Due, Watched, Claimed            int
	Suppressed                       bool // claim_majority
}

// WatchClaims decides one round (H7, H9). seen is the round's listed hosts in list order; t is the round's Targets
// (its First names the speaking host of a device that is not bound). It is pure.
func WatchClaims(devices []ClaimDevice, seen []ports.HostSeen, t Targets, now time.Time) ClaimWatch

// server/internal/app
func (s *InventorySync) InventoryBindings(ctx context.Context) ([]inventory.Binding, error)                 // platform
func (s *InventorySync) BindInventoryHost(ctx context.Context, device uuid.UUID, reportedAt time.Time,
	host ports.HostRef, now time.Time) (bool, error)                                                        // ctx: device's org
func (s *InventorySync) ClearFleetDeviceToken(ctx context.Context, device uuid.UUID, reportedAt time.Time) error
func (s *InventorySync) InventoryClaimDevices(ctx context.Context) ([]inventory.ClaimDevice, error)        // platform
// ApplyClaimWatch applies one organization's part of w (the worker splits w per organization) in one transaction,
// then reports each claim through ActionRunner (MarkFleetClaimReported; 0 rows records nothing; tamper finding).
func (s *InventorySync) ApplyClaimWatch(ctx context.Context, w inventory.ClaimWatch, now time.Time) ([]uuid.UUID, error)
// ReportAgentNotRunning(ctx, now) passes held_before = now - inventory.ClaimQuiet;
// ReportAgentBinaryUnknown gains now as its second parameter: (ctx, now, evaluatedAfter, knownHashes).
func (d *DeviceReports) RecordFleetDeviceToken(ctx context.Context, hb ingest.Heartbeat) error

// server/internal/worker/inventory.go
func (i *Inventory) WithBinder(b ports.InventoryBinder) *Inventory // nil binder: rules 3–9 never run
// metrics (registered like metricUnmappedHosts):
//   paddock_inventory_host_bindings_total{result="bound|rebound|current|expired|unknown_token|uuid_mismatch|unavailable"} counter
//   paddock_inventory_claim_watch_suppressed gauge
```

**Round order** (`Inventory.Round`, binding):
1. Policies, the agent binary policy, `VulnerabilityState`: unchanged.
2. List every page. Collect the changed hosts (as today) and `Seen` (every host with a UUID).
3. `InventoryBindings`, then the H5 decisions. The worker keeps the decided bindings in memory for steps 4 and 6.
4. `HostTargets`; `MapHosts` for the UUIDs of the changed hosts; then H6 for each changed host, and `StoreHost`.
5. `InventoryClaimDevices`; `WatchClaims` with step 4's `Targets`; `ApplyClaimWatch` per organization; the H9 log
   and gauge.
6. `reportAgents`, `reportBinaries` (with the hold), `summarize`.

A failure in steps 2, 4 or 5 fails the round, as today. A Fleet failure in step 3 is rule 5 and does not fail it.

**Alert** (`deploy/compose/prometheus/alerts.yml`, group of the inventory alerts; the test cases follow the existing
`alerts_test.yml` pattern: fires after 15m, not after 14m, not at 0):
```yaml
      - alert: PaddockInventoryClaimWatchSuppressed
        expr: max(paddock_inventory_claim_watch_suppressed) > 0
        for: 15m
        labels: { severity: critical }
        annotations:
          summary: "Inventory claim reports are held: most watched devices have an open claim"
          description: "More than half of the devices with inventory have an open claim episode, so no claim is reported. A Fleet database restore causes this for up to 60 minutes; otherwise follow docs/operations/fleet.md, \"When the inventory claim watch is suppressed\"."
```

**Device API** (`api/openapi/device.yaml`, `CheckinRequest.properties`):
```yaml
        fleet_device_token:
          type: string
          pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
          description: |
            fleetd's current device token (the content of /opt/orbit/identifier), sent when it changed since the last
            successful check-in. The server resolves it through the inventory system to the device's inventory host
            and stores only that host's data for the device (ADR 0057). A value that does not match the pattern is
            ignored without failing the check-in. Optional; agents before 0.1.0-alpha.11 leave it out.
```

**Texts** (the implementer applies them on top of the texts of PDK-1122c, `b228593a`):

- **RR-22**, risk column: replace "Fleet host identity is not yet bound to the device (follow-up PDK-1123)." with:
  "Each device's inventory host is bound to the identity the device reports over its signed device connection; hosts
  that are not bound to a device are not stored for it, and another host that claims a device, or a re-enrollment of
  its host, is reported as `device.tamper_fleet_host_claimed` (ADR 0057). A device whose agent predates 0.1.0-alpha.11
  has not named its host yet; for it, the host Fleet enrolled first is stored until the agent updates."
  - Mitigation column: replace "hosts that map to no device are ignored and counted;" with "hosts that map to no
    device, or that do not speak for the device, are ignored and counted;".
  - Recommendation column: replace "Accept, or rotate the secret periodically." with "Upgrade the server first, then
    every agent to 0.1.0-alpha.11 or later through a staged rollout; until a device's agent is updated, its
    inventory host is not yet bound to it (residual). Accept, or rotate the secret periodically."
- **RR-149**, not-reported list: replace "a Fleet host whose identity is not yet bound to the device (RR-22, follow-up
  PDK-1123);" with "a device whose agent has not named its inventory host yet, while the host Fleet enrolled first
  for it is used (RR-22);".
- **`docs/architecture.md` §15**, "Mapping:" bullet, replace its first sentence with: "Fleet hosts are matched to
  Paddock devices through the binding each device reports over its device connection (ADR 0057): fleetd's device
  token, resolved by the worker through Fleet's device endpoint. Until a device has reported one, the host Fleet
  enrolled first for the device's hardware UUID (`system_info.uuid`) is used."
- **`docs/architecture.md` §11.5**: new row "Only the host that speaks for the device claims it (worker, from Fleet's
  host list) | every inventory round | `device.tamper_fleet_host_claimed` (`kind` `second_host` after 15 min,
  `reenrolled` at once)".
- **`docs/operations/fleet.md`**:
  - "fleetd on devices", step 1: `orbit.env` also sets `ORBIT_HOST_IDENTIFIER=instance`. On a device whose fleetd was
    enrolled before, the agent re-enrolls fleetd once (it stops `orbit.service` and removes orbit's node key, device
    token and osquery database).
  - "Inventory sync and mutual watch", step 3, replace with: "binds each device to the host its agent named
    (fleetd's device token, resolved through Fleet's device endpoint) and stores only that host for the device. A
    device whose agent has not named a host yet uses the host Fleet enrolled first for its hardware UUID. Hosts that
    do not speak for a device are counted in the log attribute `ignored`; `paddock_inventory_host_bindings_total`
    counts the binding decisions by `result`."
  - Step 5 gains: "It reports, once per episode, `device.tamper_fleet_host_claimed` when another host reports a
    device's hardware UUID and keeps contacting Fleet for 15 minutes, or when the device's host was enrolled again.
    After a re-enrollment, agent reports from Fleet wait 60 minutes. A Fleet database restore re-enrolls many hosts at
    once; the worker then holds the claim reports (`claim_majority`)."
  - New runbook subsection "When the inventory claim watch is suppressed": the alert `PaddockInventoryClaimWatchSuppressed`
    and the log `inventory claim watch suppressed`. Steps: (1) check whether Fleet was restored or upgraded; the
    episodes end 60 minutes after the last re-enrollment. (2) Otherwise list the Fleet hosts per hardware UUID; several
    live hosts per UUID without such a cause need a security review of the devices concerned.
  - "Settings Paddock enforces" gains: "`FLEET_OSQUERY_HOST_IDENTIFIER=provided` (compose): Fleet identifies a host by
    the identifier fleetd provides."
- **`docs/operations/monitoring.md`**: rows for `paddock_inventory_host_bindings_total`,
  `paddock_inventory_claim_watch_suppressed` and `PaddockInventoryClaimWatchSuppressed`.
- **`docs/operations/upgrade.md`**, notes of 0.1.0-alpha.11: "Each device enrolls its fleetd once more after its agent
  updates; a new Fleet host appears per device, and the previous one stays in Fleet without data being stored for it.
  Inventory of a device pauses for up to about 10 minutes around its re-enrollment."
- **Changelog** `changelog.d/PDK-1123.security.md`: "Each device's inventory host is now bound to the identity the
  device reports over its signed device connection, and only that host's data is stored for the device. Another
  inventory host that claims a device, and a re-enrollment of a device's host, are reported as tamper findings.
  Update the agents: a device whose agent predates this release uses the host Fleet enrolled first until it updates.
  Each device enrolls its fleetd once more after the agent update."

### 7. Steps

1. **Probes on the devstack and one VM (no code), recorded in the result document.**
   - (a) On a VM with the current fleetd, `/opt/orbit/identifier` exists, is mode 0644 and matches the token format
     although Fleet Desktop is disabled.
   - (b) `GET /api/latest/fleet/device/<token>?exclude_software=true` on Fleet's internal address answers the VM's
     host ID and hardware UUID; a random UUID answers 401.
   - (c) With `FLEET_OSQUERY_HOST_IDENTIFIER=provided`, an existing host keeps working: `seen_time` advances and no
     second host appears for 15 minutes.
   - (d) After setting `ORBIT_HOST_IDENTIFIER=instance` and the reset of H2 by hand on the VM: exactly one new host
     appears, its `uuid` is the VM's hardware UUID, the old host's `seen_time` stops, and the new token resolves to
     the new host.
   - (e) A `devicesim` re-enrollment under an existing identifier keeps the host ID and changes `last_enrolled_at`;
     `last_enrolled_at` does not change while a host just answers for 3 minutes.
   Check: the six observations are in the result document.
2. **Migration, queries, ports, adapter** (`make gen`). Check: `go test ./server/internal/adapters/fleet/ -run
   'TestResolveDeviceToken|TestListHostsSeen'`; `make gen` no diff; `make lint` (RLS lint) green.
3. **`inventory` package** (`binding.go`, `claims.go`). Check: `go test ./server/internal/inventory/ -run
   'TestHostTargets|TestDecideBinding|TestWatchClaims'`.
4. **App, registry, finding, messages.** Check: `go test ./server/internal/app/ -run
   'TestRecordFleetDeviceToken|TestBindInventoryHost|TestApplyClaimWatch|TestReportAgentNotRunning|TestReportAgentBinary|TestInventoryDevices'`.
5. **Protocol, gateway, ingest, reports.** Check: `go test ./server/internal/transport/http/device/ -run
   TestCheckinFleetDeviceToken` and `go test ./server/internal/worker/ -run TestReportsHeartbeatFleetDeviceToken`.
6. **Worker round** (order, H5, H6, H7, H9, metrics, `WithBinder` wiring). Check: `go test ./server/internal/worker/
   -run 'TestInventoryRound'`.
7. **Agent** (H2, H3, `RemoveAll`). Check: `go test ./agent/internal/reconcile/ -run 'TestInventory'` and `go test
   ./agent/internal/agent/ -run TestCheckinFleetDeviceToken`.
8. **Compose and alert.** Check: `make lint-prometheus`; `docker compose config` of the dev stack shows
   `FLEET_OSQUERY_HOST_IDENTIFIER: provided`.
9. **devicesim and acceptance.** Check: `make acceptance` runs `TestInventoryHostBinding` and every existing
   inventory gate green.
10. **VM gate F8** (`make deb` first; serially to acceptance; `df` before). Check: `make system-test VM=all
    SUITE=misc` green, including F1–F5.
11. **Docs and changelog**; quality gate (`make typecheck`, the full `go test` with `nice -n 19`); `make
    changelog-check`.

### 8. Tests

"Regression" tests MUST fail without the change (mutation recorded in the result document).

- **Unit `TestHostTargets`**: no bindings → `First` per UUID is the lowest listed host; a binding to host 9 of UUID u
  with hosts 7 and 9 listed → `Bound[9]`, `First[u] = 7` (7 is not bound); two devices bound to host 9 →
  `Excluded[9]`, neither in `Bound`; a bound host whose reported UUID differs from the device's still maps by ID.
- **Unit `TestDecideBinding`**: every row of H5's table, including the boundaries `TokenMaxAge - 1s` (resolve) and
  `BindingStale - 1s` (current); a zero `seen_time` of the bound host → resolve.
- **Unit `TestWatchClaims`**:
  - second host: first round → `ClaimStart`; `since = now - 15m` → claim `second_host` with `Bound`, `Others`,
    `Hosts`, `Binding`; `now - 14m59s` → none.
  - live window: an other claimant with `R - seen = 10m` → not live; `9m59s` → live.
  - previous host after a re-enrollment: other claimant last seen before `ClaimStart` → never due (regression of the
    H7 window argument).
  - re-enrolled: stored `EnrolledAt` differs, same `ExternalID` → `Reenrolled`, `ClaimStart`, claim at once with kind
    `reenrolled`; different `ExternalID` → none; stored `EnrolledAt` NULL → none, `Enrolled` set.
  - episode end at `ReenrolledAt = now - 61m`, kept at `now - 59m`.
  - guard: 3 of 4 claimed → `Suppressed`, no `Claims`, `Due` counted; 2 of 3 → reported; 3 of 6 → reported.
  - binding modes: `BoundHost` set → `Binding = device` and the bound host speaks even with a lower-ID claimant;
    unset → `first`.
- **Adapter `TestResolveDeviceToken`** (httptest): 200 → ref and UUID, request path
  `/api/latest/fleet/device/<token>` with `exclude_software=true`; 401 and 404 → `problem.NotFound`; 500 →
  `problem.UpstreamUnavailable` after exactly one request; malformed token → no request; a transport error → the
  error text does not contain the token. **`TestListHostsSeen`**: `last_enrolled_at` and `seen_time` parsed; a host
  without `seen_time` → zero `SeenAt`; unchanged hosts are in `Seen`; order follows the page.
- **Gateway `TestCheckinFleetDeviceToken`**: a valid token reaches the heartbeat; an upper-case, 37-character or
  path-character value → empty, check-in 200; absent → empty.
- **Worker `TestReportsHeartbeatFleetDeviceToken`**: a coalesced heartbeat (claim refused) still records the token; an
  unavailable organization acks.
- **App** (Postgres):
  - `TestRecordFleetDeviceToken`: insert; newer overwrites; older does not; a retired device → no row; another
    organization's context sees no row (RLS negative) and cannot write one (positive and negative).
  - `TestBindInventoryHost`: binds on a matching `token_reported_at`; a newer token reported meanwhile → 0 rows, the
    token stays.
  - `TestInventoryDevicesIgnoresBound` (regression of the duplicate-UUID case): two active devices with one UUID →
    unmapped; after one is bound → the other maps.
  - `TestApplyClaimWatch`: one event with the seven params (`other_hosts` capped at 10, ascending) and a tamper
    finding; a second apply records nothing; transitions as written; another organization's device is untouched.
  - `TestReportAgentNotRunningHeldAfterReenroll` (regression): failing device with `fleet_reenrolled_at = now - 10m` →
    0 events; `now - 61m` → 1. The same for `ReportAgentBinaryUnknown`.
- **Worker rounds** (fake source and binder, Postgres):
  - `TestInventoryRoundBoundHost` (regression): hosts 7 (fails the binary policy, enrolled first) and 9 (passes) with
    one UUID; the device's token resolves to 9 → after each round `external_id = 9`, the binary result passes, no
    `device.tamper_agent_binary_changed`; after the confirmation one `device.tamper_fleet_host_claimed` (`second_host`,
    `binding device`, `bound_host 9`, `other_hosts 7`).
  - `TestInventoryRoundFirstEnrolledHost` (regression): unbound device; host 7 fails `paddock_agent_running`, host 9
    passes and changes every round → the stored result stays failing, `external_id = 7`; claim `binding first`.
  - `TestInventoryRoundBindsReportedToken`: `bound`, `rebound`, `uuid_mismatch`, `unknown_token`, `expired`,
    `current` without a call, `unavailable` keeps the token and the round succeeds, and at most 200 calls per round;
    the counter labels match.
  - `TestInventoryRoundReenrolledHost` (regression): the speaking host keeps its ID, its `last_enrolled_at` changes,
    and in the same round its binary policy fails after the gate → claim `reenrolled` and no binary event; 61 minutes
    later, still failing → the binary event.
  - `TestInventoryRoundFleetRestore`: 5 devices re-enroll in one round → no claim, gauge 5, agent reports held; after
    61 minutes without re-enrollment → episodes end, gauge 0.
  - `TestInventoryRoundDuplicateHardwareUUID` (regression): devices A (bound to host 9) and B (unbound) with one UUID;
    hosts 7 and 9 → 9 stored for A, 7 stored for B.
  - `TestInventoryRoundNotLeaderResetsClaimGauge`.
- **Agent**:
  - `reconcile` `TestInventoryOrbitEnvHostIdentifier`: the rendered `orbit.env` is exactly H2's text.
  - `TestInventoryEnrollmentReset`: old `orbit.env` without the line and the package installed → `systemctl stop
    orbit.service`, the three paths removed, files written, restart; a second Apply → no reset; no `orbit.env` → no
    reset; package not installed → no reset; missing paths → no error.
  - `agent` `TestCheckinFleetDeviceToken`: sent when valid and new; not sent again after HTTP 200; sent again after a
    failed check-in and after a change; omitted when missing, malformed or with trailing garbage.
- **devicesim** (`fleet_test.go` against an httptest Fleet): `EnrollFleetBound` sends orbit enroll, device token and
  osquery enroll in that order with the same instance ID; `EnrollFleetAs` sends the given identifier; `EnrollAgain`
  replaces the node key; `Device.Checkin` sends `fleet_device_token` only when set; `HardwareUUIDOverride` changes
  `HardwareUUID()`.
- **Rules**: `alerts_test.yml` for `PaddockInventoryClaimWatchSuppressed`.
- **Acceptance `TestInventoryHostBinding`** (acme, alice; one failure bound of 20 minutes; conditions only):
  1. `bound`: device D1. A host `EnrollFleetAs(identifier "acc-bind-early-"+suffix, uuid D1)` whose binary policy
     fails is enrolled **first**. Then `EnrollFleetBound(uuid D1)` passes every policy. D1 checks in with the bound
     host's token; both hosts answer in every iteration.
     - Wait until `device_fleet_binding.host_id` and `device_inventory_ref.external_id` are the bound host's ID (owner
       DB).
     - After two further `synced_at` values: still that ID, `paddock_agent_binary_known` passing, and alice sees no
       `device.tamper_agent_binary_changed` for D1.
     - Seed `fleet_claim_since` 16 minutes back; alice sees exactly one `device.tamper_fleet_host_claimed` for D1 with
       `kind second_host`, `binding device`, `bound_host` = the bound host's ID.
  2. `reenrolled`: device D2 bound to its `EnrollFleetBound` host. A second `FleetHost` enrolls with D2's host's
     instance identifier (`EnrollFleetAs`) and fails the binary policy; D2's original host gets `node_invalid` and
     calls `EnrollAgain`. Alice sees one claim with `kind reenrolled`; after two further `synced_at` values, no
     `device.tamper_agent_binary_changed` for D2.
  3. `first`: device D3 without a token, host `EnrollFleet(uuid D3)` passing, then `EnrollFleetAs("acc-first-late-"+
     suffix, uuid D3)` failing the binary policy → after two `synced_at` values `external_id` is the first host and
     the binary result passes; after seeding, one claim with `binding first`.
  4. `refused`: device D4 checks in with D1's bound host's token → after two rounds D4 has no `host_id`.
  5. `same_uuid`: device D5 with `HardwareUUIDOverride` = D1's UUID becomes active → D1's `synced_at` advances in
     the next two rounds.
  6. carol (globex) sees none of these events; D1–D5 have no `device.tamper_agent_not_running`.
  7. Cleanup: stop the extra hosts and delete them through Fleet's API (`fleet_api_token`).
- **System gate F8 "inventory host binding"** in `TestInventoryGates`, after F1–F5, per VM in parallel:
  1. `/etc/paddock/orbit.env` contains `ORBIT_HOST_IDENTIFIER=instance`; `stat -c '%a' /opt/orbit/identifier` is
     `644`; the content matches the token format.
  2. Within 10 minutes, `SELECT host_id FROM device_fleet_binding WHERE device_id = '<id>'` (`paddockSQL`) equals the
     ID of the most recently seen Fleet host with the VM's hardware UUID, and so does `external_id`.
  3. **Upgrade path.** The harness stops `paddock-supervisor`, writes `orbit.env` without the
     `ORBIT_HOST_IDENTIFIER` line, and starts `paddock-supervisor`. Within 15 minutes:
     - a new Fleet host with a higher ID and the VM's UUID is the binding;
     - the previous host's `seen_time` stops;
     - the device's `synced_at` advances after the rebinding;
     - no `device.tamper_fleet_host_claimed` and no `tamper.protected_file_changed` for the VM.
  4. **Second host.** The harness enrolls `EnrollFleetAs(identifier "pdk-f8-"+suffix, uuid = the VM's UUID)` with a
     failing binary policy and answers every 30 s in a goroutine stopped by `t.Cleanup`.
     - Within 30 minutes the org admin sees one `device.tamper_fleet_host_claimed` (`second_host`, `binding device`,
       `bound_host` = step 3's host).
     - Throughout, no `device.tamper_agent_binary_changed` for the VM.
     - Cleanup deletes the extra host through Fleet's API.
  - `fleetHostByUUID` returns the most recently seen host when several exist (earlier runs and step 3 leave stale
    hosts).
  - **Per-VM counts:** `device.tamper_fleet_host_claimed` 1 per VM; 0 for every other device of the run.

### 9. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC-H1 | Given a device that reported its device token, when another host with its hardware UUID was enrolled earlier and fails a policy, then the device's stored inventory and policy results stay those of its bound host, and after 15 min the org admin sees one `device.tamper_fleet_host_claimed` (`second_host`, `binding device`) and a tamper finding | ADR 0057, RR-22 | Org admin (audit log, findings, device inventory) |
| AC-H2 | Given a re-enrollment of a device's speaking host, then the org admin sees one `device.tamper_fleet_host_claimed` (`reenrolled`) and no Fleet-derived agent tamper event for that device for 60 min | ADR 0057 F | Org admin |
| AC-H3 | Given a device whose agent reports no token, then the host Fleet enrolled first is stored, and a later host is reported (`binding first`) | ADR 0057 D | Org admin |
| AC-H4 | Given a token whose host has another hardware UUID, then the device is not bound | ADR 0057 A | Maintainer (acceptance), platform operator (`paddock_inventory_host_bindings_total{result="uuid_mismatch"}`) |
| AC-H5 | Given a second device with a bound device's hardware UUID, then the bound device's inventory keeps syncing | ADR 0057 | Org admin (device inventory shows a recent sync) |
| AC-H6 | Given an upgraded device, then its fleetd re-enrolls once, the new host is bound within 15 min, and no claim event is raised (VM gate F8) | H11 | Org admin; platform operator (Fleet host list) |
| AC-H7 | Given a Fleet database restore that re-enrolls most hosts, then no claim event; the operator sees `reason=claim_majority`, the gauge, and the alert after 15 min | H9 | Platform operator |
| AC-H8 | Given another organization, then its admin never sees these events | isolation | Org admin of globex |
| AC-H9 | An alpha.10 agent against this server and this agent against an alpha.10 server both check in successfully | ADR 0047 | Maintainer (CI `upgrade`, gateway test) |

### 10. Freedoms

- Internal helper names; whether `HostTargets` and the claim watch share an index of `Seen`.
- How `Seen` is collected across pages.
- The order of the params in the event map.
- Whether the per-organization transition statements share one statement.
- Test helper names in `devicesim` and the acceptance package beyond the names this section fixes.
- Where in the existing check-in code `fleetTokenSent` is set, as long as it is set only after HTTP 200.

### 11. Stop conditions

Stop and report to main, without deciding yourself, when:

- **Probe 1(a) or 1(b) fails.** The fleetd in the package does not keep `/opt/orbit/identifier`, or Fleet does not
  resolve it. The device-side design then needs another identity source.
- **Probe 1(c) or 1(d) fails.** Duplicate hosts appear under `provided`, or the reset does not lead to exactly one new
  host.
- **Probe 1(e) fails.** `last_enrolled_at` does not change on a re-enrollment, or changes without one.
- Fleet's host list is not ordered by ascending ID with `order_key=id`.
- A device needs a change in `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, the supervisor, `pkg/bundle/` or
  `api/openapi/admin.yaml`, or a new dependency.
- An existing acceptance or system gate starts recording `device.tamper_fleet_host_claimed`, or loses inventory.
- The VM gate shows `uuid_mismatch` for a real device.
- The production size exceeds about 1050 hand-written lines (section 13, H13).
- Probe (f) of H14 fails: the reset re-uses the previous host record.
- `TestFleetDeviceTokenNeverLogged` cannot be made green without changing a shared logging or error path outside the
  files of section 5.
- The migration lint refuses `CREATE OR REPLACE` of `paddock_inventory_devices`.

### 12. Risks and open points

- **Agents not yet updated** stay in mode `first`. A further enrollment of their host is reported and held. The
  changelog and the release notes ask operators to update agents. Default: accepted
  (RR-22 text above).
- **Stale previous hosts in Fleet** (one per updated device). Follow-up PDK-1123a removes the hosts that no device is
  bound to and that have been silent for 24 hours, with an audit event. Default: alpha.12.
- **Two unbound devices with one hardware UUID** still stop each other's inventory (`HAVING count(*) = 1`). Follow-up
  PDK-1122i, reduced to this case and a report of it. Default: alpha.12.
- **A rollout wave that re-enrolls many devices at once** can open short claim episodes. They never become due (H7);
  only H9's count can briefly suppress other claims, which the 15-minute alert delay absorbs.
- **Clock skew between Fleet and the worker** affects only the comparison of `R` with `seen_time` (both Fleet's
  clock); the episode timers use the worker's clock.
- **A lost osquery database** (fleetd purged by an administrator) creates a new host. The device's next token binds
  it (`rebound`); no event. If Fleet re-uses the record instead, the result is one `reenrolled` claim.
- **The device token passes through RabbitMQ and Postgres.** It lives for at most an hour, opens only Fleet's
  unpublished device endpoints, and is cleared after the decision. Accepted.

### 13. Size (estimate)

| Part | Lines | Files |
| --- | --- | --- |
| Server, hand-written: migration ~70, queries ~45, ports ~25, Fleet adapter ~60, `binding.go` ~100, `claims.go` ~150, app ~170, worker ~140, gateway/ingest/reports ~35, protocol and OpenAPI ~15, registry/finding/messages ~25, alert ~12, compose 2 | about 850 | 16 |
| Device side, hand-written: agent check-in ~35, reconciler H2 ~40, `RemoveAll` and fake ~15 | about 90 | 4 |
| Generated (`pgstore`, audit doc, TS codes) | about 150 | 4 |
| Tests: unit ~380, adapter ~80, app ~260, worker ~380, gateway/reports ~80, agent ~180, devicesim ~140, acceptance ~380, system ~200, rules ~15 | about 2100 | 14 |
| Docs by the implementer | about 70 | 6 |

**PDK-1123: about 940 hand-written production lines** (850 server, 90 device), within the ~1000 bound. H13 and H14
add about 70 (server ~45: migration, queries, gateway, ingest, claim rule; device ~25: state, announcement) and about
180 test lines: **about 1010 production lines**, below the stop at 1050. Not
protocol-breaking: one optional request field. VM time: F8 adds about 35 minutes per VM, with the VMs in parallel.

## Amendment 2026-11-17 e — review round 1 (architect, PDK-1123)

Status: **accepted** (main, `decisions-alpha11.md` §163). It decides the findings of review round 1 on `06088289`
(internal review and external code review). It changes H5, H6, H7, H9 and the migration of amendment e. Where this
section and amendment e differ, this section wins. ADR 0057 records it in its amendment "2026-11-17, review round 1".

### R-1 Terms (added)

- **stored host** of a device: its `device_inventory_ref.external_id`.
- **valid bound host**: the bound host is listed **and** its lower-case hardware UUID equals the binding's
  `HardwareUUID`.
- **suspended binding**: a binding whose bound host is not valid, either because it is not listed or because it is
  listed with another hardware UUID.
- **host in use** by a device: the device's bound host, or its stored host, for an active or quarantined device.

### R-2 Decisions

**F1 A bound host counts only with the device's hardware UUID.**

- H5 rule 2 (`DecideCurrent` without a Fleet call) applies only to a **valid** bound host that is live. A suspended
  binding resolves its pending token (rule 3 onwards).
- H6 rule 1 stores a host for its bound device only if the host is the device's valid bound host. A bound host
  listed with another hardware UUID is stored for no device. It is counted `ignored`, and
  `Targets.Bound` does not contain it.
- **The binding is kept, and suspended.**
  - `device_fleet_binding` gains `suspended_at timestamptz`.
  - Each round, after H5, the worker sets `suspended_at = now` for every binding that is suspended and has
    `suspended_at` NULL. It sets `suspended_at = NULL` for every binding whose bound host is valid again, and on every
    bind or rebind (`BindInventoryHost` clears it).
  - While suspended, nothing is stored for the device, and the device's next token that resolves to a valid host
    rebinds it (rule 9). orbit re-enrolls and rotates its token when Fleet no longer knows its keys, so a device whose
    host vanished, or whose ID Fleet gave to another machine, names a new host within about one token rotation.
  - A token that resolves to the same ID with another UUID is `uuid_mismatch` (rule 6). The binding stays suspended.
- **Claims while suspended.**
  - For up to `ClaimQuiet` (60 min) after `suspended_at`, live other claimants of the device do not count as
    **second host**, as for H14's resetting device.
  - After 60 minutes, the normal rule applies again, and the worker logs `Warn` `inventory binding suspended`
    (`organization_id`, `device_id`, `since`) once per round and device.
  - A `reenrolled` claim never depends on suspension.
- New gauge `paddock_inventory_bindings_suspended`: the number of suspended bindings in the round. The round's process
  sets it; a non-leader sets 0.

**F2 The host that speaks for an unbound device is sticky.**

- The speaking host of a device that is not bound (mode `first`) is chosen in this order:
  1. its **stored host**, if that is listed with the device's lower-case hardware UUID and is not in use by another
     device;
  2. otherwise, the listed host with the lowest Fleet ID, among the hosts with the device's UUID that are neither
     bound to any device nor in use by another device. This is the initial choice, and the choice after the stored
     host disappeared, changed its UUID, or became another device's host.
- Every other listed host with the device's UUID is a claimant (H7).
- **A change of the speaking host counts as a re-enrollment.** When a device in mode `first` has a stored host and the
  round's speaking host differs from it, H7's **re-enrolled** holds for the device in that round. That sets
  `fleet_reenrolled_at` (the H8 hold applies) and reports the claim at once with kind `reenrolled`. A rebind of a bound
  device stays a rebinding (not counted).
- One pure function decides it, `inventory.FirstSpeaker(uuid string, stored ports.HostRef, hosts []ports.HostSeen, t
  Targets) ports.HostRef` (hosts in list order). The store rule (H6 rule 3) and the claim watch (H7) both use it, so
  they never disagree.
- `Targets.First` is removed. `Targets` gains `InUse map[ports.HostRef]uuid.UUID`: the device for which a host is in
  use (bound or stored).
- **Data:** the worker loads `paddock_inventory_claim_devices` once per round, **before** H5. The function returns active
  **and** quarantined devices with a stored host and gains the column `active boolean` (the claim watch watches only
  active rows; `Watched` counts only active rows). The round uses the pre-store values for H7 in step 5. A
  `reenrolled` comparison therefore sees the host that was stored before the round.

**F3 `paddock_inventory_devices` keeps counting bound devices.** Migration 00163 drops its `CREATE OR REPLACE
FUNCTION paddock_inventory_devices` (00163 is not merged or released, so it is changed in place). The function
stays as migration 00024 defines it. A bound device is stored through its binding (H6 rule 1), never through
`MapHosts`, so goal 4 holds. A device that shares a bound device's UUID and is not bound makes the UUID ambiguous, and
no host is stored for it.

**R1 New H5 rule 6b: a host in use by another device is never bound.** After rule 6 and before rule 7:

| # | Condition | Action | `result` label |
| --- | --- | --- | --- |
| 6b | the resolved host is in use by another active or quarantined device (its bound host or its stored host) | clear the token; `Warn` `inventory host binding refused` (`organization_id`, `device_id`, `host`, `reason` `host_in_use`) | `host_in_use` |

- No audit event: the requesting device's organization must not learn that another device uses the host, and the
  other device's organization must not learn about the requesting device. The other device keeps its host. A
  re-enrollment of that host is reported to its organization by H7.
- The legitimate case is a machine enrolled again in Paddock while its previous device record is still active. Its
  new device record is refused until the previous one is retired. fleet.md states this.

**F4 The wave guard counts re-enrollment episodes only, per binding mode.** H9 changes:

- `Claimed(mode)` = the active watched devices of that binding mode (`device` or `first`) whose open episode saw a
  re-enrollment in the round's decision: `fleet_reenrolled_at >= fleet_claim_since`, or re-enrolled this round.
- `Watched(mode)` = the active watched devices of that mode.
- For each mode separately: if `Claimed(mode) >= 3` and `2 × Claimed(mode) > Watched(mode)`, no `reenrolled` claim of
  that mode is reported this round.
- `second_host` claims are **never** suppressed.
- The log `inventory claim watch suppressed` gains the attribute `binding` (one `Warn` per suppressed mode). The gauge
  `paddock_inventory_claim_watch_suppressed` gains the label `binding` (`device`, `first`). The alert keeps its
  expression with `max(...)` over both labels.
- Why: a Fleet restore shows as many re-enrollments of one binding mode at once. Claims of another host and the
  re-enrollments of the other mode keep being reported.
- **A real Fleet database restore, for bound devices:**
  - A host enrolled before the dump and not enrolled again since keeps its ID, its identifier and its node key. Nothing
    happens.
  - A host enrolled again after the dump has a stale node key in the restored database. Its fleetd enrolls again under
    its instance ID and finds the same record (same ID): `reenrolled`.
    - If that is most bound devices (at least 3 and more than half), the guard suppresses these claims. The H8 hold
      keeps agent reports waiting for 60 minutes. The episodes end without a report, and the operator sees
      `PaddockInventoryClaimWatchSuppressed` with `binding="device"`.
    - If it is a minority, each of them is reported once as `reenrolled`. Each such report is correct (the host was
      enrolled again), and their number is bounded by the hosts enrolled again since the dump.
  - A host created after the dump is missing from the restored database, or its ID is given to another machine that
    enrolls after the restore. The binding is suspended (F1), nothing is stored, and there is no `second_host` for 60
    minutes. fleetd enrolls anew, the next token rebinds the device, and the suspension ends.
  - **Result:** no wave of false reports, and no lasting blind spot. Suspended bindings show in
    `paddock_inventory_bindings_suspended`, and the suppression in the alert. After 60 minutes the normal rules apply
    again.
- **Devices in mode `first`** behave as before, guarded within their own mode. That repeated re-enrollments of an
  unbound device keep its hold open is residual RR-22 (agent not updated).

**L1 A host bound to two devices.** Rule 6b refuses a host in use by another device. A double binding can still arise
for a while after a Fleet rebuild (corrected in review round 3, §L-15). A double binding left from before the fix stays in `Targets.Excluded`, is stored for nobody, and is logged once per
round as `Warn` `inventory host bound to several devices` (`host`, `devices`). No audit event.

**L2 Resolve throughput in large waves.** Decided:
- H5 decides the bindings of devices that are resetting (H14) or suspended (F1) first, then the others by
  `token_reported_at`.
- Residual, documented in `docs/operations/upgrade.md` and `fleet.md`: more than about 1,500 agent updates per hour
  in one installation can leave a device unresolved for longer than 60 minutes. That device then gets one false
  `second_host` report. Keep rollout waves below that rate. `ResolvePerRound` stays 200.

**L3 Unknown heartbeat fields.**
- The worker's `Reports.heartbeat` decodes `ingest.Heartbeat` **without** `DisallowUnknownFields`, through a new
  `decodeLenient`. Every other message type keeps `decode`.
- Why: the gateway may add an optional heartbeat field in a release while an older worker still consumes, and a
  heartbeat is a status report that the next check-in replaces.
- An alpha.10 worker still dead-letters alpha.11 heartbeats while the roles of one installation are upgraded
  non-atomically. `docs/operations/upgrade.md` (alpha.11 notes) states: "Upgrade all roles together (`./paddock up`
  does). A `PaddockDLQ` alert during the upgrade window can come from heartbeats; they need no replay."

### R-3 Texts (replace amendment e's versions; neutral)

- **RR-22**, risk column, the part from "Each device's inventory host…" to the end of the cell: "A device whose agent
  runs 0.1.0-alpha.11 or later names its inventory host over its signed device connection, and only that host's data
  is stored for it. For a device whose agent has not done so yet, the host Paddock already stores for it keeps
  speaking for it while Fleet lists it with the device's hardware UUID (residual until the agent is updated). Another
  host that claims a device, a re-enrollment of the host that speaks for it, and a change of that host are reported as
  `device.tamper_fleet_host_claimed` (ADR 0057)."
- **RR-149**: the item stays "a device whose agent has not named its inventory host yet, while the host Paddock
  already stores for it is used (RR-22);".
- **Changelog** `changelog.d/pdk-1123.security.md`, replace "a device whose agent predates this release uses the host
  Fleet enrolled first until it updates" with "until a device's agent is updated, the inventory host Paddock already
  stores for it keeps speaking for it, and a change of that host is reported".
- **`docs/operations/fleet.md`**:
  - "Inventory sync and mutual watch", step 3: replace "uses the host Fleet enrolled first for its hardware UUID"
    with "keeps the host Paddock already stores for it while Fleet lists it with the device's hardware UUID (the
    lowest Fleet ID when none is stored yet)". Add: "A host that already speaks for another device is never bound to
    a device (`result="host_in_use"`); retire a device's previous record before you enroll the machine again."
  - Move the claim-watch paragraph ("It reports, once per episode, `device.tamper_fleet_host_claimed` …") out of the
    binary-policy item into its own numbered step after it. Replace its last sentence with: "A Fleet database restore
    re-enrolls many hosts at once; the worker then holds the re-enrollment reports of the affected binding mode
    (`claim_majority`, label `binding`). A bound host that Fleet no longer lists with the device's hardware UUID
    suspends the device's binding until the device names its new host (`paddock_inventory_bindings_suspended`)."
  - The runbook "When the inventory claim watch is suppressed" counts re-enrollment episodes only and names the label
    `binding`.
- **Event description** `device.tamper_fleet_host_claimed`:
  - replace "kind reenrolled: the host that speaks for the device was enrolled again, which also happens when fleetd's
    local state on the device is lost." with "kind reenrolled: the host that speaks for the device was enrolled again,
    which also happens when fleetd's local state on the device is lost, or, for a device that has not named its host,
    another host took the place of the one stored for it.";
  - replace "first when it has not named one yet and the host the inventory system enrolled first for its hardware UUID
    speaks for it" with "first when it has not named one yet and the host already stored for it (else the one with the
    lowest ID) speaks for it".
  - `make gen` updates the audit document.
- **ADR 0057 Decision rule** "A host that no device is bound to maps through the hardware UUID only to an unbound
  device, and only if it is that device's first-enrolled host" reads, through the ADR amendment, "…only if it is the host
  already stored for that device, or, when none is stored or it is gone, the one with the lowest ID".

### R-4 Regression tests (each MUST fail on `06088289`; the mutation or the failing assertion goes into the result document)

Model: the review's own probe tests (worker package, testcontainers DB, fake source and binder; kept out of the
repository).

| Test | Package | Covers | Fails on 06088289 because |
| --- | --- | --- | --- |
| `TestDecideBindingCurrentNeedsHardwareUUID` | inventory | F1 rule 2 | the shortcut returns `DecideCurrent` for a live bound host with another UUID |
| `TestInventoryRoundBoundHostListedWithOtherUUID` | worker | F1: bound host 100 listed with W's UUID → nothing stored for V, V's pending token resolved (binder called), binding suspended, no claim, no agent tamper event; V's new token → rebind, suspension cleared, V stored again | V stores host 100, binder not called, one `device.tamper_agent_binary_changed` |
| `TestInventoryRoundSuspendedBindingNoSecondHostFor60Min` | worker | F1 claims | without suspension, the new host raises `second_host` after 15 min |
| `TestInventoryRoundOlderHostDoesNotReplaceStoredHost` | worker | F2: unbound V stores host 20; host 10 starts reporting V's UUID → V still stores 20; no agent tamper event from 10; `second_host` after 15 min | V stores 10 at once; agent tamper events from host 10; 0 claims |
| `TestInventoryRoundFirstSpeakerReplacedIsReenrolled` | worker | F2: stored host 20 disappears → 10 speaks, claim `reenrolled` at once, agent reports held 60 min | 10 stored without claim or hold |
| `TestInventoryRoundDuplicateOfBoundDeviceGetsNothing` | worker | F3: bound V (previous host 7 stale), unbound X with V's UUID → nothing stored for X; V keeps its bound host | X stores host 7 |
| `TestInventoryDevicesCountsBoundDevices` | app | F3 (replaces `TestInventoryDevicesIgnoresBound`) | the bound device is not counted |
| `TestInventoryRoundRefusesHostInUse` | worker | R1: X' token resolves to Y's stored host → `host_in_use`, no binding, nothing stored for X', Y unchanged | X' binds and stores Y's host |
| `TestWatchClaimsGuardCountsReenrollmentsPerMode` | inventory | F4: 4 of 6 devices with live second hosts → all reported; 4 of 6 bound re-enrolled → `device` suppressed; 4 of 5 `first` re-enrolled and 1 of 4 bound re-enrolled → the bound one reported | the guard counts second hosts and both modes together |
| `TestInventoryRoundFleetRestoreBoundDevices` | worker | F4 restore: 5 bound devices — 3 re-enrolled (same IDs), 2 hosts vanished and re-created → no claim event across 70 min, held reports, 2 suspended then rebound, gauges as stated | the 2 re-created hosts raise `second_host`, or the round stores foreign data |
| `TestBindHostsResettingAndSuspendedFirst` | worker | L2 ordering with `ResolvePerRound` = 2 in the test | oldest token first |
| `TestReportsHeartbeatToleratesUnknownFields` | worker | L3: an alpha.11 heartbeat JSON with an extra field `future_field` is recorded, not dead-lettered; an older-style struct without the fleet fields decodes an alpha.11 heartbeat | `decode` refuses unknown fields |
| `TestHostTargetsDoubleBoundLogged` | inventory/worker | L1 warn | no log |

Existing tests that change with the decisions: `TestHostTargets` (no `First`), `TestInventoryRoundFirstEnrolledHost`
(the sticky host), `TestInventoryDevicesIgnoresBound` (replaced), acceptance `TestInventoryHostBinding` step 3 (the
`first` host is the stored one) and step 5 (`same_uuid`: D1 keeps syncing; D5 stores nothing).

**Review.** The external review re-runs the binding probes against the finished stack. The confidential list of
probes is in the ticket.

### R-5 Files

As amendment e, plus:
- `server/migrations/paddock/00163_inventory_host_binding.sql` (changed in place: `suspended_at`; no
  `paddock_inventory_devices`; `paddock_inventory_claim_devices` with quarantined rows and `active`);
- the queries `SuspendInventoryBindings`, `ResumeInventoryBindings` (organization pool, `device_id = ANY(...)`);
- `server/internal/worker/worker.go` (`decodeLenient`);
- `docs/operations/upgrade.md`.

Nothing else is touched.

### R-6 Stop conditions (added)

- The fix needs a change outside amendment e's files and R-5.
- Production growth beyond about 160 lines for this round (section R-7).
- A test of R-4 does not fail on `06088289`, and no mutation makes it fail: report it, do not weaken it.

### R-7 Size (estimate)

| Part | Lines |
| --- | --- |
| Production, hand-written: `binding.go` (F1, R1, `FirstSpeaker`, `InUse`) ~60, `claims.go` (suspension, per-mode guard, replacement) ~45, worker (load order, suspend/resume, ordering, logs, gauges, `decodeLenient`) ~45, migration and queries ~15 (net, after the removed function), app ~10, description ~2 | about +175 / −20, **net about +155** |
| Tests (R-4 and the changed tests) | about +650 |
| Docs | about +40 |

Main accepted 902 code lines for `06088289` (§162). After this round: **about 1060**. That is at the stop of about
1050 and needs main's acknowledgement.

## Amendment 2026-11-17 e — review round 2 (architect, PDK-1123): left inventory hosts

Status: **accepted** (user, via main, 2026-11-17). This section builds on amendment e and its review round 1 and
changes them as stated below. Where this section and the earlier ones differ, this section wins. ADR 0057 records the
rule on hosts listed with another hardware UUID in its amendment "2026-11-17, review round 1".

### L-1 Goal

A Fleet host record that a device no longer speaks from still holds that device's inventory until Fleet forgets it.
After this round, Paddock reserves every such host for the device that left it, so that no other device is bound to it
or stores it, and removes it from Fleet. Organization administrators see each removal as an audit event of the device.
Operators see the removals in a metric. Other organizations see nothing of it.

### L-2 Terms (added to R-1)

- **left host** of a device: a host the device does not speak from any more, while Fleet may still hold the device's
  inventory in it. A host becomes a left host in exactly two ways:
  - **replaced:** the device's stored host changes from host A to another host (`StoreHost`). A becomes a left host.
  - **relisted:** the device's stored host is not its bound host, and Fleet lists it with another hardware UUID than
    the device's. For a device that is not bound, this is any stored host listed with another UUID.
- **reservation**: a row of `device_inventory_left_host` with `removed_at` NULL.
- **reserved host**: the host of a reservation. A reserved host is in use by the reservation's device.

### L-3 Binding decisions

1. **The N1 rule stays for bound hosts only.** A device's **bound** host that Fleet lists with another hardware UUID
   is not in use by that device (review round 1, unchanged, ca7377ab). This covers the device's stored host only when
   the stored host is the bound host. Why: Fleet can give an ID to another machine after a rebuild or restore, and
   that machine must be able to use it.
2. **A relisted stored host stays in use and becomes a left host.** In `inventory.HostTargets`:
   - a stored host listed with another hardware UUID, that is not the same device's bound host, stays in use by that
     device;
   - it is returned in `Targets.Left` with reason `relisted`.

   The worker persists these reservations in the same round, before the store step.
3. **A replaced stored host becomes a left host.** `StoreHost` records the previous stored host as a reservation with
   reason `replaced` in its own transaction, before it upserts the new reference. When the device stores, or is bound
   to, a host for which it has a reservation, `StoreHost` and `BindInventoryHost` delete that reservation in their
   transactions. A device that speaks from the host again therefore keeps it.
4. **Reserved hosts are in use.** `HostTargets` adds every reserved host to `InUse` for its device, unless a binding
   or a stored host already sets it. Effects:
   - H5 rule 6b refuses a token that resolves to a reserved host of another device (`host_in_use`).
   - `FirstSpeaker` does not choose it for another device.
   - The device that left the host may choose it again (decision 3).
5. **Removal.** Every round, after the claim watch, the worker handles up to `LeftHostDeletesPerRound` (50)
   reservations, oldest `left_at` first. It skips a reservation whose `attempted_at` is less than
   `LeftHostRetryAfter` (1 hour) ago. For each reservation:
   1. `PlatformPool.FleetHostInUse(ctx, device, host)` runs; the function is redefined (§L-6).
   2. **`ref`** (another device of any organization and any state stores the host, is bound to it, or holds a
      reservation for it): delete the reservation. No Fleet call, no audit event. Metric `result="in_use"`.
   3. **`none` or `hardware`**: one action `device.inventory_host_removed` through `ActionRunner.RunExternal` in the
      device's organization:
      - `ports.InventoryAdmin.DeleteHost` runs with a 30-second timeout.
      - Success, including Fleet no longer knowing the host: `removed_at = now()` in the finalizing transaction.
        Metric `removed`.
      - `problem.InvalidState`: `attempted_at = now()` in the finalizing transaction. Metric `failed`. The worker
        continues with the next reservation.
      - `problem.UpstreamUnavailable`: the reservation is unchanged. Metric `unavailable`. The removal step ends for
        this round, and the round itself does not fail.
      - Any other error fails the round, like every other database error of the round.
   - Why `hardware` does not block: the left host is a record the device itself no longer speaks from. A device record
     of the same machine without a reference gets a fresh host record from fleetd.
   - Why no race: only the inventory round, which holds the worker's leader lock, writes bindings, stored hosts and
     reservations. Retention and offboarding only delete. The check and the deletion therefore see the same state.
6. **Rows stay after removal.** A row with `removed_at` set is no reservation. It stays so that the same device does
   not record the same host again. It is deleted when the device stores or is bound to that host again (decision 3),
   and by the organization deletion.
7. **Restart safety.** Every reservation is persisted before the host can leave the device's use:
   - `relisted` reservations are written in the round that sees them, before the store step;
   - `replaced` reservations are written in the `StoreHost` transaction.

   A crash between `DeleteHost` and the finalizing transaction leaves the reservation. The next round deletes again;
   a 404 counts as deleted. The interrupted action is finalized as `unknown` by the existing reaper.
8. **Organization deletion and retention.**
   - `device_inventory_left_host` is registered in `offboarding_table` (order 166).
   - The organization deletion's Fleet step also lists the organization's reserved hosts, so they are deleted from Fleet
     like stored hosts. The existing check `FleetHostInUseOutside` applies, redefined in §L-6.
   - A retired device's reservations are still removed by the round. Retention does not change. Through the redefined
     `paddock_fleet_host_in_use`, it keeps a retired device's host that another device has reserved, is bound to or
     stores.
9. **Signals.**
   - Audit event `device.inventory_host_removed`, one per attempt, in the device's own organization. Params:
     `hostname`, `fleet_host` (the device's own former host ID), `reason` (`replaced` or `relisted`), `left_at`,
     `fleet_host_deleted`. No other device's or organization's identifier, no token, no hardware UUID.
   - Counter `paddock_inventory_previous_hosts_total{result}` with results `removed`, `in_use`, `failed` and
     `unavailable`.
   - The logs are below. Every one names only the reservation's own organization, device and host:
     - `Info` `inventory left host removed` (`organization_id`, `device_id`, `host`, `reason`);
     - `Info` `inventory left host released` (`organization_id`, `device_id`, `host`), for `in_use`;
     - `Warn` `inventory left host not removed` (`organization_id`, `device_id`, `host`, `error`), for `failed`;
     - `Warn` `removing left inventory hosts failed; retrying next round` (`error`), for `unavailable`.
   - The `in_use` outcome records no event. The device's organization must not learn that another device uses the
     host (as rule 6b).
10. **Cost after a Fleet rebuild, accepted and documented.** After a Fleet rebuild or restore, a stored host ID can
    name another machine's record. When that record is a left host of a device and no device stores it, is bound to
    it or holds a reservation for it yet, it is removed. That machine's fleetd then enrolls again under a new ID, and
    its device names it with its next token (bound) or speaks from it (not bound). Each such removal is recorded as
    `device.inventory_host_removed`. Unbound devices whose stored IDs Fleet swapped among them recover this way
    within a few rounds instead of waiting for each other.

### L-4 Non-goals

- No removal of hosts that never spoke for a device, such as hosts that map to no device or second hosts that claim a
  device. Those stay as they are, reported by the claim watch.
- No change to H5's rules other than the source of `InUse`, to H7 to H9, or to the agent.
- No change to the retention round's code or to `device.inventory_purged`.
- No change to the device API, the admin API or the portal beyond the two message keys.
- PDK-1123a's 24-hour removal of silent unbound hosts is replaced by this round. Nothing else of it is built.

### L-5 Files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/00163_inventory_host_binding.sql` | change in place (not released) | table, offboarding registration, two redefined functions, one new platform function |
| `server/internal/adapters/postgres/queries/inventory.sql` | change | queries of §L-6 |
| `server/internal/adapters/postgres/queries/offboarding.sql` | change | `ListOffboardingInventoryRefsPage` also lists reserved hosts |
| `server/internal/adapters/postgres/pgstore/*` | regenerate (`make gen`) | |
| `server/internal/inventory/binding.go` | change | `LeftHost`, constants, `HostTargets` (decisions 1, 2, 4) |
| `server/internal/app/inventory.go` | change | `StoreHost`, `BindInventoryHost`, `InventoryLeftHosts`, `RecordLeftInventoryHosts`, `RemoveLeftInventoryHost` |
| `server/internal/domain/audit/codes.go` | change | `CodeDeviceInventoryHostRemoved` and its registry entry |
| `server/internal/worker/inventory.go` | change | `WithAdmin`, loading and persisting reservations, removal step, metric |
| `server/cmd/paddock-server/worker.go` | change | `.WithAdmin(fleetClient)` |
| `server/web/src/locales/en.json`, `de.json` | change | `audit.device.inventory_host_removed` |
| generated `docs/compliance/audit-codes.md` and `server/web/src/lib/auditCodes.gen.ts` (`make gen`) | regenerate | |
| `server/internal/siemcontent/wazuh_test.go` | change | the new code joins the base-level list (as `device.inventory_host_kept`) |
| `docs/operations/fleet.md`, `docs/operations/monitoring.md`, `docs/compliance/residual-risks.md` | change | texts of §L-9 |
| tests of §L-8 | new or change | |

Do not touch: the Fleet adapter (`DeleteHost` is used as it is), `server/internal/app/retention.go`,
`server/internal/app/offboarding_job.go` (only its query changes), the agent, `api/openapi/`, and
`changelog.d/pdk-1123.security.md` except the sentence of §L-9.

### L-6 Interfaces, data model and texts

Migration 00163 (appended in place; it is not merged or released):

```sql
CREATE TABLE device_inventory_left_host (
  device_id uuid NOT NULL REFERENCES device(id),
  organization_id uuid NOT NULL,
  host_id text NOT NULL CHECK (host_id ~ '^[0-9]{1,19}$'),
  reason text NOT NULL CHECK (reason IN ('replaced','relisted')),
  left_at timestamptz NOT NULL,
  attempted_at timestamptz,
  removed_at timestamptz,
  PRIMARY KEY (device_id, host_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_inventory_left_host_host ON device_inventory_left_host (host_id) WHERE removed_at IS NULL;
-- The organization deletion deletes by organization_id.
CREATE INDEX device_inventory_left_host_org_idx ON device_inventory_left_host (organization_id);
ALTER TABLE device_inventory_left_host ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_inventory_left_host FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_inventory_left_host TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON device_inventory_left_host TO paddock_worker;
INSERT INTO offboarding_table (table_name, delete_order) VALUES ('device_inventory_left_host', 166);

-- Reservations of active organizations, any device state, oldest first (platform pool).
CREATE FUNCTION paddock_inventory_left_hosts()
  RETURNS TABLE (device_id uuid, organization_id uuid, host_id text, reason text, left_at timestamptz,
                 attempted_at timestamptz, hostname text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT l.device_id, l.organization_id, l.host_id, l.reason, l.left_at, l.attempted_at, d.hostname
     FROM public.device_inventory_left_host l JOIN public.device d ON d.id = l.device_id
          JOIN public.organization o ON o.id = l.organization_id
     WHERE l.removed_at IS NULL AND o.status = 'active'
     ORDER BY l.left_at, l.device_id, l.host_id $$;
REVOKE ALL ON FUNCTION paddock_inventory_left_hosts() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_inventory_left_hosts() TO paddock_platform;
```

`paddock_fleet_host_in_use(retired_device uuid, host text)` and `paddock_fleet_host_in_use_outside(org uuid, host
text)` are redefined in 00163 with `CREATE OR REPLACE FUNCTION`. The signature, return values, search path,
`SECURITY DEFINER` and grants stay the same. Only the `'ref'` branch widens. It answers `'ref'` when any of these
holds:
- `device_inventory_ref.external_id = host`;
- `device_fleet_binding.host_id = host`;
- `device_inventory_left_host.host_id = host AND removed_at IS NULL`.

Each condition applies to a device other than `retired_device` (resp. an organization other than `org`), and to a
device in any state. The `'hardware'` branch is unchanged. Retention and the organization deletion keep their Go
code, because they already handle `'ref'`.

Queries (`inventory.sql`, organization pool unless stated):

```sql
-- name: RecordReplacedInventoryHost :exec
INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
SELECT r.device_id, r.organization_id, r.external_id, 'replaced', now() FROM device_inventory_ref r
WHERE r.device_id = @device_id AND r.external_id <> '' AND r.external_id <> @external_id::text
ON CONFLICT (device_id, host_id) DO NOTHING;

-- name: RecordRelistedInventoryHost :exec
INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
VALUES (@device_id, @organization_id, @host_id, 'relisted', @left_at)
ON CONFLICT (device_id, host_id) DO NOTHING;

-- name: ForgetLeftInventoryHost :exec
DELETE FROM device_inventory_left_host WHERE device_id = @device_id AND host_id = @host_id;

-- name: LockLeftInventoryHost :one
SELECT host_id FROM device_inventory_left_host
WHERE device_id = @device_id AND host_id = @host_id AND removed_at IS NULL FOR UPDATE;

-- name: MarkLeftInventoryHostRemoved :exec
UPDATE device_inventory_left_host SET removed_at = now() WHERE device_id = @device_id AND host_id = @host_id;

-- name: MarkLeftInventoryHostAttempted :exec
UPDATE device_inventory_left_host SET attempted_at = now() WHERE device_id = @device_id AND host_id = @host_id;

-- name: InventoryLeftHosts :many   (platform pool)
SELECT l.device_id::uuid AS device_id, l.organization_id::uuid AS organization_id, l.host_id::text AS host_id,
       l.reason::text AS reason, l.left_at::timestamptz AS left_at,
       coalesce(l.attempted_at, 'epoch')::timestamptz AS attempted_at, l.hostname::text AS hostname
FROM paddock_inventory_left_hosts() l;
```

`offboarding.sql`, `ListOffboardingInventoryRefsPage` (same name, parameters and result columns):

```sql
SELECT DISTINCT ON (external_id) external_id, device_id FROM (
  SELECT external_id, device_id FROM device_inventory_ref WHERE external_id <> ''
  UNION ALL
  SELECT host_id, device_id FROM device_inventory_left_host WHERE removed_at IS NULL) h
WHERE external_id > @after_external_id::text ORDER BY external_id, device_id LIMIT @max_hosts;
```

Go (`server/internal/inventory/binding.go`):

```go
// Reasons a host became a left host (plan M5a amendment e, review round 2).
const (
	LeftReplaced = "replaced"
	LeftRelisted = "relisted"
)

const (
	// LeftHostDeletesPerRound bounds the left hosts the worker removes from the inventory system per round.
	LeftHostDeletesPerRound = 50
	// LeftHostRetryAfter is how long a left host the inventory system refused to delete waits for the next attempt.
	LeftHostRetryAfter = time.Hour
)

// LeftHost is a host a device no longer speaks from, reserved for it until the inventory system deleted it.
type LeftHost struct {
	DeviceID, OrganizationID uuid.UUID
	Host                     ports.HostRef
	Reason                   string
	Hostname                 string
	LeftAt                   time.Time
	AttemptedAt              *time.Time
}

// Targets gains:
//	// Left holds the stored hosts listed with another hardware UUID than their device's that are not that device's
//	// bound host, in device order; the worker records them as left hosts (reason LeftRelisted).
//	Left []LeftHost

func HostTargets(seen []ports.HostSeen, bindings []Binding, devices []ClaimDevice, left []LeftHost) Targets
```

`HostTargets` rules, in this order:
1. Bindings: as today. A bound host is in use by its device unless it is relisted.
2. Stored hosts. For each device `d` with `d.ExternalID != ""` and no `InUse` entry yet for that host:
   - if the host is relisted and equals `d`'s bound host (from `bindings`, `Host != ""`): not in use;
   - if the host is relisted and does not equal it: `InUse[host] = d.DeviceID`, and append
     `LeftHost{DeviceID, OrganizationID, Host, Reason: LeftRelisted}` to `Left`;
   - otherwise: `InUse[host] = d.DeviceID`.
3. Reservations. For each `left` entry without an `InUse` entry for its host: `InUse[host] = entry.DeviceID`.

App (`server/internal/app/inventory.go`):

```go
// InventoryLeftHosts returns the reservations of active organizations, oldest first (platform pool).
func (s *InventorySync) InventoryLeftHosts(ctx context.Context) ([]inventory.LeftHost, error)

// RecordLeftInventoryHosts records relisted stored hosts of devices of the organization in ctx as left hosts.
func (s *InventorySync) RecordLeftInventoryHosts(ctx context.Context, hosts []inventory.LeftHost, now time.Time) error

// LeftHostOutcome is the result of RemoveLeftInventoryHost.
type LeftHostOutcome int

const (
	LeftHostRemoved LeftHostOutcome = iota // deleted from the inventory system (or unknown to it)
	LeftHostInUse                          // another device uses it; the reservation was deleted, nothing recorded
)

// RemoveLeftInventoryHost applies decision 5 to one reservation in the organization in ctx (system principal).
// It returns problem.UpstreamUnavailable or problem.InvalidState from DeleteHost unchanged (wrapped).
func (s *InventorySync) RemoveLeftInventoryHost(ctx context.Context, h inventory.LeftHost,
	admin ports.InventoryAdmin) (LeftHostOutcome, error)

// SpecDeviceInventoryHostRemoved records the removal of a left host; system principal only.
var SpecDeviceInventoryHostRemoved = ActionSpec{Code: audit.CodeDeviceInventoryHostRemoved}
```

- `StoreHost` runs `RecordReplacedInventoryHost(device, ref)` before `UpsertInventoryRef` and
  `ForgetLeftInventoryHost(device, ref)` after it, in the same transaction.
- `BindInventoryHost` runs `ForgetLeftInventoryHost(device, host)` in its transaction when the compare-and-set
  updated a row.
- `RemoveLeftInventoryHost`:
  - It calls `s.platform.FleetHostInUse`. On `db.FleetHostUsedByRef`, it runs `ForgetLeftInventoryHost` in the
    organization and returns `LeftHostInUse`.
  - Otherwise it calls `s.runner.RunExternal(ctx, ScopeOrg, spec, prepare, external, finalize)`, where:
    - `spec` has the target `{Type: "device", ID, Display: hostname}`, the params `hostname`, `fleet_host`, `reason`,
      `left_at` (RFC 3339) and `fleet_host_deleted` (false);
    - `prepare` runs `LockLeftInventoryHost`; a missing row returns `problem.NotFound`;
    - `external` runs `admin.DeleteHost` under a 30-second timeout;
    - `finalize` runs `MarkLeftInventoryHostRemoved` and sets `fleet_host_deleted` true when there is no error. On
      `problem.InvalidState` it runs `MarkLeftInventoryHostAttempted`. On any other error it changes nothing.

Worker (`server/internal/worker/inventory.go`):

```go
// WithAdmin makes the sync round remove left inventory hosts through a (plan M5a amendment e, review round 2); nil
// removes none.
func (i *Inventory) WithAdmin(a ports.InventoryAdmin) *Inventory

var metricPreviousHosts = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_inventory_previous_hosts_total",
	Help: "Left inventory hosts the sync round handled, by result: removed from Fleet, released because another device uses them, failed or unavailable (ADR 0057).",
}, []string{"result"})
```

Round order:
1. The existing steps up to `InventoryClaimDevices`.
2. **`InventoryLeftHosts`.**
3. `bindHosts`, with the reservations passed into its `HostTargets` call.
4. `HostTargets(seen, bindings, devices, left)`.
5. **`RecordLeftInventoryHosts` per organization for `targets.Left`.**
6. Store.
7. Claim watch.
8. **The removal step** (decision 5). It reloads `InventoryLeftHosts` so that it sees this round's `replaced`
   reservations. It does nothing when `WithAdmin` was not called.
9. The agent reports and the summary, as today.

Audit registry (`server/internal/domain/audit/codes.go`):

```go
// CodeDeviceInventoryHostRemoved: a host the device no longer speaks from was removed from the inventory system (ADR 0057).
CodeDeviceInventoryHostRemoved Code = "device.inventory_host_removed"

CodeDeviceInventoryHostRemoved: {
	Code: CodeDeviceInventoryHostRemoved, Emitted: true,
	Description: "The inventory round removed from Fleet a host that the device no longer speaks from (actor: system). reason replaced: the host Paddock stores for the device changed and fleet_host was the previous one; reason relisted: Fleet lists fleet_host, the host stored for the device, with another hardware UUID. Until it is removed, the host is reserved for the device: no other device is bound to it or stores it. left_at is when it was left. fleet_host_deleted is true when Fleet deleted the host or no longer knew it. A host that another device stores, is bound to or holds reserved is not removed and records no event. A failure keeps the reservation: upstream_unavailable when Fleet failed or could not be reached (retried next round), invalid_state when Fleet refused this host (retried after an hour). After a Fleet rebuild, the removed host can be another machine's record; that machine's fleetd enrolls again under a new ID.",
	Params:      []string{"hostname", "fleet_host", "reason", "left_at", "fleet_host_deleted"},
	Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
	Note:        "Deletion evidence (ISO/IEC 27001 A.8.10); ADR 0057.",
},
```

Messages (`server/web/src/locales/*.json`, key `audit.device.inventory_host_removed`):
- en: `"Fleet host {fleet_host}, which {hostname} no longer speaks from, was removed from Fleet"`
- de: `"Der Fleet-Host {fleet_host}, über den {hostname} nicht mehr spricht, wurde aus Fleet entfernt"`

### L-7 Steps

1. **Migration and queries** (`make gen`). Check: `make gen` produces no further diff, `make lint` (RLS lint) is green,
   and `go test ./server/internal/platform/db/ -run 'TestOffboarding|TestFleetHostInUse'` is green.
2. **`inventory` package.** Check: `go test ./server/internal/inventory/ -run 'TestHostTargets|TestWatchClaims'`.
3. **App and registry.** Check: `go test ./server/internal/app/ -run
   'TestStoreHost|TestBindInventoryHost|TestRemoveLeftInventoryHost|TestFleetHostInUse'` and `go test
   ./server/internal/domain/audit/`.
4. **Worker and wiring.** Check: `go test ./server/internal/worker/ -run 'TestInventoryRound'`.
5. **Messages and docs** (§L-9); quality gate (`make typecheck`, the full `go test` with `nice -n 19`).

### L-8 Tests

Each regression test MUST fail on ca7377ab. The mutation or the failing assertion goes into the result document.

| Test | Package | Covers |
| --- | --- | --- |
| `TestHostTargetsLeftHosts` | inventory | an unbound device's stored host listed with another UUID: in use by it and in `Left`; a bound device's stored host equal to its relisted bound host: not in use, not in `Left`; a bound device's stored host that is not its bound host, relisted: in use and in `Left`; a reservation: in use by its device unless a binding or stored host sets it |
| `TestInventoryRoundLeftHostNotBoundElsewhere` | worker | the review's probe across **3 rounds**. Setup: unbound V stores host 5 and also has host 6 with V's UUID. Host 5 is then listed with D's UUID, and D reports a token for 5 before each round. Assertions: D never binds or stores 5; V stores 6 with one `reenrolled` claim; `DeleteHost(5)` is called exactly once; one `device.inventory_host_removed` (success, reason `relisted`) in V's organization; none in D's |
| `TestInventoryRoundPreviousHostRemovedAfterBind` | worker | V stores 5; V binds new host 9 by token and stores 9; host 5 is removed in that round's removal step (reason `replaced`); a new worker instance created between the store and the removal still removes it |
| `TestInventoryRoundLeftHostUsedElsewhereNotDeleted` | worker | V's left host 5 is stored for (and in a second case bound to, and in a third case reserved for) device Y of another organization. No `DeleteHost`, V's reservation is deleted, metric `in_use` +1, no event in either organization; no log record or metric label contains Y's or Y's organization's ID |
| `TestInventoryRoundLeftHostDeleteRetried` | worker | `DeleteHost` returns `UpstreamUnavailable`: reservation kept, removal step stops (the second reservation is not tried), round succeeds, one failure event; next round deletes. `InvalidState`: `attempted_at` set, not tried again within 1 hour, tried after it. A 404 counts as removed |
| `TestInventoryRoundLeftHostReservedUntilRemoved` | worker | while V's left host 5 is reserved (`WithAdmin` not called), D's token for 5 is refused `host_in_use` across rounds; an unbound device whose UUID Fleet lists on 5 does not store it |
| `TestInventoryRoundLeftHostCap` | worker | 60 reservations → 50 handled in the first round, 10 in the second |
| `TestInventoryRoundUnboundHostIDsSwapped` | worker | unbound V stores 5 and unbound W stores 6; Fleet lists them swapped. Both hosts are removed; after the fake re-enrolls both machines under new IDs, V and W store their new hosts; no `second_host` claim during the rounds; no deadlock (each device stores a host within 3 rounds after its new host is listed) |
| `TestInventoryRoundHostIDsSwapped` | worker | unchanged (bound devices): both rebind crosswise, `host_in_use` +0, no `DeleteHost` of a host that is now bound |
| `TestStoreHostRecordsReplacedHost` | app (integration) | changing the stored host records one reservation; storing the same host again records none; returning to a reserved host deletes its row |
| `TestRemoveLeftInventoryHost` | app (integration) | the outcomes of decision 5; exactly one action per attempt; params as §L-6; nothing recorded on `in_use` |
| `TestFleetHostInUseCoversBindingsAndReservations` | platform/db (integration) | `ref` for another device's binding and for another device's reservation, in another organization and for a retired device; removed rows do not count; `_outside` likewise |
| `TestOffboardingDeletesReservedHosts` | app (integration) | the organization deletion's Fleet step deletes a reserved host of the organization and keeps one that another organization stores |
| `TestEveryRegisteredCodeIsClassified` (existing) | siemcontent | the new code is listed among the codes at the base level, like `device.inventory_host_kept` |

Existing tests that change: `TestHostTargets` and the `claims_test.go` helpers gain the `left` argument (nil).

### L-9 Texts (neutral)

- **`docs/operations/fleet.md`**, "Inventory sync and mutual watch", step 3: append "A host a device no longer speaks
  from (its previous stored host, or a stored host Fleet lists with another hardware UUID) stays reserved for that
  device and is removed from Fleet in the same or the next round (`device.inventory_host_removed`,
  `paddock_inventory_previous_hosts_total`). After a Fleet rebuild or restore, such a host ID can name another
  machine's record; the record is removed and the machine's fleetd enrolls again under a new ID."
- **`docs/operations/monitoring.md`**: a row for `paddock_inventory_previous_hosts_total{result}` with the four
  results. A rising `failed` count means Fleet refuses deletions; check the Fleet API user's role.
- **`docs/compliance/residual-risks.md`**, RR-22, mitigation column: append "A host a device no longer speaks from is
  reserved for it and removed from Fleet; after a Fleet rebuild, this can remove a record that another machine took
  over, which then enrolls again."
- **Changelog** `changelog.d/pdk-1123.security.md`: append "A device's previous inventory host is removed from Fleet."
- **§12 of amendment e**, item "Stale previous hosts in Fleet": replaced by this round.

### L-10 Freedoms

- Internal helpers, variable names, the order of the guard checks within decision 5, log message wording beyond the
  stated messages and attributes.
- Whether `RecordLeftInventoryHosts` runs one statement per host or one batch per organization.

### L-11 Stop conditions

- The fix needs a change outside §L-5.
- `offboarding_table` order 166 is taken.
- The RLS lint or the offboarding registry test demands something §L-6 does not state.
- Production growth beyond about 300 lines for this round.
- A test of §L-8 does not fail on ca7377ab and no mutation makes it fail: report it, do not weaken it.
- The rebuild cost turns out larger than decision 10 states: a removal of a host that a device is bound to or stores.

### L-12 Risks and open points

- **Rebuild cost** (decision 10). Accepted and documented.
- **Event volume after a rebuild:** at most one event per left host and attempt, and at most 50 per round. Accepted.
- **Phase 2 live checks** (ticket). Fleet deletes a reserved host with the existing API user, and the removed
  machine enrolls again under a new ID. Also check whether a record that was enrolled again still holds the earlier
  software list.

### L-13 Size (estimate)

| Part | Lines |
| --- | --- |
| Production: migration ~60, queries ~30, `binding.go` ~30, app ~80, registry ~12, worker ~60, wiring ~2, messages 2 | about **+275** |
| Tests | about +450 |
| Docs | about +15 |

Main's estimate for this round was about 220 production lines. Persisting the relisted reservations before the
store step adds about 50. After this round, PDK-1123 has about 1340 code lines.

## Amendment 2026-11-17 e — review round 3 (architect, PDK-1123): reservations in every organization, retired devices

Status: **accepted** (main, 2026-11-17, within the user's decision on left hosts). This section changes review
round 2 (§L-1 to §L-13). Where they differ, this section wins.

### L-14 Reservations count in every organization status

- `paddock_inventory_left_hosts()` (00163, changed in place):
  - it no longer filters on the organization status;
  - it returns every reservation (`removed_at` NULL) of every organization that still has rows;
  - it gains the column `org_active boolean`, computed as `o.status = 'active'`, after `hostname`.
- `InventoryLeftHosts` (query and app) passes the column through. `inventory.LeftHost` gains
  `OrgActive bool // the organization is active; only then does the removal step handle the reservation`.
- `HostTargets` uses every reservation, whatever `OrgActive` is. A reserved host of a suspended organization's device
  therefore stays in use: rule 6b refuses it, and `FirstSpeaker` does not choose it for another device.
- The removal step (§L-3 decision 5) skips reservations with `OrgActive` false. They count neither against
  `LeftHostDeletesPerRound` nor in the metric. Once the organization is active again, the next round handles them.
- An organization in deletion keeps its reservations in use until the organization deletion has deleted its reserved
  hosts from Fleet and its rows (§L-3 decision 8).

### L-15 Correction of L1

L1's "It cannot arise any more" did not hold, and the text is corrected above. A double binding can arise in this case:
- the trigger is a Fleet rebuild that swaps the IDs of bound devices;
- their next tokens arrive in different rounds;
- the first device rebinds to its new host, which is still the other device's suspended bound host. A bound host listed
  with another hardware UUID is not in use (review round 1, N1).

What happens then:
- the host stays in `Targets.Excluded` and nothing is stored for it, as L1 states;
- the first device's previous host becomes a `relisted` left host and is removed from Fleet, although the second
  machine now uses it. That is the accepted rebuild cost of §L-3 decision 10;
- the second machine's fleetd enrolls again under a new ID, and its next token rebinds it.

### L-16 Retirement reserves the stored host

- **Decision:** retiring a device reserves its stored host like a left host, with reason `retired`. The removal step
  removes it from Fleet like any other left host, with the audit event in the retired device's own organization.
  Until then, no other device is bound to it or stores it.
- **Why:** claim devices are only active and quarantined devices, so a retired device's stored host was in use by
  nobody until retention removed it.
- **Where:**
  - Every retirement passes through `app.TransitionDevice` (`server/internal/app/devices.go`), inside the action's
    transaction. Its callers are `Devices.Retire` (admin API, role `paddock_api`) and
    `DeviceReports.RetireUninstalled` (worker, role `paddock_worker`).
  - `TransitionDevice` runs `q.RecordRetiredInventoryHost(ctx, id)` when `to == device.StateRetired`, right after
    `RevokeDeviceIdentityKeys`. The reservation therefore commits or rolls back with the retirement.
- **Only the stored host is reserved, not a differing bound host.** A bound host carries the device's instance
  identifier. A host stored for the device is the one whose record holds its inventory.
- **The removal step handles retired devices without change:**
  - `paddock_inventory_left_hosts()` already ignores the device state;
  - `paddock_fleet_host_in_use(device, host)` excludes the retired device itself;
  - `ActionRunner` records the event in the organization scope, as retention already does for retired devices
    (`device.inventory_purged`).
- **Retention:**
  - Its code does not change.
  - When its purge reaches the device, the Fleet host is normally already gone. `DeleteHost` then sees a 404, which
    counts as deleted (`fleet_host_deleted` true).
  - A `hardware` or `seen_recently` answer can still keep the retired device's reference. The removal step deletes the
    Fleet record all the same (a `hardware` answer does not block it, §L-3 decision 5). The machine's fleetd enrolls
    again under a new ID, and a new device record of that machine speaks from it.
  - ADR 0032 records the shorter time for the Fleet copy in an amendment. Paddock's own copy of the retired device's
    inventory keeps `retired_inventory_days`.
- **Existing retired devices:** migration 00163 reserves the stored host of every device that is already retired.
  The migration runs as `paddock_owner`, which has `BYPASSRLS`.

Migration 00163 changes (in place):

```sql
-- in CREATE TABLE device_inventory_left_host:
  reason text NOT NULL CHECK (reason IN ('replaced','relisted','retired')),

-- the policy also applies to the API role, which retires devices; the API role may only insert:
CREATE POLICY tenant ON device_inventory_left_host TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT INSERT ON device_inventory_left_host TO paddock_api;
-- ON CONFLICT needs SELECT on the conflict columns (review round 3, amended): the API role reads only the device and
-- host IDs of its own organization's rows (forced RLS), which it already reads in device_inventory_ref.
GRANT SELECT (device_id, host_id) ON device_inventory_left_host TO paddock_api;

-- after the table: existing retired devices
INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
SELECT r.device_id, r.organization_id, r.external_id, 'retired', now()
FROM device_inventory_ref r JOIN device d ON d.id = r.device_id
WHERE d.state = 'retired' AND r.external_id <> ''
ON CONFLICT (device_id, host_id) DO NOTHING;
```

Query (`inventory.sql`, organization pool):

```sql
-- name: RecordRetiredInventoryHost :exec
INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
SELECT r.device_id, r.organization_id, r.external_id, 'retired', now() FROM device_inventory_ref r
WHERE r.device_id = @device_id AND r.external_id <> ''
ON CONFLICT (device_id, host_id) DO NOTHING;
```

`ON CONFLICT DO NOTHING` needs `SELECT` on the conflict columns, hence the column grant above (amended).

Go:
- `server/internal/inventory/binding.go`: `LeftRetired = "retired"` next to `LeftReplaced` and `LeftRelisted`.
- `server/internal/domain/audit/codes.go`, description of `device.inventory_host_removed`: replace "reason replaced:
  … ; reason relisted: …" with the same text, followed by "; reason retired: the device was retired and fleet_host
  is the host Paddock stored for it". Params, outcomes and messages stay the same.

### L-17 Texts (neutral)

- `docs/operations/fleet.md`, at the end of step 3's sentence on left hosts: "Retiring a device reserves its stored
  host in the same way; the next inventory round removes it from Fleet. Paddock's copy of the retired device's
  inventory follows the retention period."
- ADR 0032, new section "Amendment 2026-11-17 (ADR 0057, PDK-1123)": "The host in Fleet of a retired device is
  removed by the next inventory round (`device.inventory_host_removed`, reason `retired`), not at the end of
  `retired_inventory_days`. Paddock's copy of the inventory keeps the retention period above. The inventory purge
  then finds the host deleted." The architect adds this amendment with this plan.

### L-18 Tests

Each regression test MUST fail on 28312ead.

| Test | Package | Covers |
| --- | --- | --- |
| `TestInventoryRoundSuspendedOrgReservationInUse` | worker | Setup: V's left host 5 (reason `relisted`) is refused once (`InvalidState`), then V's organization is suspended, and D reports a token for 5 before each of 3 rounds. Assertions: D never binds or stores 5; no `DeleteHost` while V's organization is suspended; after it is active again and `LeftHostRetryAfter` has passed, 5 is removed once, with the event in V's organization |
| `TestInventoryRoundSuspendedOrgSkippedByRemoval` | worker | 2 reservations of a suspended organization and 1 of an active one, cap 1 → the active one is removed in the first round; the metric counts 1 |
| `TestRetireReservesStoredHost` | app (integration) | `Devices.Retire` (admin API principal) and `DeviceReports.RetireUninstalled` each create one reservation with reason `retired` for the stored host; a device without a stored host gets none; a failed retirement (invalid transition) creates none |
| `TestInventoryRoundRetiredHostNotBoundElsewhere` | worker | retired V with stored host 5, listed with D's UUID; D reports a token for 5 → `host_in_use` across 2 rounds; with admin, 5 is removed once, the event `device.inventory_host_removed` (reason `retired`) is in V's organization, none in D's |
| `TestRetentionPurgeAfterRetiredHostRemoved` | app (integration) | after the removal, the inventory purge of the retired device records `fleet_host_deleted` true (Fleet answers 404) and deletes Paddock's rows as before |
| `TestMigration00163ReservesRetiredHosts` | platform/db (integration) | a retired device with a stored host that exists before 00163 has a reservation with reason `retired` after it; an active device has none. If the test harness cannot migrate step by step, verify it once by hand and record the result in the result document |

`TestHostTargetsLeftHosts` additionally covers a reservation with `OrgActive` false: it is in use.

### L-19 Stop conditions (added)

- `paddock_api` needs more than `INSERT` and the column grant `SELECT (device_id, host_id)` on
  `device_inventory_left_host` (amended: `ON CONFLICT` needs `SELECT` on the conflict columns; a reservation made in
  the worker round instead would leave the host free between the retirement and the next round).
- A retirement path that does not pass through `TransitionDevice`.
- Production growth beyond about 40 lines for this round.

### L-20 Size (estimate)

| Part | Lines |
| --- | --- |
| S1: function, query, `LeftHost`, removal-step filter | about +8 |
| Retired devices: migration ~10 (check, policy roles, grant, backfill), query ~5, `TransitionDevice` ~3, constant 1, description ~1 | about +20 |
| Tests | about +250 |
| Docs | about +10 |

### L-21 A retired device holds its hardware UUID until retention purges it (review round 4)

Status: accepted (main, 2026-11-17).

- Decision: a retired device counts in the hardware-UUID ambiguity check while its state is `retired`,
  `uninstalled_at` is NULL, it still has a `device_inventory_ref` row and has no `retention_inventory_hold` row. A UUID
  it shares with an active or quarantined device maps to no device; a UUID only it holds maps to none (unchanged).
- It stops counting once retention's inventory purge ran for it (reference deleted, or hold row written for
  `fleet_host_kept` `hardware`/`seen_recently`) or it was retired as uninstalled. No fixed period.
- Why: a retired machine can keep running fleetd; after the round removes its host, fleetd enrolls again under a new ID
  with the same UUID, which could otherwise map to another device reporting that UUID.
- Only devices that are not bound are affected (a bound device stores only its bound host).
- Migration 00163 changed in place (unreleased): `paddock_inventory_devices` with the retired-holder condition and
  `HAVING count(*) = 1 AND bool_and(d.state IN ('active','quarantined'))`. Grants: none new. Go: no change.
- Tests: worker `TestInventoryRoundRetiredDeviceHoldsItsUUID`; app `TestMapHostsRetiredHolder`; `TestMapHosts`
  unchanged.
- Residual: a retired device that never stored a host does not hold its UUID.

## Amendment 2026-11-17 f (architect, PDK-1126c) — Paddock-written identity files in the integrity check

Protected area 4 includes identity files that Paddock itself writes. Before this amendment, the login reconciler
corrected a changed `himmelblau.conf`, `login-deny` or socket drop-in and reported only `device.login_applied`. The
integrity check of ADR 0056 (part C) now judges these files too. A change raises
`device.tamper_protected_file_changed` with the existing `file` param; there is no new code and no new `reason`. The
correction stays as it was. Decisions §183, §185, §187 and §190.

**Component choice.** The check observes these files in every pass, and the login reconciler wraps each of its own
writes in the check. Two alternatives were rejected:
- A separate baseline in the login reconciler. Report-only mode never reaches its apply, and the lock, once-per-change
  and suspension rules of part C would be duplicated.
- The integrity pass alone. It runs on its own ticker, so in enforce mode the login correction could hide a change
  before the next pass sees it.

**F1 Checked files.** `reconcile.LoginManagedFiles`: `/etc/himmelblau/himmelblau.conf`, `/etc/paddock/login-deny`
and the three `90-paddock.conf` drop-ins of `himmelblaud.socket`, `himmelblaud-tasks.socket` and
`himmelblaud-broker.socket`.
- Their value is the SHA-256 of the content, and `""` when absent, as for the agent-written files (C7).
- Mode and owner are not judged; the login reconciler still corrects them without an event.
- They are checked in both enforcement modes.

**F2 Baseline only from Paddock's own content.** The baseline entry of an F1 file is never taken from the disk; a pass
with no entry for such a file skips it. An entry is written only at these points:
- `Written(path, content)` after each successful write by the login reconciler: the SHA-256 of the content written.
  The file's once-per-change mark is cleared. A record that cannot be saved (lock timeout) stays in memory and is
  saved by the next successful `Expect`, `BeforeWrite`, `Written` or pass. The configuration written before a package
  installation is recorded only once the installation succeeded or was killed at its timeout, which both keep it. The
  restore or removal after a failed installation records nothing.
- `Written(path, render)` for every F1 file that already holds Paddock's current render when the login reconciler
  applies a login resource (`confirmManaged`). The value is the render, not the disk, so an entry left behind by a
  crash, an unsaved record or an older agent follows the file as soon as Paddock's render is in place.
- `ConfirmPrevious` at every agent start, after `SetPrevious` and before the first pass: the same confirmation for the
  renders of the previously enforced spec. It covers a rollback to an agent without this check that wrote new
  content, followed by an update again.
- `Expect(path, render)` when the login reconciler applies a login resource after an agent start. It applies only when
  the agent enforced a bundle before this start, which the agent passes on with `SetPrevious` after loading its cached
  bundle. At every agent start, where no entry exists, the baseline records the render of that earlier bundle's login
  spec for `himmelblau.conf` and `login-deny`. A cached report-only bundle counts as no bundle, because it wrote
  nothing. The drop-ins get no `Expect`: agents before them never wrote them. `himmelblau.conf` gets neither `Expect`
  nor the start confirmation while the previous spec's packages are not installed: a failed installation took that
  configuration back. After a successful apply, its own spec becomes the previous one.
- `Expect(login-deny, empty)` when the agent keeps the deny list of the PAM profile without a login resource and
  finds it missing, again only after an enforced bundle. Agents before this change kept the list in place, so its
  absence is a change: it unlocks every locked user. A device that never enforced a bundle records nothing here. An
  existing list is never expected or written.

As a result:
- A fresh enrolment raises no event.
- The first spec change after an update compares the disk with what Paddock wrote before, which matches, so it raises
  no event. This holds also when the last installation before the update failed.
- An edit or deletion made before the update, including one locked name removed from `login-deny`, raises one event
  at the first correction.
- After a rollback to an agent without this check and an update again, the first pass raises no event, and a later
  change is reported.
- `renderHimmelblauConf`, `renderDenyList` and `EnsureDenyList` are unchanged since v0.1.0-alpha.10.

**F3 Check right before the correction.** `BeforeWrite(path)` hashes the file and compares it with its entry under
`integrity.lock`.
- No entry, or an equal value: nothing happens.
- Otherwise: the part C once-per-change mark (C8), one `Warn` "a protected Paddock file changed outside Paddock" and
  one event.
- A hash or lock error is one `Warn` and no event.

The login reconciler's helper `writeManaged` calls `BeforeWrite`, then the write, then `Written`; a failed write
records nothing. Every write of an F1 file goes through it (the deny list and `himmelblau.conf` in apply, the drop-ins,
and `EnsureDenyList`), except the configuration write before the installation, which calls `BeforeWrite` and records
as F2 says, and the restore or removal after a failed installation, which calls no guard method. `Expect`,
`BeforeWrite` and `Written` are safe from any goroutine and never touch the pass's hash cache or `Warn` throttle. A
rebuilt baseline makes the next `Expect` record again.

**F4 Wiring.** `reconcile.FileGuard` (`Expect`, `BeforeWrite`, `Written`) is implemented by `integrity.Checker`.
`apply.Applier.WithFileGuard`, `SetPrevious` and `ConfirmPrevious` pass it on to the login reconciler. `agent.New`
wires the guard and `SetPrevious`; the agent's run calls `ConfirmPrevious` before its first pass, because `agent.New`
also serves `paddockd plan`, which changes nothing. The
reconciler does not import the integrity package, and `baseline.go` is unchanged.

**F5 Residuals (RR-148).**
- Only content is judged.
- A change made in the instant between the check and Paddock's own write is overwritten without an event.
- A check that cannot hash the file or take `integrity.lock` logs a `Warn`; the correction then overwrites a change
  without an event.
- At every agent start without an entry, until Paddock's first write, `himmelblau.conf` and `login-deny` are judged
  against what Paddock wrote for the bundle it enforced before. A local account created or removed since then can
  raise one event.
- A stop or an unsaved record between Paddock's write and its record can raise one event for that write; the next
  apply of a login resource records it again.
- With a report-only bundle cached at the agent start there is no previous render: an edit made before the start, or
  a deleted `login-deny`, is corrected without an event when the device enforces again.
- The drop-ins are judged only after Paddock's first write.
- On a device that never enforced a bundle, an absent `login-deny` is not a change.
- A Paddock-written file stays judged after the login resource leaves the bundle, until Paddock removes it.
- After a rollback to an older agent that wrote a new lock, a change outside Paddock that sets the deny list back to
  the content recorded before the rollback, made before the update again, is corrected without an event. This needs
  root; no regular flow leads there.
- A change that already equals the next content Paddock applies, for example a lock removed just before the
  administrator unlocks that user, is recorded without an event. The window is at most one check interval.
- A later release that changes a render and is installed directly over an agent without this check can raise one
  event per changed file.
- Report-only mode records nothing until the device enforces a bundle.

**Tests.** Integrity unit tests:
- no event when the disk matches the render;
- an edit made before the update is reported;
- no entry is recorded from the disk;
- a change after a write is reported at the next check right before the correction, and a repeat is reported again;
- a render change raises no event;
- an edit after a write is reported by the next pass;
- a deleted file is reported by the pass alone;
- an empty file;
- lock timeouts;
- a rebuilt baseline makes `Expect` record again;
- an unsaved record is saved by the next `Expect`;
- concurrency under `-race`.

Reconcile tests: the guard order, no `Expect` on a fresh device, the previous renders, the confirmation at start, a
failed write, a failed installation that records nothing, a timeout that keeps the record, and `EnsureDenyList` with
and without an enforced bundle.

Agent tests with a real applier and checker:
- a manipulation is reported and corrected;
- the update followed by a new lock raises no event, and the missing drop-ins are written without an event;
- an edit, a deletion and a removed locked name before the update are each reported once;
- the deny list without a login resource;
- a report-only bundle before the update;
- a rollback to an agent without the check and an update again;
- a stop between a write and its record;
- a failed installation before the update;
- a deleted drop-in on a report-only device.

**Acceptance.**
1. 1126c-1: in enforce mode, root edits `himmelblau.conf`. Within one drift interval there is one event for that file
   and one `device.login_applied` (`config`), and the file is restored.
2. 1126c-2: an update or spec change that changes a render raises `device.login_applied` and no tamper event.
3. 1126c-3: the first start of the agent with this change raises no event.
4. 1126c-4: an edit made before the update raises one event at the first correction, and the file is restored.
5. 1126c-5: on a report-only device, a deleted drop-in with an entry raises one event, and the file stays deleted.

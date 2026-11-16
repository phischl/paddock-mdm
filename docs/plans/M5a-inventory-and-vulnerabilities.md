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

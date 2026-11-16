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

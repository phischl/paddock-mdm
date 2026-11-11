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

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
  min` with `E > F` means at least two distinct failing evaluations, 15 minutes apart, with no stored passing
  evaluation between them (a stored pass clears `failing_since`). With the production interval of 10 min it takes the
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

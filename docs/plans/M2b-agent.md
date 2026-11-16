# Implementierungsplan: M2b — paddock-agent, supervisor, A/B update, VM system tests

Status: Ready for implementation · 2026-10-04 · Author: architect
Basis: `docs/architecture.md` v1.5 §6, §7.2, §11 (agent), §21 (A7); concept "Design contract (binding)" 1–9 (quoted in
`CLAUDE.md`); ADR 0004, 0005, 0012, 0013; M2a (protocol in `pkg/`, device API `api/openapi/device.yaml`)

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

After M2b a real Ubuntu device runs `paddock-supervisor` and `paddockd`: it enrolls with an enrollment config, checks
in, applies its signed bundle (files, systemd units, time sync) idempotently, corrects drift, keeps working when the
server is unreachable, and updates itself through signed A/B releases with self-test, watchdog and automatic rollback,
rolled out in waves with an automatic stop. Proven on both test VMs.

## 2. Context

- M2a delivered: `pkg/protocol` (request signing), `pkg/canonicaljson`, `pkg/dsse`, `pkg/bundle` (schema v1, `Verify`),
  device API (`/v1/enroll`, `/v1/enroll/{id}`, `/v1/checkin`, `/v1/events`), enrollment config JSON
  (`server_url`, `organization_id`, `token`, `bundle_keys`), compiler, gateway, portal pages, reference client
  `test/acceptance/devicesim`.
- Test VMs `paddock-u2404` / `paddock-u2604` (read `test/vms/virtualbox/README.md`, NVRAM caveat; start from snapshot
  `base-installed`; never modify that snapshot). The guest reaches the host as `10.0.2.2`; `/etc/hosts` overrides of
  `*.paddock.localhost` work through NSS (PoC M1); the Caddy root CA must be trusted in the guest.
- Design contract (from `CLAUDE.md`, binding): separate supervisor and agent, agent never replaces itself in-process,
  supervisor simple enough to need no updates; A/B with one symlink flip; self-test before switch; watchdog with
  automatic rollback and audit event; signed artifacts verified with the supervisor's key; staged rollout with
  automatic stop; fail safe; static binary.

## 3. Binding decisions

### 3.0 M2a follow-ups (step 0)
1. **Action routes become sub-resources:** `POST /api/v1/enrollment-tokens/{id}/revoke`,
   `POST /api/v1/devices/{id}/approve|reject|release-quarantine|retire`. Remove the `actions.go` special dispatch and
   the oapi-codegen exclusions; generated strict handlers serve them. Add to `CLAUDE.md` under "Portal and list
   endpoints": "State-changing actions on a resource are `POST /<collection>/{id}/<verb>`; never `:verb` suffixes."
2. `server/go.mod` gets `require github.com/paddock-mdm/paddock/pkg v0.0.0` with `replace … => ../pkg` so that
   `go mod tidy` works per module; same for `agent/go.mod` and `test/acceptance/go.mod` where they import `pkg`.
3. `deploy/compose/scripts/rustfs-audit-bootstrap.sh`: same `--`/`--user=` fix as the bundles script.
4. `make test` also runs the unit tests of `./test/acceptance/cmd/devseed/...` (no stack needed).

### 3.1 Agent
5. **Module** `agent/` (`github.com/paddock-mdm/paddock/agent`), binaries `agent/cmd/paddockd`,
   `agent/cmd/paddock-supervisor`; `CGO_ENABLED=0`, `linux/amd64` and `linux/arm64`; version injected with
   `-ldflags -X`. Approved dependencies: `github.com/godbus/dbus/v5` (network/resume events) and `aead.dev/minisign`
   (supervisor signature verification). Nothing else beyond the standard library and `pkg`.
6. **Files:** `/etc/paddock/agent.yml` (server URL, optional proxy, organization ID), `/etc/paddock/trust.json`
   (bundle keys from the enrollment config), `/var/lib/paddock/identity/sign.key` (ECDSA P-256, PKCS#8 PEM, 0600,
   dir 0700), `/var/lib/paddock/state/{state.json,managed.json}`, `/var/lib/paddock/spool/events.jsonl`,
   `/var/lib/paddock/staging/`, `/run/paddock/agent.sock` (health), `/run/paddock/last-checkin`.
   All state writes are atomic (temp file + fsync + rename). Key protection `file` in M2b (TPM-resident keys: later).
7. **Enrollment:** `paddockd enroll --config <enrollment-config.json>` (root only): validates JSON, writes
   `agent.yml` and `trust.json`, generates the key, calls `/v1/enroll`, polls `/v1/enroll/{id}` (10 s → 5 min
   back-off, max 24 h, Ctrl-C safe — re-running resumes with the same key and enrollment ID), stores `device_id`, then
   deletes the enrollment config file it was given if `--remove-config` is set. Exit codes: 0 active, 2 pending
   (still waiting when `--no-wait`), 3 rejected, 1 error.
8. **Run loop** (`paddockd run`, started only by the supervisor): check-in every `next_checkin_s` from the server
   (fallback 300 s ± 20 %); failure back-off 30 s, 60 s, 2 min, 5 min, 10 min, 30 min (±20 %); immediate check-in
   (0–15 s random delay, at most one per 60 s) on NetworkManager `Connectivity` becoming `FULL` (D-Bus
   `org.freedesktop.NetworkManager`, property changes), on logind `PrepareForSleep(false)`, and at start. If D-Bus or
   NetworkManager is unavailable the timer still works (logged once).
9. **Bundle apply:** download from the presigned URL, check SHA-256 against the check-in response, `bundle.Verify`
   with `trust.json`, device/org and `minVersion = last applied`; then reconcile in the order `time` → `file` →
   `systemd_unit` (units may depend on files). Each resource yields
   `ok | changed | error`; errors do not stop other resources. The bundle counts as applied (version persisted) when
   all resources were attempted; the event `bundle.applied` carries `{version, changed, errors:[{id, message}]}`.
   Verification failure → state unchanged, event `bundle.rejected {version, reason}`.
10. **Reconcilers** (`agent/internal/reconcile/`, interface below): each idempotent; `Plan` never changes the system.
    - `file`: compare content hash, mode, owner, group; write atomically into the same directory, create missing parent
      directories `0755 root:root`, `chown`/`chmod` before rename. Refuse paths that violate the M2a path policy
      (defence in depth: copy the policy into `pkg/policy` and use it on server and agent).
    - `systemd_unit`: `systemctl is-enabled/is-active`, then `enable|disable` and `start|stop`; unknown unit → error.
    - `time`: if `chrony` is installed, ensure `chrony.service` enabled+active; else ensure
      `systemd-timesyncd.service` enabled+active and `timedatectl set-ntp true`; neither installed → error.
    - **Removal:** `managed.json` records every file Paddock wrote with its content hash. A file resource that
      disappears from the bundle is deleted only if its current content hash equals the recorded one; otherwise it is
      left in place and reported (`errors` entry `left_modified_file`). A removed unit resource is left in its current
      state (no action).
11. **Drift loop:** every `drift_interval_s` (default 300; `agent.yml` may set ≥ 30 only when the agent was built
    with the `paddock_dev` build tag) the agent re-plans the current bundle; if anything changes it applies and emits
    `config.drift_corrected {resource_ids}`.
12. **Events:** spool `events.jsonl` (append, fsync), monotonic `event_seq` persisted in `state.json`; sent in batches
    of ≤ 500 after each check-in; deleted after 202. Spool cap 50 MiB: drop oldest events of type
    `config.drift_corrected` first, then oldest overall; a drop creates `agent.events_dropped {count, from_seq, to_seq}`.
13. **Fail safe:** no code path in M2b locks, wipes, reboots or blocks logins. Server unreachable → keep the last
    applied bundle, keep running the drift loop on it, keep spooling.
14. **Health:** `GET /health` on `/run/paddock/agent.sock` → `{status, version, last_checkin_at, last_bundle_version,
    last_error}`; `paddockd self-test` (exit 0/1, JSON report on stdout): binary runs, `agent.yml` and `trust.json`
    parse, identity key loads, the last applied bundle (if cached in `/var/lib/paddock/state/bundle.dsse`) still
    verifies, server reachable (unreachable = `inconclusive`, not failure).

### 3.2 Supervisor and update
15. **Supervisor** (`paddock-supervisor`, systemd `Type=notify`, `WatchdogSec=60`, `Restart=always`,
    `WantedBy=multi-user.target`, **no** dependency on `network-online.target`): starts
    `/opt/paddock/agent/current/paddockd run` as child, restarts it on exit with back-off (1 s → 60 s), pets the
    systemd watchdog only while it is itself responsive. It contains the **release public key** compiled in
    (`-ldflags -X main.releasePublicKey=<minisign pubkey>`); it is the only component that verifies release
    signatures and flips the symlink. ≤ 600 lines of non-test Go code (design contract: simple enough to need no
    updates).
    Amendment 2026-10-12 (architect, PDK-043 Review 2) — **how the budget is measured**: the limit applies to the
    supervisor as a whole, not per file: all non-test Go files of `agent/internal/supervisor/` and
    `agent/cmd/paddock-supervisor/`, counting lines that are neither blank nor comment-only. Until PDK-043 the count
    was applied to `supervisor.go` alone; with the outcome `rollback_failed` and its retry the supervisor is at 693 such
    lines. The ceiling is **800**. Code that pushes past it is moved out of the supervisor (into the agent or `pkg/`),
    not split into more files. PDK-062 adds a check to `make lint` that enforces the ceiling.
    Amendment 2026-11-16 (architect, PDK-1118): the ceiling is **835**; see the section of that date at the end of
    this plan.
16. **Update protocol (agent ↔ supervisor):** the check-in response may contain
    `agent_update: {version, url, sha256, size, minisig}` (device API change, §6.1). The agent downloads to
    `/var/lib/paddock/staging/<version>/paddockd` + `paddockd.minisig`, checks size and SHA-256, then writes
    `/var/lib/paddock/staging/request.json` `{version}` and sends `SIGUSR1` to the supervisor (PID from `$PPID`). The
    supervisor: verifies minisign with its key → copies into the inactive slot (`/opt/paddock/agent/{A,B}`) → runs
    `<slot>/paddockd self-test` (timeout 120 s) → on success flips `current` (atomic `rename` of a new symlink),
    restarts the child, enters **probation** (10 min; 2 min with `paddock_dev`): healthy = child alive **and**
    `/run/paddock/last-checkin` newer than the switch time. Failure (self-test, crash loop ≥ 3 exits, probation timeout)
    → flip back, restart old child. Result written to `/var/lib/paddock/state/update-result.json`
    `{version, from_version, outcome: updated|self_test_failed|rolled_back|signature_invalid, at}`; the running agent
    turns it into an event (`agent.updated`, `agent.update_failed`, `agent.rolled_back`) and deletes the file after 202.
    Amendment 2026-10-12 (architect, ADR 0024): the outcome `rollback_failed` (a flip back that failed; the rollback
    stays pending and is retried) joins the list; it is carried by `agent.update_failed`.
    Amendment 2026-10-12 (architect, PDK-062) — **unreadable probation log**: a `probation.json` that exists but
    cannot be parsed is not dropped when the facts on disk still describe a forward switch; the supervisor rebuilds the
    probation from the slots. Rebuild if all of: `current` points at `A` or `B`; the other slot holds a `paddockd`
    whose `version` output matches the version pattern; the active slot's version matches the pattern and is newer
    than the other slot's by semantic version precedence (`pkg/semver`); no `update-result.json` names the active
    version with outcome `updated`. The rebuilt probation is `{version: <active>, from_version: <other>, from_slot:
    <other slot>, to_slot: <active slot>, switched_at: now, rebuilt: true}`, written synced (if the write fails it runs
    in memory and the next start rebuilds again), then resumed exactly like a readable log: the switch is treated as
    not known durable (`unsynced`), the check-in mark is cleared, and a full probation window runs; the supervisor
    logs at error level that the log was unreadable and the probation rebuilt. If `update-result.json` names the
    active version with outcome `rolled_back` or `rollback_failed`, the flip back was lost or failed: the supervisor
    resumes a pending rollback to the other slot (ADR 0024 rule 5) instead of a probation. In every other case
    (`current` on neither slot, the other slot empty or without a parsable version, the active version not newer,
    a result `updated` for the active version) the log is dropped as before (PDK-060), with the reason in the error
    log. Rejected: a conservative flip to the other slot (it would roll a possibly verified release back, count a false
    failure in the rollout, and under disk corruption the other slot is no safer); accepting the gap (a release would
    run without probation and the server would never learn its outcome: a silent breach of contract 4).
    Extended 2026-10-12 (architect, review 1 of PDK-062) — **pending marker**: the agent deletes `update-result.json`
    once delivered, so a pending rollback whose log is corrupted later would meet every rebuild precondition and could
    end in `updated` after `rollback_failed`. When a pending rollback is recorded in the probation log (also by the
    rewrite of a log that could not record it at first), the supervisor creates `state/rollback-pending` (synced, the
    version as content; its presence alone is authoritative) and removes it (synced) only after `rolled_back` is
    concluded. An unreadable log with the marker present is never rebuilt forward: the supervisor rebuilds the pending
    rollback from the slots (version = active, from = the other slot, `rollback_pending`, `rebuilt: true`; if current
    already points at the slot with the older valid version, the flip back landed and the newer slot is the failed
    release) and resumes the retries without writing a new result. The marker and a result that names the active
    version `rolled_back` or `rollback_failed` are checked before the slots' versions, so a rollback stays pending
    whatever the other slot reports. Accepted residual: an `updated` already delivered before the log is corrupted can
    lead at most to a duplicate `updated` (the rebuilt probation of the healthy release passes again).
    Extended 2026-10-12 (architect, review 2 of PDK-062) — **the marker's version decides**: the marker names the
    failed release, so its version, not the order of the slots' versions, identifies the failed slot and names the
    result. The failed slot is the slot whose `version` equals the marker's; if no slot reports it, the slot that
    reports no valid version next to one that reports another valid version. With current on the other slot the flip
    back landed: the supervisor confirms it durable and concludes `rolled_back` naming the marker's version. With
    current on the failed slot it rebuilds the pending rollback with the marker's version and the other slot as target.
    If neither slot can be identified (no slot reports a valid version), the log is dropped without a flip. A marker
    whose version neither of two valid slots reports is stale (for example after its removal failed): it is removed,
    synced, and the normal rebuild rules apply. A marker without a readable version rebuilds a pending rollback only if
    both slots report valid versions (the newer is the failed release); otherwise the log is dropped without a flip.
17. **Release key:** development key pair generated by `make dev-release-key` into `deploy/compose/.secrets/release/`
    (minisign format, password-less, dev only); production key is offline (documented in `docs/operations/agent-releases.md`,
    never in CI). The supervisor build target reads the public key file.
18. **Test-broken builds** (only via test targets, never in release packaging): build tag
    `paddock_testbroken_selftest` (self-test exits 1) and `paddock_testbroken_probation` (self-test passes, `run`
    exits 1 after 20 s).

### 3.3 Server side of releases and rollouts
19. **Platform entities** (platform scope, no organization): `agent_release (version PK semver, created_at,
    created_by, status draft|published)`, `agent_artifact (version, arch, sha256, size, minisig, object_key)`,
    `agent_rollout (version PK, waves int[] default {1,10,50,100}, current_wave_index, wave_started_at,
    min_wave_minutes default 1440, failure_threshold_percent default 2, failure_threshold_min default 3,
    status running|halted|completed, halted_reason)`. Artifacts in RustFS bucket `paddock-agent-artifacts`
    (`releases/<version>/<arch>/paddockd`), presigned for the device via the bundles host.
20. **Platform API** (`/api/platform/v1/agent-releases…`, list contract, audited): create release, upload artifact
    (`PUT …/{version}/artifacts/{arch}` body = binary, header `X-Paddock-Minisig: <base64 signature file>`; server
    verifies the signature with the configured release public key before accepting), publish, start rollout
    (`POST …/{version}/rollout` with optional overrides; `min_wave_minutes` < 60 only in development), halt, resume.
    Audit codes `agent_release.created|artifact_uploaded|published`, `agent_rollout.started|advanced|halted|resumed|completed`.
21. **Eligibility** (gateway, no DB): Valkey `ar:current` = `{version, waves, current_wave_index, artifacts{arch:…}}`
    written by the worker. A device is eligible when `fnv32a(device_id) % 100 < waves[current_wave_index]` and its
    reported `agent_version` differs. The gateway adds `agent_update` with a presigned artifact URL for the device's
    reported arch (check-in body gains `arch`).
22. **Auto-stop and advance** (worker, every 60 s, advisory-lock leader): per running rollout count devices that
    reported `agent.update_failed` or `agent.rolled_back` for this version vs. devices eligible in the current and
    previous waves; if failures > max(`failure_threshold_min`, ceil(eligible × percent / 100)) → `halted` + audit
    `agent_rollout.halted` (system actor) + Valkey update (eligibility off). Advance to the next wave when the current
    wave is older than `min_wave_minutes` and not halted; `completed` after the last wave.
23. **New device event types** (closed enum, M2a decision 14 extended): `agent.updated`, `agent.update_failed`,
    `agent.rolled_back`, `agent.events_dropped` → audit codes `device.agent_updated`, `device.agent_update_failed`,
    `device.agent_rolled_back`, `device.agent_events_dropped`.
24. **Portal (platform admin):** *Agent releases* (DataList; detail with artifacts, rollout status, wave, failure
    counts; actions start rollout, halt, resume via `ConfirmDialog`). Upload is done with
    `make agent-release VERSION=x.y.z` (builds, signs with the dev key, uploads via the platform API using the
    `authflow` helper), not in the portal.

### 3.4 Packaging and system tests
25. **Debian packages** built with `nfpm` (container image `goreleaser/nfpm`, pinned; approved): `paddock-supervisor`
    (binary, systemd unit, `/opt/paddock/agent/{A,B}` dirs) and `paddock-agent` (installs `paddockd` into slot `A` and
    creates `current → A` **only if `current` does not exist**; never touches an existing slot; depends on
    `paddock-supervisor`). `make deb` builds both for amd64.
26. **System tests** `test/system/` (Go module, added to `go.work`), driving the VMs via SSH with the scripts in
    `test/vms/virtualbox/` (used, not changed) and the dev stack via the admin/platform APIs. Each test starts from
    `base-installed`, prepares hosts entries + CA trust, installs the debs, enrolls via a fresh enrollment config, and
    restores `base-installed` at the end (`t.Cleanup`). `make system-test VM=<vm|all> T=<regex>`.

## 4. Non-goals

Commands, escrow, LUKS, sudo, login/Himmelblau, apt holds/updates, Fleet, TPM-resident keys, identity rotation,
time tickets/dead man's switch, `paddock-revoke`, apt repository hosting, arm64 system tests, portal upload of
releases.

## 5. Affected files

New: `agent/**`, `pkg/policy/`, `packaging/nfpm/{paddock-agent,paddock-supervisor}.yaml`, `packaging/systemd/paddock-supervisor.service`,
`server/migrations/paddock/00004_agent_releases.sql`, server domain/app/worker/gateway/admin changes for §3.3,
`server/web/src/views/AgentReleases*.vue`, `test/system/**`, `docs/operations/agent-releases.md`,
`deploy/compose/*` (artifacts bucket, release public key secret for api), `Makefile` (targets `deb`, `dev-release-key`,
`agent-release`, `system-test`), `CHANGELOG.md`, `CLAUDE.md` (only the rule in 3.0.1), `api/openapi/{admin,device}.yaml`.
Off-limits as in M2a.

## 6. Interfaces

### 6.1 Device API changes
```yaml
# POST /v1/checkin request: add
arch: { type: string, enum: [amd64, arm64] }
# 200 response: add (nullable)
agent_update: { version: string, url: string, sha256: string, size: integer, minisig: string }  # minisig = base64 of the .minisig file
# POST /v1/events: event types extended per decision 23
```

### 6.2 Reconciler interface
```go
package reconcile
type Result struct{ ID string; Status Status; Message string } // Status: OK | Changed | Error
type Reconciler interface {
    Type() string                                                     // "file" | "systemd_unit" | "time"
    Plan(ctx context.Context, r bundle.Resource) (changes []string, err error)
    Apply(ctx context.Context, r bundle.Resource) Result
}
type System interface { // narrow OS port, faked in unit tests
    ReadFile(path string) ([]byte, fs.FileInfo, error)
    WriteFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error
    Remove(path string) error
    LookupUser(name string) (uid int, err error); LookupGroup(name string) (gid int, err error)
    Systemctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
    PackageInstalled(name string) bool
}
```

## 7. Implementation steps

0. **M2a follow-ups** (§3.0) — `make lint test acceptance` green. Commit `refactor(api)!: sub-resource action routes` (+ small fix commits).
1. **Agent core** — module, config, identity, enrollment command, protocol client, run loop with triggers and
   back-off, health socket, self-test. Unit tests with an `httptest` gateway fake and fake clocks; integration test
   against the real dev stack using a temp root dir (`--root` flag, test-only). Commit `feat(agent): enrollment and check-in loop`.
2. **Reconcilers + bundle apply + drift + events/spool** — unit tests per reconciler on a fake `System` and on a
   temp directory for `file`; idempotency tests (second `Apply` → all `OK`). Commit `feat(agent): reconcilers and bundle apply`.
3. **Supervisor + A/B update** — unit tests with fake child processes and symlink dirs (crash loop, probation
   timeout, bad signature, self-test failure, success). Commit `feat(agent): supervisor with A/B update and rollback`.
4. **Server releases and rollouts** — §3.3 incl. migration, platform API, gateway eligibility, worker auto-stop/advance,
   portal page, isolation/list/audit gates extended. Commit `feat(releases): agent releases and staged rollouts`.
5. **Packaging** — nfpm configs, `make deb`, `make dev-release-key`, `make agent-release`. Check: `dpkg-deb -c` lists
   expected paths; lintian in a container SHOULD be clean of errors. Commit `build(agent): debian packages`.
6. **System tests on both VMs** — gates S1–S5 (§8). Commit `test(system): agent gates on Ubuntu 24.04 and 26.04`.
7. **Regression** — full reset; `make dev-secrets up dev-seed acceptance e2e system-test VM=all` green; both VMs
   powered off at `base-installed`.

## 8. Gates (system tests, both VMs)

| ID | Gate (concept acceptance gate) | Content |
| --- | --- | --- |
| S1 | Enrollment + bundle | install debs, `paddockd enroll`, device active in portal API, managed file + unit + time applied; `bundle.applied` audit event |
| S2 | **Configuration idempotency** | after apply, a second run (forced drift pass) reports `changed = 0`; local modification of a managed file is corrected within the drift interval with `config.drift_corrected`; removing the file resource deletes the unmodified file, a locally modified one is left and reported |
| S3 | **Agent outage** | `make down` (stack stopped) for 10 min: agent and supervisor keep running, device fully usable (SSH login, managed files untouched), no lock/block; after `make up` the device checks in within one interval (or immediately after a link up/down via `setlinkstate1`) and the spooled events arrive exactly once |
| S4 | **Agent update** | good release → device runs the new version, event `device.agent_updated`; `paddock_testbroken_probation` release → rolled back within probation, `device.agent_rolled_back`; `paddock_testbroken_selftest` release → never switched, `device.agent_update_failed`; artifact with a bad signature → rejected, `signature_invalid` |
| S5 | **Staged rollout auto-stop** | rollout with `failure_threshold_min = 1`, waves `[100]`, broken release → after the first failure the rollout is `halted`, audit `agent_rollout.halted`, the second VM does not receive the update offer |

Plus: existing acceptance gates and e2e stay green; new e2e case for the agent releases page (list, detail, halt via modal).

## 9. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given an Ubuntu 24.04 or 26.04 device, when the operator installs the packages and runs `paddockd enroll`, then the device appears in the portal and applies its configuration | F1, A6 | Org admin |
| AC2 | Given an applied bundle, when nothing changes, then a second apply changes nothing; local drift is corrected and reported | F1, concept gate "Configuration" | Org admin (audit) |
| AC3 | Given the control plane is down, then the device works normally and catches up afterwards | C2, gate "Agent outage" | User at device, org admin |
| AC4 | Given a broken agent release, then the watchdog rolls it back and the rollout halts automatically | gate "Agent update", design contract 3–6 | Platform admin (portal) |

## 10. Freedoms

Internal agent package layout, log format details (`slog` JSON to journald), back-off implementation, test helper
structure, portal layout of the releases page.

## 11. Stop conditions

A design-contract rule cannot be met; a needed dependency is not approved here; the M2a protocol needs an incompatible
change beyond §6.1; system tests cannot run on the VMs without changing `test/vms/**`; M0 §11 S2/S6/S7/S8.

## 12. Risks

| # | Item | Default |
| --- | --- | --- |
| R1 | VM system tests are slow (boots, installs) | Run per VM in sequence; snapshot restore per test file, not per test |
| R2 | NetworkManager not present on servers | Timer fallback (decision 8) |
| R3 | Supervisor size limit too tight | Report; do not move logic into the agent that belongs to the supervisor |

## Amendment 2026-10-10

Decision 16, probation health (PDK-031): the criterion "`/run/paddock/last-checkin` newer than the switch time" is
replaced. The kernel stamps files with its coarse clock, up to one tick behind the switch time taken from the clock, so
a check-in right after the switch could be dated before it and a healthy update was rolled back. The rule now is:

- The supervisor removes `/run/paddock/last-checkin` while no agent runs: at the switch, after the old child has
  exited and before the new one starts, and when it resumes an interrupted probation, before it starts the child.
- The probation passes only if, at its deadline, the new child runs and has recreated the mark.
- If the mark cannot be removed (any error other than "does not exist"), the probation ends in a rollback with the
  reason "check-in mark could not be cleared", without waiting for the deadline. A resumed probation rolls back from
  the supervisor's loop, after the child has started, never before it.

## Amendment 2026-10-12 (architect, PDK-075) — the staging directory belongs to the agent

Decision 16: a release staged while a probation or a pending rollback runs is ignored by the supervisor (`onRequest`);
when the probation concludes, `finishAt` removes `staging/request.json` and the directory of the release it processed,
and the ignored release's `staging/<version>/` stays behind (PDK-043 Review 1). The supervisor is at 786 of its 800
counted lines (decision 15), and a supervisor change ships only through the distribution package (contract 1), so the
cleanup is the agent's:

- The agent owns `/var/lib/paddock/staging/`. At start and at every check-in before it stages a release, while
  `staging/request.json` does not exist, the agent removes every other entry of the staging directory: a release
  directory without a request is garbage, whether the supervisor dropped its request at the end of a probation or a
  pending rollback, refused it as invalid (`cleanup("")`), or the download was interrupted before `request.json` was
  written. While `request.json` exists nothing is removed: the supervisor may be reading the request.
- The supervisor is not changed. It keeps removing `request.json` and the directory of the release it processed
  (`cleanup`), and `resumeRequest` keeps its rules; both tolerate a directory the agent removed first (`os.RemoveAll`
  of a missing path is no error), and the agent tolerates the supervisor removing it concurrently (an error of the
  sweep is logged at warning level and does not stop the check-in).
- A release the supervisor ignored is staged again when the server still offers it (the agent treats "no request, no
  result" as not staged), as before; the sweep costs no additional download, because `Stage` wrote the files again
  anyway.

## Amendment 2026-10-30 (PDK-480) — accepted residual in the update flow
A supervisor restart that finds `request.json` without `staging/<version>/` (a crash between the two cleanup removals,
microseconds wide) writes `signature_invalid`. The reported failure code is wrong, the device counts as
one failure toward the release's rollout halt rate and skips the release until a newer one; nothing is activated,
updates do not wedge, and the agent marks the release as failed. Accepted by the architect so that the supervisor stays
unchanged (design contract 1); see the amendment in ADR 0024.

## Amendment 2026-10-30 (PDK-496, main as architect lead) — release files are immutable once published

Decisions 19 and 20 are extended by an upload lease. Since PDK-432 the database refuses to record a file for a
release that was published after the upload's draft check. The object store write, however, runs between the two
transactions of the upload, under a deterministic object key. Without the lease, an upload that was still writing when
the release was published could overwrite the published object. Object keys stay unchanged, because deployed agents
validate the package path.

- **Lease.** Every write path for a release file (artifact and package upload, and through them the host command
  and the import of ADR 0043) takes a lease on `(version, object_key)` in its first transaction (table
  `agent_upload_lease`, migration 00077). It takes the lease in the same statement as the PDK-432 draft guard
  (`FOR SHARE` on a draft release). The lease lasts `agentrelease.UploadLeaseTTL` (10 min). An unexpired lease on the
  same object refuses a second upload with `invalid_state`; an expired lease is taken over. A new write path for
  release files must take the lease as well.
- **Write deadline.** The object store write runs under a deadline of `agentrelease.UploadStoreTimeout` (5 min),
  measured from when the lease is taken. The margin to the lease absorbs clock skew between server and database, so
  the write ends before the lease does.
- **Commit.** The second transaction records the file through the guarded upsert and drops the lease. If the lease
  has expired or been taken over, the commit is refused with `invalid_state` and rolled back, so a late commit never
  records a file.
- **Failed write.** Only a write the store answered with a 4xx on its only attempt is a definitive rejection
  (`objectstore.ErrRejected`), and only that drops the lease at once. Every other failure keeps the lease until it
  expires, because the store may still complete the write: a timeout, a cancel, a transport error, a 5xx, or a 4xx
  after an SDK retry.
- **Publish.** Publish locks the release `FOR UPDATE` and deletes its expired leases. While an unexpired lease exists,
  it refuses with `invalid_state`. It then hashes every stored artifact and package object as it streams and compares
  the SHA-256 with the row. This verification is bounded by `agentrelease.PublishVerifyTimeout` (2 min) because it
  runs under the row lock; a timeout or store error returns `upstream_unavailable`. A missing or mismatched object
  refuses with `invalid_state`, and the failed `agent_release.published` event lists the objects in
  `mismatched_objects`.
- **Residual risk.** A store-side write that completes more than the lease lifetime after its upload gave up, and
  after the publish, is not detected. Devices refuse such an object by its SHA-256 (fail safe) until the release is
  replaced.

## Amendment 2026-11-16 (architect, PDK-1118) — supervisor decisions under disk stalls; line budget 835

Slow device disks can stall a single fsync for half a minute (measured: 33 s for a 7-byte fsync under parallel
writers; PDK-1115 Review 1). The probation's health verdict does not depend on a disk write, but two side paths of
decision 16 do, and both fixes belong in the supervisor: it alone flips the slots and refuses downgrades (decision 15),
and a fail-closed decision under an I/O stall cannot be delegated to the agent it judges. Both parts ship in the same
change (PDK-1118), with an external review.

**Part 1 — the probation window is bounded across supervisor restarts (decision 16).** `WatchdogSec=60` stays, the
watchdog stays petted once per tick from the single loop goroutine, and the probation stays 10 min (2 min with
`paddock_dev`). Until now `resumeProbation` set `SwitchedAt = Now()`, so every watchdog kill during a stalled rollback
pass started a full new window and the rollback of a sick release could be postponed again and again. The rule now is:

- The probation log records the kernel boot ID at the switch: field `boot_id` (string, `omitempty`) of
  `probation`, set in `onSelfTest` and in `rebuildProbation` from `Config.BootID`. `New` fills an empty
  `Config.BootID` from `/proc/sys/kernel/random/boot_id` (trimmed; a read error leaves it empty); tests inject it.
- `resumeProbation` no longer overwrites `SwitchedAt`; the persisted switch time stays the start of the window. The
  resumed deadline is `Now() + remaining`, with `remaining = min(max(SwitchedAt + Probation - Now(), Probation/5),
  Probation)`, so it carries the monotonic clock of the resume, never extends the original window (a clock set back
  cannot stretch it past one fresh window), and leaves a healthy agent that the restart killed (`KillMode=mixed`) at
  least `Probation/5` (2 min; 24 s with `paddock_dev`) to check in again.
- If the log's `boot_id` is empty (a log of an earlier supervisor, a rebuild that could not read the boot ID) or
  differs from `Config.BootID` (the device rebooted; a watchdog restart never changes it), `remaining = Probation`,
  as before: after a reboot the network may need minutes, and a short window would roll back healthy releases.
- Nothing else changes: the check-in mark is cleared on resume, the switch counts as `unsynced`, the rollback runs from
  the loop after the child has started. A resume whose deadline has passed rolls back at the first tick after the
  floor; within one boot, watchdog restarts can postpone a rollback by at most `Probation/5` each, not by a window.
- Rejected: petting the watchdog after every completed fsync (it would wrap `SyncDir`/`SyncFile`, blur the meaning of
  the watchdog, which proves a responsive loop, and break the tests' tick counting, which counts `WATCHDOG=1`); a
  watchdog goroutine (it would pet a hung loop); raising `WatchdogSec` or the window (excluded by the ticket); keeping
  `SwitchedAt` without the boot ID (a reboot after the deadline would leave only the floor to a booting laptop).

**Part 2 — a stalled `paddockd version` defers the decision (decision 16, direction B).** A `paddockd version` call
that hits its 10 s timeout is distinguished from an agent that cannot report a version. In `onRequest` such a timeout
writes no outcome and keeps `staging/request.json`; the request is processed again on a later tick, and after a
restart through `resumeRequest`, so a stall never lets a release that is not newer pass the downgrade refusal. In
`rebuildProbation` such a timeout keeps the unreadable probation log and skips the probation until the next start,
instead of rebuilding or dropping it from a slot that only looked version-less. Rejected: refusing the release with
`downgrade_refused` on a timeout (a false failure counted against the rollout, and the agent marks the release as
failed); moving helpers out of the supervisor to make room (it would split the A/B logic across components that update
on different channels).

**Part 2, persistent stall — visibility and the way out.** If `paddockd version` of the active slot hangs on every
call (an agent binary that deadlocks, or reads of `/opt/paddock/agent` that never complete), the request is deferred
for good. While `staging/request.json` exists the agent stages nothing (`update.Pending`) and installs no supervisor
package, so neither the rollout nor *Update agent now* reaches the device. No new outcome code is introduced (that
would change the result contract and needs its own decision); the rules are:

- **Retry rate.** Each attempt blocks the loop for up to the 10 s timeout, so a deferred request is not retried on
  every tick: the wait between attempts starts at `pendingRetryStart` (10 s) and doubles up to `pendingRetryMax`
  (5 min), the constants of a pending rollback; it resets when a request is processed or removed. A restart retries
  at once through `resumeRequest`.
- **Device.** Every deferred attempt logs one warning, `update request deferred: the active agent did not report its
  version in time`, with the requested version and the next wait (at most 12 lines an hour). It is in the
  supervisor's journal and in the diagnostics bundle (`journal/paddock-supervisor.log`), which an administrator
  requests from the portal.
- **Fleet.** The device keeps checking in with its old agent version: the fleet overview counts it as outdated
  against the current release (`agent_outdated`), the device page shows the old version, and an *Update agent now*
  request ends after 24 hours without a report. The fleet shows that the update does not arrive, not why; the why
  is in the diagnostics bundle. Accepted residual for alpha.11; a reason visible in the portal needs a new event or
  check-in field and a separate decision.
- **Way out (operator, on the device, root).** A supervisor restart alone, *Update agent now* and `apt install
  --reinstall paddock-agent` do not help: the restart asks the same binary again, the agent does not stage while the
  request waits, and the package's postinst never touches an existing `current` or the slots. What works is to make
  the active slot answer again and restart the supervisor, which then processes the waiting request with signature
  check, downgrade refusal, self-test and probation: (1) if the other slot holds a working agent
  (`timeout 15 /opt/paddock/agent/<slot>/paddockd version` prints a version), point `current` at it with the same
  `ln -sfn` and `mv -T` commands as in *A rollback that failed*; otherwise (2) copy the packaged binary into the active
  slot (`install -m 0755 /usr/lib/paddock/paddockd /opt/paddock/agent/<active>/paddockd.new`, then `mv -f` over
  `paddockd`); then `systemctl restart paddock-supervisor`. PDK-1118 documents this in
  `docs/operations/agent-releases.md` as a new subsection `### An update that waits for the active agent` under
  *On the device*, after *A rollback that failed*, together with the journal query
  `journalctl -u paddock-supervisor | grep 'update request deferred'`, and adds a `changelog.d/` fragment.
- **Budget.** The back-off and the warning take up to 5 lines from the buffer of 6 below; the ceiling stays 835.

**Budget.** The supervisor counts 797 lines at 64382b2f. Part 1 is estimated at 11 counted lines (`Config.BootID` 1,
reading it in `New` 4, the `probation` field 1, the two struct literals +1 each, the resumed deadline +3); part 2 at
21 (implementer's estimate). 797 + 11 + 21 = 829, plus a buffer of 6: the ceiling is **835**
(`test/supervisor-budget.sh`, its regression test and the `Makefile` comment change with it). The principle of design
contract 1 is unchanged: the supervisor stays one goroutine's loop with no new dependency, simple enough to need no
updates; only the number changes. A change that needs more than 835 lines stops and goes back to the architect.

**PDK-1118b rollback ordering (architect, 2026-11-16).** Today a supervisor killed by the watchdog after `rollback`'s
flip back has landed, but before the log records `rolling_back` or the outcome, leaves an undecided log with `current`
on `FromSlot`. On disk that looks the same as a switch whose flip never landed, so `resumeProbation` drops the log and
reports nothing. The rollout then does not count the failure (contract 6), and the agent may stage the release again.
The rollback therefore records its intent before it flips back:

- `rollback` sets `RollingBack = true` and writes the probation log (`writeJSON`, synced) **before** `flipBack`.
  The write after a flip whose sync failed is removed; that branch only sets `s.rolledBack`. If the intent write fails,
  the flip back runs anyway: a rollback never waits for the disk (contract 4). The residual is today's behaviour: a
  kill in that window reports nothing.
- An undecided log with `current` on `FromSlot` and without `rolling_back` now means only "the switch never landed".
  It is still dropped without a result.
- `RollingBack` with `current` on `FromSlot`: as today, the supervisor resumes the rollback, makes the flip back
  durable (`confirmFlip`) and reports `rolled_back`.
- `RollingBack` with `current` on `ToSlot` (the intent is recorded, but the flip back did not land or was lost with
  the power): the probation does **not** run again. `resumeProbation` takes the existing pending-rollback branch: its
  condition gains `|| p.RollingBack && s.activeSlot() == p.ToSlot`, so `RollbackPending = true` and
  `s.rolledBack = &p`, with no result written at the restart. At the first tick, `confirmRollback` flips back once
  (`retryFlipBack`).
  - If the flip succeeds, `confirmFlip` makes it durable, then `rolled_back` is reported and the previous agent
    restarts.
  - If it fails, the existing ADR 0024 path runs: `keepRollbackPending` reports `rollback_failed` once, and the retries
    back off until a flip back lands, which then reports `rolled_back`.
  - `rolled_back` is never reported while `current` points at `ToSlot`. Until the first tick, the failed release runs,
    as in every pending rollback (contract 8).
  - `p.RollingBack = false` before the resumed probation forward is removed. That line can no longer be reached with
    `RollingBack` set.
- `RollingBack` with `current` on neither slot is dropped as before. The decision names `FromSlot`, but an
  unknown `current` is not overwritten.
- **Kill matrix.** The tests in `window_test.go` cover each point; `TestWatchdogKillAfterTheFlipBackConverges` changes
  to expect `rolled_back` where it expected no result.
  1. *Before the intent write.* The log is undecided and `current` is on `ToSlot`. The probation resumes (Part 1 window,
     floor `Probation/5`) and decides anew. No result is written at the restart; the new decision reports.
  2. *During the intent write.* `writeJSON` is atomic: the log is the old one (row 1) or the complete new one (row 3),
     never torn.
  3. *After the intent write, before the flip.* `RollingBack` with `current` on `ToSlot`, handled as the pending
     rollback above. The result is `rolled_back` once the flip back lands, or first `rollback_failed` and later
     `rolled_back` if the flip back fails.
  4. *After the flip, before the outcome is recorded* (a stall in the flip's `SyncDir`, or in `conclude`'s `SyncFile`
     before the rename). `RollingBack` with `current` on `FromSlot` resumes the rollback, then `confirmFlip`, then
     `rolled_back`. If `conclude`'s rename landed already, the log holds `outcome: rolled_back`, and the restart
     writes that same result again.
  5. *After the outcome* (the log records `rolled_back`; the result is written or not). The restart writes the
     recorded result again with the same `at`, or nothing if the log is already gone. The agent reports it once.
  - Regression that must stay green: a kill in the switch's own log write or flip (an undecided log, no
    `rolling_back`, `current` on `FromSlot`) reports nothing and drops the log.
- **Protocol, audit, budget.** The result contract, the device protocol and the audit registry do not change.
  `rolled_back` and `rollback_failed` exist already. Estimate: moving the intent write is net 0, the extended
  condition +1, and the removed `p.RollingBack = false` −1. That gives about 834 of 835. The ceiling stays 835; a
  change that needs more stops and goes back to the architect. PDK-1118b ships after PDK-1118, in the same
  distribution package (contract 1).

**PDK-1118 fix batch after the external review (architect, 2026-11-16); line budget 865.** This paragraph is binding
and replaces the sentences above that it contradicts. The rule of Part 2 that a kept log waits "until the next start"
is replaced by M2. PDK-1118b above stays as written.

- **M1 — a resume after a reboot starts the window anew, and records that.** In `resumeProbation`, a log whose
  `boot_id` is empty or differs from a non-empty `Config.BootID` gets `SwitchedAt = Now()` and `BootID =
  Config.BootID`, and is written back with `writeJSON` before the window is computed. If the write fails, an error is
  logged and the new values hold in memory. `remaining` is then always the formula `min(max(SwitchedAt + Probation -
  Now(), Probation/5), Probation)`; the separate assignment `remaining = Probation` is removed. A watchdog restart
  later in the same boot therefore gets at most the rest of the window, never a new one.
  - *Residual:* with an unreadable boot ID (`Config.BootID == ""`), every resume keeps the full window, as before.
    Item m5 makes this visible.
- **M2 — a kept log is retried during the run, and no request is processed meanwhile.**
  - `Supervisor` gains `keptLog bool`. `resumeProbation` sets it to `false` on entry. Its `versionTimedOut` branch
    sets it to `true` and schedules a retry through the deferral back-off of Part 2. That back-off becomes the helper
    `deferRetry()`, which doubles `deferWait` from `pendingRetryStart` up to `pendingRetryMax` and sets `deferredAt`;
    `onRequest` calls the same helper.
  - `onRequest` ignores requests while `keptLog` is set, with the existing "update in progress" warning. `resumeRequest`
    returns without doing anything while it is set. So a request left from the switch can never produce a
    `downgrade_refused` or `signature_invalid` for the running release (PDK-066).
  - When `deferredAt` is due, the tick handler checks `keptLog`. If it is set, the handler calls `resumeProbation()`
    and then `resumeRequest(ctx)`; otherwise it calls `onRequest(ctx)` as today. Each retry blocks the loop for at
    most two version calls (20 s), well below `WatchdogSec=60`.
  - A rebuilt probation forward runs with the agent of `current` that is already running. A rebuilt pending rollback
    continues through `confirmRollback`. A log that is dropped also has its request removed (`dropProbation`).
    `cleanup` resets `deferWait`, as before.
  - *Residual:* a sick release keeps running for the duration of the stall plus one window from the rebuild. That
    window is bounded and the rollback follows (contract 4).
- **m3 — the self-test after a stall.** `onSelfTest` no longer calls `version` for `from`. The struct `selfTest` gets
  a field `from string`, which `onRequest` fills with the `from` it has already checked. So `" timed out"` can no
  longer reach the log, the result or an audit param.
  - *Residual, accepted:* a version check inside `runSelfTest` that times out stays `self_test_failed`. The run of
    `paddockd self-test` itself, with its `SelfTest` timeout, has the same exposure to the stalled disk. There a stall
    cannot be told apart from a new binary that hangs, and a hanging binary must fail closed (contract 3).
- **m4 — clock and the passed state.** Both are accepted residuals; neither is fixed.
  - `CLOCK_BOOTTIME` is rejected: reading it needs either a new import for the supervisor or an uptime field and a
    `/proc/uptime` reader with a seam, about 10 lines. A clock step within one boot moves the window: forward, it
    leaves at least `Probation/5` at the next restart; backward, it is capped at one window.
  - `passed` is not persisted. A kill while a passed probation confirms its switch re-judges it with at least
    `Probation/5`. The agent checks in at its start, so only an agent that cannot reach the server within that time is
    rolled back, which is the same class as a failed probation.
- **m5 — an unreadable boot ID is visible.** If `New` cannot read `/proc/sys/kernel/random/boot_id`, it logs one
  warning (`slog.Warn`, with the error) and keeps `BootID` empty.
- **m6 — no real short timeouts in tests (flake rule).**
  - `Config` gains the seam `Version func(dir string) string`. When nil, the default is the real call. The current
    body of the `version` method moves unchanged into the package function `runVersion(dir string, timeout
    time.Duration) string`. The method returns `s.cfg.Version(dir)` when the seam is set, and otherwise
    `runVersion(dir, cmp.Or(s.cfg.VersionTimeout, 10*time.Second))`.
  - `stallVersion` in `stall_test.go` injects a `Version` that returns `versionTimedOut` for the stalled slot until
    `release()`, and otherwise `runVersion(dir, 10*time.Second)`. The tests no longer set `VersionTimeout`.
  - Exactly one unit test still exercises the real timeout: `runVersion` on a script that only runs `exec sleep 300`,
    with a 500 ms timeout, returns `versionTimedOut`. No healthy call runs under a short timeout.
- **m7 — runbook.** In `docs/operations/agent-releases.md`, *An update that waits for the active agent* gets a new
  first step, before `current` is flipped or the binary is replaced. The operator removes the waiting request and its
  release:
  `rm -f /var/lib/paddock/staging/request.json && rm -rf /var/lib/paddock/staging/<version>`, where `<version>` is
  the `version` in `request.json`, read beforehand. The text says why: a waiting request compared against the other
  slot could pass the downgrade refusal. The agent stages the server's target release again on its own.
  - The sentence "The supervisor then processes the waiting request …" becomes: "The agent then stages the current
    release again, and the supervisor processes it as usual …".
  - Steps 1–3 become 2–4.
- **Internal Review 1 minors.**
  - A test pins the back-off reset in `cleanup`: defer a request, let it end (`downgrade_refused`), stage a second
    request while the agent stalls again, and expect `next_attempt_in=10s`.
  - The ticket and the closure note that AC 1 is superseded by Part 1 of this amendment, including M1.
- **Kill and stall matrix.** Each row is a test.
  - M1: (a) the log names `boot-0` and the supervisor runs as `boot-1`. The first resume gets a full window, the log
    then holds `boot-1` and the resume time, and a second resume at `P-1s` gets only the floor. (This is the external
    review's sketch `TestExtRestartAfterRebootKeepsTheWindow`.) (b) The write-back fails: the first run still keeps the
    full window. (c) With `BootID == ""` the window stays full and the warning is logged once (m5).
  - M2: (a) a torn log and a stalled B at start keep the log. After `release()` and the next due retry, the rebuild runs,
    and a release that never checks in is rolled back within one window plus the back-off (`rolled_back`). (b) As (a),
    with a leftover `request.json` for the running release: no `downgrade_refused` or `signature_invalid` result
    while the log is kept and after it. (c) As (a), with the stall never released: the retries back off 10 s, 20 s, …
    up to 5 min, and the log and the request stay. (d) As (a), with the pending marker: after the rebuild the pending
    rollback continues (`rolled_back` once the flip back lands).
  - m3: a stall of `paddockd version` on the active slot between `onRequest` and `onSelfTest` leaves `from_version`
    as checked in `onRequest`, never `" timed out"`.
  - PDK-1118b: rows 1–5 of the kill matrix above, plus the regression for the switch's own log write or flip.
- **Budget, counted lines (`test/supervisor-budget.sh`), measured 834 at 02e94b07.**

  | Part | Lines |
  |---|---|
  | M1 | +3 |
  | M2 | +11 (field 1, flags 2, call 1, `deferRetry` net +3, tick branch +4) |
  | m3 | 0 |
  | m5 | +3 |
  | m6 | +6 |
  | PDK-1118b | +1 (conservative) |
  | Sum | 858 |
  | Buffer | 7 |

  The ceiling is **865**. `test/supervisor-budget.sh`, `test/supervisor-budget_test.sh` and the `Makefile` comment
  change in the same commit as this paragraph. The principle of contract 1 is unchanged: one loop goroutine, no new
  dependency. A batch that needs more than 865 stops and goes back to the architect.

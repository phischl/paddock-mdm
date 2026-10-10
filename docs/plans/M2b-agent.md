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

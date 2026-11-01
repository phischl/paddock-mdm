# 0033 — Staged configuration rollout, change-set revert and report-only adoption
Status: Accepted (2026-10-16; plan `docs/plans/M11-safe-config.md`)

## Context

A configuration change reaches the whole fleet within one check-in interval: the compiler renders every affected
device from the live tables (`managed_file`, `managed_unit`, `package_hold`, `organization_update_settings`, …),
publishes a new bundle version per device and the agents apply it at their next check-in (ADR 0005, architecture
§7.1). Agent releases roll out in waves with an automatic stop (design contract 6, `agent_rollout`,
`domain/agentrelease`); configuration does not (roadmap F-01). There is no undo of a change set (F-02), no
per-device and fleet view of what applied, failed or drifted (F-03), and no supported path to enroll a laptop that
is already installed (F-19).

Facts about the code that bound the design (checked 2026-10-15):

- **Change sets exist only for declarative applies.** `PUT /api/v1/config` records a `change_set` (actor, source,
  counts, sections, plan); the portal's per-resource endpoints (managed files, units, package holds, profiles,
  assignments, device groups, settings) share the use-case layer but record no change set (ADR 0011 amendment
  2026-10-08). A plan stores a managed file's content as `sha256:… (n bytes)` (`declarative.ContentSummary`), not
  the content, so the before-state of a file content is not stored anywhere.
- **The compiler has one input: the live tables.** `compiler.render` reads `app.LoadManagedDefinitions`,
  `loadUpdates` and the identity data, resolves per device group (`managedconfig.Resolve`) and skips content-equal
  results. A bundle is the full desired state of one device; the agent applies a newer version whole and rejects
  resource types it does not know, which is why new capabilities are optional top-level sections (architecture
  §11.3 amendment 2026-10-08).
- **The agent already reports apply results per resource ID**: `bundle.applied` carries `{version, changed,
  errors[{id, message}]}` (`apply.Report`; `ChangedIDs` is not sent), `bundle.rejected` `{version, reason}` and
  `config.drift_corrected` `{version, resource_ids}`. The server records each as an audit event and nothing else;
  resources that applied without error are not named anywhere. The gateway rejects a whole event batch with 400
  `unknown_event_type` for an unknown type (ADR 0024), so a new event type blocks the spool of a new agent against
  an older server.
- **Agent rollouts**: `paddock_rollout_bucket(device_id)` = FNV-1a(32) of the UUID text mod 100; waves are
  percentages `{1,10,50,100}`; the worker advances after `min_wave_minutes`, halts when failed devices reach
  `max(failure_threshold_min, ceil(eligible × failure_threshold_percent / 100))`; at most one running rollout
  (`agent_rollout_one_running_idx`); every transition is audited (`agent_rollout.*`).
- **Sudo entries are checked server-side before a bundle is signed** (`visudo -c`, `device.bundle_render_failed`,
  `device.bundle_entry_omitted`). Managed files, units, holds and update settings have no such safety net.
- **Enrollment**: `paddockd enroll --config <file>` (operator, root) and the autoinstall path
  (`enroll.Autoinstalled`, reads `/etc/paddock/enroll.json` at the agent's start) send the same `EnrollRequest`;
  the server cannot tell them apart. The sudo reconciler's first apply quarantines foreign `/etc/sudoers.d` files
  and removes members of privileged groups (`tamper.sudoers_d_file`, `tamper.sudo_group_member`); the login
  reconciler installs Himmelblau and writes PAM/NSS configuration. On a laptop that was installed by hand this
  cuts the user off (roadmap auditor §4.2 F-19; design contract 8).
- The test VMs are enrolled exactly this way (`test/system/device.go` `Install`: `dpkg -i`, `paddockd enroll`).

Requirements from the role reviews: waves with a canary group, automatic stop, a visible wave per change set and an
urgent opt-out with step-up and a mandatory reason (F-01, AUD-15); sudo removals, user locks and revocations never
wait for a wave; every wave start, advance, halt, resume and override is an audited action (A.8.32); the
configuration version in force on device X at date D must be answerable for the audit retention period (A.8.9); the
revert is its own audited change that references the original (`reverts`), and stored before-states follow the
secrets rule and the retention matrix (A.8.32, AUD-07/M10); adopted devices are visibly distinguishable
(`enrollment_method`) and get a report-only first apply (A.8.1, contract 8).

## Options

### A. Where the staged state lives while a rollout runs

- **A1 — Overlay of the before-state over the live tables (chosen).** The change set is applied to the live tables
  at once, as today. The change set additionally stores the *before* item of every key it updated or deleted
  (`change_set.before`). While its rollout runs, the compiler renders a device **outside the current wave** from the
  live tables with the staged keys replaced by their before items (created keys omitted), and a device **inside**
  the wave from the live tables unchanged. + The database stays primary: the portal, `GET /api/v1/config` and
  `paddockctl` see the applied configuration; unrelated changes made during the rollout reach every device
  immediately because only the staged keys are overlaid; the overlay is the same record the revert needs; the
  compiler stays stateless per device (the overlay is a pure function of the rollout row and the wave). − The
  compiler gains one more input (the running rollout of the organization); a change set that touches a staged key
  while the rollout runs must be refused (otherwise the overlay would be stale).
- **A2 — The staged change set is not applied to the live tables until promoted; devices in the wave get it as an
  overlay.** + "Applied" means fleet-wide. − Two sources of truth while a rollout runs: the live tables no longer
  describe what the canaries run; `GET /config` and `paddockctl apply` diff against a state that hides the staged
  changes, so a GitOps apply re-stages or conflicts with them; promotion is a second write with its own failure
  modes. Rejected: it violates ADR 0011 in spirit (database primary, one write path).
- **A3 — Full snapshot of the rollout-able sections at rollout start; non-wave devices render from the snapshot.**
  + Simple compiler branch. − Every unrelated change during the rollout must also be applied to the snapshot, or
  non-wave devices miss it (including security-relevant withdrawals). Rejected.
- **A4 — Per-entity revision tables (`managed_file_revision`, …) and a per-wave "configuration generation".** +
  General history. − A data-model rewrite of four tables and every use case for a benefit the overlay gives at a
  fraction of the cost. Rejected for M11; the before map in the change set is the history record.

### B. Which configuration rolls out in waves

- **B1 — The device-configuration sections: `managed_files`, `managed_units`, `package_holds`, `settings.updates`
  (chosen).** These are the sections without a server-side safety net and the ones a typo can break fleet-wide
  (`resolved.conf`, a unit that must not be stopped, a hold with a wrong version). − A permission profile with a
  typo still reaches every device at once; the compiler's sudoers check blocks syntactically broken entries, and a
  wrong-but-valid entry is a privilege change that the auditor wants immediate in the withdrawal direction.
- **B2 — Every section, with a per-change classification into "withdrawal" (immediate) and "grant" (staged).** −
  A profile update mixes both directions; a login setting such as `sudoers_d_allowlist` is both; classifying per
  field is an open-ended rule set that would make the overlay partial per item. Rejected for M11; revisited when
  packages (M13, F-04) join the rollout-able sections.

### C. Device selection

- **C1 — The agent rollout bucket `paddock_rollout_bucket(device_id)`.** + Exists. − The same 1 % of devices would
  be the canaries of every agent release *and* every configuration change; a device that is a permanent canary
  for both sees correlated failures and its user bears every risk. Rejected.
- **C2 — A per-rollout bucket: FNV-1a(32) of `<device_id>:<rollout_id>` mod 100, plus an optional canary device
  group whose members are eligible from wave 0 (chosen).** + Different devices per rollout; a configuration rollout
  and an agent rollout are statistically independent; the canary group gives the administrator a deterministic
  first wave (the IT team's own laptops). The SQL function and the Go function are kept equal by a test, as for the
  agent bucket.

### D. Failure signal and stop

- **D1 — Apply and reject reports of bundles that carry the staged keys (chosen).** A device counts as failed when
  its newest report for a bundle rendered *with* the staged keys is `bundle.rejected`, or `bundle.applied` with an
  error on a staged resource ID (`file:<path>`, `unit:<name>`, `updates`). Eligible = active devices in the waves
  up to the current one. Threshold and advance rules as for agent rollouts; wave durations are shorter (default
  60 minutes, production minimum 15, development 1) because a configuration wave needs one check-in and one apply.
  The compiler tags each bundle row with the rollout it rendered with (`bundle.config_rollout_id`), so the count
  needs no parsing of bundle objects.
- **D2 — Additionally "device silent after apply".** − A laptop that is closed after applying is silent for hours;
  on a laptop fleet the false-positive rate defeats the stop. Not in M11; M8b's gap detection and M9's
  notifications cover silence separately.

### E. Concurrency of rollouts

- **E1 — One running or halted configuration rollout per organization (chosen).** Mirrors
  `agent_rollout_one_running_idx`; a halted rollout keeps its overlay, so it blocks the next staged change set until
  it is completed or reverted, which forces the administrator to decide. A change set that touches a key staged by
  the running rollout is refused (409 `rollout_conflict`); a change set that touches other keys is applied
  immediately (it is not a rollout) and reaches every device.
- **E2 — Several concurrent rollouts with disjoint keys.** − Overlays compose per key but the counts, the portal and
  the revert ordering become hard to explain. Rejected for M11.

### F. Urgent opt-out

- **F1 — Query parameters `urgent=true&reason=<2–500 chars>` on every write of a rollout-able section (`PUT
  /api/v1/config`, managed files, managed units, package holds, update settings), step-up required, audited with
  `rollout: urgent` and the reason (chosen).** The administrator decides per change; the audit event carries the
  override and its justification (AUD-15). With rollouts disabled for the organization, `urgent` is refused (400):
  every change is immediate anyway and the trail must not suggest an override that did not happen.
- **F2 — A per-organization switch only.** − Turning rollouts off to push one fix and forgetting to turn them on is
  the likely failure. Rejected as the only mechanism; the organization switch exists (default off) and the opt-out
  is per change.

### G. Revert semantics

- **G1 — A new change set with the item-level inverse (chosen).** `POST /api/v1/change-sets/{id}/revert` computes,
  per change of the original: create → delete the key; delete → create the before item; update → set the before
  item; keys of the original's sections that the original did not touch are untouched, so items created since are
  kept (roadmap F-02 risk). The desired document is the current export with those items replaced, diffed with the
  existing `declarative.Diff` and executed through the existing `configExec`, so every validation, role and step-up
  rule applies unchanged. Dry run first (`?dry_run=true`), then `expected_plan` as for `paddockctl apply`. The result
  is a change set with `reverts_change_set_id`, audited as `config.reverted`. A revert of the change set of the
  organization's running or halted rollout is immediate (its non-wave devices already run the before state) and
  ends the rollout with status `reverted`; any other revert is an ordinary change set and follows the rollout rule.
  A before-state that M10's retention has purged refuses the revert (409 `invalid_state`).
- **G2 — Rewrite history or "undo" by replaying the plan backwards without a plan.** Rejected: every change stays a
  change set, and the administrator sees the plan before anything is applied.

### H. Per-device status, history and the report-only first apply

- **H1 — Extend `bundle.applied` (chosen).** The data gains `resources: [{id, status: applied|failed|pending,
  message?, changes?[]}]` and `mode: enforce|report_only`. Old servers ignore the fields (the audit params are an
  allow list), old agents do not send them (the server then knows failures only). No new event type (ADR 0024
  precedent). The server stores the per-resource outcome in `device_resource_status`, every report in
  `device_bundle_report`, and `config.drift_corrected` marks resources `drift_corrected`. Apply messages stay
  status, not WORM: the audit params of `device.bundle_applied` keep today's `errors` and gain only `mode`.
- **H2 — Report-only mode as the optional top-level bundle field `mode: "report_only"` (chosen).** An agent that
  knows it plans every resource and writes nothing (no file, unit, update, login or sudo change, no stale-file
  removal, no drift correction, no local administrator management) and reports `bundle.applied` with
  `mode: report_only` and the planned changes per resource. An agent that does not know the field enforces — which
  is why the server sets report-only only for devices whose agent declared `enrollment_method: adopted` at
  enrollment (a field only new agents send). ADR 0005 is unchanged: the field is additive and absent for enforced
  bundles; ADR 0013 holds: additive, ignored by older agents. The administrator ends report-only mode with
  `POST /api/v1/devices/{id}/enforce` (typed hostname, audited `device.enforcement_enabled`), after reading what the
  first enforced apply would change.
- **H3 — Report-only as a server-side filter of the bundle (render an "empty" bundle).** − An empty bundle removes
  managed files the device never had, and the device would not report what enforcement will do. Rejected.
- **History:** `bundle` rows (version, content hash, created_at, rollout tag) plus `device_bundle_report` (what the
  device reported for each version, when) answer "which configuration was in force on device X at date D" without
  reading bundle objects; both are listed per device (`GET /api/v1/devices/{id}/bundles`). Retention belongs to
  M10's matrix (classes: configuration evidence; the rows reference no personal data beyond the device).

## Decision

1. **Rollout-able sections** are `managed_files`, `managed_units`, `package_holds` and `settings.updates`. Every
   other section stays immediate. User locks, login suspension, revocation and profile changes never wait for a
   wave; their audit events are unchanged.
2. **Every configuration write records a change set.** Per-resource endpoints of the eight declarative sections
   record a one-change change set through the same `insertChangeSet` path as `PUT /api/v1/config`, with the same
   plan shape. `change_set` gains `before jsonb` (the full before items of updated and deleted keys, keyed by
   section and key, managed file content included), `reverts_change_set_id`, `rollout` (`immediate | staged |
   urgent`), `urgent_reason` and `before_purged_at` (written by M10's purge; a NULL `before` with a purge timestamp
   refuses the revert).
3. **Staged rollout = overlay of the before items for devices outside the current wave** (option A1), with
   per-rollout buckets and an optional canary device group (C2), one running or halted rollout per organization
   (E1), failure counting on tagged bundles (D1), the urgent opt-out as query parameters with step-up and reason
   (F1), and the organization settings `settings/rollout` (`enabled` default false, `waves` default
   `{1,10,50,100}`, `min_wave_minutes` default 60, production minimum 15, `failure_threshold_percent` default 2,
   `failure_threshold_min` default 3, `canary_device_group_id` nullable).
4. **Rollout states** `running → halted → running`, `running | halted → completed` (worker after the last wave, or
   an administrator's `complete`), `running | halted → reverted` (through the revert of its change set). Every
   transition is one audited action: `config_rollout.advanced`, `config_rollout.halted`, `config_rollout.resumed`,
   `config_rollout.completed` (actor system or administrator); the start is carried by the apply's own event
   (`config.applied` or the per-resource code) with params `change_set_id`, `rollout`, `rollout_id`,
   `urgent_reason`; the revert by `config.reverted`. M9 notifies on `config_rollout.halted` and
   `agent_rollout.halted` through the audit index; no other interface is promised.
5. **Revert** as option G1: `config.reverted`, target the new change set, params `reverts_change_set_id`,
   `plan_sha256`, counts, sections, and, when it ends a rollout, `rollout_id` and `rollout_status: reverted`.
6. **Per-device status and history** as option H1: `device_resource_status`, `device_bundle_report`,
   `bundle.config_rollout_id`; list endpoints per device and per organization under the ADR 0018 contract.
7. **Adoption**: `EnrollRequest.enrollment_method` (`autoinstall | adopted`; absent → `unknown`),
   `device.enrollment_method` and `device.config_mode` (`enforce | report_only`; `report_only` at creation for
   `adopted`), the bundle field `mode`, the agent's report-only apply, `POST /api/v1/devices/{id}/enforce`
   (`device.enforcement_enabled`), the attention kind `report_only`, and the runbook
   `docs/operations/enroll-existing.md` with `paddockd preflight`.
8. **Interaction with agent rollouts**: independent buckets, independent counters, both may run at the same time;
   a device's agent update failure never counts toward a configuration rollout and vice versa. The portal shows
   both on the overview.

## Consequences

+ A bad managed file reaches 1 % of the fleet (or the IT team's own laptops) and stops there; the administrator sees
  per device and per resource what applied, failed or is pending, and undoes a change set with a reviewed plan.
+ ADR 0011 holds: the database is primary, one write path per use case, change sets for every write; ADR 0005 and
  0013 hold: no bundle schema change, one additive optional field, no new event type.
+ Existing laptops can be adopted without cutting anybody off; adopted devices are distinguishable and counted.
− The compiler reads one more row per organization and applies an overlay; a change set touching a staged key is
  refused while a rollout runs; a halted rollout must be completed or reverted before the next staged change.
− `change_set.before` duplicates managed file contents (≤ 64 KiB each) for the retention period; M10 owns the purge
  and the retention classes of `change_set.before`, `device_bundle_report` and `device_resource_status`.
− Report-only devices are unmanaged until an administrator enforces; the attention kind keeps that visible.
− Profiles and assignments are not staged (option B1); packages (M13) join the rollout-able sections when they
  exist.
Follow-ups: plan `docs/plans/M11-safe-config.md` (PDK-150 to PDK-164); architecture §7, §11.3, §11.5, §16, §17
amendments in PDK-163; the declarative document does not carry `settings.rollout` in M11 (a later plan may add it).

## Amendment 2026-11-01 (writes during an open rollout)

Architect decision for PDK-157 (plan M11 amendment R6.13), the precise reading of option E1 next to decisions 25 and
29 of the plan. A *section* is a section key of `configrollout.StagedKeys`; `package_holds` and `settings.updates`
count as one section (both render into the `updates` resource). While the organization has a `running` or `halted`
rollout, a write that is not urgent:

1. touches a staged (section, key) → 409 `rollout_conflict`;
2. otherwise touches any section the rollout stages → 409 `rollout_running`; a change set that also touches other
   sections is refused as a whole, never split;
3. otherwise (only sections the rollout does not stage, or no rollout-able section) → `immediate`: it reaches every
   device and starts no rollout.

An urgent write that touches a staged key is refused with 409 `rollout_conflict`; one that does not is `urgent` and
reaches every device. Reverts follow the same rule, except the revert of the open rollout's own change set, which is
immediate and ends the rollout (option G1). A device group deletion is a write of every section it cascades into.
Every refusal is decided inside the audited action.

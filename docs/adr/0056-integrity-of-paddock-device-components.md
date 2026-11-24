# 0056 — Integrity of Paddock's own device components: agent-side baseline and a server-generated hash policy
Status: Accepted (architect, 2026-11-16; maintainer decision §137 of 2026-11-16: PDK-1122 ships in 0.1.0-alpha.11
with both options, confirmed despite the size in §142; plan `docs/plans/M5a-inventory-and-vulnerabilities.md`, "Amendment 2026-11-16 (architect,
PDK-1122)")

## Context

The binding rules (root `CLAUDE.md`, "Protected areas", item 3) and architecture §11.5/§11.6 promise that a change to
the agent, the supervisor, `fleetd`, the update timer and their files and units is a tamper event. On `7f8ab8d7` only
the files that the inventory and updates reconcilers render are compared. Nothing reports a replaced agent or
supervisor binary, a flipped `current` slot, a foreign systemd drop-in, or a changed `agent.yml` or trust file.
The mutual-watch policy `paddock_agent_running` checks only the process name and path. The architecture's mutual-watch
paragraph in §11.5 claimed a binary-hash check that does not exist.

Facts that bound the design:

- The agent never replaces itself (design contract 1). The supervisor installs a release into the inactive slot after
  a minisign check. The supervisor upgrade helper (`agent/internal/supervisorpkg/upgrade.go`) restores the previous
  supervisor binary and unit by **copying** them back, not through dpkg. After such a rollback, dpkg's `md5sums` no
  longer describe the files on disk.
- Fleet policies are global. There is one query for all hosts, and it returns only pass or fail (plan M5a decision 2).
- Releases are immutable once published (plan M2b, amendment PDK-496). Paddock has no "yank". Only published releases
  reach devices. During a staged rollout and after a rollback, a device legitimately runs an older published release.
- A local root user can defeat every device-side check (RR-01). Both mechanisms raise the cost of a silent change;
  neither of them prevents a change.

## Options

1. **C: agent-side baseline, report-only.** Each drift pass, the agent compares its slots and `current`, the
   package-installed binaries (against dpkg `md5sums`), the agent's own configuration files and an allow list of unit
   drop-ins against a baseline. The baseline moves only through Paddock's own regular paths. It reports through
   the existing `device.tamper_protected_file_changed`.
   - Pro: covers every object of protected area 3. No contract change, no new dependency. The supervisor does not
     change.
   - Con: a replaced agent checks itself. An agent that is already tampered with reports nothing.
2. **A: server-generated osquery hash policy.** The worker builds the policy `paddock_agent_binary_known` from the
   SHA-256 of every published agent artifact and applies it to Fleet. A failure raises a new server-emitted code.
   - Pro: independent of the agent, so it catches a replaced agent binary.
   - Con: covers only the running agent binary. It needs a new audit code (public contract), and policy updates
     race with releases.
3. **B: supervisor self-check.** Not chosen. This was the architect's recommendation in the estimate requested in
   §134, and §137 took up only C and A. The supervisor's line budget (design contract 1) leaves no room, and the
   supervisor must stay simple enough to need no updates.

For A's downgrade handling:

- **A1: compare with the device's expected version.** This would need one policy per release or per-host data. Fleet
  policies are global and return pass or fail. The "expected" version is ambiguous during waves, holds, the manual
  update policy and rollbacks, so A1 would raise false alarms on regular flows.
- **A2: accept any published hash.** A genuine older published release passes. This is a documented residual.

## Decision

**C and A together (maintainer decision §137), with A2.**

1. C runs in the agent's drift tick in both enforcement modes, changes nothing, and reports each change of an
   observed value once (rules: plan M5a amendment 2026-11-16, part C). The baseline file is
   `/var/lib/paddock/state/integrity.json`, written under the lock `/var/lib/paddock/state/integrity.lock`. The
   baseline moves only at these points:
   - its initialization (trust on first use);
   - an agent update result whose release the agent staged itself;
   - a supervisor upgrade result;
   - the agent's own writes of its configuration files;
   - a re-initialization from what the agent observes, with a `Warn` and no event, in two cases: an update result
     without a matching staged record (C4), and a corrupt baseline file (C9).

   The last case and a forged update result are the paths a local root user can use to move the baseline (RR-148).

   For dpkg-installed files the baseline is dpkg's `md5sums`, plus a recorded exception after a supervisor rollback.
2. A uses the policy `paddock_agent_binary_known`. It passes unless a `paddockd` process that runs from
   `/opt/paddock/agent/` with its binary on disk has a SHA-256 outside the set of published agent artifacts. A
   failure raises `device.tamper_agent_binary_changed`, once per failure, only for a host that evaluated the current
   definition at least 2 minutes after the worker applied it. There is no check-in silence rule: a replaced agent
   keeps checking in.
3. The worker regenerates the policy every inventory round from the database (at most 5 minutes after a publish).
   Applying it is idempotent. Publish triggers no separate path, because the evaluation gate already makes the lag
   harmless. With no published release, the policy is `SELECT 1;`.
4. **Binding for future work:** a future "yank", withdrawal or deletion of a published release MUST keep that
   release's hashes in the policy. A withdrawn release still runs legitimately on devices until they update.
   Every new Paddock component or package installed on devices MUST join C's checked set (C5, C6) in the same
   change, or be named as a residual in RR-148.
5. A new code in the closed registry is an additive change of the audit event contract (the SIEM integrations and the
   generated `docs/compliance/audit-codes.md`). Its MSGID alias is `device.tamper_agent_bin_changed`, because the
   code is longer than 32 characters. ADR 0031's alias table is add-only.

## Consequences

- Positive: once PDK-1122a and PDK-1122b are merged, every binary, unit and agent-written configuration file of
  protected area 3 has a check, with the exceptions named in RR-148. Until then, architecture §11.5 marks these checks
  as planned. A replaced agent is caught independently of itself.
- Negative:
  - Two residuals are accepted. RR-148 (C): a local root user can rewrite the baseline file, a dpkg `md5sums` file or
    an update result, or corrupt the baseline file to force a re-initialization; package symlinks other than
    `current` and `/usr/bin/paddockd` and some reconciler-written files are not checked (plan M5a, C2). RR-149 (A2):
    a genuine older published release passes the policy.
  - dpkg `md5sums` are MD5. Here they are only a change detector, not a signature, and root can rewrite them anyway.
  - The system-test harness must publish the binaries it installs on the VMs. Otherwise A reports every VM.
- Follow-up work: PDK-1122a (C) and PDK-1122b (A). A future yank feature must honor decision 4.

## Amendment 2026-11-16 (architect, PDK-1122b review round 1)

The reviews of PDK-1122b showed two gaps in decision 2. Details, tests and texts: plan
`docs/plans/M5a-inventory-and-vulnerabilities.md`, "Amendment 2026-11-16 (architect, PDK-1122b review round 1)",
A7 to A11.

1. **Judged processes (replaces the first sentence of decision 2).** The policy `paddock_agent_binary_known` passes
   unless a running process that is named `paddockd`, runs a file named `paddockd` or a file below
   `/opt/paddock/agent/`, or was started by `paddock-supervisor` (other than in the instant before `exec`) runs an
   executable whose SHA-256 is outside the set of published agent artifacts. The hash is taken from
   `/proc/<pid>/exe`, the executable the process actually runs, with the process's path as fallback for a process
   that exits during the evaluation. The filter on `/opt/paddock/agent/` and the exception for `on_disk = 0` are
   dropped.
   - Reason: with the old filter, pointing `current` elsewhere, a `BindReadOnlyPaths=` drop-in or a changed process
     name hid a replaced agent from the only check that does not run inside it. The maintainer's mandate is that a
     change of protected area 3 is detected.
   - Option not chosen: keep the filter and only name the evasions in RR-149. It is cheaper but leaves the cheapest
     evasion, one symlink, undetected.
   - False alarms: Paddock runs only slot binaries of published releases; no `paddockd` running still passes; a
     locally built `paddockd` on a device fails, which is the intended meaning and documented.
2. **Once per failure across unanswered results.** Fleet resets a policy's results when its query changes, which
   happens at every publish. A stored failure that was already reported keeps its row and mark while Fleet lists the
   policy without an answer; an unreported one is deleted as before. This holds for every Paddock policy, including
   `paddock_agent_running`.
3. **RR-149** now reads: the policy trusts every published release and judges only processes it recognizes as the
   agent. A foreign program that is none of the above and checks in while the genuine agent is stopped is not
   reported by this policy, nor by `paddock_agent_running`, which stays silent while the device checks in (plan M5a
   decision 8). Closing that gap changes decision 8 and is proposed as PDK-1122c, pending the maintainer's approval.
   Swapping the executable link (`PR_SET_MM_EXE_FILE`), code injection into the genuine agent, an LSM policy against
   osquery and a replaced osquery stay residual (RR-01).

Consequences: the description of `device.tamper_agent_binary_changed` changes before its first release (code,
params and MSGID alias unchanged). The policy query is longer by a constant; its size still grows with the number of
published hashes, which the worker logs.

## Amendment 2026-11-16 b (architect, PDK-1122c) — a check-in does not prove the genuine agent

Status: **accepted** (`decisions-alpha11.md` §147, maintainer and main, 2026-11-16). Details, texts
and tests: plan `docs/plans/M5a-inventory-and-vulnerabilities.md`, "Amendment 2026-11-16 b (architect, PDK-1122c)".

**Context.** Item 3 of the previous amendment left a gap: a local root user stops the genuine agent and lets a
foreign program under another name and unit check in with the device's credentials. `paddock_agent_binary_known` does
not judge that program, and `paddock_agent_running` fails without a report, because plan M5a decision 8 reports only
devices that have not checked in for 15 minutes.

**Options.**

1. **Prove the genuine agent in the check-in** (a challenge only the published binary answers, a process-identity
   binding between osquery and the check-in, TPM attestation).
   - Pro: would make the check-in itself trustworthy.
   - Con: root holds the device key (file or TPM) and can run the genuine binary as an oracle or relay its signed
     requests; Fleet policies are global and pass/fail, so no per-device binding reaches osquery; attestation shows
     what ran since boot, not what signs now. Every variant costs a device API change and proves nothing against root.
2. **Report the agent's absence from osquery evaluations regardless of check-ins (chosen).**
   - Pro: no device API, agent or supervisor change; uses data the server already stores (Fleet's
     `policy_updated_at`, migration 00161).
   - Con: a decoy that keeps `paddock_agent_running` passing, or a stopped fleetd, defeats it.
3. **Leave decision 8 and document the gap.** Cheapest; leaves the cheapest impersonation unreported.

**Decision.** Option 2.

1. A check-in is never treated as proof that the genuine agent runs. The device API (`api/openapi/device.yaml`
   1.0.0) does not change; agents of every supported release keep working unchanged in both directions.
2. Plan M5a decision 8 reports `device.tamper_agent_not_running` also when `paddock_agent_running` failed in two
   evaluations at least 15 minutes apart (Fleet's clock) with no stored pass between them, whether or not the device
   checks in. The silence rule stays. Report only (design contract 8).
3. The existing code `device.tamper_agent_not_running` is reused; it gains the optional params `failing_since` and
   `evaluated_at` and a new description (additive change of the audit event contract).
4. RR-149 is rewritten: the gap of item 3 is closed for a foreign program while fleetd evaluates and no decoy runs;
   a decoy and a stopped fleetd stay residual. Detecting a fleetd that falls silent while the device checks in is
   proposed as PDK-1122d.

**Consequences.**

- Positive: the naive impersonation is reported within about 40 minutes at the default policy interval, with no
  contract cost beyond one nullable column and two audit params.
- Negative: a root user who also keeps a decoy `paddockd` running or stops fleetd is not reported (RR-149, RR-01).
  A device whose `/opt` is a symbolic link elsewhere is reported (unsupported layout, documented).
- Follow-up: PDK-1122c (implementation, after PDK-1122b), PDK-1122d (proposed, maintainer decision).

## Amendment 2026-11-16 c (architect, PDK-1122d) — the server watches fleetd

Status: **accepted** (`decisions-alpha11.md` §148, 2026-11-16). Details, texts and
tests: plan `docs/plans/M5a-inventory-and-vulnerabilities.md`, "Amendment 2026-11-16 c (architect, PDK-1122d)".

**Context.** After amendment b, a root user who replaces the agent and also stops fleetd is not reported: the impostor
does not report the stopped `orbit.service`, and fleetd evaluates no policy. The maintainer put the fix into
alpha.11 (§147) with a guard against alarm waves during inventory-system outages.

**Options.**

1. **Server-side watch of Fleet's contact times (chosen).** Each round, a device that keeps checking in while its
   fleetd's last contact with Fleet is 15 min older than the newest contact of any host, for 15 more minutes, is
   reported, if at least one and at least half of the live devices reach Fleet.
   - Pro: no agent, device API or supervisor change; uses the host list the worker already reads every round.
   - Con: blind on single-device installations and when most devices are cut off; a site that blocks only Fleet's
     address is reported.
2. **Per-organization quorum** (the maintainer's example). Weaker: one Fleet serves every organization, and an
   organization with one device could never be judged.
3. **Agent-reported fleetd state.** Useless here: the impostor reports what it wants.

**Decision.** Option 1, report only, with the new registry code `device.tamper_fleetd_silent` (params
`fleetd_seen_at`, `last_contact_at`, `silent_since`), a tamper finding and no attention kind. The state lives in the
database (two columns on `device_inventory_ref`), so worker restarts change nothing. All freshness judgements use
Fleet's clock relative to its newest contact, so a Fleet that stops recording contacts looks fresh, not silent.

**Consequences.**

- Positive: the "stopped fleetd" gap of RR-149 is closed while most devices reach Fleet; an operator sees an
  installation-wide Fleet reachability problem as a suppression log line and gauge.
- Negative: residuals stay in RR-149 (a decoy agent; a replaced or simulated osquery; single-device installations;
  a root user controlling more than half of the live devices). One more additive code in the audit event contract.
- A lasting suppression is itself an alert (`PaddockFleetSilenceWatchSuppressed`, critical, added in §148), so a
  root user who controls more than half of the live devices stays unreported per device but not unnoticed.
- Follow-up: PDK-1122d, after PDK-1122c; PDK-1122e (attention kind for the event, alpha.12).

## Amendment 2026-11-16 (architect, PDK-1122b review round 2)

Details: plan M5a, "Addendum 2026-11-16 (architect, PDK-1122b review round 2)".

1. **What A claims (qualifies decision 2, the previous amendment's item 1 and the consequence "A replaced agent is
   caught independently of itself").**
   - A judges, at each evaluation, only the processes it recognizes as the agent while they run. It catches a replaced
     agent independently of the agent only while such a process runs the replaced binary.
   - The previous amendment's reason "it leaves the cheapest evasion, one symlink, undetected" is withdrawn. A symlink
     to a launcher that detaches the impostor and exits escapes A. The mutual watch of amendment b (PDK-1122c)
     reports it, because osquery then sees no genuine agent.
   - Which of A, C, PDK-1122c and PDK-1122d covers each evasion is mapped in the plan addendum.
2. **Replaced supervisor file.** The parent clause also matches a supervisor whose executable is
   `/usr/sbin/paddock-supervisor (deleted)`, and excludes that path as a child, the same way as the regular path. A
   regular supervisor upgrade passes: the old supervisor's children are genuine slot binaries.
3. **RR-149** is given as one text per merge (PDK-1122b, then c, then d). The text in this amendment's plan addendum
   supersedes the RR-149 text of amendment b, section 6, and amendment c's replacement applies to it unchanged.
4. **Unanswered policies.** A Paddock policy that hosts evaluate without an answer is counted in a gauge and logged
   once per full round. A re-tamper after a repair that a publish reset before the server stored the pass stays
   unreported until the policy passes again. This is documented, not changed.

## Amendment 2026-11-16 (architect, PDK-1122a review round 1)

Plan M5a, "Amendment 2026-11-16 (architect, PDK-1122a review round 1)", holds the binding detail. Changes to the
decision:

1. **A check that cannot run is reported (amends decision 1).** Every reason to skip an object or a pass belongs to a
   closed table of suspension causes (the lock held, `integrity.json` unreadable or unwritable, a pending update
   request, probation, an unprocessed result, the supervisor upgrade marker, the staged guard, the conversion skip, a
   held dpkg lock, a failed read or `systemctl show`). A cause that lasts past its bound in observed time (15 minutes
   for the baseline itself, 6 hours for Paddock's own flows; a suspend or restart counts as at most two drift
   intervals) raises `device.tamper_protected_file_changed` once per episode, with `file` naming the blocking path and
   the new value `check_suspended` of the existing param `reason`. This is an additive change of the released
   code's audit contract (description text; no new code, param name or MSGID). Options weighed: a new audit code
   (rejected: a new public code for a variant of the same finding), `file` only without `reason` (rejected: a SIEM
   and the operator could not tell a suspension from a change; it remains the fallback if the `reason` value is not
   approved), and a local `Warn` only (rejected by the maintainer guidance §148).
2. **The supervisor rollback exception needs the pre-upgrade state (amends the last sentence of decision 1).** Before
   it launches a supervisor upgrade, the agent records the SHA-256 of the supervisor binary and unit that are expected
   at that moment. After a rollback, a restored file becomes an exception only when its SHA-256 equals that record for
   the same version. A planted stale marker can no longer turn a replaced supervisor into an accepted exception. No
   supervisor line changes.
3. **The baseline moves at two more points, both Paddock's own writes:** a deferred re-sync of an agent-written file
   whose sync lost the lock, and an update result of the last staged release after a pending rollback.
4. **The check observes without the lock** and holds `integrity.lock` only to load, compare and save, so a slow pass
   never makes a Paddock writer give up.

5. **A baseline reset is reported (main §150; amends the re-initialization of a corrupt baseline in decision 1).** A
   corrupt `integrity.json`, or a missing baseline on a device whose baseline was once established (agent state
   `integrity_established_at`), is re-initialized as before, and is now reported once per episode as
   `device.tamper_protected_file_changed` with `file` the baseline file and `reason` `baseline_reset`. The episode
   ends with the next valid record. The re-initialization after an update result without a matching staged release
   stays a `Warn` without an event, because a rollback to an older agent causes it on a regular flow.
   Root who resets the agent state together with the baseline makes the device look freshly installed and stays
   silent here (RR-148); a server-side anchor would need a protocol or audit-contract change and was not taken. The
   Fleet policy (decision 2) and the mutual watches of PDK-1122c and PDK-1122d remain independent of the agent's state.

Consequences: RR-148 also names short-lived changes within one drift interval, the staged-guard, conversion and
re-sync windows, and that changes during a suspension are reported only as the suspension. An unwritable baseline
delays staging, supervisor upgrades and update results by at most 15 minutes before they proceed.

### Addendum 2026-11-16 (round 2, main and user decision §152)

The bounds of point 1 hold per **blocked object** (the baseline, the slots, each package, each agent-written file,
each unit), not per cause, so alternating causes no longer restart them. They are kept in observed time while the
agent runs. A gap between passes counts at most twice the check's interval, and that interval is capped at 1 hour
whatever `drift_interval_s` says. A pass runs at every agent start. The suspension state lives in the agent's
`state.json`, so restarts, a held lock or an unwritable baseline no longer reset it. Root who edits the agent state
resets it, the same residual as the joint reset in point 5. Plan M5a R15 holds the detail.

## Amendment 2026-11-16 d (architect, PDK-1122d) — osquery that stops evaluating, and a failing agent-running query

Status: **accepted** as reduced (2026-11-17, main, `decisions-alpha11.md` §159). Details, texts and tests: plan
`docs/plans/M5a-inventory-and-vulnerabilities.md`, "Amendment 2026-11-16 d (architect, PDK-1122d)". Builds on ADR
0057 (inventory hosts bound to their device, PDK-1123), which lands first.

**Context.** The PDK-1122c review found two cases that the mutual watch and amendment c do not report:
- an `osqueryd` that stops storing policy results while orbit keeps talking to Fleet;
- a `paddock_agent_running` query that stops answering on the device. Its empty result is dropped every round.

Amendment c also judged a device by the newest contact of every host with its hardware UUID. After ADR 0057, the
device's bound host is the one that counts.

**Options.**

1. **Server-side, from Fleet's host list (chosen).**
   - A device whose bound host's policy results are 30 minutes older than the newest host's is a silent fleetd
     (`reason` `policies`).
   - An unanswered `paddock_agent_running` on a host that evaluates its policies counts as a failing evaluation. Its
     query never changes (D7), so an empty answer means that the query failed.
   - Pro: no device or protocol change.
   - Con: `FLEET_OSQUERY_POLICY_UPDATE_INTERVAL` must stay at 15 minutes or less.
2. **A separate code for each case.** Not chosen: the operator needs to know that fleetd cannot confirm the agent,
   and the description names the cause.

**Decision.** Option 1, report only.

- Amendment c's `seen(d)` becomes the `seen_time` of the device's bound host (ADR 0057). For a device without a
  binding, it is the host Fleet enrolled first.
- `device.tamper_fleetd_silent` (unreleased) gains the params `policy_updated_at` and `reason`.
- The released `device.tamper_agent_not_running` gains one additive sentence in its description.
- Amendment c's migration becomes `00164` (PDK-1123 takes `00163`).

**Consequences.**

- Positive: the two cases of the review are reported; amendment c's watch follows the bound host.
- Negative: a longer description of a released code; an operator who raises the policy interval above 15 minutes
  gets false `policies` reports (documented).
- Follow-up: none beyond amendment c's.

## Amendment 2026-11-17 (architect, PDK-1126c) — Paddock-written identity files

Plan M5a, "Amendment 2026-11-17 f", holds the binding detail. C also judges the identity files the login reconciler
writes: `/etc/himmelblau/himmelblau.conf`, `/etc/paddock/login-deny` and the `90-paddock.conf` drop-ins of the three
Himmelblau socket units. Only their content is judged. Their baseline comes only from content Paddock wrote, never
from the disk. After each write that stays, the baseline takes the content just written; a file that already holds
Paddock's render is confirmed with that render when the login reconciler applies, and at every agent start for the
renders of the bundle enforced before. At every agent start without an entry, the baseline takes the render of the
bundle the agent enforced before; the drop-ins have no such render. Right before the login reconciler corrects one
of these files, it checks the file against the baseline. A change found there or in a pass raises
`device.tamper_protected_file_changed` once, and the login reconciler still corrects the file
(`device.login_applied`). A missing `login-deny` after an enforced bundle is a change, because its absence unlocks
every locked user. The remaining gaps are listed in RR-148.

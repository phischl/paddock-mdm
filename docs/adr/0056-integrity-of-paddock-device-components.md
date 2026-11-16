# 0056 — Integrity of Paddock's own device components: agent-side baseline and a server-generated hash policy
Status: Accepted (architect, 2026-11-16; maintainer decision §137 of 2026-11-16: PDK-1122 ships in 0.1.0-alpha.11
with both options; plan `docs/plans/M5a-inventory-and-vulnerabilities.md`, "Amendment 2026-11-16 (architect,
PDK-1122)")

## Context

The binding rules (root `CLAUDE.md`, "Protected areas", item 3) and architecture §11.5/§11.6 promise that a change to
the agent, the supervisor, `fleetd`, the update timer and their files and units is a tamper event. On `7f8ab8d7` only
the files that the inventory and updates reconcilers render are compared. Nothing reports a replaced agent or
supervisor binary, a flipped `current` slot, a foreign systemd drop-in, or a changed `agent.yml` or trust file.
The mutual-watch policy `paddock_agent_running` checks only the process name and path. Architecture line 1625 claims a
binary-hash check that does not exist.

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
3. **B: supervisor self-check.** Rejected, as already decided in §134. The supervisor's line budget (design
   contract 1) leaves no room, and the supervisor must stay simple enough to need no updates.

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
   - the agent's own writes of its configuration files.

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
   Every new Paddock component installed on devices MUST join C's checked set in the same change.
5. A new code in the closed registry is an additive change of the audit event contract (the SIEM integrations and the
   generated `docs/compliance/audit-codes.md`). Its MSGID alias is `device.tamper_agent_bin_changed`, because the
   code is longer than 32 characters. ADR 0031's alias table is add-only.

## Consequences

- Positive: every object of protected area 3 has a check. Architecture §11.5 and the binding rules become true. A
  replaced agent is caught independently of itself.
- Negative:
  - Two residuals are accepted. RR-148 (C): a local root user can rewrite the baseline file, a dpkg `md5sums` file or
    an update result. RR-149 (A2): a genuine older published release passes the policy.
  - dpkg `md5sums` are MD5. Here they are only a change detector, not a signature, and root can rewrite them anyway.
  - The system-test harness must publish the binaries it installs on the VMs. Otherwise A reports every VM.
- Follow-up work: PDK-1122a (C) and PDK-1122b (A). A future yank feature must honor decision 4.

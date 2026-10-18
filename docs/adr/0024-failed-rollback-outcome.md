# 0024 — Agent update: a failed rollback is a distinct outcome and stays pending
Status: Accepted (2026-10-12)

## Context
When a new agent release fails its probation, `paddock-supervisor` flips `current` back to the previous slot
(design contract 2 and 4). Since PDK-037 a flip back that still fails after five attempts is reported as
`self_test_failed`, the probation log is removed, and the device keeps running the release that failed its probation
without any further attempt to leave it. Three things are wrong with that: the label is false for the audit trail
(the self-test passed, the probation failed, the rollback failed), contract 4 is broken for good on that device
(nothing retries), and no surface tells an operator which devices are in this state. An operator cannot push the
previous version either: a release that is not newer than the active one is refused as `downgrade_refused`
(plan M4b.1 decision 11, release binding).

Constraints: devices in the field run the current protocol, and the server must keep accepting old agents
(ADR 0013). The gateway rejects a whole `POST /v1/events` batch with 400 `unknown_event_type` when one event has a type
outside `protocol.EventTypes`, and the agent then keeps the batch spooled (`agent.flush`), so an event type an older
server does not know blocks every later event of that device. Every probation ends in exactly one recorded result
(PDK-058); the audit registry is closed and codes are never rewritten; the device must keep working whatever happens
(contract 8).

## Options
- **Keep `self_test_failed` (status quo).** + No contract change. − False audit label; no retry; invisible to operators.
- **New event type `agent.rollback_failed`.** + Explicit on the wire. − A newer agent against an older server blocks
  its whole event spool on the gateway's 400; needs `pkg/protocol`, `api/openapi/device.yaml`, the gateway and the
  agent to change, plus an upgrade-order rule for operators.
- **New outcome `rollback_failed` carried by the existing event `agent.update_failed`; the server classifies the pair
  (type, outcome) into a new audit code.** + Compatible in both directions: an old agent maps the unknown outcome to
  `agent.update_failed` by its default branch, and an old server records that event under
  `device.agent_update_failed` with the outcome param and counts the failure; the `outcome` field already is the
  discriminator of `agent.update_failed` (`signature_invalid`, `downgrade_refused`, `self_test_failed`), and the
  server already branches on it (`downgrade_refused` does not count toward the failure rate, PDK-025). − One
  mapping keyed on two fields; servers older than this decision show the approximate code.
- **Retry:** retry the flip back until it succeeds or an operator intervenes, with bounded back-off (chosen), versus
  deciding the probation again after a restart (contradicts PDK-058: a decided probation is never decided anew),
  versus no retry (status quo).
- **Way back for the operator:** allow a downgrade to the slot's previous version after a failed rollback (rejected:
  the downgrade uses the same install-and-flip that just failed, so it cannot succeed where the retry cannot, and it
  weakens the release binding that protects against a rollback to a vulnerable release), versus the retry itself plus
  a documented manual flip on the device, plus visibility in the portal (chosen).

## Decision
1. **Outcome.** `update-result.json` gains the outcome `rollback_failed` (constants in
   `agent/internal/supervisor` and `agent/internal/update`). It means: the release failed its probation, the flip back
   to the previous slot failed, and the device keeps running the release until the rollback succeeds. The agent turns
   it into `agent.update_failed` with `outcome: rollback_failed`; `protocol.EventTypes` and `device.yaml` are
   unchanged.
2. **Audit.** New code `device.agent_rollback_failed` in the closed registry, emitted for `agent.update_failed` whose
   `outcome` is `rollback_failed`; every other `agent.update_failed` keeps `device.agent_update_failed`. The portal
   localizes it via `audit.device.agent_rollback_failed`. The description of `device.agent_update_failed` names the
   exception.
3. **Rollout counting.** `agent_update_report.outcome` gains `rollback_failed`. Every failure count of a rollout
   (`paddock_agent_rollout_stats`, `paddock_agent_rollout_evaluation_stats`, `paddock_agent_current_release_stats`)
   counts `rollback_failed` like `rolled_back`, as distinct devices, so a device that later reports `rolled_back`
   for the same version counts once. The release detail's `failed` count includes it.
4. **Supervisor: pending rollback.** When the immediate attempts of `flipBack` fail, the supervisor restarts the agent
   from `current` (the new release keeps running; contract 8), records `rollback_failed` in the probation log with
   `rollback_pending: true`, writes the result, and **keeps the log**. From then on it retries one flip per retry slot
   on its tick; the wait between attempts starts at the tick (10 s) and doubles up to 5 minutes; every failed attempt
   is logged at error level with the attempt count, the active slot, the target slot and the error. When a flip
   succeeds, the supervisor restarts the previous agent, makes the flip durable as for any flip back (PDK-045), and
   concludes the probation with `rolled_back` and a new `at`. This is the one case in which a probation ends in two
   results, each for its own decision: `rollback_failed` at the end of the probation, `rolled_back` when the rollback
   is made. A `rolled_back` written before the agent delivered `rollback_failed` replaces it; the device then reports
   `rolled_back` only, which is the true end state.
5. **Supervisor: restart.** A probation log with `rollback_pending: true` and `current` on the new slot writes its
   recorded result again unchanged (idempotent, PDK-058) and resumes the retries; with `current` on the previous slot
   (an operator flipped by hand, or the rename landed before a crash) it resumes as a rollback whose flip waits to be
   confirmed durable and then concludes `rolled_back`. A log with a recorded `rolled_back` whose `current` is on the
   new slot (the flip back was lost with the power) resumes as a pending rollback as well instead of writing
   `rolled_back` again; if its first retry fails, the outcome is replaced by `rollback_failed`.
6. **Blocking.** While a rollback is pending, update requests are ignored, as during a probation.
7. **No downgrade through the update channel.** `downgrade_refused` stays as decided in plan M4b.1 decision 11.
   The way back is: the retry (an operator fixes the cause on the device, for example a read-only or full
   `/opt/paddock/agent`, a stray `.current.tmp` directory), or a manual flip of `current` to the previous slot, which
   the next retry recognises; both are documented in `docs/operations/agent-releases.md`.
8. **Visibility.** The attention list gets the kind `agent_rollback_pending`: a device with a `rollback_failed` report
   for a version, without a `rolled_back` report for the same version, whose `device_status.agent_version` still is
   that version; detail is the version.

## Consequences
+ The audit trail names what happened; auditors can list devices that ran a release which failed its probation and
  see when each left it. + Contract 4 holds again: a failed rollback is retried until it succeeds. + Operators see
  the devices on the attention page and in the release's failure count; the device keeps working meanwhile.
− A forward-only migration (CHECK constraint, three count functions, the attention view). − The supervisor grows
  (555 non-empty, non-comment lines of 600, plan M2b decision 15); the pending-rollback state adds one more field to
  `probation.json`. − Older servers record the new outcome under `device.agent_update_failed`.
Follow-ups: PDK-043 (implementation), a stub for the attention kind if the implementer splits it off, and the
unreadable-log recovery of PDK-062, which resumes a pending rollback as defined in rule 5 (plan M2b, amendment
2026-10-12).

## Amendment 2026-10-18 (M8f, PDK-300) — the result precedes the restart
A durable flip back wrote `update-result.json` only after the previous agent had been restarted. An agent that
checked in before the result existed received the release offer again (the server offers the current release to every
older agent at every check-in), staged it, and the supervisor — with no probation and no pending rollback — installed
and rolled it back a second time (lab, 2026-10-17, two `rolled_back` events 64 s apart under disk pressure). Rule 4 is
completed: the supervisor concludes the probation (log, result, removal of the request) **before** it restarts the
previous agent, on the immediate rollback and on a rollback made by a retry alike; the restarted agent then reads the
result at its first check-in and never stages the version it was rolled back from. Nothing changes for the pending
rollback (the new agent keeps running) or the not-yet-durable flip (the request stays until the result is written).

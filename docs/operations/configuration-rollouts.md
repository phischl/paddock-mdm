# Configuration rollouts

A configuration change normally reaches every device at its next check-in. With staged rollouts switched on, a change
to the device configuration (managed files, managed units, package holds, update settings) reaches a small share of
the devices first, wave by wave, and stops by itself when too many devices fail. This guide describes the settings,
one change from start to finish, the counts, the actions, the revert and the urgent opt-out. The decisions are in
[ADR 0033](../adr/0033-staged-configuration-rollout.md); the agent releases have their own rollout
([agent releases](agent-releases.md)).

Staged rollouts are **off by default**. While they are off, every change is immediate, as before.

## 1. What is staged and what never is

Staged (the *rollout-able sections*): managed files, managed units, package holds and the update settings
(`settings.updates`). A change that touches none of them is never staged, whatever the setting says.

**Never staged**, always immediate for every device:

- permission profiles and profile assignments,
- user locks and login suspension,
- revocation (lock and destroy),
- device groups, the login settings, the privacy settings, the operator roots of the managed files and the watched
  units,
- agent and supervisor releases (own rollout, [agent releases](agent-releases.md)) and the dead man's switch.

A sudo removal, a user lock or a revocation therefore never waits for a wave. Where a change set mixes sections, only
its changes to the four rollout-able sections are staged; everything else in it reaches every device at once.

## 2. Settings

*Settings → Rollouts* in the portal (`/settings/rollout`), or `GET /api/v1/settings/rollout` and `PUT
/api/v1/settings/rollout`. Organization administrators change them, operators and auditors read them. A change is the
audit event `settings.rollout_changed` and does not touch a rollout that is already running: it keeps the values it
started with.

| Setting | Field | Default | Rule |
| --- | --- | --- | --- |
| Roll configuration changes out in waves | `enabled` | off | |
| Waves | `waves` | `1, 10, 50, 100` | 1 to 10 strictly increasing percentages between 1 and 100, ending with 100 |
| Minimum duration of a wave | `min_wave_minutes` | 60 | at least 15 (1 on a development stack) |
| Failure rate that stops a rollout | `failure_threshold_percent` | 2 | 0 to 100 |
| Minimum number of failed devices | `failure_threshold_min` | 3 | at least 0 |
| Canary group | `canary_device_group_id` | none | a device group of the organization; its devices always receive a change first |

A rollout halts when the failed devices reach the larger of `failure_threshold_min` and `failure_threshold_percent`
of the devices in the waves reached so far, rounded up, and at least one device failed. An invalid value is 400
`invalid_request`; an unknown canary group, or one of another organization, is 404 `not_found`. Deleting the canary
group clears the setting; while a rollout is open the group cannot be renamed or deleted (section 6).

## 3. One staged change, end to end

The example changes one managed file for the whole organization. The same steps apply to a unit, a package hold or the
update settings.

**1. Switch staged rollouts on, once.** *Settings → Rollouts*: tick *Roll configuration changes out in waves*, optionally
pick a canary group (for example the IT team's own laptops), save.

```sh
curl -sS -X PUT $PADDOCK_URL/api/v1/settings/rollout \
  -H "Authorization: Bearer $PADDOCK_TOKEN" -H 'X-Paddock-CSRF: 1' -H 'Content-Type: application/json' \
  -d '{"enabled":true,"waves":[1,10,50,100],"min_wave_minutes":60,
       "failure_threshold_percent":2,"failure_threshold_min":3,"canary_device_group_id":null}'
```

(A token needs the role `org_admin` for this call. Mutating requests carry `X-Paddock-CSRF: 1`, see
[API tokens](api-tokens.md).)

**2. Make the change.** In the portal edit the managed file (*Managed files*), or apply a document:

```sh
paddockctl apply -f paddock.yml --dry-run     # review the plan
paddockctl apply -f paddock.yml               # prints: Applied change set <id>, then: Rollout: staged (rollout <id>)
```

The change is written to the configuration at once: the portal, `paddockctl get config` and the API show the new
state. What differs is what the devices receive. The audit event of the change (`config.applied` for an apply,
`managed_file.updated` for the portal form) carries `rollout: staged`, `rollout_id` and `change_set_id`. *Change sets*
shows the change set with the chip *Staged* and a link to its rollout.

**3. Watch the first wave.** *Configuration rollouts* lists the rollouts with their status, wave and counts. The
rollout's page shows:

- the wave strip (every wave with its percent, the current wave highlighted, the canary group named),
- the stop rule and the counts (section 4),
- the planned changes of the change set,
- the devices: whether each is in the wave, its newest bundle (and whether that bundle carries the change), its newest
  report and the staged resources that failed.

```sh
curl -sS -H "Authorization: Bearer $PADDOCK_TOKEN" "$PADDOCK_URL/api/v1/config-rollouts?status=running"
curl -sS -H "Authorization: Bearer $PADDOCK_TOKEN" $PADDOCK_URL/api/v1/config-rollouts/<id>
curl -sS -H "Authorization: Bearer $PADDOCK_TOKEN" "$PADDOCK_URL/api/v1/config-rollouts/<id>/devices?in_wave=true&report_outcome=rejected"
```

On a device, *Apply status* shows each resource and the *Bundle history* names the rollout that rendered a version.

**4. Let it run, or act.** The worker checks every rollout every 60 seconds (section 5). Without failures the rollout
advances after each wave's minimum duration and completes after the last wave; with failures it halts. You can
advance, halt, resume or complete it yourself (section 5), or revert the change set (section 7).

```sh
curl -sS -X POST $PADDOCK_URL/api/v1/config-rollouts/<id>/halt \
  -H "Authorization: Bearer $PADDOCK_TOKEN" -H 'X-Paddock-CSRF: 1' -H 'Content-Type: application/json' \
  -d '{"reason":"Unit fails on the 2024 laptops"}'
```

### What a device receives

Each rollout draws its own buckets: a device's bucket is FNV-1a (32 bit) of `<device id>:<rollout id>` modulo 100. A
wave of `p` percent contains every device whose bucket is below `p`, plus every member of the canary group from the
first wave on. Devices differ from rollout to rollout, and from agent rollouts. With few devices a wave can be empty
or hold more or fewer devices than its percent; the canary group is the deterministic first wave.

- A device **in the wave** receives the bundle with the new configuration; that bundle is tagged with the rollout.
- A device **outside the wave** keeps the previous state of the staged items: the compiler renders it with their
  before-state. Changes to anything else, made while the rollout runs, reach it at once.
- A device the change does not concern (for example a file of another device group) gets no new bundle. It counts as
  pending and never as failed.
- A device in report-only mode ([enroll-existing](enroll-existing.md)) is never in a wave; it plans the previous state
  and is never counted.
- A halted rollout keeps the wave it reached: devices inside keep the new state, devices outside the old one.
- After the rollout completes, every device receives the change at its next check-in.

## 4. The counts

The rollout's page, `GET /api/v1/config-rollouts` and `GET /api/v1/config-rollouts/{id}` show the same counts the
worker decides on:

| Count | Meaning |
| --- | --- |
| `eligible` | active, enforced devices inside the wave the rollout reached (every such device once it completed) |
| `failed` | devices whose **newest** report on a bundle of the rollout is a rejection (`device.bundle_rejected`), or an apply with a failed staged resource, received since the rollout started or was last resumed |
| `applied` | devices whose newest report on a bundle of the rollout applied every staged resource (enforced apply) |
| `pending` | every other eligible device: no bundle of the rollout, no report yet, or a report that no longer counts |

Rules that are easy to miss:

- **Devices that never report never count.** A laptop that is closed or offline is `pending`, neither failed nor
  applied; a silent device does not stop a rollout. The rollout advances on time whether or not the devices of the
  wave have reported. Use *Configuration status* and the attention list for silent devices.
- **The server's receive time counts**, not the device's clock: a device clock that runs behind cannot date a failure
  before the start of the rollout.
- **Only staged resources count.** A failure of another resource of the same bundle does not count against the rollout;
  the staged resource IDs are `file:<path>`, `unit:<name>` and `updates` (package holds and update settings).
- **Plan errors never count.** A report-only device reports plan errors as failed resources (section 6 of
  [enroll-existing](enroll-existing.md)); they are never a failed apply, and a report-only device is not in a wave.
- An agent update that fails does not count against a configuration rollout, and the reverse (section 9).

## 5. Halt, resume, advance, complete

Actions: organization administrators and operators; auditors only read. Each is confirmed in the portal and recorded
as one audit event. The settings page is not consulted, so every action works after rollouts were switched off.

| Action | API | Effect | Refused (409 `invalid_state`) |
| --- | --- | --- | --- |
| Halt | `POST /api/v1/config-rollouts/{id}/halt` with `{"reason": "…"}` (2 to 500 characters) | running becomes halted; devices keep the state of the wave reached; the rollout stays open | rollout not running |
| Resume | `POST /api/v1/config-rollouts/{id}/resume` | halted becomes running in the same wave; failures reported before now no longer count and the wave's observation period starts again | rollout not halted |
| Advance wave | `POST /api/v1/config-rollouts/{id}/advance` | the next wave starts now, without waiting for the observation period | halted, or already in the last wave |
| Complete | `POST /api/v1/config-rollouts/{id}/complete` | every device receives the change at its next check-in; the rollout ends | already completed or reverted |

Automatic behaviour of the worker (every 60 seconds, for running rollouts only):

1. **Halt** (`config_rollout.halted`, actor *system*) when the failed devices reach the threshold of section 2. The
   audit event carries `reason` (`<n> failed devices reached the threshold of <m>`), `wave`, `eligible`, `failed` and
   `threshold`.
2. **Advance** (`config_rollout.advanced`, `manual: false`) when the current wave is older than `min_wave_minutes`
   and a next wave exists.
3. **Complete** (`config_rollout.completed`, `manual: false`) when the last wave is older than `min_wave_minutes`.

A halted rollout is not evaluated: it waits for you. After resolving the cause, resume it, complete it (the change
then reaches everyone) or revert its change set. There is no automatic resume and no automatic revert.

## 6. While a rollout is open

At most one rollout per organization is open (running or halted). While it is open, writes are checked against it
inside the audited action:

| Write | Result |
| --- | --- |
| touches an item the rollout stages (same section and key) | 409 `rollout_conflict`, urgent or not |
| not urgent, touches another item of a section the rollout stages (package holds and update settings are one section) | 409 `rollout_running` |
| only other sections | immediate, for every device; no new rollout |
| urgent, touches no staged item | urgent, for every device |
| renames or deletes a device group that scopes a staged item or is the canary group | 409 `rollout_conflict` |

A change set that is refused is refused whole, never split. Complete the rollout, or revert its change set, then
repeat the change. These rules apply even after staged rollouts were switched off while the rollout was open.
`paddockctl apply` meets them like the portal ([paddockctl](paddockctl.md)).

## 7. Revert a change set

*Change sets* → *Revert*, or `POST /api/v1/change-sets/{id}/revert`: the inverse of a change set is applied as a new
change set that references the original (`reverts_change_set_id`; the original shows `reverted_by`). An item the change
set created is deleted, an item it updated or deleted is restored from its before-state; items created since are kept.

1. Dry run: `POST …/revert?dry_run=true` returns the inverse plan and its `plan_sha256`; nothing is applied or audited.
2. Apply: `POST …/revert?expected_plan=<plan_sha256>`; a different plan is 412 `plan_changed`. The portal does both steps
   in its confirmation dialog.

The revert is audited as `config.reverted`. Every rule of the per-resource endpoints applies unchanged (roles,
step-up for the sections that need one). A revert that is itself a staged change set follows section 6; with
rollouts on, it can be staged or urgent.

- **Reverting the change set of the open rollout** is immediate: the devices outside the wave already run the previous
  state, so the rollout ends with status `reverted` (`ended_reason` names the revert) and the audit event carries
  `rollout_id` and `rollout_status: reverted`.
- 409 `invalid_state`: the change set was reverted already, or it has no before-state (recorded before before-states
  existed, or purged after 90 days; an open rollout's before-state is kept until it ends).
- 409 `in_use`: the revert of the open rollout's change set would delete a device group that the change set created and
  that has members since. The rollout stays open; move the members to other groups, or complete the rollout.
- Before-states hold full managed file contents and are removed after 90 days
  ([retention](../compliance/retention.md)).

## 8. The urgent opt-out

A change that must not wait for the waves can opt out of staging. It is **portal only**:

- With staged rollouts on, every form that writes a rollout-able section (managed file, managed unit, package hold,
  update settings), its delete confirmation and the revert dialog offer *Apply immediately to every device (urgent)*
  with a required *Reason for the urgent change* (2 to 500 characters).
- The server asks for a fresh step-up (within the last 5 minutes); the portal runs it and repeats the change.
- The change then reaches every device at once. Its change set shows the chip *Urgent* with the reason.
- **Audit trail:** the audit event of the change carries `rollout: urgent` and `urgent_reason`, next to
  `change_set_id`. An urgent change that overlaps an item of the open rollout is refused (section 6).
- Refused: `urgent` without a reason (400 `invalid_request`), `urgent` while staged rollouts are off (400
  `invalid_request`, *rollouts are disabled for this organization*), and any request without a step-up (403
  `step_up_required`).

`paddockctl apply` has no `--urgent` or `--reason`: an API token never satisfies a step-up, so a command line and an
assistant session (MCP) cannot opt out. A pipeline that must not wait applies the change in the portal.

## 9. Interaction with agent releases and report-only devices

Configuration rollouts and [agent rollouts](agent-releases.md) are independent. Their buckets differ, both can run at
the same time, and a device's failed agent update never counts toward a configuration rollout and the other way
round. Reasons to wait with a configuration change until an agent rollout ends are yours; Paddock does not couple them.

Devices in report-only mode never receive a staged change and never count; enable enforcement for them first
([enroll-existing](enroll-existing.md)). An enforced device that was adopted takes part like any other.

## 10. Audit codes

All codes are in the closed registry ([audit codes](../compliance/audit-codes.md)); the portal shows them as
`audit.<code>`.

| Code | When | Actor | Parameters |
| --- | --- | --- | --- |
| `settings.rollout_changed` | the settings changed | administrator | `enabled`, `waves`, `min_wave_minutes`, `failure_threshold_percent`, `failure_threshold_min`, `canary_device_group_id` |
| `config.applied` | a declarative apply; staged or urgent changes carry the rollout parameters | administrator or token | `change_set_id`, `created`, `updated`, `deleted`, `sections`, `rollout`, `rollout_id`, `urgent_reason` |
| `managed_file.*`, `managed_unit.*`, `package_hold.*`, `settings.updates_changed` | a portal write of a rollout-able section | administrator | the usual parameters plus `change_set_id`, `rollout`, `rollout_id`, `urgent_reason` |
| `config.reverted` | a revert | administrator | `change_set_id`, `reverts_change_set_id`, `plan_sha256`, `created`, `updated`, `deleted`, `sections`, `rollout`, `rollout_id`, `rollout_status`, `urgent_reason` |
| `config_rollout.advanced` | next wave started | system or administrator | `rollout_id`, `change_set_id`, `wave`, `percent`, `manual` |
| `config_rollout.halted` | halted by the worker or an administrator | system or administrator | `rollout_id`, `change_set_id`, `reason`, `wave`, `eligible`, `failed`, `threshold` |
| `config_rollout.resumed` | resumed | administrator | `rollout_id`, `change_set_id`, `wave` |
| `config_rollout.completed` | completed by the worker or an administrator | system or administrator | `rollout_id`, `change_set_id`, `wave`, `manual` |

Every attempt, also a refused one, records exactly one event with outcome success, failure or denied. The start of a
rollout is carried by the event of the change that started it. `config_rollout.halted` is a preset event of the
[notification rules](notifications.md), so a halt is forwarded like the other security events; the worker exports the
gauge `paddock_config_rollouts{status}` (rollouts by status, never labelled with an organization).

## 11. Troubleshooting

| Symptom | Cause and remedy |
| --- | --- |
| 409 `rollout_conflict` or `rollout_running` on a change | A rollout is open. Open *Configuration rollouts*, complete it or revert its change set (section 6). |
| A rollout halted | Read *Halt reason* and the devices list (`report_outcome` *Rejected*, failed resources). Fix the cause, resume, or revert the change set. |
| A rollout does not move on | It is halted, or the wave's minimum duration has not passed. *Advance wave* skips the wait. |
| Counts stay at `pending` | The devices are offline, do not carry the change (not concerned), or are report-only. Section 4. |
| 409 `invalid_state` on an action | The rollout is not in the status the action needs (section 5). |
| 409 `in_use` on a revert | Section 7. |
| 403 `step_up_required` with `urgent` | Only the portal can opt out; section 8. |
| 400 `invalid_request`, *rollouts are disabled* | Switch staged rollouts on, or make the change without `urgent`. |

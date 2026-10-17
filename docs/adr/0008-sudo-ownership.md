# 0008 — sudo ownership and device-scoped profiles (A13)
Status: Proposed

## Context
A13: exactly one system determines effective sudo rights; every right appears in the portal's effective profile;
behavior defined for users in a sudo-granting group without a Paddock profile. Open point in the concept:
per-device or device-group overrides — decided by the product owner: device-group scope.

## Options
- **Paddock owns sudo; login component grants none; sudo-granting local groups reconciled.** + One source; full
  derivation in the portal. − Agent must actively police `sudo`/`admin`/`wheel` membership.
- **Himmelblau group mapping to local `sudo` group.** + No sudoers generation. − Two systems, no restricted profiles, no derivation.
- **Both, merged.** − Violates "exactly one system".

## Decision
Paddock is the only owner. Himmelblau/SSSD are configured without sudo mapping. Members of `sudo`, `admin`, `wheel`
are exactly `{paddock-admin}`; other members are removed and reported. Per-user files
`/etc/sudoers.d/paddock-u-<sha256(username)[0:16]>`, validated with `visudo -c`, atomic rename, rollback.
`profile_assignment.device_group_id` (nullable) limits an assignment to devices of a group; the effective profile
is computed per (user, device) with the concept's merge rules.

## Consequences
+ The portal can always show the complete derivation.
− Users who added themselves to `sudo` lose that membership at the next apply (documented, visible as finding).

## Amendment 2026-10-17 (M8x, lab finding L15) — never remove the last administrator
The first apply on an adopted laptop of an organization without a domain removed the only local administrator from
`sudo`: no managed local administrator existed (it needs the login resource, which needs a domain) and no break-glass
account was configured, so the device was left without any administrator. The rule "members of `sudo`, `admin`,
`wheel` are exactly the break-glass accounts" is narrowed: the agent removes foreign members of a privileged group
**only while at least one break-glass account (the managed local administrator included) is a member of that
group**. A group without one keeps every member; each kept member is reported once as
`device.tamper_sudo_group_member` with `removed=false` and `reason=last_admin`, so the administrator sees it and
adds a break-glass account or lets the local administrator be created. Report-only adoption (ADR 0033, M11) runs
before this rule for adopted devices; the rule applies to every enforced apply (fail safe, design contract 8).

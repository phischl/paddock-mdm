# 0057 — Inventory hosts bound to their device
Status: Accepted (2026-11-17, main, `decisions-alpha11.md` §159, with the conditions in plan
`docs/plans/M5a-inventory-and-vulnerabilities.md`, "Amendment 2026-11-17 e (architect, PDK-1123)", H13 and H14)

## Context

- Paddock stores, per device, the inventory, vulnerability findings, hardware facts and policy results that Fleet
  holds for the device's host (plan M5a decisions 6 to 8, ADR 0056). The policy results feed tamper reports
  (`device.tamper_agent_not_running`, `device.tamper_agent_binary_changed`).
- The worker maps a Fleet host to a device by the hardware UUID that the host reports (`paddock_inventory_devices`,
  migration 00024).
- **The inventory host identity is not yet bound to the device.** Paddock cannot tell which of several hosts that
  report one hardware UUID belongs to the device, nor whether the host it stores was enrolled again.
- Fleet free has no per-device or per-organization enrollment credential for Linux:
  - teams and team enroll secrets need Fleet Premium (`server/service/teams.go`: `NewTeam` and
    `ModifyTeamEnrollSecrets` return `ErrMissingLicense`);
  - one-time enroll secrets exist only for Apple and Windows MDM (`mdm.apple_one_time_enroll_secrets`,
    `mdm.windows_one_time_enroll_secrets`);
  - TPM-backed host identity certificates are licensed under the Fleet EE license (orbit flag
    `--fleet-managed-host-identity-certificate`).
  ADR 0009 rules out Fleet Premium features.
- What fleetd offers in the free edition (Fleet `fleet-v4.94.1` sources):
  - orbit's `--host-identifier` / `ORBIT_HOST_IDENTIFIER` takes `uuid` (default) or `instance`. With `instance`, orbit
    and osquery enroll under osquery's per-installation `instance_id` (`orbit/cmd/orbit/orbit.go`). Fleet recommends it
    for cloned virtual machines.
  - Fleet's server option `osquery.host_identifier` (`provided`, `instance`, `uuid`, `hostname`) chooses the
    identifier of an osquery enrollment (`getHostIdentifier`, `server/service/osquery.go`). orbit's own enrollment
    always uses the identifier orbit sends (`EnrollOrbit`, `server/service/orbit.go`).
  - orbit keeps a device token in `/opt/orbit/identifier`. It generates the token (a random UUID), registers it for
    its own host over the orbit API (`POST /api/fleet/orbit/device_token`, authenticated by orbit's node key), and
    rotates it hourly. It does so whether or not Fleet Desktop is enabled (`orbit.go`: "Always keep the device
    identifier … up to date"). Fleet answers `GET /api/latest/fleet/device/{token}` with that host for one hour
    after the token was registered (`AuthenticateDevice`, `deviceAuthTokenTTL = time.Hour`).
- The device API is signed per request with the device key (ADR 0004). An additive request field is
  compatible in both directions: the gateway ignores unknown fields (`decodeJSON` uses `json.Unmarshal`), and agents of
  earlier releases leave the field out (ADR 0047).

## Options

### A. How a device names its inventory host

1. **The agent reports orbit's device token over the signed device API; the worker resolves it through Fleet's
   device endpoint to the host ID and binds the device to that host (chosen).**
   - Pro: Fleet itself attests the host, through a token that only the host's own orbit can register. Free edition.
     No new dependency. The token is short-lived.
   - Con: an additive device-API field, an agent release, and a worker call to Fleet per new binding. The token is
     a short-lived credential for Fleet's device endpoints, and it passes through RabbitMQ and Postgres until the
     worker resolves it.
2. **The agent reports orbit's node key, or osquery's instance ID; the worker looks it up with
   `GET /api/latest/fleet/hosts/identifier/{identifier}`.**
   - Con: that lookup also matches the hostname, the hardware UUID and the serial number
     (`HostByIdentifier`: `WHERE ? IN (h.hostname, h.osquery_host_id, h.node_key, h.uuid, h.hardware_serial)`). It
     does not prove that the reporter has the host's key. orbit's node key is not a lookup key at all.
3. **The agent reports the Fleet host ID it reads itself.**
   - Con: nothing on the device names the host ID, and an unverified ID proves nothing.

### B. How Fleet identifies hosts

1. **fleetd enrolls under osquery's instance ID (`ORBIT_HOST_IDENTIFIER=instance`); Fleet uses the identifier the host
   provides (`FLEET_OSQUERY_HOST_IDENTIFIER=provided`) (chosen).**
   - Pro: a host's identity in Fleet is specific to the fleetd installation, not derived from hardware. `provided`
     keeps orbit's and osquery's enrollments of one host on one record for both settings of the device side, during
     the agent rollout too.
   - Con: every host enrolls once more (a new Fleet host per device), and the old host stays in Fleet until it is
     removed. A lost osquery database creates a new host, which the device's next token binds.
2. **`FLEET_OSQUERY_HOST_IDENTIFIER=instance` on the server.**
   - Con: orbit of a device not yet switched enrolls under the hardware UUID while its osquery enrolls under the
     instance ID, so the device gets two hosts.
3. **Keep `uuid`.**
   - Con: the identity stays derived from hardware.

### C. Per-organization enroll secrets (Fleet teams), with a team-to-organization mismatch check

- Con: needs Fleet Premium (ADR 0009). A team does not change how Fleet identifies a host, so a team check would
  add a second signal without binding a host to its device; option A already ignores hosts that are not bound.
- **Not chosen,** neither instead of A nor in addition to it.

### D. Devices whose agent does not report a token yet

1. **The host Fleet enrolled first for the hardware UUID speaks for the device until the device is bound
   (chosen).**
   - Pro: inventory keeps working during the agent rollout and for devices without a token.
   - Con: until a device is bound, its host is checked through the claim report (E) and the hold (F) only.
2. **Store nothing for an unbound device.**
   - Con: inventory and tamper reports stop for every device until its agent is updated, which can take the whole
     rollout or longer under the manual update policy.

## Decision

A1, B1, D1, plus:

- **E. Claim report.** A host other than the device's bound host that reports the device's hardware UUID and keeps
  talking to Fleet for 15 minutes, and every re-enrollment of the bound host, are reported once per episode as the
  new audit code `device.tamper_fleet_host_claimed`, with a tamper finding.
- **F. Hold.** After a re-enrollment of the bound host, agent reports derived from Fleet (`device.tamper_agent_not_running`,
  `device.tamper_agent_binary_changed`) wait 60 minutes.
- **G. Wave guard.** Claim reports are held while at least 3 watched devices and more than half of them have an
  open claim episode, for example after a Fleet database restore. A gauge and a critical alert show the hold.
- Rule: **only the bound host's data is stored for a device.** A host bound to exactly one device maps to it. A host
  that no device is bound to maps through the hardware UUID only to an unbound device, and only if it is that
  device's first-enrolled host. Every other host is stored for no device.

## Consequences

**Positive.**
- A bound device's inventory, findings, hardware facts and policy results come only from the host that its own orbit
  registered.
- A second device with the same hardware UUID no longer stops a bound device's inventory, because the binding, not
  the UUID, maps the host.

**Negative.**
- Device API: one optional request field (`fleet_device_token`).
- Fleet configuration: `FLEET_OSQUERY_HOST_IDENTIFIER=provided`; `ORBIT_HOST_IDENTIFIER=instance` in `orbit.env`.
- Every host enrolls once more after its agent update, and its previous host stays in Fleet.
- One more audit code; a 60-minute hold of Fleet-derived agent reports after each re-enrollment and after a Fleet
  restore.
- A lost osquery database is reported once as a claim (`reenrolled`) when Fleet re-uses the record, and otherwise
  rebinds silently.
- ADR 0041's context statement "fleetd runs osquery with `--host_identifier=uuid`" no longer holds. Its conclusion
  still holds: a rename neither duplicates nor unmaps a host, because the instance ID does not depend on the hostname.

**Residual (RR-22).** Devices whose agent predates the binding are covered by E and F until they update.
Upgrade the server first, then the agents through a staged rollout.

**Announced reset (acceptance condition).** The agent announces its one-time enrollment reset over the signed check-in
before it resets. Until the device is bound again, at most 60 minutes, the new host it creates does not count as
another claimant. A re-enrollment of the device's host is reported regardless (plan amendment e, H14).

**Follow-ups.**
- Removal of the previous Fleet hosts that no device is bound to.
- A report when two devices claim one hardware UUID and neither is bound.

## Amendment 2026-11-17, review round 1

Status: Accepted (main, `decisions-alpha11.md` §163). Details: plan M5a, "Amendment 2026-11-17 e — review round 1".

**Context.** The review of the first implementation refined the decision rules:
- a bound host is checked against the device's hardware UUID, because Fleet can give a host ID to another machine
  after a rebuild or restore;
- the host that speaks for an unbound device stays the one already stored for it, and a change is reported;
- bound devices keep counting in the hardware-UUID ambiguity check;
- a host already in use by one device is not bound to another;
- the wave guard counts re-enrollments per binding mode.

**Decision.**
1. A bound host counts only while Fleet lists it with the device's hardware UUID. Otherwise the binding is
   **suspended**: kept, nothing stored, the device's next token resolved, and no `second_host` counted for at most 60
   minutes.
2. For a device that is not bound, the host already stored for it keeps speaking while it is listed with the device's
   UUID. Otherwise the listed host with the lowest ID that no other device uses speaks. A change of the speaking host
   is reported as `reenrolled` and holds agent reports.
3. Bound devices keep counting in the hardware-UUID ambiguity check.
4. A host that is bound to, or stored for, another active or quarantined device is never bound (`host_in_use`).
   A bound host that Fleet lists with another hardware UUID is not in use by its device. A retired device keeps
   counting as a holder of its hardware UUID until retention has purged its inventory or it was retired as
   uninstalled.
5. The wave guard counts only episodes with a re-enrollment, separately for bound and unbound devices, and never
   suppresses `second_host`. For a device in binding mode `first`, another host that appears while its open episode
   also saw a re-enrollment is reported as `reenrolled`, so the guard can hold it (RR-22).
6. The worker accepts unknown heartbeat fields.

**Consequences.**
- Positive:
  - data of one machine is never stored for a device whose hardware UUID differs;
  - an unbound device's speaker changes only with a report;
  - claims of another host are always reported (for binding mode `first`, see decision 5).
- Negative:
  - a suspended binding pauses a device's inventory until its fleetd names a new host;
  - a machine enrolled again in Paddock is refused its host until its previous device record is retired;
  - more than about 1,500 agent updates per hour can cause one false `second_host` per device left unresolved.
- Residual unchanged: devices whose agent is not updated are covered by the claim report and the hold until their agent
  updates.

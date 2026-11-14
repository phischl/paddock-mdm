# Implementation plan: M18 — Himmelblau upstream fix for synthetic NSS users, pin bump and the end of the NSS hold

Status: accepted (architect arch-a11, 2026-11-14), release 0.1.0-alpha.11 **or later**: the Paddock part (PDK-1029,
PDK-1030) lands only after Himmelblau has released the fix. Binding language: **MUST** / **MUST NOT** / **SHOULD** /
**MAY**. Tickets: PDK-1028 (upstream), PDK-1029, PDK-1030.

## 1. Goal

On an enrolled device, packages that create a system account install while `himmelblaud` runs, so the agent no
longer has to stop the daemon around its own package transactions and directory logins no longer pause during
installations; a local administrator's own `apt` runs work as well.

## 2. Context

- **The defect (PDK-983, plan M5a amendment 2026-11-10 "Why").** Himmelblau 4.0.8 with the generic OIDC provider
  answers `getpwnam()` for any unknown name with a synthetic `LookupOnly` user while online: a bare name is mapped to
  `<name>@<domain>` (`cn_name_mapping`, default true) and `OidcApplication::unix_user_get` returns a fake object ID and
  an idmap UID without an existence check; names in foreign domains are synthesized too. `adduser --system` (exit 13)
  and `useradd` (exit 9) refuse because the name "exists". Groups are not synthesized.
- **The interim mitigation (alpha.10).** The NSS hold: `agent/internal/reconcile/shield.go`, `shield_lock.go`;
  callers `agent/internal/agent/agent.go` (`reconcile.Shielded`), `agent/internal/agent/osupdates.go`,
  `agent/internal/osupdates/osupdates.go` (`Hold`), `agent/internal/encrypt/prepare.go`, `agent/cmd/paddockd/main.go`;
  event `login.nss_shield` / audit `device.login_nss_shield`; plan M5a N1–N9 and amendment 2026-11-11 b (P1–P3);
  RR-133, RR-07; `docs/operations/device-login.md` "Package installations pause directory logins".
- **The pin.** `PADDOCK_HIMMELBLAU_VERSION` default `4.0.8` in `server/cmd/paddock-server/compiler.go`; the login
  reconciler installs exactly that version and renders `/etc/himmelblau/himmelblau.conf`
  (`agent/internal/reconcile/login.go::renderHimmelblauConf`, protected area 4). ADR 0019 (Accepted) owns the pin.
- **User decision (`decisions-alpha10.md` §45):** develop and test the fix in
  Himmelblau's repository; submit issue and fix together after reading Himmelblau's CONTRIBUTING and AI policy, and
  only with the maintainer's approval of the final text. A draft issue exists from PDK-983.

## 3. Binding decisions

### Requirements

| ID | Requirement | Acceptance (who sees it) |
| --- | --- | --- |
| HB-1 | Himmelblau gains an option under which NSS synthesizes a lookup-only user only for a full UPN in one of the configured domains; bare names and foreign domains return "not found" unless the user is cached. | The Himmelblau maintainers see a PR with tests; the device sees `getent passwd probe` → not found with the option on. |
| HB-2 | Paddock pins the first Himmelblau release with the option and renders it. | The platform administrator sees the new Himmelblau target on the component targets page; devices report it installed. |
| HB-3 | With the option in effect the agent runs package transactions without stopping `himmelblaud`. | The organization administrator sees no `device.login_nss_shield` events for such devices; device users see no login pause during installs. |

### Decisions

1. **Upstream behaviour (PDK-1028).** A configuration option in `himmelblau.conf` `[global]`, proposed name
   `nss_synthesize_upn_only` (boolean, default `false`). When `true`: NSS `getpwnam` for a name that is not in the
   cache resolves to a synthetic `LookupOnly` user **only** when the name contains exactly one `@` and its domain part
   (case-insensitive) equals one of the `domain` values configured; every other uncached name — a bare name, a name
   in a foreign domain, a string of digits — returns not found. Cached and authenticated users keep resolving by
   short name and by UID exactly as today (`cn_name_mapping` unchanged). PAM's name mapping at login is unchanged.
   `getgrnam` is unchanged (groups are not synthesized today).
2. **Upstream process.** The work happens in a fork of Himmelblau's repository outside this repository. Before any
   public post, the implementer reads Himmelblau's CONTRIBUTING and AI policy and records their requirements; the
   final issue text and PR description are written to the maintainers' local upstream notes (outside the repository) and
   submitted **only after the maintainer has approved that text**. No public post, comment or PR is created before that
   approval. Tests required upstream: unit tests of the decision function (bare, foreign domain, configured domain,
   mixed case, digits, cached bare name) and the project's existing test suite green.
3. **Local proof before submission.** The patched build (Debian packages built from the fork for Ubuntu 24.04 and
   26.04) is installed on both test VMs by hand, with the option set, and the probe of §8.3 is run; the results are
   recorded in the PDK-1028 result document. The patched build MUST NOT be shipped by Paddock.
4. **Pin bump (PDK-1029), after the upstream release.** `PADDOCK_HIMMELBLAU_VERSION` default and the ADR 0019 pin
   move to the first released version that contains the option (`HimmelblauNSSUPNOnlyMin` below). The bundle's login
   spec gains the additive field `nss_upn_only bool` (ADR 0013), set by the compiler iff its configured Himmelblau
   version ≥ `HimmelblauNSSUPNOnlyMin`; older agents ignore it.
5. **Rendering.** `renderHimmelblauConf` writes `nss_synthesize_upn_only = true` (or the released option name, see
   stop condition 1) iff `LoginSpec.NSSUPNOnly` is true **and** the installed `himmelblau` package version is ≥
   `HimmelblauNSSUPNOnlyMin` (agent constant in `agent/internal/reconcile/login.go`). The file stays a protected area:
   the existing write, verification and restart paths are used unchanged.
6. **Hold bypass (PDK-1030).** `NSSShield.Run` runs the transaction without a hold and without an event when the
   predicate `NSSUPNOnlyInEffect()` is true: the rendered `himmelblau.conf` on disk contains the option set to `true`
   **and** `himmelblaud` started after that file's last modification (its `ActiveEnterTimestamp` is later than the
   file's mtime) **and** the installed package version is ≥ `HimmelblauNSSUPNOnlyMin`. Otherwise the hold behaves
   exactly as in plan M5a. Reason: a mixed fleet and the window between a bump and the daemon restart must stay
   protected.
7. **Shield code stays** in alpha.11; the code, its event and its tests are removed in the first release after the
   oldest supported agent (ADR 0013 support window) renders the option. That removal is a later ticket.
8. **Documents.** ADR 0019 amendment (pin, option, why); plan M5a amendment "the hold ends where the option is in
   effect"; RR-133 and RR-07 updated (RR-133 closes for devices with the option; it stays for older agents);
   `docs/operations/device-login.md` and `docs/operations/software.md` updated; changelog fragment.

## 4. Non-goals

- No change of `cn_name_mapping`, `local_groups`, `cache_timeout` or any other rendered option.
- No `name_mapping_script`, no nsswitch change, no dpkg hook (options rejected in plan M5a).
- No removal of the shield code (decision 7).
- No Paddock release depends on an unreleased Himmelblau; no patched Himmelblau package in Paddock's repository.
- No change under `agent/internal/revoke/` or `agent/cmd/paddock-revoke/`.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| Himmelblau fork (outside this repository) | new | the fix (PDK-1028) |
| `server/cmd/paddock-server/compiler.go` | change | default version |
| `pkg/bundle` (login spec) | change | `NSSUPNOnly bool \`json:"nss_upn_only,omitempty"\`` |
| `server/internal/compiler/*.go` | change | set the field |
| `agent/internal/reconcile/login.go` | change | constant, rendering |
| `agent/internal/reconcile/shield.go` | change | `NSSUPNOnlyInEffect`, bypass |
| `test/system/selfservice_test.go`, `identity_test.go` | change | SV13 and assertions |
| `docs/adr/0019-login-component-himmelblau.md` | change (amendment) | pin |
| `docs/plans/M5a-inventory-and-vulnerabilities.md` | change (amendment) | hold bypass |
| `docs/compliance/residual-risks.md`, `docs/operations/device-login.md`, `software.md` | change | §3.8 |
| `changelog.d/PDK-1029.changed.md`, `PDK-1030.changed.md` | new | operator-visible |

**MUST NOT be touched:** `agent/internal/reconcile/shield_lock.go` semantics, the safety timer, the
`login.nss_shield` event schema, `/etc/nsswitch.conf` and PAM rendering.

## 6. Interfaces and data model

```ini
# /etc/himmelblau/himmelblau.conf, [global], rendered only under decision 5
nss_synthesize_upn_only = true
```

```go
// pkg/bundle (login spec), additive
NSSUPNOnly bool `json:"nss_upn_only,omitempty"`

// agent/internal/reconcile/login.go
const HimmelblauNSSUPNOnlyMin = "<the released version, set by PDK-1029 from the upstream release>"

// agent/internal/reconcile/shield.go
func (s *NSSShield) NSSUPNOnlyInEffect(ctx context.Context) bool
```

The value of `HimmelblauNSSUPNOnlyMin` is the only value this plan cannot fix in advance; PDK-1029 sets it from the
upstream release and records it in the ADR 0019 amendment.

## 7. Implementation steps

1. **PDK-1028 upstream.** Do: decisions 1–3. Result: tested fork branch, local VM proof, approved texts, then the
   submitted issue and PR. Check: upstream test suite green; probe of §8.3 on both VMs recorded.
2. **Wait** for the Himmelblau release containing the option (or an equivalent upstream option, stop condition 1).
3. **PDK-1029 pin and rendering.** Do: decisions 4, 5 and the ADR 0019 amendment. Check: unit tests; `TestIdentityGates`
   and `TestLocalAdminGates` on both VMs.
4. **PDK-1030 hold bypass.** Do: decision 6, documents of decision 8. Check: unit tests; SV13 and
   `TestSelfServiceGates` on both VMs.

## 8. Tests

1. Upstream unit tests (decision 2).
2. Paddock unit tests: rendering with field true/false and installed version below/at the minimum; the bundle field
   is absent for older compiler configuration; `NSSUPNOnlyInEffect` false when the option is missing, when the daemon
   started before the file changed, when the version is lower; `NSSShield.Run` holds when false and emits no event and
   stops nothing when true.
3. VM probe and gate **SV13** (`TestSelfServiceGates`, both VMs, after PDK-1029 and PDK-1030): with `himmelblaud`
   active and online: `getent passwd sv13-probe` → exit 2; `getent passwd sv13-probe@other.example` → exit 2;
   `getent passwd <tenant user UPN>` → a synthetic entry; `adduser --system --group --no-create-home sv13-probe`
   → exit 0; a required package that creates a system account (the SV10 fixture) installs with no
   `device.login_nss_shield` event; a directory user signs in during that installation (no pause).
4. `TestIdentityGates`, `TestLocalAdminGates`, `TestSelfServiceGates` (SV5, SV6, SV10–SV12) stay green on both VMs;
   SV6 and SV11 run against a device whose bundle has `nss_upn_only` false (the hold path stays proven).

## 9. Acceptance criteria

- HB-1 — Given the patched build with the option on a test VM; when `getent passwd probe` runs; then the implementer
  sees "not found", and a tenant UPN still resolves; the Himmelblau maintainers see the issue and PR only after the
  user approved the text.
- HB-2 — Given the bump; when devices check in; then the platform administrator sees the new Himmelblau target and
  devices report it as installed.
- HB-3 — Given a device with the option in effect; when the agent installs a package that creates a system account;
  then the organization administrator sees the package installed and no `device.login_nss_shield` event, and a
  directory user signs in during the installation.

## 10. Degrees of freedom

- The Rust structure of the upstream patch, within Himmelblau's conventions.
- How `NSSUPNOnlyInEffect` reads the daemon start time (systemd property or `/proc`), within the agent's sandbox.

## 11. Stop conditions

1. Upstream releases the behaviour under another option name or with other semantics: stop; the architect amends
   decisions 1, 5 and 6 to the released form.
2. Upstream rejects the change: stop; the hold stays; the architect re-evaluates (options of plan M5a).
3. The maintainer has not approved the submission text: nothing is posted; PDK-1029/1030 stay blocked.
4. Rendering the option requires a change of PAM or nsswitch.

## 12. Risks and open points

- Timing: the upstream release is outside Paddock's control; alpha.11 MAY ship without PDK-1029/1030. The release
  notes then keep RR-133 unchanged.
- A device whose Himmelblau lags behind the pin keeps the hold (decision 6), which is the safe direction.
- Approval dependency: the maintainer approves the upstream text.

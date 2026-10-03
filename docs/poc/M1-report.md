# M1 PoC report

- **Date:** 2026-10-03/04 (measurements 2026-10-03 20:29 – 22:35 UTC)
- **Paddock commit:** `103d4aa` (PoC scripts on top of plan commit `3bb8195`); scripts in `test/poc/m1/`, reproduction
  guide `test/poc/m1/README.md`, raw evidence in `test/poc/m1/out/<vm>/<criterion>/` (git-ignored, kept on the
  workstation)
- **Authentik:** 2026.8.3 (`deploy/compose/versions.env`), dev stack from `make dev-secrets up dev-seed`
- **Himmelblau:** 4.0.4 on both VMs, official signed package repository
  `https://packages.himmelblau-idm.org/stable/4.0.4/deb/ubuntu{24.04,26.04}/` (the per-release apt repository the
  GitHub release 4.0.4 links to), signing key `himmelblau.asc`, fingerprint
  `E87F D8D4 63A5 E481 4B9C DBA9 0CC0 D400 2C42 5E03` ("Himmelblau Build (2025)"), `InRelease` signature verified.
  Packages: `himmelblau`, `pam-himmelblau`, `nss-himmelblau`, `himmelblau-qr-greeter`, `himmelblau-sshd-config`
  (as the upstream installer selects them for a GDM desktop with sshd), pulled in `himmelblau-apparmor`,
  `krb5-user`, `krb5-config`. No build from source was needed (26.04 is packaged).
- **VMs:** `paddock-u2404` Ubuntu 24.04.5, kernel 7.0.0-38-generic, systemd 255.4-1ubuntu8.17;
  `paddock-u2604` Ubuntu 26.04.1, kernel 7.0.0-38-generic, systemd 259.5-0ubuntu3.4, dracut 110. Secure Boot enabled
  throughout (`mokutil --sb-state` after every TPM boot test).
- **Clock offset (decision 8):** guest − host < 0.5 s including the SSH round trip on both VMs (24.04 timesyncd,
  26.04 chrony, both `NTPSynchronized=yes`; `out/<vm>/clock.txt`). Timings below come from host timestamps unless
  stated otherwise.
- **How the VMs reached Authentik (decision 5):** `/etc/hosts` entry `10.0.2.2 auth.paddock.localhost` plus the Caddy
  root CA in `/usr/local/share/ca-certificates/`. glibc NSS and systemd-resolved honour the hosts entry for
  `*.localhost`, and Himmelblau (reqwest/getaddrinfo) resolved it, so the dev-only `auth.paddock.test` Caddy site was
  **not** needed and no compose/Caddy file was changed. (curl and browsers inside the guest would still map
  `*.localhost` to loopback; no guest browser was involved.)

## Verdict summary

| # | Criterion | 24.04 | 26.04 | Evidence |
| --- | --- | --- | --- | --- |
| C1 | Authentik as OIDC provider incl. MFA | PASS (needs the Authentik-side group claim adaptation, see C1) | PASS (same) | `out/<vm>/C1/`, `out/<vm>/C5b/gdm/` |
| C2 | Lock takes effect via Authentik | PASS (PIN refused 2.0 s after the lock call; PAM failure 69.1 s, device code expiry) | PASS (1.9 s; 68.8 s) | `out/<vm>/C2/` |
| C3 | Device-wide suspension via allow list | PASS (`pam_allow_groups`, daemon restart required) | PASS (same) | `out/<vm>/C3/` |
| C4 | Hello PIN in OIDC mode | PASS (refresh token + `offline_access`; PIN unseal secret TPM-bound, keys in soft HSM) | PASS (same) | `out/<vm>/C4/` |
| C5a | Offline login refused after allow-list removal | PASS | PASS | `out/<vm>/C5a/` |
| C5b | Screen unlock refused | FAIL (pamtester refuses, the real GNOME lock screen unlocks) | FAIL (same) | `out/<vm>/C5b/` |
| C5c | pam_listfile fallback | PARTIAL (offline login refused and fail safe; screen unlock still succeeds with the specified `account` line) | PARTIAL (same) | `out/<vm>/C5c/`, diagnostic `out/<vm>/C5c-diag-auth-phase/` |
| C6 | No sudo granted by the login component | PASS | PASS | `out/<vm>/C6/` |
| C7 | TPM2+PIN boot unlock | PASS (after switching to dracut 060; text prompt, no Plymouth) | PASS (dracut 110 as installed) | `out/<vm>/C7/` |
| C8 | Recovery key | PASS (accepted at the PIN prompt only after the TPM token attempts are used up, 3 entries) | PASS (same, 4 entries) | `out/<vm>/C8/` |
| C9 | Keyslot inventory | PASS (passphrase + tpm2 + recovery; header backup 16 777 216 bytes) | PASS (same) | `out/<vm>/C9/` |

Step 7 (SSSD fallback) was **not** triggered: C1 and C2 pass with Himmelblau's OIDC mode on both VMs.

## Per criterion

### C1 — Authentik as OIDC provider incl. MFA

**Setup.** `authentik-setup.sh setup` (Authentik API only): public OAuth2 client `paddock-device-acme`, grant types
`urn:ietf:params:oauth:grant-type:device_code`, `refresh_token`, `authorization_code`; application with the expression
policy "effective groups contain `paddock:acme` and not `paddock:acme:locked`"; flow `paddock-device-code`
(stage configuration, requires authentication) set as `flow_device_code` of the default brand; users dave, erin
(`paddock:acme`), frank (`paddock:globex`), each with a TOTP device enrolled through the real
`default-authenticator-totp-setup` flow (secret captured by `akflow.py`). VMs from `base-installed` +
`vm-prepare.sh`, snapshot `poc-m1-himmelblau`.

**How the login works.** Himmelblau 4.0.4 has a generic OIDC mode (`oidc_issuer_url`, `app_id`). Against Authentik it
uses the **device authorization grant**: the greeter (and pamtester) shows the verification URL, the user code and a
QR code (`himmelblau-qr-greeter`); the user completes password + TOTP in a browser on another device. The
browser-orchestrated mode (`experimental_orchestrator_enabled`, Playwright in podman) only knows Keycloak, Okta and
Entra ID; ROPC is offered only with `allow_console_password_only = true` and would skip TOTP, so it is disabled. In the
PoC the "other device" is `akflow.py` on the host, which runs Authentik's flow executor exactly like a browser and logs
the stages: `ak-stage-identification`, `ak-stage-password`, `ak-stage-authenticator-validate` (TOTP code),
`ak-provider-oauth2-device-code-finish`.

**Commands.** `checks/c1-login.sh <vm>` (pamtester `gdm-password dave@acme.test authenticate acct_mgmt open_session
close_session`, twice, then frank); graphical: `checks/gdm.sh` (README, phase 3).

**Observed.**

- PAM level, both VMs: first login of dave = device code → password + TOTP at Authentik → "Set up a PIN" (Hello
  enrollment) → `account management done` → session opened; exit 0. Second login with the Hello PIN, exit 0.
- Identity: `dave:x:811622788:811622788:dave@acme.test:/home/dave@acme.test:/bin/bash`, identical after every login
  on both VMs (UID derived from the name by Himmelblau's idmap, `id_attr_map = name`). Home directory
  `/home/0664b380-ea6e-5f5a-b5bc-1a3f16026625` (object UUID) with symlink `/home/dave@acme.test`, created at
  `open_session`. Groups: `dave`, `users` (from `local_groups`), `paddock.acme` (from the claim).
- Graphical, both VMs: erin's first login at the GDM greeter ("Not listed?" → `erin@acme.test`) shows the QR code and
  the code (`out/<vm>/C1/gdm/02-…png` / 26.04 `03-device-code-qr.png`), approval from the host, "New PIN"/"Confirm PIN"
  at the greeter, then a Wayland GNOME session. dave logged in at GDM with his Hello PIN
  (`out/<vm>/C5b/gdm/01…04`), `loginctl`: `Type=wayland Class=user Active=yes`.
- frank: Authentik refuses the device approval (application policy; the flow returns to the code page), Himmelblau
  reports `Device code expired during device flow` after 60 s and the PAM stack fails (exit ≠ 0). Note: `getent passwd
  frank@globex.test` returns a synthetic entry before any successful login (Himmelblau resolves unknown OIDC names).
- Timing: device approval to PAM success ≈ 4 s (Himmelblau polls every 5 s); PIN login ≈ 0.4 s.

**Deviation needed to pass (Authentik configuration only, no change to Himmelblau).** The first runs failed in
`acct_mgmt` ("Number of intersecting groups: 0"):

1. Himmelblau requests only `openid profile email offline_access` (hard-coded; no `groups` scope), and Authentik emits
   the existing `groups` claim only for the `groups` scope.
2. Himmelblau drops every claim value that contains `:` (`oidc_extract_claim_string` in
   `src/common/src/idprovider/openidconnect.rs`, silently) — all Paddock group names contain `:`.

Fix in Authentik: an extra scope mapping on scope `profile`, attached to the device provider, returning
`{"groups": sorted({g.name.replace(":", ".") for g in request.user.all_groups()})}`; `pam_allow_groups =
paddock.acme`. (Authentik returned the list with a duplicate entry; harmless.)

**Verdict:** PASS on both VMs, with the claim adaptation above as a product requirement (see findings).

### C2 — Lock takes effect via Authentik

**Setup / commands.** `checks/c2-lock.sh <vm>`: baseline PIN login of erin; `authentik-setup.sh lock erin` = add to
`paddock:acme:locked` + delete erin's refresh tokens, access tokens and authenticated sessions via the API; then an
online login with the Hello PIN, approving the device code as erin when asked; `unlock erin`; login again.

**Observed (both VMs).**

| | 24.04 | 26.04 |
| --- | --- | --- |
| lock API calls (group + revocation) | 22:20:44.565 → 22:20:46.081 | 21:54:03.242 → 21:54:04.741 |
| PIN login after the lock: "Your session has expired. Please sign in again." | 22:20:46.552 (**2.0 s** after the call started) | 21:54:05.172 (**1.9 s**) |
| device code approval by erin | refused by Authentik immediately (policy) | same |
| PAM returns failure (device code expired) | 22:21:53.6 (**69.1 s**) | 21:55:12.0 (**68.8 s**) |
| after unlock | device code login + new Hello PIN enrollment, exit 0 | same |

The Hello PIN login refreshes tokens online; with the refresh token revoked the PIN no longer suffices and Himmelblau
falls back to the device flow, which the application policy refuses. The final PAM failure waits for the device code
to expire (Authentik `expires_in` 60 s); after that Himmelblau starts a second device flow, logs
`MFA poll already in progress`, returns `PAM_SYSTEM_ERR`, and the stack falls through to the `pam_unix` password
prompt (the checker stops there). After the unlock the old Hello key is invalid: the user must use the device flow
and enroll a new PIN.

**Diagnostic — lock by group only (`authentik-setup.sh lock erin group-only`):** the PIN login **succeeds** on both
VMs (`out/<vm>/C2/6-group-only-lock.log`). Authentik's refresh-token grant does not evaluate application policies, so
the revocation of refresh tokens is the part of the lock that takes effect on devices.

**Verdict:** PASS on both VMs (online lock effective within ≈ 2 s for PIN logins; ≈ 69 s until PAM gives up on a
device-code attempt).

### C3 — Device-wide suspension via allow list

**Commands.** `checks/c3-suspend.sh <vm>`. Option: `pam_allow_groups` in `/etc/himmelblau/himmelblau.conf`.

**Observed (both VMs).**

- The option is read at daemon start: after changing it to a group nobody has (`paddock.suspended`) dave was still
  admitted until `systemctl restart himmelblaud himmelblaud-tasks`; after the restart dave is refused in `acct_mgmt`
  ("Authentication failure"; authentication itself still succeeds). Reverting also needs a restart. Restart
  duration ≈ 3 s on the VMs.
- `pam_allow_groups =` (present, empty) **refuses everyone**; the man page's "if not set, all users are permitted"
  applies to a missing line. Removing the line therefore re-opens the device (fail-open by deletion).
- The local admin `paddock` was unaffected while suspended: `gdm-password` stack with password (`authenticate
  acct_mgmt open_session close_session`, exit 0) and SSH (key).

**Verdict:** PASS on both VMs (restart required).

### C4 — Hello PIN in OIDC mode

**Observed (both VMs).** Enrollment is offered right after the first successful device-code login ("Set up a PIN",
minimum 6). It needs the provider to allow the `refresh_token` grant and the client to get `offline_access` (refresh
tokens carry scopes `offline_access openid email profile`); `enable_hello = true` is the default. A PIN login is online
when the network is up (refresh-token grant + userinfo, ≈ 0.4 s) and offline otherwise (C5a). One wrong PIN:
"Failed to authenticate with Hello PIN", the correct PIN works afterwards. Three wrong PINs (`hello_pin_retry_count`
default 3, observed by accident on 26.04, `out/paddock-u2604/C4/diag-three-wrong-pins-reset.log`): "Too many incorrect
PIN attempts. You will need to enroll a new Linux Hello PIN." → device flow + re-enrollment.

**TPM binding.** `hsm_type` default `tpm_bound_soft_if_possible`; `aad-tool tpm`: "Soft HSM, but HSM PIN is TPM-bound
via systemd-creds" — the Hello key material is in Himmelblau's software HSM, its unsealing PIN is sealed with the TPM
(emulated TPM in the VMs). `hsm_type = tpm` (keys in the TPM) was not tested.

**Verdict:** PASS on both VMs.

### C5a — Offline login refused for a user removed from the allow list

**Commands.** `checks/c5a-offline.sh <vm>`. SSH uses the NAT adapter that `setlinkstate1 off` cuts, so the steps run
inside the guest as a transient systemd unit (`systemd-run --on-active=5`) with pamtester reading the PIN from stdin;
the log is collected after the link is back.

**Observed (guest clock).**

| step | 24.04 | 26.04 |
| --- | --- | --- |
| carrier 0 / Authentik unreachable | 22:23:27.9 / 22:23:32.9 | 22:03:00.1 / 22:03:05.1 |
| A: offline PIN login, dave in allow list | rc 0 | rc 0 |
| B: `pam_allow_groups = paddock.suspended`, restart, offline PIN login | rc 1 (`acct_mgmt`: Authentication failure) | rc 1 |
| C: reverted + restart, offline PIN login | rc 0 | rc 0 |

(26.04: the first run is invalid because of a script bug that captured the wrong exit status;
`out/paddock-u2604/C5a-run1-rc-bug/`.)

**Verdict:** PASS on both VMs.

### C5b — Screen unlock refused

**Commands.** dave logged in at GDM (Hello PIN), `checks/c5b-unlock.sh <vm>`: `loginctl lock-session` →
`LockedHint=yes`; allow list → `paddock.suspended` + restart; pamtester `gdm-password` (PIN); then the real lock
screen: Space, PIN, Enter, screenshot, `LockedHint`.

**Observed (both VMs).** pamtester: refused in `acct_mgmt`. Real lock screen: **unlocked** (`LockedHint=no`,
screenshot `12-after-unlock-attempt.png` shows the desktop). The journal shows that Himmelblau's account check ran
during the unlock and denied ("Number of intersecting groups: 0"), and `gdm-password` unlocked the keyring anyway —
the GDM/gnome-shell unlock path does not act on the account-management result. Reproduced twice on 26.04 (manual run
`out/paddock-u2604/C5b/manual-first-run/` and the script) and once on 24.04.

**Verdict:** FAIL on both VMs (the PAM-level check alone would have passed).

### C5c — pam_listfile fallback

**Setup.** `checks/c5c-listfile.sh <vm>` adds, as the first account line of `/etc/pam.d/common-account`:
`account required pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed`; the deny file holds
`dave@acme.test` and `dave`.

**Observed (both VMs).**

- File absent: dave logs in (fail safe, `onerr=succeed`).
- C5a with the deny file: offline login A rc 0 (before the file), B rc 1 (dave listed), C rc 0 (file removed).
- C5b with the deny file: pamtester refused, **the lock screen unlocks** (`LockedHint=no`) — same cause as C5b, the
  line sits in the account phase.

**Diagnostic, not part of the specified criterion:** the same `pam_listfile` options in the **auth** phase (`auth
requisite pam_listfile.so …` as first line of `common-auth`) make the lock screen refuse the PIN ("Sorry, password
authentication didn't work"), `LockedHint` stays `yes`; after removing the file the unlock works again
(`out/<vm>/C5c-diag-auth-phase/`). The PAM lines were removed after each run.

**Verdict:** PARTIAL on both VMs.

### C6 — No sudo granted by the login component

**Observed (both VMs).** `id`: `dave`, `users`, `paddock.acme`; `getent group sudo` → `sudo:x:27:paddock`;
`sudo -l -U dave@acme.test` → "User dave is not allowed to run sudo"; no sudoers entry. Group options in effect:
`local_groups = users` (also the package default in `/usr/lib/himmelblau/himmelblau.conf`); not set:
`sudo_groups`, `local_sudo_group` (default `sudo`, only effective with `sudo_groups`),
`local_groups_reconcile_interval`. Note: `local_groups` never removes memberships it added (man page).

**Verdict:** PASS on both VMs.

### C7 — TPM2+PIN boot unlock

**Commands.** `tpm/dracut-switch.sh` (24.04), `tpm/enroll.sh`, `tpm/boot-test.sh <vm> pin|wrong-pin|passphrase`.
Enrollment: `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 /dev/sda3` with `PASSWORD` and
`NEWPIN` from stdin-fed environment → "New TPM2 token enrolled as key slot 1"; `/etc/crypttab`:
`dm_crypt-0 UUID=… none luks,tpm2-device=auto`; `dracut -f --regenerate-all`.

**26.04 (dracut 110 as installed).** No dracut configuration needed: the initramfs already contains
`systemd-cryptsetup`, `libcryptsetup-token-systemd-tpm2.so` and the `libtss2-*` libraries once crypttab has
`tpm2-device=auto`. Plymouth prompt "Please enter LUKS2 token PIN". PIN typed via `keyboardputstring`: unlocked
(prompt → SSH 11 s). Wrong PIN: "Bad PIN.", prompt repeats, correct PIN then unlocks.

**24.04 (dracut 060 after the switch).**

- `apt-get install dracut`: installs `dracut`, `dracut-core` 060+5-1ubuntu3.4 and (recommends) `binutils*`,
  `finalrd`, `kpartx`, `mdadm`, `pigz`, `pkg-config`/`pkgconf*`; **removes** `initramfs-tools` and `brltty` (both left
  in `rc` state with their configuration; `/etc/initramfs-tools/` stays). `initramfs-tools-core`, `initramfs-tools-bin`
  and `cryptsetup-initramfs` remain installed but unused. So the switch does **not** leave initramfs-tools in a clean
  state: residual configuration and inert hook packages remain.
- The initramfs built by the package postinst does not boot: dracut's default image is generic, contains no
  `/etc/crypttab`, Ubuntu's GRUB passes no `rd.luks.*`, so the root LV never appears (emergency shell). Required
  configuration (`/etc/dracut.conf.d/90-paddock-tpm2.conf`):

  ```
  hostonly="yes"
  add_dracutmodules+=" systemd crypt tpm2-tss lvm "
  ```

  The `plymouth` module cannot be installed on 24.04 (`plymouth-set-default-theme` is not shipped; with it in the
  module list dracut aborts), so the prompt is the text console "Please enter LUKS2 token PIN: (press TAB for no
  echo)".
- PIN unlocks (prompt → SSH 11 s); wrong PIN: "Failed to unseal secret using TPM2: State not recoverable", prompt
  repeats, correct PIN unlocks.

**Passphrase after the switch / enrollment (both).** The passphrase is accepted only at the same PIN prompt and only
after the TPM token attempts are exhausted: 26.04 (systemd 259) tries every entry as PIN until the emulated TPM is in
dictionary-attack lockout (`TPM2_PT_MAX_AUTH_FAIL` 3, `LOCKOUT_RECOVERY` 1000 s), then "falling back to traditional
unlocking" with the cached entry; 24.04 (systemd 255) falls back after two failed token attempts. Measured: 3 entries
on both. The lockout persists in the TPM across reboots (cleared by the scripts with
`tpm2_dictionarylockout --clear-lockout`; the VMs have no lockout authorization).

**Snapshot `poc-m1-tpm`** taken after enrollment + recovery key on both VMs; after the snapshot restore the PIN still
unlocks and `mokutil --sb-state` = "SecureBoot enabled".

**Verdict:** PASS on both VMs.

### C8 — Recovery key

**Commands.** `tpm/recovery-key.sh <vm>` (`systemd-cryptenroll --recovery-key`, slot 2, token `systemd-recovery`),
`tpm/boot-test.sh <vm> recovery`.

**Observed.** The recovery key unlocks at boot, typed at the "LUKS2 token PIN" prompt; as with the passphrase it is
used only after the TPM attempts are spent: 26.04 4 entries (the DA counter started at 0 after a clear), 24.04 3
entries.

**Verdict:** PASS on both VMs (with the prompt behaviour above).

### C9 — Keyslot inventory

**Commands.** `tpm/inventory.sh <vm>`: `cryptsetup luksDump --dump-json-metadata` + jq,
`cryptsetup luksHeaderBackup` to `/var/backups/luks-header-<date>.img` (root only, stays in the guest).

**Observed (identical on both VMs).**

```
keyslot=0 type=luks2 token=none kdf=argon2id          (passphrase)
keyslot=1 type=luks2 token=systemd-tpm2 kdf=pbkdf2    (token 0: pcrs=7 pin=true, bank sha256)
keyslot=2 type=luks2 token=systemd-recovery kdf=pbkdf2 (token 1)
header backup: 16777216 bytes
```

**Verdict:** PASS on both VMs.

## Configuration that worked

`/etc/himmelblau/himmelblau.conf` (from `test/poc/m1/himmelblau/himmelblau.conf.tmpl`; no secrets in it):

```ini
[global]
oidc_issuer_url = https://auth.paddock.localhost:8443/application/o/paddock-device-acme/
app_id = paddock-device-acme
domain = acme.test
pam_allow_groups = paddock.acme
allow_console_password_only = false
enable_hello = true
hello_pin_min_length = 6
local_groups = users
debug = true
```

Installation: apt source `deb [signed-by=/etc/apt/keyrings/himmelblau.gpg] https://packages.himmelblau-idm.org/stable/4.0.4/deb/ubuntu$VERSION_ID/ ./`,
`apt-get install -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold` (the options of the upstream
installer; without them dpkg stops at a conffile prompt for `/etc/apparmor.d/local/*` from `himmelblau-apparmor`).
PAM/NSS: the package enables its `pam-auth-update` profile itself (`aad-tool configure-pam` changed nothing
afterwards):

```
common-auth:    auth    [success=3 default=ignore]               pam_himmelblau.so ignore_unknown_user set_authtok
common-account: account [success=2 auth_err=die default=ignore]  pam_himmelblau.so ignore_unknown_user
nsswitch.conf:  passwd/group/shadow: files systemd sss himmelblau
```

The daemon must be `systemctl reset-failed` and restarted after writing the configuration (the package starts it
without a configuration and it hits the start limit).

Authentik (all through the API, `test/poc/m1/authentik-setup.sh`):

- OAuth2 provider `paddock-device-acme`: `client_type: public`, `client_id: paddock-device-acme`, grant types
  `device_code`, `refresh_token`, `authorization_code` (only device code and refresh token were used; redirect URI
  `http://127.0.0.1:8765/callback` registered but unused), `authentication_flow: default-authentication-flow`,
  `authorization_flow: default-provider-authorization-implicit-consent`, `issuer_mode: per_provider`,
  `sub_mode: hashed_user_id`, `include_claims_in_id_token: true`, `access_token_validity: minutes=10`,
  `refresh_token_validity: days=30`, scope mappings openid, email, profile, offline_access, `Paddock: groups`
  (unused by Himmelblau) and the extra profile-scope groups mapping of C1.
- Application `paddock-device-acme`, `policy_engine_mode: all`, expression policy `paddock-device-acme-access`:
  ```python
  groups = {g.name for g in request.user.all_groups()}
  return "paddock:acme" in groups and "paddock:acme:locked" not in groups
  ```
- Default brand: `flow_device_code = paddock-device-code` (designation stage configuration, requires authentication,
  no stages). Device codes expire after 60 s.
- Verification flow: the brand's `default-authentication-flow` (identification, password, MFA validation with
  `not_configured_action: skip`).
- Lock: add to `paddock:acme:locked` **and** delete the user's refresh tokens, access tokens and authenticated
  sessions.

PAM change (C5c only, removed afterwards):
`account required pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed` as first account
line of `/etc/pam.d/common-account`.

dracut on 24.04 (C7): `/etc/dracut.conf.d/90-paddock-tpm2.conf` as shown in C7; crypttab option `tpm2-device=auto` on
both releases.

PoC snapshots (base-installed unchanged on both VMs):

| VM | snapshot | content |
| --- | --- | --- |
| both | `poc-m1-tpm` | base-installed + TPM2+PIN (PCR 7) + recovery key, passphrase slot kept; 24.04 also dracut instead of initramfs-tools |
| both | `poc-m1-himmelblau` | base-installed + Himmelblau 4.0.4, CA, hosts entry, pamtester; nobody logged in yet |

Both VMs are powered off; their current state is the end state of the login checks (after `poc-m1-himmelblau`).

## Findings and recommendations

### A2 — Himmelblau vs SSSD

Recommendation: **Himmelblau (4.x, OIDC mode)**. With configuration only it met C1–C4, C5a and C6 on both releases
against Authentik, including MFA verified by Authentik, Hello PIN, online lock and offline operation. Constraints the
architecture has to absorb:

1. **Login UX is the device authorization grant** (code/QR, completed on a second device). Password + TOTP at the
   greeter itself is not possible with Authentik: the orchestrator supports only Keycloak/Okta/Entra, ROPC is
   single-factor. Day-to-day logins use the Hello PIN.
2. **Group claim:** Paddock's `paddock:<slug>` names cannot be used as is. The device application needs a claim that
   Himmelblau accepts — emitted on a scope Himmelblau requests (`profile`) and without `:`. Recommendation: a defined
   device-claim naming (e.g. `paddock.<slug>`) owned by Paddock's Authentik adapter, plus an upstream request.
3. **Lock semantics:** only the revocation of refresh tokens/sessions locks devices; the group membership alone does
   not stop PIN logins. Paddock's lock must always do both. Refusal for a device-code attempt surfaces only after the
   device-code lifetime (60 s).
4. **Allow-list changes need a `himmelblaud` restart**; an empty value denies all, a missing line allows all — the
   agent must write the line explicitly and restart.
5. MFA enforcement for the device application should not rely on `default-authentication-flow`
   (`not_configured_action: skip` lets users without an authenticator in with a password only); give the device
   provider/brand an authentication flow with mandatory MFA.

### §9.5 step 2 — is the pam_listfile deny list needed?

For offline logins it is not needed: Himmelblau's allow list is enforced offline (C5a). For screen unlock **neither**
Himmelblau's allow list nor the specified `account`-phase `pam_listfile` line is effective, because the GNOME/GDM
unlock ignores the account-management result (C5b, C5c). The same `pam_listfile` check in the **auth** phase closed
the gap in a diagnostic run and stayed fail safe. Recommendation: architect decision to place the deny list in the
auth phase (`auth requisite pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed` before
`pam_himmelblau`), verify it also against SSH/TTY in M4, and report the GDM behaviour upstream. Note that
`common-auth`/`common-account` are generated by `pam-auth-update`; a durable solution is a `pam-auth-update` profile
shipped by Paddock rather than an edited file.

### K9/O4 — Ubuntu 24.04 with dracut

Supportable. TPM2+PIN works on 24.04 with dracut 060 and systemd 255, but needs: replacing initramfs-tools (removes
`initramfs-tools` and `brltty`, leaves configuration and `cryptsetup-initramfs` behind), `hostonly="yes"` and explicit
modules, no Plymouth (text prompt). 26.04 works out of the box with `tpm2-device=auto` in crypttab. On both, the
passphrase/recovery key is accepted only after the TPM PIN attempts are used up, which costs TPM dictionary-attack
budget (emulated TPM: 3 failures, 1000 s recovery per failure; R3 — re-test on hardware in M4). The recovery UX
documentation must say "type the recovery key at the PIN prompt, repeat until it is accepted".

### A14 — observations only

- GDM: directory users are reached through "Not listed?"; after the first login they are listed. The QR greeter
  extension works on GNOME 46 (24.04) and on 26.04; text and QR code overlap the Ubuntu logo at 1280×800.
- "New PIN"/"Confirm PIN" appear as separate greeter steps; the confirm field appears with a delay on 24.04.
- First login of a directory user starts the Ubuntu welcome wizard.
- Lock-screen errors read "Sorry, password authentication didn't work" even for PIN users.
- After a lock/unlock cycle in Authentik the user must re-enroll a Hello PIN.

### Upstream issues to file (not filed)

1. **Himmelblau: make the requested OIDC scopes configurable (or request `groups`).** Generic OIDC mode requests only
   `openid profile email offline_access`, while `pam_allow_groups` reads the `groups` claim from userinfo. Providers
   that emit group claims only for a `groups` scope (Authentik, many others) need provider-side workarounds.
2. **Himmelblau: group claim values containing `:` are silently dropped.** `oidc_extract_claim_string` rejects values
   with `:` without a log line, so an allow list on such groups never matches and the reason is invisible. Map or log
   them, and document the restriction in `himmelblau.conf(5)`.
3. **Himmelblau: `pam_allow_groups` changes need a daemon restart; empty vs. missing semantics undocumented.** A
   reload path (or file watch) and documentation that an empty value denies everyone while a missing line allows
   everyone.
4. **Himmelblau: second device flow after expiry fails with "MFA poll already in progress".** After a device code
   expires, the PAM conversation starts a new flow that immediately errors (`PAM_SYSTEM_ERR`) and the stack falls
   through to `pam_unix`.
5. **Himmelblau packaging: daemon started before configuration, AppArmor conffile prompt.** The postinst starts
   `himmelblaud` without a configuration (start limit reached), and `himmelblau-apparmor` ships `/etc/apparmor.d/local/*`
   conffiles that collide with the stubs Ubuntu creates, which stops non-interactive installs without
   `--force-confdef/--force-confold`. Also: "DB folder /var/cache/himmelblaud has 'everyone' permission bits".
6. **GDM / gnome-shell: screen unlock ignores `pam_acct_mgmt` failures.** With an account module denying the user
   (Himmelblau allow list, `pam_listfile` in the account phase) the lock screen still unlocks on Ubuntu 24.04 and
   26.04, while `pamtester gdm-password … acct_mgmt` refuses. Expected: the unlock honours the account phase like the
   login does.
7. **Ubuntu dracut 060 (noble): `plymouth` module not installable** because `plymouth-set-default-theme` is missing;
   dracut aborts when the module is requested, so TPM2-PIN prompts are text-only.

## Notes on the work itself

- Step 1 also fixed `deploy/compose/scripts/openbao-bootstrap.sh`: after `make down V=1` OpenBao was re-initialized but
  the old AppRole secret-ids were kept, so `paddock-api` never became healthy. Without that fix the step 1 check
  (three times `make down V=1 && make up && make dev-seed`) could not pass. Result: three cycles of 115–120 s each, all
  green; `make acceptance T=TestLogin` and `make lint test` green.
- The TPM phase ran before the Himmelblau phase (independent; it used the time while the dev stack was being
  recycled). The 24.04 dracut switch failed once (generic initramfs without crypttab, emergency shell); the VM was
  restored from `base-installed` and the corrected script re-run.

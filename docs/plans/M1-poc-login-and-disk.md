# Implementierungsplan: M1 — Proof of concept: login component (A2) and TPM2+PIN disk unlock

Status: Ready for implementation · 2026-10-03 · Author: architect
Basis: `docs/architecture.md` v1.3 (§2.1 K9, §9.3–9.5, §12.4, §25 O1/O4), concept "Login component: Himmelblau" (PoC gate items 1–4), architecture §9.5 (PoC item 5)

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

> **Nature of this plan.** This is a proof of concept, not product code. Its product is **evidence**: a report with a
> verdict per criterion, reproducible scripts, and the exact configuration that worked. A criterion that fails is a
> valid result, not a reason to stop. Do not "make it pass" by patching Himmelblau, writing PAM modules, wrappers or
> forks — that is forbidden by the concept (login rule 1 and 2) and would invalidate the PoC.

## 1. Goal

After M1 the architect can decide A2 (Himmelblau vs. SSSD fallback), whether the `pam_listfile` deny list (§9.5
step 2) is needed, and whether Ubuntu 24.04 is supportable with TPM2+PIN via dracut (K9/O4) — based on measured
results on the two test VMs against the real Paddock dev stack. Additionally, the flaky `make dev-seed` after a fresh
`make up` (M0.1 observation) is fixed.

## 2. Context

- **Dev stack:** M0/M0.1 complete; `make dev-secrets up dev-seed` starts Caddy, Authentik 2026.8.3, Paddock api etc.
  Authentik is reachable at `https://auth.paddock.localhost:8443` (Caddy `tls internal`; CA root exported to
  `deploy/compose/.secrets/caddy-root.crt`). Authentik bootstrap API token: `deploy/compose/.secrets/` (see
  `deploy/compose/scripts/gen-dev-secrets.sh` for the file name). Organizations `acme`, `globex` exist after
  `make dev-seed`; Authentik groups `paddock:acme`, `paddock:acme:admins|operators|auditors`.
- **Test VMs** (VirtualBox 7.2.16, read `test/vms/virtualbox/README.md` first):
  `paddock-u2404` (Ubuntu 24.04.5, initramfs-tools, SSH `127.0.0.1:2224`) and `paddock-u2604` (Ubuntu 26.04.1,
  dracut 110, chrony, SSH `127.0.0.1:2226`). Both: EFI + Secure Boot, TPM 2.0 (emulated), LUKS2 with one passphrase
  keyslot, GNOME/GDM, user `paddock` with passwordless sudo, snapshot `base-installed`. Start with
  `test/vms/virtualbox/start-vm.sh <vm>` (types the LUKS passphrase); with TPM unlock enrolled use `--no-unlock`.
  Secrets in `test/vms/virtualbox/.secrets/credentials.env`. The guest reaches the host as `10.0.2.2`.
- **VirtualBox NVRAM caveat (from the VM agent):** snapshots taken before the `VBoxHeadless` process has exited can
  silently wipe NVRAM (Secure Boot keys, TPM state). Always use `lib.sh` helpers (`wait_vm_state <vm> poweroff`,
  which waits for process exit) before snapshots or settings changes. Never run `VBoxManage modifynvram … listvars`
  on a VM whose NVRAM may be empty — it crashed VBoxSVC.
- **Concept rules for the login component (quoted):** "No intervention beyond configuration. What Himmelblau cannot do
  through its options is not added through patches, wrappers, or custom PAM modules." — "Missing features go upstream,
  never into a fork." Standard distribution PAM modules configured in PAM files (e.g. `pam_listfile`) are allowed;
  custom code in the login path is not.
- **Architecture decisions relevant here:** Himmelblau runs in **OIDC mode** against Authentik (no Entra direct mode);
  Paddock alone owns sudo (Himmelblau must grant none); per organization one Authentik application
  `paddock-device-<org_slug>` with an expression policy "member of `paddock:<slug>` and not of `paddock:<slug>:locked`";
  lock = membership in `paddock:<slug>:locked` + revocation of the user's sessions and refresh tokens; device login
  suspension = empty allow list; the managed local admin (here: `paddock`, a local `pam_unix` user) must stay usable.
- **TPM:** target enrollment `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7`, then
  removal of the passphrase slot after a recovery key exists (architecture §12.4). In the PoC the passphrase slot is
  **kept** (it is the recovery path for the VMs).

## 3. Binding decisions

1. **Snapshots:** `base-installed` MUST NOT be deleted or modified. Every phase starts from `base-installed` or from a
   PoC snapshot created by this work. PoC snapshots are named `poc-m1-<phase>` and taken only via a helper that waits
   for `VBoxHeadless` to exit. At the end both VMs are powered off.
2. **Himmelblau source:** the official Himmelblau package repository or the official GitHub release `.deb`s. Record
   version, source URL and signing-key fingerprint. If no package exists for a release (e.g. 26.04), building from the
   **unmodified** upstream source tag with the documented upstream build procedure is allowed; record that.
3. **Mode:** Himmelblau in OIDC mode against Authentik. If the installed Himmelblau version has no OIDC mode, that is
   the result for criteria 1–5 (FAIL: "not supported"), and the conditional SSSD step (§7 step 7) becomes mandatory.
4. **Authentik objects for the PoC** are created **only through the Authentik API** by an idempotent script with the
   bootstrap token, never by editing product blueprints. Names: OAuth2 provider + application
   `paddock-device-acme`; groups `paddock:acme:locked` (new), test users `dave@acme.test` (member `paddock:acme`,
   TOTP enrolled with a secret known to the script), `erin@acme.test` (member `paddock:acme`, TOTP enrolled),
   `frank@globex.test` (member `paddock:globex` only, for the isolation check). Passwords are generated and stored in
   `test/poc/m1/.secrets/` (git-ignored).
5. **Name resolution from the VMs:** the VM resolves the Authentik hostname to `10.0.2.2` via `/etc/hosts` and trusts
   the Caddy root CA via `/usr/local/share/ca-certificates/`. If `*.localhost` cannot be overridden inside the VM
   (systemd-resolved synthesizes it), add a development-only extra Caddy site `auth.paddock.test` through
   `compose.dev.yaml` (no change effective in production) and use that hostname from the VMs. Record which way was used.
6. **No product code changes** except §7 step 1 (dev-seed readiness fix) and the dev-only Caddy site of decision 5.
   PoC artefacts live in `test/poc/m1/` and the report in `docs/poc/M1-report.md`.
7. **No custom login code** (see box at the top). `pam_listfile` is the only PAM change allowed, and only for
   criterion 5c.
8. **Measurements** are made with timestamps (`date -u +%FT%T.%3NZ`) on host and guest; guest clocks are synced
   (chrony/timesyncd) — record the offset.

## 4. Non-goals

Paddock agent, bundles, device gateway, Paddock user-lock API, Paddock UI changes, SSSD as product implementation,
UX test for A14, Arch Linux, any change to `docs/architecture.md`, `docs/adr/**`, `docs/plans/**`, `.claude/**`,
`test/vms/**` (scripts there may be **used**, not changed).

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `test/acceptance/internal/authflow/*`, `test/acceptance/cmd/devseed/*`, `Makefile` (target `up` / `dev-seed` only) | change | Step 1 readiness fix |
| `deploy/compose/compose.dev.yaml`, `deploy/compose/caddy/` (dev-only snippet) | change, only if decision 5 requires | Extra dev hostname |
| `test/poc/m1/README.md` | new | How to reproduce every phase |
| `test/poc/m1/.gitignore` | new | `.secrets/`, `out/` |
| `test/poc/m1/authentik-setup.sh` | new | Idempotent API setup (decision 4) |
| `test/poc/m1/vm-prepare.sh <vm>` | new | hosts entry, CA trust, Himmelblau install + config |
| `test/poc/m1/himmelblau/himmelblau.conf.tmpl` | new | Configuration template actually used |
| `test/poc/m1/checks/*.sh` | new | One script per criterion, writing evidence to `out/<vm>/<criterion>/` |
| `test/poc/m1/tpm/*.sh` | new | TPM2+PIN enrollment and boot tests |
| `test/poc/m1/snapshot.sh` | new | Safe snapshot/restore wrapper around `lib.sh` |
| `docs/poc/M1-report.md` | new | The deliverable (§6) |
| `CHANGELOG.md` | change | Step 1 fix (`Fixed`) and dev-only Caddy site if added (`Added`) |

## 6. Report format (`docs/poc/M1-report.md`)

```markdown
# M1 PoC report
Date, Paddock commit, Authentik version, Himmelblau version + source + key fingerprint (per VM), kernel per VM,
how the VMs reached Authentik (decision 5).

## Verdict summary
| # | Criterion | 24.04 | 26.04 | Evidence |
Each cell: PASS / FAIL / PARTIAL / NOT TESTED (+ one-line reason).

## Per criterion
### C1 … C9 (below) — for each: setup, exact commands, observed result, timings, log excerpts (short), screenshots
paths, deviations, verdict.

## Configuration that worked
Final himmelblau.conf (secrets redacted), Authentik provider/application settings (grant types, scopes, refresh
token settings, flows), PAM changes if any.

## Findings and recommendations
For A2 (Himmelblau vs SSSD), §9.5 step 2 (pam_listfile needed?), K9/O4 (24.04 with dracut), A14 (observations only),
upstream issues to file (title + one paragraph each; do not file them).
```

Criteria (both VMs each):

| # | Criterion | PASS means |
| --- | --- | --- |
| C1 | **Authentik as OIDC provider incl. MFA** (concept PoC 1) | `dave` logs in at GDM (graphical) and via a PAM-level check (`pamtester gdm-password dave authenticate acct_mgmt open_session` or the equivalent interactive path) with password **and** TOTP verified by Authentik; home directory created; UID/GID stable across logins; `frank@globex.test` is **refused** on the acme device |
| C2 | **Lock takes effect via Authentik** (concept PoC 2) | after `authentik-setup.sh lock erin` (add to `paddock:acme:locked` + revoke sessions/refresh tokens via API), the next **online** login of `erin` fails; measure time from API call to refusal; unlock restores login |
| C3 | **Device-wide suspension via allow list** (concept PoC 3) | changing only Himmelblau's allow-list setting (and restarting/reloading the Himmelblau daemon if required) refuses all directory users; local user `paddock` still logs in (console/GDM and SSH); reverting restores directory logins; document the exact option and whether a restart is needed |
| C4 | **Hello PIN in OIDC mode** (concept PoC 4) | `dave` enrolls a Hello PIN and later logs in with the PIN; record the Authentik provider settings needed (refresh tokens / `offline_access`) and whether the PIN is TPM-bound |
| C5a | **Offline login refused for a user removed from the allow list** (architecture §9.5 item 5a) | VM network cut (`VBoxManage controlvm <vm> setlinkstate1 off`); `dave` (has cached credentials) is first shown to log in offline successfully; then `dave` is removed from the allow list locally and the offline login is refused |
| C5b | **Screen unlock refused** (§9.5 item 5b) | `dave` has a running GNOME session; session locked (`loginctl lock-session`); `dave` removed from the allow list; unlock attempt refused — measured both via the `gdm-password` PAM service (`pamtester`) and, if feasible headless, via keyboard input + screenshot; record `LockedHint` |
| C5c | **pam_listfile fallback** (§9.5 item 5c) — only if C5a or C5b FAIL | `account required pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed` added to `/etc/pam.d/common-account`; repeat C5a/C5b with `dave` in the deny file → refused; with the file absent → logins work (fail safe) |
| C6 | **No sudo granted by the login component** (A13) | `dave` is not in `sudo`/`admin` groups after login and `sudo -l` shows no rights; Himmelblau options that map groups to local groups are documented |
| C7 | **TPM2+PIN boot unlock** (K9/O4, §12.4) | 26.04 as installed (dracut) and 24.04 after switching to dracut: `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7` succeeds; reboot; PIN typed via `keyboardputstring` unlocks; wrong PIN is rejected and the passphrase still works; record the dracut configuration needed on 24.04 and whether the switch to dracut leaves `initramfs-tools` in a clean state |
| C8 | **Recovery key** (§12.4) | `systemd-cryptenroll --recovery-key` adds a slot; the recovery key unlocks at boot |
| C9 | **Keyslot inventory** (§11.5) | `cryptsetup luksDump --dump-json-metadata` output parsed (jq) lists exactly the expected tokens/slots (passphrase, tpm2, recovery); a header backup (`cryptsetup luksHeaderBackup`) is taken and its size recorded |

## 7. Implementation steps

1. **Fix dev-seed readiness**
   - **Do:** `make up` (or `dev-seed`) MUST wait until the Authentik flow `paddock-admin-login` is executable, not only
     until the container is healthy: poll `GET /api/v3/flows/executor/paddock-admin-login/` (or the cheapest call the
     `authflow` helper makes first) until it returns the expected first stage, at most 180 s, interval 3 s; then
     proceed. The `authflow` helper itself MUST NOT retry silently on authentication failures (only on readiness).
   - **Check:** three consecutive `make down V=1 && make up && make dev-seed` runs succeed without manual retry;
     `make acceptance T=TestLogin` green.
   - **Commit:** `fix(dev): wait for Authentik login flow before seeding` + CHANGELOG `Fixed`.

2. **Authentik PoC setup**
   - **Do:** `authentik-setup.sh` (decision 4) with subcommands `setup`, `lock <user>`, `unlock <user>`, `status`.
     Provider settings: confidential or public client as Himmelblau's OIDC mode requires; grant types needed for the
     greeter flow (authorization code, refresh token, device code — enable what Himmelblau needs and record it);
     scopes `openid profile email groups offline_access`; expression policy binding as in §2. Store client
     credentials in `.secrets/`.
   - **Check:** `authentik-setup.sh status` shows provider, application, policy binding, users and TOTP devices;
     discovery document reachable from the host at the hostname the VMs will use.
   - **Commit:** `test(poc): authentik setup for M1`.

3. **VM preparation**
   - **Do:** from `base-installed`: start VM, `vm-prepare.sh <vm>`: hosts entry + CA trust (decision 5), install
     Himmelblau (decision 2) and its PAM/NSS integration via the package's documented method, render
     `himmelblau.conf` from the template (issuer, client, allowed group `paddock:acme`, Hello PIN per criterion,
     no local sudo-group mapping), enable services. Power off, snapshot `poc-m1-himmelblau`.
   - **Check:** `getent passwd dave@acme.test` (or the name form Himmelblau uses) resolves after the first online
     lookup/login; Himmelblau services active; `journalctl` without errors at start.
   - **Commit:** `test(poc): VM preparation scripts`.

4. **Criteria C1–C4, C6** on both VMs (scripts in `checks/`, evidence in `out/`, `out/` is git-ignored but summarized
   in the report).
   - **Commit:** `test(poc): login criteria checks`.

5. **Criteria C5a, C5b, and C5c if required** on both VMs.
   - **Commit:** `test(poc): offline and screen-unlock checks`.

6. **TPM criteria C7–C9** on both VMs, starting from `base-installed` (independent of Himmelblau). 24.04: install
   `dracut`, configure it for LUKS + TPM2 (`systemd-cryptsetup`, `tpm2-tss` modules) and rebuild the initramfs; record
   every package change. Take snapshot `poc-m1-tpm` after successful enrollment.
   - **Check:** criteria evidence; VM boots with PIN; snapshot verified bootable (Secure Boot still enabled —
     `mokutil --sb-state`; TPM unlock still works after snapshot restore).
   - **Commit:** `test(poc): TPM2+PIN scripts`.

7. **Conditional — SSSD fallback (only if C1 or C2 FAIL on both VMs because Himmelblau's OIDC mode is missing or
   unusable):** time-boxed to 3 hours. Evaluate SSSD against Authentik on 26.04 via the most direct supported path
   (SSSD `idp` provider if present in the installed SSSD, otherwise Authentik LDAP outpost + SSSD `ldap` provider with
   credential caching): repeat C1 (without MFA if not possible — record), C2, C3, C5a. Report only; no product changes.
   - **Commit:** `test(poc): SSSD fallback evaluation`.

8. **Report**
   - **Do:** `docs/poc/M1-report.md` per §6; `test/poc/m1/README.md` reproduction guide; both VMs powered off;
     list PoC snapshots in the report.
   - **Commit:** `docs(poc): M1 report`.

## 8. Tests

The PoC checks are the tests. Product tests: `make lint test` and `make acceptance T=TestLogin` after step 1;
`make lint` at the end (shell scripts SHOULD pass `shellcheck` via the `koalaman/shellcheck` container image).

## 9. Acceptance criteria

| # | Given / When / Then | Requirement | Observed by |
| --- | --- | --- | --- |
| AC1 | Given a fresh stack, when `make up && make dev-seed` runs three times in a row, then it succeeds every time | M0.1 observation | Developer |
| AC2 | Given `docs/poc/M1-report.md`, then every criterion C1–C9 has a verdict per VM with evidence or a stated reason for NOT TESTED | A2, K9, O4, §9.5 | Architect |
| AC3 | Given `test/poc/m1/README.md`, when a developer follows it from `base-installed`, then each phase is reproducible without undocumented steps | reproducibility | Developer |
| AC4 | Given both VMs, then `base-installed` is unchanged and both VMs are powered off | safety | Developer |

## 10. Freedoms

Script structure and names inside `test/poc/m1/`; how GDM interaction is automated (keyboard input, screenshots,
`pamtester`, `gdbus`); additional diagnostic checks; order of VMs; extra PoC snapshots (prefix `poc-m1-`).
For criteria that can only be partly automated, a documented manual-equivalent headless method is acceptable.

## 11. Stop conditions

Stop and report (QUESTION format) only when:

- the environment is broken in a way you cannot restore from snapshots (VirtualBox service crash loops, NVRAM/TPM of
  `base-installed` corrupted, dev stack cannot start);
- achieving a criterion would require custom login code, patching or forking Himmelblau, or disabling Secure Boot —
  then record FAIL with the reason instead and continue with the next criterion (this is **not** a stop);
- a step would change something listed in §4 as off-limits.

A failing criterion is never a stop condition. The product owner is unavailable until 2026-10-04 07:00; questions you
send will be answered by the architect only.

## 12. Risks and open points

| # | Item | Default |
| --- | --- | --- |
| R1 | Himmelblau may not package 26.04 yet | Decision 2 (build from unmodified source) |
| R2 | GNOME unlock hard to automate headless | `pamtester` against `gdm-password` is the primary evidence; screenshots secondary |
| R3 | Emulated TPM differs from hardware TPM (lockout, PCR behaviour) | Record; real-hardware test stays in M4 acceptance |
| R4 | Network cut may disturb the dev stack | Only the VM link is cut (`setlinkstate1`) |

# Revocation: hardware acceptance protocol and second-person review

The revocation path stays disabled (`PADDOCK_REVOCATION_ENABLED=false`) until **both** parts of this document are
signed off: the second-person review of the device code and the test on a real laptop (design contract 10, plan
M4c §7). Only then does the architect plan enabling the flag. Gates R1–R6 on the test VMs are necessary, not
sufficient: they run `paddock-revoke` with the `paddock_revoke_testtarget` build against a second disk, never the
release binary against a real root volume.

The protocol is executed by the product owner. Record every result in the table at the end, with the date, the
commit and the package versions.

## Prerequisites

- A **test installation** of Paddock with `PADDOCK_REVOCATION_ENABLED=true` (api, compiler and revocation-issuer),
  `PADDOCK_ENV=development` for the one-day dead man's switch period (step 5), and a test organization with two
  organization administrators **with different Authentik identities** (admin A and admin B), both with MFA.
- A laptop that may lose its data: TPM 2.0, Secure Boot on, no data of value. A live USB stick with Ubuntu 24.04 or
  26.04 (`cryptsetup` included).
- **Release builds** of the agent packages (`make agent-release`, never with `REVOKE_TAGS`): check on the laptop that
  `/opt/paddock/revoke/paddock-revoke version` prints the release version and that
  `/etc/paddock/revoke-test-target` does not exist.
- A second computer for the portal.
- **A second LUKS volume** on the laptop (M4c.1, PDK-009): after step 1, create a LUKS2 data volume on a spare
  partition or USB disk with its own passphrase, add it to `/etc/crypttab` by `UUID=`, and put a test file on it.
  Note its LUKS UUID (`cryptsetup luksUUID`).

## 1. Install the laptop with the Paddock autoinstall (TPM2+PIN)

1. Admin A: portal → *Enrollment tokens* → new token with auto-approval; then generate the autoinstall for the laptop
   (`docs/operations/autoinstall.md`) and install from it.
2. At the first boot enter a boot PIN twice.

**Expected:** the laptop reboots, asks for the PIN, starts with it. The device page shows the device as active, *Disk
encryption* `compliant` with a stored recovery key and header generation. After the data volume is added (prerequisites),
*Disk encryption* lists **both** volumes, each with a stored header, and stays `compliant`. On the laptop
`/etc/paddock/revoke-trust.json` exists (the revocation keys pinned at enrollment) and `/etc/paddock/revoke-enabled`
exists (flag on).

## 2. Lock → the device does not unlock

1. Log in on the laptop as a user and open a document.
2. Admin A: device page → *Lock and Destroy*: reason "hardware acceptance", *Lock device*, step-up, type the hostname,
   confirm.
3. Wait for the next check-in (at most a few minutes; the request on *Revocations* goes `issued` → `delivered`).

**Expected:**

- The user session ends, the laptop reboots by itself.
- The request is `confirmed`; its result shows `erased: true` and `slots_after: 0`; the audit log has
  `revocation.requested`, `revocation.issued` and `device.revocation_confirmed`.
- At the boot prompt the PIN is refused; the recovery key is refused; the install passphrase (if known) is refused.
  The disk does not unlock with anything.
- The confirmation lists **both** volumes with `slots_after: 0` (the data volume was escrowed, so the Lock token listed
  it); `skipped_not_escrowed` and `unresolved` are empty. From the live USB, the data volume does not unlock with its
  passphrase.

**2b. Lock skips a volume without a stored header.** Repeat steps 1–2 on a fresh installation, but add a second data
volume right before the Lock, so its header is not stored yet. **Expected:** the confirmation reports that volume under
`skipped_not_escrowed` and it still unlocks with its passphrase; root and the escrowed volume are erased.

## 3. Restore from the escrow with the recovery key (live USB)

1. Admin A: device page → *Disk encryption* → *Download header backup* and *Show recovery key* (each with a step-up
   and the typed hostname).
2. Boot the laptop from the live USB stick, copy the header file onto it and run (`lsblk -f` names the LUKS
   partition):

   ```sh
   sudo cryptsetup luksHeaderRestore /dev/<partition> --header-backup-file <hostname>-luks-header-<generation>.img
   sudo cryptsetup open --test-passphrase /dev/<partition>   # type the recovery key
   ```

3. Reboot without the stick.

**Expected:** `--test-passphrase` succeeds with the recovery key; the laptop starts with the PIN (or the recovery key
at the PIN prompt); the document from step 2 is intact. The device checks in again; it reports the keyslot change
(`device.tamper_keyslot_changed`) and escrows the header again. It does not lock again.

## 4. Destroy with two administrators → unrecoverable, escrow gone

Wait 24 hours after step 2 (the device accepts one revocation per 24 hours; a refusal `rate_limited` before that is
also a pass of that limit — note it and wait).

1. Download the header backup and reveal the recovery key once more (admin A) and keep both for the check below.
2. Admin A: *Destroy device* with reason, step-up and typed hostname. **Expected:** the request waits on
   *Revocations* (`Waiting for approval`); admin A sees only *Cancel request*, the device is unchanged.
3. Admin A, with a second administrator account of the **same** Authentik identity if one exists: approve.
   **Expected:** rejected (`revocation.issue_refused`), nothing happens.
4. Admin B: *Approve*, step-up, typed hostname.

**Expected:**

- The laptop reboots and does not unlock (as in step 2).
- The request is `confirmed`; the audit log has `device.escrow_destroyed` **before** `revocation.issued`.
- *Disk encryption* shows no recovery key and no header; *Download header backup* and *Show recovery key* answer
  "This item no longer exists" (404).
- In the escrow bucket no version of any object below `org/<org>/devices/<device>/luks-header/` is left (operator:
  `aws s3api list-object-versions --bucket paddock-escrow --prefix org/<org>/devices/<device>/`).
- From the live USB, restoring the header kept in step 1 and typing the kept recovery key works (the old header has
  its keyslots) — this documents that a Destroy relies on nobody keeping a copy; then erase the laptop. Without such
  a copy nothing restores it.

## 5. Dead man's switch with a one-day test period

Re-install the laptop as in step 1 (a destroyed device cannot be restored).

1. Admin A: portal → *Dead man's switch*: turn it on with period 7 days (step-up, confirmation). Right after the page
   reports the settings saved — within the step-up window (`PADDOCK_STEPUP_WINDOW`, 30 s in the development
   compose stack) — set the period to **1 day** and no warnings (development installations accept 1 day; the portal
   stops at 7, so use the browser console of the portal tab; an answer 403 `step_up_required` means the window
   passed: save in the portal again and repeat):

   ```js
   await fetch('/api/v1/settings/dms', { method: 'PUT', headers: { 'Content-Type': 'application/json',
     'X-Paddock-CSRF': '1' }, body: JSON.stringify({ enabled: true, period_days: 1, warn_days: [] }) })
   ```

   For the warnings, run a second pass with period 2 days and `warn_days: [1]`.
2. Wait for a check-in: `/var/lib/paddock/revoke/self-lock.dsse` exists on the laptop; *Revocations* lists a
   `self_lock` request for it.
3. Cut the laptop off from Paddock (disconnect the network, or block the server address), keep it powered on and
   note the time. Change the wall clock by +3 days and back (`sudo date -s`).

**Expected:**

- Nothing happens before 24 hours of uptime (the clock change neither triggers nor defers it); with the 2-day pass the
  warning appears after 24 hours as a desktop notification and on the login screen.
- After 24 hours of uptime the laptop locks itself as in step 2 (the confirmation is posted once the network is back,
  if it is). After 24 h + 5 min the device page shows *presumably locked itself* (`device.presumed_self_locked`).
- Restore as in step 3. Turn the switch off: `self-lock.dsse` disappears with the next check-in.
- Powered-off time does not count: a laptop that is switched off for longer than the period does not lock at its next
  start.

## 6. Second-person review of `agent/internal/revoke/` and `agent/cmd/paddock-revoke/`

The reviewer is not the author of the change. Review the whole package, not only the diff, at the commit that is
tested in steps 1–5. Check every item and note the file and line you checked.

| # | Check |
| --- | --- |
| 1 | **Sequence order** (`revoke.go`, `execute`): the token ID is recorded first, then (1) sessions terminated, (2) every keyslot erased and verified (`luksDump` shows none), (3) the confirmation posted with at most `ConfirmTimeout` (20 s), (4) reboot regardless of the confirmation. Nothing else runs between (2) and (4). |
| 2 | **No network calls before the erasure**: the trust checks read local files only (`revoke-enabled`, `revoke-trust.json`, `state.json`); the only network call is the confirmation in step (3). `main.go` builds the client but does not use it before `Confirm`. |
| 3 | **No erasure without a verified token**: every path to `erase` passes `verify` (DSSE signature against a key of `revoke-trust.json`, payload type, this device ID) and `check` (not executed before, 24 h limit, root device found). A Lock or Destroy also passes the lifetime check; a self-lock passes `VerifyStored` (lifetime checked when it was stored) and the period check against the uptime counted by `paddockd`. A refusal (`*Refusal`) returns before any session or keyslot is touched. |
| 4 | **Trust anchor**: the keys come only from `/etc/paddock/revoke-trust.json` (pinned at enrollment, or once on first use for older devices, `agent/internal/agent/revocation.go`), never from the token, a bundle at run time or the network. |
| 5 | **24 h limit**: `check` refuses while `LastRevocationAt` is less than `RateLimit` (24 h) ago; `record` sets it before the sequence; a crash after `record` cannot lead to a second run of the same `command_id`. |
| 6 | **Feature flag**: without `/etc/paddock/revoke-enabled` every token is refused (`disabled`), including stored self-locks. |
| 7 | **Test target excluded from release builds**: `target_testtarget.go` carries `//go:build paddock_revoke_testtarget`, `target_release.go` the negation; the release `RootDevice` refuses (`test_target_present`) while `/etc/paddock/revoke-test-target` exists; `make agent-release` refuses `REVOKE_TAGS`; the release package was built without it (prerequisites). |
| 8 | **Self-lock**: `Handle` only stores a self-lock token, never runs it; `SelfLock` runs only a self-lock token and only with an elapsed uptime ≥ its `period_days`. |
| 9 | **No secrets in logs**: the token, the device key and keyslot material are never logged; refusals log the reason only. |
| 10 | **Exit codes and output** (`main.go`): 0 executed or stored, 2 refused (nothing changed), 1 error; `paddockd` hands every envelope over once and reports refusals as `device.revocation_refused`. |
| 12 | **Target selection** (`agent/internal/luks/crypttab.go`, `targets.go`): every `/etc/crypttab` LUKS entry is a target (`UUID=`, `PARTUUID=`, `/dev/…`, `header=` uses the detached header); plain/swap/tmp entries are skipped only with those options; anything unclassifiable is `unresolved` and makes `erased` false; paths outside `/dev` are rejected; volumes sharing a UUID (clones) stay targets. |
| 13 | **Token volumes only narrow a Lock**: a Lock or self-lock erases root plus exactly the token's `volumes` that are in the device's own selection; shared-UUID volumes and, while the root UUID is unknown, every secondary are skipped; a **Destroy ignores `volumes` and erases every target**. `paddockd` cannot add a target. |
| 14 | **Deadlines**: secondaries share one deadline (`SecondaryWithin`), commands have `WaitDelay`; root is always attempted afterwards with its own timeout; a hung root-UUID read never shrinks a Destroy. |
| 11 | **Tests**: `go test ./agent/internal/revoke/` and `go test -tags paddock_revoke_testtarget ./agent/internal/revoke/` pass; the tests cover every refusal reason and the sequence order. |

## Sign-off

| Part | Result (pass / fail, notes) | Commit and versions | Date | Name |
| --- | --- | --- | --- | --- |
| 1 Install | | | | |
| 2 Lock | | | | |
| 2b Lock skips unescrowed volume | | | | |
| 3 Restore | | | | |
| 4 Destroy | | | | |
| 5 Dead man's switch | | | | |
| 6 Review (second person) | | | | |

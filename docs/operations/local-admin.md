# Managed local administrator

Every device managed with login management (its organization has a domain) gets a local administrator account
whose password Paddock rotates and keeps escrowed, so an organization administrator can always sign in at the
device, also without network or identity provider (concept F16, architecture §12.2, plan M4a).

## Settings

*Login & privileges → Local administrator* (`PUT /api/v1/settings/login`):

| Setting | Default | Meaning |
| --- | --- | --- |
| `local_admin_username` | `paddock-admin` | Account name (`^[a-z_][a-z0-9_-]{0,31}$`). It cannot change once a device has an active password (409 `setting_locked`). |
| `local_admin_rotation_days` | 30 | The device rotates the password every that many days (1–365). |
| `rotate_after_reveal_hours` | empty | If set (1–168), a reveal schedules a rotation that many hours later. |

The account is always a break-glass account: it is never on the deny list and never removed from the `sudo` (or
`wheel`) group. It has **full sudo rights** (intended for break-glass use); every login with it is audited.

## On the device

The agent creates the account (`useradd -m -K HOME_MODE=0700 -s /bin/bash -G sudo`, `wheel` where `sudo` does not
exist) with a locked password and rotates it at once:

1. It generates a password of 24 characters (144 bits), encrypts it to the escrow key of its bundle
   (`escrow-wrap`, RSA-OAEP with SHA-256) and uploads it (`POST /v1/escrow`, generation = the highest one it tried
   plus one).
2. It polls `GET /v1/escrow/{id}` every 30 s for up to 15 minutes. Only when the server answers `stored` does it
   set the password (`chpasswd`, input on stdin) and report `local_admin.rotated`; the server then marks that
   generation active and older ones superseded.
3. If the server does not store it in time, or refuses it, the old password stays valid and the device reports
   `local_admin.rotation_failed` (`escrow_timeout`, `escrow_failed`; `apply_failed` if `chpasswd` failed). An
   automatic rotation is retried 15 minutes later; a *Rotate now* command fails.

The plaintext exists only in the agent's memory during a rotation and is zeroed afterwards; it is never written,
logged or sent unencrypted. Rotations need the server: an offline device keeps its password, and the portal shows
the rotation as overdue (`next_rotation_at` in the past).

**Local changes** are detected every 30 s by comparing the account with the last rotation: a changed password
hash, a locked or expired account, another shell or a missing group membership are reported once each as
`device.tamper_local_admin_changed` (`field` `password`, `locked`, `shell`, `group`, `missing`). Shell, group and
expiry are repaired at once; a changed or locked password triggers a rotation, which restores a password Paddock
knows. A deleted account is created again.

**Logins** with the account (`pam_unix` session openings in the journal) are reported as `local_admin.login` with
the PAM service (`sshd`, `login`, `gdm-password`, …) and the time — no terminal, no remote host.

## Portal and API

- `GET /api/v1/devices/{id}/local-admin` — account name, active and pending generation, last rotation, next
  rotation, last failed rotation.
- `POST /api/v1/devices/{id}/local-admin/rotate` (administrators, operators) — command `rotate_admin_password`
  (audit `local_admin.rotation_requested`).
- `POST /api/v1/devices/{id}/local-admin/reveal` (organization administrators) — needs a step-up within the last
  300 s (`docs/operations/step-up.md`) and the device's hostname as `confirm_hostname`. It returns the active
  password and, during a rotation, the pending one with `Cache-Control: no-store`, and records exactly one
  `local_admin.revealed` event with the generations (never the passwords).

While a rotation waits for its confirmation, the server keeps both generations, so a reveal never misses the
password that is valid on the device.

## Keys and credentials

Only `paddock-api`'s reveal decrypts, with its own OpenBao AppRole `paddock-escrow-reader` (`update` on
`transit/decrypt/escrow-wrap`), configured with `PADDOCK_OPENBAO_ESCROW_ROLE_ID_FILE` and
`PADDOCK_OPENBAO_ESCROW_SECRET_ID_FILE` (see `docs/operations/openbao.md`). The rest of the api uses its normal
AppRole. A sealed OpenBao makes reveals fail with 502 `upstream_unavailable`; devices keep their passwords.

# Device login: Himmelblau, locks, suspension, break-glass accounts

How users sign in on Paddock devices, and what happens on a device when an administrator locks a user or suspends
logins (architecture §9.3–9.5, plan M3b). Directory users sign in through **Himmelblau** in OIDC mode against the
organization's Authentik application `paddock-device-<slug>`; local accounts sign in with their password as before.

## What the agent sets up

At the first bundle with login management (agents report bundle schema 2), the agent:

1. installs Himmelblau `PADDOCK_HIMMELBLAU_VERSION` (setting of `paddock-compiler`, default `4.0.4`) from the
   official repository `https://packages.himmelblau-idm.org/stable/<version>/deb/ubuntu<release>/`. The repository
   signing key is built into the agent (fingerprint `E87F D8D4 63A5 E481 4B9C DBA9 0CC0 D400 2C42 5E03`) and written
   to `/etc/apt/keyrings/himmelblau.gpg`; the source is `/etc/apt/sources.list.d/paddock-himmelblau.list`. Only this
   source is updated; if the installation then fails on a dependency (stale package lists of the other sources), the
   agent runs one `apt-get update` of every source and tries once more. apt waits up to 10 minutes for a dpkg lock
   held by unattended upgrades. A failure is reported as `device.login_apply_failed` (stage `apt`) and retried at
   every drift pass;
2. writes `/etc/himmelblau/himmelblau.conf` (issuer and client of the organization's device application, the device's
   allow list `pam_allow_groups`, Hello PIN settings, no console password login, the fixed UID range
   `idmap_range = 200000-999999999` — sudo-rs cannot handle longer numeric users, and changing the range would give
   every directory user a new UID) and restarts `himmelblaud` and
   `himmelblaud-tasks`, which read the allow list only at start. Local changes are reverted at the next drift pass;
3. keeps the deny list `/etc/paddock/login-deny` of locked users (see below), an empty file when nobody is locked.

The `paddock-agent` package enables the PAM profile `paddock-deny` (`/usr/share/pam-configs/paddock-deny`). It puts
`pam_listfile` with the deny list in front of every other primary module:

```
common-auth:    auth requisite pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed
common-account: account required pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed
```

The agent never edits PAM files. It checks these lines at every apply; if the profile was removed (for example with
`pam-auth-update`), it reports `device.login_apply_failed` (stage `pam`) and `device.tamper_protected_file_changed`.
Restore the profile with:

```sh
sudo dpkg-reconfigure paddock-agent
```

Without the deny file every login works (`onerr=succeed`): the deny list can only refuse, never lock out a device. A
missing file is written again (empty, or with the locked users) at the next drift pass. On a device without login
management (its organization has no domain) the agent still creates the file empty while the
profile is enabled, but never changes an existing one.

## Login notice

The organization's login notice (*Login & privileges → Login notice*, setting `notice_text`, at most 2000
characters of plain text; empty removes it) is shown before every login (plan M4a decision 19):

| Where | File (written by the agent, restored when changed locally) |
| --- | --- |
| GDM login screen | `/etc/dconf/db/gdm.d/90-paddock-notice` (`banner-message-enable`, `banner-message-text`), then `dconf update`; only with `gdm3` installed |
| Text consoles | `/etc/issue.d/90-paddock.issue` |
| SSH | `/etc/paddock/notice` and `/etc/ssh/sshd_config.d/90-paddock-banner.conf` (`Banner /etc/paddock/notice`), then `systemctl try-reload-or-restart ssh.service`; only with `openssh-server` installed |

The GDM greeter shows a changed banner the next time it starts (logout or restart). The notice replaces the sudo
lecture as the place for the usage policy on devices whose sudo is sudo-rs, which ignores custom lectures.

## Signing in (users)

- **First login** on a device, and the first login after a lock and unlock or after three wrong PINs: at the login
  screen choose *Not listed?*, type the username (`name@domain`). The screen shows a code and a QR code. Open the
  QR code (or `https://auth.<domain>/device` and type the code) on a second device — a phone or another computer —
  and sign in there with password and MFA. Back at the device, set a **Hello PIN** (twice).
- **Day-to-day logins** use the Hello PIN, also offline. Online PIN logins are checked against Authentik, so a lock
  takes effect at once.
- Users not in the device's login assignment (or not in the organization) are refused: Authentik refuses users of
  other organizations, the device refuses users outside its allow list.

## Throttle of device-code logins

Every device-code login (the code and QR code at the login screen) starts one device authorization at Authentik.
Authentik limits them per client address; Authentik's own default is 20 per hour. Paddock sets the limit with
`PADDOCK_DEVICE_LOGIN_THROTTLE` in `deploy/compose/.env` (default `600/hour`; format `<count>/<second|minute|hour|day>`),
which Compose passes to both Authentik containers as `AUTHENTIK_THROTTLE__PROVIDERS__OAUTH2__DEVICE`. Above the limit
Authentik refuses new device codes (`slow_down`) and the login screen shows an error until the window has passed.

**NAT:** Authentik sees one client address for all devices behind the same NAT, proxy or VPN exit, and they share
the limit. Size it for the busiest such address at its peak hour of first logins — a site rollout, a Monday morning
after a mass lock and unlock, or new laptops for a class — not for the total number of devices. Day-to-day Hello PIN
logins do not start device authorizations. A change takes effect when the Authentik containers are recreated:

```sh
docker compose up -d authentik-server authentik-worker
```

## Authentik brand flows

`paddock-worker` sets the recovery flow (`paddock-recovery`, the one-time links of new local users) and the device-code
flow (`paddock-device-code`, the `/device` page with mandatory MFA) of Authentik's default brand at start and every 10
minutes, and resets them if they were changed in Authentik. Until the flows are set — on a fresh installation until
Authentik has applied the Paddock blueprints — creating a local user fails with 502 `upstream_unavailable`.

## Locks

Locking a user in Paddock (portal *Users*, `POST /api/v1/users/{id}/lock`) acts on two paths:

| Path | Effect | When |
| --- | --- | --- |
| Authentik | the user's tokens and sessions are revoked; every online login and online PIN login fails | at once |
| Device | the user is written to the deny list: login, offline login with the cached PIN and **screen unlock** are refused; the user's open sessions show the lock screen (`user_lock_session_action: lock_screen`) or are ended (`terminate`) | at the device's next check-in (network change, resume, or the regular interval of about 5 minutes) |

The device reports `device.user_lock_applied` with the number of sessions it locked or ended. A device that is
offline keeps accepting the cached PIN until its next contact. After an unlock the user signs in with the device code
again and sets a new PIN.

The deny list holds the user's full name and the short name before `@`, except when the short name is a local account
(UID below 60000): local accounts are never denied by a directory lock. Break-glass accounts are never denied.

## Suspending logins

*Suspend logins* on a device (`POST /api/v1/devices/{id}/suspend-logins`) empties the device's allow list: at its next
check-in the device refuses every directory login and ends the sessions of all directory users
(`device.logins_suspension_applied`). Local accounts keep working. *Resume logins* restores the allow list.

## Break-glass accounts and sudo

Paddock alone grants sudo on its devices (architecture §10). Set in *Login & privileges*:

- **break-glass accounts**: the local administrator accounts of your devices (for example `paddock-admin`). They are
  never denied by a lock, never ended by a suspension, and stay members of `sudo`, `admin` and `wheel`. Every other
  member of these groups is removed at the next apply and reported (`device.tamper_sudo_group_member`).
- **sudoers.d allow list**: the files in `/etc/sudoers.d` that are not Paddock's (for example `README` and the sudoers
  file of the break-glass account). Every other file is moved to `/var/lib/paddock/quarantine/sudoers.d/` and
  reported (`device.tamper_sudoers_d_file`).

**Configure both before devices get an agent of this release**; otherwise the first apply takes sudo away from your
local administrator.

Users with a permission profile get a file `/etc/sudoers.d/paddock-u-<hash>` that names their numeric UID. The agent
writes it for the sudo implementation behind `/usr/bin/sudo` — classic sudo, or sudo-rs, the default of Ubuntu 26.04 —
and checks it with that implementation's `visudo`. sudo-rs does not support a custom lecture text: on such devices users
see sudo-rs's default lecture, and the device detail says so. A user who
never signed in on a device is not known there yet (`device.sudo_user_unresolved`); the rights apply after the first
login. Changes of `/etc/sudoers` are reported (`device.tamper_sudoers_changed`) but not reverted; a missing
`@includedir /etc/sudoers.d` is reported as `device.sudo_apply_failed`.

## Device reports

The device detail in the portal shows the latest login and sudo report of the agent (*Latest reports of the agent*);
the audit log has every report as `device.<event>`.

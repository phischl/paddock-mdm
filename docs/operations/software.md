# Software catalog: package sources, applications and their enforcement

An organization lists the applications its devices install, keep, hold or block in the **software catalog**, and the
third-party APT repositories they come from as **package sources**. Each application (a catalog entry) is assigned to
a device group or to the whole organization with an **intent**. The agent enforces the assignments on every device
and reports what it did per application (ADR 0042, plan M13a). This page covers adding a source, writing entries,
what each intent does on the device, the states and reasons the device reports, and troubleshooting.

In the portal: *Package sources* (organization administrators), *Software catalog* with an entry's assignments and
devices, *Software requests*, and the *Managed software* tab of a device. The admin API: `/api/v1/software-sources`,
`/api/v1/software-catalog`, `/api/v1/software-catalog/{id}/devices`, `/api/v1/software-assignments`,
`/api/v1/software-requests`, `/api/v1/device-groups/{id}/maintenance-window` and
`/api/v1/devices/{id}/managed-software`. Changes to assignments roll out in waves (*Waves*), devices apply them inside
their maintenance windows (*Maintenance windows*), and an entry can require an administrator's approval (*Approvals*).

## Adding a package source

A source is root-equivalent: every package its key signs installs as root on every device of an assignment (RR-77).
Only an organization administrator adds, changes or removes one, and only with a fresh step-up (a security key). API
tokens never have a step-up, so they cannot change sources (403 `step_up_required`, recorded as a `denied` event).

1. **Get the vendor's fingerprint out of band**: from the vendor's documentation page over HTTPS, a signed
   announcement or the vendor's support, never from the same download as the key. Paddock checks the key against the
   fingerprint you type; it cannot tell whether the fingerprint is the vendor's.
2. **Paste the key**: the ASCII-armored OpenPGP public key (`-----BEGIN PGP PUBLIC KEY BLOCK-----`), exactly one
   primary key with its subkeys, at most 64 KiB. Accepted are RSA of at least 2048 bits (2048–3071 bits are accepted
   with a *weak key* warning, acceptable until 2030; `weak_key` is in the audit event), Ed25519, Ed448 and NIST
   P-256/384/521; DSA, ElGamal, Brainpool and secp256k1 are refused.
3. **Type the fingerprint** (40 hexadecimal characters; spaces and case do not matter). A different fingerprint is
   refused with 422 `fingerprint_mismatch`, naming both values, and recorded as a `failure`.
4. **Fill in the repository**: a slug (`[a-z0-9-]`, 2–41 characters, fixed after creation; the device files are named
   after it), a name, 1–4 URIs, the suites, the components and optionally the architectures (`amd64`, `arm64`).
   URIs must use `https://` (anything else is 400 `invalid_request`, *uris must use https*), without user info, query
   or fragment. Either every suite is a flat repository (ends in `/`, for example `./`) and there are no components, or
   no suite is flat and there is at least one component: a malformed deb822 entry would stop every apt operation on
   the device.
5. **Save** and confirm the step-up. The audit event `software_source.created` records the name, slug, URIs, suites,
   components and the fingerprint.

The server never contacts a source: no reachability check and no key server lookup. A URI may therefore name an
internal host or an internationalized domain name; the devices fetch from it, so it must resolve and be reachable from
them, with a certificate their system trust store accepts.

**Changing the key** (the vendor rotated it): paste the new key with its fingerprint in the same form; both are
required together. The step-up applies again, and `software_source.updated` records the new `fingerprint` and the
`old_fingerprint`. Devices write the new keyring and refresh the source at their next check-in. Until then apt on the
device refuses the source's signature if the vendor already signs with the new key: `NO_PUBKEY` where apt verifies
with gpgv, `Missing key` or `No good signature` where it verifies with sqv (Debian 13, Ubuntu 26.04), each with a
`W:` or `E:` line such as *The repository … is not signed*.

**Removing a source** asks you to type its name. A source that a catalog entry uses cannot be removed (409 `in_use`);
change or delete the entries first. Devices remove the source file and the keyring at their next check-in; installed
software stays.

## Catalog entries

An entry is one application: a name, a description, a category, an optional source (none means the distribution's own
repositories) and 1–20 package names, each for a distribution, a release and an architecture:

| Field | Value |
| --- | --- |
| `distribution` | the `ID` of the device's `/etc/os-release`, for example `ubuntu`, `debian` |
| `release` | the `VERSION_ID`, for example `24.04`, or `*` for every release |
| `architecture` | `amd64`, `arm64` or `*` |
| `package` | the Debian package name |

The device gets the most specific match: exact release and architecture, then exact release with `*`, then `*` with
the exact architecture, then `*`/`*`. A device whose distribution has no package name, or whose architecture is not
known yet (it then matches `*` only), is **not applicable** for the entry. The device's distribution and release
follow its check-ins: an agent that reports another os-release (for example after a release upgrade) updates the
device record (`device.os_release_changed`), and the device's bundle is compiled again with the new match. Agents that
do not report it keep the values of their enrollment.

**Protected packages** cannot be managed through the catalog, because any intent would move, pin or remove them
outside the signed A/B update path or break the login (400 `invalid_request`, one `failure` event):

| Tier | Packages | Refused |
| --- | --- | --- |
| Fully protected | `paddock-agent`, `paddock-supervisor`, `paddock-revoke`, `fleet-osquery`, every Himmelblau package (`himmelblau`, `himmelblau-*`, `*-himmelblau`) | no entry may name them |
| Removal protected | the agent's dependencies `cryptsetup`, `libpam-modules`, `sudo`, `tpm2-tools`, and `dracut` | `forbid` and `uninstall` |
| Conflicting | `initramfs-tools` (installing it removes `dracut`) | `required` and `hold` |

A package name that apt would read as a pattern selecting a protected package (for example `sud.` or `himmelblau.`) is
refused like the package itself. The agent passes a name to apt only when `apt-cache pkgnames` lists exactly that
name; any other name fails as `no_candidate`.

## Intents

An entry is assigned once per scope: a device group, or the whole organization (no group). On a device, several
assignments of the same package are merged; the strongest intent wins: `forbid` > `uninstall` > `required` > `hold`.

| Intent | Update rule | On the device |
| --- | --- | --- |
| `required` | `latest` (no version) | installed when missing and kept installed; the version moves only with the update runs (daily security run, regular run), never by the catalog |
| `required` | `pinned` (with a version) | installed, upgraded or downgraded to exactly that version and held there by a version pin (priority 1001) |
| `hold` | with or without a version | installs nothing; keeps the installed version (`apt-mark hold`) or pins the version |
| `uninstall` | — | removed (`apt-get remove`, configuration files stay) |
| `forbid` | — | removed and pinned to priority −1, so `apt-get install` of it fails |

When a `required` package is also held (by a `hold` or another `required pinned`), it is pinned at the lexicographically
smallest named version; two different versions are reported as a hold conflict, as for package holds. A versionless organization
package hold unpins a required pinned software package, while a versionless software hold does not. A `forbid` or
`uninstall` result supersedes a package hold of the same package for that device: the hold is left out of the device's
bundle so that the removal can run, and the device's apply status of the `software` resource names the superseded
hold.

Holds and version pins of the catalog are applied by the update management, together with the organization's package
holds (`/etc/apt/preferences.d/50paddock`, `apt-mark hold`, the unattended-upgrades blacklist); the regular update run
reports held packages as held back.

A device receives a source only while one of its packages is `required` from it: under `hold`, `uninstall` or
`forbid` alone the source file and keyring are removed from the device. A hold alone therefore drops the source: the
held package stays at its version, and the device sees no newer version from that source until a package of it is
required again.

## What the device does

At every apply and every drift check (5 minutes), the agent:

1. writes `/etc/apt/sources.list.d/paddock-<slug>.sources` (deb822, mode 0644, `Signed-By:
   /etc/apt/keyrings/paddock-<slug>.gpg`) and the keyring of every source it needs, after checking that the
   keyring's fingerprint equals the signed bundle's (otherwise nothing of that source is written and its packages
   fail with `fingerprint_mismatch`); it removes every other `paddock-*.sources` and `paddock-*.gpg`; it writes
   `/etc/apt/preferences.d/51paddock-software` with one stanza per forbidden package (`Pin: release *`, `Pin-Priority:
   -1`) or removes it when nothing is forbidden;
2. checks apt's configuration (`apt-get -s check`): a Paddock source that repeats a repository the device already has
   with another `Signed-By` keyring (for example a vendor's own list file) makes apt refuse its whole configuration,
   so Paddock's source file and keyring are removed again (never the device's own entry) and its packages fail with
   `conflicting_source`, naming the URI; the source is written and checked again about an hour later;
3. refreshes the package lists of a changed source on its own (`apt-get update` for that source only);
4. simulates every installation and removal first (`apt-get -s`) and refuses it when it would remove any package that
   is not itself a planned removal (`would_remove_dependents`), or when it would install, upgrade or remove a fully
   protected package or its summary does not add up (`protected_package_affected`); the real installation runs with
   `--no-remove`, so it never removes a package its simulation did not show;
5. installs missing `required` packages and moves `required pinned` packages to their version, in one `apt-get
   install`; a required package it installed before and finds removed is **reinstalled** (`device.software_reinstalled`
   with reason `locally_removed`); nothing stops a local administrator from removing it in the first place;
6. removes `uninstall` and `forbid` packages, **only while the server is reachable**: when the device's last successful
   check-in is older than 15 minutes, removals wait (`pending`, `deferred_offline`) and run at the first drift check
   after a check-in succeeds again. Installations do not wait;
7. records the packages it installed in `/var/lib/paddock/state/software-installed` and reports the status.

A package installed for several architectures counts as installed; a removal removes every installed architecture of
it. Another package operation holding the dpkg lock (an update, `unattended-upgrades`, a user's `apt`) makes the pass
wait up to 60 seconds and then end with `pending`, `dpkg_locked`; the next drift check retries, and no failure event is
recorded for it.

Every installation, reinstallation and removal is an audit event of the device (`device.software_installed`,
`device.software_reinstalled`, `device.software_removed`). A failure is recorded once as
`device.software_apply_failed` with the stage and reason, and not again while the assignment and the failure stay the
same.

The source files, keyrings and the forbid pin file are a **protected area**: an edited file is restored and a foreign
`paddock-*.sources` or `paddock-*.gpg` is removed at the next drift check, each with
`device.tamper_protected_file_changed` naming the file (RR-80). The Himmelblau source and keyring belong to the login
configuration and are never touched by the catalog.

**Installations pause directory logins.** On a device with directory logins the agent stops the login service
(`himmelblaud`) around every package installation, removal and update run it carries out, so that packages can create
their system accounts, and starts it again afterwards. Meanwhile new logins and screen unlocks of directory users
wait: seconds, for large packages minutes, at most 10 minutes per installation. Running sessions continue, and
signed-in directory users resolve by name and UID during the pause, so `ls -l` and `sudo` work as usual. Only a lookup
of a directory user who has never signed in on the device can answer "no such user" until the installation has
finished. Local accounts, the local administrator included, are not affected. Each pause is recorded as
`device.login_nss_shield`. A maintenance window therefore also decides when logins may wait. Details and the bounds:
[device-login.md](device-login.md), "Package installations pause directory logins" (residual risk RR-133).

**Packages a user installs with apt are not covered.** `sudo apt install` of a package that creates a system account
fails on such a device with *already exists, but is not a system user*. Stop the login service around it:

```sh
sudo systemctl stop himmelblaud.service
sudo apt install <package>          # after a failed attempt: sudo dpkg --configure -a
sudo systemctl start himmelblaud.service himmelblaud-tasks.service
```

The agent reports that stop as `device.tamper_service_stopped` and does not undo it.

## Waves

With configuration rollouts switched on (*Settings* → *Rollouts*, [configuration rollouts](configuration-rollouts.md)),
an **assignment change** is staged like a managed file: it reaches the devices wave by wave, a device outside the
current wave keeps the assignments it had, and a `failed` software status of the staged entry on a device of the wave
counts as the failed resource `software:<entry id>` toward the rollout's failure threshold. The rollout halts itself at
the threshold; the revert of its change set brings the previous assignments back and ends it. **Catalog entries and
package sources are never staged**: a new or changed entry reaches no device on its own, only its assignments do.

Deleting a catalog entry follows from that:

- An entry that still has assignments is not deleted (409 `in_use`, naming the first ten assignments by target, for
  example `device group "Laptops"`). This holds for `DELETE /api/v1/software-catalog/{id}` and for a declarative
  document that deletes the entry, even when the same document deletes its assignments. Remove the assignments first;
  that removal rolls out in waves like every assignment change.
- While that removal, or any other staged change of the entry's assignments, rolls out, the entry can neither be
  deleted nor renamed (409 `rollout_conflict`). Delete it once the rollout has completed; the deletion then changes
  nothing on any device. `software_catalog_entry.deleted` carries `assignment_count` (0 on success).
- Renaming an assigned entry through the API keeps its assignments and stages nothing.
- The revert of the open rollout is always possible: when its change set created an entry and its assignments, the
  revert removes the assignments and then the entry.

How waves advance when devices wait for their maintenance window is under *Maintenance windows*, *Staged rollouts and
windows*.

## Maintenance windows

A device group can have one maintenance window (`GET`, `PUT`, `DELETE /api/v1/device-groups/{id}/maintenance-window`,
or the `maintenance_window` field of the group's item in the declarative configuration). A window is a set of ISO
weekdays (`days`, 1 = Monday to 7 = Sunday), a start in minutes after local midnight (`start_minute`, 0 to 1439), a
duration (`duration_minutes`, 30 to 1440) and an IANA timezone (`timezone`, for example `Europe/Berlin`):

```json
{ "days": [1, 2, 3, 4, 5], "start_minute": 1320, "duration_minutes": 180, "timezone": "Europe/Berlin" }
```

is every weekday night from 22:00 to 01:00 Berlin time. A window may run past midnight into the next day; the next day
need not be one of its days. The duration is elapsed time: on the night the clocks change, a window ends an hour
earlier or later on the wall clock, a start that falls into the skipped hour moves forward by that hour, so a window
is never skipped, and a start in the repeated hour opens once, at its second occurrence. A window of 1440 minutes
from 00:00 is therefore not "always": on the night the clocks go back it ends at 23:00, and the device waits one hour
until the next day's window opens at midnight. A group that should apply at any time has no window. Setting and removing a window
needs `org_admin` or `org_operator` and is audited (`device_group.maintenance_window_changed`,
`device_group.maintenance_window_removed`, with every field).

**A device in several groups** has the union of their windows: it applies its software whenever one of them is
open. Only groups with a window count (Q17, confirmed by architect decision A10-16): a device in a group with a window
and in another group without one has the first group's window and stays restricted to it. A device none of whose
groups has a window applies at any time.

**Outside every window** the device still writes the source files, keyrings and the forbid pin file, but it neither
installs, reinstalls, moves to a pinned version nor removes the packages of its policy, APT and Flatpak alike. They
report `pending`, `outside_window`, and the first drift check inside a window runs them (the check runs every 5
minutes, so a 30-minute window always gets several). The drift checks keep their own rhythm and do not wait for a
window to open: a device whose `drift_interval_s` in `/etc/paddock/agent.yml` is raised to the length of its shortest
window or more can miss that window on some days, so keep the interval well below the shortest window. Removals inside the window still wait for a server connection
(`deferred_offline`). A user's own self-service installs and removals never wait. Removing a window lets the devices
apply at their next drift check.

**Urgent assignments.** An assignment with `urgent: true` is applied outside the windows too, for example a `forbid`
of a package with a known vulnerability. Setting `urgent` (on creation or on an update, where an absent `urgent` is
`false`) needs a reason of 2 to 500 characters and a step-up within the last 5 minutes; API tokens and MCP sessions
cannot set it (403 `step_up_required`). The audit event carries `urgent` and the reason. The declarative configuration
does not carry the flag: an apply that changes only the reason keeps it, and an apply that changes the intent, the
update rule or the version clears it, because an apply cannot carry a step-up. Set it again through the API after
such an apply. `urgent` is about the window only; it does not skip a staged rollout's waves (that is the `urgent`
query parameter of the configuration writes).

**Staged rollouts and windows.** In a staged rollout, a device whose staged entry waits for its window counts as
pending, never as failed, until it has run the change; the rollout's device list shows it with `waiting_for_window`.
A wave advances only when both hold (architect decision A10-16): `min_wave_minutes` have passed since the first device
of the wave applied, and the share of the wave's devices that applied reaches the rollout's
`wave_success_threshold_percent` (default 90) or none of them still waits for its window. A change made during the day
for devices with a nightly window therefore stays in its first wave until the night; the next wave starts once the
first one's devices have applied and the minimum duration has passed. A wave without a new apply for `stall_warning_hours` (default 24) gets one `config_rollout.stalled` audit
event; it forces nothing and nothing is installed outside a window because of it. To go faster, advance the wave by
hand or make the assignment `urgent`. Details: [configuration rollouts](configuration-rollouts.md), section 5.

**Timezones.** The api accepts only timezones it knows. A device without the zone in its tzdata evaluates the window
in UTC and names the zone in the software resource's status message (`window_timezone_unknown: <zone> (evaluated in
UTC)`); the agent's log has it once per bundle. Install the `tzdata` package on the device to fix it. An agent before
0.1.0-alpha.10 does not know windows and applies at once.

## Approvals

A catalog entry can require an administrator's approval (`approval: required` on the entry, or in the declarative
`software_catalog` section; absent means `none`). It matters for `available` assignments: the user of a device asks
for the application, and an organization administrator decides.

1. The user asks on the device. The device reports the request (`device.software_requested`, with the user name and
   the entry). The server opens a request when an available assignment of the entry offers it to that device and user
   (the organization, a device group of the device, or a user or user group the device's owner belongs to). It opens
   none for a repeat while one is open, for a user who already holds an approval of it on the device, or within 24
   hours of a denial. An opened request records `software_request.opened` (a notification code for destinations with
   `all` or a custom list; not in the security preset) and shows in the attention list as `software_requests_open`.
2. The administrator decides in the portal (*Software requests*) or with `POST
   /api/v1/software-requests/{id}/approve` (an optional reason) or `…/deny` (a reason the user sees, 1 to 500
   characters). Deciding needs `org_admin` and no step-up of its own: trusting the entry's source needed one.
   Operators and auditors read the requests (`GET /api/v1/software-requests`, filters `state`, `catalog_entry_id`,
   `device_id`, search by user name). A request that is no longer open, whose 30 days have run out, or whose entry
   changed its approval since cannot be decided (409 `invalid_state`).
3. An approval lets that user install the application on that device; it takes effect with the device's next bundle,
   after the rollout's overlay; like any self-service install it does not wait for a maintenance window. A `forbid`
   of the same package still wins. An approval is no configuration change: it stages nothing and has no change set.
4. The worker's request round (every 10 minutes) expires an open request after 30 days (`validity_ended`), and open
   and approved requests whose entry no longer requires approval (`approval_removed`) or that no available assignment
   offers any longer (`assignment_removed`), each with `software_request.expired`.

**Agents.** An approval-required package reaches no agent before the release with the request flow on the device
(PDK-811); until then the users of such an entry see nothing of it, so nobody installs it without an approval. The
user's justification text is not stored yet; it follows with the request flow on the device (see
[privacy](../compliance/privacy.md)).

## States and reasons

The device reports one state per assigned application with its check-in when the status changed, and at least once a
day; the portal shows when it was reported (RR-82).

| State | Meaning |
| --- | --- |
| `installed` | a `required` package is installed (with its version) |
| `held` | a `hold` package is installed and held |
| `absent` | an `uninstall`, `forbid` or `hold` package is not installed |
| `pending` | the operation has not happened yet; the reason says why |
| `failed` | the operation was refused or failed; the reason and the error say why |
| `not_applicable` | the entry has no package for the device's distribution, release and architecture (derived by the server) |
| `unknown` | assigned and applicable, but the device has not reported it yet (derived by the server) |

| Reason | State | Meaning and what to do |
| --- | --- | --- |
| `not_yet_applied` | pending | the device has the assignment but has not run the operation yet; wait for the next drift check |
| `dpkg_locked` | pending | another package operation holds the dpkg lock; the device retries at the next drift check |
| `deferred_offline` | pending | a removal waits because the device has had no check-in for 15 minutes; it runs after the next successful check-in |
| `outside_window` | pending | the device is outside the maintenance windows of its groups; the operation runs at the first drift check inside one, or at once when the assignment is made `urgent` |
| `fingerprint_mismatch` | failed | the keyring in the bundle does not have the source's fingerprint; nothing of the source was written. Check the source's key |
| `source_unreachable` | failed | the source's `apt-get update` failed (DNS, TLS, HTTP, signature); the error has apt's message. See troubleshooting |
| `conflicting_source` | failed | the device already has the repository with another keyring; remove one of the two entries |
| `no_candidate` | failed | the package or the version is not available from the device's sources (after one full `apt-get update` and a retry), or the name is not exactly a package apt knows |
| `would_remove_dependents` | failed | the operation would remove other packages; nothing changed. It stays refused until the assignment or the device changes (RR-81) |
| `protected_package_affected` | failed | the operation would touch a fully protected package, or apt's simulation could not be read; nothing changed |
| `apt_failed` | failed | apt or dpkg failed otherwise; the error has the last line of its output |

When a device manages more applications than fit into its check-in, it leaves out applied items first (never a failed
one) and the device's managed software is marked as truncated.

## Packages stored in Paddock

An organization without an APT repository of its own uploads its `.deb` packages to Paddock (ADR 0050). Paddock keeps
one repository per organization at `https://bundles.<domain>/apt/<organization slug>/` (suite `paddock`, component
`main`); its system source (kind `paddock`, slug `paddock`) is maintained by Paddock and cannot be changed or deleted
through the API or the declarative configuration, which leaves it out of the export and names it by its slug in
catalog entries.

1. **The repository.** The first `GET /api/v1/software-repository` (any role) or the first upload attempt creates the
   repository with a random read credential and queues the generation of its signing key. Until the key exists the
   state is `disabled`: `source` and `fingerprint` are `null`, an upload is refused with 409 `repository_not_ready`
   (recorded as `denied`) and the repository publishes nothing (404).
2. **Uploading.** `POST /api/v1/software-packages` (multipart form field `file`, at most 256 MiB; optional `package`,
   `version`, `architecture`, which must equal the package's control file), `org_admin` with a step-up (API tokens
   never). **Uploading a package is root-equivalent on every device it is assigned to:** its maintainer scripts run as
   root, and Paddock scans nothing inside it (RR-114). The api reads only the archive structure and the control file
   and never runs anything from the package. It accepts an `ar` archive of exactly `debian-binary` (`2.0`),
   `control.tar`, `control.tar.gz` or `control.tar.zst` and `data.tar.*`, with a control file of one paragraph whose
   `Package`, `Version` and `Architecture` (`amd64`, `arm64` or `all`) pass the Debian rules and which sets none of
   the index fields `Filename`, `Size`, `MD5sum`, `SHA1`, `SHA256`, `SHA512` or `Description-md5`. A control archive in
   xz (`dpkg-deb -Zxz`) or any other compression is refused with 415 `unsupported_compression`: build with `dpkg-deb
   -Zgzip` or `-Zzstd` (the default of Ubuntu 21.10 and later). The same name, version and architecture again is 409
   `already_exists`. The audit event `software_package.uploaded` records the package, version, architecture, size and
   the SHA-256 of the file. The file is stored as `pool/main/<p>/<package>/<package>_<version>_<arch>.deb` of the
   repository (the version without its epoch) and the repository is rebuilt in the background.
3. **Assigning.** A catalog entry whose source is the `paddock` source names the uploaded package names; it is
   assigned like any other entry.
4. **Deleting.** `DELETE /api/v1/software-packages/{id}` (`org_admin`, step-up; `software_package.deleted`). While a
   catalog entry of the `paddock` source names the package, every stored version of it is kept (409 `in_use`): an
   assignment may pin any of them. Change or delete the entry first.
5. **The read credential.** apt reads the repository with HTTP basic authentication, user `paddock`. Every device whose
   bundle names the `paddock` source receives the credential with its bundle and keeps it in
   `/etc/apt/auth.conf.d/paddock-repo.conf` (mode 0600, root). That file is protected: a change, a looser mode or its
   removal is reverted at the next drift pass and reported as `tamper.protected_file_changed`; a bundle without the
   repository removes it, and so does the removal of Paddock. The secret never appears in an event, the log or the
   health report. `POST /api/v1/software-repository/rotate-credential` (`org_admin`, step-up;
   `software_repository.credential_rotated`) replaces it and shows the new secret once; every device's bundle changes,
   and the previous secret stays valid for 24 hours (`previous_credential_valid_until`). A device that stays offline
   longer fails `apt-get update` for the repository with 401 (`source_unreachable`) until its next check-in. The
   credential is one per organization, not per device (RR-115).
6. **Build and signing key.** The worker builds the repository every minute when it is due (PDK-813): after an upload
   or a delete, a key rotation, and after a failed build. It writes `dists/paddock/main/binary-{amd64,arm64}/Packages`
   and `Packages.gz` (a package of architecture `all` is listed for both), the same lists again below
   `by-hash/SHA256/<sha256>` of their directory, `Release` with their SHA-256 and `Acquire-By-Hash: yes`, the detached
   `Release.gpg` and the clearsigned `InRelease`, which it writes last. apt fetches the lists by their hash, so a build
   that fails halfway leaves the previous build readable. Older `by-hash` files stay in the bucket. The first build generates the organization's signing key, an Ed25519 OpenPGP key `Paddock <slug>`; its
   private key exists in clear only in the worker while it signs, is stored encrypted with the Transit key
   `software-repo-wrap`, which no other role can use, and never appears in the log. The first build also creates the
   system source with the public key, so `GET /api/v1/software-repository` shows `fingerprint` and `source` and uploads
   are accepted from then on. Every published build is recorded as `software_repository.built` (generation,
   fingerprint, package count). A failed build (OpenBao sealed, the object store unreachable) keeps the previous build
   published; it is shown as `state: failed` with `last_error`, recorded once per distinct error as
   `software_repository.build_failed`, and retried every minute. An error of OpenBao or the object store is recorded as
   its step and class (for example `upload InRelease: AccessDenied, HTTP 403` or `network error`); the full message,
   with the request ID, is in the worker's log (`software repository round failed`).
7. **Rotating the signing key.** `POST /api/v1/software-repository/rotate-key` (`org_admin`, step-up;
   `software_repository.key_rotated` with the replaced fingerprint) answers 202 with `key_rotation_requested_at` set.
   Within a minute the worker generates the new key, signs the repository with it and only then gives the system
   source the new key; every device receives it with its next bundle, writes the keyring before it updates, and finds
   `InRelease` signed with the key it has. For 30 days the worker signs `InRelease` and `Release.gpg` with the previous
   key (`previous_fingerprint`) as well, so a device that has not received the new key yet, also one that is offline
   meanwhile, keeps updating from the repository; 30 days after the new key was first published the worker drops the
   previous key and rebuilds with the new key alone. A build that fails does not start the 30 days. A device that has
   not checked in for 30 days after a rotation fails `apt-get update` for this repository until its next check-in
   brings the new key. Rotating again while the previous rotation has not been published yet (its build failed and
   `state` is `failed`) is safe: the unpublished key is replaced and the key the devices have keeps signing. A second
   rotation after the first was published ends the overlap of the first: only the key it replaces keeps signing, so a
   device that had not fetched the first new key before the second rotation fails `apt-get update` for this repository
   until its next check-in brings the current key. Leave a device poll interval between two rotations unless the key
   is compromised.
8. **Serving.** On the bundles host, `GET /apt/<slug>/<path>` answers 401 with a `Basic` challenge without the
   credential, 302 to a presigned download URL (valid for 10 minutes) with it, and 404 for a path the repository does
   not have. At most `PADDOCK_RATELIMIT_BUNDLES_APT` requests a minute (default 60) per client address are answered;
   more get 429. Many devices behind one address can exceed it during a package roll-out: raise the limit then.

To read the repository by hand: `curl -u paddock:<secret> -I https://bundles.<domain>/apt/<slug>/pool/main/…` answers
302. To check the signature as apt does: download `dists/paddock/InRelease` with `curl -L -u paddock:<secret>`, save
the system source's `signing_key` (`GET /api/v1/software-sources/{id}`) as `paddock.asc`, and run
`gpg --dearmor <paddock.asc >paddock.gpg && gpgv --keyring ./paddock.gpg InRelease`.

## Self-service app

*Paddock Self-Service* is the desktop app through which users install, update and remove the applications offered to
them with the intent `available`, and see why a required application is on their device (ADR 0049). Paddock does not
install it on its own: an organization offers it like any other application, as a required catalog entry.

- **Package.** `make deb` builds `bin/selfservice/paddock-self-service_<version>_all.deb` next to the agent packages
  (`make selfservice-deb VERSION=<version>` builds it alone). Releases do not publish it yet; until they do, the
  operator builds it from the release's source tag.
- **Requirements.** Ubuntu 24.04 or 26.04 with a graphical session. The package needs only Ubuntu's own `python3`,
  `python3-gi`, `gir1.2-gtk-4.0` and `gir1.2-adw-1`; apt installs them from the distribution, nothing comes from PyPI.
  The package is architecture independent and the agent update never delivers or changes it.
- **Offering it as a required entry:**
  1. Build the package of the release (above).
  2. Upload it to the organization's repository (*Packages stored in Paddock*; architecture `all` is accepted).
  3. Create a catalog entry *Paddock Self-Service* with the source `paddock` and the package `paddock-self-service`.
  4. Assign the entry with the intent `required` to every device group (or the whole organization) whose users get
     self-service. With each release, upload the new version; the assignment's update rule decides when devices take it.
- **What the user sees.** *Apps* lists the applications the device offers to the user, each with its state and
  *Install*, *Update* or *Remove*; every application the organization manages (any intent but `available`) shows
  *Managed by your organization* and has no buttons. *Details* names the version, the source, whether it is installed
  for all users or only the user, and the reason of a failure. *Activity* follows the operations the user started in
  this session (queued with the position, running, done, failed or refused with the reason). On the first start the app
  shows the transparency notice once per notice text: the organization's text when one is set, otherwise the default
  text. While the agent does not answer the app shows *Paddock is not running* and tries again every 10 seconds; before
  the first policy it shows *Waiting for your organization's policy*. The texts are in English or German, following the
  session's language.
- **What it does not do.** The app runs as the logged-in user and refuses to start as root. It talks only to the agent's
  socket `/run/paddock/selfservice.sock`, makes no network connection and holds no credential; the agent identifies the
  user by the socket's peer credentials. It shows everything it receives as plain text, never as markup, and accepts
  icons only as PNG of at most 64 KiB. The only file it writes is `~/.config/paddock-self-service/state.json` (which
  notice text the user has acknowledged).

An installation or removal a user starts in the app pauses new directory logins and screen unlocks on that device
until it has finished ("Installations pause directory logins" under [What the device does](#what-the-device-does));
the user's own session continues.

## Uninstalling Paddock

The removal of Paddock from a device (both modes, `leave` and `reset`, `docs/operations/uninstall.md`) removes every
`/etc/apt/sources.list.d/paddock-*.sources`, every `/etc/apt/keyrings/paddock-*.gpg` and
`/etc/apt/preferences.d/51paddock-software` and `/etc/apt/auth.conf.d/paddock-repo.conf`, then refreshes the package
lists. **Installed applications stay
installed.** The summary names the step `software_sources`.

## Troubleshooting

On the device:

| Look at | What it tells |
| --- | --- |
| `cat /etc/apt/sources.list.d/paddock-*.sources` | the sources Paddock wrote, each with `Signed-By: /etc/apt/keyrings/paddock-<slug>.gpg` |
| `gpg --show-keys /etc/apt/keyrings/paddock-<slug>.gpg` | the fingerprint of the keyring, to compare with the source's |
| `apt-cache policy <package>` | the versions, the sources they come from and the pins: `1001` for a pinned version, `-1` for a forbidden package |
| `apt-mark showhold` | the versionless holds |
| `cat /etc/apt/preferences.d/51paddock-software` | the forbidden packages |
| `sudo apt-get update -o Dir::Etc::sourcelist=sources.list.d/paddock-<slug>.sources -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0` | the source alone, as the agent refreshes it: TLS, DNS and signature errors (`NO_PUBKEY` with gpgv; `Missing key` or `No good signature` with sqv) |
| the agent's health socket (`/run/paddock/agent.sock`, `GET /health`, field `software`) | the current state and reason of every application, before the next check-in |
| `journalctl -u paddock-supervisor` | the agent's log, including every file the software reconciler removed |

| Symptom | Cause and fix |
| --- | --- |
| `failed`, `source_unreachable`, error with `NO_PUBKEY`, `Missing key` or `No good signature` | the vendor signs with a new key: verify the new fingerprint out of band and change the source's key |
| `failed`, `source_unreachable` for the `paddock` source with `401` | the device's credential is older than the overlap of a rotation, or `/etc/apt/auth.conf.d/paddock-repo.conf` is missing; it is restored with the device's next bundle or drift pass |
| `failed`, `source_unreachable`, certificate error | the device does not trust the repository's TLS certificate; fix the certificate or the device's trust store |
| `failed`, `no_candidate` for a pinned version | the repository no longer offers the version (RR-83); pin another version or switch to `latest` |
| `failed`, `would_remove_dependents` | another installed package depends on the package (removal) or conflicts with it (install); resolve it on the device or change the assignment |
| `pending`, `deferred_offline` for a long time | the device cannot reach the server; check its network and the last contact on the device page |
| `pending`, `dpkg_locked` for a long time | a package operation hangs on the device (`ps -C apt,apt-get,dpkg,unattended-upgr`); `sudo dpkg --configure -a` after it ended |
| `not_applicable` although the package exists | the entry has no package name for the device's distribution, release or architecture; add one |
| `sudo apt install` of a package fails with *already exists, but is not a system user* (or useradd exit 9) | its maintainer script creates a system account and Himmelblau's NSS module answered for the name (PDK-983); the agent holds `himmelblaud` stopped around its own installations, not around yours: stop it around the installation as described in [device-login.md](device-login.md#package-installations-pause-directory-logins) |
| A required application keeps being reinstalled | a user or a tool removes it again and again: each removal is a `device.software_reinstalled` event (RR-80) |

## Residual risks

RR-77 (a source key is root-equivalent), RR-78 (maintainer scripts run as root), RR-79 (reserved for Flathub, M13b),
RR-80 (local root bypasses pins and holds), RR-81 (refused operations stay refused), RR-82 (status can lag), RR-83
(pinned versions vanish) and RR-118 (maintenance windows defer security-relevant removals), in
[residual-risks.md](../compliance/residual-risks.md#software-catalog-m13a). RR-133 (packages that create a system
user: manual installations fail, agent installations pause directory logins), in
[residual-risks.md](../compliance/residual-risks.md#login-and-identity).

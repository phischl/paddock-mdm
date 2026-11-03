# Software catalog: package sources, applications and their enforcement

An organization lists the applications its devices install, keep, hold or block in the **software catalog**, and the
third-party APT repositories they come from as **package sources**. Each application (a catalog entry) is assigned to
a device group or to the whole organization with an **intent**. The agent enforces the assignments on every device
and reports what it did per application (ADR 0042, plan M13a). This page covers adding a source, writing entries,
what each intent does on the device, the states and reasons the device reports, and troubleshooting.

In the portal: *Package sources* (organization administrators), *Software catalog* with an entry's assignments and
devices, and the *Managed software* tab of a device. The admin API: `/api/v1/software-sources`,
`/api/v1/software-catalog`, `/api/v1/software-catalog/{id}/devices`, `/api/v1/software-assignments` and
`/api/v1/devices/{id}/managed-software`.

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
device reports `NO_PUBKEY` for the source if the vendor already signs with the new key.

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
bundle so that the removal can run, and the device's software status names the superseded hold.

Holds and version pins of the catalog are applied by the update management, together with the organization's package
holds (`/etc/apt/preferences.d/50paddock`, `apt-mark hold`, the unattended-upgrades blacklist); the regular update run
reports held packages as held back.

A device receives a source only while one of its packages is `required` from it: under `hold`, `uninstall` or
`forbid` alone the source file and keyring are removed from the device.

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
| `fingerprint_mismatch` | failed | the keyring in the bundle does not have the source's fingerprint; nothing of the source was written. Check the source's key |
| `source_unreachable` | failed | the source's `apt-get update` failed (DNS, TLS, HTTP, signature); the error has apt's message. See troubleshooting |
| `conflicting_source` | failed | the device already has the repository with another keyring; remove one of the two entries |
| `no_candidate` | failed | the package or the version is not available from the device's sources (after one full `apt-get update` and a retry), or the name is not exactly a package apt knows |
| `would_remove_dependents` | failed | the operation would remove other packages; nothing changed. It stays refused until the assignment or the device changes (RR-81) |
| `protected_package_affected` | failed | the operation would touch a fully protected package, or apt's simulation could not be read; nothing changed |
| `apt_failed` | failed | apt or dpkg failed otherwise; the error has the last line of its output |

When a device manages more applications than fit into its check-in, it leaves out applied items first (never a failed
one) and the device's managed software is marked as truncated.

## Uninstalling Paddock

The removal of Paddock from a device (both modes, `leave` and `reset`, `docs/operations/uninstall.md`) removes every
`/etc/apt/sources.list.d/paddock-*.sources`, every `/etc/apt/keyrings/paddock-*.gpg` and
`/etc/apt/preferences.d/51paddock-software`, then refreshes the package lists. **Installed applications stay
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
| `sudo apt-get update -o Dir::Etc::sourcelist=sources.list.d/paddock-<slug>.sources -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0` | the source alone, as the agent refreshes it: TLS, DNS and signature errors (`NO_PUBKEY`) |
| the agent's health socket (`/run/paddock/agent.sock`, `GET /health`, field `software`) | the current state and reason of every application, before the next check-in |
| `journalctl -u paddock-supervisor` | the agent's log, including every file the software reconciler removed |

| Symptom | Cause and fix |
| --- | --- |
| `failed`, `source_unreachable`, error with `NO_PUBKEY` | the vendor signs with a new key: verify the new fingerprint out of band and change the source's key |
| `failed`, `source_unreachable`, certificate error | the device does not trust the repository's TLS certificate; fix the certificate or the device's trust store |
| `failed`, `no_candidate` for a pinned version | the repository no longer offers the version (RR-83); pin another version or switch to `latest` |
| `failed`, `would_remove_dependents` | another installed package depends on the package (removal) or conflicts with it (install); resolve it on the device or change the assignment |
| `pending`, `deferred_offline` for a long time | the device cannot reach the server; check its network and the last contact on the device page |
| `pending`, `dpkg_locked` for a long time | a package operation hangs on the device (`ps -C apt,apt-get,dpkg,unattended-upgr`); `sudo dpkg --configure -a` after it ended |
| `not_applicable` although the package exists | the entry has no package name for the device's distribution, release or architecture; add one |
| A required application keeps being reinstalled | a user or a tool removes it again and again: each removal is a `device.software_reinstalled` event (RR-80) |

## Residual risks

RR-77 (a source key is root-equivalent), RR-78 (maintainer scripts run as root), RR-79 (reserved for Flathub, M13b),
RR-80 (local root bypasses pins and holds), RR-81 (refused operations stay refused), RR-82 (status can lag) and RR-83
(pinned versions vanish), in [residual-risks.md](../compliance/residual-risks.md#software-catalog-m13a).

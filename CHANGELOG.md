# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Entries of merged changes that are not released yet are in `changelog.d/`.

## [0.1.0-alpha.10] - 2026-11-13

An installation of 0.1.0-alpha.9 upgrades with `./paddock upgrade <old dir>` and goes back with
`./paddock rollback <old dir>` (ADR 0047; `docs/operations/upgrade.md`, "0.1.0-alpha.10, from 0.1.0-alpha.9").
Before the upgrade, remove an explicit `PADDOCK_TRUSTED_PROXY_CIDRS` or `PADDOCK_INTERNAL_CIDRS` from `.env`
(`./paddock upgrade-check` names them; a lab sets them again with `PADDOCK_EDGE_TRUSTED_PROXIES`). Run the upgrade
with `BAO_TOKEN` set, so that it creates the new Transit keys of the organization repositories and the changed
policies, then `./paddock bootstrap buckets` and `./paddock up` once more. The containers move to networks by trust
zone and Valkey gets one user per role; `./paddock up` creates the new secrets. No stateful image changes; Fleet
moves to v4.94.1 and Caddy to 2.11.9. Upgrade the server first, then roll out this release's agent; agents of
0.1.0-alpha.8 and 0.1.0-alpha.9 keep working in the meantime. Installations of 0.1.0-alpha.8 upgrade to 0.1.0-alpha.9 first.

Self-service (plan M13b, ADR 0049): the desktop app *Paddock Self-Service* lets users install, update and remove the
applications their organization offers them, including Flatpak applications and applications assigned to users and
groups. Software waves, approvals and an own repository (plan M13c): software changes roll out in waves and maintenance
windows, users request applications that need an administrator's approval, and organizations without an APT
repository upload their packages to a repository that Paddock builds and signs for them (ADR 0050). Hardening (plan M12h, ADR
0051): networks by trust zone, Valkey users per role, request rate limits, edge body limits and security headers, and
every container with only the capabilities it needs and a memory limit.

Agents: the agent changes in this release (self-service, approvals and withdrawals, maintenance windows, Flatpak); the
supervisor does not. Every release now also publishes the self-service app as the signed package
`paddock-self-service_<version>_all.deb`, which the platform's agent releases carry and the GitHub import requires from
this release on. Every package of an agent release is bound to its release by its signature's trusted comment
`paddock-agent version=<release version> arch=<arch>`; this now includes fleetd and `paddock-revoke`. The holders of
the revocation release key therefore sign `paddock-revoke` offline with
`-t "paddock-agent version=<release version> arch=<arch>"`, and fleetd is signed with the release's comment, not the
fleetd version's (`docs/operations/agent-releases.md`, *Signing in the release workflow*). On devices with directory
logins, the agent pauses the login service while it installs or removes packages, so that packages which create a
system account install: new directory logins and screen unlocks wait during an installation, for at most 10 minutes,
while running sessions continue (residual risk RR-133, `docs/operations/device-login.md`). `paddock-revoke` changes
(it signs out only real user entries); revocation (Lock, Destroy, dead man's switch) stays disabled behind `PADDOCK_REVOCATION_ENABLED`.

Schema: migrations 00113–00125 (control-plane database; new tables, columns, constraints, policies and grants, 00115 fills its new column); audit unchanged.
Upgrade: from 0.1.0-alpha.9: steps: remove an explicit PADDOCK_TRUSTED_PROXY_CIDRS or PADDOCK_INTERNAL_CIDRS from .env (a lab sets them again), BAO_TOKEN for ./paddock upgrade, then ./paddock bootstrap buckets and ./paddock up
Agents: supports 0.1.0-alpha.8, 0.1.0-alpha.9, 0.1.0-alpha.10

### Added

- Software catalog: applications can be assigned to individual users and user groups, offered with the new intent
  `available` for users to install themselves, and come from Flatpak remotes (a new source kind that needs a step-up
  like every source). The admin API lists the applications that target a user directly or through a group. Devices
  receive these assignments with a later update of this release.
- Software: device policies now carry assignments to users and user groups. They reach the devices their users own;
  an application offered with `available` names who may install it — everyone for organization and device-group
  assignments, otherwise the owning users (at most 200 per application; a larger audience is cut and logged as
  `audience_truncated`). Changing a device's owners updates its policy. Flatpak applications that are required or
  available are delivered with their remote, and devices that need them also get the `flatpak` package; a Flatpak
  forbid or uninstall never installs Flatpak. Agents older than 0.1.0-alpha.10 receive neither offered applications
  nor Flatpak, and keep enforcing their required, forbidden and removed packages; a device whose agent is upgraded
  past that version, or rolled back below it, gets an updated policy automatically.
- Software: the agent now manages Flatpak applications. It adds an organization's Flatpak source as a system remote
  named `paddock-<source>` with the source's pinned key (a key that does not match its fingerprint is never written),
  installs required applications for the whole system or, for user-scope applications, in the session of each
  targeted user who is signed in (a targeted user without a session gets them at the next sign-in; they are never
  installed system-wide instead, and other users of the device get nothing), uninstalls forbidden and removed
  applications and blocks forbidden and held ones from installing and updating. A user-scope application assigned to
  the whole device acts system-wide: forbidding or removing it leaves copies users installed for themselves alone.
  Paddock's remotes are protected: a changed, disabled or unverified Paddock remote is restored and a
  `paddock-*` remote Paddock did not add is removed, both reported as tampering; other remotes are not touched.
  Without the `flatpak` package, required applications report `flatpak_missing`. Removing Paddock from a device
  removes its system remotes and keeps the installed applications.
- Software: the agent serves the self-service channel on `/run/paddock/selfservice.sock` for the coming desktop app.
  Every local user can connect; the agent identifies the caller by the operating system's peer credentials, never by
  anything the caller sends. A user sees the applications offered to everyone and to them by name, plus the
  organization's managed applications as read-only, and nothing offered only to other users. A user may install an
  offered application and remove or update one that self-service installed; managed applications cannot be changed.
  Operations run one at a time through the same safety checks as the policy (an installation that would remove
  another package is refused), at most five queued per user and 60 requests a minute; each one is reported to the
  server as `software.self_service` with the user name and told to the user in their desktop session (at most five
  notices an hour). An application the user removed by hand is not reinstalled, and policy always wins over a
  self-service installation. Until a policy has been applied the channel answers `no_bundle`.
- Software: the desktop app *Paddock Self-Service* lists the applications the organization offers the user, installs,
  updates and removes them with one click, follows each operation to its end and says why a managed application cannot
  be changed. It shows the organization's transparency notice once, tells the user when Paddock is not running, and
  speaks English and German. The app runs as the user, talks only to the agent on the device and holds no credential.
  `make deb` builds it as `paddock-self-service_<version>_all.deb`; it needs only Ubuntu's own packages (24.04 and
  26.04). Organizations offer it as a required catalog entry (`docs/operations/software.md`, *Self-service app*).
- Software: every self-service operation a device reports is recorded in the audit log as
  `device.software_self_service`, with the user who asked for it, the application, the action, the scope, the outcome,
  the reason and the version. A succeeded operation is recorded as a success; a failed or refused one as a failure with
  the error code `self_service_failed` or `self_service_refused`.
- Software: the software status keeps one row per application and scope, so an application installed for the system
  and for a user of the device shows both. The device's managed software and the devices of a catalog entry show the
  scope and filter by it (`scope=system|user`), and applications offered for self-service (`available`) appear in both
  lists once the device reports them.
- Portal, software: an assignment can now target every device, a device group, a single user or a user group, with
  searchable pickers for users and groups, and the intent *Available* offers an application for self-service. Package
  sources can be Flatpak remotes (one https URL and the remote's key), and catalog entries of a Flatpak source name
  Flatpak application IDs with their scope (system or user). The devices of a catalog entry and a device's managed
  software show the scope of each row and filter by it. A catalog entry and a device's managed software list the
  compile warnings of their devices (too many users offered or targeted, Flatpak forbidden on the device), localized.
  A user's page lists the software assigned to them directly or through a user group.
- Software: software sources, the software catalog and software assignments are part of the declarative
  configuration (`GET`/`PUT /api/v1/config`, `paddockctl apply -f`). A change to software sources needs an
  administrator with a fresh step-up, so an API token's apply that changes them is refused and the dry run names the
  section under `requires_step_up`. Every change to software is recorded as a change set and can be reverted. With
  staged rollouts enabled, a change to software assignments rolls out in waves and stops itself when devices of the
  wave report the application as failed; catalog entries and sources still apply at once.
- Software: a device group can have a maintenance window (weekdays, start time, duration and timezone; through the
  API or the device group's item in the declarative configuration). Its devices install and remove the software of
  their policy only inside the union of the windows of their groups and report `pending`, `outside_window` until
  then; a user's own self-service installs never wait. An assignment marked `urgent`, with a reason and a fresh
  step-up, is applied outside the windows too, for urgent security fixes.
- Software: a catalog entry can require approval. Users of an available application then ask for it on their device,
  and an organization administrator approves or denies the request with a reason under
  `/api/v1/software-requests`. An approval reaches the device with its next bundle. A request with no decision expires
  after 30 days. A device can only request an application that is offered to it and to the requesting user; open and
  approved requests expire once the entry no longer requires approval, its approval setting changes, or no available
  assignment offers it to that device and user any longer. An application that requires approval reaches no agent
  before the agent release with the approval flow, so no device can install it without approval. Open requests appear
  in the attention list as `software_requests_open`. A new request emits the notification code
  `software_request.opened`; it is not in the security preset. The declarative `software_catalog` section carries
  `approval`. The user's request and the approval flow on the device follow with the agent and the portal.
- Self-service: for an application that requires approval, the desktop app shows *Request* instead of *Install*. The
  user can add an optional justification of up to 500 characters and withdraw a pending request. The app shows the
  request as *Requested* until a decision arrives with the device's next bundle: an approved user can then install
  the application, and a denied user sees *Denied* with the administrator's reason, shown only to that user. A
  request without a decision ends on the device after 30 days, as on the server. A user can send at most 10 requests
  an hour. Approval-required applications reach devices only once the server enables the approval gate for this
  agent release. The server stores the justification and delivers denials in a follow-up change.
- Software: organizations without an APT repository of their own upload their `.deb` packages to Paddock
  (`POST /api/v1/software-packages`, `org_admin` with a step-up, at most 256 MiB, audited with the file's SHA-256 as
  `software_package.uploaded`) and assign them like any other package through the system source `paddock`. The api
  checks the archive and the control file and never runs anything from the package; a control archive in xz is refused
  with 415 `unsupported_compression` (build with `dpkg-deb -Zgzip` or `-Zzstd`). Each organization has one repository
  at `https://bundles.<domain>/apt/<slug>/`, read by apt with a per-organization credential (HTTP basic
  authentication) that the devices receive in their bundles and keep in the protected file
  `/etc/apt/auth.conf.d/paddock-repo.conf`; `POST /api/v1/software-repository/rotate-credential` replaces it with a
  24-hour overlap. Uploads wait until the repository's signing key exists (409 `repository_not_ready`). Upgrade: run
  `./paddock upgrade` with `BAO_TOKEN` set (the new Transit key `software-repo-credential` and its policies), then
  `./paddock bootstrap buckets` (the api's new bundles credential `rustfs_bundles_api_*`, which `./paddock secrets`
  creates) and `./paddock up`. The edge accepts package uploads of up to 256.5 MiB (multipart framing included).
- Software: the worker now builds and signs each organization's Paddock repository within a minute of an upload or a
  delete. The first build generates the organization's Ed25519 OpenPGP signing key `Paddock <slug>` and creates the
  system source `paddock` with it, after which uploads are accepted. Every build publishes `Packages`, `Packages.gz`,
  `Release`, `Release.gpg` and `InRelease` (written last, so a failed build leaves the previous one readable) and is
  audited as `software_repository.built`; a failed build is shown as `last_error` and audited once per distinct error
  as `software_repository.build_failed`. `POST /api/v1/software-repository/rotate-key` (`org_admin`, step-up, audited
  as `software_repository.key_rotated`) replaces the signing key: the repository is signed with the new key before the
  devices receive it, and for 30 days it is signed with the previous key as well, so devices that have not received
  the new key keep updating. The lists are also published by hash, so a build that fails halfway leaves the previous
  one readable. The private key is kept encrypted with the
  new Transit key `software-repo-wrap`, which only the worker can use. New Go dependency
  `github.com/ProtonMail/go-crypto` (BSD-3-Clause). Upgrade: run `./paddock upgrade` with `BAO_TOKEN` set (the Transit
  key `software-repo-wrap` and the worker's policy), then `./paddock secrets` and `./paddock bootstrap buckets` (the
  worker's new bundles credential `rustfs_bundles_worker_*`) and `./paddock up`.
- Portal: a *Software requests* page lists the users' requests for applications that need approval; an organization
  administrator approves a request, optionally with a reason, or denies it with a reason the user sees. A catalog
  entry has a *Users need approval* switch, a device group page shows and edits its maintenance window, an
  assignment can be marked urgent with a reason (confirmed by a fresh sign-in), and the assignment list marks urgent
  assignments and those an open rollout stages.
- Software: when the compiler has to shorten or drop something an administrator assigned, it now records a warning
  for the device and the assignment instead of only logging it. The warnings of each device's latest policy are
  available through the admin API (`GET /api/v1/compile-warnings`, filterable by device, assignment, catalog entry and
  code). Two warnings exist so far: `audience_truncated` (an offered application names more than 200 users) and
  `flatpak_forbidden`. An organization that forbids or uninstalls the `flatpak` package now gets no Flatpak
  applications, remotes or runtime on the affected devices; the rest of their software policy is delivered as before.
- Software: a Flatpak application installed per user, forbidden or removed for specific users or user groups now
  reaches only those users on a shared device. The policy names them for each application (at most 200 per
  application; a longer list records the warning `flatpak_users_truncated`). An application assigned to the whole
  organization or a device group applies system-wide, never to every user individually. Devices with agents before
  0.1.0-alpha.10 keep receiving no Flatpak applications.
- Software: the self-service app on a device shows the icons uploaded for catalog entries. Devices fetch each icon
  from the same object storage as their configuration, through a short-lived link, and only for the applications
  their own configuration names; an entry without an icon, or an icon that cannot be fetched, keeps the category
  symbol.
- Every release publishes the self-service app package `paddock-self-service_<version>_all.deb`, signed with the agent
  release key like the agent packages. The platform's agent releases carry it (package `paddock-self-service`,
  architecture `all`), `make agent-release` uploads it, and the GitHub import requires it from 0.1.0-alpha.10 on, so
  operators take a verified package from `bundles.<domain>/packages/<version>/` instead of building it themselves.
- `./paddock check` warns about leftover `.bundle-seq.replaced.*` directories that an upgrade again after a rollback
  keeps in the bundle directory (item `upgrade: no leftover bundle-seq directories`, control plane and lab with
  backups). The warning lists each path and the `sudo rm -rf` command; it never fails the check.
- Software approvals: the server now stores the user's justification with a software request, and the portal's
  *Software requests* page shows it as plain text. A denial now reaches the user's device with the administrator's
  reason and stays there for 24 hours, the time in which the user cannot ask again. Approval-required applications
  now reach agents from 0.1.0-alpha.10 on; older agents still never receive them. The reason of an approval or a
  denial may no longer contain tab characters.
- Software requests: when a user withdraws a pending request in the desktop app, the server now closes the request as
  *Withdrawn*, so administrators no longer see it as waiting and cannot approve a request the user no longer wants.
  The audit log records the withdrawal as `device.software_request_withdrawn` (syslog MSGID
  `device.sw_request_withdrawn`). Agents report a withdrawal only to a server that announces support for it in the
  device's bundle; with an older server the withdrawal stays on the device as before.

### Changed

- The worker's identity rounds send fewer requests to the identity provider: the administrator-accounts round reads an
  organization's three role groups in one listing instead of three, and the reconcile round reads all per-device login
  groups of an organization in one listing instead of two to three requests per device. Large installations leave
  more of the identity provider's capacity to portal and device logins.
- Software: an application in the software catalog that still has assignments can no longer be removed, in the portal,
  through the API or in a declarative document. The refusal names the assignments; remove them first (with staged
  rollouts enabled, that removal rolls out in waves), then remove the application, which changes nothing on the
  devices.
- Configuration rollouts: a wave advances only once its devices have applied the change, and its minimum duration now
  counts from the first device of the wave that applied. A wave whose devices are all offline therefore no longer
  advances on time. Devices that wait for their maintenance window hold the wave (they appear as
  `waiting_for_window` in the rollout's device list) until the share set by the new rollout setting
  `wave_success_threshold_percent` (default 90) has applied. A wave without progress for `stall_warning_hours`
  (default 24) is reported once with the new audit event `config_rollout.stalled`.
- Configuration rollouts: resuming a halted rollout restarts the current wave's minimum duration, and only reports
  received after the resume count toward `wave_success_threshold_percent`. A device of any wave whose failure the
  resume discarded, and after a resume every device that fails again, holds the rollout until it has applied
  successfully, and a wave whose new devices have only failed never advances by itself. The rollout counts gain
  `waiting` and `awaiting_retry`, and the rollout's device list gains the field and filter `awaiting_retry`. The stall
  warning `config_rollout.stalled` now also fires while devices await a retry; its params `waiting` and
  `awaiting_retry` replace `wave_waiting`.
- Documentation: the software guide explains how changes to software assignments roll out in waves, when a catalog
  entry can be deleted, and how software requests are approved, denied and expire; the privacy notice lists what a
  software request records.
- Updated the pinned third-party images: Fleet and fleetctl 4.94.1, Fleet vulnerability data 202611090045, Caddy 2.11.9,
  Prometheus 3.16.0, AWS CLI 2.39.6, rc 0.1.37, Playwright 1.65.0, BuildKit 0.34.2, Syft 1.57.0 and Trivy 0.76.2.

### Fixed

- After a backup key rotation, the first full database backup in the new key's repository starts at once instead of
  waiting up to PostgreSQL's checkpoint timeout. Scheduled full backups are unchanged.
- The agent no longer misreads user, group, session or sudo version lookups when a name-service module writes log
  lines into their output, for example while himmelblaud is still starting. Such output now fails the lookup for that
  round instead of being used: privileged group members are never removed and no sudoers file is written from it, and
  a sudo-rs device is never taken for classic sudo.
- `backup now` and a backup requested in the portal are no longer answered by a full database backup that was
  already running when the request came; a new full starts after it. Before, such a request could look done while
  the backup targets never showed a backup from after the request.
- `backup now` and a backup requested in the portal are no longer answered by a Fleet dump that was written before
  the request and was still waiting to be sealed; such a dump is still sealed, and a new Fleet dump is taken for the
  request. Before, `backup now --wait` could report success with a Fleet backup older than the request.
- A mounted SMB or NFS backup target whose server stops answering is now shown as unreachable, as documented, instead
  of as not mounted.
- The copy to a mounted SMB or NFS backup target whose server stopped answering is now reported as an I/O error, in
  line with the target being unreachable, instead of "not mounted".
- A point-in-time restore of an installation that is still in place no longer stops in the PostgreSQL step with
  "volume is in use".
- A point-in-time restore after an earlier restore no longer fails with "could not locate required checkpoint
  record": the restore now stages the database log of the backup it actually restored, on that backup's timeline.
- The databases' health checks now wait until PostgreSQL accepts network connections. On a fresh installation or a
  restore onto empty volumes, a busy host could otherwise start the one-time database provisioning while PostgreSQL
  was still initializing, and it failed with "connection refused".
- The managed local administrator is hidden from the login screen on Ubuntu 26.04 again. The agent's check of parent
  directories now accepts root-owned directories that only the root group may write to.
- A request body sent very slowly to the device, admin or apt repository endpoints is cut off after 60 s again, as
  documented. The edge held such a connection for about two minutes; it now passes the server's answer on at once and
  closes that HTTP/1.x connection, for error answers and for any answer to a GET or HEAD that carries a body. Other
  successful answers and HTTP/2 connections are unchanged.
- A backup mirror to an S3 target no longer fails as "stalled" while the target takes minutes to return the first page
  of its listing, as an S3 server does on a versioned bucket that holds many deleted objects. While the mirror waits for
  a page, it checks that the endpoint still answers; an endpoint that answers nothing still counts as stalled after two
  minutes, and a listing page that does not arrive within 20 minutes ends the mirror.
- A pgBackRest repository path on a backup target that no backup key names no longer stops every deletion on that
  target. The mirror keeps that path and still fails the target run as `unknown_path`, but it removes what retention
  allows everywhere else, including retired keys' repositories. `./paddock backup status` points to the target, and
  the role's log names the path.
- `./paddock upgrade` can run again from the same bundle directory after `./paddock rollback`. It no longer fails in
  `migrate-from` because the new release's `bundle-seq/` belongs to the backup role; the directory it replaces is kept
  as `.bundle-seq.replaced.<random>` and can be removed as root.
- On devices with directory logins, packages whose installation creates a local system account (for example Flatpak,
  which self-service needs for Flatpak applications, and many server packages) failed with "already exists, but is not
  a system user". Paddock now pauses the login service while it installs or removes software, including the regular
  updates and the dracut installation of in-place encryption, and starts it again afterwards. The pause waits until no
  other package operation runs and ends after 10 minutes at the latest, with a systemd timer as a fallback if the
  agent stops. New directory logins and screen unlocks wait during an installation; running sessions continue. Every
  pause is recorded as `device.login_nss_shield`, and a stop of the login service by anyone else is reported as
  `device.tamper_service_stopped`. Installations that a local administrator starts with apt are not covered; the
  device login guide describes the workaround.
- A slow or hanging backup target no longer holds up the backup role. Each target is now mirrored in its own lane,
  which the role's round starts but never waits for: scheduled OpenBao snapshots and Fleet dumps, `backup now`, key
  confirmations and target connection tests are served every round while a target takes minutes or hours to list,
  and the other targets are mirrored on time. A run's mirror results and audit event follow when its mirrors ended;
  a newer run that a target's mirror in progress does not carry waits for that target's next mirror. Disabling or
  deleting a target stops its running mirror at the next round, and the new gauge
  `paddock_backup_target_mirror_started_timestamp_seconds` shows since when a target's mirror runs.
- The backup role now holds its leader lock for as long as the process runs, so its mirrors never run outside the
  lock. When the lock's database connection drops, the role stops its rounds and mirrors before writing anything
  more, logs the loss, counts it in `paddock_backup_leader_lost_total` and leads again once the lock is free. The new
  gauge `paddock_backup_leader` shows which process leads.
- When the lock file of the login-service pause cannot be opened, the agent no longer starts the login service in the
  middle of another Paddock process's package installation and no longer reports that pause twice. The installation
  runs without a pause and is reported once as `hold_failed`.
- The dead man's switch warning now reaches the desktop of users whose account name is a full sign-in name
  (`alice@example.com`). Before, these users saw the warning only on the login screen.
- The server no longer rejects a device's whole event batch because one event has a type it does not know, for
  example from a newer agent. It skips only that event, logs it once and counts it in
  `paddock_device_events_unknown_total`, and stores the rest of the batch.
- User-scope Flatpak applications now install into the signed-in user's own installation, both when an
  administrator requires them and through self-service. Adding the source's remote there failed before.
- A user-scope Flatpak application whose target user's installation the agent cannot read no longer stays "pending"
  for good after the user signs in. The device now reports it as failed with the cause, and the agent retries it.
- The device list of a software catalog entry now includes the devices that get the entry through their owners, for
  example self-service software assigned to a user or a user group. Before, such devices only showed the entry on
  their own software page, and the list of the entry stayed empty.
- A device that gets a catalog application through its owners (an assignment to a user or a user group) is now listed
  as `unknown` on the application's device list and on the device's software page before it first reports the
  application. Before, such a device appeared only after its first report.
- On devices with directory logins, a restart of the login service that applies a changed login configuration (for
  example a changed list of groups allowed to log in) and waits because another process keeps the lock file of
  Paddock's login-service pause taken is now logged as a warning, at most once an hour, with how long the lock has
  been held. The restart still waits and runs once the lock is free.
- The backup role no longer clears its per-target metrics (`paddock_backup_target_reachable`,
  `paddock_backup_target_held_files`, `paddock_backup_last_success_timestamp_seconds`) before setting them again, so a
  Prometheus scrape at that moment can no longer miss those series.
- `./paddock rollback` no longer refuses every rollback after a release that changed the schema: the upgrade now
  records the schema versions of the pre-upgrade backup before its first `up`, and the rollback restores that point
  with them instead of the schema the new release's backups report; a rollback point without them is refused with a
  pointer to `./paddock restore`.
- The worker no longer stays unhealthy when many of its periodic rounds run long, for example the identity reconcile
  round with hundreds of organizations: the rounds' leader locks now use connections of their own instead of taking
  the connections their work and the readiness check need, so `./paddock up` and upgrades no longer time out waiting
  for the worker, and rollouts, role sync and session ends no longer stall. The worker may now open up to 14 more
  PostgreSQL connections than before (PDK-1010).
- The api now opens at most 8 connections to the control-plane database and 8 to the audit database instead of one per
  logical CPU, so that all Paddock roles together stay within PostgreSQL's default of 100 connections on hosts of any
  size; `docs/operations/capacity.md`, "PostgreSQL connection budget", lists what each role needs (PDK-1010).

### Security

- The control plane's containers are separated by trust zone: Caddy, Authentik and Fleet can no longer reach
  PostgreSQL, OpenBao, Valkey or RabbitMQ, and only Caddy may name a client's address to the Paddock roles.
  RabbitMQ's management interface is reachable inside its container only, and the health and metrics ports of the
  roles that call the public names answer on the internal network only. `./paddock check` fails a configuration
  that undoes this and warns while the admin allow list admits every address or another Docker network of the host
  overlaps the new fixed subnet (`PADDOCK_EDGE_SUBNET`). Existing installations: an explicit
  `PADDOCK_TRUSTED_PROXY_CIDRS` or `PADDOCK_INTERNAL_CIDRS` in `.env` must be removed before the upgrade (on a lab: set again,
  with `PADDOCK_EDGE_TRUSTED_PROXIES`; `./paddock upgrade-check` names them); see the upgrade notes of this release.
- Valkey has one ACL user per role instead of one shared password: each role may touch only the keys it needs, and the
  internet-facing gateway can no longer write device keys, bundle pointers or signed commands. `./paddock up` creates
  the new secrets `.secrets/valkey_<user>_password` (`api`, `gateway`, `worker`, `compiler`, `escrow_reader`,
  `revocation_issuer`, `healthcheck`); the secrets `valkey_password` and `valkey_auth_conf` are no longer used. Valkey
  stores only hashes of the passwords. `./paddock check` verifies the users, the default user being off and that Fleet's
  Redis uses its own configuration file.
- The control plane now limits request rates: sign-ins to 20 per minute per client address, admin API reads to 600,
  writes to 120 and agent uploads to 10 per minute per session or API token, answered with 429 and `Retry-After`
  above the limit. The device per-address limit is configurable and counts an IPv6 client by its /64. The limits are
  `PADDOCK_RATELIMIT_*`, `PADDOCK_DEVICE_PER_IP_LIMIT` and `PADDOCK_DEVICE_PER_IP_V6_PREFIX`; `./paddock check` fails
  when a limit is switched off. Installations with many administrators behind one NAT should raise
  `PADDOCK_RATELIMIT_AUTH` (see the installation guide). The new alert `PaddockRateLimitStorm` reports sustained
  refusals.
- The PostgreSQL databases and both Valkey instances run with only the Linux capabilities their entrypoints need, can
  no longer gain privileges, and have a memory limit (PostgreSQL 2 GiB for Paddock, 1 GiB for Authentik and the audit
  index, Valkey 512 MiB), so that a runaway or attacked service cannot starve the host. Valkey's root file system is
  read-only. The limits can be raised in `.env` (`PADDOCK_POSTGRES_MEM_LIMIT`, `PADDOCK_AUTHENTIK_POSTGRES_MEM_LIMIT`,
  `PADDOCK_AUDIT_POSTGRES_MEM_LIMIT`, `PADDOCK_VALKEY_MEM_LIMIT`, `PADDOCK_FLEET_REDIS_MEM_LIMIT`); see
  `docs/operations/capacity.md`, "Memory limits". The bundle ships `hardening-exceptions.yaml`, the list of every
  remaining deviation from the container hardening with its reason.
- OpenBao and both RustFS object stores drop every Linux capability (OpenBao keeps only `IPC_LOCK`), can no longer
  gain privileges and have a memory limit (OpenBao 1 GiB, RustFS 2 GiB, the audit RustFS 4 GiB). OpenBao runs as its
  image's non-root `openbao` user (100:1000), now pinned in the Compose file; existing data volumes need no change.
  The RustFS root file systems are read-only. The limits can be raised in `.env` (`PADDOCK_OPENBAO_MEM_LIMIT`,
  `PADDOCK_RUSTFS_MEM_LIMIT`, `PADDOCK_AUDIT_RUSTFS_MEM_LIMIT`); see `docs/operations/capacity.md`, "Memory limits".
- Fleet's MySQL, RabbitMQ, Fleet and Prometheus run with only the Linux capabilities they need (RabbitMQ, Fleet and
  Prometheus with none), can no longer gain privileges, and have a memory limit (Fleet's MySQL 2 GiB, RabbitMQ 1 GiB,
  Fleet 3 GiB, Prometheus 1 GiB). Fleet's and Prometheus' root file systems are read-only. RabbitMQ now runs as its own
  user from the start and sizes its memory alarm from its limit, so it blocks publishers before it would be killed. The
  limits can be raised in `.env` (`PADDOCK_FLEET_MYSQL_MEM_LIMIT`, `PADDOCK_RABBITMQ_MEM_LIMIT`,
  `PADDOCK_FLEET_MEM_LIMIT`, `PADDOCK_PROMETHEUS_MEM_LIMIT`); see `docs/operations/capacity.md`, "Memory limits".
- Authentik's server and worker drop every Linux capability, can no longer gain privileges and have a memory limit
  (server 2 GiB, worker 1 GiB; `PADDOCK_AUTHENTIK_SERVER_MEM_LIMIT`, `PADDOCK_AUTHENTIK_WORKER_MEM_LIMIT` in `.env`,
  see `docs/operations/capacity.md`, "Memory limits"). Raise the server's limit by about 256 MiB for every web worker
  you add with `PADDOCK_AUTHENTIK_WEB_WORKERS`.
- `./paddock check --online` gains the item `containers: capabilities and security options match the matrix`: every
  running container of the host's project is compared with the hardening matrix of `hardening-exceptions.yaml`, so a
  container recreated by hand or with an edited Compose file that adds a capability, keeps the default ones, may gain
  privileges or runs unconfined is named.
- The agent refuses to write, rename or delete a managed file when a parent directory is a symbolic link or can be
  changed by someone other than root, so a local service account can no longer redirect a managed file into a
  protected area. The resource reports `parent_not_trusted`.
- The supervisor and the first-boot disk setup run in a systemd sandbox (no personality changes, no realtime
  scheduling, no kernel log access, no obsolete system calls, a private `/tmp`).
- The agent checks the login settings it receives against the server's own rules before it writes the Himmelblau
  configuration and reports `invalid_spec` instead of writing a malformed one; the server no longer signs such a
  login section.
- Every public host of the control plane (`admin.`, `auth.`, `device.`, `bundles.`, `fleet.`) now answers with
  `Strict-Transport-Security` including subdomains, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and a
  `Referrer-Policy`, also for Authentik and Fleet. The edge refuses smaller request bodies: 1 MiB on `auth.` (was
  16 MiB) and `device.` (was 2 MiB); the admin platform uploads may be up to 256 MiB. Agent release uploads may now
  take up to 30 minutes (was 10 minutes). A reverse proxy in front of Caddy must pass bodies of up to 256 MiB to
  `admin.` (see the upgrade notes).
- When a device's data access is revoked, the step that signs out every user now accepts only real user entries in
  the list of signed-in users. Any other text in that list (for example error messages of an identity module) is
  skipped and recorded in the revocation log with its line, and is never mistaken for a user; every real user is
  still signed out. If the list holds no user at all, the revocation log shows an error. The erasure and the restart
  of the device run as before.
- `./paddock migrate-from` (part of `./paddock upgrade`), when run as root, no longer writes inside a `bundle-seq/`
  directory that the backup role owns. Before this fix, a link planted there could redirect root's write to any file
  on the host.
- On devices with directory logins, a stop of the login service is now reported as `device.tamper_service_stopped`
  even when a local administrator keeps the lock file of Paddock's login-service pause taken. Only a pause that
  Paddock started within the last 12 minutes suppresses the report. While another process keeps that lock file, the
  agent logs a warning at most once an hour.
- Go toolchain 1.27.4 (was 1.27.3; build image `golang:1.27.4-trixie`, CI, every module): fixes GO-2026-6859
  (CVE-2026-97054), a data race in `net/http` that can crash an HTTP/1 server whose handler reads a size-limited request
  body concurrently with writing the response header. Released servers and agents are not exposed: every Paddock
  handler that limits a request body reads it to the end before it writes any response header, in the same goroutine.
- A Debian package of an agent release is accepted only when its signature's trusted comment names that release and
  the package's architecture: `paddock-agent version=<version> arch=<arch>`, with `arch=all` for
  `paddock-self-service`. The package upload, `./paddock agent-release` and the import from GitHub refuse any other
  comment with 422 `release_signature_mismatch` and store nothing of the package, so a validly signed package of an
  older release can no longer be stored under a newer one. The release workflow already signs every package this
  way. Packages signed by hand without this comment must be signed
  again (`docs/operations/agent-releases.md`).
- The fleetd package `fleet-osquery` of an agent release is accepted only when its signature's trusted comment names
  the release it is stored under and the package's architecture: `paddock-agent version=<release version>
  arch=<arch>` — the release version, not the fleetd version. The package upload, `./paddock agent-release` and the
  import from GitHub refuse any other comment with 422 `release_signature_mismatch` and store nothing of the package,
  so a validly signed older fleetd can no longer be stored under a newer release. Sign fleetd offline with
  `-t "paddock-agent version=<release version> arch=<arch>"` (`docs/operations/agent-releases.md`); releases already
  stored are not verified again.
- The revocation package `paddock-revoke` of an agent release is now bound to its release the same way: its signature,
  made with the revocation release key, must carry the trusted comment `paddock-agent version=<release version>
  arch=<arch>`. The package upload and `./paddock agent-release` refuse any other comment with 422
  `release_signature_mismatch`, and a `paddock-revoke` signed with the agent release key stays refused. The holders of
  the revocation release key sign it offline with `-t "paddock-agent version=<release version> arch=<arch>"`
  (`docs/operations/agent-releases.md`); releases already stored are not verified again.
- When the agent cannot report a directory user's sign-in because the user's name does not resolve to the session's
  user ID, its log warning now names only that user ID, no longer the user's name or the account entry the lookup
  returned.

## [0.1.0-alpha.9] - 2026-11-07

This is the first release under the upgrade guarantee (ADR 0047): an installation of 0.1.0-alpha.8 upgrades with
`./paddock upgrade <old dir>` and goes back with `./paddock rollback <old dir>` (`docs/operations/upgrade.md`,
"0.1.0-alpha.9, from 0.1.0-alpha.8"). Run the upgrade with `BAO_TOKEN` set, then `./paddock bootstrap buckets` and
`./paddock up` once more, and have a platform administrator confirm the backup key in the portal: until a backup key
is confirmed, nothing is backed up. **Breaking for operators:** backups no longer go to the S3 bucket of
`PADDOCK_BACKUP_S3_*`; they are written to the local backup repository and mirrored to the backup targets configured
in the portal, and the key of 0.1.0-alpha.8 is imported once. OpenBao moves to 2.7.2 and starts sealed after the
upgrade (have the custodians ready, or automatic unseal on), Fleet moves to v4.94.0 and migrates its database, and the
AWS CLI image of the bucket scripts moves to 2.39.3. Upgrade the server first, then roll out this release's agent;
agents of 0.1.0-alpha.7 and 0.1.0-alpha.8 keep working in the meantime. Installations of 0.1.0-alpha.7 upgrade to
0.1.0-alpha.8 first, with that release's runbook; 0.1.0-alpha.6 and earlier are installed fresh.

Backup and recovery (plan M15, ADR 0046): a new role `paddock-backup` takes the PostgreSQL, OpenBao, Fleet and
escrowed LUKS header backups, seals them with a key Paddock generates and an administrator confirms, and mirrors them
to local, SMB, NFS or S3 targets; the portal shows the state per target and kind and plans restores, and
`./paddock restore` brings a control plane back with one command (`docs/operations/backup.md`,
`docs/operations/restore.md`). Upgrade path (plan M16): `./paddock upgrade-check`, `./paddock upgrade` and
`./paddock rollback`, the server's own upgrade report and an *Upgrade* card with the agent support window on the
platform administrator's landing page. Operator toolbox (plan M12): diagnostics bundles that an administrator requests
for one device and the device user is told about (ADR 0048), syslog destinations for notifications with daily
checkpoints and replay from a sequence number, Wazuh and Sigma rules for the audit events, and an access review report
for auditors. The agent changes in this release (diagnostics bundles); the supervisor and `paddock-revoke` do not.
`paddock-revoke` stays unsigned, and revocation (Lock, Destroy, dead man's switch) stays disabled behind
`PADDOCK_REVOCATION_ENABLED`.

Schema: migrations 00100–00112 (control-plane database; new tables, columns, functions, policies and grants only); audit unchanged.
Upgrade: from 0.1.0-alpha.8: steps: BAO_TOKEN for ./paddock upgrade, then ./paddock bootstrap buckets and ./paddock up; confirm the backup key in the portal
Agents: supports 0.1.0-alpha.7, 0.1.0-alpha.8, 0.1.0-alpha.9

### Added

- Groundwork for backups operated from the portal (ADR 0046): the control-plane database gets the backup tables and
  the new database role `paddock_backup`, and OpenBao the Transit key `backup-wrap`, with which the api may only
  encrypt and the backup role only decrypt. `./paddock secrets` adds `.secrets/db_paddock_backup_password` and
  `db_paddock_backup_url`; `./paddock bootstrap openbao` creates the key and extends the policies `paddock-api` and
  `paddock-backup`. A cluster initialized before this release gets the role `paddock_backup` from the new provisioning
  step of `./paddock up` before the migration runs; no manual step.
- The backup key is generated by Paddock (ADR 0046): a platform administrator with a step-up generates it in the admin
  API (`/api/platform/v1/backup/key`), sees it exactly once and confirms that it was stored by typing back the
  characters at six positions the server chose; three wrong answers discard the key. A new key confirmed while one is
  active retires the previous one. The key is stored only encrypted with the Transit key `backup-wrap`; every step is
  audited (`platform.backup_key_generated`, `_confirmed`, `_discarded`) without the key. Existing installations set
  `PADDOCK_BACKUP_LEGACY_KEY_FILE` on `paddock-api` to import their host key file once as key `legacy`, which waits for
  the same confirmation (the positions to type are part of the key state while a key waits for its confirmation); prod-check warns while the variable is set, and the api logs a warning while it is set after
  a key was confirmed.
- Admin API for platform backups (ADR 0046): platform administrators manage backup targets (a local directory, an
  SMB or NFS share, an S3-compatible bucket), request a connection test, set the backup schedule and retention, request
  a backup now and list every run, under `/api/platform/v1/backup`. Share and bucket credentials are stored encrypted
  with the OpenBao key `backup-wrap` and never returned. Every change needs a step-up and is audited
  (`platform.backup_target_*`, `platform.backup_schedule_changed`, `platform.backup_run_requested`). A backup request
  is refused while no backup key is confirmed. The backup role that runs the tests and backups follows in a later
  change.
- Host commands for backups without the portal: `./paddock backup-target apply` mounts the local, SMB and NFS backup
  targets saved in the portal as Docker volumes of the backup service (run `./paddock up` afterwards; the target then
  shows as mounted), `./paddock backup now [--kind k]… [--label l] [--wait]` requests a backup run and
  `./paddock backup status` prints the key, the newest runs and the targets. The rendered
  `compose.backup-targets.yaml` is host-local and mode 0600 because it holds the SMB passwords; `./paddock` redacts
  them in mount errors and `./paddock compose config` refuses to print the configuration while the file is in use; `./paddock migrate-from` carries the file to a new version. `./paddock up` refuses to start when a local target no longer resolves below
  `PADDOCK_BACKUP_LOCAL_ROOT`, and `./paddock check --online` warns when the host has not applied the targets saved in
  the portal. Use a dedicated SMB account with write access to the backup share only: members of the `docker` group
  can read its password. An SMB password with a comma or whitespace is refused when the target is saved: choose another password for the share.
- `./paddock restore` brings the control plane back with one command (plan M15, ADR 0046): `--from <set directory or
  paddock-backup-set-*.tar>` or `--from-target-file <file>` on a lost or fresh installation, `--plan <id>` for a restore
  plan approved in the portal, `--at <time>` for a point in time and `--only postgres|openbao|fleet|escrow` for single
  components. It asks for the backup key (not echoed), refuses a set made with another key or with a newer schema,
  and a point in the future or before the oldest database backup, before anything stops, and waits for the typed word
  `restore`. The key goes to `.secrets/restore/backup_key`, which no container mounts, and is deleted on every exit
  unless `--keep-key-file` is given. A failed step prints the host's state and what to do next. OpenBao is unsealed automatically when automatic unseal is set up, else by three
  custodians while the command waits up to 15 minutes. Escrowed LUKS headers of devices whose escrow was destroyed
  after the backup are never put back.
- `./paddock restore --only backup-repo --from <target name, set directory or tarball>` (or `--from-target-file`)
  rebuilds a lost local backup repository from a backup target without touching any database.
- `./paddock backup-target export <name|id> <file>` writes an S3 backup target with its credentials to a 0600 file:
  keep it offline with the backup key to restore from that target without a database.
- New commands `paddock-server migrate --version`, `backup manifest`, `backup fetch-set`, `backup restore-repo`,
  `backup restore-escrow` and `backup target-export`; `make restore-drill` now runs the same restore code against the
  development backup target.
- Restore plans: a platform administrator approves a restore in the API with a step-up and the typed word `restore`;
  the plan names the source (the local backup repository or a target), the point in time and the components, is
  checked against the successful backups of that source, expires after 24 hours and gives the host command
  `./paddock restore --plan <id>`. Only one plan is open at a time; an approved plan can be cancelled. The host reads
  the plan with `paddock-server backup plan <id>` and reports the run with `paddock-server backup restore-report`;
  approval, cancellation, the start of a planned restore (also when it is refused) and the end of every restore
  (`platform.restore_planned`, `_cancelled`, `_started`, `_completed`, `_failed`) are audited, and a restore without a
  plan is listed as a fresh installation. A plan whose backup target was deleted is refused on the host. The SIEM
  content raises the start of a restore to a high-level rule.
- Portal: Platform → Backup shows per target and kind when the last backup succeeded, manages backup targets (local
  directory, SMB share, NFS export, S3 bucket), guides through generating and confirming the backup key, sets the
  schedule and lists the backup runs. The getting-started checklist gains a backup step.
- Documentation for backup and recovery (ADR 0046): `docs/operations/backup.md` (targets, the host step, the key, the
  schedule, the backup set, what the mirror deletes, metrics, alerts, audit events and the API),
  `docs/operations/restore.md` rewritten around `./paddock restore` (fresh installation, rollback with a restore plan,
  partial restore per component, why one organization cannot be restored alone, the checks after a restore and the
  restore drill with its RTO line), the backup steps of the installation guides, the alerts of
  `docs/operations/monitoring.md`, the section "From 0.1.0-alpha.8: the backup moves" of the upgrade guide, the
  architecture sections for the backup role, tables, endpoints and recovery, the retention rows of ADR 0032 and the
  residual risks RR-100 to RR-104 and RR-123 to RR-125.
- Upgrade guarantee in code: `make lint` fails when a migration of the previous release is edited or deleted, the
  signed bundles, check-ins, events, commands and audit inserts of the previous release are kept as fixtures that every
  later tree must still read (`make compat-fixtures RELEASE=<version>`), and every release section of `CHANGELOG.md`
  needs the lines `Upgrade:` and `Agents:` next to `Schema:` (`make release-check`).
- `paddock-server admin upgrade-check --target-version <version> [--json]` and `GET
  /api/platform/v1/upgrade-check?target_version=…` report, before an upgrade, whether the database is ahead of the
  release, which active devices run an agent outside the release's support window (its own and the two previous
  releases; FAIL above 1 % of the active devices or 5, whichever is larger), the backup, OpenBao, pending-rollout
  and session state. Exit code 0 without a FAIL, 1 with one, 2 on a usage error. Database migration
  `00102` runs automatically; it only lets the platform role read the applied migration version.
- `./paddock upgrade-check <old dir> [--json]` (PDK-742): run in the new bundle directory before `migrate-from`, it
  reports what an upgrade from the running release needs without changing anything: the old bundle's integrity, that
  the old release is the one directly before this one (naming the releases to go through otherwise), the release's
  Upgrade and Agents lines, `.env` keys the new release requires and keys it no longer knows, secret files to
  generate or that cannot be generated, free disk space, pullable images, the server's own upgrade report asked
  through the old stack (alpha.8 with the new image), the OpenBao unseal path and the old stack's health. PASS, WARN
  and FAIL table or `{items, exit}` JSON; exit 0 without FAIL, 1 with, 2 on usage. The bundle now ships `RELEASES`
  and `RELEASE-NOTES` for it.
- `./paddock upgrade <old dir> [--yes] [--allow-unsupported-agents] [--skip-backup]` and `./paddock rollback <old dir>
  [--yes]` (PDK-743). The upgrade runs the steps of the runbook as one command, in the new bundle directory:
  - It runs the upgrade check and stops on any FAIL. `--allow-unsupported-agents` accepts only the agents FAIL.
  - It shows the plan and asks for `yes`.
  - It runs `migrate-from`, `secrets`, `pull` and `check`.
  - On the control plane, it takes a backup labelled `pre-upgrade-<version>` with the running release before anything
    changes. `--skip-backup` is accepted only when the release notes say `Schema: unchanged` and Fleet's image stays.
  - On the audit host, after audit migrations, it stops the old audit writer.
  - It runs `up`.
  - With `BAO_TOKEN` set, it runs `bootstrap openbao`.
  - It checks that every service is healthy and that the new server reports its migrations, plus `check --online` on
    the audit host.
  - Every step prints its command. A failed run continues at the failed step when started again.

  The rollback stops the new release. When the release changed the schema, it restores the pre-upgrade backup from the
  local repository with the old release's restore, including Fleet's dump when Fleet's image changed. Then it starts
  the old release. It asks for `yes` and states that every change after the upgrade point is lost.
  It checks every precondition of the restore before it stops anything, and it uses the upgrade point only once,
  for the upgrade attempt that recorded it. It refuses unless the running stack is the release of its directory, and
  a later upgrade from that directory supersedes its upgrade point.
- The platform administrator's landing page in the portal has an *Upgrade* card: the agent support window of the
  release the server runs, the active devices whose agent is outside it, and the backup state, read from the upgrade
  report of the server (`GET /api/platform/v1/upgrade-check`); the card has no action, the upgrade stays a host
  command. `docs/operations/upgrade.md` is rewritten around `./paddock upgrade-check`, `./paddock upgrade` and
  `./paddock rollback`, with one subsection per release from 0.1.0-alpha.8; residual risks RR-105 to RR-107 record what
  the guarantee does not cover.
- Diagnostics bundles, server side (ADR 0048): the new device command `collect_status` (valid one hour) asks a
  device for Paddock's own logs and configuration; the device announces the sealed bundle with `POST /v1/diagnostics`
  and uploads it to the escrow bucket, and the worker keeps it only once its size and SHA-256 match. Stored bundles are
  deleted seven days later by the retention round (`retention.purged`, store `device_diagnostics`). New audit codes
  `device.diagnostics_requested`, `device.diagnostics_collected`, `device.diagnostics_downloaded` and
  `device.diagnostics_purged` carry only the bundle's hash, never its content. The bundled RustFS bootstrap lets the
  gateway presign uploads below `diagnostics/` and the worker delete them; run `./paddock bootstrap buckets` once
  after the upgrade. Database migration `00103` runs automatically.
- Diagnostics bundles, device side (ADR 0048): the agent answers `collect_status` with a closed list of Paddock's
  own state, the journals of the Paddock and Himmelblau units of the last seven days, the Paddock-managed
  configuration and a few system facts. Secrets are removed before anything is archived (Himmelblau secrets, proxy
  credentials, the Fleet enroll secret and managed file contents of the applied configuration, mount passwords in
  fstab and crypttab, identity fields, the users of apt history, hardware addresses); home directories, the device identity
  and enrollment secrets are never read. Every journal is cut at 8 MiB and the archive at 24 MiB. Before collecting,
  every user with an active graphical session sees a desktop notification with the administrator's reason (German
  when the system locale is German). The collection runs in the background, so check-ins and tamper checks continue
  meanwhile. The bundle is sealed to the escrow key and uploaded; nothing stays on the device,
  and an uninstall removes `/var/lib/paddock/diagnostics`.
- Diagnostics bundles in the portal and the admin API (ADR 0048): administrators and operators request a bundle on the
  new Diagnostics tab of a device with a reason the device's user is shown, list every bundle of the organization on
  the new Diagnostics page, and download a stored bundle after a fresh identity confirmation; the escrow-reader unwraps
  its key for the new purpose `diagnostics`. Before anything is served, the download checks the stored object against
  the size and SHA-256 the worker verified and refuses an object that was replaced. Administrators can purge a bundle
  before its seven days end. Auditors and API tokens cannot download bundles; auditors do not see them at all. Devices
  now report the escrow-wrap key version of a bundle (`key_version` in `POST /v1/diagnostics`, optional for older
  agents). The bundled RustFS bootstrap narrows the api's escrow-bucket access to escrowed headers and diagnostics
  bundles, lets it list and delete diagnostics bundles only, and removes the former bucket-wide read policy
  `paddock-escrow-read`; run `./paddock bootstrap buckets` once after the upgrade. Database migration `00106` runs automatically.
- Diagnostics bundle documentation (ADR 0048): `docs/compliance/privacy.md` gains the section *Diagnostics bundle (on
  request only)* for employees and works councils, with the closed content list file by file, the notice text in
  German and English, who may request and download a bundle, the seven-day deletion and that the audit trail holds
  only the bundle's hash; a unit test keeps the list equal to what the agent collects. The new runbook
  `docs/operations/diagnostics.md` explains when to request a bundle, its states and failure reasons, the download
  with a step-up, how to read the archive, the purge and the audit codes. Residual risks RR-108 (journals name users),
  RR-109 (the notice is best effort) and RR-110 (syslog delivers at least once) are recorded.
- Notification destinations can now be syslog receivers: Paddock sends every matching audit event as one RFC 5424
  message over TLS (octet-counting framing, JSON body), with an optional private CA certificate and TLS server name.
  The `MSGID` is the audit code; the few codes longer than the 32 characters RFC 5424 allows use a fixed alias
  listed in the audit code reference, and the message body always carries the full code.
  Webhook and syslog destinations gain the *Send daily checkpoints* setting.
- Webhook and syslog destinations with *Send daily checkpoints* now receive, for every sealed audit day, a checkpoint
  with the day's event count and the WORM manifest hash, signature and key version, numbered like the events, so a
  SIEM can reconcile its copy with the audit chain.
- Administrators can replay a notification destination from a sequence number (*Replay from…*, with step-up): the
  stored batches and checkpoints are sent again with their original delivery IDs and numbers; events the index no
  longer holds are marked missing.
- Wazuh decoders and rules and Sigma rules for the audit events (`integrations/`), and runbook sections for receiving the syslog push with rsyslog or Wazuh, deduplication, checkpoint reconciliation and replay in `docs/operations/siem.md`. The pull loop in `docs/operations/siem.md` now writes one `{"organization", "commit_seq", "event"}` line per event, the shape the Wazuh rules read.
- Access review report for auditors and administrators (`GET /api/v1/access-review`, export as JSON or CSV): role
  members, role changes, administrator accounts, API tokens, reveals of secrets, step-ups, ended sessions and
  destructive actions for any period up to 400 days. Platform administrators get the platform counterpart under
  `/api/platform/v1/access-review`. Every export is recorded as `access_review.exported`; a view is recorded once per
  actor and day while the organization records audit searches.
- Access review in the portal: administrators and auditors open *Access review* in the security group, choose a period
  (30, 90 or 365 days or a custom range of up to 400 days), expand each section and export the report as JSON or CSV.
  Platform administrators have the platform counterpart under *Platform access review*.
- Restore in the portal: the Backup page gains a Restore tab with the restore plans and a Plan a restore dialog (also on the Overview tab). The platform administrator chooses the source, the point in time and the components, types the word `restore` and confirms with a step-up; the approved plan shows its host command with a Copy button and the time it expires. An approved plan can be cancelled. A running plan whose host restore can no longer report can be abandoned on the Restore tab after typing the word `abandon` and a step-up.
- The diagnostics bundles of a device can be searched by requester and reason (`q` on `GET /api/v1/devices/{id}/diagnostics`).
- Restore plans: a plan the host started but never reported as finished (the host crashed, or the database was
  unreachable when the restore stopped) no longer blocks every further plan. A platform administrator abandons it in
  the API with a step-up and the typed word `abandon`; the plan is then abandoned with the administrator named in its
  outcome, a new plan can be approved, and the host's later report for it is refused. Every attempt is audited
  (`platform.restore_abandoned`); `docs/operations/restore.md` describes the procedure.
- `./paddock upgrade` and `./paddock rollback` now cover the move from 0.1.0-alpha.8 (PDK-840). That release has no
  labelled backup, so before `up` the upgrade runs 0.1.0-alpha.8's own backup through its own Compose files:
  - full pgBackRest backups of both databases;
  - an OpenBao snapshot;
  - a Fleet dump.

  It checks that all four are in the backup bucket. Right before `up` it stops 0.1.0-alpha.8's pgBackRest and pushes
  the WAL it still holds, so that nothing the new release writes reaches the backup bucket.

  `./paddock rollback` to 0.1.0-alpha.8 runs that release's documented restore procedure from the backup bucket. It
  restores PostgreSQL, then OpenBao into a fresh instance (the custodians or the automatic unseal unseal it), then
  Fleet's database when Fleet's image changed. Last, it runs the restore commands. Before it stops anything, it checks
  that both directories name the same Compose project, that the newest backups are the recorded ones and that the snapshot and the dump download and decrypt. Changes made
  after the pre-upgrade backup can be lost. The escrow bucket is not part of 0.1.0-alpha.8's restore.

### Changed

- Updated OpenBao to 2.7.2 (security fixes for the PKI, AppRole, SSH and Transit engines), Himmelblau on devices to 4.0.8, and the Fleet vulnerability database to NVD release 202611020042; `./paddock up` recreates OpenBao, which starts sealed, so have the custodians ready (`docs/operations/upgrade.md`). Himmelblau 4.0.8 offers the password change at the console login on an enrolled device; it does not yet contain the upstream fix for the Hello PIN loss, so the `cache_timeout` workaround and RR-40 stay in place.
- Backups run in the new role `paddock-backup` (`paddock-server serve backup`, ADR 0046): it is the only process that
  decrypts the backup key, and nothing is backed up until a platform administrator has confirmed a key. pgBackRest now
  writes to the local volume `backup-repo` (`pgbackrest/<key_id>/`, a new path and an immediate full backup after every
  key rotation) instead of an S3 bucket; the role adds sealed OpenBao snapshots, sealed Fleet dumps and the escrowed
  LUKS headers, writes `manifest.json` and mirrors the identical backup set to every enabled backup target (S3 bucket
  or mounted directory). A target that fails never stops the others or the control plane. Each run is one
  `backup_run` row and one audit event `platform.backup_completed` or `platform.backup_failed`.
- New commands `paddock-server backup now [--kind k]... [--label l] [--wait]` and `paddock-server backup status`;
  `paddock-server backup openbao` is gone (use `backup now --kind openbao`).
- Breaking for operators: `PADDOCK_BACKUP_S3_*`, the secrets `backup_{pgbackrest,worker,fleet}_{access,secret}_key`
  and the service `fleet-backup-upload` are removed, `paddock-worker` no longer holds any backup secret, and
  `fleet-backup` writes plaintext dumps that only the backup role seals. Run `./paddock secrets` and
  `./paddock bootstrap` once after the upgrade for the read-only escrow credential `rustfs_escrow_backup_*` of the
  backup role; the host key file is mounted into `paddock-api` for its one-time import as key `legacy`.
- Metrics and alerts: `paddock_backup_last_success_timestamp_seconds{kind,target}`,
  `paddock_backup_target_reachable`, `paddock_backup_key_confirmed`, `paddock_backup_runs_total`,
  `paddock_backup_repo_bytes`; new alerts `PaddockBackupKeyUnconfirmed`, `PaddockBackupTargetUnreachable` and
  `PaddockBackupRepoFull`; `PaddockBackupStale` is per kind and target (escrow after 3 hours). `./paddock check` gains
  the items `backup: paddock-backup service present with its secrets`, `backup: no S3 credentials or encryption key
  on the worker` and `backup: repo volume named`.
- A backup target loses only what the local retention would have removed from the target's own copy: a lost or
  rebuilt local repository never wipes the copies on the targets (the target then reports `set_shrunk` and keeps
  every byte). Objects a target keeps although the local set lacks them are counted in
  `paddock_backup_target_held_files{target}`; the alert `PaddockBackupTargetHolding` fires after a week of holding.
  A target holding a repository path no backup key names reports `unknown_path` and deletes nothing. pgBackRest now
  verifies the whole stanza after every full backup (state file `verify-ok`); only a contiguous, verified archive
  lets WAL leave the targets.
- An escrowed LUKS header leaves the backup set and the targets only after a recorded Destroy of its device
  (`device.escrow_destroyed`) that is not older than the header itself, and once `retention_full` full intervals
  have passed since then; a header that merely disappeared from the escrow bucket, or was escrowed after the Destroy,
  is kept. `manifest.json` records each escrowed header's time in the escrow bucket (`contents.escrow[].at`). An escrow bucket listing that lacks all, or more than 10 %, of the
  headers without such a Destroy (lost, re-created or wrong bucket) copies and deletes nothing, fails the escrow run
  and raises the new alert `PaddockBackupEscrowListingSuspicious`; smaller gaps are kept and counted in
  `paddock_backup_escrow_unevidenced_missing`.
- `make restore-drill` now measures a restore as a fresh installation with the code of `./paddock restore`: it backs up
  every kind to the development target, deletes both databases, OpenBao, Fleet's MySQL and the local backup repository,
  rebuilds the repository from the target, restores, runs the acceptance subset and prints the time until the control
  plane is ready and until the subset is green. `make dev-seed BACKUP=1` confirms a backup key for it.
- A device whose agent is older than the server's support window keeps checking in and receives only the agent
  update offer of the current rollout, regardless of its wave; it gets no configuration bundle and no commands until
  it runs a supported agent. Lock, Destroy and dead man's switch tokens and the command that disarms the dead man's
  switch still reach it. A Lock or Destroy takes effect on such a device only if revocation was enabled in the last
  configuration it applied; otherwise the device refuses it as disabled, so an old agent stays lockable only if
  revocation was enabled before it left the window. Its events are still accepted. Agent versions that are no release
  version (development builds) are not judged.
- `./paddock pull` without arguments pulls only the images that are not already present on the host by their
  reference (tag and digest), and prints `present: <image>` for the others. Images loaded with `docker load` on a host
  without registry access therefore pass the pull step of `./paddock upgrade`. `./paddock pull <service>…` pulls the
  named services as before.
- New database roles no longer need a manual `CREATE ROLE` on an existing installation. A one-shot service,
  `db-provision` (`audit-db-provision` on the audit host), runs before every database migration of `./paddock up` and
  `./paddock upgrade`: it creates each role whose password file exists and sets every password again from
  `.secrets/`, so a rotated password file takes effect on the next `up`. The migration user stays without the right to
  create roles; only this service reads the PostgreSQL superuser password. Passwords never appear in logs.
- Updated the AWS CLI image of the bucket bootstrap scripts to 2.39.3: Docker pulls it at the next `./paddock bootstrap
  buckets`, `./paddock bootstrap audit-bucket` or restore onto a fresh installation, not with `./paddock pull`. The
  portal is built with Node.js 26.13.0 (LTS); nothing changes for the operator.
- Updated Fleet and fleetctl to v4.94.0, which migrates the Fleet database: take the Fleet dump before `./paddock up` (`docs/operations/upgrade.md`).
- Local backup targets are now a relative subpath of the new base directory `PADDOCK_BACKUP_LOCAL_ROOT` (default
  `/srv/paddock-backup`) instead of an absolute host directory: the portal and the API refuse absolute paths, `..`,
  `.` and empty path elements, and the host step refuses a root or subpath component that is a symlink. Create the
  root owned by root and not writable by group or others; `./paddock check` gains the item `backup: local target
  root`. Alpha: an existing local target with an absolute path is refused on its next edit and has to be re-entered
  as a subpath; there is no migration.
- A fresh installation starts without a backup key: `./paddock secrets` no longer writes
  `.secrets/backup_encryption_key`, and a platform administrator generates the key in the portal. An installation
  upgraded from 0.1.0-alpha.8 keeps that file; while it exists on a control-plane host (or a lab host with backups),
  `./paddock` adds `compose.backup-legacy-key.yaml`, and the api imports the file once as key `legacy` as before. A
  present but unreadable or invalid file still stops the api.

### Fixed

- Removing Paddock from a device now waits up to 10 minutes for the package lock instead of ending as `partial` when an unattended upgrade or another apt run holds it.
- `./paddock compose run --rm --no-deps pgbackrest verify` (and `pgbackrest-authentik verify`) exists now: it verifies
  the whole stanza, after a running backup and without one starting beside it, without the 15-minute limit of the verify after a full backup, so that on an installation whose
  verify always takes longer the backup targets stop holding every WAL segment once it reports ok.
- A restore to a point in time before a device's Destroy no longer brings that device's escrowed LUKS headers back:
  the escrow step of `./paddock restore` now reads the Destroy evidence from the audit index, which the restore does
  not touch, and keeps every covered header out. It runs in its own one-off service `backup-restore-escrow` (profile
  `restore`, never started by `./paddock up`), the only backup service that reaches the audit index. Each skipped
  device is listed on the terminal, and `platform.restore_completed` records the number of skipped headers as
  `escrow_skipped_destroyed`. If the audit index cannot be read, the escrow step fails and puts nothing back
  (`docs/operations/restore.md`).
- `./paddock restore` no longer leaves a plan half-recorded or a copy of the backup key behind when it is interrupted
  early: a signal between marking a restore plan `running` and the first step records the plan as failed and says that
  nothing on the host changed, and Ctrl-C during the final deletion of `.secrets/restore/backup_key` still removes the
  whole file.
- `./paddock upgrade` from 0.1.0-alpha.8 now removes the container of `fleet-backup-upload`, a service this release no
  longer has, right before `./paddock up`. Before, it kept running under the new release, uploading to the old backup
  bucket, and `./paddock down` did not stop it. Only the services a release retired are removed, never a volume; a
  rollback to 0.1.0-alpha.8 starts the service again.
- The backup role no longer spins a CPU core for hours on a large backup set. Deciding what a backup target may delete
  re-read the whole local set for every object the target held, so with a few hundred thousand files every mirror ran
  into the two-minute stall limit, kept computing after it, and no target received a current copy. The decision now
  takes time in proportion to the set, and a mirror that stalls stops its work at once.
- A mirror to a backup target that was given up as stalled no longer writes the target's `manifest.json` or any
  file of a mounted target after that point. The manifest now only follows a copy that was verified by a mirror
  still running.
- A mirror to an S3 backup target, or to a slow share, that holds a few hundred thousand objects no longer fails
  every round. Listing such a target can take several minutes. That time was taken for a stall, and later counted
  against the round's copy budget, so the mirror never got as far as removing expired copies and the target only
  grew. Listing now counts as progress page by page, and the round's budget only limits copying. A stall message now
  names what the mirror was doing, for example listing the target. After a long target outage the first mirror can
  take a while to remove the expired copies (see residual risk RR-126).
- A mirror to a mounted backup target (local, NFS or SMB) that was given up as stalled now also stops walking the
  share. Before, the walk ran to its end on a slow share and the next rounds skipped the target with "the previous
  mirror has not returned".
- After a restore or a rollback, devices again receive a newer configuration bundle right away, also when an earlier
  restore had already raised the bundle sequence (for example a restore after an upgrade, then a rollback). The restore
  now raises every device to the highest sequence the stack held before it went down plus 1,000,000, with the new
  command `paddock-server admin raise-bundle-seq --at-least N`, so the sequence grows by about 1,000,000 per restore. A
  disaster restore uses the new high-water file `bundle-seq/high-water` in the bundle directory, which the backup role
  updates after every successful round and `./paddock upgrade` carries into the new directory. Without either source
  the restore warns and raises by the previous fixed 1,000,000; an implausible value in the file stops the restore
  before anything changes.
- Actions Paddock takes on its own, outside an administrator's request (the import of the legacy backup key at the api's
  start, the backup role's finished and failed runs, the record of the IP allow list bypass at the api's start), are
  recorded in the audit trail again: they get a generated correlation ID, so the audit writer no longer rejects their
  events as incomplete.
- The diagnostics notice now reaches the logged-in user on Ubuntu 24.04 as well. The agent no longer tries to notify
  the login screen. A notice that cannot be delivered is logged at warn level with its cause, and the diagnostics
  list in the portal marks a bundle whose user was not notified.
- A backup is now recorded as soon as it is taken, no longer only after it was copied to every backup target.
  Before, a slow copy to a large target kept successful backups out of the history for hours, `paddock-server backup
  now --wait` waited as long, and restore plans did not see them. The copy results per target and the audit event
  follow when the copy ends; the event carries the time the backup itself completed. A copy that used up a round's
  time is shown as "continues next round" instead of an error.
- RabbitMQ's container health check no longer keeps about one CPU core busy on hosts with many cores. It now runs one
  check instead of two in a command-line runtime limited to one scheduler, and costs about a tenth of before. The
  broker is reported healthy as quickly as before.
- A Fleet backup is recorded as soon as its dump is sealed, also while the round's copy to the backup targets is still
  running. Before, it stayed "requested" until that copy ended, which on a large target could take hours, and
  `paddock-server backup now --wait` waited for it.

### Security

- A device with an issued Destroy can no longer escrow disk keys again: until the Destroy is confirmed, fails or
  expires, the server refuses every LUKS recovery key and header the device uploads (for example after it was offline
  and its keyslots changed), so no key material escrowed after the crypto-shredding decision is stored in the database
  or its backups. A sealed header object that still reaches the escrow bucket late (an upload URL issued before the
  Destroy) is unreadable, because its wrapped key is dropped, and is removed by the follow-up cleanup. Each refusal is
  audited once as `device.escrow_refused_destroyed` (classified by the Wazuh rule `100915` and the Sigma device
  integrity rule). The device sees the escrow as `refused` and retries at the pace of its escrow wait; agents of this
  release no longer treat a header answer without an upload URL as an error. Database migration `00109` runs
  automatically (`docs/operations/revocation.md`).
- The server's indirect dependency `golang.org/x/net` is updated from v0.61.0 to v0.62.0, which fixes
  CVE-2026-78661 (a denial of service in its HTML parser).

## [0.1.0-alpha.8] - 2026-11-04

An installation of 0.1.0-alpha.7 upgrades in place (`docs/operations/upgrade.md`, "From 0.1.0-alpha.8"): only
Paddock's own images change; no third-party image, Compose file, `.env` setting, database role or OpenBao change.
The control plane applies ten new migrations, the audit host has none. Upgrade the server first, then roll out this
release's agent. Installations of 0.1.0-alpha.6 or earlier still have no upgrade path and are installed fresh
(0.1.0-alpha.7 below).

Safe configuration changes (ADR 0033, plan M11): the server keeps what every device applied per resource and per
configuration version, every configuration write leaves a change set that can be reverted after a confirmation of
its inverse plan, and with rollouts enabled under Settings, Rollouts a change of managed files, units, package holds
or update settings reaches the devices in waves that advance on their own and halt at the failure threshold
(`docs/operations/configuration-rollouts.md`). An existing laptop is adopted after `paddockd preflight` and starts
report-only until an administrator enables enforcement (`docs/operations/enroll-existing.md`). Software catalog
(plan M13a): organization administrators register third-party APT sources with their verified signing key (step-up,
never through API tokens or the assistant), operators describe applications per distribution, release and
architecture and assign them as required, pinned, held, uninstalled or forbidden, and devices enforce the
assignments and report their state per application (`docs/operations/software.md`). On the device, the agent writes
`/etc/apt/sources.list.d/paddock-<slug>.sources`, `/etc/apt/keyrings/paddock-<slug>.gpg` and
`/etc/apt/preferences.d/51paddock-software` as a protected area; Paddock's own packages and the Himmelblau sign-in
stack can never be managed through the catalog. The agent also reports its os-release, so the device record follows
a distribution upgrade. The agent changes in this release; the supervisor and `paddock-revoke` do not.
`paddock-revoke` stays unsigned, and revocation (Lock, Destroy, dead man's switch) stays disabled behind
`PADDOCK_REVOCATION_ENABLED`.

Schema: migrations 00090–00099 (control-plane database; new tables, columns and grants only, 00097 fills its new
device columns from the existing device data); audit schema unchanged.

### Added

- Apply status of devices (plan M11, PDK-151): the server keeps what each device reports, per resource (applied, failed,
  pending in report-only, drift corrected) and per configuration version. New endpoints
  `GET /api/v1/devices/{id}/config-status`, `GET /api/v1/devices/{id}/bundles` and the fleet view
  `GET /api/v1/config-status`; the device detail carries the counts as `config_status`. The `device.bundle_applied`
  audit event records the apply mode.
- The portal shows what each device applied of its configuration: a device's *Apply status* tab lists every
  resource with its status (applied, failed, pending in a report-only apply, drift corrected), the message of a
  failure and the history of its configuration versions, and the new *Configuration status* page counts per
  resource on how many devices it failed, so an administrator sees why a laptop lacks the new configuration (PDK-152).
- Enrolling an existing device: `paddockd preflight [--json] [--config FILE]` checks an installed laptop read-only
  before adoption (OS, systemd, root, sudo, TPM, disk, sssd, Himmelblau, foreign sudoers files, privileged groups,
  server, clock), and the runbook `docs/operations/enroll-existing.md` describes the supported path.
- Every change to the configuration now leaves a change set, whether it comes from the portal, the API or
  `paddockctl apply`: single files, units, package holds, permission profiles, assignments, device groups and every
  settings page. A change set keeps what each change replaced or removed (the full file content included) for 90 days,
  so a later release can undo it; deleting a device group lists every definition that went with it. The change-set
  list and detail show whether the before-state is still stored, and the list can be filtered by rollout.
- A change set can be reverted: the change-set list and detail have a **Revert** action that shows the inverse plan
  in a confirmation dialog before anything changes, and `POST /api/v1/change-sets/{id}/revert` does the same through
  the API (`dry_run`, then `expected_plan`). The revert restores what the change set replaced or removed, deletes what
  it created and keeps everything created since; it is recorded as a change set of its own that links to the original
  and audited as `config.reverted`. Every rule of the original write applies again (organization administrators for
  settings and device group deletions, a step-up for full profiles). A change set that was already reverted, or whose
  previous state is no longer stored, cannot be reverted. The MCP tool `revertChangeSet` is marked destructive.
- Rollout settings (plan M11, PDK-156): an organization administrator configures staged configuration rollouts under
  Settings, Rollouts (`GET` and `PUT /api/v1/settings/rollout`, also an MCP tool): on or off (off by default), the waves
  (default 1, 10, 50, 100 percent), the minimum duration of a wave (default 60 minutes, at least 15), the failure
  threshold (default 2 percent and at least 3 devices) and an optional canary device group whose devices always go
  first. A change is audited as `settings.rollout_changed` with every field; deleting the canary group clears it. The
  settings only take effect for rollouts started after they were saved. Schema: migration `00092`.
- Staged configuration rollouts (plan M11, PDK-157): with rollouts enabled under Settings, Rollouts, a change of managed
  files, managed units, package holds or the update settings no longer reaches every device at once. It starts a
  rollout: the canary device group and the devices of the first wave receive it, every other device keeps the previous
  state of the changed items until a later wave reaches it; changes of other items still reach every device at once.
  While a rollout is open, a change of an item it stages is refused with 409 `rollout_conflict` and a further change
  of a section it stages with 409 `rollout_running`; reverting the rollout's change set ends the rollout. An urgent
  change skips the rollout with `urgent=true` and a reason (2 to 500 characters), needs a fresh step-up and is audited
  with the reason. The apply result, the change set and a device's bundle history name the rollout, and a device's
  effective configuration shows whether it is inside the current wave. Schema: migration `00093`.
  While a rollout is open, renaming or deleting a device group that scopes one of its staged items, or its canary
  group, is refused with 409 `rollout_conflict`; the files, units and holds of a deleted or renamed group change on
  every device at once and never start a rollout.
- Configuration rollouts advance and stop on their own (plan M11, PDK-158): every minute the worker checks each running
  rollout. When the devices in the waves reached so far that failed a staged item reach the failure threshold, the
  rollout is halted and audited as `config_rollout.halted` (a preset event of the security notifications); otherwise
  it moves to the next wave once the minimum wave duration has passed and completes after the last wave. Failures of
  items the rollout does not stage, and plan errors of a report-only device, never count; a device that never reports
  never counts either. Administrators and operators can halt a
  rollout with a reason, resume it, move it to its next wave at once or complete it so that every device receives the
  change (`POST /api/v1/config-rollouts/{id}/halt|resume|advance|complete`, also as MCP tools; halt, advance and
  complete are marked destructive); these actions work also after rollouts were switched off, and a resume starts the
  wave's minimum duration again. `GET /api/v1/config-rollouts` lists
  the rollouts with their counts of eligible, applied, failed and pending devices, `GET /api/v1/config-rollouts/{id}`
  shows one with its change set and staged resources, and `GET /api/v1/config-rollouts/{id}/devices` shows per device
  whether it is inside the wave, whether its newest bundle carries the change and the report the counts read; the
  counts are exactly what the worker evaluates. The worker exports
  the gauge `paddock_config_rollouts{status}`.
- Configuration rollouts in the portal (plan M11, PDK-159): the new *Configuration rollouts* page lists the staged
  rollouts with their status, wave and counts, and a rollout's page shows the waves with the current one and the canary
  group, the planned changes and the devices with their newest report, and halts (with a reason), resumes, advances,
  completes or reverts the rollout, each after a confirmation. Change sets show how they reached the devices
  (immediate, staged, urgent) and link to their rollout, and the bundle history of a device links to the rollout of a
  version.
- While staged rollouts are enabled, every form that writes a rollout-able section (managed files and units, package
  holds, update settings), their delete confirmations and the revert dialog offer *Apply immediately to every device
  (urgent)* with a required reason; the portal asks for the step-up the server requires and repeats the change.
  `paddockctl apply` prints `Rollout: staged (rollout <id>)` or `Rollout: urgent` after the change set; the urgent
  opt-out stays portal-only, because an API token never satisfies the step-up.
- Adopted devices start in report-only mode (plan M11, PDK-160): a device records how it was enrolled (`autoinstall`,
  `adopted`, or `unknown` for agents that send no method; any other value is refused with 400 `invalid_request`).
  An adopted device receives report-only bundles: its agent reports what it would change and changes nothing, so
  enrolling an existing laptop never cuts its user off. The method is the device's own claim and only selects the
  mode; it never grants more trust. The device header shows the chips *Adopted*/*Autoinstall* and *Report-only*, the
  *Apply status* tab shows the report-only notice and lists plan errors as their own state, the attention list and the
  findings show the new kind `report_only`, and the device list (`GET /api/v1/devices`, `paddockctl devices list`)
  filters by `enrollment_method` and `config_mode`. *Enable enforcement* on the device overview
  (`POST /api/v1/devices/{id}/enforce`, administrators and operators) is confirmed with the typed hostname, audited as
  `device.enforcement_enabled`, and makes the next bundle apply every managed resource; it is not offered to the
  assistant (MCP). Report-only devices are never part of a configuration rollout's waves and never count toward its
  failure threshold, and their plan errors never count as failed in the configuration status. Devices enrolled before
  this release are `unknown` and stay enforced.
- The agent applies a report-only bundle without changing managed configuration resources: it plans every resource
  and reports what it would change (`pending` with the planned changes, at most 50 lines per resource; plan errors as
  `failed` resources, not as apply errors), skips drift correction and the managed local administrator until
  enforcement is enabled (`rotate_admin_password` fails with reason `report_only`), and keeps checking in as usual.
  Agent and supervisor updates, disk encryption, revocation and the dead man's switch keep running.
- The agent reports the enrollment method: `autoinstall` on a device installed with the Paddock autoinstall,
  `adopted` otherwise; servers of earlier releases ignore the field. `paddockd enroll` and the agent's own enrollment
  never send two requests at the same time.
- Two operator guides: `docs/operations/configuration-rollouts.md` walks through a staged configuration change from the
  settings to the revert (waves, counts, halt, resume, advance, complete, the urgent opt-out and its audit trail, what is
  never staged, the audit codes), and `docs/operations/enroll-existing.md` now covers the report-only phase, enabling
  enforcement and the minimum agent release. The architecture document, the privacy document and the paddockctl page
  describe the same behaviour.
- The overview has a Configuration card: the open configuration rollout with its wave, failed devices and status, the
  number of failed resources and devices (plan errors of report-only devices are not failures), and the devices still
  in report-only mode, each linking to the matching page.
- Organization administrators can register third-party APT package sources (vendor or own repositories) with the
  admin API: `/api/v1/software-sources`. Each source carries its own OpenPGP signing key; the administrator types the
  key's fingerprint from the vendor's publication and Paddock refuses the source when it differs
  (`422 fingerprint_mismatch`). Sources use https only, keys must be RSA of at least 2048 bits (2048 to 3071 bits are
  marked `weak_key`) or Ed25519, Ed448 or NIST P-256/384/521. Adding, changing and removing a source is
  root-equivalent: it needs a fresh step-up, API tokens and AI assistant sessions cannot do it, and every change is
  audited with the key fingerprint (`software_source.created|updated|deleted`). Devices do not use the sources yet.
- Organization administrators and operators can describe the applications of their fleet in a software catalog with
  the admin API: `/api/v1/software-catalog` (name, description, category, optional package source, the package name per
  distribution, release and architecture, and a PNG icon) and assign them with an intent to the organization or a
  device group: `/api/v1/software-assignments` (required, pinned or latest; uninstall; hold a version; forbid). Entries
  and assignments are audited (`software_catalog_entry.*`, `software_assignment.*`); deleting an entry removes its
  assignments, and a package source that an entry uses cannot be removed (`409 in_use`). Devices do not enforce the
  assignments yet.
  Packages that Paddock itself needs cannot be managed through the catalog: the agent, supervisor, revocation tool,
  fleetd and the Himmelblau packages cannot be named in an entry (`400 invalid_request`); `sudo`, `cryptsetup`,
  `tpm2-tools`, `libpam-modules` and `dracut` cannot be forbidden or uninstalled, and `initramfs-tools` cannot be
  required or held, because installing it removes `dracut`.
- Device bundles (schema v2) now carry the device's desired software state as an optional `software` section: the
  packages its software assignments resolve to for the device's distribution, release and architecture, each with its
  intent, and the package sources (with their signing key) that required packages come from. Pinned and held catalog
  packages are merged with the package holds into the device's update settings, the smallest version winning. When a
  package is forbidden or to be uninstalled on a device, that wins over a package hold of the same package: the hold
  is left out of that device's bundle and the package is marked `superseded_hold`. A package source whose stored data
  no longer passes the current rules is left out of every bundle together with the required packages from it. A
  catalog entry or assignment that no longer passes them, or a software result that would touch a package Paddock
  depends on, keeps every device it applies to on its previous bundle (`device.bundle_render_failed` names the entry);
  the rest of the organization is compiled as usual. Older agents ignore the section; agents do not enforce it yet.
- Package source URIs containing U+FFFD are now refused (`400 invalid_request`); the upload and the bundle use one URI
  rule.
- Changing a catalog entry's packages is refused (`400 invalid_request`) when one of its existing assignments could
  not be created for the new packages, e.g. an entry with a forbid assignment cannot be changed to a package Paddock
  depends on.
- Administrators can see which devices have an application installed and in which state. A device's check-in now
  carries the state of its catalog applications (installed, held, absent, pending, failed; at most 200 items), and the
  admin API lists it on the application, `GET /api/v1/software-catalog/{id}/devices`, and on the device,
  `GET /api/v1/devices/{id}/managed-software`. An application assigned to a device that has no package for its
  operating system and architecture shows as `not_applicable`, one that has not been reported yet as `unknown`.
  The check-in accepts up to 96 KiB (was 64 KiB) so that a full software report never makes it fail.
- Devices now enforce their software catalog assignments: the agent adds the assigned APT sources with their signing keys
  (refusing a key whose fingerprint does not match), installs required applications, reinstalls one a user removed,
  removes and blocks uninstalled or forbidden ones, and reports every change and failure in the audit trail and in the
  device's software status. Removals wait while the server is unreachable, an installation that would remove other
  packages is refused, and an uninstall removes the software sources while the installed applications stay.
- Catalog entries and assignments refuse package names that apt would read as a pattern selecting one of Paddock's
  protected packages (for example `himmelblau.` or `sud.`), and devices never hand apt a package name it does not know
  exactly. When the last software assignment of a device goes away, the device removes the sources, keys and blocks
  Paddock wrote for it and leaves everything else in place.
- Package holds, install-now requests and the removal of Paddock pass a package name to apt only when apt knows exactly
  that name; anything else is reported as failed and never reaches apt.
- Package sources, software catalog and managed software in the portal (plan M13a): administrators add trusted
  package sources (https only, signing key and its fingerprint, with a security key and a typed name to remove one),
  operators describe applications in the new software catalog and assign them to device groups as required, pinned,
  held, uninstalled or forbidden, and everyone with read access sees per application and per device whether it is
  installed, held, pending or failed. A device's new *Managed software* tab lists what the catalog manages there,
  including applications that do not apply and those not reported yet.
- Software catalog operations guide (plan M13a): `docs/operations/software.md` explains how to add a package source
  with its verified vendor fingerprint, how catalog entries name packages per distribution, release and architecture,
  what each intent does on the device, every state and reason a device reports, troubleshooting and the uninstall
  rule. The residual risks RR-77 to RR-83 are in the ISMS register, and the system gate `TestSoftwareGates` proves the
  enforcement on the test VMs.
- Operating system changes (PDK-695): the agent reports the `ID` and `VERSION_ID` of its os-release with every
  check-in, and the device record follows a distribution upgrade (for example Ubuntu 24.04 to 26.04). Each change is
  recorded once as the audit event `device.os_release_changed` (old and new ID and VERSION_ID), and the device is
  recompiled so that release-specific configuration resolves against the release it runs now. The compiler's reconcile loop also
  recompiles a device that reports an architecture for the first time or a different one. Agents of earlier releases send no
  os-release and keep the value from enrollment.
- The software API now reports more for the portal's software pages: each software source shows how many catalog
  entries use it, and the device list of an application shows each device's name and its device groups next to the
  hostname. The list can still be narrowed to one device group.

### Changed

- The `bundle.applied` device event now carries the apply mode and one outcome per resource (applied or
  failed with its message), next to the existing error list.
- Installing managed software can no longer remove packages the agent's pre-check did not show (PDK-712), and an
  installation that would install, upgrade or remove one of Paddock's own packages or the Himmelblau sign-in stack is
  refused before anything changes, reported with the reason `protected_package_affected`. Upgrading a package Paddock
  depends on, such as sudo, stays allowed; removing it stays refused.
- Retention schedule (ADR 0032 amendment 2026-11-04): the stores of the safe configuration changes and the software
  catalog now have rows in `docs/compliance/retention.md` with their retention, the job that deletes them and the
  audit event that proves it. The software status of retired devices and the change-set and rollout history are
  recorded as not purged yet, with follow-up tickets.

### Fixed

- `paddockd preflight` no longer reports the operating system as unreadable on Ubuntu, where `/etc/os-release` is a
  link to `/usr/lib/os-release`; the check reads the linked file.
- A managed software source that repeats a repository the device already has with another signing key no longer breaks
  the device's package manager (PDK-710): the agent checks the whole APT configuration after writing a source, removes
  only its own source file and keyring again when they conflict, and reports the source as failed with the reason
  `conflicting_source` and the repository's address. The device's own entry is never changed. A failing package lookup
  is now reported as an APT failure instead of an unknown package name.
- Packages installed for two architectures (for example with Steam or Wine on a device with i386 enabled) are now
  reported as installed: a forbidden one is removed for every architecture instead of being reported absent, and a
  required one is no longer reinstalled and reported failed on every pass.

## [0.1.0-alpha.7] - 2026-11-02

**Breaking: there is no upgrade path from 0.1.0-alpha.6 or earlier.** PostgreSQL moves to 18 (new data directory
layout), Valkey to 9.1.3, RabbitMQ to 4.4.0 and Fleet's MySQL to 8.4.13; none of them opens the data of the previous
release. Install this release fresh and enrol every device again (`docs/operations/upgrade.md`, "From
0.1.0-alpha.7"): the databases, OpenBao with its keys, escrowed recovery keys and enrollments of the old installation
are lost with it.

AI assistants through the MCP (ADR 0044, plan M14): administrators sign in with `paddockctl mcp login` (Authentik,
passkey) and connect Claude Code or another MCP client to `paddockctl mcp`; organization and platform MCP policies and
a personal write opt-in decide what the assistant may do, step-up actions stay in the portal, and the MCP is off until
a policy is saved. Notifications and findings (plan M9): the new role `paddock-notifier` delivers security events to
signed webhooks and e-mail lists, the audit cursor feed serves SIEM pulls, findings record the reaction to every
tamper event and attention condition, devices report a stopped third-party service (watched units), and the worker
summarizes new critical vulnerabilities once a day. Evidence and privacy (ADR 0032, plan M10): signed evidence exports
of the audit log with offline verification (`paddockctl audit verify-export`), per-organization privacy settings,
read-access recording, a retention round for every store with its retention schedule, and the privacy and works
council pack. The portal shows a setup checklist with the getting-started guide, signs every administrator in with a
passkey and ends the Authentik session at sign-out. Authentik runs 4 web workers. The agent and the supervisor change
in this release (watched services, cancelled or failed in-place encryption is disarmed, stuck supervisor-upgrade
markers, an interrupted self-test no longer fails a rollout): enrol the devices of the new installation with this
release's agent packages. `paddock-revoke` stays unsigned, and revocation (Lock, Destroy, dead man's switch) stays
disabled behind `PADDOCK_REVOCATION_ENABLED`.

Schema: migrations 00072–00088 (control-plane database) and audit migrations 00007–00010 (audit database); fresh
installation only, no upgrade path from 0.1.0-alpha.6 or earlier.

### Added

- A second development stack on the same host (PDK-519): `PADDOCK_INSTANCE=2 make dev-secrets` in a second checkout
  writes a `.env` with its own Compose project (`paddock2`), image tags and host ports (every port 100 higher: HTTPS
  `8543`), and every `make` target and acceptance and end-to-end gate of that checkout then reaches that stack. The
  loopback ports of the development stack are settings (`PADDOCK_DEV_*_PORT`); unset, nothing changes. A command with
  a `PADDOCK_INSTANCE` other than the checkout's is refused. See "Running a second dev stack" in
  `docs/operations/local-dev.md`.
- The system gates on the test VMs run against the stack of their checkout (PDK-525): from a second development
  stack's checkout they use its Compose project and HTTPS port, e.g. when they cut a device off from the server.
- MCP tool catalog generated from the admin API contract (ADR 0044, PDK-434): `make gen` derives one tool per admin
  API operation (outside the login tag) from `api/openapi/admin.yaml`, classified as read or write, with scope,
  destructive and idempotent hints and a self-contained input schema. The contract gains the extensions
  `x-paddock-step-up: true` (operations that always need a step-up; never offered as tools) and `x-paddock-mcp`
  (`expose: false` keeps an operation out of the MCP, `bootstrap: true` marks the operations an MCP session may call
  before its policy is consulted). API tokens, profile changes and the release source check are never offered; nor
  are uploads and downloads. The contract lint fails when the step-up flag and the server's route table disagree or
  when an offered write operation is not audited. No runtime behaviour changes yet.
- MCP groundwork in the server (ADR 0044, PDK-435): migration `00072_mcp` adds the per-account MCP write opt-in
  (`mcp_write_enabled_at` on `admin_account` and `platform_admin`) and the MCP policy tables of the organizations and
  the platform (both off by default). `GET /api/v1/me` answers `channel` (`portal`, `api` or `mcp`); audit events of
  an MCP session carry `source: mcp` and the client's name in `actor.client`, and `admin.login` records the param
  `channel` (`portal` for every portal sign-in). The `action` table keeps the source of each action, so an action that
  gets stuck and is finalized as unknown keeps `source: mcp`. An MCP session never satisfies a step-up (403
  `step_up_required`). New problem codes `mcp_disabled`, `mcp_tool_not_allowed`, `mcp_write_not_enabled`,
  `rate_limited` and `mcp_login_required`. No MCP session can be opened yet.
- MCP login through Authentik (ADR 0044, PDK-436): a new Authentik blueprint `paddock-mcp.yaml` adds the public
  provider and application `paddock-mcp` (device authorization grant, the portal's login flow, the device providers'
  MFA authorization flow, 30-minute access and 8-hour refresh tokens; one-minute access tokens in development). The
  api reads `PADDOCK_OIDC_MCP_ISSUER` (empty turns the MCP login off; `compose.yaml` sets it for `paddock-api`) and
  `PADDOCK_OIDC_MCP_CLIENT_ID` (default `paddock-mcp`) and serves `GET /api/auth/mcp/config`,
  `POST /api/auth/mcp/session` and `POST /api/auth/mcp/logout`. A session call verifies the Authentik tokens,
  resolves the role like a portal sign-in (`role: platform` picks the platform role of a two-role identity) and records
  `admin.login` with `channel: mcp`; renewals with refreshed tokens are bound to the MFA-checked login and its role for up to
  8 hours and recorded with `renewal: true`; a renewal whose groups resolve another role ends the account's sessions. A
  token pair opens one session only; a replayed login token is refused. The access token then authenticates admin API requests as a bearer with
  channel `mcp`; logout, *End all sessions*, deactivation and a role change end it, the latter two also at the next
  request. Refused `admin.login` attempts of the portal now carry `channel: portal` as well. New metric
  `paddock_mcp_auth_total{result}`. The step-up routes refuse an MCP access token (403).
- MCP policies and the personal MCP write opt-in (ADR 0044, PDK-437): `GET`/`PUT /api/v1/settings/mcp` (organization)
  and `GET`/`PUT /api/platform/v1/settings/mcp` (platform) hold whether the MCP is enabled, whether it may change
  data, and whether all or only selected tools are allowed. Without a saved policy the MCP is off. Changing a policy
  needs an organization or platform administrator with a step-up and is audited as `organization.mcp_policy_changed`
  or `platform.mcp_policy_changed`; selected tools must be offered MCP tools that need no step-up (at most 500).
  `POST /api/v1/me/mcp-write/enable` (step-up) and `…/disable` let administrators and operators opt their own account
  in to or out of MCP write access, audited as `admin.mcp_write_enabled` and `admin.mcp_write_disabled`; auditors, API
  tokens and MCP sessions are refused (403 `forbidden`). `GET /api/v1/me` answers `mcp_write_enabled`. The policies
  are not enforced yet.
- MCP policies are enforced (ADR 0044, PDK-438): every admin API request of an MCP session is checked before it runs
  against the shared tool catalog, the policy of its scope and the account's write opt-in, and refused with 403
  `mcp_disabled`, `mcp_tool_not_allowed` (also for every operation the MCP never offers, such as step-up actions and
  the MCP settings themselves) or `mcp_write_not_enabled`; a refused change is audited once as denied with
  `source: mcp`, a refused read is not. MCP sessions are limited to 120 reads and 30 changes per account and minute
  per api replica (429 `rate_limited` with `Retry-After`); portal sessions and API tokens are neither checked nor
  limited. `GET /api/v1/me`, `GET /api/v1/mcp/access` (what the caller's MCP sessions may do) and
  `GET /api/v1/mcp/catalog` (the tool catalog) always answer. New metric `paddock_mcp_requests_total{class, result}`.
  An MCP session calling `POST /api/v1/me/mcp-write/enable` or `…/disable` now gets 403 `mcp_tool_not_allowed`.
- The audit index numbers every event per organization in the order the audit writer committed it (`commit_seq`), so
  consumers can read the audit trail without skipping late events from offline devices and can detect gaps. The
  upgrade numbers the existing events once; plan about 1.5 minutes per million audit events. The upgrade procedure
  has a new step: when audit migrations are pending, stop the audit writer before `./paddock up`, so that new events
  wait in its queue (`docs/operations/upgrade.md`). An event that a concurrent writer indexed first now fails the
  batch and leads to a redelivery instead of being skipped.
- Audit cursor feed: `GET /api/v1/audit-events/feed?after=&limit=` lets an auditor or administrator (session or API
  token) read every audit event of the organization exactly once in commit order, for a SIEM pull that catches up
  after an outage. It is not offered to MCP clients.
- Groundwork for notifications (plan M9, PDK-122): the control-plane database gains the notification tables
  (destinations, their delivery state, deliveries, pseudonym keys and lookups) under row-level security, and the new
  database role `paddock_notifier`, which reads destinations and records deliveries but cannot change destinations.
  OpenBao gains the derived Transit keys `notification-wrap` and `notification-pseudonym` (AES-256-GCM, bound per
  organization): the api may only encrypt destination secrets and obtain wrapped pseudonym keys, the new AppRole
  `paddock-notifier` may only decrypt them. Nothing is delivered yet. A cluster initialized before this change needs the one-time role creation of
  `docs/operations/upgrade.md` ("Notifications on a cluster initialized before them") and a re-run of
  `./paddock bootstrap openbao`.
- Notification destinations in the admin API (plan M9, PDK-123): organization administrators declare where their
  security events go (`/api/v1/notification-destinations`), platform administrators the same for platform events
  (`/api/platform/v1/notification-destinations`): a signed webhook or an e-mail address list, the event filter
  (security preset, all, or a custom list of audit codes), and whether user names are pseudonymized. The webhook URL
  and its signing secret are stored encrypted; the secret is shown once at creation and on rotation, the URL never
  (only scheme, host and a masked path). Every change, the secret rotation, a test request and a pseudonym lookup need
  a step-up and are audited (`notification.destination_created`, `…_updated`, `…_deleted`, `…_secret_rotated`,
  `notification.test_requested`, `notification.pseudonym_resolved`); auditors see the configuration. E-mail
  destinations are accepted only when the api runs with `PADDOCK_SMTP_ENABLED=true`
  (`GET /api/v1/notification-capabilities`). Nothing is delivered yet.
- Webhook delivery of notifications (plan M9, PDK-124): the new role `paddock-server serve notifier` reads each
  organization's and the platform's audit index in commit order and posts the matching events to the webhook
  destinations as signed JSON (`paddock.notification.v1`; headers `X-Paddock-Timestamp`, `X-Paddock-Signature`
  `v1=<HMAC-SHA256>`, `X-Paddock-Delivery`, `X-Paddock-Destination`), at most 100 events per delivery with a contiguous
  per-destination `forward_seq`, so a receiver notices any gap. A failed delivery is retried with the same numbers
  (5 s doubling up to 10 minutes) and nothing is skipped; a destination failing longer than
  `PADDOCK_NOTIFY_STALL_AFTER` (default 15 minutes) is marked stalled. Requested test deliveries, heartbeats and
  pseudonym lookups are served by the notifier as well. New audit events `notification.delivered`,
  `notification.destination_stalled` and `notification.destination_resumed`; the notifier records
  `notification.test_sent` for every test. Metrics `paddock_notify_deliveries_total`,
  `paddock_notify_destination_stalled`, `paddock_notify_lag_seconds`, `paddock_notify_round_seconds` and the alert
  `PaddockNotificationStalled`. Configuration: `PADDOCK_DB_NOTIFIER_URL_FILE`, `PADDOCK_NOTIFY_POLL_INTERVAL`
  (default 30 s), `PADDOCK_NOTIFY_STALL_AFTER`, `PADDOCK_NOTIFY_BATCH` (1–100); `PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE`
  is refused outside development and reported by `prod-check`. Webhooks are called directly, never through a proxy.
  The production Compose files and the bundle gain the role separately; the development stack runs it already.
- E-mail delivery of notifications (plan M9, PDK-125): the notifier sends e-mail destinations one plain-text message
  per delivery through the operator's SMTP relay, to all recipients at once, with the headers `Auto-Submitted:
  auto-generated`, `X-Paddock-Delivery`, `X-Paddock-Destination` and `X-Paddock-Forward-Seq`. A message shows at most
  50 events in detail (time, code, outcome, device or target, actor, portal link; parameters only with
  `include_params`; pseudonymized administrator names with `pseudonymize_users`) and summarizes the rest per code. After
  each message the destination waits `email_min_interval_s` (digest). Failures are recorded as `smtp_dial`, `smtp_tls`,
  `smtp_auth`, `smtp_timeout` or `smtp_<reply code>` with the same retry and stall rules as webhooks. Configuration of
  the notifier: `PADDOCK_SMTP_HOST` (empty = no e-mail), `PADDOCK_SMTP_PORT` (default 587, 465 with implicit TLS),
  `PADDOCK_SMTP_TLS` (`starttls` default, `implicit`; `none` only with `PADDOCK_ENV=development`),
  `PADDOCK_SMTP_USERNAME` with `PADDOCK_SMTP_PASSWORD_FILE` (PLAIN, LOGIN or CRAM-MD5, only ever over TLS),
  `PADDOCK_SMTP_FROM` (required with a host), `PADDOCK_SMTP_TIMEOUT` (default 30 s) and optionally
  `PADDOCK_SMTP_CA_FILE` for a relay certificate of an internal CA. The relay's certificate is always verified; a relay
  that does not offer STARTTLS is refused.
- Findings record the reaction to security events: every tamper event of a device opens a finding (repeated events of
  the same device and subject are counted on the open one), and every attention condition becomes a finding that is
  cleared once the condition is gone. Administrators and operators acknowledge, assign, close (resolved, accepted risk
  — administrators only — or false positive, always with a reason) and reopen findings through
  `/api/v1/findings`; each step is an audit event (`finding.acknowledged`, `finding.assigned`, `finding.closed`,
  `finding.reopened`). The attention lists show the finding of each condition, and `GET /api/v1/accounts` lists the
  organization's accounts for the assignee choice (PDK-126).
- The portal has a Findings page for the findings of your devices: filter and search them, acknowledge a finding, assign
  it to an administrator or operator, close it with a resolution and a required reason (accepted risk is for
  administrators only), or reopen it with a reason. Every step asks in a modal and shows the new status; the attention
  list and the device page show the status of the finding next to each condition (PDK-127).
- The portal has a Notifications page for organizations (Organization > Notifications) and one for the platform
  (Platform > Notifications): add a signed webhook or an e-mail list, choose which events it receives, see whether
  delivery works and since when it lags, send a test, replace the signing secret and delete a destination. The signing
  secret is shown once, enabling a disabled destination asks whether to deliver or skip the events in between, and
  organization administrators can resolve a pseudonym back to a user name. Changes ask for a fresh identity
  confirmation; the e-mail type appears only when the installation has an e-mail relay (PDK-128).
- Critical vulnerability summary (plan M9, PDK-129): once per UTC day and organization the worker records `vulnerability.critical_summary` when critical vulnerabilities were found on devices since the previous summary (the first covers 24 hours). It names the number of findings, the number of devices and up to 20 CVE ids, and belongs to the security preset, so a notification destination on that preset is told about new critical exposure without receiving the inventory.
- Presence policy, server side (plan M9, PDK-130): an organization administrator lists the third-party systemd services
  (for example `wazuh-agent.service` of an EDR or SIEM agent) that the devices should report when they stop, with
  `GET|PUT /api/v1/settings/watched-units`, on the new portal page Settings > Watched units, or as
  `settings.watched_units` in the declarative document (`paddock.yml`). Changing the list needs a step-up and is
  audited as `settings.watched_units_changed` with the added and removed units. At most 32 services; Paddock's own
  units and the protected prefixes are refused. Every v2 bundle of the organization carries the list as the `watch`
  section (absent while the list is empty); agents that do not know the section ignore it. Paddock only reports a
  stopped unit and never installs, starts or restarts it.
- Presence policy, agent side (plan M9, PDK-131): the agent checks the organization's watched third-party services on
  every bundle apply and drift pass and reports one that is not running as `device.tamper_service_stopped` with the
  unit and its state (`inactive`, `failed`, or `missing` when the unit is unknown to systemd), once per stop; a
  service that runs again and stops later is reported again. The agent never starts, stops, enables, masks or
  installs a watched service; to keep a service running, manage it as a unit resource.
- The notifier ships in the operator bundle (plan M9, PDK-132): `./paddock up` starts the new role `paddock-notifier`
  on the control plane and on a lab host, hardened like every role, with TLS to OpenBao, scraped by Prometheus
  (`paddock-notifier:9090`). `.env` gains `PADDOCK_SMTP_ENABLED` (default `false`) and the commented SMTP relay settings
  `PADDOCK_SMTP_HOST`, `PADDOCK_SMTP_PORT`, `PADDOCK_SMTP_TLS`, `PADDOCK_SMTP_USERNAME` and `PADDOCK_SMTP_FROM`;
  `./paddock secrets` creates the notifier's database URL, its AppRole placeholders and an empty `.secrets/smtp_password`
  (the relay password, only with a username). `./paddock check` refuses `PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE`,
  `PADDOCK_SMTP_TLS=none`, and a `PADDOCK_SMTP_ENABLED` that does not match whether `PADDOCK_SMTP_HOST` is set (item
  `notifications: SMTP presence flag matches the relay`). A cluster that already runs needs the database role
  `paddock_notifier` and `./paddock bootstrap openbao` before the upgrade (`docs/operations/upgrade.md`, *Notifications
  on a cluster initialized before them*). Development stacks: run `make dev-secrets` once for `.secrets/smtp_password`.
- Operator documentation for the notifications of plan M9 (PDK-133): `docs/operations/notifications.md` (webhook and
  e-mail destinations, the envelope and its signature with verification snippets in Python and Go, retry and stalling,
  pseudonyms, troubleshooting by error class), `docs/operations/siem.md` (the audit cursor feed and a pull loop for a
  SIEM) and `docs/operations/third-party-agents.md` (the presence policy and a privacy-minimal Wazuh agent); the
  compliance pack gains "What leaves the server", two residual risks, the A.5.25 and A.5.26 controls and the retention
  rows of the new tables.
- The security preset of notification destinations now includes `audit.export_requested` and
  `audit.export_downloaded`, so a destination that filters on security events is told when an evidence package is
  requested or downloaded.
- `paddockctl audit feed` reads the audit cursor feed as JSON lines (optionally following it), and `paddockctl findings list`
  lists findings with status, kind and cleared filters, so SIEM pulls and scripts need no hand-written `curl` loops.
- Retention schedule (`docs/compliance/retention.md`, ADR 0032): how long Paddock keeps every store, on which legal
  basis, which job deletes it and which audit event (`retention.purged`, `device.inventory_purged`) proves the
  deletion, with the deletion lag in backups, the handling of erasure requests and what is not purged yet. The privacy
  document, the ISO/IEC 27001 mapping (new rows A.5.28, A.5.34, A.8.10), the residual risks (RR-94 to RR-96) and the
  audit bucket runbook follow the schedule.
- Privacy settings per organization (ADR 0032 §2, PDK-136): `GET`/`PUT /api/v1/settings/privacy` and the portal page
  *Privacy settings* (`/settings/privacy`, organization administrators change them, operators and auditors read them)
  set how many days the inventory of a retired device is kept (`retired_inventory_days`, 1–365, default 30) and
  whether searches of the audit log (`audit_search_recorded`) and views of device inventory
  (`inventory_view_recorded`) are recorded (both off by default). Every change is recorded as
  `settings.privacy_changed` with the three values. `paddock.yml` gains the section `settings.privacy`, exported by
  `paddockctl get config` and applied by `paddockctl apply` like `settings.updates`. The settings take effect with the
  retention job and the read-access recording that follow. Schema: migration `00074`.
- One retention round in `paddock-worker` (ADR 0032, PDK-137) replaces the login history purge: every 6 hours
  (`PADDOCK_RETENTION_INTERVAL`, a Go duration between `1m` and `24h`; `paddock prodcheck` fails on any other value) it purges,
  per organization, the login history and the users seen on devices whose last login is older than 365 days. It deletes
  in batches of 1 000 rows, each committed on its own so device logins do not wait for a long purge; one purge runs
  for at most 5 minutes, and a larger backlog continues in the next round. Each purge that
  finds expired rows is recorded as one `retention.purged` event with its store (`device_login_event`,
  `device_user_seen`), the cutoff and the number of deleted rows; when a batch fails, the event has outcome failure and
  counts the rows of the batches committed before it. New metrics
  `paddock_retention_last_success_timestamp_seconds{store}`, `paddock_retention_deleted_total{store}` and
  `paddock_retention_stores`, alerts `PaddockRetentionPurgeStale` (critical, a store not purged for 48 hours) and
  `PaddockRetentionPurgeMissing` (warning). Schema: migration `00075` (the worker may delete users seen on devices; an index for the purge).
- The worker's retention round (ADR 0032, PDK-138) deletes the inventory of retired devices: once a device has been
  retired for the organization's `retired_inventory_days` (privacy settings, default 30), its software, vulnerability
  findings, policy results and hardware facts are deleted in Paddock and its host is deleted in Fleet, longest retired
  first and as many devices per organization as the pass's time budget allows. Each device is recorded as one
  `device.inventory_purged` event with the deleted counts, whether the Fleet host was deleted and, in
  `fleet_host_in_use`, why it was kept. While Fleet is unavailable the event has outcome failure
  (`upstream_unavailable`), nothing is deleted in Paddock and the device is retried in the next round; a device that
  fails does not hold up the others. After three Fleet failures in a row the round stops asking Fleet and records one
  `retention.purged` failure (`store` `retired_inventory`, `upstream_unavailable`) per organization it skipped. A
  Fleet host that a device of any organization still references is kept. While an active, quarantined or pending
  device of the same hardware has not synced its inventory yet, the host and the retired device's host reference are
  kept and the device is checked again every round. `paddock_retention_stores` is now 3 (new store
  `retired_inventory`, whose `paddock_retention_deleted_total` counts purged devices).
- Read-access recording (ADR 0032 §4, PDK-139): while an organization switches it on in its privacy settings, a
  search of the audit log (`GET /api/v1/audit-events`, also through the MCP and with API tokens) is recorded as
  `audit.searched` once per actor, clock hour and set of filters, with its filters and whether a search text was used
  but never the text (searches that differ only in their text share one event); a `target_id` that is not a device of
  the organization is recorded only as `target_id_used`. A view of a device's software or vulnerabilities is recorded
  as `device.inventory_viewed` once per actor, device and UTC day. While recording is on, a refused search or view
  (invalid range or paging, missing device) is recorded as a failure with its reason; a view of a device outside the
  organization records only `target_id_used`, never the device ID. When the switch cannot be read, the read fails and
  nothing is recorded. A role that may not read the audit log is recorded as denied. The coalescing keys are kept 48 hours; the worker's retention round deletes older
  ones as a fourth pass with a `retention.purged` event (store `read_audit_window`), and `paddock_retention_stores` is
  now 4. Schema: migration `00079`.
- Audit index purge (ADR 0032, PDK-140): the audit writer drops a monthly partition of the audit index every night at
  01:15 UTC once every event in it was recorded more than `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` ago (default and
  minimum: `PADDOCK_AUDIT_RETENTION_DAYS`, so the index never goes ahead of the WORM retention). Each drop is recorded
  as `retention.purged` (store `audit_index`) in the platform pseudo-organization; the WORM bucket, `audit_object` and
  `audit_manifest` are never touched. New command `paddock-server audit purge [--dry-run]`, metrics
  `paddock_audit_index_purge_last_success_timestamp_seconds` and `paddock_audit_index_partitions_dropped_total`, and
  the warning `PaddockAuditIndexPurgeStale`. Audit migration 00007 adds the owner-executed function
  `audit_purge_partition`; the writer role still holds no `DELETE` on the index.
- Privacy and works council pack (`docs/compliance/privacy-pack/`): four templates the operator completes, not legal
  advice: a transparency notice for employees (GDPR Art. 13), input for the record of processing (Art. 30) with one
  table per processing activity, input for the data protection impact assessment (Art. 35) with the risks from the
  employee's perspective, and an annex for the works council agreement (BetrVG § 87(1) no. 6) with every data
  category, the portal pages that show data about persons, the roles, the privacy switches with their agreed values
  and the change procedure.
- Evidence export requests (ADR 0032 §5, PDK-142): organization administrators and auditors request a signed
  evidence package for a range of sealed recording days with `POST /api/v1/audit/exports` (`from_day`, `to_day`,
  `purpose`) after a step-up, and follow their requests with `GET /api/v1/audit/exports` (list contract: sort,
  search over purpose and requester, `status` filter) and `GET /api/v1/audit/exports/{id}`. `to_day` is at most 400
  days after `from_day`, both days must be sealed (`422 day_not_sealed`), and at most two exports of an organization may be pending or
  running (`409 too_many_exports`). Every request is recorded as `audit.export_requested`; MCP sessions and API tokens
  are refused like every step-up action. The package itself is built by a later release; until then a request stays
  `pending`. Schema: audit migration `00008` (the audit reader role may now insert pending export requests and read the
  organization's audit objects).
- Evidence package builder (ADR 0032 §5, PDK-143): the audit writer builds every requested evidence export without
  operator action. The package is a tar of the signed daily manifests, every audit object they list byte for byte,
  the decoded events (`events.jsonl`), a canonical `export.json` (schema `paddock.audit-export.v1`, organization named
  by its ID) and its signature `export.sig` with the `audit-chain` key. A chain with problems is still delivered with
  `verify_ok=false` and the problems listed; a range with a day without a manifest fails. Exports become `ready`
  (downloadable for 7 days, then `expired` and deleted with a `retention.purged` event of store `audit_exports`) or
  `failed`; an export left `running` for 2 hours is failed as "exporter restarted". Each build is recorded as
  `audit.export_completed`. New: `PADDOCK_AUDIT_EXPORT_POLL_INTERVAL` (`paddock-audit-writer`, default `30s`),
  metrics `paddock_audit_export_total{result}`, `paddock_audit_export_pending_age_seconds`,
  `paddock_audit_export_build_seconds`, alerts `PaddockAuditExportFailed` and `PaddockAuditExportStuck`.
- Evidence package download (ADR 0032 §5, PDK-144): `GET /api/v1/audit/exports/{id}/download` streams the package of a
  ready export (`application/x-tar`) to an `org_admin` or `org_auditor` with the session. The response carries the
  package size as `Content-Length`, the file name
  `paddock-audit-export-<organization slug>-<from_day>_<to_day>-<first 8 hex of the id>.tar` and the package's SHA-256 as
  `X-Paddock-Package-SHA256`, so the file can be checked after the transfer. An export that is pending, running, failed
  or expired answers `409 export_not_ready`; another organization's export answers `404 not_found`. Every download
  attempt is recorded as `audit.export_downloaded` before the first byte is sent (range, size and checksum of the
  package). No range requests; a broken transfer starts again from the beginning.
- Evidence exports in the portal (ADR 0032, PDK-145): organization administrators and auditors request, follow and
  download signed evidence packages of the audit log on the new page *Evidence exports* (Audit log, navigation). The
  request needs a step-up; the page shows status, purpose, requester, size and the chain check of every export, offers
  the download of ready packages and lists the signing keys with their fingerprints to compare with an independently
  recorded value.
- Offline verification of evidence packages (ADR 0032, PDK-146): `paddockctl audit verify-export <file>
  [--fingerprint <hex>] [-o text|json]` checks the package signature against the audit-chain key fingerprint the
  auditor obtained out of band, every manifest signature and link, every object hash and that `events.jsonl` equals the
  decoded objects, and lists all problems. It needs no configuration, token or network and never extracts the package.
  Exit 0 = verifies, 1 = problems, 2 = usage or unreadable file. See `docs/operations/paddockctl.md`.
- Audit signing keys (ADR 0032 §5, PDK-148): the audit writer publishes the public key of every `audit-chain` version it
  signs with (daily manifests and evidence packages) in the audit database, insert-only. `GET /api/v1/audit/keys`
  (roles `org_admin`, `org_auditor`) lists them by version with their SHA-256 fingerprints, so an auditor can compare
  the fingerprint named in an evidence package with a value recorded independently. `paddock-server audit keys` (in the
  audit-writer container) prints `audit-chain v<N> <fingerprint>` per version straight from OpenBao for that
  out-of-band copy. A seal or export whose key cannot be published, or differs from the key already
  published for that version, fails instead of signing with an unpublished key; the seal-staleness alert surfaces it.
- Retention of control-plane history (ADR 0032 amendments 2026-10-18 and 2026-10-31, PDK-180): the worker's retention
  round now deletes finished device commands, cleared device alerts, filled event gaps and finished actions (the
  control-plane origin of audit events) once they lie before the start of the UTC month containing now −
  `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` − 7 days, the oldest month the audit index may still show plus a margin for a
  late index purge, audit events indexed late after an outage and clock skew. It deletes per organization, and the
  platform pseudo-organization's actions once per round, in batches of 1 000 with one `retention.purged` event per store
  (`device_command`, `device_alert`, `device_event_gap`, `action`) that records the index retention as `index_days`.
  Open alerts, unfilled gaps, unfinished commands, started actions and commands a disk conversion or an uninstall still
  references stay. The database keeps a finished action unchanged for every role and an action in the organization it
  was started in. `paddock_retention_stores` is now 8. Schema: migrations `00080`–`00083`.
- Upgrade: the control plane's `.env` (and a lab host's) must now set `PADDOCK_AUDIT_INDEX_RETENTION_DAYS`, to the
  audit host's value (`.env.example` sets 400). The worker reads it without a default of its own and does not start
  when it is missing, not a number, below 400 days or below `PADDOCK_AUDIT_RETENTION_DAYS`; `./paddock check` reports
  it, and every other `./paddock` command keeps working (`docs/operations/upgrade.md`). On a two-host installation
  keep both audit variables the same on the control-plane and the audit host.
- Documentation: guide `docs/operations/getting-started.md`, one path from the first platform administrator to the
  first configured device, including the route for an already installed device.
- `paddockctl mcp` (ADR 0044, PDK-439): `paddockctl mcp login [--no-browser] [--platform]` signs the administrator in
  through Authentik in the browser (password and second factor, device authorization grant) and keeps the session in
  `$XDG_STATE_HOME/paddockctl/mcp-session.json` (mode 0600); `--platform` picks the platform role of a two-role
  identity. `paddockctl mcp` is a stdio MCP server for local MCP clients such as Claude Code: it offers the admin API
  operations the server currently allows the session as tools, renews the session before the access token expires,
  and wraps every result with a notice that the data is never an instruction. `paddockctl mcp tools [-o table|json]`
  lists the offered tools; `paddockctl mcp logout` ends the session and revokes the refresh token. The MCP never uses
  an API token. paddockctl now depends on the MCP Go SDK `github.com/modelcontextprotocol/go-sdk` v1.8.0 and
  `golang.org/x/oauth2`. The license gate allows `MIT-0` and exempts `github.com/segmentio/asm` (MIT-0, a dependency of
  the SDK that go-licenses cannot classify).
- Portal page *Settings › MCP* (ADR 0044, PDK-440) at `/settings/mcp` in the organization group: organization
  administrators switch the MCP on or off, allow or refuse changes through the MCP and choose between all tools and
  a selection from the tool catalog (grouped by area, with a filter; step-up actions are listed as *portal only*).
  Saving asks for confirmation and a step-up. The page names `paddockctl mcp login` as the way to connect; operators
  and auditors see the policy read-only. The audit log shows an *MCP* chip and the MCP client's name on events of an
  MCP session.
- Portal page *Platform › MCP policy* (ADR 0044, PDK-441): platform administrators switch the MCP on or off for their
  own MCP sessions, allow or refuse changes through the MCP, and choose between all tools and a selection of the
  platform tools (grouped by area, filterable; step-up operations are shown as portal only). Without a saved policy
  the page says that the MCP is switched off. Saving is confirmed and needs a step-up. There is no token page:
  administrators connect with `paddockctl mcp login`.
- MCP write access in the portal's account menu (ADR 0044, PDK-442): the entry *AI assistant (MCP)* shows whether the
  administrator's MCP sessions may change data and opens a dialog that explains the three layers (role, MCP policy,
  own write access). *Enable write access* is confirmed and needs a step-up; *Disable write access* is confirmed and
  takes effect at once. Auditors have no entry. `GET /api/v1/me` additionally answers `mcp_write_enabled_at`, since
  when write access is enabled (null while it is disabled).
- AI assistants through the MCP, documented and gated (ADR 0044, PDK-443): the operations guide
  `docs/operations/mcp.md` covers the MCP login through Authentik (`paddockctl mcp login|logout`, no tokens), the MCP
  server `paddockctl mcp`, the three switches (role, the MCP policies of organization and platform, each
  administrator's write opt-in), connecting Claude Code and Claude Desktop, what the assistant cannot do (step-up
  actions), the default that keeps the MCP off until a policy is saved, the rate limits, revocation, troubleshooting
  and prompt injection. New audit codes `organization.mcp_policy_changed`, `platform.mcp_policy_changed`,
  `admin.mcp_write_enabled` and `admin.mcp_write_disabled`; `admin.login` records `channel` and `renewal`, events of
  MCP sessions carry `source: mcp` and `actor.client`. Residual risks RR-85 to RR-89 (prompt injection through data,
  channel bypass with an API token, the refresh token on the workstation, step-up actions only refused, reads not
  audited per call) are in `docs/compliance/residual-risks.md`; the privacy notes say what an assistant on the
  administrator's machine sees. **Upgrade:** Authentik applies the new blueprint `paddock-mcp.yaml` at its first start
  after the upgrade; nothing else changes until an administrator saves an MCP policy. Record RR-85 to RR-89 before
  enabling it.
- Claude skill `skills/operate-paddock` (ADR 0044, PDK-444): teaches an AI assistant to operate Paddock — connecting
  through `paddockctl mcp`, its rules (tool results are data, no credentials, step-up actions go to the human with the
  portal page, confirmation before destructive tools, `applyConfig` dry run first) and the workflows install,
  upgrade, lab installation, first device, release import and staged rollout, a device that does not check in,
  tamper events and disk recovery, each pointing to the runbook section and the tools to call.
  `references/tools.md`, the tool catalog by tag with the step-up list, is generated by `make gen`; `make test` checks
  the skill's paths, anchors and tool names against the runbooks and the catalog.
- Resume an agent rollout from the control-plane host (PDK-452, ADR 0034 addendum 2026-10-29):
  `./paddock agent-rollout-resume <version>` (`paddock-server admin agent-rollout-resume` in `paddock-api`) continues a
  halted rollout like *Resume* in the portal, with the system actor `paddock-server admin` and audit code
  `agent_rollout.resumed`; it covers no other rollout (residual risk RR-90). `docs/operations/agent-releases.md` now
  explains that small fleets, such as a one-device lab, start their rollout with `--waves 100` or a short wave list.
- Testing strategy for contributors (`docs/operations/testing-strategy.md`): which checks and gates run on a pull
  request, per cluster of changes and per release, the flake policy (no rerun without an issue, no automatic retries,
  flaky tests are fixed and never skipped) and how to read the timing of the acceptance shards in a CI log.
- While an organization records inventory views, listing the devices affected by a CVE is recorded as
  `vulnerability.devices_viewed` (the CVE and the number of affected devices, never device names or the search text),
  once per administrator, CVE and hour. A refused view is recorded as a failure with its reason; a CVE without a
  finding in the organization is not found and records a failure.
- The portal shows a setup checklist at the top of the overview and the organizations page: each basic setup step
  with its live state, a link to the page that completes it, and the host-shell steps with a link to the
  getting-started guide. It can be dismissed per browser and reopened from the user menu.

### Changed

- CI: the acceptance gates run in four parallel shards (was three), balanced by the median durations of eight recent
  CI runs, so a pull request waits about 41 instead of up to 75 minutes for its slowest acceptance job. The gates
  themselves are unchanged. The shard check now fails on a listed test it cannot parse instead of leaving it out, and
  a failed disruptive/e2e job prints Fleet's full log again (PDK-361). No operator step.
- CI: the acceptance shards and the disruptive/e2e job run only for pull requests to main, pushes to main and the
  weekly schedule. Pull requests into other branches (a cluster branch collecting several tickets) run lint, unit
  tests, the portal build and the secret and vulnerability scans; the full acceptance stage runs once when the
  cluster branch goes to main. The required check `acceptance` still fails on a pull request to main unless every
  gate passed (PDK-526).
- Portal: while a new organization is being created, the *New organization* dialog says that the identity provider
  is being set up and that this can take up to a minute (the create waits for that setup, bounded at 60 s); the
  *Create* button stays disabled meanwhile (PDK-407).
- Lab smoke test: runs against nginx 1.31.8 (was 1.28.3) and from now on follows the nginx mainline line (ADR 0029
  amendment 2026-10-28). No operator step: the image is a tooling image, is not part of the operator bundle, and the
  shipped reference configuration `nginx/paddock.conf.example` is unchanged (PDK-347).
- Portal: when *End all sessions* ends the portal sessions but the identity provider's sessions cannot be ended (502
  `upstream_unavailable`), the page now says so and asks to run *End all sessions* again (PDK-321).
- The portal is built and tested with Node 26 (image `node:26.12.1-trixie-slim`, was `24.21.0`); Node 26 is the Active
  LTS line since 2026-10-28 (ADR 0015 amendment 2026-10-28). No operator step: Node is a build and tooling image and is
  not part of the operator bundle. `engines.node` stays `>=24` because the Playwright image runs the end-to-end tests
  on Node 24 (PDK-346).
- Minor and patch updates of libraries: the portal uses Vuetify 4.3.0 (was 4.2.6) and is linted with ESLint 10.13.0
  and typescript-eslint 8.72.0 (were 10.12.0 and 8.71.2); the server validates requests against the API contract with
  kin-openapi 0.152.0 (was 0.151.0) and uses the oapi-codegen runtime 1.8.0 (was 1.7.0). Schema: unchanged.
- Linter pinned to golangci-lint v2.15.0 (PDK-348). The supervisor now logs the agent's exit status
  (`agent stopped`, with `killed: true` when the agent ignored SIGTERM for 10 seconds) when it stops the agent for a
  switch, a rollback or shutdown.
- Container logs are now rotated: every service of the control plane, the audit host, the lab and the backup overlay
  logs with Docker's `json-file` driver at 50 MB × 10 files per container, so the logs (including Caddy's access log
  with client addresses) no longer grow without limit. `./paddock check` gains the item `container logs are rotated`,
  which fails for any service without `max-size`. `docs/operations/install.md` describes what the logs contain and
  that a central log system is the operator's choice (PDK-149).
- Documentation: the device login counts one of the user's recovery codes as the second factor, like the portal and
  Authentik's own sign-in (decided 2026-10-18 for the portal, 2026-10-29 for the device login), as long as the user's
  TOTP authenticator is still registered. Residual risk RR-62 now names the device login, whose device-code sign-in
  runs the portal sign-in first; `docs/operations/device-login.md` describes the lost-authenticator sign-in (one
  recovery code per prompt, no passkey enrolment) and a lab check that a used recovery code is refused at the device
  approval. No behaviour change (PDK-325).
- **Breaking: 0.1.0-alpha.7 has no upgrade path from earlier releases.** PostgreSQL moves from 17 to 18 for the
  control plane, Authentik's database and the audit database, and the data directory layout follows the PostgreSQL
  18 image (`/var/lib/postgresql/18/docker` inside the volume). An installation of 0.1.0-alpha.6 or earlier is
  installed fresh (`docs/operations/upgrade.md`, "From 0.1.0-alpha.7"): every database, OpenBao's keys, escrowed
  recovery keys and device enrollments of the old installation are gone, and every device is enrolled again. A
  backup repository that already holds the stanzas is refused (logged, no backups) until the operator runs
  `./paddock compose run --rm --no-deps pgbackrest stanza-upgrade` once, and the same for `pgbackrest-authentik`.
- Valkey moves to 9.1.3 for the control plane's cache and for Fleet's Redis. Fresh installations only (PDK-344).
- Fleet's MySQL stays on the 8.4 LTS line Fleet documents and moves to 8.4.13; the upstream version watch follows
  that line only.
- RabbitMQ moves to 4.4.0 (Erlang/OTP 29). Fresh installations only (see the breaking note of this release)
  (PDK-354).
- CI: a pull request that changes the deployment (`deploy/`, the `Makefile` or the new workflow) now builds the
  operator bundle from its own code and runs both bundle smoke tests (default profile and lab profile behind Nginx)
  before the merge, in the new workflow `bundle-smoke`. It pushes and signs nothing; the `edge` job on `main` is
  unchanged. No operator step (PDK-389).
- A device that refuses the removal of Paddock because the request itself is invalid no longer leaves the request
  open: it ends at once, with one audit event by the device, so an administrator can request it again. A refusal that
  clears up (an in-place encryption or a Lock or Destroy pending) keeps the request open, and the device page and the
  admin API now show why the device refused (PDK-403).
- Role membership audit and administrator accounts (PDK-424, ISO 27001 A.5.18): when all role groups of an
  organization come back empty while role holders are recorded or administrator accounts are enabled, the worker now
  checks whether its Authentik service token can still see the directory: each role group must be readable by name and
  a user listing must return at least one user who is not a service account. If both hold, the organization really
  lost its last role holders: each one is recorded as `admin.role_revoked` after two consecutive rounds, and the
  administrator accounts are disabled and their sessions ended. Otherwise the round is refused as before, and nothing
  is recorded or changed. New metric `paddock_identity_directory_refusals_total` counts refused organization rounds;
  from three refusals in a row the worker logs a warning naming the organization, and the new alert
  `PaddockRoleDirectoryRefused` (warning) fires when refusals continue for 15 minutes.
- `make lint` fails when a module of the Go workspace is not tidy (`lint-tidy`, `go mod tidy -diff` per module; it
  changes no file) (PDK-457).
- Sign-in of an identity with the platform role and an organization role (ADR 0045 amendment 2026-10-29, PDK-458):
  when the organization is unknown or not active, a plain sign-in now enters the platform role instead of
  being refused, so a stale organization group no longer locks a platform administrator out. The `admin.login` event
  carries the new param `fallback: organization_inactive`, `GET /api/v1/me` answers the new optional field
  `role_fallback`, and the portal shows a notice for the whole session. A switch to the organization role stays
  refused with `organization_inactive`.
- Changelog entries of merged changes that are not released yet are collected as one file per change in
  `changelog.d/` and assembled into `CHANGELOG.md` at release (`make changelog`); the release notes keep their
  format (PDK-518).
- A pull request to `main` that changes only documentation (`docs/` except `docs/assets/`, `changelog.d/` or a
  Markdown file in the repository root) skips the acceptance stage in CI; the required `acceptance` check still
  reports and fails whenever the gates should have run and did not all pass. Pushes to `main` and the weekly
  schedule always run the full stage (PDK-537).
- Authentik now runs 4 web worker processes instead of its default 2, configurable with
  `PADDOCK_AUTHENTIK_WEB_WORKERS` in `.env` (development, production and lab stacks). With 2, simultaneous logins
  queued until clients gave up after 30 seconds. Each worker uses up to one CPU core and about 250 MiB RAM, so
  `authentik-server` needs about 0.5 GiB more; size the setting with `docs/operations/capacity.md`, "Authentik web
  workers".
- `./paddock check` fails the new item `authentik web workers` when `PADDOCK_AUTHENTIK_WEB_WORKERS` is not an integer
  of at least 1: Authentik would fall back to 2 workers on such a value, or serve no login with 0.
- `make acceptance` takes `ACCEPTANCE_GO_PARALLEL=<n>` and passes `-parallel <n>` to `go test`; without it go test caps
  a gate's parallel cases at the number of CPUs, below `PADDOCK_ACCEPTANCE_PARALLEL`. CI sets both to 8, so the
  exactly-once gate runs 8 cases at a time instead of 4 on a GitHub runner. Local runs are unchanged (PDK-556).
- Evidence exports: the audit writer now spools a package's events on its own disk volume (`audit-writer-tmp`)
  instead of in memory, and an export larger than `PADDOCK_AUDIT_EXPORT_MAX_BYTES` (`paddock-audit-writer`, default
  4 GiB) fails cleanly with the reason `export_too_large`, before any of it is stored, instead of exhausting the audit
  host. Objects larger than 256 MiB are no longer read into memory by the export or the chain verification, and
  objects are decompressed as a stream. Make sure Docker's data-root on the audit host has free disk space for at least
  one export of that size.
- Evidence packages: `export.json` now records the SHA-256 of `README.md` (`readme_sha256`), so the signature also covers
  the README an auditor reads first. `paddockctl audit verify-export` reports a changed or missing README, or an
  `export.json` without the field, as a problem; packages built before this change no longer verify OK. The package
  download is refused for an export with no recorded size, its overall time limit is capped at 24 hours, and `HEAD`
  on the download answers `405` with `Allow: GET`.

### Fixed

- Device login (PDK-498, ADR 0034 amendment 2026-10-29): approving a device sign-in on a second device no longer asks
  every user to enrol a passkey. The device-code page signs users in with the portal's sign-in, whose passkey
  enrolment now applies only to members of Paddock's administrator groups (platform administrators and the
  administrators, operators and auditors of every organization). End users approve with password and TOTP; the
  portal sign-in is unchanged for administrators. The Authentik blueprint `paddock-portal.yaml` gains the policy
  `paddock-admin-login-webauthn-administrator`, applied automatically on upgrade.
- Event gap detection (PDK-419): a device with a reported event gap that never fills no longer hides later gaps.
  Before, once such a device had delivered more than 10 000 further events, every worker round re-read the same
  window and a second gap above it was never reported as `device.event_gap`. The round now keeps a scan position per
  device (migration `00073_event_seq_scanned`) and reads one bounded window above it, moving on every round.
- Production and lab installations (PDK-492): the api now finds the MCP login provider at
  `https://auth.<domain>/application/o/paddock-mcp/`. Before, it looked for it at the development port, never became
  ready and the installation or upgrade stopped at `./paddock start`. The bundle test refuses an OIDC issuer with an
  explicit port.
- MCP login (`paddockctl mcp login`, PDK-489): the device code of the Authentik provider `paddock-mcp` now lives ten
  minutes, as the device logins' do. With Authentik's default of one minute, a sign-in with password and second factor
  could expire before it was confirmed.
- Portal: a focused input field (number, text, time, text area) shows a single focus indicator, the field's own
  outline. A second ring inside it no longer crosses the field label.

- Portal: confirmation dialogs show long names in full on narrow screens (PDK-447). A long target name in the title
  or the confirm button, such as a pre-release version `0.9.1792783862-alpha.1792944510667`, wraps onto further lines
  instead of being cut off with an ellipsis or running past the edges of the button.

- Portal overview: on a phone-width screen the attention and recent-audit tables scroll sideways, and keyboard users
  can now focus them to scroll; screen readers announce each as its own named table region (PDK-460).

- Portal: on screens narrower than 600 px the attention pill in the app bar shows only the number of devices that need
  attention, so the organization name stays visible in every language (in German the full pill text used to squeeze
  it to zero width). Screen readers still hear the full text (PDK-338).

- Portal, *Updates*: the label of the security-update time field is no longer cut off ("Uhrzeit der
  Sicherheitsupd…" in German); the field is as wide as the other text fields on the page and takes the full panel
  width on phones (PDK-461).

- Portal accessibility (WCAG 2.5.3 *Label in Name*, PDK-349): the accessible names of the user menu button, its
  language, theme and density entries and the action buttons of the attention list and the overview now begin with
  their visible text and still name the target, e.g. "Retire, lock or keep — acme-lt-0142", so speech-input users can
  activate them by saying what they see. The portal's accessibility check runs with axe-core 4.14.
- Role membership audit (PDK-423): when the worker fails to clear the "missing" mark of a role holder who reappeared
  in the identity provider, the next listing that misses that holder no longer records `admin.role_revoked`; the
  revocation needs two consecutive misses after a successful mark. The worker process remembers the failure until its
  next successful round for that role.
- A corrupt or unreadable supervisor-upgrade marker no longer keeps a device out of every agent and supervisor
  rollout (PDK-337): like the removal of Paddock, an agent update and a further supervisor upgrade wait for such a
  marker only until its modification time is older than 30 minutes, then go ahead and log a warning.
- `make system-test` and `make acceptance` fail with `no test ran` when the test filter `T` matches no test instead of
  reporting the empty run as passed (PDK-339), and pass `T` to `go test -run` verbatim, so a `$` anchor no longer gets
  lost in make's variable expansion (`T='^TestIdentityGates$/.*/^L1_login$'`); `$$` keeps working.
- Device removal: a removal that does not run (withdrawn, failed to start, or given up on an unreadable plan) no
  longer leaves its plan, its program copy or an empty `/root/paddock-uninstall/` directory on the device. The
  uninstall runbook lists what may remain there.
- End all sessions (PDK-342): the `platform.sessions_ended` audit event reports the identity-provider sessions that
  actually ended. Before, when Authentik answered the session deletion slowly and Paddock repeated it, the event could
  report 0 ended sessions although every session had ended.
- `make system-test`, `make acceptance` and `make e2e` check up front that the checkout has `deploy/compose/.env` and
  the development secrets and stop with a clear message, instead of failing minutes into a run with "couldn't find env
  file" (PDK-353). `make e2e` from a worktree whose `.secrets` is a symlink to another checkout no longer fails every
  login and every certificate check: the resolved secrets directory is mounted into the Playwright container and also
  handed to the device simulator and the release helper.
- Uninstall (PDK-357): when cancelling an uninstall, or requesting a new one over an overdue request, fails after the
  server had already reserved the device's command result, the reservation is now released. Before, the device's
  later result was refused as a conflict although the command was still open, so the removal never started and the
  request only ended when it expired.
- Agent updates (PDK-372): a supervisor stopped or restarted while a new agent release runs its self-test no longer
  can report that release as `self_test_failed`. The interrupted update stays pending and the restarted supervisor
  runs the self-test again, so a host shutdown or a supervisor restart during an update no longer counts as a failure
  against the rollout.
- In-place encryption: when a bootable kernel's initrd in `/boot` was a symbolic link to a temporary initrd left by
  an interrupted agent run, the initrd regeneration and the cleanup stayed pending with
  `key_material_shared_bootable` until an administrator stepped in. The agent now rebuilds that kernel's initrd into
  a regular file first and then overwrites and removes the temporary file; the kernel keeps booting throughout.
- Secret scan (PDK-388): the canary check of the generated gitleaks configuration gives the same verdict on every
  run. Its random fake token could contain a value that the default configuration's own global allowlist skips
  (`false`, a trailing `null`, the alphabet stopword), and the check then failed about twice in a million tokens on a
  configuration that was fine. The token now never contains an `l`, which each of those entries needs; a
  configuration that drops the token rule or skips a canary path still fails.
- Retiring a device no longer leaves its in-place encryption open on the server (PDK-396): a conversion the device
  had already prepared, or one whose cancellation was on its way, is now closed as cancelled, and a cancellation the
  device has not yet received is withdrawn. The retirement's audit event records the closure.
- Portal, attention page (PDK-417): the kind filter now offers "In-place encryption failed", so failed in-place
  encryptions can be listed on their own.
- Clock drift (PDK-418): a check-in that arrives while the worker records a clock drift episode can no longer open
  the episode (`device.clock_drift`) on an offset already back within 60 s or close it (`device.clock_drift_cleared`)
  on an offset that is again beyond 30 s; the episode is changed only when the offset at that moment still meets the
  threshold.
- Nightly audit verification (PDK-420): a restart of the audit writer no longer clears an active
  `PaddockAuditChainBroken`. At start the writer now sets `paddock_audit_verify_failed_organizations` from the newest
  recorded nightly window and sample day of every organization, instead of 0 until the next 00:45 UTC cycle.
- Nightly audit verification (PDK-421): with more than one audit-writer replica, a replica that loses the
  `audit-verify` lock no longer raises a false `PaddockAuditVerifyStale` after two nights, and no longer keeps a stale
  `PaddockAuditChainBroken` value. Until the next cycle is due, it re-reads the runs the verifying replica records
  every minute and sets `paddock_audit_verify_last_run_timestamp_seconds` and
  `paddock_audit_verify_failed_organizations` from them. Organizations whose verification errored without a recorded
  run count only on the verifying replica. The alert rules are unchanged.
- Agent rollouts (PDK-452): two concurrent starts of the same release now refuse the second with `already_exists`
  (409) instead of an internal error, and concurrent halts or resumes of one rollout change it once, record one
  successful audit event and refuse the others with `invalid_state`. Before, every concurrent halt succeeded and each
  recorded its own `agent_rollout.halted` event.
- `make e2e` with the development secrets in another directory (PDK-453): `SECRETS_DIR` now reaches the device
  simulator and the release helper as well as the specs, and a `.secrets` that is a symlink to another checkout is
  resolved and mounted into the Playwright container. Before, the device specs failed with `certificate signed by
  unknown authority`, and from such a checkout every login failed.
- `make acceptance` without `SHARD` or `T` no longer hits its timeout before the suite ends (PDK-463): a serial run
  now defaults to `ACCEPTANCE_TIMEOUT=180m` (the gates take ~131 min in a row); a shard or a single gate keeps 120m,
  and an explicit value still wins. `docs/operations/local-dev.md` describes running the suite serially or shard by
  shard (`SHARD=i/N`) against one stack.
- MCP sign-out (PDK-468): `paddockctl mcp logout` now ends the sessions of every access token of the sign-in's
  refresh chain, not only of the current one, also after the 8-hour sign-in expired; before, the sessions of earlier
  access tokens stayed valid for up to 30 minutes. Deactivation, a role change and *End all sessions* end them the
  same way. After a session store outage, the first session of a device login needs `paddockctl mcp login` again;
  renewals recover on their own.
- Agent updates (PDK-469): the supervisor removes a finished release's staged files before its update request, so the
  agent can no longer stage a new release into the moment between the two and lose its files to the old cleanup.
- Clone detection: a device is no longer quarantined as a suspected clone after its check-ins failed on the server
  side, for example while the ingest queue was full or the server was slow to accept the check-in. A failed check-in
  no longer counts as an issued sequence number, so two such failures in a row no longer leave a genuine device "two
  behind". The rule itself is unchanged: a device that sends a sequence number older than the one before the last
  issued one is still quarantined.
- Clone detection: after Valkey lost its data, a device's check-in sequence no longer restarts at 1 when the device
  checks in before the worker has rebuilt the cache. The gateway answers such a check-in with a retryable 503 until
  the device's counter is restored from the database; a counter that survived is left unchanged, so a healthy device
  is never quarantined because of a rebuild. Until a counter restored from lagging data has caught up, clone detection
  for that device is weaker (residual risk RR-97). A cache rebuild that fails for one organization no longer stops the
  rebuild of the others.
- A user's login on a device no longer produces a false "event gap" tamper trace (PDK-476): the server now records
  the sequence number of every login event like that of any other device event, so gap detection no longer reports
  logins as missing events. Logins are still not written to the audit trail. Gaps that earlier logins already caused
  are not closed by this change.
- A device no longer falls out of agent and supervisor rollouts in the remaining edge cases of a stuck
  supervisor-upgrade marker (PDK-479): a marker the agent cannot inspect, or one whose age a clock set back makes look
  younger, holds updates, the removal of Paddock and in-place encryption work for at most 30 minutes from when the agent
  first sees it. A corrupt supervisor-upgrade result is discarded with a warning instead of blocking every further
  supervisor upgrade.
- A cancelled in-place encryption no longer encrypts the disk when the device restarts before its cleanup has
  finished: the cancel disarms the prepared start-up images at once, keeps new ones from picking the encryption step
  up again, and repeats this until the cleanup is done. When it cannot (for example a full `/boot`), the
  device reports `device.disk_conversion_neutralize_failed`; a conversion that encrypts anyway after a cancel is
  continued with its escrowed recovery key and recorded as `device.disk_conversion_completed_after_cancel`. Until the
  device has reinstalled the unlock path for such a disk, a kernel whose start-up image was disarmed cannot open it;
  a failed reinstall is reported as `device.disk_conversion_unlock_restore_failed`.
- `paddockctl mcp tools` now prints `the MCP is switched off for this scope` on stderr when no saved policy enables
  the MCP, like `paddockctl mcp` does; the list on stdout stays empty and valid for `-o json`.
- End all sessions with many organizations (PDK-501): Paddock now looks up the portal users of all role groups in a
  few batched Authentik requests instead of one request per role group. Before, with about 90 organizations the
  lookup exceeded the request's time budget and *End all sessions* failed with `upstream_unavailable`, so an
  installation of that size could not end all sessions in an incident.
- A portal or MCP sign-in that fails because the database cannot resolve the organization or the administrator
  account now records a failed `admin.login` event with reason `login_failed`; before, the attempt left no audit event.
- The lint job in CI builds the server and compiler images and runs govulncheck from the Go modules that the runner
  already has in its module cache instead of downloading them again from proxy.golang.org, so a stream error of the
  module proxy no longer fails these lint steps when the Go dependencies are unchanged (PDK-516).
- Faster local stack start (PDK-517): `make up` and `make fleet-bootstrap` finish about 2 minutes sooner. The Fleet
  bootstrap no longer waits a fixed 2 minutes for Fleet; it checks Fleet's health endpoint and, if Fleet is not ready
  for its setup yet, retries a few times and then stops with an error naming the step that failed.
- Device login (PDK-521, plan M8f amendment 2026-10-29): approving a device sign-in on a second device asks for the
  second factor of the device approval once, whether the code is typed on the `/device` page or opened with the QR
  code. Before, typing the code asked twice when the first prompt was answered with a recovery code, so such a user
  spent three recovery codes instead of two. Now a user who answers with recovery codes spends two codes when not
  signed in on the second device and one when signed in. The Authentik blueprint `paddock-device.yaml` removes the prompt from the device-code page's flow
  `paddock-device-code` on upgrade; the device approval keeps it.
- Platform administrators (PDK-534, ISO 27001 A.5.18): when the last members leave `paddock.platform.admins`, the
  worker now ends their portal sessions. An empty listing of the group is trusted only when the directory check of
  PDK-424 shows that the Authentik service token can still see the directory (the group is readable by name and a user
  listing returns at least one user who is not a service account); otherwise the round is refused as before and no
  session is ended. Refused platform rounds now count in `paddock_identity_directory_refusals_total`, the warning after
  three refusals in a row names the platform with the nil organization ID, and the alert `PaddockRoleDirectoryRefused`
  covers the platform round.
- Nightly audit verification (PDK-535): an audit-writer replica that starts while another replica verifies the audit
  chain no longer keeps a mix of that night's and the previous night's results in
  `paddock_audit_verify_failed_organizations` until its own next cycle, which could raise a false
  `PaddockAuditChainBroken` or hide a real one for up to a day. After start it re-reads the recorded runs every minute
  until its own cycle is due. The alert rules are unchanged.
- A pull request retargeted from another branch to `main` no longer counts as having passed the required
  `acceptance` check without the acceptance gates: off `main` the check reports under the name
  `acceptance (not required off main)`, so after retargeting the pull request waits for a new run (PDK-538).
- The acceptance jobs in CI build the server images from the Go modules that the runner already has in its module
  cache instead of downloading them again from proxy.golang.org inside every image build, so a stream error of the
  module proxy no longer fails a run whose Go dependencies are unchanged (PDK-540).
- MCP sign-in (PDK-546): a sign-out or a deactivation that lands while a device login opens its first session now
  refuses that login instead of leaving it renewable for the rest of the 8-hour sign-in. A session call whose access
  token belongs to another sign-in than its ID token is refused with `invalid_request`.
- The lint job in CI runs golangci-lint and the Go license gate from the Go modules that the runner already has in its
  module cache instead of downloading them again from proxy.golang.org, so a stream error of the module proxy no longer
  fails these lint steps when the Go dependencies are unchanged; only the license tool itself is still fetched
  (PDK-550).
- Audit index: the partition-creating function `audit_ensure_partition` now pins its `search_path` (`pg_temp` last,
  schema-qualified names), so a session of the audit writer role can no longer shadow the index tables with temporary
  ones (audit migration 00009, PDK-558).
- The device page no longer says that a device removes Paddock at its next check-in when the device refused the
  removal or its command failed or expired. It shows the refusal reason, or that the command will not run any more,
  together with the hint to cancel the request and request it again (PDK-563).
- A failed in-place encryption no longer encrypts the disk when the device restarts before its cleanup has finished.
  This includes an encryption step that was skipped at a restart, for example because the device ran on battery:
  the next restart on mains power no longer encrypts the disk. The failure disarms the prepared start-up images in
  the same way as a cancel does, and repeats this until the cleanup is done. When it cannot, the device reports
  `device.disk_conversion_neutralize_failed`.
- The retention round's Fleet breaker for the retired inventory (PDK-138) counts only failures of Fleet itself or of
  the way to it (`upstream_unavailable`: server errors, timeouts, connection errors, a 4xx without Fleet's own error
  body such as a blocking proxy, and redirects). Fleet itself refusing to delete a single host fails only that device
  with `invalid_state`, so a few permanently refused hosts no longer stop the retired-inventory purge of every
  organization.
- The Fleet client no longer follows redirects. A redirected host deletion used to turn into a read whose success was
  recorded as a deleted host while the host stayed in Fleet; it now fails and is retried.
- A retired device's Fleet host is no longer deleted while it still checks in to Fleet after the retirement (within
  the last 7 days); it is kept like a host that a re-enrolled device of the same hardware may still use
  (`fleet_host_kept` in `device.inventory_purged`).
- A retired device whose Fleet host is kept records a `device.inventory_purged` event only when the reason changes or
  the device was retired again, not every round, and a Fleet hiccup during that check no longer records an event.
  `paddock_retention_deleted_total{store="retired_inventory"}` counts a device only when rows or its Fleet host were
  deleted. After 30 unchanged rounds a kept host records one new `device.inventory_host_kept` event. This needs
  Paddock migration 00078.
- A Fleet answer without the host's last check-in time no longer counts as a host that never checked in; it fails and
  the host is kept until the next round.
- A retention pass that cannot load the privacy settings or list the retired devices now records a `retention.purged`
  failure for the organization.
- A genuine device is no longer quarantined as a suspected clone after its check-ins stalled while it already retried
  (PDK-590): clone detection now compares a device's sequence number with the last number the server actually
  delivered to it, so a check-in that stalled (for example while the message broker blocked publishing) or that the
  device gave up on no longer counts. A clone that checks in with an outdated number is still quarantined; only
  the first check-in of a device after the upgrade or after the check-in cache was lost is not checked.
- Evidence exports: a hung package build no longer delays the expiry of ready packages or the failing of abandoned
  builds, and a build is aborted after 2 hours with a failure record. A build that another audit writer has already
  given up on no longer writes package data, and a package that became ready, failed or expired while the database
  connection failed now always gets exactly one record. One package that cannot be expired or failed no longer holds
  up the others.
- Authentik no longer records a "Failed to execute property mapping" error (NameError `token`) for the Paddock
  authenticator classes mappings whenever a client fetches the OpenID discovery document of the portal, step-up or
  MCP application (PDK-618). Sign-in, step-up and MCP tokens were not affected; the discovery document now also lists
  `paddock_mfa_classes` among the supported claims.
- The evidence exports page and `GET /api/v1/audit/keys` list the current audit signing key on a freshly installed
  platform before the first day is sealed (PDK-652), so an auditor can record its fingerprint before receiving the
  first evidence package: the audit writer publishes the key at startup and retries until OpenBao and the audit
  database answer.
- The portal shows the operating system version of enrolled devices again: the device header, the device overview,
  the attention list and the Ubuntu release distribution on the overview read the os-release fields in the lowercase
  form the agent reports, instead of showing every device as unknown.

### Security

- Agent releases (PDK-432): the database now enforces that a published release cannot change. An upload, host
  command or import that stores a file of a release which another administrator published in the meantime is refused
  with 409 `invalid_state` and keeps the recorded checksums of the release; a second concurrent publish is refused
  the same way. A release import refuses a release with more than one fleetd package for the same architecture
  (`invalid_request`), and `PADDOCK_AGENT_RELEASE_SOURCE_REPO` no longer accepts an owner or repository of only dots
  such as `..`.
- go-jose v4.1.6 in the server (was v4.1.4; CVE-2026-116587, high): parsing a JSON Web Key Set with crafted RSA keys
  could exhaust the CPU. The server reads key sets from Authentik to verify sign-ins.
- undici 6.29.1 in the portal's build tooling (was 6.29.0; CVE-2026-109383, CVE-2026-87018 and CVE-2026-109869, high;
  CVE-2026-109932, medium). undici is only used while the portal is built and never ships with the server.
- Agent releases (PDK-496): the stored file of a published agent release can no longer be overwritten by an upload
  that was still running when the release was published. While a file of a release is being uploaded, publishing that
  release is refused with `invalid_state` (409) until the upload has finished — after an upload that failed without
  the store rejecting it, for up to ten minutes; an upload that outlasts its time limit is refused. Publishing now also
  reads every stored file back and refuses, with an audit event naming the files, when one no longer matches its
  recorded checksum; upload such a file again. A second upload of the same file while one is running is refused with
  `invalid_state`.
- Portal sign-in requires a passkey for every role (PDK-500, ADR 0034 amendment 2026-10-29): an existing Authentik
  session from a sign-in with TOTP only (Authentik's own sign-in or the device-code page) no longer opens the portal
  for a platform administrator, organization administrator, operator or auditor. Such a sign-in, and a role switch
  from it, is refused with `/login-denied?reason=passkey_required` and one denied `admin.login` event; the page
  explains the passkey and offers to sign out of the identity provider. The portal provider gains the mapping
  `io.paddock/scope-login-mfa` (scope `paddock_mfa`), and `paddock-admin-login` gains the stage
  `paddock-admin-login-webauthn-confirm` (order 32), where an administrator confirms a passkey just enrolled. Upgrade
  note: Authentik must have applied the updated `paddock-portal.yaml` blueprint (it does at start) before the api
  runs the new version, or every portal sign-in is refused. `PADDOCK_LOGIN_MFA_OPTIONAL` (development only) also
  lifts the passkey requirement.
- MCP sign-in requires a passkey (PDK-531): `paddockctl mcp login` is held to the same sign-in policy as the portal
  (PDK-500), so a sign-in that validated TOTP only, or an existing Authentik session from one, is refused with
  `passkey_required` and one denied `admin.login` event. The provider `paddock-mcp` gains the mapping
  `io.paddock/scope-login-mfa` (scope `paddock_mfa`), which `paddockctl` now requests. Upgrade note: every MCP user
  must run `paddockctl mcp login` once more after the upgrade; sessions opened before it are no longer renewed
  (`mcp_login_required`). Authentik must have applied the updated `paddock-mcp.yaml` blueprint (it does at start)
  before the api runs the new version, or every MCP sign-in is refused. `PADDOCK_LOGIN_MFA_OPTIONAL` (development
  only) also lifts the MCP passkey requirement.
- Portal sign-out (PDK-532): signing out of the portal now also ends the Authentik session of the browser. Before, the
  portal sent the browser to the portal application's end-session endpoint, which ends the application only, so the
  next sign-in reused the Authentik session without asking for credentials. The browser now runs Authentik's brand
  invalidation flow (`/flows/-/default/invalidation/`) and ends on Authentik's start page. The logout response's
  `end_session_url` names that flow.
- Action records keep their own times (PDK-635, ADR 0032 amendment 2026-10-31): the database bounds the finish time
  of an action to its own clock, never earlier and at most five minutes later, whatever time the finishing or inserting
  statement wrote, so no database role can backdate a finish to have the retention round delete the record early; a
  started action changes only by being finished, and its ID, code, actor, source, correlation ID, start time and
  organization can no longer be changed by any role. A started action whose start time lies more than five minutes off
  the database clock is refused, so keep the control plane's and the database's clocks synchronised. Schema: migration
  `00084`.

## [0.1.0-alpha.6] - 2026-10-27

Evidence integrity for ISO 27001 (plan M8b): the server detects device clock drift and gaps in a device's event
numbering, verifies the audit hash chain every night and records every run, records every grant and revocation of a
portal role from Authentik, and shows organization administrators and auditors the state of their evidence on the new
*Evidence integrity* page. Platform administrators import a newer signed agent release from GitHub with one button
(ADR 0043), and the host operator starts or halts a staged agent rollout with `./paddock agent-rollout` and
`./paddock agent-rollout-halt`. One identity can hold the platform administrator role and one organization's role and
switch between them in the user menu (ADR 0045). The portal shows the server version in the navigation. **Upgrade
order: the server first, then the agents** (`docs/operations/upgrade.md`); this release changes nothing on the device,
so rolling out its agent release only aligns the version. Coming from 0.1.0-alpha.3 or earlier, follow the notes of
0.1.0-alpha.4 first (agents before the server). Fleet moves to v4.93.2 (no Fleet database migration): take the Fleet
dump before the upgrade anyway (`docs/operations/upgrade.md`, step 3). After the upgrade, the first identity sync
records the current members of every role once as `admin.role_granted` with `baseline: true`, and devices whose clock
is more than 60 s off appear on the attention list. `paddock-revoke` stays unsigned, and revocation (Lock, Destroy,
dead man's switch) stays disabled behind `PADDOCK_REVOCATION_ENABLED`. Schema: migrations 00068–00071 (control-plane
database) and audit migrations 00004–00006 (audit database).

### Added

- Role switch for one identity (ADR 0045, PDK-201): one central identity may be a member of `paddock.platform.admins`
  and of one organization's role group instead of needing a second, local account. It signs in to the organization
  role; `GET /api/v1/me` names the other role as `alternate_role` (null for single-role identities, API tokens and
  MCP sessions). The new endpoint `POST /api/auth/switch` starts a new sign-in through Authentik for the other role:
  the new session has no step-up, the previous session ends, and the switch is recorded once as the new session's
  `admin.login` with the new param `previous_role`. The step-up accepts a step-up token whose groups grant the
  session's role next to the other one. The denial reason `platform_and_organization` is removed; the new denial
  reason `role_not_granted` refuses a switch whose role the identity provider no longer grants. Identities with role
  groups of several organizations stay refused. Residual risks RR-91–RR-93.
- Role switch in the portal (ADR 0045, PDK-450): an administrator who also holds the other role sees *Switch to …*
  in the user menu (the platform administrator role, or the organization role with the organization's slug). A
  confirmation dialog states that the current session ends and privileged actions need a new step-up; a refused
  switch shows an inline alert in the menu. The sign-in denied page explains the new reason `role_not_granted`; the
  text for the removed reason `platform_and_organization` is gone.
- Agent release import from GitHub (ADR 0043, PDK-427): a platform administrator checks the official repository for a
  newer agent release and imports it with one step-up-protected action instead of downloading, renaming and uploading
  the files on the host. Every file is verified with the release public key before anything is stored; the release is
  published ready for a staged rollout, which the import never starts; `paddock-revoke` and unsigned files are never
  imported. API: `GET /api/platform/v1/agent-release-source`, `POST /api/platform/v1/agent-release-source/check`,
  `POST /api/platform/v1/agent-releases/import`. Configuration of `paddock-api`: `PADDOCK_AGENT_RELEASE_SOURCE_REPO`
  (default `phischl/paddock-mdm`, `off` for air-gapped installations), `PADDOCK_AGENT_RELEASE_SOURCE_URL` (default
  `https://api.github.com`), the optional `PADDOCK_AGENT_RELEASE_SOURCE_TOKEN_FILE`, and the proxy variables
  `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, which Compose now passes to the api. New audit code
  `agent_release.imported`; new problem codes `release_source_disabled`, `release_source_unavailable`,
  `release_not_newer` and `release_incomplete`; residual risk RR-84. The host command `./paddock agent-release` stays
  the fallback (`docs/operations/agent-releases.md` "Import from GitHub").
- Portal button for the agent release import (PDK-428): the *Agent releases* page shows a *Release source* panel with
  *Check for new release* and *Import <version>* (confirmation dialog and step-up); the panel is hidden when
  `PADDOCK_AGENT_RELEASE_SOURCE_REPO=off`.
- Server version in the portal (PDK-430): after sign-in, the bottom of the navigation shows the version of the running
  control plane, e.g. "Paddock 0.1.0-alpha.5" (in the collapsed navigation as a tooltip). `GET /api/v1/me` answers it
  as `server_version`; the login page and anonymous requests learn no version. The release images carry the release
  tag, local builds report `0.0.0-dev`; `paddock-server version` prints it.
- Audit codes for evidence integrity (plan M8b): `device.event_gap`, `device.event_gap_filled`,
  `device.event_seq_reset`, `device.clock_drift`, `device.clock_drift_cleared`, `audit.chain_verified`,
  `audit.chain_verification_failed`, `admin.role_granted` and `admin.role_revoked` are registered and documented in
  `docs/compliance/audit-codes.md`, with portal texts in English and German.
- Clock drift detection (plan M8b, ISO 27001 A.8.17): the server measures the clock offset of every device from the
  signed time of its check-in, without an agent change. A device whose clock is more than 60 s off records
  `device.clock_drift` and appears on the attention list with the kind `clock_drift` and the offset; once the clock
  is back within 30 s, `device.clock_drift_cleared` ends the episode. A device more than 300 s off is still refused
  (`clock_skew`) and shows as silent. Schema: migration 00068 adds the clock and event sequence columns to the device
  status and the attention kind `clock_drift`.
- Event gap detection (plan M8b, ISO 27001 A.8.16): the worker checks the event numbering of every active device. A
  hole that is still open after two further check-ins records `device.event_gap` and appears on the attention list
  with the kind `event_gap` and the missing range; if the events arrive later, `device.event_gap_filled` closes it.
  Ranges the agent admits it dropped (`device.agent_events_dropped`) are no gap. A device whose event counter
  restarted (agent re-installed or state wiped) records `device.event_seq_reset`, and its new numbering is recorded
  instead of being discarded as duplicates. A check-in is only compared with events the gateway received before it.
  Schema: migration 00069 adds the event gap and dropped-range tables, the receipt time of delivered events and the
  attention kind `event_gap`.
- Nightly audit chain verification (plan M8b, ISO 27001 A.5.33): every night at 00:45 UTC the audit writer verifies
  each organization's last seven sealed days and one random older day, and records every run, including
  `paddock-server audit verify`, as `audit.chain_verified` or `audit.chain_verification_failed` in the organization's
  own audit log and as a verification run; `audit verify` now prints the run ID (`run <id>`). New metrics
  `paddock_audit_verify_runs_total`, `paddock_audit_verify_failed_organizations` and
  `paddock_audit_verify_last_run_timestamp_seconds`, new alerts `PaddockAuditChainBroken` (critical) and
  `PaddockAuditVerifyStale` (warning), runbook section "Nightly verification" in `docs/operations/audit-bucket.md`.
  Schema: audit migration 00004 adds the verification runs and lets the auditor role read its organization's
  manifests and runs.
- Evidence integrity for organization administrators and auditors (plan M8b, ISO 27001 A.5.33): the portal page
  *Evidence integrity* (navigation group *Organization*) shows the last sealed day, the number of signed manifests,
  the last chain verification with its result and the last failure, every verification run (trigger, days, objects,
  result, problems) and every sealed day with its manifest hash, key version and the result of the newest run
  covering it. New read-only admin API routes `GET /api/v1/audit/integrity`, `GET /api/v1/audit/verification-runs`
  and `GET /api/v1/audit/manifests` (roles org_admin and org_auditor; lists with search, filters and sorting). No
  platform access is needed to check the evidence.
- Audited role membership (plan M8b, ISO 27001 A.5.18 and A.8.2): every identity sync interval (default 5 minutes)
  the worker compares the members of the Paddock role groups in Authentik (`paddock.<slug>.admins`, `.operators`,
  `.auditors`, `paddock.platform.admins`) and the Authentik superusers with what it saw last, and records every grant
  as `admin.role_granted` and every revocation as `admin.role_revoked` with the user name, the role and the group.
  Organization roles are recorded in the organization, platform administrators and superusers in the platform
  audit. The first successful comparison of each role records its current members once with `baseline: true`. A
  revocation is recorded only when two consecutive listings miss the member, also for the last holder of a role. A
  listing that fails records nothing for its role in that round. If all role groups of an organization, or the
  superusers, come back empty, nothing is recorded in that organization or on the platform. The role groups are
  listed once per round for both the administrator account check and this record. Schema: migrations 00070 and 00071
  add the role member and per-role snapshot tables of organizations and of the platform.
- Host commands for the agent rollout (PDK-449, ADR 0034 amendment 2026-10-26): `./paddock agent-rollout <version>
  [--waves …] [--min-wave-minutes N] [--failure-threshold-percent P] [--failure-threshold-min M]` and
  `./paddock agent-rollout-halt <version>` start and halt a staged rollout on the control-plane host
  (`paddock-server admin agent-rollout` / `agent-rollout-halt` in `paddock-api`) without a portal account. Same
  validation, defaults and audit codes as the API, with the system actor `paddock-server admin`; the rollout is
  printed as JSON, a refusal names the API's problem code. The commands skip the portal's second factor and step-up
  for the host operator: residual risk RR-90.

### Changed

- Documentation: the architecture and the compliance pack now mark every unbuilt feature as planned (with its
  milestone) or dropped: Authentik event ingestion, event-gap and clock-drift detection, Himmelblau component check
  and log shipper, per-organization retention, evidence export, `collect_status`, `playbook`, Git export, SIEM
  forward (plan M8b, ADR 0030).
- Updated bundled components (patch releases; most of them distrust the compromised eMudhra/emSign certificate
  authorities): Authentik 2026.8.5 (was 2026.8.4), RustFS 1.0.4 (was 1.0.3), Fleet and fleetctl v4.93.2 (was v4.93.1;
  no Fleet database migration) with the Fleet NVD release 202610260056, AWS CLI 2.38.5 (was 2.38.2), Prometheus
  v3.15.1 (was v3.15.0); build and release tooling BuildKit v0.34.1, cosign v3.1.4 (also used to verify the operator
  bundle), Trivy 0.76.1. Devices install Himmelblau 4.0.7 by default (`PADDOCK_HIMMELBLAU_VERSION`, was 4.0.6). The
  portal uses Vuetify 4.2.6 (was 4.2.5), vue-i18n 11.4.16 (was 11.4.14) and intl-messageformat 12.1.4 (was
  12.1.3), and is built with Vite 8.3.5 (was 8.3.4). The server talks to the S3 stores (audit WORM store, backups,
  agent artifacts) with AWS SDK for Go v2 1.47.4, its credentials module 1.20.10 and its S3 client 1.114.5 (were
  1.47.3, 1.20.9 and 1.114.3). Schema: unchanged.

### Fixed

- Command palette (PDK-352): with no matching entry, the "No matches" hint is no longer placed inside the result
  list, which broke the list's accessibility rule; screen readers now get it as a status message.
- Portal number fields (PDK-429): the unit of a number field no longer disappears when the field is too narrow for its
  label. The fields under *Login & privileges*, *Updates* and *Dead man's switch*, the password timeout of a
  permission profile and the contact thresholds of a device group now have a short label, show their unit (days,
  hours, minutes) next to the value, and name the allowed range below the field; number fields in the settings pages
  are wider.
- Audit chain (ADR 0010, amendment 2026-10-25): an audit event recorded on a day whose manifest is already sealed is
  now filed under the first unsealed day instead of the sealed one, which the next chain verification reported as
  broken (`PaddockAuditChainBroken`). In production this could only happen when the audit writer's clock ran more
  than 15 minutes ahead of the audit database; the development-only early seal of the current day triggered it too.
  Sealed days and their objects are unchanged. Schema: audit migration 00005 adds a trigger that refuses any object
  for a sealed day; audit migration 00006 pins the trigger function's `search_path`.

## [0.1.0-alpha.5] - 2026-10-24

In-place encryption of installed devices (M8e, ADR 0039): an organization administrator encrypts the disk of an
unencrypted device with a supported layout without reinstalling it and follows the encryption in the portal
(`docs/operations/in-place-encryption.md`). Organization creation no longer fails when Authentik answers slowly, and
the software list answers quickly at a few thousand packages. **Upgrade order: the server first, then the agents**
(`docs/operations/upgrade.md`): agents older than this release refuse the encryption request as unsupported. Coming
from 0.1.0-alpha.3 or earlier, follow the notes of 0.1.0-alpha.4 first (agents before the server). Fleet moves to
v4.93.1: take the Fleet dump before the upgrade (`docs/operations/upgrade.md`, step 3). Migration 00067 builds an
index on the vulnerability findings during the migration step; it takes well under a second at 200 000 findings,
while vulnerability updates from the inventory sync wait. `paddock-revoke` stays unsigned, and revocation (Lock,
Destroy, dead man's switch) stays disabled behind `PADDOCK_REVOCATION_ENABLED`. Schema: migrations 00066–00067
(control-plane database); the audit database is unchanged.

### Added

- In-place encryption, admin API and server (M8e, ADR 0039): `POST /api/v1/devices/{id}/encrypt` asks an
  unencrypted device with a supported disk layout to encrypt its root volume in place (organization administrators,
  with a step-up, the typed hostname and a backup acknowledgement), and `POST /api/v1/devices/{id}/encrypt/cancel`
  cancels the request until the device restarts. The device and its disk (`GET /api/v1/devices/{id}`, `…/disk`)
  carry the conversion's phase and progress as `disk_conversion`, `GET /api/v1/devices` filters by the disk state
  `encrypting`, the attention list reports `disk_conversion_failed`, and a device's command list
  (`GET /api/v1/devices/{id}/commands`) shows each command's `params`. Devices receive the organization's boot PIN
  length in their bundle. An uninstall is refused while a conversion is active; Lock, Destroy and Retire withdraw a
  request the device has not received. Upgrade: server first, then the agents; agents before M8e fail the command as
  unsupported. Schema: migration 00066.
- Runbook `docs/operations/in-place-encryption.md` for the in-place encryption: how it works, the supported layouts
  and every preflight reason, what the user sees, the escrowed keys, recovery when a device does not come back after
  the restart, aborting with and without a running agent, a cleanup that does not finish, completing the encryption
  by hand, and removing Paddock, Lock and Destroy during a conversion. The VM system gates of the in-place encryption
  run on throwaway VMs (`make system-test VM=paddock-ie-2604|paddock-ie-2404`).
- An unencrypted device now checks, without changing anything, whether its disk can be encrypted in place and
  reports the result with its health: eligible or not and why, the release, the disk layout, the initramfs generator
  and, on devices still on initramfs-tools, which packages the switch to dracut would remove. The check runs at most
  every 10 minutes and only while the device is unencrypted. While an encryption of the root volume is unfinished
  the device reports the disk state `encrypting` and leaves its keyslots alone.
- An unencrypted, eligible device now accepts the request to encrypt its disk in place and prepares itself
  without touching its data: it stores a new key in Paddock as the disk's first recovery key and waits until the
  server has it, switches to dracut where initramfs-tools is still in use (only when the switch would remove nothing
  but initramfs-tools and brltty, and checked afterwards), and builds the start-up image that encrypts the disk at the
  next restart. Signed-in users are asked to restart with a desktop notification, repeated every 4 hours. Until the
  restart an administrator can cancel from the portal, or an operator with `sudo paddockd encrypt-abort` at the
  device; the device then removes the prepared files and rebuilds its start-up images, and keeps retrying until no
  start-up image carries the encryption step any more. Removing Paddock is refused with `conversion_pending` while an
  encryption is prepared, running or not yet finished, and no supervisor upgrade starts while the device prepares.
- Portal: the disk card of an unencrypted device shows whether it can be encrypted in place, or why not, and lets
  organization administrators start the encryption after a step-up, a backup acknowledgement, a reason and the
  typed hostname; the dialogue names the restart, the boot PIN, the expected duration and, on devices still on
  initramfs-tools, the packages the switch to dracut removes. The card then follows the encryption (requested,
  prepared, the progress with the remaining time or the pause reason, completed, failed with a runbook link),
  offers the cancel until the device restarts, and warns while the key still lies on the boot partition. Remove
  Paddock is refused while an encryption is active, Lock and Destroy warn about it, the device list filters by
  `Encryption in progress`, and the attention list names failed encryptions. The admin API answers a cancel of an
  encryption the device already started with the problem code `conversion_not_cancellable` (409; was
  `invalid_state`).
- At the restart after the preparation, a prepared device now encrypts its disk in place before the system starts:
  the start-up image checks and shrinks the root file system to make room, writes the encryption header with the
  stored key and continues the start on the encrypted disk; later restarts open the disk the same way until its own
  unlock method takes over. On battery power, or when any step before the header fails, the device starts unencrypted
  as before and reports why, so that a new request can follow. A device that has another encrypted volume besides the
  root disk is not eligible (`other_luks_present`), nor is one set up to resume from hibernation
  (`hibernation_configured`) or, with LVM, one whose LVM configuration filters devices or uses a devices file
  (`lvm_filter`, `lvm_devicesfile`) or whose LVM configuration cannot be read (`lvm_unknown`).
- After that restart the device encrypts the rest of its disk in the background at low priority, while it is in
  normal use. The work pauses on battery power, continues when mains power returns or after any restart, and is
  reported in the device's health with its progress, the remaining time and the reason for a pause, together with the
  start, the completion or a failure of the encryption. The device trusts what its disk says: if the disk was
  encrypted at a restart the device did not expect (for example after a cancelled preparation whose clean-up was
  still unfinished), it continues that encryption and restores the start-up step first. Once the boot PIN (or, under
  TPM-only unlock, the TPM) is set up, the device rebuilds its start-up images so that the disk unlocks through the
  TPM and the stored key leaves the boot partition. Until then a skipped PIN is asked for again at every start, the
  health reports that the key still lies on the boot partition, and the disk is not reported compliant. The device
  then completes the usual disk setup on its own, right after the rebuild rather than at its next check, and removes
  the temporary disk key. Before a Lock or Destroy is carried out the background encryption is stopped, and it does
  not resume on that device afterwards, also when the revocation is refused.
- Start-up images are rebuilt one kernel at a time into a separate file, checked, and only then put in place, so that
  an interrupted rebuild never leaves a device without a working start-up image. The device waits instead of failing
  while the boot partition has too little room (health `initrd_issue: boot_space_low` with the bytes needed and free),
  while a kernel cannot be rebuilt (`kernel_not_buildable` with the kernel), when no kernel can boot
  (`no_bootable_kernel`), or while a package installation holds the package manager (`paused_reason: packages_busy`
  with the time since when). A clean-up that cannot finish reports why in `cleanup_error`.
- Leftover start-up images of removed kernels that still carry the encryption key are overwritten and removed
  (`orphan_initrd_removed`). A file that may carry the key and also has a link outside the boot images is left alone
  and reported as `key_material_hardlinked`; one that a bootable kernel's start-up image points to is kept until that
  kernel's image is rebuilt (`key_material_shared_bootable` with the kernel). Overwriting never takes extra room on
  the boot partition; on btrfs such files are only removed.
- Admin API and portal: an in-place encryption now shows what the device reports while it waits or is stuck. While
  the device prepares and a software installation or update holds the package manager, the conversion carries
  `paused_reason: packages_busy` with `paused_since`; after a failure or a cancel, `cleanup_error` says why the
  device's last cleanup attempt did not finish; and `initrd_issue` (with `initrd_issue_kernel`, `boot_space_needed`
  and `boot_space_free` where they apply) says why the device cannot rebuild its boot files, for example too little
  room in `/boot`. All fields are optional additions to `DeviceDiskConversion`; the portal's disk card explains each
  of them.

### Security

- Go toolchain 1.27.3 (was 1.27.2; build image `golang:1.27.3-trixie`, CI, every module): a security release with
  fixes to `crypto/x509`, which every Paddock binary uses for its TLS and device certificates.

### Changed

- The boot PIN, or under TPM-only unlock the TPM, is now set up at the first start after the background encryption
  has completed rather than at the restart that starts it: the disk cannot take a new unlock method while its
  encryption is unfinished, and the device no longer tries and fails at every start meanwhile. Until then the health
  reports `enrollment_deferred: reencrypt` (an optional addition to the disk's conversion health in the admin API;
  `reencrypt_after_completed` if the disk still refuses after the completion) and the portal's progress panel says
  so. The restart notification before the encryption no longer promises the PIN at that restart; once the encryption
  has completed, signed-in users are asked with a desktop notification, repeated every 4 hours, to restart. The key
  stays on the boot partition until that restart and the setup at it, and the setup is not reported as tampering.
  The portal's disk card and encryption dialogue say the same: the user restarts once to start the encryption and
  once more after it has completed, when the boot PIN or the TPM unlock is set up. The disk card also names the
  reason `initrd_tools_missing` (the device's tools cannot list its start-up image) instead of showing the code.
- Updated bundled components: Fleet and fleetctl v4.93.1 (was v4.93.0; bug fixes), AWS CLI 2.38.2 (was 2.38.1).

### Fixed

- A Lock or Destroy during an unfinished in-place encryption is now confirmed as erased: the device counts only the
  keyslots that hold a key, and reports the key-less keyslot of the unfinished encryption, which the erasure leaves
  behind, separately. The portal names that leftover keyslot under the volume. Before, the confirmation reported such
  an erasure as incomplete although the disk no longer unlocked. As before, data the encryption had not yet reached
  stays readable on such a disk; the portal now says so under the volume. A keyslot of a type the device does not
  know, or a header without keyslot information, is reported as not erased.
- Creating an organization no longer fails when Authentik answers slowly: its groups and device login objects are
  set up with independent steps in parallel (about a third of the round trips), a create step whose answer was lost
  finds the object instead of failing, and the setup continues when the browser gives up. It is bounded at 60 s;
  beyond that, or when Authentik is down, the request fails with `502 upstream_unavailable` (never a 500) and the
  organization can be created again. Single Authentik requests slower than 2 s are logged.
- Creating an organization in the portal no longer waits on the worker's periodic identity reconcile: that round
  sends one Authentik request at a time instead of a dozen, so it no longer saturates Authentik while an
  administrator waits. The create itself no longer looks up Authentik's flows, signing key and scope mappings every
  time (they are reused for an hour; the most expensive requests on a loaded Authentik), and the device login
  application gets its access policy before its provider is attached, so it never admits users without the policy.
- In-place encryption no longer fails at the preparation with `escrow_not_stored`: the device stored the conversion
  key in a form the server refused, so no device could be prepared. Found by the new VM gates; the server's
  acceptance rules are unchanged.
- In-place encryption now accepts an installed device whose `/etc/fstab` names the root file system as
  `/dev/disk/by-uuid/<uuid>`, the form the Ubuntu installer writes for a root without LVM; such devices were reported
  `root_reference_unsupported`. Other device links stay refused.
- The software list (`GET /api/v1/software`, portal Software page) answers within a second at a few thousand
  packages: the check whether a package has vulnerabilities scanned every finding of the organization once per
  package, so a page took about a minute and timed out. Migration 00067 adds an index for that check; the migration
  step of the upgrade builds it and holds back vulnerability updates from the inventory sync for well under a second.

## [0.1.0-alpha.4] - 2026-10-19

Fixes from the first lab installation on real hardware (M8x) and their follow-ups (M8f), the device lifecycle (M8d),
the device name set from the platform (M8h) and the optional automatic unseal of OpenBao (M8u). **Upgrade order:
update the agents on the devices first, then the server** (`docs/operations/upgrade.md`): the Hello PIN fix and the
last-administrator fix live in the agent, and every device lifecycle change is additive in both directions; devices
update `paddock-supervisor` once the server runs this release. After the upgrade every Authentik sign-in asks for a
second factor, and every administrator signs in to the portal and confirms their identity with a WebAuthn
authenticator. Restart Authentik once after the upgrade (`docs/operations/upgrade.md`). Schema: migrations
00049–00065 (control-plane database); the audit database is unchanged.

### Security

- Every portal sign-in is now refused without a second factor; the default brand's authentication flow and
  Authentik's default authentication flow ask for a second factor as well. After the upgrade every Authentik sign-in
  (the portal, Authentik's own interfaces including `akadmin`, the device approval page) asks for a second factor and
  enrols one when missing (GHSA-34qw-8jfm-g64v, medium).
- A step-up (identity confirmation) is refused when Authentik answered it without authenticating again, that is with
  a token whose authentication predates the step-up; the user is asked to confirm again instead of the earlier sign-in
  counting as a step-up. The portal's failure message suggests waiting 20 seconds after a recent confirmation.
- A step-up (identity confirmation) now proves a WebAuthn authenticator to Paddock itself: the identity provider names
  the authenticator classes it validated and the portal refuses any other factor (GHSA-wj3v-v8f4-pp78, medium).

### Added

- Optional automatic unseal of OpenBao (ADR 0035). A platform administrator opens the new portal page *Platform* →
  *OpenBao*, reads a versioned disclaimer of the risks and confirms, with a step-up, by typing "I understand and accept
  the risk" (German: "Ich verstehe und akzeptiere das Risiko"); the page also shows the seal status, who acknowledged
  which disclaimer version, the unsealer on the host and the last automatic unseal. The host operator then runs
  `./paddock auto-unseal enable` with three custodians, who type their unseal shares without echo; the command refuses
  without the portal acknowledgement, stores the shares in `.secrets/openbao/auto-unseal-shares`, sets
  `PADDOCK_AUTO_UNSEAL=yes` and starts the new `paddock-unsealer` service (its own PostgreSQL role, no AppRole), which
  unseals OpenBao after every restart while the setting is on. Disabling in the portal stops it at once;
  `./paddock auto-unseal disable` removes the unsealer and the shares of its bundle directory (delete the copy in a
  bundle directory kept for rollback as well, `docs/operations/openbao.md` section 6); `./paddock auto-unseal status`
  reports the state.
  Every step is audited (`platform.auto_unseal_enabled`, `platform.auto_unseal_disabled`,
  `platform.openbao_auto_unsealed`); `paddock-server admin auto-unseal show|verify|disable` serves the host. The
  shares on the host are residual risk RR-43: `./paddock check` gains the item `openbao auto-unseal` and the status
  `WARN`, warns on every run on a production control plane and passes on a lab host. Alerts
  `PaddockAutoUnsealWithdrawn` (shares left on the host after disabling) and `PaddockAutoUnsealerDown` (the unsealer
  does not report). Lab hosts that unseal with a cron job move to it as `docs/operations/lab-install.md` section 11
  describes. `./paddock secrets` now also creates the unsealer's database secrets.
- A device can be named from the portal; the device applies the name as its hostname at its next check-in and keeps
  it; the device page shows whether the name is pending or applied, and an invalid name is rejected with the rule it
  breaks (uppercase, invalid characters, a leading or trailing hyphen, too long, `localhost`, a domain). Runbook
  `docs/operations/device-name.md`: what changes on the device, the effects on DHCP and DNS, and `/etc/hosts` as a
  managed file.
- A platform administrator sets an organization's domains in the portal: the create dialog of *Platform* →
  *Organizations* takes them, the list shows them, and the row action *Domains* changes them. A create with domains
  records `organization.created` and `organization.domains_changed`.
- Every portal button that sends a request shows a progress indicator and is disabled until the answer arrives, so a
  second click no longer sends the request twice.
- The portal shows until when the last identity confirmation (step-up) is valid: a chip in the app bar and a line in
  the user menu; `GET /api/v1/me` carries `step_up_valid_until`. A long organization name in the app bar is shortened
  and shown in full on hover or tap.
- The permission profile form warns before saving when the class or the commands grant root in effect (also through
  a pair of commands, one writing what the other runs), and says that saving then needs an organization
  administrator with a step-up. New read-only endpoint `GET /api/v1/permission-profiles/root-equivalence`.
- Managed files: a path with characters outside ASCII shows a hint (it is still saved as given), and the page links
  to the operator roots. The German portal calls operator roots „Freigegebene Verzeichnisse“.
- Users whose username does not end with one of the organization's domains are marked "No organization domain"
  (they cannot sign in on devices), the user page explains why, and the Users page of an organization without a
  domain shows a banner. Users in the API carry `domain_match`.
- A weekly upstream version watch compares the pinned container images, the Himmelblau version, fleetd and the Fleet
  NVD release with upstream and keeps one GitHub issue with the label `upstream` per outdated pin, naming the gates
  to run before the bump; `make upstream-check` prints the same comparison locally.
- A device has owners: the users responsible for it, set on the device page (at most 20, audited as
  `device.owners_changed`), shown and filterable in the device list, searchable by user name, and listed under
  *Devices owned* on the user page. Owners get no login or sudo rights through this setting.
- The device page shows the hardware facts the inventory reports (manufacturer, model, serial number, processor,
  memory, disk size); the device search finds a device by its serial number. Free disk space, uptime and network
  addresses stay in Fleet.
- A device group can override the organization's contact thresholds (*Contact thresholds*, with a laptop preset of
  5 days / 35 days): its members are warned and presumed lost by the group's values, a device in several groups takes
  the most lenient ones, and `device.stale_warning` / `device.stale_critical` name the source of the threshold.
- Login history (off by default): `PUT /api/v1/settings/login` takes `login_history_enabled` and
  `login_history_days` (7–365, default 90); while it is on every session start a device reports is stored and listed
  by `GET /api/v1/devices/{id}/logins`; the worker deletes older entries every 6 hours (`retention.purged`, store
  `device_login_event`), and switching it off deletes every entry at once. Sessions that started before the switch-on
  or outside the retention period are not stored, and a login time from a device's clock is capped at the server's
  time plus 5 minutes.
- *Login & privileges* has a *Login history* section with the privacy notice (works council agreement), and the device
  page a *Logins* tab. With the history on, agents of this release report every session start instead of once per
  user and day.
- Agent update policy (*Updates* → *Agent updates*, `agent_update_policy` of the update settings and of device groups,
  also in the declarative document): with *Manual*, devices install no agent release, and no newer fleetd, unless an
  administrator requests it for the device; *Automatic* (default) follows the rollout waves. A group set to manual
  wins over automatic.
- *Update agent now* on the device page (`POST /api/v1/devices/{id}/update-agent`, organization administrators and
  operators, audited as `device.agent_update_requested`): the device installs the offered agent release at its next
  check-in, outside its rollout wave and regardless of the update policy, with the usual self-test, probation and
  rollback. The request ends with the device's report or after 24 hours.
- Devices update `paddock-supervisor` themselves, in the waves of the release's rollout: once a device's wave is
  reached, an agent of that release installs the package through a transient unit, waits up to 10 minutes for its next
  check-in and restores the previous supervisor otherwise (audited as `device.supervisor_updated` or
  `device.supervisor_update_failed`). Supervisor upgrades that failed on the device count toward the rollout's failure
  threshold (a rollback only because the server was unreachable does not), and a halted rollout offers no supervisor
  package. The update policy applies, and *Update agent now* also brings the supervisor package to a device outside the
  current wave and stays open until the supervisor followed; a failed version is not installed again, except after a
  rollback only because the server was unreachable, which is retried after 24 hours, up to 3 times.
- Devices can be removed from Paddock from the portal (*Danger zone* → *Remove Paddock*, organization administrators
  with a step-up and the typed hostname, `POST /api/v1/devices/{id}/uninstall`) in two modes, leave as is or reset, and
  the request can be cancelled until the device received it, or requested again or cancelled once the device's removal
  report is 24 hours overdue (`report_overdue`, which also withdraws a command the device received but did not answer
  yet); a cancelled removal never starts on the device. The device is retired after it reported the removal of the open
  request (`device.uninstalled`, `device.retired` with reason `uninstalled`); a removal report without such a request is
  audited and retires nothing. Pending removals appear on the attention page. Lock and Destroy take precedence:
  requesting one cancels a pending removal (recorded on `revocation.requested` as `uninstall_cancelled` with the
  removal's `uninstall_command_id`), and the device page warns when the device had already received the removal and may
  have removed `paddock-revoke`.
- Agents of this release carry out the removal in the transient unit `paddock-uninstall` once the server accepted
  the request, after a running supervisor upgrade but waiting for it 30 minutes at most: they stop and purge
  Paddock's services and packages, keep every user file and the disk encryption, keep the managed local administrator
  when it is the last local administrator, and leave a summary in `/root/paddock-uninstall/result.json`.
- Runbook `docs/operations/uninstall.md`: both removal modes step by step, what stays, the last-administrator guard,
  the TPM clear and its firmware fallback, cancelling, and what to do when a device's removal report never arrived.
- Disk unlock mode for new installations (*Login & privileges → Disk encryption*, device groups can override it, also
  in the declarative document): TPM + boot PIN (default) or TPM only, with a security notice. The autoinstall embeds
  the mode of the token's group, bundles carry it, and devices whose keyslots do not match are reported as
  `unlock_mode_mismatch`; `docs/operations/disk-recovery.md` describes the conversion with the recovery key.
- Agents of this release set up a `tpm_only` installation at its first boot without a PIN dialogue (the TPM unlocks
  the disk while Secure Boot is unchanged), count the recovery key and the mode's TPM keyslot as compliant, and report
  a disk enrolled for the other mode as `unlock_mode_mismatch`; they never enroll or wipe a TPM keyslot of an
  installed device.
- The disk encryption card tells for an unencrypted device, and for one encrypted outside Paddock, that a reinstall
  with the Paddock autoinstall is needed, and names devices with a separate `/boot` as candidates for the in-place
  encryption planned for a later release; nothing on the disk changes.
- Agents report the installed versions of paddockd, the supervisor, paddock-revoke, Himmelblau and fleetd at every
  check-in. The server keeps the expected versions (the current release, the newest fleetd package, the compiler's
  Himmelblau version; `GET /api/platform/v1/component-targets`), the device detail lists every component with its
  status, and `GET /api/v1/devices?component_outdated=true` finds devices with an outdated component.
- The device page shows the panel *Components* (installed and expected version of the agent, the supervisor,
  paddock-revoke, Himmelblau and fleetd with their status), the device list a *Components* column and the filter
  *Component outdated*, and the platform's *Agent releases* page the card *Rollout targets*. The target is the last
  completed release (a running rollout does not move it), and a component newer than its target counts as up to
  date; all three places say so.
- The attention page lists a device that keeps checking in but has not applied its newest configuration for more than
  an hour (kind *Configuration behind*).

### Changed

- The device lifecycle changes (M8d) work in either upgrade order: every protocol and bundle change is additive; older
  agents ignore the new bundle fields, and the new event types (`agent.supervisor_updated`, `agent.uninstalled`) are
  only sent after a bundle section or command of this release. The release as a whole updates the agents first (see
  above).
- The hostname shown for a device follows what the device reports at every check-in instead of the name it had at
  enrollment.
- A portal sign-in reuses an existing Authentik session that was authenticated with a second factor instead of asking
  for the password again; a session without a second factor is still refused.
- Devices install Himmelblau 4.0.6 by default (`PADDOCK_HIMMELBLAU_VERSION`, previously 4.0.4): a device code
  that expired at the login screen no longer ends in `PAM_SYSTEM_ERR`. The device-login guide lists the messages of the
  login screen and what they mean.
- The dialog that creates an enrollment token explains which members of the sudo group a device keeps and links to
  the break-glass accounts; for an organization without a domain it warns that its devices get no login management
  and no managed local administrator. `GET /api/v1/me` names the organization's `domains`.
- Clearer texts: a device's local administrator password that waits for the device's confirmation is no longer shown
  as "none yet"; permission profiles and device access explain that they apply to directory users only, never to
  local accounts; the password switch of a profile explains what it does.
- The device list shows Online only for devices that checked in within the last 15 minutes and names a stopped agent
  on the device and the attention page. A device without a check-in for longer shows *No recent contact* until the
  organization's silence threshold applies (contact filter `unseen`, overview field `devices.no_recent_contact`, part
  of the Silent tile); a stopped agent reported by fleetd is the attention kind `agent_not_running` until fleetd sees
  it running again.
- A repeated identity confirmation (step-up) is possible 20 seconds after the previous one instead of a minute; the
  step-up asks the identity provider to authenticate again after 20 seconds.
- The portal sign-in enrols a WebAuthn authenticator when the administrator has none: after the TOTP code (or one of the
  account's recovery codes, which the identity provider counts as the TOTP factor) for an administrator with TOTP only,
  after the password for a new administrator without any authenticator. Keep administrators' recovery codes in custody.
  TOTP stays usable for the identity provider's own interfaces and the device login.
- *End all sessions* now also signs every portal user out of the identity provider, so a stolen browser session cannot
  sign in again without password and authenticator.
- The dead man's switch setting says that a blocked connection triggers the lock like an outage.
- Updated bundled components: Caddy 2.11.7 (was 2.11.6; fixes a crash when proxying over HTTP/2 and streams cut off
  after a minute), Authentik 2026.8.4 (was 2026.8.3), RustFS 1.0.3 (was 1.0.1), Fleet and fleetctl v4.93.0 (was
  v4.92.3; Fleet migrates its own database at its first start: take a Fleet dump before the upgrade and restore it
  when rolling back, `docs/operations/restore.md`), AWS CLI 2.38.1 (was 2.37.9).

### Fixed

- A portal sign-in or step-up no longer fails with "Sign-in failed" when Authentik answers "authentik starting" for a
  moment while it completes the sign-in; the portal repeats the request for up to about two seconds.
- When Valkey stalls or is unreachable, the device API now answers 503 with `Retry-After` (problem code
  `backpressure`) instead of 500. Devices back off and retry instead of reporting a server fault.
- The permission profile form no longer leaves an unhandled error in the browser console when the root-equivalence
  preview cannot reach the server; the preview just stays empty.
- A release public key or another secret file of a Paddock service with mode 0600 made the roles fail with
  "permission denied". `./paddock check` now names such a file (item `secret files readable by the Paddock services`)
  with the `chmod 644` to run, and `./paddock agent-release` refuses a release directory the `paddock-api` service
  cannot read and names `chmod -R a+rX`.
- A refused portal sign-in names the reason: no Paddock role group, roles in several organizations, several roles in one
  organization, platform and organization roles on one account, or an inactive organization. The audit event
  `admin.login` carries it as `denial_reason`.
- While OpenBao was sealed at the start of `paddock-api`, the portal sign-in answered with an internal error. It now
  shows *The server's key store is sealed*; `paddock-server healthcheck` and the timeout line of `./paddock up` name
  the reason (`session keys not loaded: OpenBao is sealed or unreachable`).
- The device code at the login screen is valid for ten minutes (it expired after one minute).
- The Hello PIN keeps working while a user stays signed in; the login component refreshes a signed-in user's cached
  attributes at the next PIN sign-in or after 30 days. The fix is on the device (`cache_timeout` in
  `himmelblau.conf`): **update the agents first**; a device with an older agent keeps losing the PIN after a few
  minutes of use. After 30 days without a PIN sign-in the user signs in with the device code and sets a new PIN
  (residual risk RR-40).
- The agent no longer removes the last administrator of a device: a privileged local group (sudo, admin, wheel) that
  has no break-glass account as a member keeps all its members, and each is reported once as
  `device.tamper_sudo_group_member` with `removed=false` and `reason=last_admin`. The members are removed once a
  break-glass account or the managed local administrator is a member; such an account counts only if it exists on the
  device and its password is not locked (`!` or `*` in `/etc/shadow`). Configure break-glass accounts before the first
  enrolment of a device whose administrators are not managed by Paddock.
- The login component no longer removes accounts from the sudo group or re-adds them to local groups every five
  minutes; Paddock alone manages sudo.
- Public portal pages such as the sign-in refusal use the browser's language (German or English) before a session
  exists.
- `./paddock logs` and `make logs` redact token values that the identity provider prints for refused token refreshes.
- A release that failed its probation is rolled back exactly once; the restarted agent no longer re-installs it before
  the rollback is recorded.
- Authentik's own sign-in asks a user with an authenticator for the second factor once instead of twice; a sign-in
  with a recovery code, e-mail, SMS or Duo code is still followed by a prompt for a second factor of the user's own
  devices, where a further recovery code is accepted as well.

## [0.1.0-alpha.3] - 2026-10-17

Hardening release (milestone M8s) plus the lab installation profile (M8a). **Upgrade order: update the agents on the
devices first, then the server** (`docs/operations/upgrade.md`); every administrator enrols a WebAuthn authenticator
before the upgrade.

### Security

- Granting root on devices required the administrator step-up only for profiles declared as full: restricted profiles
  with root-equivalent commands, combinations of grants, and managed files on root-equivalent paths could be created
  or assigned by operators and API tokens without it. Fixed by the effective-privilege step-up and the managed-file
  path tiers below (GHSA-qg7r-3q9c-w6jf, high).
- Portal sessions survived logout, role removal and deactivation for up to 8 hours, and API tokens outlived their
  creator's rights. Fixed by server-side sessions and the token creator check below (GHSA-7whf-c2cp-cx8m, medium).
- The escrow upload did not bind its size and the edge had no body limits. Fixed by the size-bound upload and the edge
  limits below (GHSA-j64g-m99w-9jv7, low).

### Added

- Security review of existing data (ADR 0034): `GET /api/v1/security-review` lists effectively Full permission
  profiles and managed files on sensitive paths that no organization administrator has confirmed yet, and managed
  files on denied paths; `POST /api/v1/permission-profiles/{id}/confirm-root-grant` and
  `POST /api/v1/managed-files/{id}/confirm-sensitive` confirm an item with a step-up. Permission profiles carry
  `root_grant_confirmed_at`, managed files `sensitive_confirmed_at`, and the overview `security_review` counts. The
  portal shows a banner on the overview and the page Security review. Run `paddock-server admin security-review`
  once after the upgrade; it prints the counts per organization and records them in the audit log. Existing grants and
  files keep working while they await review.

- End all sessions: a platform administrator ends every portal session of the installation under *Platform* →
  *Sessions* (`POST /api/platform/v1/sessions/end-all`, with a step-up, audited as `platform.sessions_ended`), or with
  `paddock-server admin end-sessions` when the portal is not usable.

- Lab installation profile (plan M8a, ADR 0029; not for production): `PADDOCK_HOST=lab` runs control plane and audit
  domain in one Compose project on one amd64 host behind the operator's own TLS-terminating reverse proxy. The
  bundle ships `compose.lab.yaml`, `caddy/Caddyfile.lab` (plain-HTTP sites, `auto_https off`), the settings template
  `.env.lab.example` and the Nginx reference configuration `nginx/paddock.conf.example`. Caddy publishes one port,
  `PADDOCK_LAB_HTTP_PORT` (default 8080) on `PADDOCK_INTERCONNECT_ADDR`, and nothing else is published; the proxy
  `PADDOCK_EDGE_TRUSTED_PROXIES` is the only peer whose `X-Forwarded-For` counts; the roles reach the public names
  through the proxy at `PADDOCK_LAB_PROXY_ADDR`, and the certificate probe watches the proxy's certificate. Backups
  are optional (`PADDOCK_LAB_BACKUP=yes` adds `compose.backup.yaml`). `./paddock secrets` writes the secrets of both
  halves and one internal CA; every `bootstrap` subcommand and `agent-release` run on a lab host; `./paddock check`
  and `./paddock up` print `lab profile (PADDOCK_HOST=lab): not for production` as their first line. `prod-check
  --host lab` replaces the host-shape items with `only Caddy's HTTP port published, on the bind address`,
  `Caddy: plain HTTP behind the TLS proxy`, `lab: edge admin allow list`, `lab: caddy has no hostname aliases` and
  `lab: roles resolve the public names to the proxy`, and makes `edge client address` stricter (`X-Forwarded-For`,
  specific proxies, never `private_ranges`); every other production item applies unchanged. Guide:
  `docs/operations/lab-install.md`.

- Audit codes `admin.sessions_revoked`, `platform.sessions_ended`, `permission_profile.root_grant_confirmed`,
  `managed_file.sensitive_confirmed`, `organization.security_review_required` and `device.header_object_rejected`
  (plan M8s), the parameter `effective_class` of the permission-profile and profile-assignment events, the parameter
  `tier` of `managed_file.created` and `managed_file.updated`, and the problem code `session_store_unavailable`
  (503) in the registry, the portal's messages and `docs/compliance/audit-codes.md`.

- `SECURITY.md`: supported versions, how to report a vulnerability privately, response targets, scope and how to
  verify releases.

### Changed

- A device group can be deleted once its enrollment tokens are revoked, expired or used up; only an active token
  keeps it (409 `in_use`).

- Upgrade order for the release with the managed-file path tiers: roll out the new agent to every device first, then
  upgrade the server. The new server no longer ships managed files on denied paths, and an older agent would delete
  unchanged files that leave its bundle (`docs/operations/upgrade.md`, residual risk RR-36).

- Managed files on paths outside the denied catalog are sensitive by default: an operator manages files without a
  step-up only below the organization's operator roots (new setting, empty by default: portal Configuration →
  Operator roots, `GET|PUT /api/v1/settings/managed-files`, declarative `settings.managed_files`, audited as
  `settings.managed_files_changed`), and not for executables, scripts, compiled bytecode, Java archives, shared
  objects or `.d` directories there.
  Package-manager, boot-loader, interpreter, shell, display-manager, audit, firewall, network, directory-client,
  trust-anchor, PAM, identity, new-user skeleton, service-environment and container-runtime directories can never be
  operator roots, below `/etc/` and
  `/usr/local/etc/` alike. Existing definitions keep working; the security review lists
  those that now need a confirmation.

- Granting root in effect needs an organization administrator with a step-up also when it happens indirectly: a
  profile change or assignment whose commands combine with another assigned profile of the organization into a
  root-equivalent pair, adding a user to a Paddock group that carries such a grant, or adding a device to the device group of one.
  Operators receive 403 `forbidden`, API tokens 403 `step_up_required`; the portal runs the step-up for group
  members and device groups. Creating an enrollment token into such a device group, and approving or releasing a
  device in one, follow the same rule, as does creating a user who would receive root through grants to everyone. A
  device that an auto-approve token would activate into such a grant is enrolled pending and waits for an approval;
  `device.enrolled` records it with `auto_approve_withheld: root_grant`. Membership synchronized from the upstream directory is not affected. Creating or
  changing an effectively Full profile is now reserved to organization administrators as well.

- Managed files on sensitive paths (cron, systemd, login scripts, SSH, network hooks, logrotate, files directly in
  `/etc/`, `/etc/<name>.d/` directories and executables) can only be created or changed by an organization
  administrator with a step-up, in the portal, the admin API and `PUT /api/v1/config`; operators keep ordinary
  application configuration. Definitions on denied paths are refused, and existing ones are no longer shipped to
  devices or listed in a device's effective configuration; they stay in the database for review. Managed files carry
  `tier`, shown as a chip in the portal.

- Creating, changing the commands or class of, assigning or re-scoping a permission profile that grants
  root-equivalent sudo rights (class `full`, or restricted with a root-equivalent command) now requires a step-up, in
  the portal, the admin API and `PUT /api/v1/config`; API tokens cannot make such changes and receive 403
  `step_up_required` with an explanatory detail. Permission profiles carry `effective_class`, and the portal shows
  it ("Full (effective)") and asks for the typed name before the step-up.

- Managed-file paths fall into three tiers (ADR 0034): denied paths (sudo, PAM, NSS and the other protected areas, the
  loader, boot, initramfs, kernel module, sysctl, AppArmor, udev and polkit configuration, and the units of Paddock,
  fleetd, Himmelblau, SSH, GDM, sudo and systemd, and systemd's type-wide drop-in directories such as
  `/etc/systemd/system/service.d/`, and the runtime unit directories `/etc/systemd/system.control/` and
  `/etc/systemd/system.attached/`) are refused by server and agent; sensitive paths (cron, systemd,
  login scripts, SSH, network hooks, logrotate, any file directly in `/etc/`, any `/etc/<name>.d/` directory and every
  file with an execute bit) and ordinary application configuration below `/etc/`, `/usr/local/etc/` and `/opt/`
  remain manageable. The agent no longer deletes a managed file on a now-denied path when its definition leaves the
  bundle: it keeps the file unchanged, stops tracking it and reports `left_denied_file`.

- API tokens stop working once their creator's account is disabled or no longer has a role that may create the
  token's role; such a use is refused with 401 and recorded as `api_token.use_denied` with reason `creator_inactive`.
  A token that must outlive its creator needs a creator who keeps the role.
- The worker follows administrator accounts to the identity provider every identity sync interval
  (`PADDOCK_IDENTITY_SYNC_INTERVAL`, default 5 minutes): an administrator moved to another role group takes the new
  role, one removed from every role group or deactivated is disabled, and every portal session of the account ends
  (`admin.sessions_revoked` with reason `role_changed`, `removed` or `deactivated`). A platform administrator removed
  from `paddock.platform.admins` or deactivated loses every portal session the same way. When the role groups cannot
  be read, or list no members at all while accounts exist, nothing changes and the round reports the failure.
- A step-up now also checks the administrator's role groups in the identity provider. When they no longer grant the
  session's role in its organization, the step-up is refused, the account takes the current role (or is disabled when
  it has none), every portal session of the account ends and `admin.sessions_revoked` is recorded. A disabled account
  can no longer decrypt escrowed secrets; the next successful login enables it again.
- Portal sessions are now also kept on the server, in Valkey. Signing out ends the session on the server, so a copied
  session cookie no longer works afterwards. While Valkey is unreachable the portal answers 503
  `session_store_unavailable`; devices and API tokens are not affected. Administrators sign in again after the
  upgrade.
- The step-up accepts WebAuthn authenticators only; TOTP codes no longer complete a step-up (the portal login still
  accepts them). Before upgrading, every administrator enrols a WebAuthn authenticator in Authentik's user settings
  (`https://auth.<domain>/if/user/`, MFA devices); an administrator with TOTP only cannot reveal keys, lock or destroy
  devices, create API tokens or grant root-equivalent rights until then. New administrators enrol a WebAuthn
  authenticator as well: the login still offers TOTP enrolment, which is not enough for a step-up. The development
  stack keeps a TOTP step-up through its development blueprint. The upgrade steps are in `docs/operations/install.md`,
  section 12.
- The upload URL of an escrowed LUKS header now binds the announced size: the object store refuses a body of another
  size, and the worker checks the stored object's size before reading it. An object of another size fails the escrow
  without being read and is recorded as `device.header_object_rejected`; it stays in the bucket for the operator
  (`docs/operations/disk-recovery.md`). A header the worker cannot check no longer holds up the others.
- Caddy bounds the request bodies it forwards on every site: admin 2 MiB (agent release uploads 130 MiB), auth
  16 MiB, device 2 MiB, bundles 1 MiB (escrow uploads 33 MiB), Fleet's device paths 64 MiB. A larger body is refused
  with 413.
- Containers run with tighter defaults: the Paddock roles drop every Linux capability and may not gain privileges,
  Caddy keeps only the capability to bind 80 and 443, and every service of every Compose file set has a process limit
  (`pids_limit`). `./paddock check` adds the item `container hardening`, which fails when an edit removes one of these
  settings. Keep Docker's default seccomp and AppArmor profiles enabled on the hosts.
- The admin API accepts request bodies of at most 256 KiB; a larger body is refused with 400 `invalid_request`. The
  declarative configuration (`PUT /api/v1/config`, 1 MiB) and the agent release uploads (128 MiB) keep their own
  limits. The api, gateway and escrow-reader roles now close a connection that takes longer than 60 seconds to send
  its request or 120 seconds to receive its answer; agent release uploads may take up to 10 minutes.
- `PADDOCK_ACME_EMAIL` no longer stops `compose.prod.yaml` from rendering when it is unset, because the lab profile
  has no ACME. A production control plane still refuses to run without it: `./paddock check` fails the Caddy item
  and Caddy refuses to start.
- `./paddock check` fails the published-ports item on every host when a service runs with `network_mode: host`,
  `container:…` or `service:` of an unknown service, which would expose ports the check cannot see.
- Attention list by device with a stale fleet (PDK-094): `GET /api/v1/attention/devices` reads the attention
  conditions once per query and applies its search, `kind` and device filters afterwards, and it reads device details
  only for the requested page. With 10 000 devices that each have an open staleness alert, the query time of a request
  (list and count) drops from 271 ms to 87 ms, and with `kind=agent_outdated` from 337 ms to 79 ms (`EXPLAIN ANALYZE`
  medians of the plan PostgreSQL uses for a reused statement, `docs/operations/capacity.md`). A device's own conditions
  (`device_id`) take about 50 ms instead of 15 ms at that fleet size. The results do not change. No migration.

### Fixed

- Attention list by device (PDK-103): a device's conditions in `GET /api/v1/attention/devices` come back in the same
  order on every request. Conditions of the same severity and the same time, such as `agent_outdated` and
  `disk_not_compliant`, are ordered by kind; before, their order could change between reloads. No migration.

## [0.1.0-alpha.2] - 2026-10-13

The first published pre-release. 0.1.0-alpha.1 was prepared but never published, and its tag was removed; its changes
are listed in its own section below and are part of this release.

### Added

- Overview: latest published agent release and running rollout (plan M7c decision 26, amendment 2026-10-12). The
  *Updates and agent rollout* panel shows "Latest published" while the newest published release differs from the
  release of the last completed rollout, and the running rollout with its wave, e.g. "Rollout 1.10.0: wave 2 of 4
  (10 %)". `GET /api/v1/overview` gains `updates.agent.latest_published`, `updates.agent.rollout` (`version`, `wave`,
  `waves`, `percent`, null while no rollout runs) and `updates.agent.ahead`, the active devices on an agent newer than
  the current release; `outdated` now counts only older agents and agents without a semantic version, as the attention
  kind `agent_outdated` does. Organization roles read these platform values through two functions of migration 00041.
- Failed agent rollback (ADR 0024): when a new agent release fails its probation and the supervisor cannot flip back
  to the previous version, the device reports the new outcome `rollback_failed` (event `agent.update_failed`, audit
  code `device.agent_rollback_failed`) instead of `self_test_failed`. The new version keeps running, the supervisor
  keeps the rollback pending in `probation.json` and retries it every 10 seconds, doubling up to every 5 minutes, also
  after a restart, until it succeeds and reports `rolled_back`. The rollout failure counts take `rollback_failed` like
  `rolled_back`, once per device; the attention list shows the new kind `agent_rollback_pending` while the device
  runs the release (migration 00040). There is still no downgrade through the update channel; the way back is
  documented in `docs/operations/agent-releases.md`.
- Client address behind proxies and CDNs (M7a step 1, ADR 0021): Caddy reads the client address from
  `PADDOCK_EDGE_CLIENT_IP_HEADER` (`none`, `X-Forwarded-For` right to left, or `CF-Connecting-IP`) only when the peer
  is in `PADDOCK_EDGE_TRUSTED_PROXIES`, validated by the new Caddy entrypoint `caddy/entrypoint.sh` (no `/0`, header
  and proxies together or neither). Caddy forwards the resolved address as `X-Paddock-Client-IP`, which the roles
  accept only from `PADDOCK_TRUSTED_PROXY_CIDRS` (default: private ranges) and use for the gateway's per-address
  limit, audit actors and access logs; `X-Forwarded-For` is no longer read by any role. `GET /api/v1/me` returns
  `client_ip`. The edge allow list moves into the shared snippet file `caddy/guards.caddy`:
  `PADDOCK_ADMIN_ALLOWED_CIDRS` now also restricts Authentik's administrative paths on `auth.` (`/if/admin/`,
  `/if/user/`, `/api/v3/` except the flow executor), while logins and the device-code approval stay public;
  `PADDOCK_INTERNAL_CIDRS` admits the Paddock roles to Authentik's API. An operator bundle of `Caddyfile.prod` needs
  `caddy/guards.caddy` and `caddy/entrypoint.sh` next to it. `prod-check` gains the items `edge client address`,
  `role trusted proxies` and `ip allow list bypass is off` and checks the two mounts. The development stack trusts
  private ranges, reads both headers and adds the untrusted listener 8444 for the gates.
- Application IP allow list (M7a step 2, ADR 0021): platform administrators manage the allow list of the portal and
  the admin API under `/api/platform/v1/ip-allowlist` (every write needs a fresh step-up); while it has entries,
  every api replica refuses sessions and API tokens from other addresses with 403 `ip_not_allowed` before any session
  or token is read, and follows changes within 2 s through a Valkey change counter. Until a replica has loaded the
  list it refuses every request with 503 `ip_allowlist_unavailable` (fail closed). A change that would exclude the
  caller's own address or remove the last entry is refused with 409 until confirmed (`confirm=lockout` or
  `confirm=disable`; any other value is 400). New audit codes `platform.ip_allowlist_changed`, `platform.ip_allowlist_denied` (aggregated per
  address and 10-minute window, at most 41 events per window and replica; `distinct_ips_capped` marks a summary of
  more than 10 000 addresses) and `platform.ip_allowlist_disabled`;
  metrics `paddock_ip_allowlist_*`. Migration 00036 adds the platform table `ip_allowlist_entry`.
- Break-glass of the IP allow list (M7a step 3): `paddock-server admin allowlist show|disable|add` on the host
  (audited as `platform.ip_allowlist_disabled` and `platform.ip_allowlist_changed` with actor system) and the api
  variable `PADDOCK_IP_ALLOWLIST_BYPASS` (default `false`; its audit event is retried until PostgreSQL is reachable;
  `prod-check` fails and the alert
  `PaddockIPAllowlistBypassed` fires while it is set). Runbook: `docs/operations/ip-allowlist.md`.
- Portal page *IP allow list* for platform administrators (M7a step 4): the own address and whether the list covers
  it, the entries with search and sorting, add and edit dialogs with a "use my address" button and client-side CIDR
  validation, removal through the confirmation modal, and the typed confirmation of a change that would lock the
  administrator out or switch the list off.
- Screenshots and glossary (M7c step 10): `PADDOCK_E2E_SCREENSHOTS=1 make e2e` writes the README screenshots of the overview, the device list, a device and the audit log in the light and the dark theme, plus a visual review set at 390, 1280 and 1920 px (not committed); the German glossary has the terms of the redesigned portal (Übersicht, Befehlspalette, Gefahrenbereich, Erscheinungsbild, Dichte, Tastenkürzel and the status chips).
- Status chips, empty states and phone layout everywhere (M7c step 9): device, token, API token, revocation, agent release and rollout, organization, user lock, user and group source, change set source and permission profile badges are chips with a dot and a label; list timestamps are mono, one line, relative for last contact and last use. Every empty list says what it is for and, when the role may act, offers the next step (for example *Create device group*; the device list links to the enrollment tokens). Settings forms show one panel per section with fields as wide as their content. At 390 px no page scrolls horizontally, lists are cards and filters open in a sheet. New end-to-end gates check the phone layout and run the accessibility check in the light and the dark theme.
- Audit log and attention pages (M7c step 8): audit sentences name a device by its hostname instead of its ID, a Device column links to it, timestamps are one mono line, the actor carries a type chip, the outcome is a chip, and a row expands to the stored event fields and params, shown unchanged. A device's new Audit tab lists its events (administrators and auditors). The attention page lists one row per device with its open conditions as chips, most severe first, and one action.
- Device split view (M7c step 7): a device opens beside the device list (a pane with search and filters that keeps the list the administrator came from; hidden below 960 px), under a header band with the hostname, status chips (contact, encryption, logins suspended, locked), Ubuntu release, agent version and last contact, and the primary actions — approve, reject or release for new and quarantined devices, *Install updates…* and *Rotate admin password…* for active ones. The device's sections are tabs with their own URLs (Overview, Software, Vulnerabilities, Login & sudo, Configuration, Commands; `Alt+1…9`). The Overview tab shows health and compliance at a glance, identity with a copyable device ID, device groups, the local administrator, disk encryption, updates and the top findings; Lock, Destroy and Retire sit in the danger zone at its end, each with its own explanation and dialog, and the reason for a Lock or Destroy is entered in the dialog.
- Portal overview (M7c step 6): administrators and operators start on a new overview page with the fleet numbers (online, silent, presumed lost, encrypted, not encrypted, the number of distinct critical or high CVEs, security updates overdue, reboots required), each linked to its pre-filtered list, the attention list grouped by device, a severity bar of devices by their worst finding with the top CVEs, updates and the agent rollout, and the recent audit activity (administrators and auditors). Every KPI number equals the total of the list it opens: the device KPIs open the active devices filtered by contact, disk state or overdue security updates, and *Critical / high CVEs* counts distinct CVEs like the vulnerability list. Auditors start on the audit log. The device list filters by contact state and by overdue security updates (`GET /api/v1/devices?security_updates=overdue`, no successful run in 48 hours); `GET /api/v1/attention/devices` filters by `device_id`; the overview reports `vulnerabilities.critical_high_cves`. The vulnerability tile on the device groups and vulnerabilities pages is replaced by the overview.
- Overview and grouped attention API (M7c step 5, ADR 0023): `GET /api/v1/overview` returns the organization's fleet numbers in one transaction (devices by state and contact, encryption, devices by their worst finding and the top CVEs, security updates overdue for more than 48 hours, reboots required, agent rollout, Ubuntu releases, open attention conditions and devices); `GET /api/v1/attention/devices` lists the attention conditions grouped by device, most severe first, with the `kind` filter and the sorts `severity`, `hostname` and `since`; devices carry a derived `contact` state (`never`, `ok`, `stale_warning`, `stale_critical`, `presumed_lost`) and `GET /api/v1/devices` filters by it; audit events carry the device they concern with its current hostname (`device`, resolved at read time; the stored event is unchanged) and `GET /api/v1/audit-events` filters by `target_id`. Database migrations `00038` (paddock) and `00003` (audit) run automatically.
- Shared portal components (M7c step 4): status chips with a dot and a label (`StatusChip`, one vocabulary ok / warn / critical / info / neutral; `SeverityChip` on its own scale with an orange *high*), an actor chip for audit events, mono timestamps (`YYYY-MM-DD HH:MM`, the time only for today, relative in tables with the absolute value as tooltip), empty states with the next step, a danger zone card for Lock, Destroy and Retire (each with its own explanation and dialog; the reason is typed in the confirm dialog, which also requires the hostname and keeps Cancel focused), and list extensions: cards below 600 px with the filters in a sheet, a row cursor (`j`/`k`, Enter/`o`), expandable rows, "Clear filters" on an empty filtered list, and query prefixes so two lists share one page.
- Portal shell (M7c step 3): a 44 px app bar with the organization name, a command field that opens the command palette (`Ctrl K` / `⌘ K`, `/`; pages, devices, device groups, a CVE id and non-destructive actions such as switching the theme, language, density or navigation), a labelled attention pill ("3 need attention") instead of the bare badge, a theme toggle, and a user menu with language, theme (System / Light / Dark, stored on the account), density (Compact / Comfortable, per browser) and the keyboard-shortcut help. The navigation drawer has icons, overline group headers, `g`-shortcut hints, one Tab stop with Up/Down/Home/End, collapses to a 52 px rail with tooltips (`[`; expanded by default from 1280 px, a rail between 600 and 1279 px, a temporary drawer below) and scrolls independently. Global shortcuts: `g o/a/d/s/v/l` navigate, `j`/`k`/Enter work in lists, `?` lists every shortcut; single-key shortcuts can be switched off in the help dialog; no shortcut or palette entry performs a destructive or security-relevant action.
- Portal design system (M7c step 2, ADR 0023): the portal ships with a light and a dark theme built on one token set (`--pd-*`, `server/web/src/plugins/theme.ts`), self-hosted IBM Plex Sans and JetBrains Mono (OFL-1.1, upstream woff2 files unmodified, licence texts next to them) and vendored Lucide icons (ISC); no font or icon leaves the portal origin. The api role serves `.woff2` as `font/woff2`. `make lint` fails when a vendored font or icon is missing, changed, unlisted in `server/web/src/assets/vendored.json`, under another licence or not recorded in `docs/compliance/third-party.md`, and when the generated icon module is out of date (`npm run gen:icons`).
- Portal theme preference on the account (M7c step 1, ADR 0023): `GET /api/v1/me` returns `theme` (`system`, `light` or `dark`; `system` follows the operating system's preference) and `PATCH /api/v1/me` accepts a patch of `locale` and/or `theme` (at least one field; an unsupported value or an empty patch answers 400). Database migration `00037` runs automatically.
- Operator bundle (M7b step 3, ADR 0022): `paddock-deploy-<version>.tar.gz` holds the production Compose files, their
  configuration, the bootstrap scripts, `versions.env` with the Paddock images by tag and digest, `SHA256SUMS`, a
  README and the entry script `./paddock` (`version`, `verify`, `secrets`, `pull`, `check`, `up`, `down`, `ps`, `logs`,
  `compose`, `bao`, `bootstrap openbao|buckets|audit-bucket|fleet`, `agent-release`, `migrate-from`). `./paddock check`
  runs `prod-check` from the server image. `make bundle` builds a local bundle of the local images; the drift test
  `make bundle-test` (part of `make test`) proves that the bundle renders the same production configurations as
  `deploy/compose/`, ships every mounted file and image reference, and builds reproducibly.
- Published images (M7b step 4, ADR 0022): `make release-images` builds `paddock-server`, `paddock-compiler` and the
  new `paddock-pgbackrest` with `docker buildx` for `linux/amd64` and `linux/arm64`, pushes them to `ghcr.io/phischl/`
  with the OCI labels of the release and records index and platform digests in `images.txt`. Tags: a plain `x.y.z`
  gets `<version>`, `<major>.<minor>` and, as the highest plain version among the tags, `latest`; a pre-release only
  its version; the new edge channel (`RELEASE_CHANNEL=edge`, versions `edge-<yyyymmdd>-<sha7>`) `edge` and its
  version. `release-sbom` writes one SPDX SBOM per image and platform from the registry, `release-sign` signs every
  image recursively, attests each SBOM on its platform manifest and signs `SHA256SUMS` and the bundle tarball;
  `release-packages`, `release-bundle` and `release-sums` complete the release, and `release-artifacts` runs them all
  locally.
- Agent releases from the host (M7b step 5): `paddock-server admin agent-release --version <v> --dir <dir>` (in the
  bundle: `./paddock agent-release <v> <dir>`) verifies every signed `paddockd` and Debian package of the offline
  signing step first, then creates, uploads and publishes the release through the same use cases and audit events as
  the admin API, with the system actor of the host commands, and prints the release as JSON. A published release or a
  wrong signature is refused without storing anything.
- Release gates for the bundle (M7b step 6): `deploy/bundle/ci/smoke.sh` installs a bundle on one machine as two hosts
  (projects `paddock-cp` and `paddock-audit`) by the installation guide — secrets, OpenBao initialization and
  configuration, buckets, Fleet, `./paddock check` on both hosts against the unmodified production files, start,
  probes through Caddy, a pgBackRest backup, an agent release with throwaway keys and a second `./paddock up` that
  must not recreate a container — with the CI overlay `deploy/bundle/ci/compose.ci.yaml` for internal TLS.
  `deploy/bundle/ci/prune-edge.sh` deletes edge image versions older than 30 days whose tags are all
  `edge-<date>-<sha>` and keeps releases, `edge`, `latest` and untagged versions (tested in `make test`).
- Upgrade and rollback runbook `docs/operations/upgrade.md` (M7b step 7): new bundle next to the running one,
  `./paddock migrate-from`, check, backup, `./paddock up`; rollback by the release's `Schema:` line. The installation
  guide is rewritten for the bundle (download and signature check, `./paddock secrets|bootstrap|check|up`, first
  agent release, installing from source with a local bundle); ADR 0022 records the distribution decision. M7b adds no
  database migration.
- Audit writer latency metrics (PDK-067): the histograms `paddock_audit_writer_transaction_seconds{result}` and
  `paddock_audit_worm_put_seconds{object,result}` tell a slow WORM store from a slow audit database, and the warning
  `PaddockAuditWriterTransactionSlow` fires when the writer's transaction p95 stays above 5 s for 5 minutes
  (`docs/operations/monitoring.md`).

### Changed

- Agent version comparisons at large fleets (PDK-090): every device stores the sort key of its agent version, computed
  when it checks in, so the attention list's "agent outdated" filter and the overview's agent counters no longer
  compute it once per device. At 10 000 devices the query time of the overview's agent counters drops from 151 ms to
  7 ms and that of `GET /api/v1/attention/devices?kind=agent_outdated` from 344 ms to 174 ms (`EXPLAIN ANALYZE`
  medians, `docs/operations/capacity.md`). The lists and counters do not change. Database migration `00044` runs
  automatically and rewrites the device status table once (one row per device).
- Device contact state at large fleets (PDK-089): the overview's contact counters, the device list's contact column and
  filter, its count and the device detail read a device's open staleness alert together with the device instead of
  looking it up once per device. The contact states and counters do not change. Database migration `00043` runs
  automatically.
- Attention list and overview at large fleets (PDK-027): the attention list, its counts and the overview look up the
  current agent release once per request instead of once per active device. At 10 000 devices the query execution
  time of the attention list queries drops from about 0.6 s to 0.06–0.12 s, and that of the overview's agent counters
  from 2.2 s to 0.15 s (`EXPLAIN ANALYZE` medians, `docs/operations/capacity.md`). The lists and counters do not
  change. Database migration `00042` runs automatically.
- Secret scan of pull requests (PDK-087): `make scan-secrets-diff` scans its blob layers in parallel, as many at once
  as the machine has CPUs, and prints each layer's result in layer order afterwards (the whole history of this
  repository as one pull request: 60 seconds before, 31 seconds now on 22 CPUs). What is scanned, and every verdict,
  stays the same; a layer whose scan fails or reports no result fails the scan.
- Secret scan of pull requests (PDK-072): `make scan-secrets-diff` places the blobs a pull request adds in their
  layers without probing every earlier layer again and reads them from git in one batch, so a pull request with many
  versions of one file is scanned much faster (300 versions of one file: 2 minutes before, 16 seconds now). What is
  scanned, and every verdict, stays the same.

- Secret scan lock files (PDK-077, ADR 0026): the repository's `.gitleaks.toml` now skips every `go.sum` and
  `server/web/package-lock.json` by path itself instead of relying on gitleaks' default path allowlist, which a later
  change drops. Today's scan results are unchanged.

- Secret scan configuration (PDK-078, ADR 0026): `make scan-secrets` and `make scan-secrets-diff`, and with them the
  CI job `secrets` on pull requests and on `main`, run gitleaks' default rules without the path entries of its global
  allowlist, extended by the repository's `.gitleaks.toml`. Files such as `src/bootstrap.js`, `javascript.json`,
  `node_modules/…` or anything under `d.png/` are now scanned by content in both scans. The default configuration is
  read from the pinned gitleaks image and checked against two new pins in `deploy/compose/versions.env`
  (`GITLEAKS_DEFAULT_CONFIG_BYTES`, `GITLEAKS_DEFAULT_CONFIG_SHA256`); a gitleaks image bump updates the image and both
  pins together (`docs/operations/secret-scan.md`), and wrong pins fail the scan. Files under binary extensions are no
  longer scanned under a `.scan` name: findings and `.gitleaksignore` fingerprints use the file's own path; archives
  keep their `.zip` and `.tar.gz` suffixes. `.gitleaks.toml` is now parsed and checked against a closed list
  of keys: the scan fails on anything but `title`, `[extend]` with exactly `useDefault = true` and `[[allowlists]]`
  with the known allowlist keys (for example on `disabledRules`, `url`, `[Extend]`, `stopwords` or an unknown key),
  and on a `paths` or `regexes` entry that matches the empty string or does not compile in Go's `regexp`. Each scan
  first checks the generated configuration with a canary token (Python 3.11 or later is needed to run the scans).

- Secret scan of pull requests (PDK-069, ADR 0025): `make scan-secrets-diff` also scans files under extensions that
  gitleaks' default configuration skips (images, fonts, office documents, `.pdf`, `.bin`, `.exe` and others), and
  files in directories named that way, under the suffix `.scan` on each such path component, and opens zip archives,
  office documents, `.jar` files and gzipped tars (`.tar.gz`, `.tgz`) one level deep, so a text secret in `creds.bin`
  or `assets.png/creds.bin` or a credential inside a zip or a `.docx` fails the CI job `secrets`. Archives under other
  names gitleaks does not recognise are not opened. Real PDFs, fonts, executables and compressed data stay unscanned
  in every mode (gitleaks skips them by content). A `.gitleaksignore` fingerprint or path allowlist for such a file
  names its renamed path (`creds.bin.scan`, `assets.png.scan/…`, `creds.docx.zip!…`). A pull request that changes both
  `creds.bin` and `creds.bin.scan` fails the scan. The CI job `secrets` now stops after 30 minutes.

- Secret scan documentation (PDK-074): `docs/operations/secret-scan.md` lists the default gitleaks path entries that
  still skip whole files and directories in `make scan-secrets-diff` (for example `gitleaks.toml`, `go.mod`,
  `package-lock.json`, `node_modules`, `venv/lib`, `Database.refactorlog`), as probed with gitleaks v8.30.1. It covers
  matches anywhere in a path, matches that span two directories, and which entries ignore case. It also states that
  changes to `.gitleaks.toml` itself are not scanned and that review is the backstop for such paths. The scan itself
  is unchanged.

- Agent release signing moves into the release workflow (ADR 0006 amendment 2026-10-11): a new job `sign` in the
  protected GitHub environment `release` (tags `v*` only, maintainer approval for every run), which runs only after the
  smoke test passed, signs `paddockd` for
  amd64 and arm64 and the `paddock-agent` and `paddock-supervisor` packages with the agent release key (secrets
  `PADDOCK_RELEASE_KEY` and `PADDOCK_RELEASE_KEY_PASSPHRASE`) and verifies them against `PADDOCK_RELEASE_PUBLIC_KEY`.
  The draft release carries them without the `-unsigned` suffix, each with its `.minisig`; `SHA256SUMS` and its
  Sigstore signature cover the final names. `paddock-revoke` stays `-unsigned` and is signed offline.

- Production Compose files carry no `build:` sections any more (M7b step 1, ADR 0022): `compose.yaml`,
  `compose.audit.yaml` and `compose.backup.yaml` reference the images `PADDOCK_IMAGE`, `PADDOCK_COMPILER_IMAGE` and
  `PADDOCK_PGBACKREST_IMAGE` only; the development overlays `compose.dev.yaml` and `compose.backup.dev.yaml` build
  them from source, so `make up` is unchanged. The server image cross-compiles (portal and Go build on the build
  platform) for `linux/amd64` and `linux/arm64`; `make lint-image` also builds the arm64 Go stage.
- Bootstrap scripts are production-capable (M7b step 2): `scripts/lib.sh` holds the Compose file sets of both hosts
  and of the development stack (the Makefile and the `prod-check` tests read them from there), selects them by
  `PADDOCK_ENV` and the new `.env` setting `PADDOCK_HOST=controlplane|audit`, and names the Compose project after
  `PADDOCK_PROJECT` (default `paddock`). The OpenBao configuration (keys, policies, AppRoles, now including the audit
  writer's credentials for the audit host) moves into `openbao-configure.sh`, which runs against an OpenBao that the
  operator initialized and unsealed; `openbao-bootstrap.sh` keeps the development init and unseal. The audit bucket,
  bundles bucket and Fleet bootstraps no longer refuse production. `gen-prod-secrets.sh` takes the host from
  `PADDOCK_HOST` when no argument is given.
- `make prod-secrets` and `make prod-check` are removed (M7b step 3): production hosts use the operator bundle's
  `./paddock secrets` and `./paddock check`; installing from source means building the images and a local bundle.
- The secret scan (`make scan-secrets`, CI job `secrets`) scans the current branch's history instead of every ref
  (PDK-034): in CI a pull request scans only its own commits and `main` its full history, so a finding on an unrelated
  branch no longer fails other pull requests. Reviewed false positives are content-based allowlists in `.gitleaks.toml`
  (file plus exact value shape) instead of commit-bound fingerprints, and `.gitleaksignore` is removed. The scan works
  from git worktrees and fails when it scanned no commits.
- The secret scan also catches a secret added only in a merge commit (PDK-057), even when a later commit removes it:
  `make scan-secrets` reads the history with `--remerge-diff`, which shows what a merge resolution changed, and fails
  when gitleaks or git reports an error instead of passing with 0 scanned commits. A range made only of clean merge
  commits passes with 0 scanned commits; any other range that scans 0 commits fails. A range with an octopus merge
  (more than two parents) fails, because its changes cannot be scanned. For pull requests the CI job
  `secrets` additionally scans the current content of every changed file (`make scan-secrets-diff`, base
  `GITLEAKS_DIFF_BASE`, default `origin/main`). The path allowlists in `.gitleaks.toml` accept the `b/` prefix that
  gitleaks reports for files of a merge conflict.
- A pull request can no longer loosen the secret scan through its scan configuration (PDK-065): `make scan-secrets`
  and `make scan-secrets-diff` read `.gitleaks.toml` and `.gitleaksignore` from `GITLEAKS_CONFIG_REF` (default: the
  working tree), and the CI job `secrets` sets it to the pull request's merge base. A pull request that changes either
  file is scanned with the base's version, so an allowlist for a new false positive lands in its own pull request
  first. A `.gitleaksignore` a pull request adds is no longer picked up on its own, inline `gitleaks:allow` comments
  are ignored, and a `.gitleaks.toml` that extends another file (`[extend] path`) fails the scan. A pull request still
  runs its own `ci.yml` and `Makefile`, so the scan's integrity rests on code review of `.github/`, the `Makefile` and
  `deploy/compose/versions.env` (read by the Makefile; it pins the gitleaks image): `.gitleaks.toml`,
  `.gitleaksignore`, `Makefile`, `.github/`, `deploy/compose/versions.env` and `deploy/compose/scripts/` have a code owner, which
  GitHub enforces only once branch protection requires code-owner review (see `docs/operations/secret-scan.md`).

### Fixed

- Load test (PDK-088): `make load-identities` and the k6 scenarios send each load device's address in
  `X-Paddock-Client-IP`, the header the gateway reads since the client address is derived through trusted proxies
  (plan M7a decision 3). With `X-Forwarded-For` every load device counted as the load generator's one address, so
  enrolling a fleet stopped after about 100 devices with HTTP 429. The identities tool's flag `--forwarded-for` is now
  `--client-ip`.
- Secret scan of pull requests (PDK-085, ADR 0027): the scan refuses a `.gitleaks.toml` allowlist with
  `condition = "AND"` and `paths` unless it names `targetRules`. gitleaks' directory scan skipped every file under such
  a global allowlist's path without applying its `regexes`, so `make scan-secrets-diff` missed secrets there that the
  history scan reports. The repository's own allowlists already name their rules and are unchanged.
- Fleet's vulnerability data in development and CI stacks (PDK-054, ADR 0009 amendment 2026-10-12): the development
  overlay passes Fleet direct URLs for its CPE dictionary, CPE translations and NVD feeds, so a fresh stack on a shared
  CI runner no longer waits on GitHub's anonymous API rate limit before the inventory gates find vulnerabilities. The
  CPE release is pinned in `deploy/compose/versions.env` (`FLEET_CPE_DATABASE_URL`, `FLEET_CPE_TRANSLATIONS_URL`);
  no GitHub token is passed to Fleet. Production stacks are unchanged and keep Fleet's own lookup of the latest data.
  Because Fleet then downloads the CPE database on every vulnerability run, the development stack runs that job
  hourly like production (was every 5 minutes) and the inventory gates trigger the runs they need. A failed CI
  acceptance run now also prints Fleet's full log.
- `paddockd plan` changed the agent state (PDK-081): run next to the daemon, it reported the daemon's running
  `install_now` job as failed with reason `interrupted`, dropped it from the agent state and saved the state file
  from a second process. `paddockd plan` now writes nothing under the agent layout; the daemon still reports a job
  that a restart interrupted, when it starts.
- Agent release staged during a probation or a pending rollback (PDK-075, plan M2b decision 16): the supervisor
  ignores such a release and later removes only its request, which left the release under
  `/var/lib/paddock/staging/<version>/` on disk. The agent now removes every staged release without a
  `request.json` at start and at every check-in before it stages a release; while a request exists nothing is
  removed. A release the server still offers is downloaded and staged again as before. The supervisor is unchanged.
- Agent supervisor with an unreadable `probation.json` (PDK-062, plan M2b decision 16): instead of dropping the log
  and leaving the new release running without a probation, the supervisor rebuilds the probation from the slots when
  `current` points at `A` or `B`, the other slot holds an agent with a valid version, the active agent is newer by
  semantic version and no `update-result.json` names it `updated`; the rebuilt log carries `"rebuilt": true` and a
  full probation runs again. A result `rolled_back` or `rollback_failed` for the active version, or the new marker
  `/var/lib/paddock/state/rollback-pending`, which the supervisor keeps from a failed rollback until it is made,
  resumes the pending rollback instead. In every other case the log is dropped as before, with the reason logged at
  error level.
- Agent supervisor after a manual flip back (review of PDK-043): when the supervisor restarted before it could record
  a failed rollback in `probation.json` and `current` already points at the previous version, it now confirms the
  flip back and reports `rolled_back` instead of dropping the probation and leaving `rollback_failed` as the device's
  last report.
- Device API contract (PDK-073): the `Event.type` enum in `api/openapi/device.yaml` lists every event type the
  gateway accepts, adding `revocation.trust_pinned_tofu`, `revocation.refused`, `tamper.service_stopped` and
  `updates.run`. The gateway's behaviour is unchanged; a test keeps the contract and the accepted list in sync.
- Secret scan of pull requests (PDK-068): `make scan-secrets-diff` also scans every blob the pull request adds, so a
  binary file with a secret that the pull request adds and removes again, which gitleaks' history scan skips, fails
  the CI job `secrets`. A file over 100 MB fails the scan instead of being skipped. Files that
  gitleaks' default configuration allowlists by extension (such as `.bin` and images) and archive contents are covered
  by PDK-069 (see Changed).
- Agent versions compare by SemVer order, not as text or for equality (PDK-025): the attention list flags a device
  as `agent_outdated` only when its agent is older than the current release, and the server offers a device an agent
  update only when the release is newer than its agent, so a device that is ahead of the last completed rollout is
  neither flagged nor offered an older release. An update a device refuses as a downgrade no longer counts toward a
  rollout's failure rate. `GET /api/platform/v1/agent-releases?sort=version` sorts 0.2.0 before 0.10.0 and a
  pre-release before its release, and the newest release among equally recent ones is the highest version.
- The bucket bootstraps no longer fail when a generated RustFS root credential begins with `-` (a random
  base64url value does so now and then): `rc alias set` takes the credentials after `--`.
- The OpenBao scripts no longer put a secret on a command line: the root token reaches the container by name only,
  the session keys and the unseal shares go through stdin (`openbao-configure.sh`, `openbao-bootstrap.sh`, the restore
  drill); a test of `make test` refuses `-e NAME=$value` and secret arguments in the bootstrap and bundle scripts.
- `fleet-bootstrap.sh` replaces the API-only user `paddock` only when Fleet rejects the stored token with 401; when
  Fleet is unreachable, answers otherwise or does not answer within 10 seconds, or when the stored token file exists
  but cannot be read, it stops without touching the user, so a passing outage no longer rotates the token.
- `paddock-server admin agent-release` audits every refusal like the admin API: an invalid version or a release
  without an agent binary records a failed `agent_release.created` event, a refused file a failed
  `agent_release.artifact_uploaded` event.
- `paddock-supervisor` no longer rolls back a healthy agent update whose first check-in follows the switch within one
  kernel clock tick: the file system dated such a check-in before the switch. The supervisor now removes
  `/run/paddock/last-checkin` while no agent runs, and a probation passes if the new agent recreated it. If the
  supervisor cannot remove the mark, it rolls the update back.
- Portal device page: a click on Save right after picking a device group saves the groups again. The group field no
  longer shrinks by a line when it loses focus, so the Save button stays where the click lands.
- `paddock-supervisor` no longer reports `rolled_back` when it could not point `/opt/paddock/agent/current` back at
  the previous slot. It retries the switch back five times within about four seconds; if it still fails, it logs
  `rollback failed: current still points at the new agent` at error level, keeps the new agent running and reports
  the update as failed (`agent.update_failed` with outcome `self_test_failed`), which counts toward the rollout's
  failure rate as a rollback does.
- `paddock-supervisor` no longer reports an agent update as `updated` or `rolled_back` while the switch of
  `/opt/paddock/agent/current` may still be lost with a power failure, because syncing the slot directory failed.
  Such a switch now keeps the probation record on disk, and the result waits until a new switch to the same slot was
  synced; after a restart the supervisor checks `current` against the record and decides again. A failed sync of the
  forward switch no longer reports `self_test_failed` while `current` already points at the new agent; the new agent
  starts and its probation runs as usual. Once the new agent was healthy at the end of its probation, later exits
  while the switch still waits are restarted, not rolled back.
- `paddock-supervisor` now syncs the content of its probation record and update result to disk before it renames
  them into place. A new probation record could otherwise come back empty after a power failure; the supervisor then
  dropped it, and the new agent kept running without probation or automatic rollback. If the probation record cannot
  be synced, the switch does not happen and the update is reported as failed (`self_test_failed`).
- Portal confirmation dialogs no longer take focus away from a field that someone starts typing into while the dialog
  is still opening. The dialog moved focus back to Cancel when its opening animation ended, so text typed in that
  moment, such as the hostname of a Lock or Destroy, could be lost and the confirm button stayed disabled.
- Portal device page: the Disk encryption, Updates and Local administrator panels show their facts in the same
  label/value rows as the Identity panel, with a panel header, instead of a table with offset values. Empty lists, such
  as the IP allow list without entries, no longer show an empty row above their empty state.
- Portal overview: while no agent rollout has completed, the "Updates and agent rollout" panel now says "No agent
  rollout completed yet" instead of "No agent release published yet". The panel names the release of the most recent
  completed rollout, so published releases without a completed rollout were wrongly reported as missing.
- After a rollback, `paddock-supervisor` no longer ends the agent it has just restarted: its check-in request
  (SIGHUP) could arrive before the agent was ready for it, the agent exited with `signal: hangup` and only came back
  after the restart back-off. The supervisor now ignores SIGHUP (and no longer exits on one itself), so the agent
  starts with SIGHUP ignored until it handles check-in requests; it checks in at start anyway, so no update result
  goes unreported.
- Portal device page, Login & sudo tab: the user and group fields of the login assignment no longer shrink by a line
  when they lose focus, so a click on Save or Suspend logins right after picking an entry lands on the button.
- `paddock-supervisor` no longer reports a second, possibly contradicting result for an agent update after a power
  failure. A power failure right after the result was written could bring the probation record back; the restarted
  supervisor then ran the probation again and could report `rolled_back` for a release it had already reported as
  `updated`, or report a rollback twice. The supervisor now writes the decided outcome into the probation record
  before the result, and a restart that finds it writes the same result again, which the agent does not report twice.
- A device no longer stops accepting agent updates after `paddock-supervisor` restarts with a probation record it
  cannot resume (unreadable, or `/opt/paddock/agent/current` on neither the new nor a rolled-back slot, for example
  after a power failure during the switch). The supervisor dropped the record but left the update request behind, so
  the agent waited for it forever. It now removes the request as well and logs the drop; it reports no result, because
  it cannot tell which release or what happened, and the agent stages the offered release again.
- `paddock-supervisor` no longer loses the result of an agent update when writing `update-result.json` fails, for
  example on a full disk. It keeps the probation record with the decided outcome, and its next start writes the
  result.
- A device no longer stops accepting agent updates after `paddock-supervisor` restarts while it verifies or
  self-tests a staged release. The update request stayed behind without a probation record, and the agent waited for
  it forever. The restarted supervisor now processes such a request again from the staged files, with a new
  signature check and self-test, and reports one result. It removes a request whose release the existing
  `update-result.json` already names instead, and it syncs the removal of a request before it writes the result, so
  a power failure cannot bring back a request that was already reported.
- `paddock-supervisor` no longer reports `downgrade_refused` for the agent version that is already running, after a
  successful update whose request came back after a power failure when the agent had already reported and removed
  the result. Such a report counted against the release's rollout and made the device refuse its own version as a
  failed update. The supervisor now removes a leftover request for the active version without a result.

### Security

- The RustFS bucket bootstraps (`./paddock bootstrap audit-bucket` and the bundles, artifacts and escrow buckets, plus
  the development backup bucket) no longer put a RustFS root password or user secret key on a command line, where
  `ps` showed it to every user of the host (PDK-036): the root credentials reach the rc client as `RC_HOST_<alias>`
  by name only, and each user's secret key is set from the environment (`rc admin user passwd
  --password-from-env`). A user is created with a throwaway secret and gets its policy only after that, and every
  bootstrap run now sets each user's secret key to the value in its secret file: after changing a RustFS user secret
  file, re-run the bootstrap and restart the services that use that credential. A bootstrap creates a user only when
  RustFS reports it as missing and aborts on any other error, so a transient failure never resets an existing
  user's secret. A test of `make test` refuses credentials as arguments of `rc`/`mc alias set` and `admin user add`.
- The worker's certificate probe (`PADDOCK_TLS_PROBE_HOSTS`) verifies each public certificate against the system
  trust store and the hostname, like a client. An expired, untrusted or wrong-name certificate now reads
  `paddock_tls_probe_success` 0 and raises `PaddockCertificateProbeFailing`, instead of reporting its expiry.
- Device gateway cache errors no longer contain the cache key, so logs carry neither a device key ID nor the hash of
  an enrollment token.
- The audit sealer refuses a signing key version outside 1…2³¹−1 before it writes the manifest, instead of
  truncating it into the manifest index.
- Dependency update (PDK-032): `github.com/google/cel-go` 0.28.0 → 0.31.0, fixing GHSA-gcjh-h69q-9w9g (private JSON
  fields exposed through `NativeTypes` and `ParseStructTag`). The library is only pulled in by the build-time code
  generator `sqlc`; Paddock's own code does not evaluate CEL and the shipped binaries do not contain it, so running
  installations were not exposed.
- Every GitHub Action in the CI, release and image-prune workflows is pinned to a full commit SHA (PDK-050), not
  only those of the release signing and publishing jobs: a re-pointed tag can no longer change the release build that
  produces the agent and package bytes before they are signed. Dependabot keeps the pins up to date.
- The release and edge image builds pull the QEMU emulator image (`BINFMT_IMAGE`) and the BuildKit daemon image
  (`BUILDKIT_IMAGE`) by digest from `deploy/compose/versions.env` instead of by the mutable tags `latest` and
  `buildx-stable-1` (PDK-055). The release build restores no Go module, build or BuildKit cache from earlier runs, so
  only the tagged sources and pinned images feed the bytes that are signed; the CI builds keep their caches.

## [0.1.0-alpha.1] - 2026-10-09

**Alpha.** This is a pre-release for evaluation, not for production fleets. Revocation (Lock, Destroy, dead man's
switch) stays behind the feature flag `PADDOCK_REVOCATION_ENABLED` until its code has passed the second-person
review and the hardware acceptance. There are no upgrade guarantees between alpha releases: an alpha may change
data, configuration or APIs without a migration path.

First public release, published as an alpha pre-release. Paddock manages Linux workstations — signed configuration, identity and device login, sudo rights, managed local
administrator, disk encryption with escrow, updates and inventory, tamper detection and a WORM audit trail — with
an English and German portal, a license-checked supply chain and a compliance pack (`docs/compliance/`).
Revocation (Lock, Destroy, dead man's switch) ships disabled until an installation has passed its hardware
acceptance.

### Added

- Pre-release versions (PDK-022): `make release-check` and the release workflow accept `x.y.z` and the SemVer
  pre-releases `x.y.z-alpha.N`, `x.y.z-beta.N` and `x.y.z-rc.N`, nothing else. A pre-release's Debian packages carry
  the version `x.y.z~alpha.N` (`~beta.N`, `~rc.N`), which sorts before `x.y.z`, so apt and dpkg upgrade from an alpha
  to the release; the release assets are still named with the release version
  (`paddock-agent_0.1.0-alpha.1_amd64-unsigned.deb`), because GitHub renames asset names with `~` and they must
  match `SHA256SUMS`; its images are tagged with exactly that version, never `latest`. Agents update along
  `0.1.0-alpha.1 < 0.1.0-alpha.2 < 0.1.0-beta.1 < 0.1.0-rc.1 < 0.1.0` and refuse a step back.
- WAL archive lag alert (M6a decision 8, `docs/operations/monitoring.md`): the worker exports `paddock_backup_wal_last_archived_timestamp_seconds{stanza}` (the newest archived WAL segment of `paddock` and `authentik`, read with a bounded listing of the backup bucket, never a full one) and `paddock_backup_wal_stanzas`; `PaddockWALArchiveLag` fires when a database's newest archived segment is older than 15 minutes for 10 minutes, `PaddockWALArchiveLagMissing` when the age of a stanza is never exported for 30 minutes. Before, only the 26-hour backup alert watched the backups.
- Restore runbook and drill (M6a step 3, A11, `docs/operations/restore.md`): the runbook restores both PostgreSQL databases with pgBackRest to the latest archived point, OpenBao from its newest snapshot into a fresh OpenBao, and then runs `paddock-server admin bump-bundle-seq --by 1000000`, `rebuild-cache` and `recompile --all` in the order of plan M6c. `make restore-drill` runs it on the development stack (`make up BACKUP=1`) with the acceptance subset and prints the measured RTO; it refuses unless `deploy/compose/.env` (not the process environment) says `PADDOCK_ENV=development`, no production secrets exist and the running stack uses no production overlay. A restore fails when it cannot stage the WAL up to the newest archived segment. `paddock-server backup decrypt <in> -` writes to stdout.
- Monitoring (M6a step 4, A12, `docs/operations/monitoring.md`): the Compose profile `observability` runs Prometheus (`PROMETHEUS_IMAGE`, pinned; `prometheus` on the control plane, `prometheus-audit` on the audit host; development: started by `make up`, published on `127.0.0.1:9091`) with the alert rules of `deploy/compose/prometheus/alerts.yml`: role down, RabbitMQ dead-letter queues (critical for `dlq.audit.writer`), audit writer lag above 10 minutes and no audit consumer, compile latency p95 above 30 s, gateway 5xx rate, OpenBao sealed or unreachable, OSV data stale (M5c), backup older than 26 hours, certificate expiry within 14 days. RabbitMQ enables its bundled plugin `rabbitmq_prometheus`. The worker exports `paddock_openbao_sealed`, `paddock_openbao_reachable` and, with `PADDOCK_TLS_PROBE_HOSTS` (production overlay), `paddock_tls_certificate_expiry_timestamp_seconds{host}` and `paddock_tls_probe_success{host}`; `paddock_backup_last_success_timestamp_seconds` reads 0 for a kind without any backup, and a kind that cannot be listed no longer hides the others or stops the snapshot. The alerts `PaddockBackupAgeMissing`, `PaddockOpenBaoHealthMissing` and `PaddockCertificateExpiryMissing` (with `paddock_backup_kinds`, `paddock_tls_probe_hosts`) fire when those series never appear. Alertmanager and Grafana are not bundled. `make lint-prometheus` (part of `make lint`) checks the configuration and runs the rule tests. The install guide lists the outbound HTTPS the control plane needs, including Ubuntu's OSV feed for the worker.
- Backups of the control plane (M6a step 2, A11, `docs/operations/restore.md`): the overlay `compose.backup.yaml` (part of the production configuration; development: `make up BACKUP=1`) archives the WAL of both PostgreSQL databases continuously and takes a daily full backup with pgBackRest (new image `paddock-pgbackrest` from the Debian package on the pinned Debian base, services `pgbackrest` and `pgbackrest-authentik`, 14 full backups kept), lets `paddock-worker` take an OpenBao Raft snapshot every 6 hours (AppRole `paddock-backup` with read on `sys/storage/raft/snapshot` only) and dumps Fleet's MySQL daily (`fleet-backup`, `fleet-backup-upload`), all encrypted with `backup_encryption_key` into the bucket of `PADDOCK_BACKUP_S3_*` outside the control-plane host (versioning without Object Lock and lifecycle rules are operator steps; production file order `compose.yaml`, `compose.prod.yaml`, `compose.backup.yaml`). New commands `paddock-server backup openbao` (a snapshot now, after key operations) and `paddock-server backup decrypt <in> <out>`. The worker exports `paddock_backup_last_success_timestamp_seconds{kind}`. The development OpenBao bootstrap creates the AppRole `paddock-backup`; `make dev-secrets` writes the backup secrets; `make prod-secrets` writes the encryption key, which must also be kept offline.
- Production installation on two hosts (M6a step 1, `docs/operations/install.md`): the overlays `compose.prod.yaml` (control plane) and `compose.audit.prod.yaml` (audit host) give Caddy certificates from a public ACME CA (`Caddyfile.prod`, `PADDOCK_ACME_EMAIL`, optional `PADDOCK_ADMIN_ALLOWED_CIDRS` for `admin.`), publish only 80/443 and, on the private interconnect address `PADDOCK_INTERCONNECT_ADDR` only, the TLS endpoints the other host needs (RabbitMQ `amqps` 5671, OpenBao 8200 with TLS, audit PostgreSQL with TLS for the reader's `sslmode=verify-full`), and run every role with `PADDOCK_ENV=production`. `make prod-secrets HOST=controlplane|audit` writes a host's secrets, its internal CA and TLS certificates without printing a secret (settings template `deploy/compose/prod.env.example`). `make prod-check HOST=controlplane|audit [ONLINE=1]` (`paddock-server prod-check`) prints a PASS/FAIL checklist and exits 1 on any FAIL: development overlay, variables or `PADDOCK_ENV`, the revocation path without `PADDOCK_REVOCATION_ACCEPTED=yes`, missing, empty or world-readable secret files (symbolic links resolved), paths below `/run/secrets/` a service names without mounting that secret, the development release key, 80/443 on any service but Caddy and other published ports, plaintext links between the hosts, `tls internal`, and online on the audit host an audit bucket without Object Lock COMPLIANCE. The audit writer's bucket policy gains the read-only `s3:GetBucketObjectLockConfiguration` (`docs/operations/audit-bucket.md`).
- Restorable Locks for every encrypted volume (flagged, M4c.1 amendment 2026-10-08): the agent escrows the LUKS header of every LUKS1 or LUKS2 volume of `/etc/crypttab` besides the root volume (the same volume selection `paddock-revoke` erases, without adding a recovery key), each with its LUKS UUID (`POST /v1/escrow` field `volume`, object key `org/<org>/devices/<device>/luks-header/<volume>/<generation>.bin`; header generations count across all volumes), escrows a volume's header again after a keyslot change (`device.tamper_keyslot_changed` gains param `volume`), reports every volume and the unclassified crypttab entries in `health.disk` (`volumes`, `unresolved`) and is `compliant` only when every volume is escrowed. Root volume headers escrowed before stay under their old object key and get the root volume's UUID with the device's first check-in that reports it. The admin API and the portal's *Disk encryption* card list the volumes (`volumes`, `unresolved`, `volume` per header) and download the header of each volume (`volume` in the body of `POST /api/v1/devices/{id}/disk/header`, default the root volume; file `<hostname>-luks-header-<volume>-<generation>.img`; audit `disk.header_downloaded` gains param `volume`). A Lock or self-lock now erases the root volume and only the volumes with a stored header: the revocation-issuer writes their UUIDs into the signed token (`volumes`; audit `revocation.issued` gains the count `volumes`; self-lock tokens are re-issued when the set changes), and `paddock-revoke` reports every other volume as `skipped_not_escrowed` (shown in the device's revocation timeline, audit `device.revocation_confirmed` gains the count; such volumes stay readable and do not make the Lock fail). Destroy still erases every volume and deletes the headers of all volumes. `paddock-revoke` builds before this change refuse tokens with `volumes`: the new `paddock-revoke capabilities` command reports the capability, `paddockd` sends it in the check-in health (`revoke_capabilities`), and only devices that report it get tokens with volumes; update the `paddock-revoke` package on devices with more than one encrypted volume; a check-in without the value keeps the last reported one. A token lists a volume only when its newest header generation is stored; a device escrows at most 32 volumes (a header of a 33rd is refused with escrow status `refused`, audited as `device.header_escrow_refused` with error code `too_many_volumes`, and the device does not upload it again for 24 hours); volumes sharing a LUKS UUID with another volume or the root volume are reported as `shared_uuid`, are not escrowed, are erased by a Destroy and skipped by a Lock. After a downgrade of `paddock-revoke`, Locks with volumes are refused until the device reports its capabilities again. When `paddock-revoke` cannot read the root volume's UUID, a Lock erases the root volume only, while a Destroy still erases every volume; the agent inventories the other volumes in the background, so a hung disk never holds up the agent, escrows headers only right after a completed inventory, and discards a header backup whose LUKS UUID is not the volume's (renumbered disks). Database migration `00035` runs automatically (`docs/operations/revocation.md`, `docs/operations/disk-recovery.md`).
- Public README (M6b step 6): what Paddock is, screenshots of the portal (written by `PADDOCK_E2E_SCREENSHOTS=1 make e2e`, light only: the portal has no dark theme), links to the installation guide, the runbooks, the compliance pack and this changelog.
- Compliance pack (M6b step 5, `docs/compliance/`): `iso27001-mapping.md` maps ISO/IEC 27001:2022 A.5.33, A.8.15, A.8.16, A.8.17, A.8.1, A.8.2, A.8.5, A.8.8, A.8.9, A.8.13 and A.8.24 to Paddock features, evidence (audit codes, WORM store, hash chain, `audit verify`) and operator duties; `residual-risks.md` lists every residual risk recorded so far with its mitigation and what to record in the ISMS; `privacy.md` now also lists update runs, revocation results, the per-volume disk data and what Paddock stores of administrators; `README.md` indexes the pack.
- Release artifacts (M6b step 4, `docs/operations/agent-releases.md` section *Server release*): `make release-artifacts RELEASE_VERSION=x.y.z RELEASE_PUBLIC_KEY_FILE=… [PUSH=1]` builds the images `ghcr.io/phischl/paddock-server` and `ghcr.io/phischl/paddock-compiler` (OCI labels; `PUSH=1` pushes them and records the digests), the Debian packages and `paddockd` for amd64 and arm64 with the production release public key, all marked `-unsigned` (the release keys stay offline), an SPDX SBOM per image (`syft`, pinned `SYFT_IMAGE`) and `SHA256SUMS` into `dist/release/<version>/`; it refuses build tags, a public key whose second line is not a minisign Ed25519 key, and the development keys (compared by that line). `PUSH=1` pushes the tags before signing; consumers verify the cosign signature of the digest, not the tag. `make release-sign` signs the pushed images keyless with `cosign` (pinned `COSIGN_IMAGE`, GitHub OIDC), attaches each SBOM as a signed attestation and signs `SHA256SUMS`; `DRY_RUN=1` prints the commands. The runbook describes the offline signing of the agent artifacts.
- Load test (M6b step 1, N1, N2; `docs/operations/capacity.md`): k6 scenarios `checkin` (1 000 check-ins/s against one gateway replica, p99 < 200 ms, error rate < 0.1 %) and `ingest` (5 000 events/s with 3 worker replicas, consumer lag of `ingest.event` < 60 s, read from Prometheus) in `test/load/k6/`, run with `make load-test SCENARIO=checkin|ingest` on the Compose network with the pinned `K6_IMAGE` (tool only, not shipped). Devices sign like the agent with k6's WebCrypto. `make load-identities CONFIGS=… COUNT=…` enrolls the load devices through the real enrollment API (`test/load/cmd/identities`, new workspace module `test/load`; `--server` is required). Both targets refuse when the running gateway has `PADDOCK_ENV=production` or the checkout carries production markers: never run them against production.
- License gate (M6b step 3, C8): `make lint-licenses`, part of `make lint`, checks every Go dependency of every workspace module with `go-licenses` (v2.0.1, `go run` in the pinned Go image) and every npm production dependency of the portal with `license-checker-rseidelsohn` (new dev dependency; its JSON is evaluated as SPDX expressions, AND needs every license allowed, OR one, and `SEE LICENSE IN`, `UNKNOWN` or a missing license fails) against the allow list MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, MPL-2.0, BlueOak-1.0.0, 0BSD, CC0-1.0, Python-2.0 and Unlicense, and fails with the package name otherwise. `docs/compliance/third-party.md` lists the bundled services, the published images, the software installed on devices and the build tools with their licenses.
- German portal (M6b step 2, C7): a complete German catalog (`server/web/src/locales/de.json`, ICU plurals, every audit event display text; audit events stay stored with their English codes) and a language switch in the app bar that stores the choice on the administrator's account (`PATCH /api/v1/me` accepts `locale` `de`; `GET /api/v1/me` returns it). The portal lint (`make lint`) fails on any key missing from or extra in a translated catalog, on invalid ICU messages, on arguments that differ from the English message and on audit codes without a display text. Terminology: `docs/compliance/glossary-de.md`.
- Lock, Destroy and the dead man's switch erase every LUKS volume of a device (flagged, M4c.1): `paddock-revoke` erases besides the root volume every `/etc/crypttab` entry whose source (`UUID=`, `PARTUUID=` or a `/dev` path), or whose detached header (`header=`), is a LUKS1 or LUKS2 volume, the root volume last, and verifies each; entries marked `plain`, `swap` or `tmp` have no keyslots and are skipped. The volumes other than the root volume get at most 3 minutes together, so a hung disk cannot keep the root volume from being erased. The confirmation keeps `erased`, `slots_before` and `slots_after` (now sums over the reported volumes; `erased` is true only if every volume has no keyslot left and no entry is unresolved) and adds `volumes` (`device`, `slots_before`, `slots_after`, `erased` per volume) and `unresolved` (crypttab entries that could not be erased with certainty, an unreadable `/etc/crypttab` included; they do not stop the others but make the revocation incomplete and failed). The audit event `device.revocation_confirmed` gains the params `volumes` and `unresolved` (counts), and the device's revocation timeline in the portal shows the result of every volume and marks an incomplete erasure. Since PDK-009 a Lock erases only the volumes with an escrowed header (entry above). Test builds (`paddock_revoke_testtarget`) still erase only their test target.
- Runbooks `docs/operations/api-tokens.md` (token model, role ceiling, step-up, expiry, revocation, audit codes, residual risks) and `docs/operations/paddockctl.md` (installation, configuration, commands and exit codes, `paddock.yml` semantics, a CI example with `apply --dry-run` on pull requests and `apply --yes` on the main branch, and the restore commands in their order) (M6c step 6).
- Portal pages *API tokens* and *Change sets* (M6c step 5): administrators and operators create API tokens with a role up to their own and an expiry of up to 365 days (default 90) after a step-up; the token is shown once with a copy button and never again. Tokens are listed with prefix, role, status, creator, expiry and last use, filtered by status, and revoked after a confirmation. *Change sets* lists every applied configuration with its actor, source and counts and shows its plan field by field. The audit log filters by actor type *API token*.
- `paddockctl` (M6c step 4), a static command-line tool for Linux amd64 and arm64 (`make paddockctl` builds `bin/paddockctl/<arch>/paddockctl`): `whoami`, `schema`, `get config [-o yaml|json]` (YAML in the key order of the schema), `apply -f <file|-> [--dry-run] [--yes]` (shows the plan first; a plan with deletions is refused with exit code 3 unless `--yes`), `devices list` (the list contract's parameters) and `version`. It authenticates with an API token read from a file that only its owner may read (`--token-file`, `PADDOCK_TOKEN_FILE` or `token_file` in `~/.config/paddockctl/config.yaml`; the token itself is never in the config file), takes the admin API URL (`https://` only) from `--url`, `PADDOCK_URL` or `url` and an additional CA from `--ca-file`. `apply` applies exactly the plan it showed: when the configuration changed in between, nothing is applied and it exits with code 3. Exit codes: 0 success, 1 API or network error, 2 usage or configuration error, 3 apply refused. `examples/paddock.yml` is a complete example.
- Restore commands (M6c step 3, architecture §20): `paddock-server admin bump-bundle-seq --by N` (1 ≤ N ≤ 1 000 000 000) raises the bundle sequence of every device, `paddock-server admin recompile --all` publishes a new bundle version for every active device even when its content is unchanged, and `paddock-server admin rebuild-cache` rewrites the gateway's enrollment tokens, device keys and sequence numbers in Valkey from PostgreSQL (bundle pointers follow from the running compiler within 60 s). They run with the worker's configuration, in the Compose stack as `docker compose … run --rm --no-deps paddock-worker admin <command>`; after a database restore run them in this order: stop `paddock-compiler`, `bump-bundle-seq --by 1000000`, start the compiler, `rebuild-cache`, `recompile --all`. Audit codes `platform.bundle_seq_bumped`, `platform.cache_rebuilt` and `organization.recompile_requested` (one per organization). Database migration `00032` runs automatically.
- Declarative configuration (M6c step 2, ADR 0011): `GET /api/v1/config` exports the organization's configuration as a `paddock.v1` document (schema `api/schema/paddock.v1.json`: login and update settings, device groups, permission profiles, managed files and units, package holds, profile assignments) and `PUT /api/v1/config` applies one in a single transaction. A section that is present is authoritative (unlisted items are deleted), absent sections are untouched; `?dry_run=true` computes and checks the plan without changing or recording anything. The rules of the per-resource endpoints apply unchanged and abort the whole apply with their problem code and the document path in the detail (deleting device groups and changing settings need `org_admin`, assigning a full profile needs a step-up, which an API token never has); a schema violation is 422 `invalid_document` listing up to 20 paths; documents are limited to 1 MiB. Every apply is audited once as `config.applied`; one with changes records a change set (`GET /api/v1/change-sets`, list contract with filter `source` = `session|api_token`, and `GET /api/v1/change-sets/{id}` with the plan; file contents appear only as SHA-256). Items are identified by their natural keys, shown as the JSON array of their parts (for example `[null,"/etc/motd"]`). Every answer carries `plan_sha256`; an apply with `?expected_plan=<plan_sha256>` is refused with 412 `plan_changed` and applies nothing when the plan differs from the confirmed one. Deleting a device group deletes its scoped files, units, holds and assignments, so each must be a deletion in the plan: a document that deletes a group is refused with 409 `in_use` when it leaves out a section in which the group still has items, and with 422 `invalid_document` when it still lists an item of the group. A device group that still has member devices is not deleted or renamed (409 `in_use`); move its devices in the portal first. Database migrations `00031` and `00034` run automatically.
- API tokens (M6c step 1): `/api/v1/api-tokens` (list contract with filter `status` = `active|expired|revoked`, create, get, `POST …/{id}/revoke`) issues scoped, expiring credentials of one organization for automation. A token carries one organization role (`org_admin` creates any, `org_operator` operator and auditor tokens, auditors none), expires between 1 hour and 365 days after creation, and is created only with a step-up of the last 5 minutes, so a token cannot create tokens. The secret (`pdk_` and 43 characters) is shown once; only its SHA-256 is stored, lists show its first 12 characters. Requests authenticate with `Authorization: Bearer <secret>` instead of the session cookie and still send `X-Paddock-CSRF: 1` on mutating requests; everything a token does is audited with actor type `api_token` and source `api`. A revoked or expired token is refused with 401 and one `api_token.use_denied` event; unknown secrets are refused without an event (metric `paddock_api_token_auth_total{result}`). `GET /api/v1/me` with a token describes the token (`api_token`). Audit codes `api_token.created`, `api_token.revoked`, `api_token.use_denied`. Database migration `00030` runs automatically.
- Review of M5c: `paddock-server osv import` is audited as `platform.osv_imported` (records, entries, data version; no file path); findings keep Fleet's own severity and fixed version (`fleet_severity`, `fleet_fixed_version`), so a CVE Ubuntu drops or has not prioritized shows Fleet's values again. Database migration `00029` runs automatically.
- Portal and admin API show Ubuntu's priorities (M5c step 3): the vulnerability lists of a device and of the organization sort by severity (`sort=severity`, `-severity`; unknown last), the organization's list shows per CVE the finding with the highest severity, and findings carry `cvss_vector`, shown as tooltip of the CVSS column. Runbook `docs/operations/vulnerability-data.md` (download, monitoring, air-gapped import); `docs/compliance/privacy.md` states that the OSV download carries no device data.
- Vulnerability findings carry Ubuntu's priority and fix (ADR 0020, M5c step 2): after every inventory sync of a host and whenever Ubuntu's data changed, each finding gets the severity from Ubuntu's priority for the release of its device (critical, high, medium, low; negligible counts as low; untriaged or no priority keeps the previous severity, `unknown` with Fleet free), the version that fixes it in that release, and the CVSS vector (new column `cvss_vector`). Fleet reports binary package names; they are matched to Ubuntu's source packages through the binary packages Ubuntu's data lists.
- Ubuntu's vulnerability data (ADR 0020, M5c step 1): the worker downloads Ubuntu's OSV bulk file (`PADDOCK_OSV_UBUNTU_URL`, default `https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip`) once a day at a random minute, and at start when its data is older than a day, with the ETag of the last download (`If-None-Match`), at most 2 GiB and 10 minutes, parsed while it arrives. It keeps Ubuntu's priority, the fixed version and the CVSS vector per CVE, Ubuntu LTS release from 24.04 on and source package, and which binary packages each source package builds. A failed or incomplete download keeps the previous data; after 3 days without a successful update the worker records `platform.osv_stale` (platform pseudo-organization) and sets `paddock_osv_stale` to 1 (also `paddock_osv_last_success_timestamp_seconds`, `paddock_osv_entries`). Installations without access to the OSV bucket import the file with `paddock-server osv import <file>`. Database migration `00028` runs automatically. Allow `paddock-worker` outbound HTTPS to `osv-vulnerabilities.storage.googleapis.com` (or set a mirror in `PADDOCK_OSV_UBUNTU_URL`); without it the findings keep severity `unknown` and the stale alert follows after 3 days.
- Portal for update management (M5b step 4): *Updates* settings (schedules and staleness thresholds, validated as the server does), *Package holds* (list, create, change, release after a confirmation), an *Updates* card on the device page (last security and regular run, pending reboot, held packages and conflicting versions, *Install now*), *Install now* on the device group page, and the *Attention* page with a count badge in the navigation; organization administrators start on it while it has entries.
- Staleness alerts and the attention list (F12, M5b step 3): every 5 minutes the worker compares each active device's last contact with the organization's `staleness_warning_h` (default 24) and `staleness_critical_h` (default 168); crossing a level raises an alert, audited once as `device.stale_warning` or `device.stale_critical`, critical marks the device presumed lost (`presumed_lost_at` on the device detail), and its next contact clears both with `device.stale_cleared`. `GET /api/v1/attention` (list contract, filter `kind`) lists every open condition that needs an administrator: staleness, presumed lost, quarantined, disk encryption not compliant, agent not the current release, failed login or sudo configuration, a waiting or recently expired Lock or Destroy. Database migrations `00026` and `00027` run automatically.
- Update management (F6, M5b steps 1–2): `GET` and `PUT /api/v1/settings/updates` (organization administrators; audit `settings.updates_changed`) set the time of the daily security updates (`security_daily_at`, default 03:00 local device time), the schedule of regular updates (`regular_schedule`, default `Sat 04:00`; optional weekdays and `HH:MM`, anything else is 422 `invalid_schedule`), whether regular updates run, the random delay (default 60 minutes) and the staleness thresholds. `/api/v1/package-holds` (list contract, create, change, delete; audit `package_hold.*`) holds packages for the organization or a device group, optionally pinned to a version. `POST /api/v1/devices/{id}/install-now` and `POST /api/v1/device-groups/{id}/install-now` (at most 20 packages, 500 devices; audit `device.install_now_requested`) issue the new command `install_now` (valid 24 hours); a held package is refused with 409 `package_on_hold`. `GET /api/v1/devices/{id}/updates` shows a device's last runs, a pending reboot, its holds and conflicting versions. v2 bundles carry an `updates` section: the agent restricts unattended-upgrades to the security pocket with the held packages blacklisted, moves `apt-daily-upgrade.timer` to `security_daily_at`, holds packages with `apt-mark hold` or pins them (`/etc/apt/preferences.d/50paddock`, priority 1001), leaves holds it did not set alone, and runs `paddockd updates run` (`apt-get dist-upgrade`, at most 60 minutes) from `paddock-updates.timer`. Every finished regular or security run is reported as `device.updates_run` (security runs are taken from `apt-daily-upgrade.service` and the unattended-upgrades log entry that began during it); a masked apt timer is never unmasked by the agent and is reported as an error; apt and dpkg run in the C locale, an install now or regular run is not cut short when the agent stops, an installation interrupted earlier is finished with `dpkg --configure -a` first, and an install now an agent restart interrupted is reported as failed with reason `interrupted`, never run again; check-ins report `reboot_required`, and Paddock never reboots for updates. Database migration `00025` runs automatically.
- `LICENSE` file with the MIT license text; `make typecheck` type-checks every Go module including tests (`go vet`) and the portal (`vue-tsc`); the CI runs the acceptance gates for pull requests as well, not only on `main`.
- Software and vulnerabilities in the portal and admin API (F4, M5a step 4): device detail tabs *Software* and *Vulnerabilities*, organization-wide pages *Software* (per package and version with the number of devices) and *Vulnerabilities* (per CVE with its affected devices), and a start page tile with the devices that have critical or high findings and those with findings of unknown severity; the read-only list endpoints `GET /api/v1/devices/{id}/software`, `GET /api/v1/devices/{id}/vulnerabilities`, `GET /api/v1/software`, `GET /api/v1/vulnerabilities`, `GET /api/v1/vulnerabilities/{cve}/devices` and `GET /api/v1/vulnerabilities/summary` follow the list contract. Fleet free reports no CVSS score, severity or fixed version: such findings show severity `unknown` (filter `severity=unknown`) and sort last by score. New CVE matches of Fleet reach Paddock in the next inventory round (`docs/operations/fleet.md`).
- `docs/compliance/privacy.md` lists everything the Paddock agent and fleetd collect, what Paddock stores of it and the negative list of what is never collected (C9, M5a step 4).
- Inventory sync (F4, M5a step 3): every inventory round `paddock-worker` pushes Paddock's pass/fail policies (`paddock_agent_running`, `disk_encrypted`) to Fleet, maps Fleet hosts to devices by hardware UUID (only a UUID of exactly one active or quarantined device maps; others are counted in `paddock_inventory_unmapped_hosts` and never stored) and stores each mapped device's OS and fleetd version, installed packages, matched CVEs and policy results under its organization. A device whose agent fleetd finds not running while it has not checked in for 15 minutes is reported as `device.tamper_agent_not_running`. The database migration `00024` runs automatically; retire old devices of reinstalled machines so that their hosts map again (`docs/operations/fleet.md`).
- fleetd on devices (F4, M5a step 2): `make fleetd-deb` builds fleetd with `fleetctl package` (no enroll secret, scripts, Fleet Desktop or auto-updates) and `make agent-release` uploads it as package `fleet-osquery` of the release (`PUT …/packages/fleet-osquery/amd64?package_version=<fleetd version>`; database migration `00023` runs automatically). v2 bundles carry an `inventory` section (Fleet URL, enroll secret, package of the newest published release with one); the agent installs fleetd from `https://bundles.<domain>/packages/…` after checking its SHA-256, enrolls it and keeps `orbit.service` running, and reports a stopped fleetd as `device.tamper_service_stopped` and changed fleetd files as `device.tamper_protected_file_changed`. Managed files and units can no longer target `/opt/orbit/`, `/etc/default/orbit`, `/etc/systemd/system/orbit*` or units named `orbit*`. **BREAKING:** give `paddock-compiler` `PADDOCK_FLEET_PUBLIC_URL` and `PADDOCK_FLEET_ENROLL_SECRET_FILE`, and include fleetd in your agent releases (`docs/operations/fleet.md`).
- Fleet for inventory and vulnerabilities (F4, M5a step 1): new Compose services `fleet` (Fleet free, pinned), `fleet-mysql` (MySQL 8.4) and `fleet-redis` (Valkey) on the internal network `fleet`; Caddy publishes only Fleet's device endpoints under `fleet.<domain>` (`/api/osquery/*`, `/api/v1/osquery/*`, `/api/fleet/orbit/*`), every other path, including Fleet's UI, admin API and file carving, answers 404. `paddock-worker` enforces Fleet's data minimization settings at start and every inventory round (host users, live queries, scripts, reports, usage statistics and webhooks off; no scheduled queries or packs; Linux software from the system package managers only) and resets drift. **BREAKING:** create the DNS name `fleet.<domain>`, set up Fleet and its API-only user `paddock` as in `docs/operations/fleet.md`, and give `paddock-worker` `PADDOCK_FLEET_URL`, `PADDOCK_FLEET_PUBLIC_URL` and `PADDOCK_FLEET_TOKEN_FILE`; development stacks run `make dev-secrets up`.
- Portal (flagged, M4c step 6): the device page has a *Lock and Destroy* card (reason, step-up, typed hostname; Destroy explains that a second administrator must approve) with the device's revocation timeline and a notice when the device presumably locked itself; the new *Revocations* page lists the organization's requests with approve, reject and cancel; the new *Dead man's switch* page sets the switch and warns that every device locks itself when Paddock is unreachable for longer than the period. While the flag is off these pages say that revocation is not enabled on this installation. `GET /api/v1/me` returns `revocation_enabled`, the device detail `presumed_self_locked_at`.
- Runbooks (M4c step 7): `docs/operations/revocation.md` covers the portal, restoring a locked device from the escrow and the dead man's switch; `docs/operations/revocation-acceptance.md` is the hardware acceptance protocol and the second-person review checklist that must be signed off before the revocation flag may be enabled.
- Dead man's switch (flagged, F5, M4c step 5): `GET` and `PUT /api/v1/settings/dms` (organization administrators; turning it on or changing it while on needs a step-up; audit `settings.dms_changed`) set whether the organization's devices lock themselves after `period_days` (7–365, default 30; development installations accept 1 for the hardware acceptance protocol) of uptime without reaching Paddock, with warnings `warn_days` before (default 3 and 1 days) on the login screen and as desktop notifications. While it is on, the revocation-issuer gives every active device a `self_lock` token valid 365 days (renewed after 60) that `paddock-revoke` stores; only uptime since the last time ticket counts, never the wall clock. Turning it off cancels the tokens and sends `delete_self_lock` to every device. The worker marks devices silent for longer than the period as presumably self-locked (audit `device.presumed_self_locked`). Database migration `00022` runs automatically.
- Time tickets (M4c step 5): the compiler signs a time ticket per organization every 10 minutes with the new OpenBao Transit key `time-ticket`; check-in responses carry it as `time_ticket` and schema v2 bundles carry its public keys in `keys.time_ticket` and the switch in a `dms` section. **BREAKING:** create the key and extend the `paddock-compiler` policy with `transit/sign/time-ticket` and read on `transit/keys/time-ticket` as described in `docs/operations/openbao.md`; `make up` does this in development.
- `paddock-revoke` (flagged, M4c step 3): its own Debian package (`/opt/paddock/revoke/paddock-revoke`, no dependencies), installed by the Paddock autoinstall and updated only by package installation, never by the agent update. `paddockd` hands it every revocation token of a check-in once without interpreting it; `paddock-revoke` refuses unless `/etc/paddock/revoke-enabled` exists, the token is signed by a pinned revocation key, names this device, has not expired, has not run before and no other revocation ran within 24 h; then it terminates the user sessions, erases every keyslot of the root volume, verifies the erasure, posts the confirmation (waiting up to 20 s) and reboots. Refusals are audited as `device.revocation_refused` with the reason.
- Lock and Destroy (flagged, F5, M4c step 2): `POST /api/v1/devices/{id}/lock` and `/destroy` (organization administrators, a step-up per request and approval, typed hostname, reason), `POST /api/v1/revocation-requests/{id}/approve|reject|cancel` and `GET /api/v1/revocation-requests`; a Destroy needs a second administrator with another identity. The new role `paddock-server serve revocation-issuer` verifies every approval's step-up token against Authentik, enforces the limits of ADR 0014 (per administrator 3 per hour and 10 per 24 h, per organization 20 per 24 h; exceeding them rejects the request, raises `paddock_revocation_refused_total{reason=~"limit_.*"}` and freezes the administrator for 24 h), deletes the escrowed header versions and recovery keys of a Destroy and signs the device-bound token. Audit codes `revocation.*`, `device.escrow_destroyed`, `device.revocation_confirmed`. **BREAKING:** run the revocation-issuer (database role `paddock_revocation`, RabbitMQ user `revocation_issuer`, AppRole `paddock-revocation-issuer`, an escrow bucket credential that may delete header versions) as described in `docs/operations/revocation.md` before migration `00020` runs.
- Revocation trust anchor (flagged, M4c step 1): enrollment configurations carry `revocation_keys`, the public keys of the new OpenBao Transit key `revocation-signing`, and `paddockd enroll` pins them in `/etc/paddock/revoke-trust.json`; devices enrolled earlier pin the keys of their first bundle that carries them once (trust on first use, audit `device.revocation_trust_pinned_tofu`; re-enrolling replaces them). Schema v2 bundles carry a `revocation` section with the feature flag and these keys; the agent keeps `/etc/paddock/revoke-enabled` only while the flag is on.
- Feature flag `PADDOCK_REVOCATION_ENABLED` (default `false`) for the revocation path; it stays off outside development and test installations until the revocation path has passed its second-person review and the hardware acceptance protocol (M4c decision 1).
- Disk recovery (AC2): `GET /api/v1/devices/{id}/disk` shows the disk encryption state, keyslots, escrowed recovery key and header generations and the last keyslot change; `POST /api/v1/devices/{id}/disk/recovery-key` reveals the recovery key and `POST /api/v1/devices/{id}/disk/header` downloads a decrypted header backup for `cryptsetup luksHeaderRestore` (organization administrators, step-up and typed hostname, audit `disk.recovery_key_revealed` and `disk.header_downloaded`); the device list filters by `disk_state`. The portal shows a *Disk encryption* card on the device page and a disk state column and filter in the device list. **BREAKING:** the api needs `PADDOCK_ESCROW_S3_ENDPOINT`, `PADDOCK_ESCROW_S3_ACCESS_KEY_FILE` and `PADDOCK_ESCROW_S3_SECRET_KEY_FILE` (read-only credential of `paddock-escrow`). Runbook: `docs/operations/disk-recovery.md` (M4b step 5).
- Disk encryption on the device (agent `luks` reconciler): on a device installed with the Paddock autoinstall the agent enrolls a high-entropy recovery key, escrows it (`POST /v1/escrow` kind `luks_recovery_key`) and the LUKS header (kind `luks_header`: sealed with AES-256-GCM, the key wrapped to `escrow-wrap`, uploaded with a 10-minute presigned PUT to `org/<org>/devices/<device>/luks-header/<generation>.bin` in the new bucket `paddock-escrow`, verified by the worker), then removes the install passphrase and escrows the header again; check-ins report `health.disk` (`state` `not_encrypted`, `unmanaged`, `tpm_missing`, `tpm_pin_missing`, `escrow_pending` or `compliant`, keyslot kinds), and a keyslot change outside Paddock is reported as `device.tamper_keyslot_changed` and escrows the header again (device event `tamper.keyslot_changed`). The database migration `00017` runs automatically (M4b step 4).
- **BREAKING:** the worker needs `PADDOCK_ESCROW_S3_ENDPOINT`, `PADDOCK_ESCROW_S3_ACCESS_KEY_FILE` and `PADDOCK_ESCROW_S3_SECRET_KEY_FILE` (read-only credential of `paddock-escrow`; `PADDOCK_ESCROW_S3_BUCKET` defaults to `paddock-escrow`); operators create the bucket with versioning and without Object Lock, allow the gateway's bundles credential `s3:PutObject` on `paddock-escrow/org/*/devices/*/luks-header/*`, and route `PUT /paddock-escrow/org/*` on the bundles host to the object store; `make dev-secrets up` does this in development (M4b step 4).
- First-boot disk setup: the `paddock-agent` package ships `paddock-disk-setup.service`, which on a device installed with the Paddock autoinstall asks on the console for the boot PIN (twice, at least `boot_pin_min_length` characters) before the login screen and enrolls TPM2+PIN (PCR 7) with `paddockd disk-setup`; entering nothing twice skips it, and a device without TPM 2.0 boots as before. The agent then enrolls itself with `/etc/paddock/enroll.json` at its first start. The package now depends on `cryptsetup` and `tpm2-tools` (M4b step 3).
- Paddock autoinstall: `POST /api/v1/autoinstall` (organization administrators and operators, audit `autoinstall.generated` with release and agent version) returns Ubuntu 24.04 or 26.04 user-data for one device from an enrollment configuration of the organization — LVM inside LUKS2 under a random temporary passphrase, the agent packages of the newest published release pinned by SHA-256, the enrollment configuration and the first-boot disk setup; on 24.04 it switches the initramfs to dracut for TPM2+PIN. The answer is secret and never stored; see `docs/operations/autoinstall.md`. The api needs `PADDOCK_BUNDLES_PUBLIC_URL` (M4b step 2).
- Login setting `boot_pin_min_length` (6–32, default 8; portal *Login & privileges → Disk encryption*): the shortest boot PIN that devices installed with the Paddock autoinstall accept at their first boot. **BREAKING:** `PUT /api/v1/settings/login` requires the field; clients that read the settings before writing them keep working. The database migration `00016` runs automatically (M4b step 2).
- Agent releases carry their Debian packages: `PUT /api/platform/v1/agent-releases/{version}/packages/{name}/{arch}` (platform administrators, signed with the release key, audited as `agent_release.artifact_uploaded` with `kind` `deb`) stores `paddock-agent` and `paddock-supervisor` in `paddock-agent-artifacts`, served without credentials at `https://bundles.<domain>/packages/<version>/<name>_<version>_<arch>.deb`; `make agent-release` uploads them. **Operators** add the public-read bucket policy for `packages/*` and the Caddy route `/packages/*` described in `docs/operations/agent-releases.md`; the database migration `00015` runs automatically (M4b step 1).
- CI security checks: gitleaks over the full git history, trivy for dependencies, misconfiguration, secrets and both server images (`make scan`), Dependabot for Go modules, npm and GitHub Actions; weekly scheduled run for new CVEs.
- Portal: the device page shows the managed local administrator (account, active and pending generation, last and next rotation, overdue and failed rotations) with Rotate now and Reveal — reveal runs the step-up, asks for the typed hostname and shows the passwords with a copy button for 60 s — and lists the device's commands; actions that need a step-up (assigning or editing a `full` permission profile) send the administrator through it and repeat once afterwards (M4a step 6).
- Login notice: the organization's `notice_text` (login settings, at most 2000 characters, with an English default about the acceptable-use policy and logging; empty removes it) is shown at the GDM login screen, on text consoles and before SSH logins of every device with login management; the agent restores the four files when they are changed locally, and the database migration `00014` runs automatically; see `docs/operations/device-login.md` (M4a step 5).
- Managed local administrator (F16): devices with login management create the account `paddock-admin` (setting `local_admin_username`, member of `sudo`, a break-glass account in both bundle resources) and rotate its password every `local_admin_rotation_days` (default 30) — escrowed first, set only after the server stored it, so the password is never unknown; changes of password, lock, shell or group are reported (`device.tamper_local_admin_changed`) and repaired, logins with the account are audited (`local_admin.login`); see `docs/operations/local-admin.md` (M4a step 4).
- Admin API `GET /api/v1/devices/{id}/local-admin` and `POST /api/v1/devices/{id}/local-admin/reveal` (organization administrators, step-up and typed hostname; returns the active and a pending password with `Cache-Control: no-store`, audit `local_admin.revealed` without passwords; with `rotate_after_reveal_hours` a rotation follows that many hours later); login settings `local_admin_username`, `local_admin_rotation_days` and `rotate_after_reveal_hours` (database migration `00013`, runs automatically); device events and audit codes `local_admin.rotated`, `local_admin.rotation_failed`, `local_admin.login`, `device.tamper_local_admin_changed` (M4a step 4).
- Secret escrow (shared with M4b): the new OpenBao Transit key `escrow-wrap` (RSA-4096, not exportable), whose latest public key v2 bundles carry as `keys.escrow_wrap`; devices encrypt secrets to it with RSA-OAEP and SHA-256 and upload them with `POST /v1/escrow` (device API, at most 4 KiB), the worker stores them (database migration `00012`, table `escrow_secret`, runs automatically) and devices poll `GET /v1/escrow/{escrow_id}` until `stored` or `failed` (a generation not above the active one fails); only the new AppRole `paddock-escrow-reader` may decrypt (M4a step 3).
- The compiler recompiles every organization once when the public keys of bundles change (a rotation of `command-signing` or `escrow-wrap`, and once after its start), so devices receive new keys with their next bundle; devices whose content is unchanged keep their bundle version (M4a step 3).
- Step-up authentication: changing a permission profile to class `full` and assigning a `full` profile require a fresh password-and-MFA authentication of the administrator (at most 300 s old); without it the request answers 403 `step_up_required` and is audited as `denied`, a permitted action records the actor with `step_up: true`. The portal session starts it with `GET /api/auth/stepup`; Authentik runs the new flow `paddock-stepup` through the new OIDC application `paddock-portal-stepup` (blueprint `paddock-stepup.yaml`, applied automatically); see `docs/operations/step-up.md` (M4a step 2).
- `make dev-seed` gives the development users TOTP authenticators with the keys in `.secrets/dev_<user>_totp_key`, so the acceptance gates can complete step-ups (M4a decision 8).
- Device commands (architecture §11.4): commands are signed individually by the new OpenBao Transit key `command-signing` (Ed25519, not exportable) in `paddock-worker`, delivered in the check-in response (`commands`, device API, additive) until they finish or expire, and executed by the agent at most once after it verified signature, device, organization and lifetime against the command keys of its bundle; results arrive through `POST /v1/commands/{command_id}/result` (idempotent, another status is 409 `conflict`), and the worker marks open commands `expired` at the end of their lifetime (M4a step 1).
- Admin API `GET /api/v1/devices/{id}/commands` lists a device's commands (list contract with status and type filters) and `POST /api/v1/devices/{id}/local-admin/rotate` issues `rotate_admin_password` (valid 7 days, audit `local_admin.rotation_requested`); the agent of this step answers it with `unsupported_type` until the managed local administrator arrives (M4a step 1).
- Bundles of schema v2 carry a top-level `keys` object with every version of the `command-signing` public key; agents of earlier releases ignore it (M4a decision 5).
- Compose stack for the control plane (Caddy, PostgreSQL, RabbitMQ, OpenBao, Authentik) and a separate audit domain (`compose.audit.yaml` with its own PostgreSQL and RustFS); all images are pinned by tag and digest in `deploy/compose/versions.env` (M0 step 2).
- `make dev-secrets`, `make up`, `make dev-seed` start a complete local development stack; `make up` also initializes and unseals OpenBao and creates the audit bucket (M0 steps 2, 7, 10).
- WORM audit bucket `paddock-audit` with Object Lock COMPLIANCE and 400 days default retention, verified by the acceptance gate `make acceptance T=TestWORM` (F7, M0 step 3).
- `paddock-server migrate paddock|audit` applies the forward-only database migrations; organization data is isolated by PostgreSQL row-level security (F10, M0 step 4).
- `paddock-server provision rabbitmq` declares the audit exchange, quorum queue and dead-letter queue; the `outbox-relay` role delivers audit events with publisher confirms and finalizes stuck actions as `unknown` after 10 minutes (F7, M0 step 5).
- `audit-writer` role: indexes audit events, stores them as WORM objects under `org/<organization_id>/`, and seals a daily per-organization manifest signed with the OpenBao Transit key `audit-chain` at 00:15 UTC (F7, M0 step 6).
- `paddock-server audit verify --org <id> --from <day> --to <day>` checks the signed manifest chain and every object hash (exit code 0/1) (F7, M0 step 6).
- Admin API (`api/openapi/admin.yaml`) with portal login through Authentik (OIDC with PKCE, encrypted session cookie), device groups, audit log and platform organization management; every privileged action records exactly one audit event (F7, F8, F10, M0 step 7).
- Creating an organization creates its Authentik groups `paddock.<slug>`, `.admins`, `.operators`, `.auditors`; an organization left in `provisioning_failed` is re-provisioned by repeating the request (F10, M0 step 7).
- Administration portal at `https://admin.<domain>` for device groups, the audit log and organizations, English only, served with a strict Content Security Policy (F8, C7, M0 step 8).
- Portal roles come from Authentik group membership: `paddock.<slug>.admins`, `.operators` and `.auditors` map to organization administrator, operator and auditor; `paddock.platform.admins` grants platform administration (F8, M0 step 7).
- `make dev-seed` creates the development organizations `acme` and `globex` and assigns the test accounts listed in `README.md` (M0 step 9).
- Acceptance gates for organization isolation, exactly-once auditing, login rules and the audit hash chain (`make acceptance`) (M0 step 9).
- Runbooks `docs/operations/openbao.md` (production initialization with five custodians, unsealing, credential rotation) and `docs/operations/audit-bucket.md` (one-shot production bucket creation and verification) (M0 step 10).
- Admin API lists support sorting (`sort`, `-` prefix for descending), case-insensitive search (`q`) and filters (audit log: `code`, `outcome`, `actor_type`; organizations: `status`), documented per endpoint by the OpenAPI extension `x-paddock-list` (ADR 0018, M0.2 step 1).
- Database migrations add indexes for sorting and searching lists; the audit database migration installs the PostgreSQL extension `pg_trgm` as `audit_owner`, no operator action needed (ADR 0018, M0.2 step 1).
- Every portal list (device groups, audit log, organizations) offers search, filters, sortable columns, page numbers and 10, 25, 50 or 100 items per page; the list state is kept in the URL, so reload, back navigation and shared links restore it (ADR 0018, M0.2 step 4).
- The audit log in the portal can be filtered by outcome and actor type in addition to time range and event; without a time range it shows the last 7 days (ADR 0018, M0.2 step 4).
- Valkey (`valkey` service, AOF `everysec`, password from `.secrets/valkey_password`) and a control-plane RustFS (`rustfs` service) with the bucket `paddock-bundles` join the stack; `make bundles-bootstrap` (run by `make up`) creates the bucket and the compiler (read/write) and gateway (read-only) credentials (M2a step 2).
- Public hostname `bundles.<domain>` serves bundles through presigned `GET` URLs only; other methods and paths are refused with 403 (M2a step 2).
- `paddock-server provision rabbitmq` also declares the exchanges `paddock.ingest` (queues `ingest.enroll`, `ingest.heartbeat`, `ingest.event`, byte limit `PADDOCK_INGEST_QUEUE_MAX_BYTES`, default 256 MiB) and `paddock.state` (queues `state.p00`…`state.p15`, `state.priority` with single active consumer), each queue with a dead-letter queue `dlq.<queue>` (M2a step 2).
- OpenBao Transit key `bundle-signing` (Ed25519, not exportable) and AppRole `paddock-compiler`; the `paddock-api` policy may read the public keys of `bundle-signing` (M2a step 2).
- Admin API for the device control plane: enrollment tokens (`/api/v1/enrollment-tokens`, the secret and the enrollment configuration with the bundle-signing public keys are returned once, only a hash is stored), devices with approve, reject, release-quarantine and retire actions, device group memberships, effective configuration per device, managed files and managed systemd units, and the members of a device group; all lists follow the list contract and all changes are audited (A6, F1, M2a step 3).
- Managed files are restricted to paths below `/etc/`, `/usr/local/etc/` and `/opt/` outside protected areas (sudoers, PAM, NSS, Himmelblau, Paddock, crypttab, fstab, account databases, `/etc/apt/`), at most 64 KiB of UTF-8 text; reserved units (`paddock*`, `himmelblau*`, `fleet*`, `ssh*`, `gdm*`, `systemd-*`) are refused with 422 (M2a decision 8).
- `worker` role (`paddock-server serve worker`, Compose service `paddock-worker`): turns enrollment requests from `ingest.enroll` into devices and keeps the enrollment token and device key caches in Valkey in step with PostgreSQL (every change immediately, everything every 60 s) (A6, M2a step 3).
- Audit codes `enrollment_token.created`, `enrollment_token.revoked`, `device.enrolled`, `device.approved`, `device.rejected`, `device.quarantine_released`, `device.retired`, `device.groups_changed`, `managed_file.*`, `managed_unit.*`; devices appear as audit actor type `device` (M2a step 3).
- Device API at `https://device.<domain>` served by the new `gateway` role (`paddock-server serve gateway`, Compose service `paddock-gateway`): enrollment, enrollment status, check-in with presigned bundle URLs (valid 120 s) and device event batches, contract `api/openapi/device.yaml`. Every request is signed with the device's ECDSA P-256 key (timestamp within ±300 s, single-use nonce); the gateway has no database credentials and keeps answering check-ins while PostgreSQL is down (A5, C2, M2a step 4).
- The gateway limits device requests to 30 per minute per key and 300 per minute per source address (429 with `Retry-After`) and answers 503 `backpressure` when an ingest queue refuses a message (M2a step 4).
- Metrics `paddock_gateway_requests_total{route,code}` and `paddock_gateway_auth_failures_total{reason}` (M2a step 4).
- `compiler` role (`paddock-server serve compiler`, Compose service `paddock-compiler`): after every change of a device's inputs it renders the device's bundle (schema v1: NTP, managed files, managed units), signs it as a DSSE envelope with the OpenBao key `bundle-signing` and stores it as `org/<organization>/devices/<device>/bundles/<version>.dsse` in `paddock-bundles`; content-equal renders keep the version, changes within 2 s are coalesced, and bundle pointers in Valkey are rebuilt from PostgreSQL every 60 s (F1, A9, M2a step 5).
- The worker records check-ins in the device status at most once per minute per device, quarantines a device whose sequence numbers diverge (cloned identity, audit event `device.clone_suspected`) and records device events as audit events `device.bundle_applied`, `device.bundle_rejected` and `device.config_drift_corrected`, each once per event sequence number (A6, M2a step 5).
- Metrics `paddock_compiler_bundles_total{result}` and `paddock_compiler_latency_seconds` (M2a step 5).
- Acceptance gates D1–D4 for the device protocol, its security, clone detection and the absence of a synchronous device-to-database path, run with the reference device client `test/acceptance/devicesim` (`go run ./test/acceptance/cmd/devicesim enroll` enrolls a simulated device) (M2a step 6).
- Portal pages *Devices* (list with state and device group filters; detail with identity, device groups, effective configuration and conflicts, approve, reject, release quarantine and retire — retiring requires typing the hostname), *Enrollment tokens* (the enrollment configuration with its copy button is shown once), *Managed files* and *Managed units*; a device group page lists its devices (AC1, AC2, M2a step 7).
- Device agent `paddockd` (module `agent/`, static binary for linux/amd64 and linux/arm64): `paddockd enroll --config <file> [--remove-config] [--no-wait]` stores `/etc/paddock/agent.yml` and `/etc/paddock/trust.json`, creates the device key `/var/lib/paddock/identity/sign.key` and waits for approval (exit code 0 active, 2 pending, 3 rejected, 1 error; re-running resumes with the same key and enrollment) (A6, M2b step 1).
- `paddockd run` checks in every `next_checkin_s` (back-off 30 s to 30 min while the server is unreachable), at start, and within 15 s after NetworkManager reports full connectivity or the device resumes; a device that is still pending approval keeps polling its enrollment (C2, M2b step 1).
- `paddockd self-test` prints a JSON report of the agent's own checks (configuration, trust anchor, identity key, cached bundle, server reachability) and exits 0 or 1; `GET /health` on `/run/paddock/agent.sock` reports status, version, last check-in, last bundle version and last error (M2b step 1).
- The agent applies its signed bundle after verifying hash, signature, device, organization and version: NTP (chrony if installed, otherwise systemd-timesyncd), managed files (atomic write, owner, group, mode) and managed systemd units, in that order; a failing resource does not stop the others and is listed in the `bundle.applied` event, a bundle that fails verification is reported once as `bundle.rejected` and changes nothing (F1, M2b step 2).
- The agent enforces the managed path and unit policy itself before it touches the device, and never manages Paddock's own, SSH, GDM, Himmelblau, Fleet or systemd units (M2b decision 10).
- When a file leaves the configuration, the agent deletes it only if nobody changed it since Paddock wrote it; a locally modified file stays in place and is reported as `left_modified_file` (F1, M2b step 2).
- Drift correction: every `drift_interval_s` (default 300, from `/etc/paddock/agent.yml`) the agent re-checks the applied bundle, corrects local changes and reports them as `config.drift_corrected`; without a server it keeps enforcing the last applied bundle (F1, C2, M2b step 2).
- Device events are spooled in `/var/lib/paddock/spool/events.jsonl` (at most 50 MiB; on overflow drift events are dropped first and the gap is reported as `agent.events_dropped`) and sent after each check-in until the server accepted them (M2b step 2).
- `paddockd plan` prints, without changing anything, what applying the last applied bundle again would change (M2b step 2).
- Device event types `agent.updated`, `agent.update_failed`, `agent.rolled_back` and `agent.events_dropped` with the audit codes `device.agent_updated`, `device.agent_update_failed`, `device.agent_rolled_back` and `device.agent_events_dropped`; device event audit params additionally record `version`, `changed`, `errors`, `resource_ids`, `from_version`, `outcome`, `count`, `from_seq` and `to_seq` (M2b decision 23).
- `paddock-supervisor` starts `/opt/paddock/agent/current/paddockd run`, restarts it with back-off (1 s to 60 s) and pets the systemd watchdog while it is responsive; it installs agent releases only after verifying their minisign signature with the release public key compiled into it, copies them into the inactive slot `/opt/paddock/agent/A` or `B`, runs `paddockd self-test`, switches with one symlink flip and watches a probation of 10 minutes; a release that crashes three times or does not check in by the end of the probation is rolled back automatically (design contract 1–5, M2b step 3).
- The agent downloads an offered release into `/var/lib/paddock/staging/`, checks size and SHA-256 and asks the supervisor to install it; the supervisor's result is reported as `agent.updated`, `agent.update_failed` (`signature_invalid`, `self_test_failed`) or `agent.rolled_back`, and a failed version is not tried again (M2b step 3).
- Agent releases and staged rollouts (platform API `/api/platform/v1/agent-releases`): create a release, upload its signed `paddockd` per architecture (`PUT …/{version}/artifacts/{arch}` with `X-Paddock-Minisig`; the server refuses binaries that do not verify with the release public key), publish, and start, halt or resume its rollout; all actions are audited (`agent_release.*`, `agent_rollout.*`) (M2b step 4).
- Rollouts proceed in waves (default 1 %, 10 %, 50 %, 100 % of the devices, at least 1440 minutes each); the worker evaluates them every minute, halts a rollout automatically when the failed devices reach `max(failure_threshold_min, ceil(eligible × failure_threshold_percent / 100))` (audit `agent_rollout.halted`, actor system) and advances or completes it otherwise; the gateway offers the release at check-in to eligible devices (design contract 6, M2b step 4).
- Portal page *Agent releases* for platform administrators: list, detail with artifacts, rollout wave and device counts, and start, halt and resume in a confirmation dialog (starting requires typing the version) (M2b step 4).
- Bucket `paddock-agent-artifacts` on the control-plane RustFS (created by `make up`), served read-only through presigned URLs on `bundles.<domain>`; runbook `docs/operations/agent-releases.md` for release keys, releasing and rollouts (M2b step 4).
- Debian packages `paddock-supervisor` (supervisor binary, systemd unit `paddock-supervisor.service` with `Type=notify` and `WatchdogSec=60`, slots `/opt/paddock/agent/A` and `B`) and `paddock-agent` (installs `paddockd` into slot A and points `current` at it only on a device without an agent; `/usr/bin/paddockd` follows `current`); `make deb` builds both for amd64, `make agent` builds both binaries for amd64 and arm64, statically linked (A6, design contract 9, M2b step 5).
- `make dev-release-key` creates a password-less development release key in `deploy/compose/.secrets/release/` (also run by `make dev-secrets`); `make agent-release VERSION=x.y.z` builds, signs and uploads a release with it. Production releases are signed offline (`docs/operations/agent-releases.md`) (M2b step 5).
- `make system-test VM=<paddock-u2404|paddock-u2604|all>` runs the agent system gates S1–S5 (enrollment and bundle, configuration idempotency, agent outage, agent update with rollback, staged rollout auto-stop) on the VirtualBox test VMs against the running stack, each from the snapshot `base-installed` (M2b step 6).
- Device API: the check-in request may carry `arch` (`amd64`, `arm64`) and the response may carry `agent_update` (M2b §6.1).
- Authentik blueprint `paddock-device.yaml`: device sign-in flow `paddock-device-authentication` (identification without user enumeration, password, mandatory WebAuthn or TOTP; users without an authenticator must enroll one) device-code flow `paddock-device-code` (MFA again unless passed within 5 minutes), set as the default brand's device-code flow, and authorization flow `paddock-device-authorization` with a mandatory MFA stage, so the QR code path (`?code=`) cannot skip MFA (M3a decision 6, ADR 0007 amendment).
- Authentik blueprint `paddock-recovery.yaml`: recovery flow `paddock-recovery` for the one-time links of new local users (password of at least 12 characters), set as the default brand's recovery flow (M3a decision 18).
- Organization domains: platform administrators set them with `PATCH /api/platform/v1/organizations/{id}` (`{domains}`, lowercase DNS names, each in one organization only, 409 `domain_taken`); the first is the primary domain of device logins, and local usernames must be `<local-part>@<a domain of the organization>` (audit `organization.domains_changed`) (M3a decision 1).
- Users (`/api/v1/users`): list with search and the filters `source` and `locked`, detail with groups, local users created in Authentik without password together with a one-time recovery link (valid 24 h, shown once, never stored), changing and deleting local users; synced users' upstream attributes are read-only (409 `attribute_owned_upstream`) (audit `user.created`, `user.updated`, `user.deleted`) (F13, M3a decision 2).
- Locking and unlocking users (`POST /api/v1/users/{id}/lock`, `/unlock`, organization administrators only): a lock marks the user locked and recompiles the affected devices on the compiler's priority lane before Authentik is called, then adds the user to `paddock.<slug>.locked` and deletes its refresh tokens, access tokens and sessions by deactivating and at once reactivating the user in Authentik; a lock that Authentik did not confirm is recorded as failed, the user stays locked for the devices with `lock_incomplete` true (database migration `00009`, runs automatically), and the user page offers *Retry lock*, which locks again; unlock removes the membership (audit `user.locked`, `user.unlocked`) (F2, M3a decision 7).
- User groups (`/api/v1/user-groups`): local groups `paddock.<slug>.g.<group>` with members managed in Paddock, and imports of upstream Authentik groups (`GET /api/v1/upstream-groups`) as mirror groups `paddock.<slug>.s.<group>` whose members the worker copies; every membership change is audited with the user's highest effective sudo class before and after (`user_group.*`) (F13, M3a decisions 3 and 4).
- Login settings (`GET`/`PUT /api/v1/settings/login`): Hello PIN on/off and minimum length, session action of a user lock (`lock_screen` or `terminate`), break-glass accounts, the `/etc/sudoers.d` allow list and the sudo lecture text; every organization starts with the defaults (audit `settings.login_changed`) (M3a decision 8).
- Login assignment per device (`PUT /api/v1/devices/{id}/login-assignment`, users and groups; empty means every user of the organization; directly assigned users are kept in the Authentik group `paddock.<slug>.d.<device_id>`) and suspension of directory logins (`POST /api/v1/devices/{id}/suspend-logins`, `/resume-logins`, priority lane) (audit `device.login_assignment_changed`, `device.logins_suspended`, `device.logins_resumed`) (F15, M3a decisions 9 and 11).
- Permission profiles (`/api/v1/permission-profiles`: class none, restricted or full, commands of restricted profiles, password requirement, timestamp timeout, lecture) and their assignments (`/api/v1/profile-assignments`: global, to a group or a user, optionally only on one device group); commands that hand out root on their own or in combination are flagged `root_equivalent` (audit `permission_profile.*`, `profile_assignment.*`) (F11, A13, M3a decisions 12–14).
- Effective profiles with derivation: `GET /api/v1/users/{id}/effective-profile?device_id=` shows each part of a user's effective sudo profile with the assignment that granted it; `GET /api/v1/devices/{id}/effective-sudo` lists the effective profiles of the users allowed on a device (F11, M3a decision 14).
- The device detail reports `logins_suspended`, `login_assignment`, the agent's `schema_versions` and `login_management` (false: the agent is too old for login management) (M3a decision 14a).
- Device event type `session.login` (`{username, at}`): the worker remembers which users logged in on which device (`device_user_seen`, no audit event per login) (M3a decision 10).
- Bundle schema v2: the compiler renders a `login` resource (Himmelblau settings, allowed groups, locked users, suspension, break-glass accounts) and a `sudo` resource (effective sudo entries of the device's users, privileged groups, `/etc/sudoers.d` allow list, lecture) for devices whose agent reports schema 2 in `schema_versions` at check-in, and schema v1 unchanged for all others; a device is recompiled when its agent starts reporting schema 2 (F2, F11, F15, M3a decisions 14a–17).
- Every rendered sudo entry is checked with `visudo`; an entry that fails blocks the device's new bundle, the device keeps its previous bundle, and the compiler records the audit event `device.bundle_render_failed` (M3a decision 17).
- User locks and suspended device logins reach the affected bundles through the compiler's priority lane (`state.priority`) without the 2 s coalescing of other changes (F2, M3a decision 7).
- The worker synchronizes synced users (direct members of `paddock.<slug>` without `paddock_managed`) and the members of imported groups every 5 minutes (`PADDOCK_IDENTITY_SYNC_INTERVAL`, 60 s in the development stack) and reconciles every organization's Authentik objects and per-device login groups every 10 minutes (`PADDOCK_IDENTITY_RECONCILE_INTERVAL`); runbook `docs/operations/identity-sources.md` describes how a platform operator connects an upstream source (F13, M3a decisions 2, 3, 5 and 9).
- `make dev-seed` gives `acme` and `globex` the domains `acme.test` and `globex.test`, and `acme` the break-glass account `paddock` and the sudoers.d allow list `README`, `90-paddock` of the test VMs (M3a decision 8).
- Creating an organization also creates the Authentik group `paddock.<slug>.locked` and the device login provider and application `paddock-device-<slug>` (public client with the device code, refresh token and authorization code grants, authorization flow `paddock-device-authorization`, a Paddock scope mapping for scope `profile` that emits the profile claims and a `groups` claim with only the organization's `paddock.<slug>…` groups instead of Authentik's managed profile mapping, access policy "member of `paddock.<slug>` and not of `.locked`") (M3a decision 5).
- Portal pages *Users* (create local users with the one-time recovery link and its copy button, lock and unlock with typed confirmation, effective sudo profile with the assignment behind every part), *Groups* (local and imported upstream groups, members), *Permission profiles* (profiles, assignments, inline warning for root-equivalent commands) and *Login & privileges* (login settings); the device detail adds the login assignment, the suspension of directory logins in a confirmation dialog, the effective sudo profiles of its users and a notice when the agent is too old for login management (F2, F11, F13, F15, M3a step 5).
- Acceptance gates I1–I4 (Authentik provisioning, lock with token revocation, login and sudo bundles, upstream sync), P1 (effective profile, `visudo` in the compiler container) and P2 (root equivalence) and the portal test E3; `make acceptance` now allows 90 minutes (M3a step 6).
- The agent accepts bundle schema 2 and rejects a bundle with a resource type it does not know as a whole (`bundle.rejected`, reason `unknown_resource_type`) instead of applying it partially (M3b decision 4).
- Device events and audit codes for identity and privileges on the device: `device.login_applied`, `device.login_apply_failed`, `device.user_lock_applied`, `device.logins_suspension_applied`, `device.sudo_apply_failed`, `device.sudo_user_unresolved`, `device.tamper_sudo_group_member`, `device.tamper_sudoers_d_file`, `device.tamper_sudoers_changed` and `device.tamper_protected_file_changed`; their payloads carry user and file names only (M3b decision 5).
- The device detail in the portal and the admin API (`login_status`) show the latest login and sudo report of the agent; the database migration `00010` adds `device_status.login_state` and runs automatically (M3b decision 17).
- The login resource names the Himmelblau release devices install (`login.himmelblau.package_version`), set with `PADDOCK_HIMMELBLAU_VERSION` on `paddock-compiler` (default `4.0.4`); the bundle schema stays 2 (M3b decision 6).
- The `paddock-agent` package ships the `pam-auth-update` profile `paddock-deny` and enables it on installation: `pam_listfile` with `/etc/paddock/login-deny` runs before every other primary module of `common-auth` (`auth requisite`, so it also blocks offline logins and screen unlock) and `common-account` (`account required`); without the file every login works (`onerr=succeed`). `dpkg-reconfigure paddock-agent` enables the profile again after it was removed locally; removing the package removes it. The package now depends on `libpam-modules` and `sudo` (M3b decisions 9 and 16).
- The agent manages logins (it reports bundle schema 2): it installs Himmelblau `login.himmelblau.package_version` from `https://packages.himmelblau-idm.org/stable/<version>/deb/ubuntu<release>/` with the signing key built into the agent (fingerprint `E87F D8D4 63A5 E481 4B9C DBA9 0CC0 D400 2C42 5E03`), writes `/etc/himmelblau/himmelblau.conf` and restarts `himmelblaud` and `himmelblaud-tasks` only when it changed, writes the deny list `/etc/paddock/login-deny` of locked users, locks (or, with `user_lock_session_action: terminate`, ends) the sessions of a newly locked user, ends all directory users' sessions when logins are suspended, and reports a directory user's login once per day (`session.login`); local changes of `himmelblau.conf` and the deny list are reverted at the next drift pass (F2, F15, M3b decisions 6–11).
- The agent manages sudo rights: one file `/etc/sudoers.d/paddock-u-<hash>` per user with an effective profile, written with the user's numeric UID through a `visudo`-checked apply procedure that keeps or restores the previous state on failure, the lecture `/etc/paddock/sudo_lecture`, the quarantine of other files in `/etc/sudoers.d` to `/var/lib/paddock/quarantine/sudoers.d/`, the detection (never the rewrite) of changes of `/etc/sudoers`, and the removal of every member of `sudo`, `admin` and `wheel` that is no break-glass account; users who never logged in on a device get their rights after the first login (F9, F11, A13, M3b decisions 12–15).
- Runbook `docs/operations/device-login.md`: first login with code or QR code on a second device, Hello PIN, what a lock and a login suspension do on a device, break-glass accounts, the sudoers.d allow list and how to restore the `paddock-deny` PAM profile (M3b).
- System gates L1–L5, P3 and P4 on the test VMs with real GDM and GNOME (`make system-test VM=<vm|all> T=TestIdentityGates`); screenshots are kept in `bin/system-evidence/<vm>/`, and `PADDOCK_SYSTEM_KEEP=1` leaves a failed VM running for inspection; the development stack allows Authentik 1000 device authorizations per hour and address instead of 20, because every VM and gate reaches it from the same Docker address (M3b step 5).

### Changed

- The portal navigates through a drawer instead of app bar links, which no longer fit the bar (at 1 920 px *Dead
  man's switch*, *API tokens*, *Change sets*, *Audit log* and sign-out were cut off): the pages are grouped into
  Overview, Devices, Configuration, Security, Inventory, Organization and Platform, shown by role as before. From
  1 280 px the drawer stays open and the menu button of the app bar hides and shows it (remembered per browser); below
  it opens from that button.
  The app bar keeps the logo, the organization name, the attention count and a user menu with language and sign-out.
- **BREAKING:** `paddock-api` needs `PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE`, the public key of the revocation release key that signs `paddock-revoke` packages (`docs/operations/agent-releases.md`); agent releases may carry the package `paddock-revoke` (migration `00021`), and the Paddock autoinstall installs it with the release (M4c step 3).
- The disk recovery endpoints answer 404 `not_found` once a Destroy of the device was issued: its escrow is gone (M4c step 2).
- **BREAKING:** OpenBao needs the Transit key `revocation-signing` (Ed25519, non-exportable), read access to `transit/keys/revocation-signing` for the policies `paddock-api` and `paddock-compiler`, and the new policy and AppRole `paddock-revocation-issuer`; without them creating an enrollment token fails with `upstream_unavailable` and the compiler stops. Run the commands of `docs/operations/openbao.md` §1 for the new key and policies (M4c step 1).
- The portal shows the Paddock symbol in the app bar and the Paddock favicons (light and dark tile by colour scheme, small icon as fallback); the build copies them from `docs/assets/logo/` (M4c step 0b).
- **BREAKING:** `paddock-api` needs the Valkey connection (`PADDOCK_VALKEY_ADDR`, `PADDOCK_VALKEY_PASSWORD_FILE`, as for gateway and worker) to publish enrollment tokens to the device cache; add both to the api role's configuration.
- GDM no longer lists the managed local administrator: the agent writes `/var/lib/AccountsService/users/<local_admin_username>` with `SystemAccount=true` before it creates the account and restores the file (restarting AccountsService) when it is removed or changed; the account still signs in through "Not listed?", on text consoles and over SSH (M4a.1 step 2).
- **BREAKING:** Go module path is `github.com/phischl/paddock-mdm/…` (`pkg`, `server`, `agent`, `test/acceptance`, `test/system`) instead of `github.com/paddock-mdm/paddock/…`; code importing the modules and builds that set `-X github.com/paddock-mdm/paddock/agent/internal/buildinfo.Version` must use the new path (M4a.1 step 1).
- **BREAKING:** `PUT /api/v1/settings/login` requires `notice_text` (M4a step 5).
- **BREAKING:** `paddock-api` requires the credential of the OpenBao AppRole `paddock-escrow-reader` (`PADDOCK_OPENBAO_ESCROW_ROLE_ID_FILE`, `PADDOCK_OPENBAO_ESCROW_SECRET_ID_FILE`), used only to decrypt for a reveal; `PUT /api/v1/settings/login` requires `local_admin_username` and `local_admin_rotation_days` (M4a step 4).
- **BREAKING:** OpenBao needs the Transit key `escrow-wrap` (`type=rsa-4096 exportable=false`), the `paddock-compiler` policy `read` on `transit/keys/escrow-wrap`, and the AppRole `paddock-escrow-reader` (`update` on `transit/decrypt/escrow-wrap`); the RabbitMQ worker user must also read `ingest.escrow`. Production: follow `docs/operations/openbao.md`; development: `make dev-secrets && make up` and restart RabbitMQ (M4a step 3).
- **BREAKING:** `paddock-api` requires `PADDOCK_OIDC_STEPUP_ISSUER` (issuer of the Authentik application `paddock-portal-stepup`, e.g. `https://auth.<domain>/application/o/paddock-portal-stepup/`) and is not ready until it is discovered; assigning a `full` profile or changing a profile to `full` now also needs a step-up, so administrators need an MFA authenticator (M4a step 2).
- **BREAKING:** `paddock-worker` signs device commands and requires the OpenBao AppRole `paddock-worker` (`PADDOCK_OPENBAO_ADDR`, `PADDOCK_OPENBAO_ROLE_ID_FILE`, `PADDOCK_OPENBAO_SECRET_ID_FILE`, policy: `update` on `transit/sign/command-signing`), the Transit key `command-signing`, and the `paddock-compiler` policy needs `read` on `transit/keys/command-signing`; production: follow `docs/operations/openbao.md`, development: `make dev-secrets && make up` (M4a step 1).
- **BREAKING:** RabbitMQ: the relay user may publish to the new exchange `paddock.command` and the worker user may read the queues `command.issued` and `ingest.command_result` (`paddock-server provision rabbitmq` declares them); update the user permissions of production brokers, development regenerates them with `make dev-secrets` (restart RabbitMQ to import them). The database migration `00011` adds the table `device_command` and runs automatically (M4a step 1).
- Authentik accepts 600 device-code logins per hour and client address (Authentik's default is 20), configurable with `PADDOCK_DEVICE_LOGIN_THROTTLE` in `.env`; devices behind one NAT address share the limit, so size it for the busiest address — see `docs/operations/device-login.md` (M3.1 step 2).
- The Authentik service account `paddock-service` may now also view and change brands, to keep the default brand's recovery and device-code flows; the portal blueprint applies the permission automatically (M3.1 step 2).
- Devices derive directory UIDs from the fixed Himmelblau range `idmap_range = 200000-999999999` (Himmelblau's default reaches 2 000 200 000): sudo-rs, the default sudo of Ubuntu 26.04, cannot handle numeric users over 9 digits. The range is fixed and must never change, because a change gives every directory user a new UID on every device; a UID above it still gets no sudo-rs rights and is reported as `device.sudo_apply_failed` "uid exceeds sudo-rs limit" (M3b, answer to question 2).
- **BREAKING:** Agents of this release enforce the login settings of their organization: before updating devices, list every local administrator account in *Login & privileges → break-glass accounts* and every sudoers file it needs (for example `90-<admin>`) in the sudoers.d allow list — other members of `sudo`, `admin` and `wheel` are removed and other files in `/etc/sudoers.d` are quarantined at the first apply (M3b decisions 13 and 15).
- `make acceptance` runs the cases of the exactly-once gate in parallel (`PADDOCK_ACCEPTANCE_PARALLEL`, default 8) and allows 30 minutes again (M3b decision 2).
- **BREAKING:** `paddock-compiler` runs from its own image (Dockerfile target `compiler`, Compose image `paddock-compiler:dev`, base `COMPILER_RUNTIME_IMAGE` = Debian 13 slim with the `sudo` package for `visudo`) and requires `PADDOCK_AUTHENTIK_URL` (Authentik's public URL, the authority of device logins); `PADDOCK_VISUDO` overrides the path `/usr/sbin/visudo`; the database migration `00008` records each bundle's schema version and runs automatically; why and how the image is hardened: `docs/operations/compiler-image.md`. Development stacks: `make up` (M3a step 4).
- **BREAKING:** `paddock-worker` requires `PADDOCK_AUTHENTIK_URL` and `PADDOCK_AUTHENTIK_TOKEN_FILE` (the `paddock-service` token) and must trust the certificate of Authentik's public URL (`SSL_CERT_FILE` in Compose); the database migration `00007` adds the identity tables and runs automatically. Development stacks: `make up` (M3a step 3).
- Organizations in the platform API carry `domains` (M3a decision 1).
- The Authentik service account `paddock-service` may now also manage users, groups and their members, OAuth2 providers, applications, scope mappings, expression policies and their bindings and create recovery links; the portal blueprint applies the permissions automatically (M3a step 2).
- Paddock is built with Go 1.27.1 (was 1.25): `go.work` and every `go.mod` declare `go 1.27.0` and `toolchain go1.27.1`, the build image is `golang:1.27.1-trixie`; an older host Go downloads the toolchain automatically, a host environment with `GOTOOLCHAIN=local` must unset it for `go` commands outside make (M2.2 step 1).
- **BREAKING:** `paddock-api` requires the agent release public key (`PADDOCK_RELEASE_PUBLIC_KEY_FILE`) and the artifact store (`PADDOCK_ARTIFACTS_S3_ENDPOINT`, `PADDOCK_ARTIFACTS_S3_BUCKET`, `PADDOCK_ARTIFACTS_S3_ACCESS_KEY_FILE`, `PADDOCK_ARTIFACTS_S3_SECRET_KEY_FILE`), `paddock-worker` requires `PADDOCK_DB_PLATFORM_URL_FILE`, and `paddock-gateway` reads `PADDOCK_ARTIFACTS_S3_BUCKET`; the database migration `00004` adds the release tables. Development stacks: `make dev-secrets` (creates the development release key) and `make up` (M2b step 4).
- **BREAKING:** device and enrollment token actions are sub-resources: `POST /api/v1/devices/{id}/approve`, `/reject`, `/release-quarantine`, `/retire` and `POST /api/v1/enrollment-tokens/{id}/revoke` replace the `{id}:<action>` paths; API clients must switch to the new paths (M2b step 0).
- **BREAKING:** the control-plane database has the new roles `paddock_worker` and `paddock_compiler`, created when the PostgreSQL volume is initialized, and `paddock-api` requires `PADDOCK_PUBLIC_DEVICE_URL`. Development stacks: `make down V=1`, `make dev-secrets`, `make up`. Existing installations: none (pre-release) (M2a step 3).
- Deleting a device group that an enrollment token still assigns devices to answers 409 `in_use` (M2a step 3).
- **BREAKING:** Authentik group names use `.` instead of `:` (`paddock.<slug>`, `paddock.<slug>.admins`, `.operators`, `.auditors`, `paddock.platform.admins`), so the same names work for portal and device logins; groups with the old names are ignored. Development stacks: `make down V=1`. Existing installations: none (pre-release) (ADR 0007, M0.3 step 1).
- **BREAKING:** `GET /api/v1/device-groups`, `GET /api/v1/audit-events` and `GET /api/platform/v1/organizations` page with `page` and `page_size` (10, 25, 50, 100) instead of `cursor` and `limit`, and return `{items, page, page_size, total, total_capped, sort}` instead of `next_cursor`; `page × page_size` above 10 000 answers 400 `page_out_of_range`. API clients must switch to the new parameters (ADR 0018, M0.2 step 1).
- WORM object keys, `audit_object.day`, daily manifests and object retention are dated by the UTC day on which the audit writer recorded the events instead of their occurrence day; writer transactions are limited to 5 minutes and `paddock-server audit seal` refuses a day before 00:15 UTC of the following day (F7, M0.1 step 2).
- Portal UI library switched from PrimeVue to Vuetify (MIT); PrimeVue 5 requires a commercial license (C8, M0.1 step 4).
- Deleting a device group is confirmed in a modal dialog with the focus on *Cancel*; the portal never uses browser-native confirmation dialogs, and while a dialog is open the page behind it is inert for keyboard and screen reader users (ADR 0018, M0.2 step 4).

### Fixed

- CI: the trivy job saves its vulnerability database cache again (the cache step failed on root-owned files).
- `docs/architecture.md`: five table-of-contents links point to their sections again.
- Two declarative applies (`PUT /api/v1/config`, `paddockctl apply`) in the same organization at the same time could deadlock, and PostgreSQL rolled one back (an audited failure). Applies and dry runs of an organization now run one after another; the second one plans against the first one's result.
- The attention count in the portal navigation is no longer a live region, so screen readers do not announce it on every page change; its label still names the number of open conditions.
- An organization administrator who opens another page while the start page is still deciding stays there instead of being sent to the attention list a moment later.
- Portal lists announce their loading state to assistive technology: the table is marked busy while a request runs and its loading bar is named *Loading results*.
- The dead man's switch counts in ticks from the last accepted time ticket, so every warning appears at its lead time; before, a tick that fell just short of a lead time delayed the warning by a tick, and the last warning could be skipped when its lead time equals one tick (development builds) (M4c gate R6, M5a step 5).
- When the dead man's switch is turned off, the device removes its pending warnings (login screen notice `/etc/issue.d/80-paddock-dms.issue` and the record of warnings shown) as soon as `delete_self_lock` arrives, and shows no further warning while it has no self-lock token, instead of warning again until the bundle with the switch off is applied (M5a step 0b).
- The agent resolves the owner and group of managed files from `/etc/passwd` and `/etc/group` only, never through NSS, where Himmelblau answers for any name; a sudo entry whose name resolves to a local account (UID below 60000) is reported as `device.sudo_user_unresolved` instead of granting that account sudo. `docs/operations/device-login.md` lists how every user decision is made (M5a step 0a).
- The GDM login notice was not shown on devices set up since M4b.1: the agent now adds `system-db:gdm` to the greeter profile `/etc/dconf/profile/gdm` itself (created from the distribution's profile if missing, other lines kept, restored when changed locally) instead of relying on the `himmelblau-qr-greeter` package to create it; no operator action needed, the next check-in repairs affected devices (M4a decision 19, M4c step 8).
- Login setup could leave sshd stopped (Himmelblau restart loop blocked the ssh restart); configuration is now written before the package install (M4b.1 step 6).
- Every `apt-get` and `dpkg` run of the agent is killed with its process group after 15 minutes and reported as `device.login_apply_failed` with `stage` `apt` and `reason` `timeout`; the installation is tried again after a back-off (15 minutes, doubling up to 4 hours), finishing an interrupted installation with `dpkg --configure -a` first, so a hanging package operation no longer blocks the agent (M4b.1 step 6).
- The agent removes only the LUKS keyslots it created: it records the keyslot of the install passphrase (`cryptsetup open --test-passphrase --verbose`) before its first change and the keyslot of each recovery key it enrolls, and removes exactly those by number; it no longer removes every passphrase or recovery keyslot by type. Passphrase and recovery keyslots added by an operator stay and are reported as `device.tamper_keyslot_changed`; such a device is not reported compliant (M4b.1 step 2).
- Locking a user no longer reactivates a user deactivated in Authentik or by its upstream directory: the lock reads the user's activation state first and activates it again only if it was active, and an unlock activates the user only to complete an interrupted lock of a previously active user. The database migration `00018` runs automatically (M4b.1 step 1).
- A device enrolling right after its enrollment token was created no longer gets `401 invalid_token`: `paddock-api` publishes new and revoked tokens to the gateway's cache as soon as they are committed (the worker's cache sync remains the safety net), and `paddockd enroll` retries `invalid_token` three times over 30 s.
- The agent also creates an empty `/etc/paddock/login-deny` on devices without a login resource while the `paddock-deny` PAM profile is enabled, so `pam_listfile` no longer logs at every authentication there; an existing list is left unchanged (M4a step 0c).
- The audit log's event filter in the portal offers every audit code; the list is generated from the server's code registry by `make gen`, and `npm run lint` fails when a code has no English message (M4a step 0b).
- The agent always writes `/etc/paddock/login-deny`, empty when nobody is locked, so `pam_listfile` no longer logs "Couldn't open /etc/paddock/login-deny" at every authentication; without the file every login still works (M3.1 step 3).
- If installing Himmelblau fails on a dependency because the device's other package lists are stale, the agent runs one `apt-get update` of every source and tries again, instead of failing until someone updates the device by hand (M3.1 step 3).
- Creating a local user on a fresh installation no longer fails with 502 because Authentik's default brand has no recovery flow: `paddock-worker` sets the brand's recovery and device-code flows at start and every 10 minutes instead of the blueprints, whose brand condition raced with the creation of the default brand, and `make dev-seed` fails if they are not set within 120 s (M3.1 step 2).
- Sudo rights apply on Ubuntu 26.04, whose default sudo is sudo-rs: the agent detects the implementation behind `/usr/bin/sudo` at every apply, writes the sudoers files in its flavor (sudo-rs does not know the setting `lecture_file`) and checks them with that implementation's `visudo`; the device detail shows the device's sudo implementation (M3b, answer to question 1).
- The agent no longer passes the supervisor's `NOTIFY_SOCKET` to the tools it runs, so systemd stops logging "Got notification message from PID …, but reception only permitted for main PID" for every `systemctl` or `loginctl` call (M3b step 5).
- Auto-stop now also protects the current release: a completed agent rollout halts (audit `agent_rollout.halted` by the worker) when the devices that reported `agent.update_failed` or `agent.rolled_back` within the last 7 days reach the rollout's threshold over the devices that checked in during those 7 days; resuming it makes it the current release again. The migration runs automatically (M2.1 step 1).
- Resuming a halted agent rollout starts its failure count again: failures reported before the resume no longer count, so a resumed rollout is not halted again at once by the failures that halted it; the migration runs automatically (M2.1 step 1).
- The `paddock-server` image builds again after the agent module joined the Go workspace (M2b).
- `make up` (audit bucket bootstrap) no longer fails when the generated audit writer access key starts with `-` (M2b step 0).
- Audit events recorded after their occurrence day was sealed are now covered by the manifest of their recording day (F7, M0.1 step 2).
- `make up` on a fresh stack no longer fails because both Authentik containers populate the shared data volume at the same time (M0 step 10).
- `make dev-seed` right after `make up` no longer fails intermittently: it waits up to 180 s until the Authentik login flow `paddock-admin-login` is executable (M1 step 1).
- `make dev-seed` right after `make up` waits up to 300 s until Authentik reports every Paddock blueprint as applied successfully before it checks the login flow, and names the pending blueprints and their status on timeout (M0.3 step 3).
- The development blueprint `paddock-dev.yaml` no longer ends in status `error` when Authentik re-applies it after the first start (M0.3 step 3).
- `make up` after `make down V=1` no longer leaves `paddock-api` and `paddock-audit-writer` unhealthy: re-initializing OpenBao now also replaces the stored AppRole secret-ids (M1 step 1).
- `fleet-backup` no longer takes its first daily dump before Fleet created its schema: on a fresh installation the
  first dump was an empty database that counted as the day's Fleet backup for 24 hours.
- The gateway reaches N1 (1 000 check-ins/s per replica, p99 < 200 ms): it publishes over 16 broker connections
  instead of one, which handled one publisher confirm at a time and held a gateway at about 800 check-ins/s
  (`docs/operations/capacity.md`). Each gateway replica now opens 16 AMQP connections.
- The worker reaches N2 (5 000 device events/s with 3 replicas): it handles 8 `ingest.event` messages at a time and
  records the events of one message in one transaction instead of one transaction per event. When that transaction
  fails, the events are recorded one by one, so one bad event fails alone.
- Device-supplied strings in audit parameters lose their C0 control characters (except tab, newline and carriage
  return): a NUL character, which PostgreSQL rejects, made the event fail on every delivery until it was
  dead-lettered. A session login of a username with control characters is ignored.
- The restore drill (`make restore-drill`) and the runbook restart OpenBao after the snapshot restore: until it
  restarts, the restored node keeps the temporary seal configuration and refuses the original shares ("invalid key
  size 33"). The drill's full backups use `--start-fast` (`paddock-pgbackrest backup` passes further arguments to
  `pgbackrest backup`) instead of waiting up to 5 minutes for a checkpoint; `make test` restores a snapshot into a
  throwaway OpenBao.
- A full backup taken by hand (the restore drill, `pc run … pgbackrest backup`) no longer runs beside the scheduled
  one of the same database: pgBackRest's lock was in each container's own `/tmp`, and the expire of one backup deleted
  the files of the other's set, which pgBackRest had reported complete. The lock is in the stanza's state volume, a
  backup by hand waits for a running one, and every full backup is read back with `pgbackrest verify` and fails
  when a file is missing or damaged.

### Known limitations

- On devices with sudo-rs (Ubuntu 26.04 by default) the organization's custom sudo lecture text has no effect; users see sudo-rs's default lecture. The device detail shows a note for such devices (M3b); the login notice shows the usage policy before every login on these devices too (M4a step 5).

### Security

- Agent releases are bound to their version and architecture, and devices refuse downgrades: the minisign trusted comment of a `paddockd` signature must be `paddock-agent version=<version> arch=<arch>`; the server refuses other comments at upload (422 `release_signature_mismatch`), and the supervisor installs a binary only as the version and architecture its signed comment names and only if it is newer than the active agent (semantic version precedence), otherwise `device.agent_update_failed` with outcome `signature_invalid` or `downgrade_refused`. **BREAKING:** sign releases with `minisign -S … -t "paddock-agent version=<version> arch=<arch>"` (`make agent-release` does); binaries signed with another comment can no longer be uploaded, see `docs/operations/agent-releases.md` (M4b.1 step 4).
- Escrowed secrets (local administrator passwords, LUKS recovery keys, LUKS header keys) are decrypted only by the new role `paddock-server serve escrow-reader` (Compose service `paddock-escrow-reader`, reachable from the api alone over the internal network `escrow`), which holds the AppRole `paddock-escrow-reader` and verifies the administrator's step-up ID token itself (signature against Authentik's JWKS, `auth_time` within the step-up window, MFA, `org_admin` of the organization, at most 5 decryptions per token) before it decrypts; code execution in the api no longer decrypts anything. A refusal is audited as `denied` (`step_up_required`). The api keeps the raw step-up ID token in Valkey (`stepup:<jti>`) for the step-up window. **BREAKING:** run the escrow-reader with `PADDOCK_ESCROW_READER_TOKEN_FILE`, `PADDOCK_DB_URL_FILE` (new database role `paddock_escrow_reader`; existing clusters create it before the migration `00019`), the `paddock-escrow-reader` AppRole, Valkey and `PADDOCK_OIDC_STEPUP_ISSUER`; give the api `PADDOCK_ESCROW_READER_URL` and the same `PADDOCK_ESCROW_READER_TOKEN_FILE` and remove `PADDOCK_OPENBAO_ESCROW_ROLE_ID_FILE` and `PADDOCK_OPENBAO_ESCROW_SECRET_ID_FILE` from it; see `docs/operations/escrow-reader.md`. Development stacks: `make dev-secrets` and `make down V=1 up dev-seed` (M4b.1 step 3).
- The compiler image applies Debian security updates at build time (`apt-get upgrade`); the pinned base digest contained fixed HIGH vulnerabilities in OpenSSL and PCRE2.
- Usernames must not start with `-`: creating a local user such as `-x@acme.test` is refused with 400 `invalid_request`, a synced user with such a name gets no sudo entry (audit `device.bundle_entry_omitted`), and the agent passes names to `getent` after `--` and never hands a name starting with `-` to `gpasswd`, which would read it as an option (M4a step 0a).
- Commands of restricted permission profiles are refused (422 `invalid_command`, the detail names the character) when they contain `^`, `$`, `*`, `?`, `[` or `]`: sudo reads them as regular expressions or globs, so `/usr/bin/systemctl ^.*$` would allow every argument; devices refuse such an entry as well, for its user alone, and report `device.sudo_apply_failed` (M3.1 step 1).
- Profiles stored with such a command before this release are marked *invalid* in the portal, and the compiler leaves out the sudo rights of every user they apply to (audit `device.bundle_entry_omitted`) until the command is changed or removed; review the permission profiles after the update (M3.1 step 1).
- `GET /api/v1/upstream-groups` lists only Authentik groups that have at least one member of the organization, and importing any other upstream group answers 404 `not_found`: before, every organization saw the names of all upstream groups (M3b decision 1).
- Device logins through the QR code URL (`/device?code=`) require MFA as well: the device providers use the Paddock authorization flow `paddock-device-authorization` with a mandatory MFA stage, because Authentik otherwise authenticates this path through the brand's default flow (M3a decision 6, ADR 0007 amendment).
- Device tokens carry only the organization's own `paddock.<slug>…` groups in the `groups` claim: the device providers use a Paddock profile mapping instead of Authentik's managed `profile` mapping, which emits all groups of a user, including non-Paddock groups and groups of other organizations (M3a decision 5, ADR 0007 amendment).
- Commands of restricted permission profiles are refused (422 `invalid_command`) when they contain `ALL`, `!`, `#` or the sudoers separators `,`, `:`, `=`, `\`: a `#` after a space starts a sudoers comment, so `/usr/bin/x #y, /usr/bin/z` would grant `/usr/bin/x` with any arguments (M3a decision 12).
- The agent, server and test modules require `golang.org/x/crypto` v0.57.0, which fixes GO-2026-6354 and GO-2026-6355, together with the newest goose, oauth2, sqlc and govulncheck; `make lint` runs `govulncheck` for every package of every module, including the server's test support, without exclusions (M2.2 step 1).
- The agent module requires `golang.org/x/crypto` v0.55.0 (was v0.13.0), so agent builds outside the Go workspace no longer use the outdated version, and `make lint` runs `govulncheck` for every Go module, failing on vulnerabilities in reachable code (M2.1 step 2).
- Organization data is isolated by PostgreSQL row-level security that fails closed without an organization context; platform endpoints use a separate database role, and cross-organization access returns 404 (F10, M0 steps 4, 9).
- The portal uses a backend-for-frontend session: tokens stay on the server, the browser only holds an encrypted, `HttpOnly`, `SameSite=Strict` session cookie (F8, M0 step 7).
- The portal is served with a strict Content Security Policy without `'unsafe-inline'`, with `frame-ancestors 'none'` and no third-party origins (C7, M0 step 8).
- Portal CSP now uses a per-response style nonce: `index.html` is served with `Cache-Control: no-store` and a fresh nonce in its `style-src` directive, still without `'unsafe-inline'` (C7, M0.1 step 4).
- Go toolchain 1.27.2 (build image `golang:1.27.2-trixie`, CI, every module): fixes GO-2026-6617 (HTTP/2 server crash
  through an HPACK encoder race) and GO-2026-6613 (HTTP/1 connection desynchronization after a 2xx CONNECT response)
  in `net/http`, which every Paddock binary uses; `golang.org/x/net` v0.60.0 in the server fixes the HTTP/2 issues
  GO-2026-6617, GO-2026-6612, GO-2026-6611, GO-2026-6610 and GO-2026-6603 of its copy.

[Unreleased]: https://github.com/phischl/paddock-mdm/compare/v0.1.0-alpha.6...HEAD
[0.1.0-alpha.6]: https://github.com/phischl/paddock-mdm/releases/tag/v0.1.0-alpha.6
[0.1.0-alpha.5]: https://github.com/phischl/paddock-mdm/releases/tag/v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/phischl/paddock-mdm/releases/tag/v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/phischl/paddock-mdm/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/phischl/paddock-mdm/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/phischl/paddock-mdm/tree/1ab53f4499a354981a06240627ea97a15d9bdc54

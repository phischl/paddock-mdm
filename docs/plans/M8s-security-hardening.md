# Implementierungsplan: M8s — Security hardening (step-up on the effective class, path tiers, revocable sessions, limits, container hardening)

Status: Ready for implementation · 2026-10-16 · Author: architect
Basis: ADR 0034 (step-up on the effective class, path tiers, API tokens, sessions, WebAuthn-only step-up, review of
existing data); ADR 0013 (version compatibility); ADR 0018 (lists and dialogs); plan M4a decisions 6–7 (step-up);
plan M2a decision 8 (file path policy); plan M4b decision 10 (header escrow); plan M6c decisions 7–9 (API tokens);
plan M7a (edge); plan M7b/M8a (bundle smoke tests); application hardening review of 2026-10-15 and its follow-up
answers of 2026-10-16.

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

Public repository: every commit, pull request, CHANGELOG line and document of this milestone describes the changes as
hardening and policy decisions. None of them describes an attack, a bypass or a recipe. §13 states the CHANGELOG
rule.

## 1. Goal

After M8s an organization administrator with a fresh step-up is the only principal that can hand out root-equivalent
sudo rights or place files on root-equivalent paths; a portal session ends when the administrator logs out, loses the
role or is deactivated, and a platform administrator can end every session at once; a device cannot store an object
larger than it announced; the edge and the api bound every request body and every connection; the Paddock
containers run without capabilities and cannot gain privileges; the step-up accepts WebAuthn only.

## 2. Context (verified in the code on 2026-10-16, `main` at `c4e528f`)

- **Step-up on the label.** `server/internal/app/privileges.go`: `UpdateProfile` (line 171) and `CreateAssignment`
  (line 290) call `rec.RequireStepUp()` only when `Class == full`; `CreateProfile` and `UpdateAssignmentScope` never
  do. `server/internal/app/declarative_exec.go` repeats the label rule at lines 188 and 305. The domain computes the
  effective class in `server/internal/domain/privilege/privilege.go` (`Effective`, `ReportedClass = ClassFull` when
  `Class == restricted && RootEquivalent`, lines 325–333) and the use cases record `root_equivalent` as an audit
  parameter (`profileParams`, line 97) without enforcing it.
- **Path policy.** `pkg/policy/policy.go`: `ValidatePath` admits everything below `/etc/`, `/usr/local/etc/`, `/opt/`
  except `protectedFiles`, `protectedDirs` and `protectedPrefixes` (lines 22–38). The server calls it in
  `app.validateFile` (`managedconfig.go`) and in the declarative path; the agent in
  `agent/internal/reconcile/file.go::spec` (defence in depth). `agent/internal/reconcile/file.go::Remove` deletes a
  recorded, unchanged file that left the bundle; `agent/internal/apply/apply.go::removeStale` calls it. Managed files
  need `RolesWrite` (`SpecManagedFileCreate/Update`, `managedconfig.go:32-33`) and no step-up.
- **API tokens.** `server/internal/app/apitokens.go::Authenticate` (line 205) builds the principal without `StepUpAt`;
  `ActionRunner.checkStepUp` (`action.go:229`) therefore already answers `step_up_required` for tokens on
  step-up-gated actions, with the generic detail.
- **Sessions.** `server/internal/transport/http/admin/session.go`: the cookie is the whole session (AES-GCM, `V: 1`,
  8 h absolute, 30 min idle). `server.go::session` (line 213) opens and validates the cookie and never consults a
  store; `bff.go::logout` only clears the cookie; `stepup.go::checkStepUp` (line 205) checks `sub`, `auth_time` and
  `amr`, not the groups. `admin_account.role` is written only at login (`accounts.go::Login`,
  `queries/accounts.sql::UpsertAdminAccount`). The api already holds a Valkey client (`cmd/paddock-server/api.go:126`,
  `stepupproof.NewStore(vk)`); so does the worker (`worker.go:81`). Valkey runs with `appendonly yes` and no
  `maxmemory` (`deploy/compose/valkey/valkey.conf`): records survive a restart and are never evicted.
- **Step-up provider.** `deploy/compose/authentik/blueprints/paddock-stepup.yaml`: validation stage with
  `device_classes: [webauthn, totp]` (line 52); provider property mappings `openid` and `profile` only (lines
  105–107); the Paddock `groups` mapping (`io.paddock/scope-groups`) is defined in `paddock-portal.yaml`. The OIDC
  client requests the scopes `openid profile email groups` for both providers (`bff.go::discoverOnce`). The
  development stack mounts `deploy/compose/authentik/dev/paddock-dev.yaml` (`compose.dev.yaml:61`), which already
  skips a stage with an always-false policy bound to a flow stage binding.
- **Escrow uploads.** `server/internal/platform/objectstore/objectstore.go::PresignPut` (line 251) signs bucket and
  key only; `server/internal/transport/http/device/escrow.go` validates `size ≤ 32 MiB` (line 107) and calls
  `PresignPut(ctx, key, HeaderUploadTTL)`; `server/internal/app/escrow.go::check` (line 235) reads the whole object
  with `GetIfExists` before comparing size and SHA-256. The agent uploads with `bytes.NewReader` (`client.go:171`),
  so Go sends `Content-Length`. No Caddyfile has a `request_body` directive.
- **Body limits and timeouts.** `admin/server.go::limitConfigBody` bounds only `PUT /api/v1/config`; the artifact
  uploads use `io.LimitReader` (`handlers_releases.go:66,78`, `agentrelease.MaxArtifactBytes = 128 MiB`). The
  `http.Server` of api, gateway and escrow-reader sets `ReadHeaderTimeout` and `IdleTimeout` only
  (`cmd/paddock-server/api.go:202`, `gateway.go:55`, `escrowreader.go:55`).
- **Containers.** `deploy/compose/compose.yaml` `x-paddock` anchor (lines 5–16): `read_only`, `tmpfs`, healthcheck;
  no `cap_drop`, `security_opt` or `pids_limit` anywhere except `openbao: cap_add: [IPC_LOCK]`.
  `compose.audit.yaml` has its own anchor `&paddock-audit` (line 49). Caddy runs as root; production publishes
  80 and 443 (`compose.prod.yaml:16-19`). `server/internal/prodcheck` parses `docker compose config --format json`
  into `Config.Services` (`Service` has no capability fields yet). `deploy/bundle/ci/smoke.sh` step 8 probes the
  hosts through Caddy on 443.
- **Tests and tooling.** Acceptance helpers: `login`, `tempUser`, `steppedUpTempUser` (temp Authentik user with a
  TOTP authenticator), `stepUp`, `expectOneEvent`, `tokenPortal`, `createAPIToken`, `env.Authentik.SetActive`,
  `RemoveFromGroup`, `Blueprint`; dev users `env.Alice`/`env.Dave` (acme admins), `env.Bob` (acme auditor),
  `env.Carol` (globex admin), `env.PlatformAdmin`; the dev worker syncs identities every 60 s
  (`compose.dev.yaml:138`). `TestOpenAPISpec` requires every privileged route in `privileged` and every
  `x-paddock-audit` code in the registry. `make gen` regenerates sqlc, oapi-codegen, the TypeScript types and
  `docs/compliance/audit-codes.md`. Migrations: next number `00045`. Problem codes: `server/internal/problem/problem.go`.

## 3. Binding decisions

### 3.1 Step-up on the effective class (SEC-1a)

1. `server/internal/domain/privilege` MUST gain, in `privilege.go`:

   ```go
   // EffectiveClass is the class a profile grants in effect: full for class full and for a restricted profile with a
   // root-equivalent command (the rule of Effective's ReportedClass applied to one profile, ADR 0034).
   func EffectiveClass(p Profile) Class
   // RequiresStepUp reports whether creating, changing or assigning p needs a step-up: EffectiveClass(p) == ClassFull.
   func RequiresStepUp(p Profile) bool
   ```

   `EffectiveClass` MUST return `ClassFull` for `Class == ClassFull`, `ClassFull` for `Class == ClassRestricted` with
   `len(RootEquivalentCommands(p.Commands)) > 0`, otherwise `p.Class`.
2. `app.Privileges` MUST call `rec.RequireStepUp()`:
   - in `CreateProfile` when `RequiresStepUp(in)`;
   - in `UpdateProfile` when `RequiresStepUp(in)` and at least one of: `!RequiresStepUp(profileOf(cur))`,
     `in.Class != Class(cur.Class)`, `!slices.Equal(in.Commands, NormalizeProfile(profileOf(cur)).Commands)`;
     a rename, a lecture, a password or a timeout change of an effectively Full profile needs no step-up;
   - in `CreateAssignment` and `UpdateAssignmentScope` when `RequiresStepUp(profileOf(profile))`.
   The label-only checks at `privileges.go:171` and `:290` are replaced, not kept beside the new rule.
3. `configExec` (`declarative_exec.go`) MUST apply decision 2 at `profile` (create and update, same conditions, the
   current row from `ex.st.profiles`) and `assignment` (create). The helper is `privilege.RequiresStepUp`; no
   second rule may be written.
4. `profileParams` and `assignmentProfileParams` MUST set `effective_class` (string of `EffectiveClass`) next to
   `root_equivalent`; the registry entries of `permission_profile.created`, `permission_profile.updated`,
   `profile_assignment.created` and `profile_assignment.updated` MUST list `effective_class` after
   `root_equivalent` (§6.4).
5. `ActionRunner.checkStepUp` MUST answer, for a principal with `APITokenID != uuid.Nil`,
   `problem.StepUpRequired.WithDetail("this change needs an interactive administrator: API tokens cannot complete a step-up")`
   before the age check. The outcome stays `denied`, error code `step_up_required` (unchanged).
6. The OpenAPI schema `PermissionProfile` MUST gain `effective_class` (`PrivilegeClass`, required) and
   `root_grant_confirmed_at` (`date-time`, nullable, required; §3.5). `PermissionProfiles.vue` (create dialog) MUST
   handle `step_up_required` like `PermissionProfileDetail.vue` does (`startStepUp('profile-create', 'new', input)`,
   `resumeStepUp` on return) and show the effective class in the list and the detail (message keys
   `privileges.effectiveClass.*`). The confirmation text of the create and edit dialogs MUST say, when the profile
   is effectively Full, that the profile grants root (existing typed confirmation for class Full is reused).

### 3.2 Managed-file path tiers (SEC-1b)

7. `pkg/policy` MUST gain:

   ```go
   // Tier of a managed-file path (ADR 0034 decision 2).
   type Tier string

   const (
       TierOrdinary  Tier = "ordinary"  // RolesWrite, no step-up
       TierSensitive Tier = "sensitive" // org_admin with a step-up
       TierDenied    Tier = "denied"    // refused by server and agent
   )

   // Classify returns the tier of path with mode (four octal digits). A malformed path or mode is ErrPathNotAllowed.
   // The order is: malformed → error; outside the allowed roots → TierDenied; denied catalog → TierDenied;
   // sensitive catalog, a file directly in /etc/, any /etc/<name>.d/ directory, or any execute bit in mode →
   // TierSensitive; otherwise TierOrdinary.
   func Classify(path, mode string) (Tier, error)

   // ValidatePath keeps its signature: it is ErrPathNotAllowed when Classify(path, "0644") is TierDenied or an error.
   func ValidatePath(p string) error
   ```

   The catalog is the one of §6.2, verbatim, as package-level slices `deniedFiles`, `deniedDirs`, `deniedPrefixes`,
   `sensitiveFiles`, `sensitiveDirs`. The `ErrPathNotAllowed` message becomes
   `path must be an absolute, normalized path below /etc/, /usr/local/etc/ or /opt/ and outside the denied paths`.
8. The agent MUST keep calling `policy.ValidatePath` in `reconcile.File.spec` (denied only). `reconcile.File.Remove`
   MUST, when `policy.ValidatePath(path) != nil`, call `f.Managed.Forget(path)` without reading or deleting the
   file and return `ErrDenied`:

   ```go
   // ErrDenied is the message of a removed file resource whose path the policy now denies: the file stays as it is
   // and is no longer managed (ADR 0034 decision 2).
   var ErrDenied = errors.New("left_denied_file")
   ```

   `apply.removeStale` needs no change (an error is reported as `ResourceError{ID, Message}` and the file counts as
   not changed). No bundle schema change.
9. `app.validateFile` MUST return the tier: `func validateFile(f pgstore.ManagedFile) (policy.Tier, error)`;
   `TierDenied` is `problem.PathNotAllowed` with the policy error's text. `CreateFile` and `UpdateFile` MUST, when
   the tier of the new definition is `TierSensitive`, or when the old definition's tier was `TierSensitive` and any
   field changes, call `requireSensitiveFile(ctx, rec)`:

   ```go
   // requireSensitiveFile is the rule of ADR 0034 decision 2 for tier-S paths: an organization administrator with a
   // fresh step-up. Any other role is problem.Forbidden (recorded as denied).
   func requireSensitiveFile(ctx context.Context, rec Recorder) error
   ```

   with `problem.Forbidden.WithDetail("files on sensitive paths need an organization administrator")` for a
   principal whose `Role != principal.RoleOrgAdmin` (system principals pass), then `rec.RequireStepUp()`.
   `DeleteFile` keeps `RolesWrite` without step-up. `recordFile` MUST set `tier`. `configExec.file` MUST apply the
   same rule (`ex.requireAdmin("may manage files on sensitive paths")`, then `ex.requireStepUp()`).
10. `app.LoadManagedDefinitions` MUST leave every file whose `Classify(path, mode)` is `TierDenied` out of
    `ManagedDefinitions.Files` and collect it in a new field `Denied []pgstore.ManagedFile`. The compiler and
    `Devices.EffectiveConfig` therefore never ship or show a denied file. Managed units are unchanged.
11. The OpenAPI schema `ManagedFile` MUST gain `tier` (enum `ordinary|sensitive|denied`, required) and
    `sensitive_confirmed_at` (`date-time`, nullable, required; §3.5). `ManagedFileCreate.path` keeps 422
    `path_not_allowed` for denied paths; the description names the three tiers and the role rule.
    `ManagedFiles.vue` MUST handle `step_up_required` on create and update (`startStepUp('managed-file-create'|
    'managed-file-edit', …)`), show the tier as a chip (`managedFiles.tier.*`) and explain a 403 `forbidden` with
    the problem detail inline (existing alert pattern).


### 3.2a Amendment 2026-10-16 — operator roots (ADR 0034 amendment of the same date)

Supersedes the *TierOrdinary* rule of decision 7 and the role rule of decision 9 where they conflict.

7a. `policy.Classify` MUST become `Classify(path, mode string, operatorRoots []string) (Tier, error)` with the order:
    malformed → error; outside the allowed roots → denied; denied catalog → denied; sensitive catalog → sensitive;
    not below any of `operatorRoots` → sensitive; below an operator root but with an execute bit, a suffix of
    `.so`, `.so.*`, `.py`, `.pth`, `.sh`, `.pl`, `.rb`, `.lua`, `.js`, or any path component ending in `.d` →
    sensitive; otherwise ordinary. `ValidatePath` (agent, denied only) is unchanged.
7b. `policy.ValidateOperatorRoot(root string) error` MUST refuse: a root not of the form `/etc/<name>/…`,
    `/usr/local/etc/<name>/…` or `/opt/<name>/…` (trailing slash, normalized); a root that is, contains or lies below
    a denied or sensitive catalog entry; and the never-operator prefixes `/etc/apt/`, `/etc/dpkg/`, `/etc/dnf/`,
    `/etc/yum*`, `/etc/pacman*`, `/etc/default/`, `/etc/grub*`, `/etc/python*`, `/etc/perl*`, `/etc/ruby*`,
    `/etc/zsh/`, `/etc/fish/`, `/etc/bash*`, `/etc/profile*`, `/etc/lightdm/`, `/etc/gdm*`, `/etc/sddm*`,
    `/etc/xdg/`, `/etc/X11/`, `/etc/audit/`, `/etc/selinux/`, `/etc/apparmor*`, `/etc/firewalld/`, `/etc/nftables*`,
    `/etc/iptables/`, `/etc/ufw/`, `/etc/NetworkManager/`, `/etc/ssl/`, `/etc/ca-certificates*`, `/etc/pki/`,
    `/etc/ssh/`, `/etc/pam.d/`, `/etc/security/`, `/etc/himmelblau/`, `/etc/sudoers*`, `/etc/systemd/`, `/etc/cron*`,
    `/etc/polkit-1/`, `/etc/dbus-1/`, `/etc/udev/`, `/etc/modprobe.d/`, `/etc/sysctl*`, `/etc/paddock/`, `/opt/paddock/`.
7c. Operator roots are an organization setting `managed_file_operator_roots text[] NOT NULL DEFAULT '{}'` (in the
    PDK-169 migration 00045 if it is not yet merged, else the next free number), exposed as
    `GET|PUT /api/v1/settings/managed-files` (`{operator_roots: []}`), `PUT` for `org_admin` with step-up, refused
    for API tokens (`step_up_required`, token detail), audited as `settings.managed_files_changed` with the old and
    new list (add the code to the registry). The declarative document gains the same section with the same rule.
    The portal settings page shows the list with the step-up dialog.
7d. `app.validateFile` and the declarative path MUST classify with the organization's roots. A change to the roots
    never re-classifies existing definitions by itself; the review (§3.5) lists definitions whose tier rose.
7e. Fuzz target: `FuzzClassify` MUST assert properties, not re-implement the function: denied is never returned for
    a path the agent's `ValidatePath` accepts and vice versa; ordinary is never returned for a path outside every
    operator root; ordinary is never returned with an execute bit.
7f. Documents: `install.md` and `upgrade.md` state the binding order "agents first, then the server" for M8s;
    RR-36 and the ADR 0013 note say the same.
7h-bis. (Architect decision 2026-10-16.) Type-wide systemd drop-ins apply to every unit of their type, Paddock's own
    units included, and are therefore **denied**: `/etc/systemd/system/<type>.d/` for `service`, `socket`, `timer`,
    `path`, `mount`, `automount`, `swap`, `target`, `slice` and `scope` join `deniedDirs`; the same directories below
    `/usr/local/lib/systemd/system/` lie outside the allowed roots and are denied already. The agent's `ValidatePath`
    refuses them too (defence in depth).
7h-ter. (Architect decision 2026-10-16.) Denied also covers `/etc/systemd/system.control/` and
    `/etc/systemd/system.attached/`; the never-operator list is extended by `/etc/dhcp/`, `/etc/openvpn/`,
    `/etc/netplan/`, `/etc/wpa_supplicant/`, `/etc/sssd/`, `/etc/samba/`, `/etc/ldap/`, `/etc/openldap/`,
    `/etc/audisp/`, `/etc/skel/`, `/etc/csh*`, `/etc/tcsh*`, `/etc/ksh*` and `/etc/php*`; the code suffixes are
    extended by `.pm`, `.php`, `.bash`, `.zsh`, `.mjs` and `.cjs`. Every `/etc/` entry of the never-operator list
    applies below `/usr/local/etc/` as well (one rule, no duplicated entries). Fix round 3 adds `/etc/sysconfig/`,
    `/etc/docker/` and `/etc/containers/` to the never-operator list and `.pyc` and `.jar` to the code suffixes.


### 3.2b Amendment 2026-10-16 — root equivalence over the combination of grants

Supersedes the per-profile reading of decisions 1–3.

7g. The step-up rule applies to the **effect** of a change, not to one profile. A change MUST require an
    organization administrator with a fresh step-up (and is refused for API tokens) when, for any subject it
    affects, the effective root-equivalent command set (`privilege.Effective` over all assignments that apply to
    that subject and device group) after the change contains a command or a writer/exec pair that it did not
    contain before. Affected subjects are: for a profile create/update, every subject of every assignment of that
    profile; for an assignment create/re-scope, the subjects and device groups of that assignment; for a change of
    Paddock-managed user-group or device-group membership, the member being added and every assignment that targets
    the group.
7h. `privilege.RootEquivalentCommands` MUST be evaluated over the merged command list of a subject, so a writer in
    one profile and the executed target in another count as a pair.
7i. Membership that arrives from an upstream directory (identity sync, system principal) is not gated; it is
    audited as today and listed by the review (§3.5). RR-35 states this.
7j. Profiles, assignments and group rows that a gated change reads MUST be read `FOR UPDATE` (profiles) or
    `FOR SHARE` (assignments, memberships) inside the same transaction, so a concurrent demotion cannot be
    overwritten by a stale write.
7k. Acceptance: two profiles that are each restricted but combine into root, assigned by an operator or a token →
    403; by an admin without step-up → `step_up_required`; with step-up → success and `effective_class: full` in
    the audit params. Adding a user to a Paddock group that carries such a combination follows the same rule.
7g-bis. (Architect decision 2026-10-16.) Growth is evaluated for devices in every state ~~and for empty and global group
    subjects through a synthetic member~~ (superseded by 7g-quater); approve, quarantine release and enrolment take the
    guard and the advisory lock.
7g-ter. (Architect decision 2026-10-16.) Enrollment tokens are gated at creation and whenever their device groups
    change: when a synthetic device in the token's device groups gives any subject root it does not have elsewhere,
    the token needs an organization administrator with a fresh step-up (operators forbidden, API tokens refused with
    the token detail). Approval keeps its own guard (devices enrolled before this release, manual group changes); for
    tokens that approve automatically the creation gate is the binding one. Acceptance: a token into the device group
    of a combination is refused without a step-up and created with one.
7g-quater. (Architect decision 2026-10-16; supersedes the synthetic subjects of 7g-bis.) **Witnesses:** the root
    witnesses of a command set are every root-equivalent command, every writer/exec pair and `ALL` for class Full
    (the rules of `RootEquivalentCommands`, as a set). **Profile and assignment changes** (create, update, re-scope,
    declarative documents, enrollment-token device groups): the witnesses of the union of the commands of all
    profiles with at least one assignment in the organization, before and after the change; any new witness requires
    an organization administrator with a step-up (operators and tokens refused as before). This over-approximates
    and does not depend on membership or device state. For an enrollment token the union of the profiles assigned to
    everyone or to one of its device groups is compared with the union of those assigned to everyone. **Membership
    and device changes** (Paddock group membership, device groups, approval, quarantine release): the exact check per
    real subject, comparing witness sets instead of classes; a subject gaining any new witness is growth, also when
    it already had Full. **Identity sync** stays ungated, audited and listed by the review. **Performance:** the
    profiles are read into one map per evaluation; the advisory lock is held only for the transaction.

### 3.3 Server-side sessions (SEC-2, part 2 and 4)

12. New package `server/internal/sessions` (no new dependency; `github.com/valkey-io/valkey-go` is already used):

    ```go
    package sessions

    // Record is the server-side half of a portal session (ADR 0034 decision 4).
    type Record struct {
        AccountID uuid.UUID `json:"account_id"`
        Kind      string    `json:"kind"`
        Role      string    `json:"role"`
        Org       uuid.UUID `json:"org"`
        Gen       int64     `json:"gen"`
        CreatedAt int64     `json:"created_at"`
    }

    // ErrUnavailable wraps every Valkey error; the api answers it with 503 session_store_unavailable.
    var ErrUnavailable = errors.New("sessions: store unavailable")

    type Store struct{ c valkey.Client }

    func NewStore(c valkey.Client) *Store
    // NewID returns 32 random bytes, base64url without padding.
    func NewID() string
    // Create writes sess:<sid> (JSON, PX ttl) and adds sid to acct-sess:<account_id> (EXPIRE ttl); Gen is read from
    // sess-gen (missing = 0) inside the same call.
    func (s *Store) Create(ctx context.Context, sid string, rec Record, ttl time.Duration) (Record, error)
    // Get returns the record and the current generation (MGET sess:<sid> sess-gen); found is false for a missing key.
    func (s *Store) Get(ctx context.Context, sid string) (rec Record, gen int64, found bool, err error)
    // Touch extends the TTL of sess:<sid> and acct-sess:<account_id> to ttl (session re-issue).
    func (s *Store) Touch(ctx context.Context, sid string, accountID uuid.UUID, ttl time.Duration) error
    // Delete removes sess:<sid> and the set member.
    func (s *Store) Delete(ctx context.Context, sid string, accountID uuid.UUID) error
    // RevokeAccount deletes every session of the account and returns how many existed.
    func (s *Store) RevokeAccount(ctx context.Context, accountID uuid.UUID) (int, error)
    // EndAll increments sess-gen and returns the new generation; every record with a lower Gen is invalid.
    func (s *Store) EndAll(ctx context.Context) (int64, error)
    ```

    Keys: `sess:<sid>`, `acct-sess:<account_id>` (a SET), `sess-gen` (an integer). `EndAll` MUST NOT scan keys.
13. `admin.Session` MUST change to `V: 2` with a new field `SID string json:"sid"`; `Validate` MUST refuse
    `V != 2` and an empty `SID` (every pre-M8s cookie is invalid after the upgrade; administrators sign in again).
    `NewSession` takes the sid. `principal.Principal` MUST gain `SessionID string` (empty for tokens and system);
    `Session.Principal` sets it.
14. `server.session` MUST, after `Validate`: call `Store.Get`; on `ErrUnavailable` answer
    `problem.SessionStoreUnavailable` (new, `code: session_store_unavailable`, status 503, §6.4) **without**
    clearing the cookie; when not found, or `rec.Gen < gen`, or `rec.AccountID != sess.PID`, or
    `rec.Role != sess.Role`, or `rec.Org != sess.Org`: clear the cookie and answer 401 `unauthenticated`; on a
    cookie re-issue also `Touch`. API token requests (`bearerSecret`) do not touch the store.
15. `bff.callback` MUST `Create` the record (ttl `SessionAbsolute`) before it seals the cookie; a store error is
    logged and the login is denied with `login_failed`. `stepUpCallback` keeps the sid (it re-seals `st.Session`).
    `bff.logout` MUST `Delete` the record of the principal's `SessionID` before it clears the cookie; a store error
    still clears the cookie and answers 200 (the record expires on its own). Logout stays unaudited.
16. **End all sessions.** `POST /api/platform/v1/sessions/end-all` (tag `platform`, `x-paddock-audit:
    platform.sessions_ended`, 200 `{generation: integer}`, 403 `step_up_required`|`forbidden`, 503
    `session_store_unavailable`) runs `ActionSpec{Code: CodePlatformSessionsEnded, AllowedRoles: RolesPlatform,
    RequiresStepUp: true}` through `runner.RunTx(ScopePlatform, …)` and calls `Store.EndAll` inside the callback;
    the caller's own session ends with the next request. The route is added to `privileged`. The CLI
    `paddock-server admin end-sessions` MUST do the same with the system principal (usage line added to
    `parseAdmin`), for the case that the portal is not usable. The portal gets the view `PlatformSessions.vue` at
    `/platform/sessions` (platform administrators only, navigation entry next to the IP allow list) with one button
    `End all sessions` behind `ConfirmDialog` with typed confirmation `END` and the step-up handling of
    `IpAllowlist.vue`.
17. `admin.sessions_revoked` (§6.4) is the one audit code for every server-initiated revocation; `reason` is one of
    `step_up_role_mismatch`, `role_changed`, `deactivated`, `removed`. The api's readiness (`healthcheck`) is
    unchanged: Valkey was already a dependency of the api.

### 3.4 Role at the step-up and account reconciliation (SEC-2, part 1)

18. `ResolveRole` and `RoleResolution` MUST move from `server/internal/transport/http/admin/role.go` to
    `server/internal/domain/organization/role.go` (package `organization`, same code, same tests); the transport
    imports it. The move is a pure relocation.
19. `paddock-stepup.yaml` MUST add the Paddock groups mapping to the provider's `property_mappings`:
    `- !Find [authentik_providers_oauth2.scopemapping, [managed, io.paddock/scope-groups]]` (after the `profile`
    entry). `stepUpClaims` MUST gain `Groups []string json:"groups"`.
20. `stepUpCallback` MUST, after `checkStepUp`, resolve `res := organization.ResolveRole(claims.Groups)` and
    refuse the step-up (log, `stepUpFailed`) when `claims.Groups == nil`, or `res.Denied`, or
    `res.Platform != (sess.Kind == platform_admin)`, or (organization session) `res.Role != Role(sess.Role)` or
    `ResolveSlug(res.Slug) != sess.Org`. On a refusal of an organization session the handler MUST call
    `Accounts.StepUpMismatch(ctx, sess.PID, sess.Org, res)`:

    ```go
    // StepUpMismatch records admin.sessions_revoked (reason step_up_role_mismatch, actor system, target the account),
    // writes the resolved role to admin_account.role when res names the same organization, sets disabled_at = now()
    // when res grants no role in it, and revokes every session of the account (ADR 0034 decision 5).
    func (a *Accounts) StepUpMismatch(ctx context.Context, accountID, orgID uuid.UUID, res organization.RoleResolution) error
    ```

    `Accounts` gains a `sessions *sessions.Store` constructor argument. The platform-admin case only refuses.
21. Migration `00046_admin_account_disabled.sql`: `ALTER TABLE admin_account ADD COLUMN disabled_at timestamptz;`.
    `UpsertAdminAccount` MUST set `disabled_at = NULL` on a successful login. `server.session` MUST NOT read the
    table (the record is the gate); the escrow-reader's check (`escrowreader/service.go:129`) MUST additionally
    refuse `admin.DisabledAt.Valid`.
22. Worker round `admin-accounts` (`worker.Identity.RunAdminAccounts`, every `syncEvery`, lock key
    `identityAdminAccountsLockKey`, same `Round` pattern as `RunSync`): per organization, the use case
    `app.AdminAccounts.Reconcile(ctx)`:
    - loads `ListAdminAccounts` (new query, all rows of the organization, `disabled_at IS NULL`);
    - calls `ports.UserDirectory.RoleGroupUsers(ctx, name)` for the three role groups of the organization
      (`organization.RoleGroup(slug, admins|operators|auditors)`), each returning `[]ports.IdentityUser` with the new
      field `Active bool`; the adapter implements it with `groups_by_name` and `include_groups=false` like
      `OrganizationUsers`;
    - for every account: `groups` = the names of the role groups that contain `account.username`;
      `res := organization.ResolveRole(groups)`; `active` = the user is in at least one of the lists and `Active`;
    - when `!active` or `res.Denied` or `res.Role == ""`: set `disabled_at = now()`, revoke sessions, record
      `admin.sessions_revoked` with reason `deactivated` (user present but inactive) or `removed` (user in no role
      group); when `res.Role != account.Role`: update `role`, revoke sessions, record with reason `role_changed`,
      `old_role`, `new_role`. One audit event per changed account, none for unchanged accounts.
    A user that the directory does not list at all counts as `removed`. The round MUST NOT call Authentik per
    account (three list calls per organization).
23. Coordination with M8b (ADR 0030, role-group membership diffs `admin.role_granted/revoked`): the M8b job MAY
    reuse `RoleGroupUsers`; M8s does not emit M8b's codes. If M8b's job lands first, PDK-173 extends it instead of
    adding a second round (stop condition S6).

### 3.5 Review of existing data (SEC-1, "no forced re-confirmation")

24. Migration `00045_security_review.sql`:

    ```sql
    ALTER TABLE permission_profile
      ADD COLUMN root_grant_confirmed_at timestamptz,
      ADD COLUMN root_grant_confirmed_by uuid REFERENCES admin_account(id) ON DELETE SET NULL;
    ALTER TABLE managed_file
      ADD COLUMN sensitive_confirmed_at timestamptz,
      ADD COLUMN sensitive_confirmed_by uuid REFERENCES admin_account(id) ON DELETE SET NULL;
    ```

    No backfill. `Insert/UpdatePermissionProfile` and `Insert/UpdateManagedFile` gain the two columns as parameters;
    the use cases set them to `now()` and the principal's `ID` when the action called `RequireStepUp` successfully
    and the row is effectively Full (profiles) or tier S (files); an update that makes a profile not effectively
    Full, or a file ordinary, sets them to NULL. API-token principals never get here (decision 5).
25. `GET /api/v1/security-review` (tag `overview`, roles `RolesRead`, no list contract: it is one review object
    like `GET /api/v1/overview`, each array capped at 100 with `total`):

    ```yaml
    SecurityReview:
      required: [generated_at, root_grants, sensitive_files, denied_files]
      properties:
        generated_at: date-time
        root_grants:     { $ref: SecurityReviewProfiles }  # effectively Full profiles with root_grant_confirmed_at = null
        sensitive_files: { $ref: SecurityReviewFiles }     # tier sensitive with sensitive_confirmed_at = null
        denied_files:    { $ref: SecurityReviewFiles }     # tier denied (not shipped)
    SecurityReviewProfiles: { required: [total, items], items: [{ profile: PermissionProfile, assignments: integer }] }
    SecurityReviewFiles:    { required: [total, items], items: ManagedFile }
    ```

    Ordering: profiles by `name`, files by `path`, then `id`. The tiers are computed in Go from the policy; the
    use case reads `ListPermissionProfilesAll` and `ListAllManagedFiles` (org scope) once.
26. `POST /api/v1/permission-profiles/{id}/confirm-root-grant` (`x-paddock-audit:
    permission_profile.root_grant_confirmed`, 200 `PermissionProfile`, 403 `step_up_required`|`forbidden`, 404,
    409 `invalid_state` when the profile is not effectively Full) and `POST /api/v1/managed-files/{id}/confirm-sensitive`
    (`x-paddock-audit: managed_file.sensitive_confirmed`, 200 `ManagedFile`, 409 `invalid_state` when the file is
    not tier S): `ActionSpec{AllowedRoles: RolesAdmin, RequiresStepUp: true}`; both set the confirmation columns.
    Both routes go into `privileged`.
27. `Overview` MUST gain `security_review: {root_grants: integer, sensitive_files: integer, denied_files: integer}`
    (required). The portal's `Overview.vue` shows a banner (`overview.securityReview.banner`, one line with the three
    counts) linking to the new view `SecurityReview.vue` at `/security-review` (three tables: unconfirmed root
    grants with a `Confirm` button per row, unconfirmed sensitive files with `Confirm`, denied files with a
    `Delete definition` link to the managed-file detail). The confirm buttons use `ConfirmDialog` and the step-up
    handling of `stepUp.ts`; the tables are small (≤ 100 rows, no `DataList`, because the endpoint is not a
    collection). The banner is hidden when all counts are 0.
28. `paddock-server admin security-review` (CLI, system principal, platform pool for the organization list, org
    scope per organization): prints one line per organization `<slug>: root_grants=<n> sensitive_files=<n>
    denied_files=<n>` and records `organization.security_review_required` (§6.4) with the three counts in every
    organization where at least one count is > 0. Idempotent (a second run records again). The release notes tell
    operators to run it once after the upgrade.

### 3.6 Escrow upload bound, edge body limits, api body limit and timeouts (SEC-3, RL-3, IV-3, HT-2)

29. `objectstore.Presigner.PresignPut` MUST become
    `PresignPut(ctx context.Context, key string, size int64, ttl time.Duration) (string, error)` and set
    `ContentLength: &size` on the `PutObjectInput`, so that SigV4 signs `content-length`; `device.escrowUpload`
    passes `msg.Size`; the `Escrow` port in `device/device.go:71` changes accordingly.
30. `app.HeaderObjects` MUST gain `Size(ctx, key) (size int64, found bool, err error)` (HeadObject) and
    `Delete(ctx, key) error`; `objectstore.Store` implements both. `Escrow.check` MUST call `Size` first: not found
    → unchanged; `size != *h.Size` → `Delete` the object, record `device.header_object_rejected` (§6.4, actor the
    device, org scope, params `generation`, `volume`, `declared_size`, `object_size`) and return
    `escrow.StatusFailed`; only then `GetIfExists` and the SHA-256 check as today.
31. Every Caddy site MUST bound request bodies with `request_body { max_size … }`, identically in `Caddyfile`,
    `Caddyfile.prod` and `Caddyfile.lab`, placed as the first directive of the matching `handle`:
    - `(admin_site)` in `guards.caddy`: `request_body @artifacts { max_size 130MiB }` with
      `@artifacts { method PUT; path /api/platform/v1/agent-releases/* }` and `request_body @other { max_size 2MiB }`
      with `@other { not path /api/platform/v1/agent-releases/* }`, both before `reverse_proxy`;
    - `(authentik_site)`: `request_body { max_size 16MiB }` before `reverse_proxy`;
    - `device.`: `request_body { max_size 2MiB }` before `reverse_proxy`;
    - `bundles.`: `@escrow` handle: `request_body { max_size 33MiB }`; `@packages` and `@read`:
      `request_body { max_size 1MiB }`;
    - `fleet.`: `@device` handle: `request_body { max_size 64MiB }`.
    `TestCaddyfilesEdge` MUST assert, per file, that every `reverse_proxy` to `paddock-api`, `paddock-gateway`,
    `rustfs`, `fleet` and `authentik-server` is preceded in its block by a `request_body` directive.
    `deploy/compose/nginx/paddock.conf.example` keeps `client_max_body_size 160m`.
32. `admin.limitConfigBody` MUST become `limitBody`: `PUT /api/v1/config` keeps `MaxDocumentBytes+1`; `PUT` on a
    path with prefix `/api/platform/v1/agent-releases/` gets no `MaxBytesReader` (the handlers keep their
    `LimitReader`); every other request gets `http.MaxBytesReader(w, r.Body, 256<<10+1)`. An exceeded limit stays a
    400 `invalid_request` (audited for privileged routes by `rejected`).
33. The `http.Server` of `api`, `gateway` and `escrow-reader` MUST set `ReadTimeout: 60 * time.Second` and
    `WriteTimeout: 120 * time.Second` next to the existing timeouts. The two artifact upload handlers
    (`UploadAgentReleaseArtifact`, `UploadAgentReleasePackage` in `handlers_releases.go`) MUST extend both deadlines
    to 10 minutes with `http.NewResponseController(w)` (`SetReadDeadline`, `SetWriteDeadline`) before reading the
    body; the strict handler receives `w` through `ctx` as today (`httpx` already exposes the response writer for the
    artifact handlers; if it does not, stop condition S7).

### 3.7 Container hardening (CR-1)

34. `compose.yaml` `x-paddock` anchor and `compose.audit.yaml` `&paddock-audit` anchor MUST gain, verbatim:

    ```yaml
      cap_drop: [ALL]
      security_opt: ["no-new-privileges:true"]
      pids_limit: 256
    ```

    The `caddy` service (`compose.yaml`) MUST gain `cap_drop: [ALL]`, `cap_add: [NET_BIND_SERVICE]`,
    `security_opt: ["no-new-privileges:true"]`, `pids_limit: 256`; `caddy-ca-export` the same without `cap_add`.
    No `read_only` and no `user:` change for any third-party service (step 2 of the review is M12h).
35. Every other service of `compose.yaml`, `compose.audit.yaml`, `compose.backup.yaml`, `compose.audit.prod.yaml`
    and `deploy/bundle/ci/compose.ci.yaml` MUST get `pids_limit` with exactly these values: `postgres`,
    `authentik-postgres`, `audit-postgres`, `rustfs`, `audit-rustfs`, `fleet`, `fleet-mysql`, `authentik-server`:
    512; `rabbitmq`, `authentik-worker`: 1024; `valkey`, `fleet-redis`, `openbao`, `prometheus`,
    `prometheus-audit`, `backup-s3-tls`: 256; `pgbackrest`, `pgbackrest-authentik`, `fleet-backup`,
    `fleet-backup-upload`: 128. Services that other files extend (`postgres` in `compose.backup.yaml`) get the
    value in the base file only. `openbao` keeps `cap_add: [IPC_LOCK]` and gets no `cap_drop` in M8s.
36. `prodcheck.Service` MUST gain `CapAdd []string json:"cap_add"`, `CapDrop []string json:"cap_drop"`,
    `SecurityOpt []string json:"security_opt"`, `PidsLimit int64 json:"pids_limit"`. New item
    `container hardening` (`checkContainerHardening`, appended after `checkTLSLinks` for every host): findings for
    every service whose name starts with `paddock-` or is `caddy`/`caddy-ca-export` without `CapDrop == ["ALL"]` or
    without `no-new-privileges:true` in `SecurityOpt`; for `paddock-*` with a non-empty `CapAdd`; for `caddy` with
    `CapAdd != ["NET_BIND_SERVICE"]`; for any service with `PidsLimit <= 0`. `TestProductionEdge`, `TestLabEdge`
    and the audit-host fixture MUST expect the item to pass; a new fixture with a stripped anchor MUST fail it.
37. `deploy/bundle/ci/smoke.sh` step 8 MUST add, after the existing probes: (a) for every container of both projects
    `docker inspect --format '{{.Name}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}} {{.HostConfig.PidsLimit}}'`
    and fail when a `paddock-*` or `caddy` container lacks `ALL` in `CapDrop` or `no-new-privileges:true` in
    `SecurityOpt`, or any container has `PidsLimit` ≤ 0; (b) `curl -s -o /dev/null -w '%{http_code}' --max-time 10
    http://127.0.0.1:80/` MUST print a three-digit status (the bind to 80 under `NET_BIND_SERVICE` works; the
    status value is not asserted). `smoke-lab.sh` adds (a) only (the lab publishes 8080).

### 3.8 WebAuthn-only step-up (AU-2)

38. `paddock-stepup.yaml` line 52 MUST become `device_classes: [webauthn]`. `paddock-portal.yaml` (login flow)
    keeps `[webauthn, totp]` with `not_configured_action: configure` (login MFA is out of scope).
39. `deploy/compose/authentik/dev/paddock-dev.yaml` MUST add (after the existing `skip-mfa` entries, depending on
    `paddock/paddock-stepup.yaml` through a second `metaapplyblueprint` entry): an expression policy
    `paddock-dev-skip-stepup-webauthn` (`return False`) bound to the flow stage binding of flow `paddock-stepup` at
    order 30 (the `!Find` pattern of the existing binding), and a stage
    `authentik_stages_authenticator_validate.authenticatorvalidatestage` named `paddock-dev-stepup-mfa` with
    `device_classes: [webauthn, totp]`, `not_configured_action: deny`, bound to `paddock-stepup` at order 31. The
    acceptance gates keep their TOTP step-ups unchanged.
40. `server/internal/prodcheck/compose_test.go` MUST gain `TestStepUpBlueprintWebAuthnOnly`: the shipped
    `paddock-stepup.yaml` contains the line `      device_classes: [webauthn]` and does not contain `totp`; the
    development blueprint contains `paddock-dev-stepup-mfa`. The acceptance gate `TestStepUpFactor`
    (`stepup_test.go`) MUST read, through `env.Authentik`, the flow `paddock-stepup`, its stage binding at order 30
    and that stage's `device_classes`, and expect exactly `[webauthn]`; and expect the binding at order 31 to exist
    in the development stack.
41. Migration note (CHANGELOG, `docs/operations/step-up.md`, `docs/operations/install.md` upgrade section): before
    the upgrade every administrator enrols a WebAuthn authenticator in Authentik's user settings
    (`https://auth.<domain>/if/user/`, MFA devices); after the upgrade a TOTP-only administrator cannot complete a
    step-up until a WebAuthn authenticator exists.

### 3.9 Documents (PDK-179, binding content)

- `docs/operations/step-up.md`: the table lists every step-up action after M8s (profile create/update/assign/scope,
  sensitive files create/update, confirm endpoints, end all sessions, the existing ones), the token rule, the
  WebAuthn-only factor and the development TOTP stage.
- `docs/operations/api-tokens.md` and `docs/operations/paddockctl.md` (CI example): the two-step GitOps flow.
- `docs/operations/install.md` (upgrade section) and `docs/operations/escrow-reader.md`: the session store, the
  `security-review` command, the WebAuthn enrolment, `disabled_at`.
- `docs/operations/local-dev.md`: the development step-up stage with TOTP.
- `docs/compliance/residual-risks.md`: **RR-35** "Portal session state in Valkey": sessions end within the worker
  interval (5 min production) after a role change or deactivation in Authentik, immediately after logout, a step-up
  mismatch or `end-all`; the portal is unavailable while Valkey is unreachable; mitigation and operator action.
  **RR-36** "Agents older than M8s and denied paths": such an agent deletes an unchanged managed file that left the
  bundle; mitigation: roll the agent out first, review the denied list before deleting definitions.

## 4. Non-goals

- Valkey ACL users per role (AZ-4), network segmentation (CR-3/4/5), third-party container capabilities and
  `read_only` (CR-2 step 2), resource memory limits (RL-4), the compose hardening lint (CR-8), the application rate
  limiter (RL-1), Authentik reputation policies (AU-3), automated session-key rotation (CK-1), cookie prefixes
  (AU-5), agent path resolution (AG-1): M12h.
- A step-up-bound short-lived token for `paddockctl`; per-token CIDR binding (AU-6).
- Any change to `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation`.
- Bundle schema changes; a new device API version; changes to managed units' policy.
- The login flow's MFA factors; MFA enrolment policy (AU-4).
- M8b, M9, M10, M11 scope (ADRs 0030–0033), including `admin.role_granted/revoked`.
- Removing anything from a device: no file is deleted because of this milestone.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/adr/0034-privilege-step-up-and-sessions.md` | new (done) | decisions |
| `docs/architecture.md` §9.6, `docs/plans/M4a-…md`, `docs/plans/M2a-…md`, `docs/adr/0003`, `0007`, `0013` | amended (done) | pointers to ADR 0034 |
| `server/internal/domain/audit/codes.go`, `docs/compliance/audit-codes.md` (gen), `server/web/src/lib/auditCodes.gen.ts` (gen), `server/web/src/locales/{en,de}.json` | change | §6.4 codes and messages |
| `server/internal/problem/problem.go` | change | `SessionStoreUnavailable` |
| `api/openapi/admin.yaml`, generated Go/TS | change | §6.1 |
| `pkg/policy/policy.go`, `policy_test.go`, new `fuzz_test.go` | change/new | tiers, catalog, fuzz |
| `agent/internal/reconcile/file.go`, `file_test.go` | change | `ErrDenied`, `Remove` |
| `server/internal/domain/privilege/privilege.go`, `_test.go` | change | `EffectiveClass`, `RequiresStepUp` |
| `server/internal/app/privileges.go`, `declarative_exec.go`, `action.go`, `managedconfig.go`, `devices.go` | change | §3.1, §3.2 |
| `server/internal/app/securityreview.go` (new), `accounts.go`, `adminaccounts.go` (new), `sessions.go` (new, end-all use case) | new/change | §3.3–§3.5 |
| `server/internal/sessions/store.go`, `store_test.go` (new) | new | §3.3 |
| `server/internal/principal/principal.go` | change | `SessionID` |
| `server/internal/domain/organization/role.go`, `role_test.go` (moved from transport) | move | §3.4 |
| `server/internal/transport/http/admin/{session,server,bff,stepup}.go`, `handlers_identity.go`, `handlers_managed.go`, `handlers_overview.go`, new `handlers_sessions.go`, `spec_test.go` | change/new | §3.3–§3.5 |
| `server/internal/ports/identity.go`, `server/internal/adapters/authentik/users.go` | change | `RoleGroupUsers`, `IdentityUser.Active` |
| `server/internal/worker/identity.go`, `server/cmd/paddock-server/{worker,api,gateway,escrowreader,admin}.go` | change | rounds, timeouts, CLI |
| `server/internal/adapters/postgres/queries/{accounts,privilege,managed_config,escrow}.sql`, `pgstore` (gen) | change | columns, queries |
| `server/migrations/paddock/00045_security_review.sql`, `00046_admin_account_disabled.sql` | new | §3.5, §3.4 |
| `server/internal/platform/objectstore/objectstore.go`, `server/internal/transport/http/device/{escrow,device}.go`, `server/internal/app/escrow.go` | change | §3.6 |
| `server/internal/escrowreader/service.go` | change | `disabled_at` |
| `deploy/compose/caddy/{Caddyfile,Caddyfile.prod,Caddyfile.lab,guards.caddy}` | change | body limits |
| `deploy/compose/{compose,compose.audit,compose.backup,compose.audit.prod}.yaml`, `deploy/bundle/ci/compose.ci.yaml` | change | §3.7 |
| `server/internal/prodcheck/{prodcheck,compose_test}.go`, testdata fixtures | change | §3.7, §3.8 |
| `deploy/bundle/ci/smoke.sh`, `smoke-lab.sh` | change | §3.7 |
| `deploy/compose/authentik/blueprints/paddock-stepup.yaml`, `deploy/compose/authentik/dev/paddock-dev.yaml` | change | §3.4, §3.8 |
| `server/web/src/views/{PermissionProfiles,PermissionProfileDetail,ManagedFiles,Overview}.vue`, new `SecurityReview.vue`, `PlatformSessions.vue`, router, navigation | change/new | portal |
| `test/acceptance/{stepup,privileges_stepup,managed_file_tiers,api_token_stepup,sessions,escrow_upload_bound,body_limits}_test.go`, `helpers.go` | new/change | §8 gates |
| `docs/operations/{step-up,api-tokens,paddockctl,install,local-dev,escrow-reader}.md`, `docs/compliance/residual-risks.md`, `CHANGELOG.md` | change | §3.9, §13 |

MUST NOT be touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`, `pkg/bundle`
(schema), `api/openapi/device.yaml`, `deploy/compose/compose.prod.yaml`, `deploy/compose/compose.lab.yaml`, `server/migrations/paddock/00001…00044`, `docs/adr/0001…0033`, any file of plans
M8b–M11.

## 6. Interfaces and formats

### 6.1 Admin API additions (`api/openapi/admin.yaml`)

```yaml
# schemas
PermissionProfile: + effective_class (PrivilegeClass, required), root_grant_confirmed_at (date-time, nullable, required)
ManagedFile:       + tier (string enum [ordinary, sensitive, denied], required), sensitive_confirmed_at (date-time, nullable, required)
Overview:          + security_review (OverviewSecurityReview, required) {root_grants, sensitive_files, denied_files: integer}
SecurityReview, SecurityReviewProfiles, SecurityReviewFiles: §3.5 decision 25
SessionsEnded:     {generation: integer, required}

# operations
GET  /api/v1/security-review                              200 SecurityReview · 401 · 403 forbidden
POST /api/v1/permission-profiles/{id}/confirm-root-grant   x-paddock-audit: permission_profile.root_grant_confirmed
                                                           200 PermissionProfile · 403 step_up_required|forbidden|csrf_missing · 404 · 409 invalid_state
POST /api/v1/managed-files/{id}/confirm-sensitive          x-paddock-audit: managed_file.sensitive_confirmed
                                                           200 ManagedFile · 403 … · 404 · 409 invalid_state
POST /api/platform/v1/sessions/end-all                     x-paddock-audit: platform.sessions_ended
                                                           200 SessionsEnded · 403 step_up_required|forbidden · 503 session_store_unavailable
# documented problem codes added to the info description: session_store_unavailable (503, every authenticated
# session request while the session store is unreachable; API tokens are not affected)
```

The `description` of `PermissionProfileCreate`/`Update` and `ProfileAssignmentCreate`/`Update` MUST state: "A
profile that is effectively Full (class full, or restricted with a root-equivalent command) needs a step-up (403
step_up_required); API tokens cannot satisfy it." The `description` of `ManagedFileCreate.path` MUST state the three
tiers and "sensitive paths need the org_admin role (403 forbidden otherwise) and a step-up".

### 6.2 Path catalog (`pkg/policy`, verbatim; trailing `/` = directory and everything below)

Allowed roots (unchanged): `/etc/`, `/usr/local/etc/`, `/opt/`.

**Denied (D)** — `deniedFiles`:
`/etc/sudoers`, `/etc/sudo.conf`, `/etc/sudo_logsrvd.conf`, `/etc/nsswitch.conf`, `/etc/crypttab`, `/etc/fstab`,
`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/default/orbit`, `/etc/default/grub`,
`/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/krb5.conf`, `/etc/login.defs`, `/etc/shells`, `/etc/securetty`,
`/etc/environment`, `/etc/sysctl.conf`, `/etc/systemd/system.conf`.
`deniedDirs`: `/etc/sudoers.d/`, `/etc/pam.d/`, `/etc/security/`, `/etc/himmelblau/`, `/etc/paddock/`,
`/opt/paddock/`, `/etc/apt/`, `/opt/orbit/`, `/etc/ld.so.conf.d/`, `/etc/tmpfiles.d/`, `/etc/dracut.conf.d/`,
`/etc/initramfs-tools/`, `/etc/cryptsetup-initramfs/`, `/etc/kernel/`, `/etc/grub.d/`, `/etc/systemd/system.conf.d/`,
`/etc/systemd/system-generators/`, `/etc/systemd/system-preset/`, `/etc/modprobe.d/`, `/etc/modules-load.d/`,
`/etc/sysctl.d/`, `/etc/apparmor.d/`, `/etc/udev/rules.d/`, `/etc/polkit-1/`.
`deniedPrefixes` (string prefix of the whole path): `/etc/systemd/system/paddock`, `/etc/systemd/system/orbit`,
`/etc/systemd/system/himmelblau`, `/etc/systemd/system/fleet`, `/etc/systemd/system/ssh`,
`/etc/systemd/system/gdm`, `/etc/systemd/system/systemd-`, `/etc/systemd/system/sudo`.

**Sensitive (S)** — `sensitiveFiles`: `/etc/crontab`, `/etc/bash.bashrc`, `/etc/logrotate.conf`.
`sensitiveDirs`: `/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`,
`/etc/cron.monthly/`, `/etc/systemd/`, `/etc/profile.d/`, `/etc/X11/Xsession.d/`, `/etc/xdg/autostart/`,
`/etc/ssh/`, `/etc/NetworkManager/dispatcher.d/`, `/etc/network/`, `/etc/logrotate.d/`.
Rules: a path with exactly one component below `/etc/` (`/etc/<file>`) is S; a path whose first component below
`/etc/` ends in `.d` is S; a mode with any execute bit (`mode[1]`, `mode[2]` or `mode[3]` odd) is S wherever the
path lies (D wins over S; S wins over O).

**Ordinary (O)**: everything else below the allowed roots.

Test vectors (MUST be in `policy_test.go`): D: `/etc/ld.so.preload`, `/etc/tmpfiles.d/x.conf`,
`/etc/systemd/system/sshd.service.d/override.conf`, `/etc/polkit-1/rules.d/10.rules`, `/etc/sudo.conf`,
`/etc/apparmor.d/usr.bin.x`, `/opt/paddock/x`; S: `/etc/cron.d/backup`, `/etc/systemd/system/myapp.service`,
`/etc/profile.d/proxy.sh`, `/etc/ssh/sshd_config.d/10.conf`, `/etc/foo.conf`, `/etc/foo.d/bar.conf`,
`/etc/myapp/hook.sh` with mode `0755`, `/opt/myapp/bin/run` with mode `0750`; O: `/etc/myapp/app.conf` `0644`,
`/usr/local/etc/tool.toml` `0644`, `/opt/myapp/conf/settings.ini` `0640`.
Fuzz target `FuzzClassify(path, mode)` invariants: no panic; a result of O or S never has a `deniedDirs` prefix,
is never in `deniedFiles` and never starts with a `deniedPrefixes` entry; `ValidatePath(p) == nil` ⇔
`Classify(p, "0644") != TierDenied` without error.

### 6.3 Go signatures (new or changed)

```go
// pkg/policy
func Classify(path, mode string) (Tier, error)

// agent/internal/reconcile
var ErrDenied = errors.New("left_denied_file")

// server/internal/domain/privilege
func EffectiveClass(p Profile) Class
func RequiresStepUp(p Profile) bool

// server/internal/domain/organization (moved)
type RoleResolution struct{ Platform bool; Slug string; Role principal.Role; Denied bool; Slugs []string }
func ResolveRole(groups []string) RoleResolution

// server/internal/sessions — §3.3 decision 12

// server/internal/principal
type Principal struct { …; SessionID string }

// server/internal/ports
type IdentityUser struct { PK, Username, Name, Email string; Managed bool; Active bool }
type UserDirectory interface { …; RoleGroupUsers(ctx context.Context, groupName string) ([]IdentityUser, error) }

// server/internal/app
func (a *Accounts) StepUpMismatch(ctx context.Context, accountID, orgID uuid.UUID, res organization.RoleResolution) error
type AdminAccounts struct{ … }; func NewAdminAccounts(runner *ActionRunner, org *db.OrgPool, dir ports.UserDirectory, sessions *sessions.Store) *AdminAccounts
func (s *AdminAccounts) Reconcile(ctx context.Context) error
type Sessions struct{ … }; func NewSessions(runner *ActionRunner, store *sessions.Store) *Sessions
func (s *Sessions) EndAll(ctx context.Context) (int64, error)
type SecurityReview struct{ … }; func NewSecurityReview(org *db.OrgPool) *SecurityReview
func (r *SecurityReview) Get(ctx context.Context) (SecurityReviewResult, error)
func (p *Privileges) ConfirmRootGrant(ctx context.Context, id uuid.UUID) (pgstore.PermissionProfile, error)
func (m *ManagedConfig) ConfirmSensitive(ctx context.Context, id uuid.UUID) (pgstore.ManagedFile, error)
type HeaderObjects interface {
    GetIfExists(ctx context.Context, key string) ([]byte, bool, error)
    Size(ctx context.Context, key string) (int64, bool, error)
    Delete(ctx context.Context, key string) error
}

// server/internal/platform/objectstore
func (p *Presigner) PresignPut(ctx context.Context, key string, size int64, ttl time.Duration) (string, error)
func (s *Store) Size(ctx context.Context, key string) (int64, bool, error)
func (s *Store) Delete(ctx context.Context, key string) error

// server/internal/problem
SessionStoreUnavailable = &Error{Code: "session_store_unavailable", Status: http.StatusServiceUnavailable}
```

### 6.4 Audit codes (closed registry, `codes.go`; descriptions verbatim)

| Code | Description | Params | Outcomes |
| --- | --- | --- | --- |
| `admin.sessions_revoked` | Every portal session of an administrator account was ended by the server because the account's role or state changed (actor: system). | `reason`, `sessions`, `old_role`, `new_role` | success, failure |
| `platform.sessions_ended` | A platform administrator ended every portal session of the installation. | `generation` | success, failure, denied |
| `permission_profile.root_grant_confirmed` | An organization administrator confirmed, with a step-up, a root-equivalent permission profile that existed before the step-up rule covered it. | `name`, `effective_class`, `commands` | success, failure, denied |
| `managed_file.sensitive_confirmed` | An organization administrator confirmed, with a step-up, a managed file on a sensitive path that existed before the path tiers. | `path`, `device_group_id`, `tier` | success, failure, denied |
| `organization.security_review_required` | An operator ran paddock-server admin security-review: the organization has unconfirmed root-equivalent profiles, unconfirmed sensitive files or files on denied paths (actor: system). | `root_grant_profiles`, `sensitive_files`, `denied_files` | success |
| `device.header_object_rejected` | The worker found an escrowed LUKS header object whose size differs from the announced size, deleted it and marked the escrow failed (actor: the device). | `generation`, `volume`, `declared_size`, `object_size` | failure |

Notes: `admin.sessions_revoked.reason` ∈ {`step_up_role_mismatch`, `role_changed`, `deactivated`, `removed`};
`old_role`/`new_role` are empty strings when unchanged or none. Existing entries gain params: `effective_class`
(`permission_profile.created/updated`, `profile_assignment.created/updated`) and `tier`
(`managed_file.created/updated`). Message keys `audit.<code>` in `en.json` and `de.json`; German terms for
"root grant", "sensitive path", "denied path", "session" in `docs/compliance/glossary-de.md`.

### 6.5 Valkey keys

`sess:<sid>` string (JSON `Record`, PX = remaining absolute lifetime) · `acct-sess:<account_id>` set of sids (EXPIRE =
absolute lifetime) · `sess-gen` integer. `paddock-server admin rebuild-cache` MUST NOT touch them.

## 7. Host and operator notes (binding figures for the documents)

- Portal sessions require Valkey; while it is unreachable the portal answers 503 `session_store_unavailable` and
  devices are unaffected. A Valkey restart keeps sessions (AOF). `./paddock down --volumes` ends every session.
- After the upgrade: run `./paddock run paddock-server admin security-review` once (or the equivalent compose
  command the docs name), then review the overview banner per organization.
- Before the upgrade: every administrator enrols a WebAuthn authenticator (decision 41).
- API tokens with the operator role keep working for ordinary changes; root-equivalent changes answer 403
  `step_up_required` with the token detail. CI pipelines split their apply (decision 3 of ADR 0034).

## 8. Steps (tickets, in order)

1. **PDK-165 — Audit codes, problem code, catalog texts.** §6.4, `SessionStoreUnavailable`, i18n `audit.*` and
   `problems.session_store_unavailable`, glossary, `make gen`. Verify: `make gen` has no diff;
   `go test ./server/internal/domain/audit/ ./server/internal/transport/http/admin/`; `make web`.
2. **PDK-166 — `pkg/policy` tiers and the agent's denied-path removal.** Decisions 7–8, §6.2, fuzz target.
   Verify: `go test ./pkg/policy/ ./agent/...`; `make fuzz FUZZTIME=10s` runs `FuzzClassify`.
3. **PDK-167 — Step-up on the effective class (server, declarative, token detail, portal).** Decisions 1–6.
   Verify: `go test ./server/internal/domain/privilege/ ./server/internal/app/`; `make typecheck`; portal
   component tests of the create dialog.
4. **PDK-168 — Managed-file tiers (server, compiler, declarative, portal).** Decisions 9–11; `EffectiveConfig`.
   Verify: `go test ./server/internal/app/ ./server/internal/compiler/` (integration test: a denied row is not in the
   bundle); `make typecheck`.
5. **PDK-169 — Security review of existing data.** Decisions 24–28 (migration 00045, review endpoint, confirm
   endpoints, overview counts, CLI, portal view and banner). Verify: `make test`; `make typecheck`; the isolation
   gate (new routes answer 404 for foreign IDs).
6. **PDK-170 — Acceptance gates SEC-1.** §9 S1–S8. Verify: `make acceptance T='TestEffectiveStepUp|TestManagedFileTiers|TestTokenCannotGrantRoot|TestSecurityReview'`.
7. **PDK-171 — Server-side sessions, logout revocation, end all sessions.** Decisions 12–17, migration none.
   Verify: `go test ./server/internal/sessions/ ./server/internal/transport/http/admin/`; `make acceptance
   T=TestStepUp` still green; `make e2e` login/logout.
8. **PDK-172 — Role re-resolution at the step-up.** Decisions 18–21 (migration 00046), blueprint groups mapping,
   escrow-reader `disabled_at`. Verify: `go test ./server/internal/app/ ./server/internal/transport/http/admin/
   ./server/internal/escrowreader/`; `make acceptance T='TestStepUp|TestEscrowReader'`.
9. **PDK-173 — Worker round admin-accounts.** Decisions 22–23. Verify: `go test ./server/internal/app/
   ./server/internal/adapters/authentik/ ./server/internal/worker/` (adapter fake with `is_active`).
10. **PDK-174 — Acceptance gates SEC-2.** §9 S9–S13, including the disruptive `TestSessionsEndAll` behind
    `PADDOCK_ACCEPTANCE_DISRUPTIVE=1` and its CI step. Verify: `make acceptance T='TestSessions'`;
    `PADDOCK_ACCEPTANCE_DISRUPTIVE=1 make acceptance T=TestSessionsEndAll`.
11. **PDK-175 — Escrow upload bound and edge body limits.** Decisions 29–31; gate S14. Verify: `make lint-caddy`;
    `go test ./server/internal/prodcheck/ ./server/internal/app/ ./server/internal/platform/objectstore/`;
    `make acceptance T='TestEscrowUploadBound|TestDiskEscrow'`.
12. **PDK-176 — Admin API body limit and server timeouts.** Decisions 32–33; gate S15. Verify:
    `go test ./server/internal/transport/http/admin/ ./server/cmd/...`; `make acceptance T='TestBodyLimits|TestRollout'`
    (artifact upload still works).
13. **PDK-177 — Container hardening.** Decisions 34–37. Verify: `make bundle-test`; `go test
    ./server/internal/prodcheck/`; `make down V=1 up acceptance` (dev stack with the anchors); the CI edge job runs
    the smoke tests on `main`.
14. **PDK-178 — WebAuthn-only step-up.** Decisions 38–41. Verify: `go test ./server/internal/prodcheck/`;
    `make down V=1 dev-secrets up dev-seed acceptance T='TestStepUp|TestStepUpFactor|TestAPITokens'`.
15. **PDK-179 — Documents, residual risks, regression, release preparation.** §3.9 documents, RR-35/RR-36, §13
    CHANGELOG, the full regression (`make lint test`, `make acceptance`, `make e2e`, `make system-test VM=all`,
    `make bundle-test`), the upgrade note. Verify: every command green; `make scan-secrets`.

PDK-166 and PDK-165 MAY run in parallel. PDK-171 depends on PDK-165; PDK-172 on PDK-171; PDK-173 on PDK-172;
PDK-174 on PDK-173. PDK-175, PDK-176, PDK-177, PDK-178 MAY run in parallel after PDK-165.

## 9. Acceptance criteria (test/acceptance, positive and negative per role)

Roles: **A** = org_admin (temp user with TOTP, `steppedUpTempUser`), **O** = org_operator (temp user with TOTP in
`paddock.acme.operators`), **U** = org_auditor (`env.Bob`), **T** = API token with role `org_operator` created by
`env.Alice`, **P** = platform admin (`env.PlatformAdmin`). "Event" = exactly one audit event with the given code,
outcome and error code, found with `expectOneEvent` by an acme admin.

| # | Given / When / Then | Role sees |
| --- | --- | --- |
| S1 | A without step-up POSTs a restricted profile with `/usr/bin/bash` → 403 `step_up_required`, event `permission_profile.created` denied; A with step-up → 201, `effective_class: full`, `root_grant_confirmed_at` set, event success with actor `step_up: true` and param `effective_class = full`. | A, U (audit) |
| S2 | A renames the profile of S1 with a PATCH of `name` only and no step-up → 200; A PATCHes `commands` adding `/usr/bin/python3` without step-up → 403 `step_up_required`. | A |
| S3 | A assigns the profile of S1 to a user without step-up → 403; with step-up → 201 (`profile_assignment.created` param `effective_class = full`); PATCH the assignment's `device_group_id` without step-up → 403. | A |
| S4 | A with step-up PUTs a declarative document with the same profile and assignment → 200, change set actor `step_up: true`; T PUTs it → 403 `step_up_required` with a detail containing `API tokens`, event `config.applied` denied. | A, T |
| S5 | T POSTs the restricted profile of S1 → 403 `step_up_required` (detail contains `API tokens`), event denied; T POSTs a profile of class `restricted` with `/usr/bin/systemctl restart nginx.service` → 201. | T |
| S6 | Managed files: O with step-up POSTs `/etc/cron.d/x` → 403 `forbidden`, event `managed_file.created` denied; A without step-up → 403 `step_up_required`; A with step-up → 201 `tier: sensitive`, `sensitive_confirmed_at` set; anyone POSTs `/etc/ld.so.preload` or `/etc/tmpfiles.d/x.conf` → 422 `path_not_allowed`; O POSTs `/etc/myapp/app.conf` mode `0644` → 201 `tier: ordinary`; O POSTs the same path with mode `0755` → 403 `forbidden`; U POSTs anything → 403 `forbidden`. | A, O, U |
| S7 | T POSTs `/etc/profile.d/x.sh` → 403 `step_up_required`; T POSTs `/opt/myapp/conf/a.ini` `0644` → 201. | T |
| S8 | Security review: after the gate NULLs `root_grant_confirmed_at` of the S1 profile and inserts a managed file on `/etc/ld.so.preload` with `docker compose exec -T postgres psql` (development stack), `GET /api/v1/security-review` lists both, `GET /api/v1/overview.security_review` counts them, `GET /api/v1/devices/{id}/config` of an acme device does not list the denied file; A confirms the profile without step-up → 403; with step-up → 200 and the review no longer lists it; a globex admin never sees acme items (isolation gate). | A, U (read) |
| S9 | Logout: A logs in, copies the cookie, POSTs `/api/auth/logout` → 200; the copied cookie on `GET /api/v1/me` → 401. | A |
| S10 | Step-up mismatch: A (temp admin with TOTP) logs in; the gate removes the user from `paddock.acme.admins`; the step-up returns `stepup=failed`; `GET /api/v1/me` → 401; event `admin.sessions_revoked` reason `step_up_role_mismatch`, `sessions ≥ 1`. | A, U (audit) |
| S11 | Deactivation: a temp admin logs in; `SetActive(false)`; within 60 s + 10 s slack (`PADDOCK_IDENTITY_SYNC_INTERVAL` of the development stack) `GET /api/v1/me` → 401; event `admin.sessions_revoked` reason `deactivated`. Reactivating the user and logging in again → 200 (`disabled_at` cleared). | A |
| S12 | Role change: a temp admin logs in; the gate moves the user from `.admins` to `.auditors`; within the interval `GET /api/v1/me` → 401; after a new login `role = org_auditor`; event reason `role_changed`, `old_role org_admin`, `new_role org_auditor`. | A |
| S13 | End all (disruptive, `PADDOCK_ACCEPTANCE_DISRUPTIVE=1` only): P with step-up POSTs `/api/platform/v1/sessions/end-all` → 200 `generation ≥ 1`, event `platform.sessions_ended`; a session of `env.Alice` created before → 401; P without step-up → 403 `step_up_required`; an org admin → 403 `forbidden`; after the call every helper logs in again successfully. | P, A |
| S14 | Escrow bound: a device announces a header of size N and PUTs N+1 bytes to the presigned URL → the object store refuses (4xx) **or** stores it; in both cases the escrow status becomes `failed` within the upload window, `HeadObject` of the key through `rootS3` answers not found, and one event `device.header_object_rejected` exists when the store had accepted the object; a PUT of exactly N bytes → `stored`; a 34 MiB PUT to `https://bundles.<domain>/paddock-escrow/org/x` → 413 from Caddy. | device, U |
| S15 | Body limits: A POSTs `/api/v1/device-groups` with a 300 KiB JSON body → 400 `invalid_request`, event `device_group.created` failure; P uploads a 1 MiB artifact → 200 (rollout gate unchanged); a 3 MiB POST to `https://admin.<domain>/api/v1/device-groups` → 413 from Caddy. | A, P |
| S16 | Step-up factor: `TestStepUpFactor` (decision 40) passes; `TestStepUp` passes against the development stack with the TOTP stage at order 31. | P |
| S17 | Containers: the acceptance job's stack runs with the anchors of decision 34; `./paddock check` of the production and lab file sets passes `container hardening`; the bundle smoke tests pass decision 37. | operator |

## 10. Freedoms

Internal structure of `sessions.Store` (one Lua script or `DoMulti`), the JSON field order of `Record`, helper
names in the use cases, the layout of `SecurityReview.vue` and `PlatformSessions.vue` within the design system, the
fixture format of the prodcheck tests, the exact wording of log lines, whether `RoleGroupUsers` shares the paging
helper with `OrganizationUsers`, the split of the acceptance gates into files (names of §9 are binding), the
`pids_limit` placement comments.

## 11. Stop conditions

- S1: `docker compose config --format json` renders `pids_limit`, `cap_drop`, `cap_add` or `security_opt` in another
  shape than decision 36 assumes (report the rendered JSON).
- S2: RustFS accepts a presigned PUT whose `Content-Length` differs from the signed value **and** the worker check of
  decision 30 cannot be made to run within the upload window (report; do not widen the limit).
- S3: Authentik does not include `groups` in the step-up ID token after decision 19 (report the token's claims; do
  not fall back to the `profile` mapping's groups silently).
- S4: Authentik's blueprint importer rejects the second validation stage or the policy binding of decision 39 (report
  the importer log; do not re-enable TOTP in the shipped blueprint).
- S5: Caddy rejects `request_body` with a matcher inside a snippet or `handle` (report `caddy validate` output).
- S6: M8b's role-group diff job exists on `main` when PDK-173 starts: extend it instead of adding a round, and report
  the overlap.
- S7: the strict handler cannot reach the `http.ResponseWriter` for the artifact uploads (decision 33): report; do
  not lower the server timeouts.
- S8: any change seems necessary in `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`,
  `pkg/bundle` or `api/openapi/device.yaml`.
- S9: a new Go module, npm package or container image seems necessary (none is expected).
- S10: an existing acceptance gate fails because a dev user cannot step up after decision 39 (report before changing
  any gate).

## 12. Risks and open points

- **Cookie version bump (decision 13)** logs every administrator out once at the upgrade. Accepted; the release
  notes say so.
- **Portal availability depends on Valkey.** Already true for step-up proofs; now for every request. RR-35.
- **Older agents delete unchanged files that left the bundle** (ADR 0034 decision 8). RR-36; the review lists
  denied definitions so that administrators clean up deliberately.
- **Catalog completeness.** A deny list over `/etc/` is never complete; the allow-list roots, the "/etc/<file> and
  /etc/*.d are sensitive" defaults and the executable rule reduce what a miss can do. The catalog review is a
  recurring practice (P6 of the hardening review).
- **WebAuthn-only locks out TOTP-only administrators** until they enrol a WebAuthn authenticator. Decision 41; the
  dev stack keeps TOTP.
- **Fleet body limit (64 MiB)**: chosen above osquery's buffered log batches; if `TestInventory` or the lab shows
  413 from Caddy on `fleet.`, raise to 128 MiB and note it (not a stop condition).
- **`end-all` in the acceptance run** is disruptive: it runs only with `PADDOCK_ACCEPTANCE_DISRUPTIVE=1` in its own
  CI step after the main run.
- Open (default chosen): whether `organization.security_review_required` should also be recorded by the migration
  automatically. Default: no, the CLI records it; a migration cannot run Go.

## 13. CHANGELOG rule for M8s

During development every ticket adds its operator-visible line under `[Unreleased]` in `### Changed`, `### Added`
or `### Fixed`, in operator language and neutral (for example "Creating, changing or assigning a permission profile
that grants root-equivalent sudo rights now requires a step-up; API tokens cannot make such changes"). No line uses
the words vulnerability, bypass, exploit or attack, and no line goes into a `### Security` section before the
release. The release commit of `0.1.0-alpha.N+1` moves the lines of SEC-1, SEC-2 and SEC-3 into `### Security` under
the release heading and adds the advisory links; the advisories are published after the release artifacts are live.

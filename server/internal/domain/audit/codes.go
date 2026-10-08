package audit

import "sort"

// Code is a stable, dotted English identifier from the closed registry below.
type Code string

const (
	CodeAdminLogin             Code = "admin.login"
	CodeOrganizationCreated    Code = "organization.created"
	CodeDeviceGroupCreated     Code = "device_group.created"
	CodeDeviceGroupUpdated     Code = "device_group.updated"
	CodeDeviceGroupDeleted     Code = "device_group.deleted"
	CodeActionFinalizedUnknown Code = "action.finalized_unknown"

	CodeEnrollmentTokenCreated     Code = "enrollment_token.created"
	CodeEnrollmentTokenRevoked     Code = "enrollment_token.revoked"
	CodeDeviceEnrolled             Code = "device.enrolled"
	CodeDeviceApproved             Code = "device.approved"
	CodeDeviceRejected             Code = "device.rejected"
	CodeDeviceQuarantineReleased   Code = "device.quarantine_released"
	CodeDeviceRetired              Code = "device.retired"
	CodeDeviceGroupsChanged        Code = "device.groups_changed"
	CodeDeviceCloneSuspected       Code = "device.clone_suspected"
	CodeDeviceBundleApplied        Code = "device.bundle_applied"
	CodeDeviceBundleRejected       Code = "device.bundle_rejected"
	CodeDeviceConfigDriftCorrected Code = "device.config_drift_corrected"
	CodeDeviceAgentUpdated         Code = "device.agent_updated"
	CodeDeviceAgentUpdateFailed    Code = "device.agent_update_failed"
	CodeDeviceAgentRolledBack      Code = "device.agent_rolled_back"
	CodeDeviceAgentEventsDropped   Code = "device.agent_events_dropped"
	CodeManagedFileCreated         Code = "managed_file.created"
	CodeManagedFileUpdated         Code = "managed_file.updated"
	CodeManagedFileDeleted         Code = "managed_file.deleted"
	CodeManagedUnitCreated         Code = "managed_unit.created"
	CodeManagedUnitUpdated         Code = "managed_unit.updated"
	CodeManagedUnitDeleted         Code = "managed_unit.deleted"

	CodeAgentReleaseCreated          Code = "agent_release.created"
	CodeAgentReleaseArtifactUploaded Code = "agent_release.artifact_uploaded"
	CodeAgentReleasePublished        Code = "agent_release.published"
	CodeAgentRolloutStarted          Code = "agent_rollout.started"
	CodeAgentRolloutAdvanced         Code = "agent_rollout.advanced"
	CodeAgentRolloutHalted           Code = "agent_rollout.halted"
	CodeAgentRolloutResumed          Code = "agent_rollout.resumed"
	CodeAgentRolloutCompleted        Code = "agent_rollout.completed"

	CodeOrganizationDomainsChanged  Code = "organization.domains_changed"
	CodeUserCreated                 Code = "user.created"
	CodeUserUpdated                 Code = "user.updated"
	CodeUserDeleted                 Code = "user.deleted"
	CodeUserLocked                  Code = "user.locked"
	CodeUserUnlocked                Code = "user.unlocked"
	CodeUserSyncedAdded             Code = "user.synced_added"
	CodeUserSyncedRemoved           Code = "user.synced_removed"
	CodeUserGroupCreated            Code = "user_group.created"
	CodeUserGroupUpdated            Code = "user_group.updated"
	CodeUserGroupDeleted            Code = "user_group.deleted"
	CodeUserGroupMemberAdded        Code = "user_group.member_added"
	CodeUserGroupMemberRemoved      Code = "user_group.member_removed"
	CodeSettingsLoginChanged        Code = "settings.login_changed"
	CodeDeviceLoginAssignmentChange Code = "device.login_assignment_changed"
	CodeDeviceLoginsSuspended       Code = "device.logins_suspended"
	CodeDeviceLoginsResumed         Code = "device.logins_resumed"
	CodePermissionProfileCreated    Code = "permission_profile.created"
	CodePermissionProfileUpdated    Code = "permission_profile.updated"
	CodePermissionProfileDeleted    Code = "permission_profile.deleted"
	CodeProfileAssignmentCreated    Code = "profile_assignment.created"
	CodeProfileAssignmentUpdated    Code = "profile_assignment.updated"
	CodeProfileAssignmentDeleted    Code = "profile_assignment.deleted"
	CodeDeviceBundleRenderFailed    Code = "device.bundle_render_failed"
	CodeDeviceBundleEntryOmitted    Code = "device.bundle_entry_omitted"

	// Identity and privileges reported by devices (plan M3b decision 5).
	CodeDeviceLoginApplied               Code = "device.login_applied"
	CodeDeviceLoginApplyFailed           Code = "device.login_apply_failed"
	CodeDeviceUserLockApplied            Code = "device.user_lock_applied"
	CodeDeviceLoginsSuspensionApplied    Code = "device.logins_suspension_applied"
	CodeDeviceSudoApplyFailed            Code = "device.sudo_apply_failed"
	CodeDeviceSudoUserUnresolved         Code = "device.sudo_user_unresolved"
	CodeDeviceTamperSudoGroupMember      Code = "device.tamper_sudo_group_member"
	CodeDeviceTamperSudoersDFile         Code = "device.tamper_sudoers_d_file"
	CodeDeviceTamperSudoersChanged       Code = "device.tamper_sudoers_changed"
	CodeDeviceTamperProtectedFileChanged Code = "device.tamper_protected_file_changed"

	// Managed local administrator (plan M4a decisions 17 and 18).
	CodeLocalAdminRotationRequested   Code = "local_admin.rotation_requested"
	CodeLocalAdminRevealed            Code = "local_admin.revealed"
	CodeLocalAdminRotated             Code = "local_admin.rotated"
	CodeLocalAdminRotationFailed      Code = "local_admin.rotation_failed"
	CodeLocalAdminLogin               Code = "local_admin.login"
	CodeDeviceTamperLocalAdminChanged Code = "device.tamper_local_admin_changed"

	CodeAutoinstallGenerated       Code = "autoinstall.generated"
	CodeDeviceTamperKeyslotChanged Code = "device.tamper_keyslot_changed"
	CodeDiskRecoveryKeyRevealed    Code = "disk.recovery_key_revealed"
	CodeDiskHeaderDownloaded       Code = "disk.header_downloaded"

	CodeDeviceRevocationTrustPinnedTOFU Code = "device.revocation_trust_pinned_tofu"
	CodeRevocationRequested             Code = "revocation.requested"
	CodeRevocationApproved              Code = "revocation.approved"
	CodeRevocationRejected              Code = "revocation.rejected"
	CodeRevocationCancelled             Code = "revocation.cancelled"
	CodeRevocationIssued                Code = "revocation.issued"
	CodeRevocationIssueRefused          Code = "revocation.issue_refused"
	CodeRevocationLimitExceeded         Code = "revocation.limit_exceeded"
	CodeDeviceEscrowDestroyed           Code = "device.escrow_destroyed"
	CodeDeviceRevocationConfirmed       Code = "device.revocation_confirmed"
	CodeDeviceRevocationRefused         Code = "device.revocation_refused"
	CodeSettingsDMSChanged              Code = "settings.dms_changed"
	CodeDevicePresumedSelfLocked        Code = "device.presumed_self_locked"
	// Inventory (plan M5a decisions 5 and 8): the mutual watch of agent and fleetd.
	CodeDeviceTamperServiceStopped  Code = "device.tamper_service_stopped"
	CodeDeviceTamperAgentNotRunning Code = "device.tamper_agent_not_running"
	// Update management (plan M5b decisions 1–3 and 6).
	CodeSettingsUpdatesChanged    Code = "settings.updates_changed"
	CodePackageHoldCreated        Code = "package_hold.created"
	CodePackageHoldUpdated        Code = "package_hold.updated"
	CodePackageHoldDeleted        Code = "package_hold.deleted"
	CodeDeviceInstallNowRequested Code = "device.install_now_requested"
	CodeDeviceUpdatesRun          Code = "device.updates_run"
	// Staleness (plan M5b decision 10).
	CodeDeviceStaleWarning  Code = "device.stale_warning"
	CodeDeviceStaleCritical Code = "device.stale_critical"
	CodeDeviceStaleCleared  Code = "device.stale_cleared"

	CodePlatformOSVStale Code = "platform.osv_stale"

	// API tokens (plan M6c decisions 4, 5 and 9).
	CodeAPITokenCreated   Code = "api_token.created"
	CodeAPITokenRevoked   Code = "api_token.revoked"
	CodeAPITokenUseDenied Code = "api_token.use_denied" //nolint:gosec // an audit code, not a credential
)

// Definition documents one code (rendered into docs/compliance/audit-codes.md by `make gen`).
type Definition struct {
	Code        Code
	Description string
	Params      []string
	Outcomes    []Outcome
	Emitted     bool // false for registry entries that are never emitted as events
	Note        string
}

// adminOutcomes are the outcomes of database-only administrator actions.
var adminOutcomes = []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied}

// deviceEventParams are the parameters of audit events reported by devices (plan M2a decision 14, M2b decisions 9,
// 11, 12 and 16, M3b decision 5); each event carries the subset its type defines.
var deviceEventParams = []string{
	"event_seq", "occurred_at", "bundle_version", "reason", "resource", "version", "changed", "errors", "resource_ids",
	"from_version", "outcome", "count", "from_seq", "to_seq", "stage", "message", "username", "sessions_locked",
	"sessions_terminated", "group", "removed", "file", "quarantined_as", "sha256_before", "sha256_after",
	"generation", "service", "at", "field", "before", "after", "unit",
	"kind", "started_at", "finished_at", "upgraded", "held_back", "reboot_required", "result", "error",
}

var registry = map[Code]Definition{
	CodeAdminLogin: {
		Code: CodeAdminLogin, Emitted: true,
		Description: "An administrator signed in to the portal, or a sign-in was rejected.",
		Params:      []string{"role", "organization_slug", "reason"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied},
		Note:        "Platform administrators and rejected sign-ins without a resolvable organization are recorded in the platform pseudo-organization.",
	},
	CodeOrganizationCreated: {
		Code: CodeOrganizationCreated, Emitted: true,
		Description: "A platform administrator created (or re-provisioned) an organization and its Authentik groups.",
		Params:      []string{"slug", "name", "reprovisioned"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeDeviceGroupCreated: {
		Code: CodeDeviceGroupCreated, Emitted: true,
		Description: "A device group was created.",
		Params:      []string{"name"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied},
	},
	CodeDeviceGroupUpdated: {
		Code: CodeDeviceGroupUpdated, Emitted: true,
		Description: "A device group was renamed or its description changed.",
		Params:      []string{"name", "old_name", "description_changed"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied},
	},
	CodeDeviceGroupDeleted: {
		Code: CodeDeviceGroupDeleted, Emitted: true,
		Description: "A device group was deleted.",
		Params:      []string{"name"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied},
	},
	CodeEnrollmentTokenCreated: {
		Code: CodeEnrollmentTokenCreated, Emitted: true,
		Description: "An enrollment token was created. The token secret is never recorded.",
		Params:      []string{"name", "expires_at", "max_uses", "auto_approve", "device_group_id"},
		Outcomes:    adminOutcomes,
	},
	CodeEnrollmentTokenRevoked: {
		Code: CodeEnrollmentTokenRevoked, Emitted: true,
		Description: "An enrollment token was revoked.",
		Params:      []string{"name"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceEnrolled: {
		Code: CodeDeviceEnrolled, Emitted: true,
		Description: "A device enrolled with an enrollment token (actor: the device), or its enrollment was rejected.",
		Params:      []string{"hostname", "state", "key_protection", "enrolled_with"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "enrolled_with is the ID of the enrollment token. A failure carries the rejection reason as error_code: invalid_token, token_revoked, token_expired, token_exhausted or invalid_request.",
	},
	CodeDeviceApproved: {
		Code: CodeDeviceApproved, Emitted: true,
		Description: "An administrator approved a pending device.",
		Params:      []string{"hostname", "from_state"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceRejected: {
		Code: CodeDeviceRejected, Emitted: true,
		Description: "An administrator rejected a pending device.",
		Params:      []string{"hostname", "from_state"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceQuarantineReleased: {
		Code: CodeDeviceQuarantineReleased, Emitted: true,
		Description: "An administrator released a quarantined device back to active.",
		Params:      []string{"hostname", "from_state"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceRetired: {
		Code: CodeDeviceRetired, Emitted: true,
		Description: "An administrator retired a device; its identity keys are revoked.",
		Params:      []string{"hostname", "from_state"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceGroupsChanged: {
		Code: CodeDeviceGroupsChanged, Emitted: true,
		Description: "The device group memberships of a device were replaced.",
		Params:      []string{"hostname", "added", "removed"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceCloneSuspected: {
		Code: CodeDeviceCloneSuspected, Emitted: true,
		Description: "The sequence numbers of a device diverged (cloned identity); the device was quarantined.",
		Params:      []string{"hostname", "reported_seq", "issued_seq", "from_state"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
	},
	CodeDeviceBundleApplied: {
		Code: CodeDeviceBundleApplied, Emitted: true,
		Description: "A device reported that it applied a bundle (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceBundleRejected: {
		Code: CodeDeviceBundleRejected, Emitted: true,
		Description: "A device reported that it rejected a bundle, e.g. a failed signature check (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceConfigDriftCorrected: {
		Code: CodeDeviceConfigDriftCorrected, Emitted: true,
		Description: "A device reported that it corrected a local change of a managed resource (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceAgentUpdated: {
		Code: CodeDeviceAgentUpdated, Emitted: true,
		Description: "A device's supervisor switched to a new agent version that passed self-test and probation (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceAgentUpdateFailed: {
		Code: CodeDeviceAgentUpdateFailed, Emitted: true,
		Description: "A device's supervisor refused an agent release before switching: invalid signature, not newer than the active version, or failed self-test (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "outcome is signature_invalid (also a signed comment that does not name the version and architecture), downgrade_refused or self_test_failed.",
	},
	CodeDeviceAgentRolledBack: {
		Code: CodeDeviceAgentRolledBack, Emitted: true,
		Description: "A device's supervisor rolled a new agent version back because it crashed or did not report healthy within its probation (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceAgentEventsDropped: {
		Code: CodeDeviceAgentEventsDropped, Emitted: true,
		Description: "A device's event spool overflowed while the server was unreachable; the events from_seq..to_seq were dropped (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceLoginApplied: {
		Code: CodeDeviceLoginApplied, Emitted: true,
		Description: "A device installed or reconfigured its login component (Himmelblau) or changed its local deny list (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "changed lists what changed: package, config, deny_list.",
	},
	CodeDeviceLoginApplyFailed: {
		Code: CodeDeviceLoginApplyFailed, Emitted: true,
		Description: "A device could not apply its login configuration; the previous state stays in effect (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "stage is apt, config, restart, deny_list, pam, sessions or notice; pam means the deny-list PAM profile is not in place (`dpkg-reconfigure paddock-agent` restores it); reason timeout marks an apt-get or dpkg run killed after 15 minutes.",
	},
	CodeDeviceUserLockApplied: {
		Code: CodeDeviceUserLockApplied, Emitted: true,
		Description: "A device blocked a newly locked user locally (login, offline login, screen unlock) and locked or terminated the user's sessions (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceLoginsSuspensionApplied: {
		Code: CodeDeviceLoginsSuspensionApplied, Emitted: true,
		Description: "A device applied a login suspension: directory logins are refused and directory users' sessions were terminated (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceSudoApplyFailed: {
		Code: CodeDeviceSudoApplyFailed, Emitted: true,
		Description: "A device could not apply a user's sudo rights, or its sudo configuration failed the check; the previous state was kept or restored (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "username is empty when the sudo configuration as a whole is affected, e.g. /etc/sudoers lost its includedir.",
	},
	CodeDeviceSudoUserUnresolved: {
		Code: CodeDeviceSudoUserUnresolved, Emitted: true,
		Description: "A user with sudo rights is not known on a device yet (never logged in there); the rights take effect after the first login (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceTamperSudoGroupMember: {
		Code: CodeDeviceTamperSudoGroupMember, Emitted: true,
		Description: "A device found a member of a privileged local group (sudo, admin, wheel) that is not a break-glass account and removed it (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceTamperSudoersDFile: {
		Code: CodeDeviceTamperSudoersDFile, Emitted: true,
		Description: "A device moved an unexpected file in /etc/sudoers.d to its quarantine directory (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceTamperSudoersChanged: {
		Code: CodeDeviceTamperSudoersChanged, Emitted: true,
		Description: "A device found /etc/sudoers changed since it last recorded it; the agent reports but does not rewrite it (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceTamperProtectedFileChanged: {
		Code: CodeDeviceTamperProtectedFileChanged, Emitted: true,
		Description: "A device found a protected file changed that the agent does not restore itself, e.g. its PAM configuration (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeManagedFileCreated: {
		Code: CodeManagedFileCreated, Emitted: true,
		Description: "A managed file was defined for the organization or a device group.",
		Params:      []string{"path", "device_group_id", "mode", "owner", "group"},
		Outcomes:    adminOutcomes,
	},
	CodeManagedFileUpdated: {
		Code: CodeManagedFileUpdated, Emitted: true,
		Description: "A managed file definition was changed.",
		Params:      []string{"path", "device_group_id", "mode", "owner", "group", "content_changed", "old_path"},
		Outcomes:    adminOutcomes,
	},
	CodeManagedFileDeleted: {
		Code: CodeManagedFileDeleted, Emitted: true,
		Description: "A managed file definition was deleted.",
		Params:      []string{"path", "device_group_id"},
		Outcomes:    adminOutcomes,
	},
	CodeManagedUnitCreated: {
		Code: CodeManagedUnitCreated, Emitted: true,
		Description: "A managed systemd unit was defined for the organization or a device group.",
		Params:      []string{"unit", "device_group_id", "enabled", "active"},
		Outcomes:    adminOutcomes,
	},
	CodeManagedUnitUpdated: {
		Code: CodeManagedUnitUpdated, Emitted: true,
		Description: "A managed systemd unit definition was changed.",
		Params:      []string{"unit", "device_group_id", "enabled", "active", "old_unit"},
		Outcomes:    adminOutcomes,
	},
	CodeManagedUnitDeleted: {
		Code: CodeManagedUnitDeleted, Emitted: true,
		Description: "A managed systemd unit definition was deleted.",
		Params:      []string{"unit", "device_group_id"},
		Outcomes:    adminOutcomes,
	},
	CodeAgentReleaseCreated: {
		Code: CodeAgentReleaseCreated, Emitted: true,
		Description: "A platform administrator created an agent release (draft).",
		Params:      []string{"version"},
		Outcomes:    adminOutcomes,
	},
	CodeAgentReleaseArtifactUploaded: {
		Code: CodeAgentReleaseArtifactUploaded, Emitted: true,
		Description: "A platform administrator uploaded the signed agent binary or a signed Debian package of a release for one architecture; the server verified its signature with the release public key.",
		Params:      []string{"version", "arch", "sha256", "size", "kind", "name", "package_version"},
		Outcomes:    adminOutcomes,
		Note:        "kind is binary (paddockd) or deb (a Debian package, with name paddock-agent, paddock-supervisor, paddock-revoke or fleet-osquery); package_version is the fleetd version of fleet-osquery; events before M4b have no kind.",
	},
	CodeAgentReleasePublished: {
		Code: CodeAgentReleasePublished, Emitted: true,
		Description: "A platform administrator published an agent release; it can now be rolled out.",
		Params:      []string{"version", "arches"},
		Outcomes:    adminOutcomes,
	},
	CodeAgentRolloutStarted: {
		Code: CodeAgentRolloutStarted, Emitted: true,
		Description: "A platform administrator started the staged rollout of an agent release.",
		Params:      []string{"version", "waves", "min_wave_minutes", "failure_threshold_percent", "failure_threshold_min"},
		Outcomes:    adminOutcomes,
	},
	CodeAgentRolloutAdvanced: {
		Code: CodeAgentRolloutAdvanced, Emitted: true,
		Description: "The worker moved a rollout to its next wave (actor: system).",
		Params:      []string{"version", "wave", "percent", "eligible", "failed"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
	},
	CodeAgentRolloutHalted: {
		Code: CodeAgentRolloutHalted, Emitted: true,
		Description: "A rollout was halted: automatically by the worker when failed devices reached the threshold (actor: system), or by a platform administrator.",
		Params:      []string{"version", "reason", "wave", "eligible", "failed", "threshold"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied},
	},
	CodeAgentRolloutResumed: {
		Code: CodeAgentRolloutResumed, Emitted: true,
		Description: "A platform administrator resumed a halted rollout.",
		Params:      []string{"version", "wave"},
		Outcomes:    adminOutcomes,
	},
	CodeAgentRolloutCompleted: {
		Code: CodeAgentRolloutCompleted, Emitted: true,
		Description: "The worker completed a rollout after its last wave (actor: system).",
		Params:      []string{"version", "eligible", "failed"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
	},
	CodeOrganizationDomainsChanged: {
		Code: CodeOrganizationDomainsChanged, Emitted: true,
		Description: "A platform administrator changed the domains of an organization; the first domain is the primary domain of device logins.",
		Params:      []string{"slug", "domains", "old_domains"},
		Outcomes:    adminOutcomes,
		Note:        "Recorded in the organization whose domains changed. A domain of another organization is refused with error_code domain_taken.",
	},
	CodeUserCreated: {
		Code: CodeUserCreated, Emitted: true,
		Description: "A local user was created in Authentik (without password) and in Paddock; the one-time recovery link is shown once and never recorded.",
		Params:      []string{"username", "display_name"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeUserUpdated: {
		Code: CodeUserUpdated, Emitted: true,
		Description: "The display name or email of a local user was changed; attributes of synced users are refused with error_code attribute_owned_upstream.",
		Params:      []string{"username", "display_name_changed", "email_changed"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeUserDeleted: {
		Code: CodeUserDeleted, Emitted: true,
		Description: "A local user was deleted in Authentik and Paddock, with their group memberships and assignments.",
		Params:      []string{"username"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeUserLocked: {
		Code: CodeUserLocked, Emitted: true,
		Description: "An organization administrator locked a user: member of paddock.<slug>.locked, refresh tokens, access tokens and sessions deleted in Authentik; the affected devices get the lock in their next bundle.",
		Params:      []string{"username", "source"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
		Note:        "The device path does not wait for Authentik: Paddock marks the user locked and recompiles before the Authentik call, so a failure leaves the user locked on the devices.",
	},
	CodeUserUnlocked: {
		Code: CodeUserUnlocked, Emitted: true,
		Description: "An organization administrator unlocked a user (removed from paddock.<slug>.locked); the user signs in with the device code flow again.",
		Params:      []string{"username", "source"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeUserSyncedAdded: {
		Code: CodeUserSyncedAdded, Emitted: true,
		Description: "The worker found a new synced user (member of paddock.<slug> put there by an upstream source) (actor: system).",
		Params:      []string{"username"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
	},
	CodeUserSyncedRemoved: {
		Code: CodeUserSyncedRemoved, Emitted: true,
		Description: "The worker removed a synced user that is no longer a member of paddock.<slug>, with their group memberships and assignments (actor: system).",
		Params:      []string{"username"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
	},
	CodeUserGroupCreated: {
		Code: CodeUserGroupCreated, Emitted: true,
		Description: "A local user group (paddock.<slug>.g.<group>) was created, or an upstream group was imported as mirror group paddock.<slug>.s.<group>.",
		Params:      []string{"slug", "name", "source", "upstream_group", "members"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeUserGroupUpdated: {
		Code: CodeUserGroupUpdated, Emitted: true,
		Description: "A user group was renamed (the slug and the Authentik group name stay).",
		Params:      []string{"slug", "name", "old_name"},
		Outcomes:    adminOutcomes,
	},
	CodeUserGroupDeleted: {
		Code: CodeUserGroupDeleted, Emitted: true,
		Description: "A user group was deleted in Authentik and Paddock, with its login and profile assignments.",
		Params:      []string{"slug", "name"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeUserGroupMemberAdded: {
		Code: CodeUserGroupMemberAdded, Emitted: true,
		Description: "A user became member of a user group: by an administrator (local groups) or by the worker's mirror of an imported group (actor: system). A privilege change: the params carry the user's highest effective class over all devices before and after.",
		Params:      []string{"user", "group", "effective_class_before", "effective_class_after"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeUserGroupMemberRemoved: {
		Code: CodeUserGroupMemberRemoved, Emitted: true,
		Description: "A user left a user group (administrator or the worker's mirror). The params carry the user's highest effective class over all devices before and after.",
		Params:      []string{"user", "group", "effective_class_before", "effective_class_after"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeSettingsLoginChanged: {
		Code: CodeSettingsLoginChanged, Emitted: true,
		Description: "The organization's login settings were changed (Hello PIN, session action of a lock, break-glass accounts, sudoers.d allow list, sudo lecture text).",
		Params:      []string{"changed"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceLoginAssignmentChange: {
		Code: CodeDeviceLoginAssignmentChange, Emitted: true,
		Description: "The users and groups that may log in on a device were replaced; empty means every user of the organization.",
		Params:      []string{"hostname", "users", "groups"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeUnknown},
	},
	CodeDeviceLoginsSuspended: {
		Code: CodeDeviceLoginsSuspended, Emitted: true,
		Description: "Directory logins on a device were suspended (its bundle denies every directory user).",
		Params:      []string{"hostname"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceLoginsResumed: {
		Code: CodeDeviceLoginsResumed, Emitted: true,
		Description: "Directory logins on a device were resumed.",
		Params:      []string{"hostname"},
		Outcomes:    adminOutcomes,
	},
	CodePermissionProfileCreated: {
		Code: CodePermissionProfileCreated, Emitted: true,
		Description: "A permission profile was created.",
		Params:      []string{"name", "class", "commands", "root_equivalent"},
		Outcomes:    adminOutcomes,
		Note:        "root_equivalent is true when a command of the profile hands out root on its own or in combination (catalog version in the effective profile).",
	},
	CodePermissionProfileUpdated: {
		Code: CodePermissionProfileUpdated, Emitted: true,
		Description: "A permission profile was changed.",
		Params:      []string{"name", "class", "old_class", "commands", "root_equivalent"},
		Outcomes:    adminOutcomes,
	},
	CodePermissionProfileDeleted: {
		Code: CodePermissionProfileDeleted, Emitted: true,
		Description: "A permission profile without assignments was deleted.",
		Params:      []string{"name", "class"},
		Outcomes:    adminOutcomes,
	},
	CodeProfileAssignmentCreated: {
		Code: CodeProfileAssignmentCreated, Emitted: true,
		Description: "A permission profile was assigned globally, to a group or to a user, optionally only on the devices of one device group.",
		Params:      []string{"profile", "class", "root_equivalent", "subject_type", "subject_id", "device_group_id"},
		Outcomes:    adminOutcomes,
	},
	CodeProfileAssignmentUpdated: {
		Code: CodeProfileAssignmentUpdated, Emitted: true,
		Description: "The device group scope of a profile assignment was changed.",
		Params:      []string{"profile", "class", "root_equivalent", "subject_type", "subject_id", "device_group_id", "old_device_group_id"},
		Outcomes:    adminOutcomes,
	},
	CodeProfileAssignmentDeleted: {
		Code: CodeProfileAssignmentDeleted, Emitted: true,
		Description: "A profile assignment was removed.",
		Params:      []string{"profile", "class", "subject_type", "subject_id", "device_group_id"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceBundleRenderFailed: {
		Code: CodeDeviceBundleRenderFailed, Emitted: true,
		Description: "The compiler blocked a device's new bundle because a rendered sudo entry failed the visudo check; the device keeps its previous bundle (actor: system).",
		Params:      []string{"username", "reason"},
		Outcomes:    []Outcome{OutcomeFailure},
		Note:        "error_code is render_failed; reason is visudo's message (at most 500 characters).",
	},
	CodeDeviceBundleEntryOmitted: {
		Code: CodeDeviceBundleEntryOmitted, Emitted: true,
		Description: "The compiler published a device's bundle without a user's sudo entry because a permission profile holds a command that is no longer allowed (stored before the command check was tightened); the user has no sudo rights on the device until the profile is fixed (actor: system).",
		Params:      []string{"username", "reason"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Recorded at most once per user and bundle version; reason names the command, the profiles it comes from and the refused character (at most 500 characters).",
	},
	CodeLocalAdminRotationRequested: {
		Code: CodeLocalAdminRotationRequested, Emitted: true,
		Description: "An administrator or operator issued the command rotate_admin_password to a device.",
		Params:      []string{"hostname", "command_id"},
		Outcomes:    adminOutcomes,
	},
	CodeLocalAdminRevealed: {
		Code: CodeLocalAdminRevealed, Emitted: true,
		Description: "An organization administrator revealed the local administrator password of a device after a step-up; the passwords are never recorded.",
		Params:      []string{"hostname", "generations", "rotation_scheduled_at"},
		Outcomes:    adminOutcomes,
		Note:        "generations lists the revealed generations; rotation_scheduled_at is set when the organization rotates after a reveal.",
	},
	CodeLocalAdminRotated: {
		Code: CodeLocalAdminRotated, Emitted: true,
		Description: "A device set a new local administrator password after the server stored it; the generation is active, older ones are superseded (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeLocalAdminRotationFailed: {
		Code: CodeLocalAdminRotationFailed, Emitted: true,
		Description: "A device could not rotate its local administrator password; the previous password stays valid (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "reason is escrow_failed, escrow_timeout or apply_failed.",
	},
	CodeLocalAdminLogin: {
		Code: CodeLocalAdminLogin, Emitted: true,
		Description: "A session of the local administrator account was opened on a device (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "service is the PAM service, e.g. sshd or login; no terminal or remote host is recorded.",
	},
	CodeDeviceTamperLocalAdminChanged: {
		Code: CodeDeviceTamperLocalAdminChanged, Emitted: true,
		Description: "A device found its local administrator account changed outside Paddock; the agent repairs it and rotates the password (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "field is password, shell, group, locked or missing.",
	},
	CodeDeviceTamperKeyslotChanged: {
		Code: CodeDeviceTamperKeyslotChanged, Emitted: true,
		Description: "A device found the keyslots of its encrypted root volume changed outside Paddock; it escrows the header again (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "before and after list the kind of every keyslot (tpm2+pin, tpm2, recovery, password, or another token type).",
	},
	CodeDiskRecoveryKeyRevealed: {
		Code: CodeDiskRecoveryKeyRevealed, Emitted: true,
		Description: "An organization administrator revealed the disk recovery key of a device after a step-up; the key is never recorded.",
		Params:      []string{"hostname", "generation"},
		Outcomes:    adminOutcomes,
	},
	CodeDiskHeaderDownloaded: {
		Code: CodeDiskHeaderDownloaded, Emitted: true,
		Description: "An organization administrator downloaded an escrowed LUKS header of a device after a step-up.",
		Params:      []string{"hostname", "generation"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceRevocationTrustPinnedTOFU: {
		Code: CodeDeviceRevocationTrustPinnedTOFU, Emitted: true,
		Description: "A device enrolled before revocation existed pinned the revocation-signing keys of the first bundle that carried them (trust on first use); re-enrolling the device replaces them with the keys of its enrollment configuration (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeRevocationRequested: {
		Code: CodeRevocationRequested, Emitted: true,
		Description: "An organization administrator requested a Lock or Destroy of a device after a step-up, typing its hostname; a Lock is approved with the request, a Destroy waits for a second administrator.",
		Params:      []string{"action", "hostname", "request_id"},
		Outcomes:    adminOutcomes,
		Note:        "action is lock or destroy. denied with revocation_disabled while PADDOCK_REVOCATION_ENABLED is off, revocation_frozen while the administrator is frozen after a limit was exceeded.",
	},
	CodeRevocationApproved: {
		Code: CodeRevocationApproved, Emitted: true,
		Description: "A second organization administrator, with another account and another identity than the requester, approved a Destroy after a step-up (two-person rule).",
		Params:      []string{"action", "hostname", "request_id"},
		Outcomes:    adminOutcomes,
	},
	CodeRevocationRejected: {
		Code: CodeRevocationRejected, Emitted: true,
		Description: "An organization administrator rejected a revocation request that waited for its second approval.",
		Params:      []string{"action", "hostname", "request_id"},
		Outcomes:    adminOutcomes,
	},
	CodeRevocationCancelled: {
		Code: CodeRevocationCancelled, Emitted: true,
		Description: "The requester cancelled a revocation request before it was issued.",
		Params:      []string{"action", "hostname", "request_id"},
		Outcomes:    adminOutcomes,
	},
	CodeRevocationIssued: {
		Code: CodeRevocationIssued, Emitted: true,
		Description: "The revocation-issuer verified the step-up proofs and the limits of a Lock or a self-lock and signed the device-bound revocation token (actor: system).",
		Params:      []string{"action", "hostname", "request_id", "requested_by", "expires_at"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
	},
	CodeDeviceEscrowDestroyed: {
		Code: CodeDeviceEscrowDestroyed, Emitted: true,
		Description: "The revocation-issuer verified a Destroy, deleted every escrowed LUKS header object (all versions) and every recovery key and header generation of the device, and signed the Destroy token in the same transaction; the device's data is unrecoverable once it erased its keyslots (actor: system).",
		Params:      []string{"action", "hostname", "request_id", "requested_by", "approved_by", "expires_at", "objects", "escrows"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeUnknown},
		Note:        "failure leaves the request approved; the issuer retries it.",
	},
	CodeRevocationLimitExceeded: {
		Code: CodeRevocationLimitExceeded, Emitted: true,
		Description: "The revocation-issuer refused a revocation because it exceeded a limit of ADR 0014 (per administrator 3 per hour and 10 per 24 h, per organization 20 per 24 h); the request is rejected, an alert is raised and the requester's revocations are frozen for 24 h (actor: system).",
		Params:      []string{"action", "hostname", "request_id", "requested_by", "reason", "frozen_until"},
		Outcomes:    []Outcome{OutcomeDenied},
		Note:        "reason is limit_admin_hour, limit_admin_day or limit_organization_day.",
	},
	CodeRevocationIssueRefused: {
		Code: CodeRevocationIssueRefused, Emitted: true,
		Description: "The revocation-issuer refused to sign a revocation: a step-up proof failed its checks (signature, issuer, audience, subject, auth_time, MFA, reuse), the approvals were not two distinct administrators, the requester is frozen, or revocation is disabled; the request is rejected (actor: system).",
		Params:      []string{"action", "hostname", "request_id", "requested_by", "reason"},
		Outcomes:    []Outcome{OutcomeDenied},
		Note:        "reason is stepup_invalid, approvals_invalid, not_org_admin, admin_frozen, revocation_disabled or device_unavailable.",
	},
	CodeDeviceRevocationConfirmed: {
		Code: CodeDeviceRevocationConfirmed, Emitted: true,
		Description: "A device confirmed a revocation before its forced reboot: every keyslot of its encrypted root volume is erased (actor: the device).",
		Params:      []string{"action", "request_id", "erased", "slots_before", "slots_after", "status"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "status failed means the device reported that the erasure did not complete.",
	},
	CodeDeviceRevocationRefused: {
		Code: CodeDeviceRevocationRefused, Emitted: true,
		Description: "paddock-revoke on a device refused a revocation token; no session and no keyslot was touched (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "reason is disabled, trust_missing, signature, malformed, wrong_device, expired, not_yet_valid, already_executed, rate_limited, period_not_reached, test_target_present, not_encrypted, not_enrolled, not_installed or internal_error.",
	},
	CodeSettingsDMSChanged: {
		Code: CodeSettingsDMSChanged, Emitted: true,
		Description: "An organization administrator changed the dead man's switch: on or off, its period and its warning lead times; turning it on or changing it while on needs a step-up.",
		Params:      []string{"enabled", "period_days", "warn_days"},
		Outcomes:    adminOutcomes,
		Note:        "denied with revocation_disabled while PADDOCK_REVOCATION_ENABLED is off.",
	},
	CodeDevicePresumedSelfLocked: {
		Code: CodeDevicePresumedSelfLocked, Emitted: true,
		Description: "A device has not reached Paddock for longer than the dead man's switch period: it presumably locked itself (actor: system).",
		Params:      []string{"period_days", "last_contact_at"},
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceTamperServiceStopped: {
		Code: CodeDeviceTamperServiceStopped, Emitted: true,
		Description: "A device found a service Paddock keeps running stopped outside Paddock and started it again (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "unit is orbit.service (fleetd, the mutual watch of agent and fleetd).",
	},
	CodeDeviceTamperAgentNotRunning: {
		Code: CodeDeviceTamperAgentNotRunning, Emitted: true,
		Description: "fleetd reports that the Paddock agent does not run on a device that has not checked in for 15 minutes: the agent was stopped or removed (actor: system; the inventory system's policy paddock_agent_running).",
		Params:      []string{"policy", "last_contact_at"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Recorded once per failure; the policy passing again ends it.",
	},
	CodeSettingsUpdatesChanged: {
		Code: CodeSettingsUpdatesChanged, Emitted: true,
		Description: "An organization administrator changed the update settings: the time of the daily security updates, the schedule of regular updates, the random delay and the staleness thresholds.",
		Params: []string{"security_daily_at", "regular_schedule", "regular_updates_enabled", "max_random_delay_min",
			"staleness_warning_h", "staleness_critical_h"},
		Outcomes: adminOutcomes,
		Note:     "failure with invalid_schedule for a schedule outside the accepted subset.",
	},
	CodePackageHoldCreated: {
		Code: CodePackageHoldCreated, Emitted: true,
		Description: "A package was held for the organization or a device group, optionally pinned to a version.",
		Params:      []string{"package", "version", "device_group_id", "reason"},
		Outcomes:    adminOutcomes,
	},
	CodePackageHoldUpdated: {
		Code: CodePackageHoldUpdated, Emitted: true,
		Description: "The version or the reason of a package hold changed.",
		Params:      []string{"package", "version", "device_group_id", "reason", "old_version"},
		Outcomes:    adminOutcomes,
	},
	CodePackageHoldDeleted: {
		Code: CodePackageHoldDeleted, Emitted: true,
		Description: "A package hold was removed; devices may upgrade the package again.",
		Params:      []string{"package", "version", "device_group_id"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceInstallNowRequested: {
		Code: CodeDeviceInstallNowRequested, Emitted: true,
		Description: "An administrator or operator issued the command install_now to a device or to the active devices of a device group.",
		Params:      []string{"packages", "hostname", "command_id", "device_count"},
		Outcomes:    adminOutcomes,
		Note:        "failure with package_on_hold when a package is held for one of the devices; no command is issued then.",
	},
	CodeDeviceUpdatesRun: {
		Code: CodeDeviceUpdatesRun, Emitted: true,
		Description: "A device finished a run of regular updates (paddock-updates.timer) or of the daily security updates (unattended-upgrades) (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "result is ok, failed or timeout; reboot_required is reported, Paddock never reboots for updates.",
	},
	CodeDeviceStaleWarning: {
		Code: CodeDeviceStaleWarning, Emitted: true,
		Description: "A device has not contacted Paddock for longer than the organization's staleness warning threshold (actor: system).",
		Params:      []string{"last_contact_at", "threshold_h"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Recorded once per crossing; the device's next contact ends it with device.stale_cleared.",
	},
	CodeDeviceStaleCritical: {
		Code: CodeDeviceStaleCritical, Emitted: true,
		Description: "A device has not contacted Paddock for longer than the organization's critical staleness threshold: it is presumed lost and listed on the attention page (actor: system).",
		Params:      []string{"last_contact_at", "threshold_h"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Recorded once per crossing; the device's next contact ends it with device.stale_cleared.",
	},
	CodeDeviceStaleCleared: {
		Code: CodeDeviceStaleCleared, Emitted: true,
		Description: "A device that was stale contacted Paddock again; its staleness alert and the presumed lost mark are cleared (actor: system).",
		Params:      []string{"last_contact_at", "previous"},
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodePlatformOSVStale: {
		Code: CodePlatformOSVStale, Emitted: true,
		Description: "Ubuntu's vulnerability data (OSV) has not been updated successfully for 3 days; findings keep the last data (actor: system, platform pseudo-organization).",
		Params:      []string{"last_success_at", "last_error"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Recorded once per stale period; the next successful download or import ends it. last_success_at is missing if no download ever succeeded.",
	},
	CodeAPITokenCreated: {
		Code: CodeAPITokenCreated, Emitted: true,
		Description: "An organization administrator or operator created an API token. The token secret is never recorded.",
		Params:      []string{"name", "role", "expires_at", "prefix"},
		Outcomes:    adminOutcomes,
		Note:        "Requires a fresh step-up: denied with step_up_required without one (an API token never has one, so a token cannot create tokens); denied with forbidden for a role above the creator's.",
	},
	CodeAPITokenRevoked: {
		Code: CodeAPITokenRevoked, Emitted: true,
		Description: "An API token was revoked; it is refused from its next request on.",
		Params:      []string{"name", "role", "created_by"},
		Outcomes:    adminOutcomes,
		Note:        "Denied with forbidden for an operator revoking another administrator's token and for a request made with an API token.",
	},
	CodeAPITokenUseDenied: {
		Code: CodeAPITokenUseDenied, Emitted: true,
		Description: "A request authenticated with a revoked or expired API token was refused (actor: anonymous, with the token's name).",
		Params:      []string{"name", "reason"},
		Outcomes:    []Outcome{OutcomeDenied},
		Note:        "reason is revoked or expired. Unknown or malformed secrets are not recorded.",
	},
	CodeAutoinstallGenerated: {
		Code: CodeAutoinstallGenerated, Emitted: true,
		Description: "An administrator or operator generated a Paddock autoinstall for one device from an enrollment configuration; the disk passphrase and the token in it are never recorded.",
		Params:      []string{"release", "agent_version"},
		Outcomes:    adminOutcomes,
		Note:        "release is the Ubuntu release (24.04 or 26.04); agent_version is the release whose packages the device installs.",
	},
	CodeActionFinalizedUnknown: {
		Code: CodeActionFinalizedUnknown, Emitted: false,
		Description: "Metric label of the reaper. The reaper finalizes a stuck action with outcome unknown under the original action code; this code is never emitted as an event.",
	},
}

// Lookup returns the definition of a registered code.
func Lookup(c Code) (Definition, bool) {
	d, ok := registry[c]
	return d, ok
}

// Registered reports whether c is part of the registry and may be emitted as an event.
func (c Code) Registered() bool {
	d, ok := registry[c]
	return ok && d.Emitted
}

// Definitions returns all registry entries sorted by code.
func Definitions() []Definition {
	out := make([]Definition, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

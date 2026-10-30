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

	CodeEnrollmentTokenCreated   Code = "enrollment_token.created"
	CodeEnrollmentTokenRevoked   Code = "enrollment_token.revoked"
	CodeDeviceEnrolled           Code = "device.enrolled"
	CodeDeviceApproved           Code = "device.approved"
	CodeDeviceRejected           Code = "device.rejected"
	CodeDeviceQuarantineReleased Code = "device.quarantine_released"
	CodeDeviceRetired            Code = "device.retired"
	CodeDeviceGroupsChanged      Code = "device.groups_changed"
	CodeDeviceOwnersChanged      Code = "device.owners_changed"
	CodeDeviceNameChanged        Code = "device.name_changed"
	// Uninstall (plan M8d decisions 37, 38 and 41).
	CodeDeviceUninstallRequested   Code = "device.uninstall_requested"
	CodeDeviceUninstallCancelled   Code = "device.uninstall_cancelled"
	CodeDeviceUninstalled          Code = "device.uninstalled"
	CodeDeviceAgentUpdateRequested Code = "device.agent_update_requested"
	CodeDeviceCloneSuspected       Code = "device.clone_suspected"
	CodeDeviceBundleApplied        Code = "device.bundle_applied"
	CodeDeviceBundleRejected       Code = "device.bundle_rejected"
	CodeDeviceConfigDriftCorrected Code = "device.config_drift_corrected"
	CodeDeviceAgentUpdated         Code = "device.agent_updated"
	CodeDeviceAgentUpdateFailed    Code = "device.agent_update_failed"
	CodeDeviceAgentRolledBack      Code = "device.agent_rolled_back"
	CodeDeviceAgentRollbackFailed  Code = "device.agent_rollback_failed"
	CodeDeviceAgentEventsDropped   Code = "device.agent_events_dropped"

	// In-place encryption (plan M8e decisions 7–9).
	CodeDeviceEncryptRequested        Code = "device.encrypt_requested"
	CodeDeviceEncryptCancelled        Code = "device.encrypt_cancelled"
	CodeDeviceDiskConversionPrepared  Code = "device.disk_conversion_prepared"
	CodeDeviceDiskConversionStarted   Code = "device.disk_conversion_started"
	CodeDeviceDiskConversionCompleted Code = "device.disk_conversion_completed"
	CodeDeviceDiskConversionFailed    Code = "device.disk_conversion_failed"
	CodeDeviceDiskConversionAborted   Code = "device.disk_conversion_aborted"

	// Supervisor package updates (plan M8d decision 33).
	CodeDeviceSupervisorUpdated      Code = "device.supervisor_updated"
	CodeDeviceSupervisorUpdateFailed Code = "device.supervisor_update_failed"
	CodeManagedFileCreated           Code = "managed_file.created"
	CodeManagedFileUpdated           Code = "managed_file.updated"
	CodeManagedFileDeleted           Code = "managed_file.deleted"
	CodeManagedUnitCreated           Code = "managed_unit.created"
	CodeManagedUnitUpdated           Code = "managed_unit.updated"
	CodeManagedUnitDeleted           Code = "managed_unit.deleted"

	CodeAgentReleaseCreated          Code = "agent_release.created"
	CodeAgentReleaseArtifactUploaded Code = "agent_release.artifact_uploaded"
	CodeAgentReleasePublished        Code = "agent_release.published"
	CodeAgentReleaseImported         Code = "agent_release.imported" // from the configured release source (ADR 0043)
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
	CodeRetentionPurged             Code = "retention.purged"
	CodeDeviceInventoryPurged       Code = "device.inventory_purged"
	CodeDeviceInventoryHostKept     Code = "device.inventory_host_kept"
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
	CodeDeviceHeaderEscrowRefused  Code = "device.header_escrow_refused"
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

	CodePlatformOSVStale    Code = "platform.osv_stale"
	CodePlatformOSVImported Code = "platform.osv_imported"

	// API tokens (plan M6c decisions 4, 5 and 9).
	CodeAPITokenCreated   Code = "api_token.created"
	CodeAPITokenRevoked   Code = "api_token.revoked"
	CodeAPITokenUseDenied Code = "api_token.use_denied" //nolint:gosec // an audit code, not a credential

	// Declarative configuration (plan M6c decision 16).
	CodeConfigApplied Code = "config.applied"

	// Restore commands of paddock-server admin (plan M6c decision 21).
	CodeOrganizationRecompileRequested Code = "organization.recompile_requested"
	CodePlatformBundleSeqBumped        Code = "platform.bundle_seq_bumped"
	CodePlatformCacheRebuilt           Code = "platform.cache_rebuilt"

	// IP allow list of the administrative surfaces (plan M7a decision 14).
	CodePlatformIPAllowlistChanged  Code = "platform.ip_allowlist_changed"
	CodePlatformIPAllowlistDenied   Code = "platform.ip_allowlist_denied"
	CodePlatformIPAllowlistDisabled Code = "platform.ip_allowlist_disabled"

	// Step-up on the effective class, path tiers, revocable sessions and the escrow size bound (plan M8s §6.4).
	CodeAdminSessionsRevoked                Code = "admin.sessions_revoked"
	CodePlatformSessionsEnded               Code = "platform.sessions_ended"
	CodePermissionProfileRootGrantConfirmed Code = "permission_profile.root_grant_confirmed"
	CodeManagedFileSensitiveConfirmed       Code = "managed_file.sensitive_confirmed"
	CodeOrganizationSecurityReviewRequired  Code = "organization.security_review_required"
	CodeDeviceHeaderObjectRejected          Code = "device.header_object_rejected"
	CodeSettingsManagedFilesChanged         Code = "settings.managed_files_changed"

	// Automatic unseal of OpenBao (ADR 0035, plan M8u §6.4).
	CodePlatformAutoUnsealEnabled   Code = "platform.auto_unseal_enabled"
	CodePlatformAutoUnsealDisabled  Code = "platform.auto_unseal_disabled"
	CodePlatformOpenBaoAutoUnsealed Code = "platform.openbao_auto_unsealed"

	// Evidence integrity: event gaps, counter resets, clock drift, chain verification and role grants (plan M8b
	// decision 9).
	CodeDeviceEventGap               Code = "device.event_gap"
	CodeDeviceEventGapFilled         Code = "device.event_gap_filled"
	CodeDeviceEventSeqReset          Code = "device.event_seq_reset"
	CodeDeviceClockDrift             Code = "device.clock_drift"
	CodeDeviceClockDriftCleared      Code = "device.clock_drift_cleared"
	CodeAuditChainVerified           Code = "audit.chain_verified"
	CodeAuditChainVerificationFailed Code = "audit.chain_verification_failed"
	CodeAdminRoleGranted             Code = "admin.role_granted"
	CodeAdminRoleRevoked             Code = "admin.role_revoked"

	// MCP policies per organization and platform and the per-user write opt-in (ADR 0044, plan M14 §6.3).
	CodeOrganizationMCPPolicyChanged Code = "organization.mcp_policy_changed"
	CodePlatformMCPPolicyChanged     Code = "platform.mcp_policy_changed"
	CodeAdminMCPWriteEnabled         Code = "admin.mcp_write_enabled"  //nolint:gosec // an audit code, not a credential
	CodeAdminMCPWriteDisabled        Code = "admin.mcp_write_disabled" //nolint:gosec // an audit code, not a credential

	// Privacy settings per organization (ADR 0032 §2, plan M10 §6.4).
	CodeSettingsPrivacyChanged Code = "settings.privacy_changed"

	// Evidence export (ADR 0032 §5, plan M10 §6.4).
	CodeAuditExportRequested Code = "audit.export_requested"
	CodeAuditExportCompleted Code = "audit.export_completed"
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

// mcpPolicyParams are the parameters of organization.mcp_policy_changed and platform.mcp_policy_changed.
var mcpPolicyParams = []string{"enabled", "write_enabled", "mode", "allowed_count"}

// deviceEventParams are the parameters of audit events reported by devices (plan M2a decision 14, M2b decisions 9,
// 11, 12 and 16, M3b decision 5); each event carries the subset its type defines.
var deviceEventParams = []string{
	"event_seq", "occurred_at", "bundle_version", "reason", "resource", "version", "changed", "errors", "resource_ids",
	"from_version", "outcome", "count", "from_seq", "to_seq", "stage", "message", "username", "sessions_locked",
	"sessions_terminated", "group", "removed", "file", "quarantined_as", "sha256_before", "sha256_after",
	"generation", "service", "at", "field", "before", "after", "unit",
	"kind", "started_at", "finished_at", "upgraded", "held_back", "reboot_required", "result", "error", "volume",
	"command_id", "mode", "local_admin", "tpm", "steps",
	"conversion_id", "layout", "data_bytes", "duration_s", "init_s", "init_result", "by",
}

var registry = map[Code]Definition{
	CodeAdminLogin: {
		Code: CodeAdminLogin, Emitted: true,
		Description: "An administrator signed in to the portal or opened an MCP session, or a sign-in was rejected.",
		Params:      []string{"role", "organization_slug", "reason", "denial_reason", "previous_role", "channel", "renewal", "fallback"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied},
		Note:        "Platform administrators and rejected sign-ins without a resolvable organization are recorded in the platform pseudo-organization. previous_role is the role of the session a role switch ended (ADR 0045); absent for a plain sign-in. channel is portal or mcp; renewal is true when an MCP session was renewed with a refreshed token (ADR 0044). fallback is organization_inactive when a plain sign-in of an identity with the platform role and an organization role entered the platform role because the organization is unknown or not active (ADR 0045 amendment 2026-10-29).",
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
		Params:      []string{"name", "staleness_warning_h", "staleness_critical_h", "agent_update_policy", "disk_unlock_mode"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied},
	},
	CodeDeviceGroupUpdated: {
		Code: CodeDeviceGroupUpdated, Emitted: true,
		Description: "A device group was renamed or its description changed.",
		Params: []string{"name", "old_name", "description_changed", "staleness_warning_h", "staleness_critical_h",
			"agent_update_policy", "disk_unlock_mode"},
		Outcomes: []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied},
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
		Params:      []string{"hostname", "state", "key_protection", "enrolled_with", "auto_approve_withheld"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "enrolled_with is the ID of the enrollment token. auto_approve_withheld is root_grant when an auto-approve token's device would have given someone root and the device was enrolled pending instead (plan M8s decision 7g-sexies). A failure carries the rejection reason as error_code: invalid_token, token_revoked, token_expired, token_exhausted or invalid_request.",
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
		Params:      []string{"hostname", "from_state", "reason", "conversion_cancelled", "conversion_id", "conversion_phase"},
		Outcomes:    adminOutcomes,
		Note:        "reason is uninstalled when the device retired itself by reporting its removal (actor: system). conversion_cancelled (before_delivery) and conversion_id when the retirement withdrew an undelivered encrypt_disk command; conversion_id and conversion_phase (requested, prepared or encrypting) when it left an open in-place encryption alone.",
	},
	CodeDeviceUninstallRequested: {
		Code: CodeDeviceUninstallRequested, Emitted: true,
		Description: "An organization administrator asked, with a step-up, to remove Paddock from a device; mode leave keeps everything else working, mode reset also removes Himmelblau, the managed files and the managed local administrator.",
		Params:      []string{"hostname", "mode", "clear_tpm", "keep_local_admin", "reason", "command_id", "report_overdue"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceUninstallCancelled: {
		Code: CodeDeviceUninstallCancelled, Emitted: true,
		Description: "An organization administrator cancelled an uninstall before the device received it, or withdrew one whose removal report is overdue (report_overdue). A Lock or Destroy request that cancels an uninstall records no event of this code: it is recorded on revocation.requested (uninstall_cancelled).",
		Params:      []string{"hostname", "mode", "command_id", "report_overdue"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceUninstalled: {
		Code: CodeDeviceUninstalled, Emitted: true,
		Description: "The device reported that it removed Paddock and the outcome of every step (actor: the device); only the report of the open request whose command succeeded retires the device, by the next event.",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "The param outcome is completed or partial (a step failed); steps maps every step to done, skipped or failed:<message>. helper_failed: the agent could not start the removal, nothing was removed, the request ends and the device is not retired.",
	},
	CodeDeviceEncryptRequested: {
		Code: CodeDeviceEncryptRequested, Emitted: true,
		Description: "An organization administrator asked, with a step-up and a backup acknowledgement, to encrypt the disk of an unencrypted device in place; the device prepares itself and converts at its next restart.",
		Params:      []string{"hostname", "reason", "backup_confirmed", "command_id", "conversion_id"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceEncryptCancelled: {
		Code: CodeDeviceEncryptCancelled, Emitted: true,
		Description: "An organization administrator cancelled an in-place encryption with a step-up: the undelivered command was withdrawn, or the device was sent a signed abort that it executes only before its restart.",
		Params:      []string{"hostname", "command_id", "conversion_id", "mode"},
		Outcomes:    adminOutcomes,
		Note:        "mode is command_cancelled (the encrypt_disk command was withdrawn, the conversion is cancelled) or abort_sent (command_id is then the encrypt_disk_abort command; the conversion keeps its phase until the device answers).",
	},
	CodeDeviceDiskConversionPrepared: {
		Code: CodeDeviceDiskConversionPrepared, Emitted: true,
		Description: "The device escrowed the conversion key and built the initrd for its in-place encryption; it waits for a restart (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Params conversion_id, layout (lvm or plain), volume (the LUKS UUID the header will have) and data_bytes.",
	},
	CodeDeviceDiskConversionStarted: {
		Code: CodeDeviceDiskConversionStarted, Emitted: true,
		Description: "The device initialised LUKS2 on its root partition at the restart and encrypts the remaining data in the background (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Params conversion_id, volume, init_s and init_result (ok, <stage>:<reason> or unknown). A conversion that was failed or cancelled is adopted as encrypting; when the device has another open conversion the event is recorded and changes no conversion.",
	},
	CodeDeviceDiskConversionCompleted: {
		Code: CodeDeviceDiskConversionCompleted, Emitted: true,
		Description: "The device finished encrypting its root partition; the recovery key, the TPM unlock and the header escrow follow as for a newly installed device (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Params conversion_id, volume, data_bytes and duration_s.",
	},
	CodeDeviceDiskConversionFailed: {
		Code: CodeDeviceDiskConversionFailed, Emitted: true,
		Description: "The in-place encryption of a device failed or was skipped at the named stage; stages preflight, prepare and init leave the device unencrypted, stage resume leaves it bootable with the encryption unfinished (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Params conversion_id, stage, reason and volume.",
	},
	CodeDeviceDiskConversionAborted: {
		Code: CodeDeviceDiskConversionAborted, Emitted: true,
		Description: "The device abandoned a prepared in-place encryption before its restart on an administrator's cancel from the portal or an operator's command at the device; the disk is unchanged and the device unencrypted (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Params conversion_id and by (admin or operator).",
	},
	CodeDeviceGroupsChanged: {
		Code: CodeDeviceGroupsChanged, Emitted: true,
		Description: "The device group memberships of a device were replaced.",
		Params:      []string{"hostname", "added", "removed"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceNameChanged: {
		Code: CodeDeviceNameChanged, Emitted: true,
		Description: "An administrator set or cleared the managed name of a device; the device applies it as its hostname at its next check-in.",
		Params:      []string{"hostname", "name", "previous_name"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceAgentUpdateRequested: {
		Code: CodeDeviceAgentUpdateRequested, Emitted: true,
		Description: "An administrator asked a device to install the offered agent release at its next check-in, outside its rollout wave and regardless of the organization's update policy.",
		Params:      []string{"hostname", "version", "from_version"},
		Outcomes:    adminOutcomes,
	},
	CodeDeviceOwnersChanged: {
		Code: CodeDeviceOwnersChanged, Emitted: true,
		Description: "An administrator changed the owners of a device.",
		Params:      []string{"hostname", "added", "removed", "owners"},
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
		Note:        "outcome is signature_invalid (also a signed comment that does not name the version and architecture), downgrade_refused or self_test_failed. The outcome rollback_failed is recorded as device.agent_rollback_failed instead (ADR 0024); servers older than that decision recorded it here.",
	},
	CodeDeviceAgentRolledBack: {
		Code: CodeDeviceAgentRolledBack, Emitted: true,
		Description: "A device's supervisor rolled a new agent version back because it crashed or did not report healthy within its probation (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceAgentRollbackFailed: {
		Code: CodeDeviceAgentRollbackFailed, Emitted: true,
		Description: "A new agent version failed its probation on a device and the supervisor's flip back to the previous version failed; the device keeps running the new version and retries the rollback until it succeeds (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Reported as agent.update_failed with outcome rollback_failed (ADR 0024); device.agent_rolled_back follows once the rollback succeeds.",
	},
	CodeDeviceSupervisorUpdated: {
		Code: CodeDeviceSupervisorUpdated, Emitted: true,
		Description: "The device installed the supervisor package of the current release and checked in with it (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "outcome is updated.",
	},
	CodeDeviceSupervisorUpdateFailed: {
		Code: CodeDeviceSupervisorUpdateFailed, Emitted: true,
		Description: "Installing the supervisor package failed, or the supervisor was restored from its backup because the agent did not check in within 10 minutes (actor: the device). It counts toward the failure threshold of the release's rollout like a failed agent update, except the outcome rolled_back_unreachable (the agent's check-ins did not reach the server).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Reported as agent.supervisor_updated (ADR 0024); outcome is install_failed, rolled_back, or rolled_back_unreachable (the server was unreachable; the device retries the version after 24 hours, at most 3 times).",
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
		Description: "A device found a member of a privileged local group (sudo, admin, wheel) that is not a break-glass account and removed it, or kept it because no break-glass account is a member of that group (reason last_admin) (actor: the device).",
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
		Params:      []string{"path", "device_group_id", "mode", "owner", "group", "tier"},
		Outcomes:    adminOutcomes,
	},
	CodeManagedFileUpdated: {
		Code: CodeManagedFileUpdated, Emitted: true,
		Description: "A managed file definition was changed.",
		Params:      []string{"path", "device_group_id", "mode", "owner", "group", "tier", "content_changed", "old_path"},
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
	CodeAgentReleaseImported: {
		Code: CodeAgentReleaseImported, Emitted: true,
		Description: "A platform administrator imported an agent release from the configured release source (GitHub); every file was verified with the release public key before anything was stored.",
		Params:      []string{"source", "source_url", "version", "newest_stored", "files"},
		Outcomes:    adminOutcomes,
		Note:        "Denied with step_up_required without a fresh step-up, release_source_disabled while the source is off, forbidden for a non-platform principal. The created, uploaded and published events of the release are recorded as well, by the same actor. No token or credential is recorded. Platform pseudo-organization.",
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
		Params:      []string{"changed", "login_history_enabled", "login_history_days", "login_history_deleted"},
		Outcomes:    adminOutcomes,
	},
	CodeRetentionPurged: {
		Code: CodeRetentionPurged, Emitted: true,
		Description: "A retention job deleted expired rows of one store (actor: system). store is device_login_event (recorded in the organization, only when rows were deleted), device_user_seen, read_audit_window (recorded in the organization, only when rows were deleted), audit_index (one event per dropped partition, platform pseudo-organization), audit_exports (one event per expired export, in its organization) or retired_inventory (only as failure, once per organization and round: upstream_unavailable when the round skipped the organization's retired devices because the Fleet step failed three times in a row with upstream_unavailable, or the error of loading the privacy settings or listing the first page of retired devices; their evidence is otherwise device.inventory_purged).",
		Params:      []string{"store", "deleted", "cutoff", "partition", "export_id"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "Deletion evidence (ISO/IEC 27001 A.8.10); ADR 0032.",
	},
	CodeDeviceInventoryPurged: {
		Code: CodeDeviceInventoryPurged, Emitted: true,
		Description: "The retention job deleted the inventory of a retired device in Paddock and its host in Fleet, retired_inventory_days after retirement (actor: system). software, findings and policy_results are the deleted rows. fleet_host_in_use is the answer of the check across all organizations before the host is deleted: ref (another device of any organization references the host; the host stays, the device's Paddock rows go), hardware (an active, quarantined or pending device with the same hardware has no reference yet) or none; it is absent when the device had no Fleet host or the check did not run. On none, Fleet's last check-in of the host is read first: fleet_host_seen_at is that time when known, and a host seen after the device's retirement and within the last 7 days is still in use. fleet_host_kept names why the host stays with the device's host reference while its other rows go: hardware or seen_recently; the device is checked again next round, and an event is recorded only when that answer changes (device.inventory_host_kept after 30 unchanged rounds). fleet_host_deleted is true only when the host was deleted or Fleet no longer knew it. A failure keeps all Paddock rows (the counts are the rows kept) and the device is retried next round: upstream_unavailable when Fleet failed or could not be reached (also an answer from a proxy in front of Fleet or a redirect), invalid_state when Fleet refused this host with its own error body, another code when a check failed or the device changed after it was listed.",
		Params: []string{"hostname", "retired_at", "software", "findings", "policy_results", "fleet_host_deleted", "fleet_host_in_use",
			"fleet_host_kept", "fleet_host_seen_at"},
		Outcomes: []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:     "Deletion evidence (ISO/IEC 27001 A.8.10); ADR 0032.",
	},
	CodeDeviceInventoryHostKept: {
		Code: CodeDeviceInventoryHostKept, Emitted: true,
		Description: "The retention job has kept a retired device's Fleet host and host reference for rounds unchanged rounds with the same answer fleet_host_kept (hardware or seen_recently, see device.inventory_purged) and records it once (actor: system). Nothing is deleted; the device is still checked every round and records device.inventory_purged again when the answer changes. A failure means the notice could not be recorded; the next round retries it.",
		Params:      []string{"hostname", "retired_at", "fleet_host_kept", "rounds"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "Notice; ADR 0032.",
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
		Params:      []string{"name", "class", "commands", "root_equivalent", "effective_class"},
		Outcomes:    adminOutcomes,
		Note:        "root_equivalent is true when a command of the profile hands out root on its own or in combination (catalog version in the effective profile).",
	},
	CodePermissionProfileUpdated: {
		Code: CodePermissionProfileUpdated, Emitted: true,
		Description: "A permission profile was changed.",
		Params:      []string{"name", "class", "old_class", "commands", "root_equivalent", "effective_class"},
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
		Params:      []string{"profile", "class", "root_equivalent", "effective_class", "subject_type", "subject_id", "device_group_id"},
		Outcomes:    adminOutcomes,
	},
	CodeProfileAssignmentUpdated: {
		Code: CodeProfileAssignmentUpdated, Emitted: true,
		Description: "The device group scope of a profile assignment was changed.",
		Params:      []string{"profile", "class", "root_equivalent", "effective_class", "subject_type", "subject_id", "device_group_id", "old_device_group_id"},
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
		Description: "A device found the keyslots of one of its encrypted volumes changed outside Paddock; it escrows that volume's header again (actor: the device).",
		Params:      deviceEventParams,
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "volume is the LUKS UUID of the volume (absent for devices before PDK-009, which watch the root volume only); before and after list the kind of every keyslot (tpm2+pin, tpm2, recovery, password, or another token type).",
	},
	CodeDeviceHeaderEscrowRefused: {
		Code: CodeDeviceHeaderEscrowRefused, Emitted: true,
		Description: "The worker refused a LUKS header escrow of a device for a 33rd distinct volume: a revocation token carries at most 32 volumes (actor: the device).",
		Params:      []string{"volume", "generation", "volumes"},
		Outcomes:    []Outcome{OutcomeFailure},
		Note:        "error_code too_many_volumes; volume is the refused volume's LUKS UUID, volumes the number of volumes the device already escrows. The device reports the escrow as failed and retries later.",
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
		Params:      []string{"hostname", "volume", "generation"},
		Note:        "volume is the LUKS UUID of the header's volume; absent for a root volume header escrowed before PDK-009 whose UUID the device has not reported yet.",
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
		Params: []string{"action", "hostname", "request_id", "uninstall_cancelled", "uninstall_command_id",
			"conversion_cancelled", "conversion_id", "conversion_phase"},
		Outcomes: adminOutcomes,
		Note:     "action is lock or destroy. uninstall_cancelled (before_delivery, or after_delivery when the device had received the uninstall command) and uninstall_command_id when the request cancelled an uninstall of the device in the same transaction; no separate device.uninstall_cancelled is recorded. conversion_cancelled (before_delivery) and conversion_id when the request withdrew an undelivered encrypt_disk command; conversion_id and conversion_phase (requested, prepared or encrypting) when it left an open in-place encryption alone. denied with revocation_disabled while PADDOCK_REVOCATION_ENABLED is off, revocation_frozen while the administrator is frozen after a limit was exceeded.",
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
		Params:      []string{"action", "hostname", "request_id", "requested_by", "expires_at", "volumes"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "volumes counts the volumes besides the root volume the token lets the device erase: those with a confirmed header escrow, so that the lock stays restorable (always 0 for a device whose paddock-revoke predates PDK-009).",
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
		Description: "A device confirmed a revocation before its forced reboot: every key-bearing keyslot of every LUKS volume of the device is erased (actor: the device).",
		Params:      []string{"action", "request_id", "erased", "slots_before", "slots_after", "volumes", "unresolved", "skipped_not_escrowed", "shared_uuid", "status"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "status failed means the device reported that the erasure did not complete. erased is true only if every volume has no key-bearing keyslot left and no crypttab entry is unresolved; slots_before and slots_after are sums of key-bearing keyslots over the reported volumes (a key-less reencrypt keyslot of an unfinished reencryption is not counted; devices before PDK-400 count every keyslot), volumes counts the reported volumes (failed ones included) and unresolved the crypttab entries the device could not erase with certainty (both 0 for devices before M4c.1); skipped_not_escrowed counts the volumes a Lock left alone because their header escrow was not confirmed (PDK-009), shared_uuid the volumes whose LUKS UUID another volume or the root volume has (a Destroy erases them, a Lock skips them).",
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
			"staleness_warning_h", "staleness_critical_h", "agent_update_policy"},
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
		Params:      []string{"last_contact_at", "threshold_h", "source"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Recorded once per crossing; the device's next contact ends it with device.stale_cleared.",
	},
	CodeDeviceStaleCritical: {
		Code: CodeDeviceStaleCritical, Emitted: true,
		Description: "A device has not contacted Paddock for longer than the organization's critical staleness threshold: it is presumed lost and listed on the attention page (actor: system).",
		Params:      []string{"last_contact_at", "threshold_h", "source"},
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
		Description: "A request authenticated with a revoked or expired API token, or a token whose creator was disabled or lost the required role, was refused (actor: anonymous, with the token's name).",
		Params:      []string{"name", "reason"},
		Outcomes:    []Outcome{OutcomeDenied},
		Note:        "reason is revoked, expired or creator_inactive; creator_inactive is recorded at most once per token and 15 minutes. Unknown or malformed secrets are not recorded.",
	},
	CodeOrganizationRecompileRequested: {
		Code: CodeOrganizationRecompileRequested, Emitted: true,
		Description: "An operator ran paddock-server admin recompile --all: every active device of the organization gets a new bundle version, also when its content is unchanged (actor: system).",
		Params:      []string{"organizations_total"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "One event per organization; part of the restore order of docs/operations/paddockctl.md.",
	},
	CodePlatformBundleSeqBumped: {
		Code: CodePlatformBundleSeqBumped, Emitted: true,
		Description: "An operator ran paddock-server admin bump-bundle-seq after a database restore: the bundle sequence of every device was raised (actor: system, platform pseudo-organization).",
		Params:      []string{"by", "devices"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
	},
	CodePlatformCacheRebuilt: {
		Code: CodePlatformCacheRebuilt, Emitted: true,
		Description: "An operator ran paddock-server admin rebuild-cache: the enrollment tokens, device keys and sequence numbers of the gateway's cache were rewritten from PostgreSQL (actor: system, platform pseudo-organization).",
		Params:      []string{"organizations"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "Bundle pointers and time tickets are rewritten by the running compiler within 60 s.",
	},
	CodePlatformIPAllowlistChanged: {
		Code: CodePlatformIPAllowlistChanged, Emitted: true,
		Description: "A platform administrator added, updated or removed an entry of the IP allow list of the administrative surfaces, or an operator added one with paddock-server admin allowlist add (actor: system).",
		Params:      []string{"action", "cidr", "label", "previous_cidr", "previous_label", "entries", "consequence"},
		Outcomes:    adminOutcomes,
		Note:        "Target is the entry (type ip_allowlist_entry, display the CIDR); action is added, updated or removed; entries is the count after the change; consequence is none, lockout (the caller's own address is no longer covered) or disable (the last entry was removed). Denied with step_up_required without a fresh step-up, forbidden for a non-platform principal; failure with lockout_confirmation_required or disable_confirmation_required when the consequence was not confirmed, already_exists for a duplicate CIDR. Platform pseudo-organization.",
	},
	CodePlatformIPAllowlistDenied: {
		Code: CodePlatformIPAllowlistDenied, Emitted: true,
		Description: "A request to the admin surface was refused because the client address is outside the IP allow list (actor: anonymous with the address); aggregated per address and window.",
		Params:      []string{"ip", "count", "window_seconds", "first_at", "last_at", "aggregated", "distinct_ips", "distinct_ips_capped"},
		Outcomes:    []Outcome{OutcomeDenied},
		Note:        "Per api replica and window (10 minutes): the first denial of an address is recorded at once (count 1, aggregated false) for at most 20 addresses; at the window's end one summary per address with further denials (count, first_at, last_at, aggregated true) and one for every address beyond the 20 (ip empty, distinct_ips; distinct_ips_capped true when more than 10000 addresses made distinct_ips a lower bound). The immediate and summary events of one address and window share the correlation ID ipal-<window start>-<ip>. Edge denials are not audited; the exact count is the metric paddock_ip_allowlist_denied_total. Platform pseudo-organization.",
	},
	CodePlatformIPAllowlistDisabled: {
		Code: CodePlatformIPAllowlistDisabled, Emitted: true,
		Description: "The IP allow list of the administrative surfaces was switched off on the host (actor: system): paddock-server admin allowlist disable removed every entry, or the api started with PADDOCK_IP_ALLOWLIST_BYPASS.",
		Params:      []string{"method", "entries_removed", "removed"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "method is cli (removed lists the CIDRs) or env (recorded once per api start with entries_removed 0; the entries stay and apply again once the variable is removed). Platform pseudo-organization.",
	},
	CodeConfigApplied: {
		Code: CodeConfigApplied, Emitted: true,
		Description: "A declarative configuration (PUT /api/v1/config, paddockctl apply) was applied in one transaction; the change set lists every change.",
		Params:      []string{"change_set_id", "created", "updated", "deleted", "sections"},
		Outcomes:    adminOutcomes,
		Note:        "Target is the change set; an apply without changes records zeros and no change set. Dry runs are not recorded. A failure carries the problem code of the refusing resource, and nothing is applied.",
	},
	CodePlatformOSVImported: {
		Code: CodePlatformOSVImported, Emitted: true,
		Description: "An operator imported Ubuntu's vulnerability data (OSV) from a file with paddock-server osv import (actor: system osv-import, platform pseudo-organization).",
		Params:      []string{"records", "entries", "data_version"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "The file path is not recorded. data_version is the version of the data after a successful import.",
	},
	CodeAutoinstallGenerated: {
		Code: CodeAutoinstallGenerated, Emitted: true,
		Description: "An administrator or operator generated a Paddock autoinstall for one device from an enrollment configuration; the disk passphrase and the token in it are never recorded.",
		Params:      []string{"release", "agent_version", "unlock_mode"},
		Outcomes:    adminOutcomes,
		Note:        "release is the Ubuntu release (24.04 or 26.04); agent_version is the release whose packages the device installs.",
	},
	CodeAdminSessionsRevoked: {
		Code: CodeAdminSessionsRevoked, Emitted: true,
		Description: "Every portal session of an administrator account was ended by the server because the account's role or state changed (actor: system).",
		Params:      []string{"reason", "sessions", "old_role", "new_role"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "reason is step_up_role_mismatch, role_changed, deactivated or removed; sessions is the number of sessions ended; old_role and new_role are empty when unchanged or none. Target is the administrator account (admin_account), or the platform administrator (platform_admin) in the platform pseudo-organization.",
	},
	CodePlatformSessionsEnded: {
		Code: CodePlatformSessionsEnded, Emitted: true,
		Description: "A platform administrator ended every portal session of the installation and every identity-provider browser session of every portal user.",
		Params:      []string{"generation", "identity_users", "identity_sessions_ended"},
		Outcomes:    adminOutcomes,
		Note:        "generation is the new session generation; every session of an older generation is invalid. identity_users is the number of portal users listed in the identity provider, identity_sessions_ended the number of their identity-provider sessions ended. Failure with upstream_unavailable when the identity provider failed; the portal sessions are ended already. Denied with step_up_required without a fresh step-up, forbidden for a non-platform principal. Platform pseudo-organization.",
	},
	CodePermissionProfileRootGrantConfirmed: {
		Code: CodePermissionProfileRootGrantConfirmed, Emitted: true,
		Description: "An organization administrator confirmed, with a step-up, a root-equivalent permission profile that existed before the step-up rule covered it.",
		Params:      []string{"name", "effective_class", "commands"},
		Outcomes:    adminOutcomes,
		Note:        "Denied with step_up_required without a fresh step-up, forbidden for another role; failure with invalid_state when the profile is not effectively Full.",
	},
	CodeManagedFileSensitiveConfirmed: {
		Code: CodeManagedFileSensitiveConfirmed, Emitted: true,
		Description: "An organization administrator confirmed, with a step-up, a managed file on a sensitive path that existed before the path tiers.",
		Params:      []string{"path", "device_group_id", "tier"},
		Outcomes:    adminOutcomes,
		Note:        "Denied with step_up_required without a fresh step-up, forbidden for another role; failure with invalid_state when the file is not on a sensitive path.",
	},
	CodeOrganizationSecurityReviewRequired: {
		Code: CodeOrganizationSecurityReviewRequired, Emitted: true,
		Description: "An operator ran paddock-server admin security-review: the organization has unconfirmed root-equivalent profiles, unconfirmed sensitive files or files on denied paths (actor: system).",
		Params:      []string{"root_grant_profiles", "sensitive_files", "denied_files"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "Recorded once per run in every organization where at least one count is greater than zero.",
	},
	CodeDeviceHeaderObjectRejected: {
		Code: CodeDeviceHeaderObjectRejected, Emitted: true,
		Description: "The worker found an escrowed LUKS header object whose size differs from the announced size and marked the escrow failed without reading it; the object stays for the operator (actor: the device).",
		Params:      []string{"generation", "volume", "declared_size", "object_size"},
		Outcomes:    []Outcome{OutcomeFailure},
	},
	CodeSettingsManagedFilesChanged: {
		Code: CodeSettingsManagedFilesChanged, Emitted: true,
		Description: "An organization administrator changed, with a step-up, the operator roots of the managed files: the directories below which operators may manage files without a step-up.",
		Params:      []string{"old_operator_roots", "operator_roots"},
		Outcomes:    adminOutcomes,
		Note:        "Denied with step_up_required without a fresh step-up and for API tokens, forbidden for another role; failure with path_not_allowed for a root outside the rules of ADR 0034 (amendment 2026-10-16).",
	},
	CodePlatformAutoUnsealEnabled: {
		Code: CodePlatformAutoUnsealEnabled, Emitted: true,
		Description: "A platform administrator acknowledged the automatic-unseal disclaimer with a step-up and enabled the setting.",
		Params:      []string{"disclaimer_version", "acknowledgement", "previous_state"},
		Outcomes:    adminOutcomes,
		Note:        "Denied with step_up_required without a fresh step-up, forbidden for a non-platform principal; failure with disclaimer_outdated or invalid_request when the version or the sentence does not match. Platform pseudo-organization.",
	},
	CodePlatformAutoUnsealDisabled: {
		Code: CodePlatformAutoUnsealDisabled, Emitted: true,
		Description: "The automatic-unseal setting was disabled; the unsealer stops unsealing at once.",
		Params:      []string{"previous_state", "method"},
		Outcomes:    adminOutcomes,
		Note:        "method is portal or cli (paddock-server admin auto-unseal disable). Platform pseudo-organization.",
	},
	CodePlatformOpenBaoAutoUnsealed: {
		Code: CodePlatformOpenBaoAutoUnsealed, Emitted: true,
		Description: "The unsealer unsealed OpenBao with the shares on the host, or failed to; recorded by the worker from the unsealer's report.",
		Params:      []string{"unseals", "last_unseal_at", "failures", "last_failure_at", "last_failure_reason"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "One event per observed change of the counters, at most every 30 s; a failure carries error code auto_unseal_failed and last_failure_reason unreachable, invalid_share or still_sealed. Actor is the system actor paddock-unsealer. Platform pseudo-organization.",
	},
	CodeDeviceEventGap: {
		Code: CodeDeviceEventGap, Emitted: true,
		Description: "The worker found event sequence numbers from_seq..to_seq of a device missing after two further check-ins: the events never arrived and the agent did not report them as dropped (actor: system).",
		Params:      []string{"from_seq", "to_seq", "event_seq_high", "first_seen_at", "last_contact_at"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "event_seq_high is the highest number the device reported in its last check-in; to_seq may equal it when the device claims events it never delivered. A spool overflow the agent admits (device.agent_events_dropped) is not a gap. Recorded once per gap; device.event_gap_filled follows if the events arrive later.",
	},
	CodeDeviceEventGapFilled: {
		Code: CodeDeviceEventGapFilled, Emitted: true,
		Description: "Every event of a gap that was reported as device.event_gap arrived later (actor: system).",
		Params:      []string{"from_seq", "to_seq", "reported_at"},
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeDeviceEventSeqReset: {
		Code: CodeDeviceEventSeqReset, Emitted: true,
		Description: "A device reported a highest event sequence number below the numbers it had already delivered: its agent state was reset (re-installed or wiped). The worker forgets the delivered numbers so that the new numbering is recorded, and closes open gaps without an event (actor: system).",
		Params:      []string{"previous_high", "reported_high", "events_seen"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "events_seen is the number of forgotten sequence numbers. A state wipe also restarts the check-in sequence, which quarantines the device as a suspected clone (device.clone_suspected).",
	},
	CodeDeviceClockDrift: {
		Code: CodeDeviceClockDrift, Emitted: true,
		Description: "The clock of a device differs from the server's by more than threshold_s seconds, measured from the signed timestamp of its check-in (actor: system). Recorded once per episode; device.clock_drift_cleared ends it.",
		Params:      []string{"offset_s", "threshold_s", "last_contact_at"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "offset_s is server time minus device time in seconds (positive: the device is behind). A device off by more than 300 s cannot authenticate and is silent instead (RR-76).",
	},
	CodeDeviceClockDriftCleared: {
		Code: CodeDeviceClockDriftCleared, Emitted: true,
		Description: "The clock of a device is back within 30 s of the server's (actor: system).",
		Params:      []string{"offset_s", "threshold_s", "since"},
		Outcomes:    []Outcome{OutcomeSuccess},
	},
	CodeAuditChainVerified: {
		Code: CodeAuditChainVerified, Emitted: true,
		Description: "The audit writer verified the organization's hash chain for from_day..to_day: every manifest exists, is signed by audit-chain, links to the previous day and lists exactly the indexed objects, and every object's SHA-256 matches (actor: system audit-writer).",
		Params:      []string{"run_id", "trigger", "from_day", "to_day", "days", "objects"},
		Outcomes:    []Outcome{OutcomeSuccess},
		Note:        "trigger is nightly (the last 7 sealed days), sample (one random older day) or cli (paddock-server audit verify).",
	},
	CodeAuditChainVerificationFailed: {
		Code: CodeAuditChainVerificationFailed, Emitted: true,
		Description: "The audit writer found problems in the organization's hash chain for from_day..to_day (actor: system audit-writer).",
		Params:      []string{"run_id", "trigger", "from_day", "to_day", "days", "objects", "problem_count", "problems"},
		Outcomes:    []Outcome{OutcomeFailure},
		Note:        "problems lists at most 50 findings of at most 500 characters each; problem_count is the full number. Raises PaddockAuditChainBroken.",
	},
	CodeAdminRoleGranted: {
		Code: CodeAdminRoleGranted, Emitted: true,
		Description: "A user became member of a Paddock role group in Authentik, or an Authentik superuser, as seen by the worker's snapshot (actor: system).",
		Params:      []string{"role", "username", "authentik_pk", "group", "baseline"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
		Note:        "role is org_admin, org_operator, org_auditor, platform_admin or authentik_superuser; group is the Authentik group name, empty for authentik_superuser; baseline is true for every member found by the first successful comparison of the role in an organization (or on the platform). A role whose listing fails records nothing that round; when all role listings of an organization, or the superuser listing of the platform, come back empty while members are recorded, nothing is recorded in that scope; a member is revoked only when two consecutive listings miss it. failure only when the change could not be stored.",
	},
	CodeAdminRoleRevoked: {
		Code: CodeAdminRoleRevoked, Emitted: true,
		Description: "A user left a Paddock role group in Authentik, or lost Authentik superuser status, as seen by the worker's snapshot (actor: system).",
		Params:      []string{"role", "username", "authentik_pk", "group"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
	},
	CodeOrganizationMCPPolicyChanged: {
		Code: CodeOrganizationMCPPolicyChanged, Emitted: true,
		Description: "An organization administrator changed the organization's MCP policy after a step-up: whether the MCP is enabled, whether it may change data, and which tools are allowed.",
		Params:      mcpPolicyParams,
		Outcomes:    adminOutcomes,
		Note:        "Denied with step_up_required without a fresh step-up (API tokens and MCP sessions never have one) and with forbidden below org_admin.",
	},
	CodePlatformMCPPolicyChanged: {
		Code: CodePlatformMCPPolicyChanged, Emitted: true,
		Description: "A platform administrator changed the platform's MCP policy after a step-up (platform pseudo-organization).",
		Params:      mcpPolicyParams,
		Outcomes:    adminOutcomes,
		Note:        "Denied with step_up_required without a fresh step-up (API tokens and MCP sessions never have one) and with forbidden for a non-platform principal.",
	},
	CodeAdminMCPWriteEnabled: {
		Code: CodeAdminMCPWriteEnabled, Emitted: true,
		Description: "An administrator enabled MCP write access for their own account after a step-up; from now on their MCP sessions may change data where the scope policy allows it.",
		Params:      []string{"role"},
		Outcomes:    adminOutcomes,
		Note:        "Denied with forbidden for auditors and for requests made with an API token or through the MCP.",
	},
	CodeAdminMCPWriteDisabled: {
		Code: CodeAdminMCPWriteDisabled, Emitted: true,
		Description: "An administrator disabled MCP write access for their own account; their MCP sessions are refused for changes from the next request on.",
		Params:      []string{"role"},
		Outcomes:    adminOutcomes,
		Note:        "Denied with forbidden for auditors and for requests made with an API token or through the MCP.",
	},
	CodeSettingsPrivacyChanged: {
		Code: CodeSettingsPrivacyChanged, Emitted: true,
		Description: "An organization administrator changed the privacy settings: the inventory retention of retired devices and whether audit searches and inventory views are recorded (ADR 0032).",
		Params:      []string{"retired_inventory_days", "audit_search_recorded", "inventory_view_recorded"},
		Outcomes:    adminOutcomes,
	},
	CodeAuditExportRequested: {
		Code: CodeAuditExportRequested, Emitted: true,
		Description: "An organization administrator or auditor requested a signed evidence package for a range of sealed recording days after a step-up; denied with step_up_required without one.",
		Params:      []string{"export_id", "from_day", "to_day", "purpose"},
		Outcomes:    adminOutcomes,
	},
	CodeAuditExportCompleted: {
		Code: CodeAuditExportCompleted, Emitted: true,
		Description: "The audit writer finished building an evidence package (actor: system). verify_ok tells whether the chain of the range verified; a package with problems is still delivered so that the auditor sees them. failure carries the error and error_code export_failed.",
		Params:      []string{"export_id", "from_day", "to_day", "days", "objects", "events", "size", "package_sha256", "verify_ok", "key_version", "error"},
		Outcomes:    []Outcome{OutcomeSuccess, OutcomeFailure},
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

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
	CodeManagedFileCreated         Code = "managed_file.created"
	CodeManagedFileUpdated         Code = "managed_file.updated"
	CodeManagedFileDeleted         Code = "managed_file.deleted"
	CodeManagedUnitCreated         Code = "managed_unit.created"
	CodeManagedUnitUpdated         Code = "managed_unit.updated"
	CodeManagedUnitDeleted         Code = "managed_unit.deleted"
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

// deviceEventParams are the parameters of audit events reported by devices (plan M2a decision 14).
var deviceEventParams = []string{"event_seq", "occurred_at", "bundle_version", "reason", "resource"}

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

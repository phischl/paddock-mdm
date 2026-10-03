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

package audit

import (
	"slices"
	"testing"
)

// TestM8sCodes: the codes of plan M8s §6.4 are registered with their params in the documented order and their
// outcomes, and the existing privilege and managed-file codes carry the effective class and the path tier.
func TestM8sCodes(t *testing.T) {
	all := []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied}
	for _, tc := range []struct {
		code     Code
		params   []string
		outcomes []Outcome
	}{
		{CodeAdminSessionsRevoked, []string{"reason", "sessions", "old_role", "new_role"}, []Outcome{OutcomeSuccess, OutcomeFailure}},
		{CodePlatformSessionsEnded, []string{"generation"}, all},
		{CodePermissionProfileRootGrantConfirmed, []string{"name", "effective_class", "commands"}, all},
		{CodeManagedFileSensitiveConfirmed, []string{"path", "device_group_id", "tier"}, all},
		{CodeOrganizationSecurityReviewRequired, []string{"root_grant_profiles", "sensitive_files", "denied_files"}, []Outcome{OutcomeSuccess}},
		{CodeDeviceHeaderObjectRejected, []string{"generation", "volume", "declared_size", "object_size"}, []Outcome{OutcomeFailure}},
	} {
		if !tc.code.Registered() {
			t.Errorf("%s is not registered", tc.code)
			continue
		}
		d, _ := Lookup(tc.code)
		if !slices.Equal(d.Params, tc.params) || !slices.Equal(d.Outcomes, tc.outcomes) {
			t.Errorf("%s: params %v outcomes %v, want %v %v", tc.code, d.Params, d.Outcomes, tc.params, tc.outcomes)
		}
	}

	for code, after := range map[Code][2]string{
		CodePermissionProfileCreated: {"root_equivalent", "effective_class"},
		CodePermissionProfileUpdated: {"root_equivalent", "effective_class"},
		CodeProfileAssignmentCreated: {"root_equivalent", "effective_class"},
		CodeProfileAssignmentUpdated: {"root_equivalent", "effective_class"},
		CodeManagedFileCreated:       {"group", "tier"},
		CodeManagedFileUpdated:       {"group", "tier"},
	} {
		d, _ := Lookup(code)
		i := slices.Index(d.Params, after[0])
		if i < 0 || i+1 >= len(d.Params) || d.Params[i+1] != after[1] {
			t.Errorf("%s: params %v, want %s directly after %s", code, d.Params, after[1], after[0])
		}
	}
}

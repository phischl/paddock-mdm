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
		{CodePlatformSessionsEnded, []string{"generation", "identity_users", "identity_sessions_ended"}, all},
		{CodePermissionProfileRootGrantConfirmed, []string{"name", "effective_class", "commands"}, all},
		{CodeManagedFileSensitiveConfirmed, []string{"path", "device_group_id", "tier"}, all},
		{CodeOrganizationSecurityReviewRequired, []string{"root_grant_profiles", "sensitive_files", "denied_files"}, []Outcome{OutcomeSuccess}},
		{CodeDeviceHeaderObjectRejected, []string{"generation", "volume", "declared_size", "object_size"}, []Outcome{OutcomeFailure}},
		{CodeSettingsManagedFilesChanged, []string{"old_operator_roots", "operator_roots"}, all},
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

// TestM8uCodes: the codes of plan M8u §6.4 are registered with their params in the documented order and their
// outcomes.
func TestM8uCodes(t *testing.T) {
	all := []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeDenied}
	for _, tc := range []struct {
		code     Code
		params   []string
		outcomes []Outcome
	}{
		{CodePlatformAutoUnsealEnabled, []string{"disclaimer_version", "acknowledgement", "previous_state"}, all},
		{CodePlatformAutoUnsealDisabled, []string{"previous_state", "method"}, all},
		{CodePlatformOpenBaoAutoUnsealed, []string{"unseals", "last_unseal_at", "failures", "last_failure_at", "last_failure_reason"}, []Outcome{OutcomeSuccess, OutcomeFailure}},
	} {
		d, ok := Lookup(tc.code)
		if !ok || !tc.code.Registered() || !d.Emitted {
			t.Errorf("%s is not registered as emitted", tc.code)
			continue
		}
		if !slices.Equal(d.Params, tc.params) || !slices.Equal(d.Outcomes, tc.outcomes) {
			t.Errorf("%s: params %v outcomes %v, want %v %v", tc.code, d.Params, d.Outcomes, tc.params, tc.outcomes)
		}
	}
}

// TestM8bCodes: the codes of plan M8b decision 9 are registered as emitted with their params in the documented
// order and their outcomes.
func TestM8bCodes(t *testing.T) {
	success := []Outcome{OutcomeSuccess}
	successFailure := []Outcome{OutcomeSuccess, OutcomeFailure}
	chain := []string{"run_id", "trigger", "from_day", "to_day", "days", "objects"}
	for _, tc := range []struct {
		code     Code
		params   []string
		outcomes []Outcome
	}{
		{"device.event_gap", []string{"from_seq", "to_seq", "event_seq_high", "first_seen_at", "last_contact_at"}, success},
		{"device.event_gap_filled", []string{"from_seq", "to_seq", "reported_at"}, success},
		{"device.event_seq_reset", []string{"previous_high", "reported_high", "events_seen"}, success},
		{"device.clock_drift", []string{"offset_s", "threshold_s", "last_contact_at"}, success},
		{"device.clock_drift_cleared", []string{"offset_s", "threshold_s", "since"}, success},
		{"audit.chain_verified", chain, success},
		{"audit.chain_verification_failed", append(slices.Clone(chain), "problem_count", "problems"), []Outcome{OutcomeFailure}},
		{"admin.role_granted", []string{"role", "username", "authentik_pk", "group", "baseline"}, successFailure},
		{"admin.role_revoked", []string{"role", "username", "authentik_pk", "group"}, successFailure},
	} {
		d, ok := Lookup(tc.code)
		if !ok || !tc.code.Registered() || !d.Emitted || d.Description == "" {
			t.Errorf("%s is not registered as emitted with a description", tc.code)
			continue
		}
		if !slices.Equal(d.Params, tc.params) || !slices.Equal(d.Outcomes, tc.outcomes) {
			t.Errorf("%s: params %v outcomes %v, want %v %v", tc.code, d.Params, d.Outcomes, tc.params, tc.outcomes)
		}
	}
}

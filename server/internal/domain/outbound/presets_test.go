package outbound_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// TestSecurityCodesRegistered: every preset code is registered (ADR 0031 decision 7), so an unregistered code in the
// preset fails here.
func TestSecurityCodesRegistered(t *testing.T) {
	codes := outbound.SecurityCodes()
	if len(codes) == 0 {
		t.Fatal("empty preset")
	}
	for _, c := range codes {
		if !c.Registered() {
			t.Errorf("preset code %s is not registered", c)
		}
	}
	if !slices.IsSorted(codes) || len(slices.Compact(slices.Clone(codes))) != len(codes) {
		t.Error("the preset is not sorted and distinct")
	}
}

// TestSecurityCodesContent: the codes named by ADR 0031 decision 7 and plan M9 amendment B3.3 are in the preset, the
// codes that end a condition or are excluded are not, and the wildcard groups expand over the registry.
func TestSecurityCodesContent(t *testing.T) {
	codes := outbound.SecurityCodes()
	for _, c := range []audit.Code{
		"device.event_gap", "device.event_seq_reset", "device.clock_drift", "audit.chain_verification_failed",
		"admin.role_granted", "admin.role_revoked", "device.tamper_sudoers_changed", "device.clone_suspected",
		"permission_profile.created", "profile_assignment.deleted", "api_token.created", "revocation.issued",
		"organization.created", "settings.login_changed", "agent_rollout.halted", "agent_release.published",
		"admin.mcp_write_enabled", "admin.mcp_write_disabled", "platform.mcp_policy_changed",
		"admin.sessions_revoked", "platform.sessions_ended", "platform.auto_unseal_enabled",
		"platform.auto_unseal_disabled", "device.retired", "device.uninstall_requested", "device.escrow_destroyed",
		"managed_file.sensitive_confirmed",
	} {
		if !slices.Contains(codes, c) {
			t.Errorf("%s missing from the preset", c)
		}
		if !outbound.IsSecurityCode(c) {
			t.Errorf("IsSecurityCode(%s) = false", c)
		}
	}
	for _, c := range []audit.Code{
		"device.event_gap_filled", "device.clock_drift_cleared", "audit.chain_verified", "retention.purged",
		"action.finalized_unknown", "device.uninstalled", "device.uninstall_cancelled", "enrollment_token.created",
		"agent_rollout.started", "agent_release.created", "device.encrypt_requested", "config_rollout.halted",
	} {
		if slices.Contains(codes, c) || outbound.IsSecurityCode(c) {
			t.Errorf("%s must not be in the preset", c)
		}
	}
	for _, d := range audit.Definitions() {
		if d.Emitted && strings.HasPrefix(string(d.Code), "device.tamper_") &&
			!slices.Contains(codes, d.Code) {
			t.Errorf("tamper code %s missing", d.Code)
		}
	}
}

// TestMatches: outcome unknown always matches, a baseline admin.role_granted never does, the custom list applies only
// in custom mode.
func TestMatches(t *testing.T) {
	modes := []outbound.FilterMode{outbound.FilterSecurity, outbound.FilterAll, outbound.FilterCustom}
	custom := []audit.Code{"device_group.created"}
	ev := func(code audit.Code, outcome audit.Outcome, params map[string]any) audit.Event {
		return audit.Event{Code: code, Outcome: outcome, Params: params}
	}
	for _, m := range modes {
		if !outbound.Matches(m, custom, ev("device.enrolled", audit.OutcomeUnknown, nil)) {
			t.Errorf("%s: outcome unknown does not match", m)
		}
		baseline := ev(audit.CodeAdminRoleGranted, audit.OutcomeSuccess, map[string]any{"baseline": true})
		if outbound.Matches(m, []audit.Code{audit.CodeAdminRoleGranted}, baseline) {
			t.Errorf("%s: baseline role grant matches", m)
		}
	}
	grant := ev(audit.CodeAdminRoleGranted, audit.OutcomeSuccess, map[string]any{"baseline": false})
	if !outbound.Matches(outbound.FilterSecurity, nil, grant) {
		t.Error("security: a non-baseline role grant does not match")
	}
	group := ev("device_group.created", audit.OutcomeSuccess, nil)
	for m, want := range map[outbound.FilterMode]bool{
		outbound.FilterSecurity: false, outbound.FilterAll: true, outbound.FilterCustom: true,
	} {
		if got := outbound.Matches(m, custom, group); got != want {
			t.Errorf("%s: custom code matches = %v, want %v", m, got, want)
		}
	}
	if outbound.Matches(outbound.FilterCustom, custom, ev("device.enrolled", audit.OutcomeSuccess, nil)) {
		t.Error("custom: a code outside the list matches")
	}
	if outbound.Matches(outbound.FilterCustom, nil, ev("device.tamper_sudoers_changed", audit.OutcomeSuccess, nil)) {
		t.Error("custom: a security code outside the list matches")
	}
	if outbound.Matches("bogus", nil, ev("admin.login", audit.OutcomeSuccess, nil)) {
		t.Error("an unknown mode matches")
	}
}

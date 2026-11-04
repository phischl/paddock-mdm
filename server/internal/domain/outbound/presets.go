// Package outbound holds the rules shared by every outbound path of the control plane (ADR 0031, plan M9 §3.3):
// which audit codes a destination receives, which webhook URLs may be called, how messages are signed, how user names
// are pseudonymized, the message envelope and the destination settings.
package outbound

import (
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// FilterMode selects the audit events a destination receives.
type FilterMode string

const (
	// FilterSecurity forwards the preset of SecurityCodes.
	FilterSecurity FilterMode = "security"
	// FilterAll forwards every event.
	FilterAll FilterMode = "all"
	// FilterCustom forwards the destination's own list of registered codes.
	FilterCustom FilterMode = "custom"
)

// securityPrefixes are the wildcard groups of ADR 0031 decision 7; every registered code starting with one of them
// belongs to the preset, so codes registered later in these groups join it without a change here.
var securityPrefixes = []string{
	"device.tamper_", "permission_profile.", "profile_assignment.", "api_token.", "revocation.", "organization.",
	"settings.", "notification.destination_", "finding.",
}

// securityExplicit are the single codes of ADR 0031 decision 7 and of the refresh of plan M9 (amendment 2026-10-31,
// B3.3). Only registered codes belong here (TestSecurityCodesRegistered).
var securityExplicit = []audit.Code{
	"device.clone_suspected", "device.bundle_rejected", "device.agent_events_dropped", "device.agent_rollback_failed",
	"device.stale_critical", "device.presumed_self_locked", "device.revocation_trust_pinned_tofu",
	"device.revocation_confirmed", "device.revocation_refused",
	"local_admin.revealed", "local_admin.login", "disk.recovery_key_revealed", "disk.header_downloaded",
	"user_group.member_added", "user_group.member_removed", "user.locked", "user.unlocked", "admin.login",
	"agent_rollout.halted", "agent_release.published", "config_rollout.halted",
	"platform.osv_stale", "platform.ip_allowlist_changed", "platform.ip_allowlist_disabled",
	"platform.ip_allowlist_denied", "config.applied",
	"device.event_gap", "device.event_seq_reset", "device.clock_drift", "audit.chain_verification_failed",
	"admin.role_granted", "admin.role_revoked",
	"admin.mcp_write_enabled", "admin.mcp_write_disabled", "platform.mcp_policy_changed",
	"admin.sessions_revoked", "platform.sessions_ended",
	"platform.auto_unseal_enabled", "platform.auto_unseal_disabled",
	"device.retired", "device.uninstall_requested", "device.escrow_destroyed", "managed_file.sensitive_confirmed",
	"vulnerability.critical_summary",
	"notification.pseudonym_resolved",
	"audit.export_requested", "audit.export_downloaded",
}

// SecurityCodes returns the preset of filter mode security, sorted: every registered code of the wildcard groups of
// ADR 0031 decision 7 and its single codes.
func SecurityCodes() []audit.Code {
	var out []audit.Code
	for _, d := range audit.Definitions() {
		if d.Emitted && hasSecurityPrefix(d.Code) {
			out = append(out, d.Code)
		}
	}
	for _, c := range securityExplicit {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// IsSecurityCode reports whether c belongs to the preset of SecurityCodes.
func IsSecurityCode(c audit.Code) bool {
	return (c.Registered() && hasSecurityPrefix(c)) || slices.Contains(securityExplicit, c)
}

func hasSecurityPrefix(c audit.Code) bool {
	for _, p := range securityPrefixes {
		if strings.HasPrefix(string(c), p) {
			return true
		}
	}
	return false
}

// Matches reports whether a destination with the filter mode and, for FilterCustom, the codes receives ev. An event
// with outcome unknown is always received (the action's result is open); an admin.role_granted of the first run's
// inventory of existing members (params.baseline = true) never is.
func Matches(mode FilterMode, codes []audit.Code, ev audit.Event) bool {
	if ev.Code == audit.CodeAdminRoleGranted && ev.Params["baseline"] == true {
		return false
	}
	if ev.Outcome == audit.OutcomeUnknown {
		return true
	}
	switch mode {
	case FilterAll:
		return true
	case FilterSecurity:
		return IsSecurityCode(ev.Code)
	case FilterCustom:
		return slices.Contains(codes, ev.Code)
	}
	return false
}

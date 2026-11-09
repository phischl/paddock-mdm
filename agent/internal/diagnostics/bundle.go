package diagnostics

import (
	"encoding/json"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/dsse"
)

// bundleNote labels the rendering of bundle.dsse in the archive.
const bundleNote = "Redacted rendering of the applied bundle.dsse: every field that is not on the agent's list of " +
	"known public bundle fields is replaced by " + Redacted + ", among them the Fleet enroll secret and the content of " +
	"managed files. This is not the signed envelope; its signatures do not verify against this payload."

// publicBundleFields is the allow-list of the bundle fields that are archived in clear (ADR 0048 amendment
// 2026-11-05): a path of JSON names from the payload root, array elements share the path of their array, ".*" stands
// for every key of a map and "resources.spec:<type>" for the spec of a resource of that type. The server is ahead of
// the agent during every staged rollout, so a field this agent does not know — a new secret among them — must fail
// closed. inventory.enroll_secret and resources.spec:file.content are deliberately absent.
func publicBundleFields() map[string]bool {
	fields := []string{
		"schema_version", "bundle_version", "device_id", "organization_id", "issued_at", "mode",
		"agent.checkin_interval_s", "agent.update_policy",
		"agent.supervisor_packages.*.version", "agent.supervisor_packages.*.url_path", "agent.supervisor_packages.*.sha256",
		"resources.id", "resources.type",
		"keys.command_signing.key_id", "keys.command_signing.public_key",
		"keys.escrow_wrap.key_id", "keys.escrow_wrap.public_key_pem",
		"keys.time_ticket.key_id", "keys.time_ticket.public_key",
		"revocation.enabled", "revocation.keys.key_id", "revocation.keys.public_key",
		"dms.enabled", "dms.period_days", "dms.warn_days",
		"inventory.fleet_url", "inventory.package.version", "inventory.package.url_path", "inventory.package.sha256",
		"updates.security_daily_at", "updates.regular_schedule", "updates.regular_updates_enabled",
		"updates.max_random_delay_min", "updates.holds.package", "updates.holds.version",
		"disk.unlock_mode", "disk.boot_pin_min_length",
		"hostname.name",
		"watch.units",
		"software.sources.slug", "software.sources.uris", "software.sources.suites", "software.sources.components",
		"software.sources.architectures", "software.sources.keyring", "software.sources.fingerprint", "software.sources.kind",
		"software.packages.package", "software.packages.intent", "software.packages.version", "software.packages.source",
		"software.packages.catalog_entry_id", "software.packages.superseded_hold",
		// The audience names user names as resources.spec:sudo.entries.username and login.locked_users do (plan M13b
		// decision 7).
		"software.packages.flatpak_ref", "software.packages.scope", "software.packages.audience.all",
		"software.packages.audience.users",
		"resources.spec:time.ntp",
		"resources.spec:file.path", "resources.spec:file.mode", "resources.spec:file.owner", "resources.spec:file.group",
		"resources.spec:file.content_sha256",
		"resources.spec:systemd_unit.unit", "resources.spec:systemd_unit.enabled", "resources.spec:systemd_unit.active",
		"resources.spec:login.provider", "resources.spec:login.suspended", "resources.spec:login.locked_users",
		"resources.spec:login.session_action", "resources.spec:login.break_glass_accounts", "resources.spec:login.notice",
		"resources.spec:login.report_every_session",
		"resources.spec:login.himmelblau.oidc_issuer_url", "resources.spec:login.himmelblau.app_id",
		"resources.spec:login.himmelblau.domain", "resources.spec:login.himmelblau.pam_allow_groups",
		"resources.spec:login.himmelblau.enable_hello", "resources.spec:login.himmelblau.hello_pin_min_length",
		"resources.spec:login.himmelblau.package_version",
		"resources.spec:login.local_admin.username", "resources.spec:login.local_admin.rotation_days",
		"resources.spec:sudo.lecture_text", "resources.spec:sudo.privileged_groups", "resources.spec:sudo.sudoers_d_allowlist",
		"resources.spec:sudo.break_glass_accounts",
		"resources.spec:sudo.entries.username", "resources.spec:sudo.entries.class", "resources.spec:sudo.entries.root_equivalent",
		"resources.spec:sudo.entries.commands", "resources.spec:sudo.entries.require_password",
		"resources.spec:sudo.entries.timestamp_timeout_min", "resources.spec:sudo.entries.lecture",
		"resources.spec:sudo.entries.profile_digest",
	}
	m := make(map[string]bool, len(fields))
	for _, f := range fields {
		m[f] = true
	}
	return m
}

// redactBundle renders bundle.dsse with its payload decoded and every field outside publicBundleFields replaced, plus
// the envelope's signature metadata. bundle.dsse is signed but not public: its payload carries the Fleet enroll secret
// and the content of managed files. An envelope that does not decode is replaced as a whole, because it cannot be
// checked.
func redactBundle(data []byte) []byte {
	env, payload, err := dsse.Decode(data)
	if err != nil {
		return []byte(Redacted + "\n")
	}
	var v any
	if err := json.Unmarshal(payload, &v); err != nil {
		return []byte(Redacted + "\n")
	}
	if _, ok := v.(map[string]any); !ok {
		return []byte(Redacted + "\n")
	}
	w := bundleWalker{leaves: publicBundleFields(), containers: map[string]bool{"": true}}
	for f := range w.leaves {
		for i := strings.LastIndexByte(f, '.'); i >= 0; i = strings.LastIndexByte(f[:i], '.') {
			w.containers[f[:i]] = true
		}
	}
	out, err := marshalIndent(struct {
		Note        string           `json:"note"`
		PayloadType string           `json:"payload_type"`
		Signatures  []dsse.Signature `json:"signatures"`
		Payload     any              `json:"payload"`
	}{Note: bundleNote, PayloadType: env.PayloadType, Signatures: env.Signatures, Payload: w.walk(v, "")})
	if err != nil {
		return []byte(Redacted + "\n")
	}
	return redactURLCredentials(out)
}

type bundleWalker struct {
	leaves     map[string]bool
	containers map[string]bool
}

// walk keeps a scalar (or a list of scalars) at a leaf path and descends into an object at a container path; any
// other value is replaced whole.
func (w bundleWalker) walk(v any, path string) any {
	if v == nil {
		return nil
	}
	if w.leaves[path] && isScalarOrList(v) {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		if !w.containers[path] {
			return Redacted
		}
		out := make(map[string]any, len(t))
		for k, child := range t {
			out[k] = w.walk(child, w.childPath(t, path, k))
		}
		return out
	case []any:
		if !w.containers[path] {
			return Redacted
		}
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = w.walk(child, path)
		}
		return out
	}
	return Redacted
}

func (w bundleWalker) childPath(parent map[string]any, path, key string) string {
	if path == "resources" && key == "spec" {
		typ, _ := parent["type"].(string)
		return "resources.spec:" + typ
	}
	p := key
	if path != "" {
		p = path + "." + key
	}
	if w.leaves[p] || w.containers[p] {
		return p
	}
	return path + ".*"
}

func isScalarOrList(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		return false
	case []any:
		for _, e := range t {
			if !isScalarOrList(e) {
				return false
			}
			if _, ok := e.([]any); ok {
				return false
			}
		}
	}
	return true
}

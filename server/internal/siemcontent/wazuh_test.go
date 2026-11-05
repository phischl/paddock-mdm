// Package siemcontent tests the SIEM detection content under integrations/ against the audit code registry and the
// real syslog frames. It lives in the server module because the registry and the frame formatter are internal; the
// content itself (integrations/) is plain XML and YAML with no code and no extra tooling.
package siemcontent_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

const (
	decodersPath = "../../../integrations/wazuh/decoders/0900-paddock_decoders.xml"
	rulesPath    = "../../../integrations/wazuh/rules/0900-paddock_rules.xml"
	siemDocPath  = "../../../docs/operations/siem.md"
	goldenDir    = "../domain/outbound/testdata/"
	hostname     = "admin.paddock.example.org"

	// builtinJSON is the name of Wazuh's built-in decoder (ruleset/decoders/0006-json_decoders.xml), which is loaded
	// before etc/decoders and takes every line that starts with {".
	builtinJSON = "json"
)

var builtinJSONPrematch = regexp.MustCompile(`^\{\s*"`)

type pcre struct {
	Type   string `xml:"type,attr"`
	Offset string `xml:"offset,attr"`
	Text   string `xml:",chardata"`
}

type decoder struct {
	Name     string `xml:"name,attr"`
	Parent   string `xml:"parent"`
	Prematch *pcre  `xml:"prematch"`
	Regex    *pcre  `xml:"regex"`
	Plugin   *pcre  `xml:"plugin_decoder"`
	Order    string `xml:"order"`
}

type field struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
	Text string `xml:",chardata"`
}

type rule struct {
	ID           int     `xml:"id,attr"`
	Level        int     `xml:"level,attr"`
	Frequency    int     `xml:"frequency,attr"`
	DecodedAs    string  `xml:"decoded_as"`
	IfSID        string  `xml:"if_sid"`
	IfGroup      string  `xml:"if_group"`
	IfMatchedSID string  `xml:"if_matched_sid"`
	SameField    string  `xml:"same_field"`
	Group        string  `xml:"group"`
	Fields       []field `xml:"field"`
	Description  string  `xml:"description"`
	// Groups holds the names of the enclosing <group> and of the rule's own <group>.
	Groups []string `xml:"-"`
}

type ruleGroup struct {
	Name  string `xml:"name,attr"`
	Rules []rule `xml:"rule"`
}

func readXML(t *testing.T, path string, out any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, xml.Unmarshal([]byte("<root>"+string(raw)+"</root>"), out), path)
}

func loadDecoders(t *testing.T) []decoder {
	t.Helper()
	var doc struct {
		Decoders []decoder `xml:"decoder"`
	}
	readXML(t, decodersPath, &doc)
	return doc.Decoders
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func loadRules(t *testing.T) []rule {
	t.Helper()
	var doc struct {
		Groups []ruleGroup `xml:"group"`
	}
	readXML(t, rulesPath, &doc)
	var out []rule
	for _, g := range doc.Groups {
		for _, r := range g.Rules {
			r.Groups = append(splitList(g.Name), splitList(r.Group)...)
			out = append(out, r)
		}
	}
	return out
}

func compile(t *testing.T, where string, p *pcre) *regexp.Regexp {
	t.Helper()
	require.NotNil(t, p, where)
	// Go's RE2 is the verifiable subset of PCRE2; an OS_Regex pattern would not be checked by these tests.
	require.Equal(t, "pcre2", p.Type, where)
	re, err := regexp.Compile(strings.TrimSpace(p.Text))
	require.NoError(t, err, where)
	return re
}

// flattenJSON is what Wazuh's JSON_Decoder makes of a JSON object: one field per leaf under its dotted path, numbers
// and booleans as text, arrays as their JSON text, null dropped.
func flattenJSON(t *testing.T, s string) map[string]string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v map[string]any
	if dec.Decode(&v) != nil {
		return nil
	}
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if prefix != "" {
					k = prefix + "." + k
				}
				walk(k, c)
			}
		case nil:
		case string:
			out[prefix] = x
		case json.Number:
			out[prefix] = x.String()
		case bool:
			out[prefix] = strconv.FormatBool(x)
		default:
			raw, err := json.Marshal(x)
			require.NoError(t, err)
			out[prefix] = string(raw)
		}
	}
	walk("", v)
	return out
}

// input is the part of log a child decoder sees: the whole log without an offset (Wazuh's default for a child
// <regex>), the text after the parent's prematch with offset after_parent.
func input(t *testing.T, where, offset, log string, afterParent int) string {
	t.Helper()
	switch offset {
	case "":
		return log
	case "after_parent":
		return log[afterParent:]
	}
	require.Failf(t, "unsupported offset", "%s: %q", where, offset)
	return ""
}

// applyChild runs one child decoder; ok is false when its regex does not match or its JSON does not parse.
func applyChild(t *testing.T, d decoder, log string, afterParent int, out map[string]string) bool {
	t.Helper()
	if d.Plugin != nil {
		require.Equal(t, "JSON_Decoder", strings.TrimSpace(d.Plugin.Text), d.Name)
		f := flattenJSON(t, input(t, d.Name, d.Plugin.Offset, log, afterParent))
		for k, v := range f {
			out[k] = v
		}
		return f != nil
	}
	m := compile(t, d.Name+" regex", d.Regex).FindStringSubmatch(input(t, d.Name, d.Regex.Offset, log, afterParent))
	if m == nil {
		return false
	}
	names := splitList(d.Order)
	require.Len(t, m, len(names)+1, "%s: <order> must name every capture group", d.Name)
	for i, n := range names {
		out[n] = m[i+1]
	}
	return true
}

// decodeLog decodes log the way the Wazuh manager does: the built-in json decoder first, then the first parent in file
// order whose prematch matches, then that parent's first matching child together with its same-named siblings. It
// returns the name rules see in <decoded_as> (the parent's) and the fields, or "" when no decoder takes log.
func decodeLog(t *testing.T, decs []decoder, log string) (string, map[string]string) {
	t.Helper()
	if builtinJSONPrematch.MatchString(log) {
		return builtinJSON, flattenJSON(t, log)
	}
	for _, p := range decs {
		if p.Parent != "" {
			continue
		}
		loc := compile(t, p.Name+" prematch", p.Prematch).FindStringIndex(log)
		if loc == nil {
			continue
		}
		fields := map[string]string{}
		matched := ""
		for _, c := range decs {
			if c.Parent != p.Name || (matched != "" && c.Name != matched) {
				continue
			}
			if applyChild(t, c, log, loc[1], fields) && matched == "" {
				matched = c.Name
			}
		}
		return p.Name, fields
	}
	return "", nil
}

func TestDecodersAreWellFormed(t *testing.T) {
	decs := loadDecoders(t)
	require.NotEmpty(t, decs)
	parents := map[string]bool{}
	for _, d := range decs {
		if d.Parent == "" {
			require.False(t, parents[d.Name], "parent decoder names are unique")
			parents[d.Name] = true
			require.Nil(t, d.Regex, d.Name)
			compile(t, d.Name+" prematch", d.Prematch)
			continue
		}
		require.True(t, parents[d.Parent], "%s: the parent is defined above the child", d.Name)
		require.NotEqual(t, d.Regex == nil, d.Plugin == nil, "%s: a child has either a regex or a plugin decoder", d.Name)
		if d.Regex != nil {
			compile(t, d.Name+" regex", d.Regex)
		} else {
			require.Equal(t, "after_parent", d.Plugin.Offset, d.Name)
		}
	}
}

func TestRulesAreWellFormed(t *testing.T) {
	rules := loadRules(t)
	parents := map[string]bool{builtinJSON: true}
	for _, d := range loadDecoders(t) {
		if d.Parent == "" {
			parents[d.Name] = true
		}
	}
	ids := map[int]rule{}
	groups := map[string]bool{}
	for _, r := range rules {
		require.GreaterOrEqual(t, r.ID, 100900, "rule id range")
		require.LessOrEqual(t, r.ID, 100999, "rule id range")
		require.NotContains(t, ids, r.ID, "unique rule id")
		ids[r.ID] = r
		for _, g := range r.Groups {
			groups[g] = true
		}
	}
	for _, r := range rules {
		if r.DecodedAs != "" {
			require.True(t, parents[r.DecodedAs], "rule %d decoded_as names a parent decoder", r.ID)
		} else {
			require.True(t, r.IfSID != "" || r.IfGroup != "" || r.IfMatchedSID != "", "rule %d has no parent", r.ID)
		}
		for _, list := range []string{r.IfSID, r.IfMatchedSID} {
			for _, s := range splitList(list) {
				id, err := strconv.Atoi(s)
				require.NoError(t, err)
				require.Contains(t, ids, id, "rule %d references rule %d", r.ID, id)
			}
		}
		for _, g := range splitList(r.IfGroup) {
			require.True(t, groups[g], "rule %d references group %s", r.ID, g)
		}
		for _, f := range r.Fields {
			compile(t, "rule field "+f.Name, &pcre{Type: f.Type, Text: f.Text})
		}
		if r.Frequency > 0 {
			require.NotEmpty(t, r.IfMatchedSID, "rule %d: frequency rule", r.ID)
			require.NotEmpty(t, r.SameField, "rule %d: a frequency rule counts per actor", r.ID)
		}
	}
}

func emitted() []audit.Code {
	var out []audit.Code
	for _, d := range audit.Definitions() {
		if d.Emitted {
			out = append(out, d.Code)
		}
	}
	return out
}

func sampleEvent(code audit.Code, outcome audit.Outcome) outbound.MessageEvent {
	return outbound.MessageEvent{ForwardSeq: 41, CommitSeq: 1207, Event: audit.Event{
		Schema: audit.Schema, EventID: uuid.MustParse("0193a1b2-0000-7000-8000-0000000000aa"),
		OrganizationID: uuid.MustParse("0193a1b2-0000-7000-8000-000000000003"),
		OccurredAt:     time.Date(2026, 11, 4, 9, 29, 58, 123456789, time.UTC),
		RecordedAt:     time.Date(2026, 11, 4, 9, 29, 59, 0, time.UTC), Code: code, Outcome: outcome,
		Actor:  audit.Actor{Type: audit.ActorAdmin, Display: "alice"},
		Target: &audit.Target{Type: "device", ID: "0193a1b2-0000-7000-8000-0000000000bb", Display: "laptop-17"},
		Source: audit.SourcePortal, Params: map[string]any{"name": "laptop-17"}, CorrelationID: "req-1",
	}}
}

func frameOf(ev outbound.MessageEvent) string {
	m := outbound.Message{Schema: outbound.MessageSchema, Kind: outbound.KindEvents, DeliveryID: "0193a1b2-0000-7000-8000-000000000001",
		Organization: "acme"}
	return string(outbound.FormatSyslog(m, ev, hostname))
}

func syslogFrame(code audit.Code, outcome audit.Outcome) string {
	return frameOf(sampleEvent(code, outcome))
}

// feedJQ is the jq filter of the pull loop in docs/operations/siem.md; feedLine builds the line it writes.
const feedJQ = `jq -c --arg org "$org" '.events[] | {organization: $org, commit_seq, event}'`

func feedLine(t *testing.T, code audit.Code, outcome audit.Outcome) string {
	t.Helper()
	ev := sampleEvent(code, outcome)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	require.NoError(t, enc.Encode(map[string]any{"organization": "acme", "commit_seq": ev.CommitSeq, "event": ev.Event}))
	return strings.TrimSuffix(b.String(), "\n")
}

func matches(t *testing.T, r rule, f map[string]string) bool {
	t.Helper()
	for _, fl := range r.Fields {
		v, ok := f[fl.Name]
		if !ok || !compile(t, "rule field", &pcre{Type: fl.Type, Text: fl.Text}).MatchString(v) {
			return false
		}
	}
	return true
}

// classify is the rule Wazuh fires for one decoded event: the first rule in file order whose decoded_as and fields
// match, then, as long as one does, its first matching child in file order. Frequency rules never fire on a single
// event. It returns the zero rule when no rule of the file matches.
func classify(t *testing.T, rules []rule, decoded string, f map[string]string) rule {
	t.Helper()
	var cur rule
	for _, r := range rules {
		if r.DecodedAs != "" && r.DecodedAs == decoded && matches(t, r, f) {
			cur = r
			break
		}
	}
	for cur.ID != 0 {
		next := rule{}
		for _, r := range rules {
			if r.Frequency == 0 && contains(splitList(r.IfSID), strconv.Itoa(cur.ID)) && matches(t, r, f) {
				next = r
				break
			}
		}
		if next.ID == 0 {
			break
		}
		cur = next
	}
	return cur
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// informational are the codes that fall to the base rule (level 3) on purpose, listed one by one: a code added to
// the registry fails TestEveryRegisteredCodeIsClassified until it gets a rule or is added here, so a new
// security-relevant code is never classified by accident.
var informational = map[audit.Code]bool{
	"agent_release.artifact_uploaded":               true,
	"agent_release.created":                         true,
	"agent_release.imported":                        true,
	"agent_release.published":                       true,
	"agent_rollout.advanced":                        true,
	"agent_rollout.completed":                       true,
	"agent_rollout.halted":                          true,
	"agent_rollout.resumed":                         true,
	"agent_rollout.started":                         true,
	"audit.chain_verified":                          true,
	"audit.export_completed":                        true,
	"audit.export_downloaded":                       true,
	"audit.export_requested":                        true,
	"audit.searched":                                true,
	"autoinstall.generated":                         true,
	"config_rollout.advanced":                       true,
	"config_rollout.completed":                      true,
	"config_rollout.halted":                         true,
	"config_rollout.resumed":                        true,
	"device.agent_events_dropped":                   true,
	"device.agent_rollback_failed":                  true,
	"device.agent_rolled_back":                      true,
	"device.agent_update_failed":                    true,
	"device.agent_update_requested":                 true,
	"device.agent_updated":                          true,
	"device.approved":                               true,
	"device.bundle_applied":                         true,
	"device.bundle_entry_omitted":                   true,
	"device.bundle_rejected":                        true,
	"device.bundle_render_failed":                   true,
	"device.clock_drift":                            true,
	"device.clock_drift_cleared":                    true,
	"device.config_drift_corrected":                 true,
	"device.disk_conversion_aborted":                true,
	"device.disk_conversion_completed":              true,
	"device.disk_conversion_completed_after_cancel": true,
	"device.disk_conversion_failed":                 true,
	"device.disk_conversion_neutralize_failed":      true,
	"device.disk_conversion_prepared":               true,
	"device.disk_conversion_started":                true,
	"device.disk_conversion_unlock_restore_failed":  true,
	"device.encrypt_cancelled":                      true,
	"device.encrypt_requested":                      true,
	"device.enforcement_enabled":                    true,
	"device.enrolled":                               true,
	"device.escrow_destroyed":                       true,
	"device.event_gap_filled":                       true,
	"device.groups_changed":                         true,
	"device.install_now_requested":                  true,
	"device.inventory_host_kept":                    true,
	"device.inventory_purged":                       true,
	"device.inventory_viewed":                       true,
	"device.name_changed":                           true,
	"device.os_release_changed":                     true,
	"device.owners_changed":                         true,
	"device.presumed_self_locked":                   true,
	"device.quarantine_released":                    true,
	"device.rejected":                               true,
	"device.retired":                                true,
	"device.software_apply_failed":                  true,
	"device.software_installed":                     true,
	"device.software_reinstalled":                   true,
	"device.software_removed":                       true,
	"device.stale_cleared":                          true,
	"device.stale_critical":                         true,
	"device.stale_warning":                          true,
	"device.sudo_apply_failed":                      true,
	"device.sudo_user_unresolved":                   true,
	"device.supervisor_update_failed":               true,
	"device.supervisor_updated":                     true,
	"device.uninstall_cancelled":                    true,
	"device.uninstall_failed":                       true,
	"device.uninstall_requested":                    true,
	"device.uninstalled":                            true,
	"device.updates_run":                            true,
	"device.user_lock_applied":                      true,
	"finding.acknowledged":                          true,
	"finding.assigned":                              true,
	"finding.closed":                                true,
	"finding.reopened":                              true,
	"local_admin.rotated":                           true,
	"local_admin.rotation_failed":                   true,
	"local_admin.rotation_requested":                true,
	"notification.delivered":                        true,
	"notification.pseudonym_resolved":               true,
	"notification.test_requested":                   true,
	"notification.test_sent":                        true,
	"retention.purged":                              true,
	"vulnerability.critical_summary":                true,
	"vulnerability.devices_viewed":                  true,
}

// mustBeHigh are the words that mark a code as security relevant: such a code must never end up below level 10.
var mustBeHigh = regexp.MustCompile(`tamper|revoc|reveal|root_grant|chain_verification_failed|header_downloaded`)

var outcomes = []audit.Outcome{audit.OutcomeSuccess, audit.OutcomeFailure, audit.OutcomeDenied}

func TestEveryRegisteredCodeIsClassified(t *testing.T) {
	rules := loadRules(t)
	decs := loadDecoders(t)
	atBase := map[audit.Code]bool{}
	for _, code := range emitted() {
		for _, outcome := range outcomes {
			dec, f := decodeLog(t, decs, syslogFrame(code, outcome))
			require.Equal(t, "paddock", dec, "%s %s: the syslog frame is decoded by paddock", code, outcome)
			require.Equal(t, string(code), f["event.code"], "the decoder reads the full code, not the MSGID")
			require.Equal(t, string(outcome), f["event.outcome"])
			require.Equal(t, "acme", f["organization"])
			require.Equal(t, "41", f["forward_seq"])
			require.Equal(t, "1207", f["commit_seq"])
			require.Equal(t, "2026-11-04T09:29:58.123456789Z", f["event.occurred_at"])
			require.Equal(t, "2026-11-04T09:29:59Z", f["event.recorded_at"])
			require.Equal(t, "admin", f["event.actor.type"])
			require.Equal(t, "alice", f["event.actor.display"])
			require.Equal(t, "laptop-17", f["event.target.display"])
			require.Equal(t, "laptop-17", f["event.params.name"])
			sys := classify(t, rules, dec, f)

			fdec, ff := decodeLog(t, decs, feedLine(t, code, outcome))
			require.Equal(t, builtinJSON, fdec, "%s %s: a pull line is taken by the built-in json decoder", code, outcome)
			require.Equal(t, string(code), ff["event.code"])
			require.Equal(t, "acme", ff["organization"])
			require.Equal(t, "1207", ff["commit_seq"])
			require.Equal(t, "laptop-17", ff["event.params.name"])
			feed := classify(t, rules, fdec, ff)

			if sys.ID == 100900 || feed.ID == 100901 {
				require.Equal(t, 100900, sys.ID, "%s %s: push and pull classify alike", code, outcome)
				require.Equal(t, 100901, feed.ID, "%s %s: push and pull classify alike", code, outcome)
			} else {
				require.Equal(t, sys.ID, feed.ID, "%s %s: push and pull classify alike", code, outcome)
			}

			switch outcome {
			case audit.OutcomeSuccess:
				if mustBeHigh.MatchString(string(code)) {
					require.GreaterOrEqual(t, sys.Level, 10, "%s is security relevant but fires rule %d at level %d", code, sys.ID, sys.Level)
				}
				if sys.ID == 100900 {
					atBase[code] = true
					require.True(t, informational[code], "%s has no rule; add one or list it as informational", code)
				}
			case audit.OutcomeDenied:
				require.GreaterOrEqual(t, sys.Level, 7, "%s denied fires rule %d at level %d", code, sys.ID, sys.Level)
			}
		}
	}
	for code := range informational {
		require.True(t, atBase[code], "%s is listed as informational but is not an emitted code at the base rule", code)
	}
}

func TestRuleLevels(t *testing.T) {
	rules := loadRules(t)
	decs := loadDecoders(t)
	cases := []struct {
		code    audit.Code
		outcome audit.Outcome
		id      int
		level   int
		group   string
	}{
		{audit.CodeDeviceTamperSudoersChanged, audit.OutcomeSuccess, 100910, 12, "paddock_tamper"},
		{audit.CodeDeviceTamperProtectedFileChanged, audit.OutcomeSuccess, 100910, 12, "paddock_tamper"},
		{audit.CodeDeviceTamperLocalAdminChanged, audit.OutcomeSuccess, 100910, 12, "paddock_tamper"},
		{audit.CodeDeviceTamperKeyslotChanged, audit.OutcomeSuccess, 100910, 12, "paddock_tamper"},
		{audit.CodeRevocationIssued, audit.OutcomeSuccess, 100911, 12, "paddock_privilege"},
		{audit.CodeDeviceRevocationTrustPinnedTOFU, audit.OutcomeSuccess, 100911, 12, "paddock_privilege"},
		{audit.CodeAuditChainVerificationFailed, audit.OutcomeSuccess, 100914, 12, "paddock_integrity"},
		{audit.CodeDiskRecoveryKeyRevealed, audit.OutcomeSuccess, 100912, 10, "paddock_privilege"},
		{audit.CodeLocalAdminRevealed, audit.OutcomeSuccess, 100912, 10, "paddock_privilege"},
		{audit.CodePermissionProfileRootGrantConfirmed, audit.OutcomeSuccess, 100913, 10, "paddock_privilege"},
		{audit.CodeDiskRecoveryKeyRevealed, audit.OutcomeDenied, 100912, 10, "paddock_privilege"},
		{audit.CodeDeviceApproved, audit.OutcomeDenied, 100960, 7, "paddock"},
		{audit.CodeAdminLogin, audit.OutcomeFailure, 100920, 7, "paddock_identity"},
		{audit.CodeAdminLogin, audit.OutcomeDenied, 100920, 7, "paddock_identity"},
		{audit.CodeAdminLogin, audit.OutcomeSuccess, 100922, 5, "paddock_identity"},
		{audit.CodeAPITokenUseDenied, audit.OutcomeDenied, 100940, 7, "paddock"},
		{audit.CodeConfigApplied, audit.OutcomeSuccess, 100950, 5, "paddock"},
		{audit.CodeSettingsLoginChanged, audit.OutcomeSuccess, 100950, 5, "paddock"},
	}
	for _, c := range cases {
		t.Run(string(c.code)+"/"+string(c.outcome), func(t *testing.T) {
			dec, f := decodeLog(t, decs, syslogFrame(c.code, c.outcome))
			r := classify(t, rules, dec, f)
			require.Equal(t, c.id, r.ID)
			require.Equal(t, c.level, r.Level, "rule %d", r.ID)
			require.Contains(t, r.Groups, c.group, "rule %d", r.ID)
			require.Contains(t, r.Groups, "paddock")
		})
	}
}

// TestFrequencyRulesAreReachable: a frequency rule counts the events of its if_matched_sid rule, so that rule must be
// the one some registered code and outcome actually fires.
func TestFrequencyRulesAreReachable(t *testing.T) {
	rules := loadRules(t)
	decs := loadDecoders(t)
	reached := map[string]bool{}
	for _, code := range emitted() {
		for _, outcome := range outcomes {
			dec, f := decodeLog(t, decs, syslogFrame(code, outcome))
			reached[strconv.Itoa(classify(t, rules, dec, f).ID)] = true
		}
	}
	var n int
	for _, r := range rules {
		if r.Frequency == 0 {
			continue
		}
		n++
		for _, sid := range splitList(r.IfMatchedSID) {
			require.True(t, reached[sid], "frequency rule %d counts rule %s, which no event fires", r.ID, sid)
		}
	}
	require.Equal(t, 2, n, "the refused API token and the failed sign-in frequency rules")
}

// TestQuotesInDisplayStrings: an admin-chosen name with a quote is JSON-escaped in the body and must not cost the
// event its classification.
func TestQuotesInDisplayStrings(t *testing.T) {
	ev := sampleEvent(audit.CodeDeviceTamperSudoersChanged, audit.OutcomeSuccess)
	ev.Event.Actor = audit.Actor{Type: audit.ActorDevice, Display: `lt "17"`}
	ev.Event.Target.Display = `Bob's "laptop" \ 2`
	dec, f := decodeLog(t, loadDecoders(t), frameOf(ev))
	require.Equal(t, `lt "17"`, f["event.actor.display"])
	require.Equal(t, `Bob's "laptop" \ 2`, f["event.target.display"])
	r := classify(t, loadRules(t), dec, f)
	require.Equal(t, 100910, r.ID)
	require.Equal(t, 12, r.Level)
}

func TestMsgIDAliasesDecodeToTheFullCode(t *testing.T) {
	rules := loadRules(t)
	decs := loadDecoders(t)
	aliases := audit.MsgIDAliases()
	require.NotEmpty(t, aliases)
	for _, a := range aliases {
		frame := syslogFrame(a.Code, audit.OutcomeSuccess)
		require.Contains(t, frame, " paddock acme "+a.MsgID+" - ", "the frame carries the alias as MSGID")
		dec, f := decodeLog(t, decs, frame)
		require.Equal(t, "paddock", dec, a.Code)
		require.Equal(t, string(a.Code), f["event.code"])
		require.NotEqual(t, a.MsgID, f["event.code"])
		if mustBeHigh.MatchString(string(a.Code)) {
			require.GreaterOrEqual(t, classify(t, rules, dec, f).Level, 10, a.Code)
		}
	}
}

func TestEveryRuleCodePatternMatchesARegisteredCode(t *testing.T) {
	var n int
	for _, r := range loadRules(t) {
		for _, f := range r.Fields {
			if f.Name != "event.code" {
				continue
			}
			n++
			re := compile(t, "rule field", &pcre{Type: f.Type, Text: f.Text})
			var hit bool
			for _, c := range emitted() {
				hit = hit || re.MatchString(string(c))
			}
			require.True(t, hit, "rule %d: pattern %q matches no registered code", r.ID, f.Text)
		}
	}
	require.Positive(t, n)
}

func TestGoldenFramesDecode(t *testing.T) {
	rules := loadRules(t)
	decs := loadDecoders(t)
	for _, name := range []string{"syslog_event_success", "syslog_event_denied", "syslog_event_failure"} {
		raw, err := os.ReadFile(goldenDir + name + ".golden")
		require.NoError(t, err)
		dec, f := decodeLog(t, decs, string(raw))
		require.Equal(t, "paddock", dec, name)
		require.Equal(t, "device.wipe_requested", f["event.code"])
		require.Equal(t, "41", f["forward_seq"])
		require.Equal(t, "0193a1b2-0000-7000-8000-0000000000aa", f["event.event_id"])
		require.Equal(t, "acme", f["organization"])
		require.Equal(t, "laptop-17", f["event.params.name"])
		require.NotZero(t, classify(t, rules, dec, f).ID, name)
	}
	raw, err := os.ReadFile(goldenDir + "syslog_control_test.golden")
	require.NoError(t, err)
	dec, f := decodeLog(t, decs, string(raw))
	require.Equal(t, "paddock-ctl", dec, "a control message is not an audit event")
	require.Equal(t, "test", f["kind"])
	require.Equal(t, "acme", f["organization"])
	require.Equal(t, 100902, classify(t, rules, dec, f).ID)
}

func TestCheckpointDecodes(t *testing.T) {
	decs := loadDecoders(t)
	m := outbound.Message{Schema: outbound.MessageSchema, Kind: outbound.KindCheckpoint, Organization: "acme",
		SentAt: time.Date(2026, 11, 5, 1, 0, 0, 0, time.UTC), Day: "2026-11-04", EventCount: 812,
		ManifestSHA256: strings.Repeat("a", 64)}
	dec, f := decodeLog(t, decs, string(outbound.FormatSyslogControl(m, hostname)))
	require.Equal(t, "paddock-ctl", dec)
	require.Equal(t, "checkpoint", f["kind"])
	require.Equal(t, "acme", f["organization"])
	require.Equal(t, "2026-11-04", f["day"])
	require.Equal(t, "812", f["event_count"])
	r := classify(t, loadRules(t), dec, f)
	require.Equal(t, 100903, r.ID)
	require.Contains(t, r.Groups, "paddock_integrity")
}

// TestMissingEventDecodes: a replayed event the audit index no longer holds arrives as one frame with MSGID
// paddock.missing, PRI 132 and the MSG {schema, forward_seq, event_id, delivery_id, missing: true} (plan M12
// decision 21); the fixture is that frame.
func TestMissingEventDecodes(t *testing.T) {
	raw, err := os.ReadFile("testdata/syslog_missing.golden")
	require.NoError(t, err)
	require.Contains(t, string(raw), "<132>1 ")
	require.Contains(t, string(raw), " paddock acme paddock.missing - ")
	dec, f := decodeLog(t, loadDecoders(t), string(raw))
	require.Equal(t, "paddock", dec)
	require.Equal(t, "true", f["missing"])
	require.Equal(t, "9", f["forward_seq"])
	require.Equal(t, "0193a1b2-0000-7000-8000-0000000000aa", f["event_id"])
	require.Equal(t, "acme", f["organization"])
	r := classify(t, loadRules(t), dec, f)
	require.Equal(t, 100904, r.ID)
	require.Equal(t, 7, r.Level)
	require.Contains(t, r.Groups, "paddock_integrity")
}

func TestPullLoopWritesTheDecodedLine(t *testing.T) {
	doc, err := os.ReadFile(siemDocPath)
	require.NoError(t, err)
	require.Contains(t, string(doc), feedJQ, "siem.md's pull loop writes the line feedLine builds")
}

var (
	octetCount = regexp.MustCompile(`^\d+ `)
	syslogPRI  = regexp.MustCompile(`^<\d+>`)
)

// TestFramingVariantsClassifyAlike: the rsyslog relay hands Wazuh the message without the octet count and, depending
// on the remoted version, without the PRI; the decoders must classify all three shapes the same.
func TestFramingVariantsClassifyAlike(t *testing.T) {
	rules := loadRules(t)
	decs := loadDecoders(t)
	m := outbound.Message{Schema: outbound.MessageSchema, Kind: outbound.KindCheckpoint, Organization: "acme",
		SentAt: time.Date(2026, 11, 5, 1, 0, 0, 0, time.UTC), Day: "2026-11-04", EventCount: 812,
		ManifestSHA256: strings.Repeat("a", 64)}
	missing, err := os.ReadFile("testdata/syslog_missing.golden")
	require.NoError(t, err)
	frames := map[string]struct {
		frame string
		id    int
	}{
		"tamper":     {syslogFrame(audit.CodeDeviceTamperSudoersChanged, audit.OutcomeSuccess), 100910},
		"checkpoint": {string(outbound.FormatSyslogControl(m, hostname)), 100903},
		"missing":    {string(missing), 100904},
	}
	for name, c := range frames {
		noCount := octetCount.ReplaceAllString(c.frame, "")
		for variant, frame := range map[string]string{
			"as sent":           c.frame,
			"without count":     noCount,
			"without count/PRI": syslogPRI.ReplaceAllString(noCount, ""),
		} {
			t.Run(name+"/"+variant, func(t *testing.T) {
				dec, f := decodeLog(t, decs, frame)
				require.NotEmpty(t, dec)
				require.Equal(t, c.id, classify(t, rules, dec, f).ID)
			})
		}
	}
}

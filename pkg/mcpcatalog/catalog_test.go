package mcpcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestVersionIsHashOfTable(t *testing.T) {
	b, err := json.Marshal(Tools())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != Version {
		t.Errorf("Version %s, SHA-256 of the table %s: run make gen", Version, got)
	}
	if !strings.HasSuffix(Instructions, "Catalog version: "+Version+".") {
		t.Error("Instructions do not end with the catalog version")
	}
}

func TestToolsSortedAndUnique(t *testing.T) {
	tools := Tools()
	if len(tools) == 0 {
		t.Fatal("empty catalog")
	}
	names := map[string]bool{}
	patterns := map[string]bool{}
	for i, tl := range tools {
		if i > 0 && tools[i-1].Name >= tl.Name {
			t.Errorf("%s follows %s: not sorted by name", tl.Name, tools[i-1].Name)
		}
		if names[tl.Name] || patterns[tl.Pattern] {
			t.Errorf("duplicate tool %s / pattern %s", tl.Name, tl.Pattern)
		}
		names[tl.Name], patterns[tl.Pattern] = true, true
		if tl.Pattern != tl.Method+" "+tl.Path {
			t.Errorf("%s: pattern %q is not the mux form of %s %s", tl.Name, tl.Pattern, tl.Method, tl.Path)
		}
		if tl.Tag == "auth" || strings.HasPrefix(tl.Path, "/api/auth/") {
			t.Errorf("%s: the BFF tag auth is in the catalog", tl.Name)
		}
		if (tl.Method == "GET") != (tl.Class == ClassRead) {
			t.Errorf("%s: class %s for method %s", tl.Name, tl.Class, tl.Method)
		}
	}
}

func TestLookups(t *testing.T) {
	for _, tl := range Tools() {
		if got, ok := ByPattern(tl.Pattern); !ok || got.Name != tl.Name {
			t.Errorf("ByPattern(%q) = %s, %t", tl.Pattern, got.Name, ok)
		}
		if got, ok := ByName(tl.Name); !ok || got.Pattern != tl.Pattern {
			t.Errorf("ByName(%q) = %s, %t", tl.Name, got.Pattern, ok)
		}
	}
	if _, ok := ByName("noSuchOperation"); ok {
		t.Error("ByName found an unknown operation")
	}
	if _, ok := ByPattern("GET /api/v1/devices/{device_id}"); ok {
		t.Error("ByPattern found an unknown pattern")
	}
	if _, ok := ByName("login"); ok {
		t.Error("the auth operation login is in the catalog")
	}
}

func TestToolsReturnsCopy(t *testing.T) {
	a := Tools()
	a[0].Expose = !a[0].Expose
	if Tools()[0].Expose == a[0].Expose {
		t.Error("Tools exposes the internal table")
	}
	name := Exposed()[0].Name
	for label, schema := range map[string]json.RawMessage{
		"Tools": Tools()[0].InputSchema, "Exposed": Exposed()[0].InputSchema, "ByName": mustByName(t, name).InputSchema,
	} {
		schema[0] = 'X'
		if Tools()[0].InputSchema[0] == 'X' || mustByName(t, name).InputSchema[0] == 'X' {
			t.Errorf("%s shares InputSchema with the internal table", label)
		}
	}
}

func mustByName(t *testing.T, name string) Tool {
	t.Helper()
	tl, ok := ByName(name)
	if !ok {
		t.Fatalf("%s missing", name)
	}
	return tl
}

func TestExposedExcludesStepUpAndHidden(t *testing.T) {
	exposed := map[string]bool{}
	for _, tl := range Exposed() {
		exposed[tl.Name] = true
		if tl.StepUp || !tl.Expose {
			t.Errorf("%s is exposed with StepUp %t Expose %t", tl.Name, tl.StepUp, tl.Expose)
		}
	}
	stepUp := 0
	for _, tl := range Tools() {
		if tl.StepUp {
			stepUp++
		}
	}
	if stepUp < 18 {
		t.Errorf("%d step-up tools, want at least the 18 step-up specs of ADR 0044", stepUp)
	}
	for _, name := range []string{
		"feedAuditEvents", "lockDevice", "destroyDevice", "revealDeviceLocalAdmin", "revealDeviceRecoveryKey", "endAllSessions",
		"createApiToken", "revokeApiToken", "updateMe", "uploadAgentArtifact", "uploadAgentPackage",
		"generateAutoinstall", "downloadDeviceHeader",
	} {
		if _, ok := ByName(name); !ok {
			t.Errorf("%s is missing from the catalog", name)
		}
		if exposed[name] {
			t.Errorf("%s is exposed", name)
		}
	}
	if feed, ok := ByName("feedAuditEvents"); !ok || feed.Expose {
		t.Errorf("feedAuditEvents: found %t, Expose %t, want hidden (ADR 0044)", ok, feed.Expose)
	}
	for _, name := range []string{"getMe", "listDevices", "createDeviceGroup"} {
		if !exposed[name] {
			t.Errorf("%s is not exposed", name)
		}
	}
	if me, _ := ByName("getMe"); !me.Bootstrap || me.Scope != ScopeAny {
		t.Errorf("getMe: bootstrap %t scope %s", me.Bootstrap, me.Scope)
	}
}

func inputSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	tl, ok := ByName(name)
	if !ok {
		t.Fatalf("%s missing", name)
	}
	var m map[string]any
	if err := json.Unmarshal(tl.InputSchema, &m); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return m
}

func TestInputSchemas(t *testing.T) {
	for _, tl := range Tools() {
		s := string(tl.InputSchema)
		if !json.Valid(tl.InputSchema) || strings.Contains(s, `"$ref"`) || strings.Contains(s, `"nullable"`) ||
			strings.Contains(s, `"readOnly"`) {
			t.Errorf("%s: input schema is not a self-contained JSON Schema: %.200s", tl.Name, s)
		}
	}
	list := inputSchema(t, "listDevices")["properties"].(map[string]any)
	for _, p := range []string{"page", "page_size", "sort", "q"} {
		if _, ok := list[p]; !ok {
			t.Errorf("listDevices lacks the query parameter %s", p)
		}
	}
	create := inputSchema(t, "createDeviceGroup")
	if req, _ := create["required"].([]any); !slices.Contains(req, any("body")) {
		t.Errorf("createDeviceGroup: body not required (%v)", create["required"])
	}
	body := create["properties"].(map[string]any)["body"].(map[string]any)
	if _, ok := body["properties"].(map[string]any)["name"]; !ok {
		t.Errorf("createDeviceGroup body is not the dereferenced request schema: %v", body)
	}
	staleness := body["properties"].(map[string]any)["staleness"].(map[string]any)
	if anyOf, ok := staleness["anyOf"].([]any); !ok || anyOf[len(anyOf)-1].(map[string]any)["type"] != "null" {
		t.Errorf("nullable staleness was not rewritten to a union with null: %v", staleness)
	}
}

func TestDescriptions(t *testing.T) {
	for _, tl := range Tools() {
		sentence := "Changes data; needs your MCP write access."
		if tl.Class == ClassRead {
			sentence = "Read-only."
		}
		if !strings.Contains(tl.Description, sentence) {
			t.Errorf("%s: description lacks %q", tl.Name, sentence)
		}
	}
	d, _ := ByName("listDevices")
	if !strings.Contains(d.Description, "Paged: page, page_size (10/25/50/100), sort (allow list: ") {
		t.Errorf("listDevices description lacks the paging sentence: %q", d.Description)
	}
}

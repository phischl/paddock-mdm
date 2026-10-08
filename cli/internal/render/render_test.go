package render_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/oasdiff/yaml"

	"github.com/phischl/paddock-mdm/cli/internal/render"
)

func decode(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestExampleRoundTrip: examples/paddock.yml → JSON → YAML → JSON keeps every value and renders multi-line
// strings as literal blocks.
func TestExampleRoundTrip(t *testing.T) {
	src, err := os.ReadFile("../../../examples/paddock.yml")
	if err != nil {
		t.Fatal(err)
	}
	j1, err := yaml.YAMLToJSON(src)
	if err != nil {
		t.Fatal(err)
	}
	y, err := render.JSONToYAML(j1)
	if err != nil {
		t.Fatal(err)
	}
	j2, err := yaml.YAMLToJSON(y)
	if err != nil {
		t.Fatalf("rendered YAML does not parse: %v\n%s", err, y)
	}
	if !reflect.DeepEqual(decode(t, j1), decode(t, j2)) {
		t.Fatalf("round trip changed the document:\n%s", y)
	}
	out := string(y)
	if !strings.Contains(out, "content: |\n      Managed by Paddock.\n      Changes are overwritten.\n") {
		t.Fatalf("multi-line content is not a literal block:\n%s", out)
	}
	if !strings.Contains(out, "sudo_lecture_text: |-\n") {
		t.Fatalf("the lecture without a final newline is not a |- block:\n%s", out)
	}
}

// TestJSONToYAMLKeepsKeyOrder: the keys of GET /api/v1/config keep the order the server sends (the schema's);
// YAMLToJSON sorts keys, so the input here is ordered JSON as the server encodes it.
func TestJSONToYAMLKeepsKeyOrder(t *testing.T) {
	y, err := render.JSONToYAML([]byte(`{"api_version":"paddock/v1","kind":"OrganizationConfig","settings":{"login":{"z":1},` +
		`"updates":{"b":1,"a":2}},"device_groups":[{"name":"x","description":""}],"permission_profiles":[],"managed_files":[],` +
		`"managed_units":[],"package_holds":[],"profile_assignments":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	out := string(y)
	last := -1
	for _, k := range []string{"api_version:", "kind:", "settings:", "login:", "updates:", "device_groups:", "permission_profiles:",
		"managed_files:", "managed_units:", "package_holds:", "profile_assignments:"} {
		i := strings.Index(out, k)
		if i <= last {
			t.Fatalf("%s out of order:\n%s", k, out)
		}
		last = i
	}
	if !strings.Contains(out, "    b: 1\n    a: 2\n") || !strings.Contains(out, "  - name: \"x\"\n    description: \"\"\n") {
		t.Fatalf("nested order or list layout:\n%s", out)
	}
}

func TestJSONToYAMLValues(t *testing.T) {
	for _, s := range []string{"plain", "", "a: b", "- x", "yes", "0644", "two\nlines", "two\nlines\n", "ends\n\n", " leading\nspace",
		"tab\there", "carriage\r\nreturn", "\nstarts with a newline", "über", "#comment", "null", "1e3", `quote"s`} {
		raw, _ := json.Marshal(map[string]any{"v": s, "list": []any{s, map[string]any{"k": s, "n": nil}}, "empty": []any{}, "obj": map[string]any{}})
		y, err := render.JSONToYAML(raw)
		if err != nil {
			t.Fatal(err)
		}
		back, err := yaml.YAMLToJSON(y)
		if err != nil {
			t.Fatalf("%q: %v\n%s", s, err, y)
		}
		if !reflect.DeepEqual(decode(t, raw), decode(t, back)) {
			t.Errorf("%q does not round-trip:\n%s\n%s", s, y, back)
		}
	}
	for _, num := range []string{`{"n":6}`, `{"n":-1.5}`, `{"n":true}`, `[1,"a",[2,[]],{}]`, `{}`, `[]`, `"x"`} {
		y, err := render.JSONToYAML([]byte(num))
		if err != nil {
			t.Fatal(err)
		}
		back, err := yaml.YAMLToJSON(y)
		if err != nil || !reflect.DeepEqual(decode(t, []byte(num)), decode(t, back)) {
			t.Errorf("%s → %s → %s (%v)", num, y, back, err)
		}
	}
	if _, err := render.JSONToYAML([]byte(`{"a":1} {}`)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestPlanText(t *testing.T) {
	p := render.Plan{Changes: []render.Change{
		{Section: "package_holds", Key: "firefox", Action: "delete"},
		{Section: "managed_files", Key: "/etc/motd", Action: "create"},
		{Section: "settings.login", Action: "update", Fields: []render.FieldChange{{Name: "hello_enabled", Before: false, After: true}}},
		{Section: "managed_units", Key: "laptops:foo.service", Action: "update", Fields: []render.FieldChange{{Name: "active", Before: true, After: false}}},
	}, Created: 1, Updated: 2, Deleted: 1}
	var b strings.Builder
	if err := render.PlanText(&b, p); err != nil {
		t.Fatal(err)
	}
	want := "- package_holds firefox\n+ managed_files /etc/motd\n~ settings.login hello_enabled: false -> true\n" +
		"~ managed_units laptops:foo.service active: true -> false\nPlan: 1 to create, 2 to update, 1 to delete\n"
	if b.String() != want {
		t.Fatalf("plan text:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestDevicesTable(t *testing.T) {
	v, contact := int64(4), "2026-10-08T10:00:00Z"
	var b strings.Builder
	if err := render.DevicesTable(&b, render.DevicePage{Items: []render.Device{
		{Hostname: "a", State: "active", LastContactAt: &contact, AppliedBundleVersion: &v},
		{Hostname: "b", State: "pending"},
	}, Page: 2, PageSize: 10, Total: 21, TotalCapped: false}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "HOSTNAME") || !strings.Contains(out, contact) || !strings.HasSuffix(out, "page 2 of 3 (total 21)\n") {
		t.Fatalf("table:\n%s", out)
	}
	b.Reset()
	_ = render.DevicesTable(&b, render.DevicePage{Page: 1, PageSize: 100, Total: 10000, TotalCapped: true})
	if !strings.HasSuffix(b.String(), "page 1 of 100 (total 10000+)\n") {
		t.Fatalf("capped footer: %s", b.String())
	}
}

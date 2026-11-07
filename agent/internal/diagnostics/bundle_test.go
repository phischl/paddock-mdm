package diagnostics

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/dsse"
)

// secretBundleFields are the bundle fields that never leave the device in clear: the Fleet enroll secret and the
// content of a managed file, which an administrator may fill with anything.
var secretBundleFields = []string{"inventory.enroll_secret", "resources.spec:file.content"}

// resourceSpecs are the spec types of the resource types the server puts into bundle.Resources.
var resourceSpecs = map[string]reflect.Type{
	bundle.TypeTime:        reflect.TypeFor[bundle.TimeSpec](),
	bundle.TypeFile:        reflect.TypeFor[bundle.FileSpec](),
	bundle.TypeSystemdUnit: reflect.TypeFor[bundle.UnitSpec](),
	bundle.TypeLogin:       reflect.TypeFor[bundle.LoginSpec](),
	bundle.TypeSudo:        reflect.TypeFor[bundle.SudoSpec](),
}

// sample builds a JSON value of type t in which every string leaf carries its own path, and records the leaf paths
// (true for a string leaf).
func sample(t reflect.Type, path string, leaves map[string]bool) any {
	join := func(name string) string {
		if path == "" {
			return name
		}
		return path + "." + name
	}
	switch {
	case t == reflect.TypeFor[time.Time]():
		leaves[path] = true
		return "v:" + path
	case t.Kind() == reflect.Pointer:
		return sample(t.Elem(), path, leaves)
	case t.Kind() == reflect.Map:
		return map[string]any{"k": sample(t.Elem(), join("*"), leaves)}
	case t.Kind() == reflect.Slice:
		return []any{sample(t.Elem(), path, leaves)}
	case t.Kind() == reflect.Struct:
		obj := map[string]any{}
		for f := range t.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			obj[name] = sample(f.Type, join(name), leaves)
		}
		return obj
	case t.Kind() == reflect.String:
		leaves[path] = true
		return "v:" + path
	case t.Kind() == reflect.Bool:
		leaves[path] = false
		return true
	default:
		leaves[path] = false
		return 7
	}
}

// fullBundle is a bundle payload with every field of pkg/bundle set to a value naming its path, and one resource of
// every type the server sends.
func fullBundle(t *testing.T) (payload []byte, leaves map[string]bool) {
	t.Helper()
	leaves = map[string]bool{}
	root := sample(reflect.TypeFor[bundle.Bundle](), "", leaves).(map[string]any)
	delete(leaves, "resources.spec")
	var resources []any
	for typ, spec := range resourceSpecs {
		resources = append(resources, map[string]any{"id": "v:resources.id", "type": typ,
			"spec": sample(spec, "resources.spec:"+typ, leaves)})
	}
	leaves["resources.type"] = false
	root["resources"] = resources
	payload, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return payload, leaves
}

func envelope(t *testing.T, payload []byte) []byte {
	t.Helper()
	env, err := dsse.New(bundle.PayloadType, payload, dsse.Signature{KeyID: "bundle:v1", Sig: "c2ln"}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestPublicBundleFieldsClassified fails when pkg/bundle grows a field that is neither on the public allow-list nor
// a known secret, or when the allow-list names a field that no longer exists: every field must be classified.
func TestPublicBundleFieldsClassified(t *testing.T) {
	_, leaves := fullBundle(t)
	public := publicBundleFields()
	for path := range leaves {
		if !public[path] && !slices.Contains(secretBundleFields, path) {
			t.Errorf("bundle field %s is not classified as public or secret", path)
		}
	}
	for path := range public {
		if _, ok := leaves[path]; !ok {
			t.Errorf("allow-listed field %s is not a field of pkg/bundle", path)
		}
	}
	for _, path := range secretBundleFields {
		if _, ok := leaves[path]; public[path] || !ok {
			t.Errorf("secret field %s is allow-listed or unknown", path)
		}
	}
}

// TestRedactBundleKnownFields: with every field of pkg/bundle set, no secret field and no managed-file content
// survives, and every public field is kept.
func TestRedactBundleKnownFields(t *testing.T) {
	payload, leaves := fullBundle(t)
	got := string(redactBundle(envelope(t, payload)))
	for _, path := range secretBundleFields {
		if strings.Contains(got, `"v:`+path+`"`) {
			t.Fatalf("secret %s survives:\n%s", path, got)
		}
	}
	for path, isString := range leaves {
		if isString && !slices.Contains(secretBundleFields, path) && !strings.Contains(got, `"v:`+path+`"`) {
			t.Errorf("public field %s is lost", path)
		}
	}
	if strings.Contains(got, `\u003c`) || !strings.Contains(got, `"`+Redacted+`"`) {
		t.Fatalf("redaction marker is not literal:\n%s", got)
	}
}

// TestRedactBundleFailsClosed: a field this agent does not know — at the top level, inside a known section, inside
// a known resource spec, as a whole unknown resource type, under a map key or as an object where a scalar is
// expected — is replaced, whatever its name.
func TestRedactBundleFailsClosed(t *testing.T) {
	payload := `{"schema_version":2,"device_id":"dev-1","psk":"planted-psk-aaaa",
		"inventory":{"fleet_url":"https://fleet.example","api_key":"planted-api-key-aaaa","package":{"version":"1","auth":"planted-auth-aaaa"}},
		"agent":{"checkin_interval_s":60,"supervisor_packages":{"amd64":{"version":"2","bearer":"planted-bearer-aaaa"}}},
		"login_extra":{"recovery_pin":"planted-pin-aaaa"},
		"resources":[
			{"id":"file:/etc/motd","type":"file","spec":{"path":"/etc/motd","content":"planted-content-aaaa","recovery_pin":"planted-pin2-aaaa"}},
			{"id":"vpn:corp","type":"vpn","spec":{"server":"vpn.example","psk":"planted-vpn-aaaa"}},
			{"id":"unit:x","type":"systemd_unit","spec":{"unit":{"name":"planted-nested-aaaa"}}}
		],
		"hostname":{"name":["planted-list-ok",{"secret":"planted-in-list-aaaa"}]}}`
	got := string(redactBundle(envelope(t, []byte(payload))))
	if strings.Contains(got, "aaaa") || strings.Contains(got, "vpn.example") {
		t.Fatalf("an unknown field survives:\n%s", got)
	}
	for _, want := range []string{`"device_id": "dev-1"`, `"fleet_url": "https://fleet.example"`, `"checkin_interval_s": 60`,
		`"version": "2"`, `"path": "/etc/motd"`, `"type": "vpn"`, `"psk": "<redacted>"`, `"spec": "<redacted>"`} {
		if !strings.Contains(got, want) {
			t.Errorf("rendering lacks %s:\n%s", want, got)
		}
	}
}

// TestRedactBundleNotAnObject: a payload that is JSON but not an object cannot be checked and is replaced whole.
func TestRedactBundleNotAnObject(t *testing.T) {
	if got := string(redactBundle(envelope(t, []byte(`["planted-aaaa"]`)))); got != Redacted+"\n" {
		t.Fatalf("%q", got)
	}
}

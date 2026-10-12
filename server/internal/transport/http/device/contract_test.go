package device_test

import (
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestEventTypeEnumMatchesProtocol keeps the Event.type enum of the device API contract equal to
// protocol.EventTypes: the gateway validates against the Go list, so a drift would only show in the document (PDK-073).
func TestEventTypeEnumMatchesProtocol(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	doc, err := openapi3.NewLoader().LoadFromFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "api", "openapi", "device.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	event, ok := doc.Components.Schemas["Event"]
	if !ok || event.Value == nil {
		t.Fatal("device.yaml: schema Event missing")
	}
	typ, ok := event.Value.Properties["type"]
	if !ok || typ.Value == nil {
		t.Fatal("device.yaml: Event.type missing")
	}
	var spec []string
	for _, v := range typ.Value.Enum {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("device.yaml: Event.type enum value %v is not a string", v)
		}
		spec = append(spec, s)
	}
	slices.Sort(spec)
	want := slices.Sorted(slices.Values(protocol.EventTypes))
	if !slices.Equal(spec, want) {
		t.Errorf("device.yaml Event.type enum differs from protocol.EventTypes\n missing in spec: %v\n not in Go:       %v",
			minus(want, spec), minus(spec, want))
	}
}

// minus returns the elements of a that b does not contain, duplicates included.
func minus(a, b []string) []string {
	rest := slices.Clone(b)
	var out []string
	for _, s := range a {
		if i := slices.Index(rest, s); i >= 0 {
			rest = slices.Delete(rest, i, i+1)
			continue
		}
		out = append(out, s)
	}
	return out
}

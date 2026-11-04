package agent

import (
	"context"
	"encoding/json"
	"maps"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
)

// TestCheckinReportsOSRelease (PDK-695): the check-in carries ID and VERSION_ID, also when /etc/os-release is the
// symlink to /usr/lib/os-release that the fake reports as no data; without a readable file the field is left out.
func TestCheckinReportsOSRelease(t *testing.T) {
	want := map[string]string{"id": "ubuntu", "version_id": "26.04"}
	const lib = "PRETTY_NAME=\"Ubuntu 26.04 LTS\"\nID=ubuntu\nVERSION_ID=\"26.04\"\n"
	for name, tc := range map[string]struct {
		files map[string]*fakesys.File
		want  map[string]string
	}{
		"etc": {map[string]*fakesys.File{"/etc/os-release": {Data: []byte(lib)}}, want},
		"usr lib fallback": {map[string]*fakesys.File{
			"/etc/os-release": {Symlink: true}, "/usr/lib/os-release": {Data: []byte(lib)}}, want},
		"single quotes":      {map[string]*fakesys.File{"/etc/os-release": {Data: []byte("ID='ubuntu'\nVERSION_ID='26.04'\n")}}, want},
		"unreadable":         {map[string]*fakesys.File{}, nil},
		"without version_id": {map[string]*fakesys.File{"/etc/os-release": {Data: []byte("ID=debian\n")}}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAgent(t, testgw.New(t))
			sys := fakesys.New()
			maps.Copy(sys.Files, tc.files)
			a.d.Sys = sys
			got := a.checkinRequest(context.Background()).OSRelease
			if !maps.Equal(got, tc.want) {
				t.Fatalf("os_release %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCheckinWithoutSystemLeavesOSReleaseOut: an agent without a system adapter sends no field, so the server keeps
// the enrollment value.
func TestCheckinWithoutSystemLeavesOSReleaseOut(t *testing.T) {
	a := newAgent(t, testgw.New(t))
	req := a.checkinRequest(context.Background())
	body, err := json.Marshal(req)
	if err != nil || req.OSRelease != nil {
		t.Fatalf("os_release %v (%v)", req.OSRelease, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["os_release"]; ok {
		t.Fatalf("body carries os_release: %s", body)
	}
}

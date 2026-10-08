package revoke

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// crypttabTools answers cryptsetup isLuks with exit 0 for the paths in luks (exit 1 otherwise) and cryptsetup
// luksUUID with the entry of uuids (exit 1 without one).
type crypttabTools struct {
	luks  []string
	uuids map[string]string
}

func (f *crypttabTools) Command(_ context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	path := args[len(args)-1]
	if name == "cryptsetup" && args[0] == "luksUUID" {
		if id, ok := f.uuids[path]; ok {
			return id + "\n", "", 0, nil
		}
		return "", "", 1, nil
	}
	for _, l := range f.luks {
		if name == "cryptsetup" && args[0] == "isLuks" && l == path {
			return "", "", 0, nil
		}
	}
	return "", "", 1, nil
}

// fakeRoot is a temporary root with empty device files and an /etc/crypttab (none if crypttab is "").
func fakeRoot(t *testing.T, crypttab string, devices ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range devices {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if crypttab != "" {
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, CrypttabFile), []byte(crypttab), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestCrypttabTargets (plan M4c.1 decision 1, PDK-009): the targets are the volumes the shared selection of
// agent/internal/luks finds, in crypttab order with the root volume last, with the LUKS UUID of every volume
// cryptsetup reported one for; the root volume is a target once even when crypttab lists it.
func TestCrypttabTargets(t *testing.T) {
	root := fakeRoot(t, strings.Join([]string{
		"dm_crypt-0 /dev/vda3 none luks", "data /dev/vdb1 none luks", "home /dev/vdc1 none luks", "label LABEL=x none luks", "",
	}, "\n"), "/dev/vda3", "/dev/vdb1", "/dev/vdc1")
	tools := &crypttabTools{luks: []string{"/dev/vda3", "/dev/vdb1", "/dev/vdc1"},
		uuids: map[string]string{"/dev/vdb1": "1b6a3c1e-0000-4000-8000-00000000000b", "/dev/vda3": "1b6a3c1e-0000-4000-8000-00000000000a"}}
	got := crypttabTargets(context.Background(), tools, root, "/dev/vda3")
	want := Targets{Devices: []string{"/dev/vdb1", "/dev/vdc1", "/dev/vda3"},
		UUIDs: map[string]string{"/dev/vdb1": "1b6a3c1e-0000-4000-8000-00000000000b"}, Unresolved: []string{"LABEL=x"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets %+v\nwant %+v", got, want)
	}
}

// TestCrypttabTargetsShared (PDK-009 review round 2): a clone of the root volume stays a target, listed as shared.
func TestCrypttabTargetsShared(t *testing.T) {
	root := fakeRoot(t, "clone /dev/vdb none luks\n", "/dev/vda3", "/dev/vdb")
	const rootID = "1b6a3c1e-0000-4000-8000-00000000000a"
	tools := &crypttabTools{luks: []string{"/dev/vdb"}, uuids: map[string]string{"/dev/vda3": rootID, "/dev/vdb": rootID}}
	got := crypttabTargets(context.Background(), tools, root, "/dev/vda3")
	want := Targets{Devices: []string{"/dev/vdb", "/dev/vda3"}, UUIDs: map[string]string{"/dev/vdb": rootID}, Shared: []string{"/dev/vdb"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets %+v\nwant %+v", got, want)
	}
}

// TestCrypttabTargetsUnreadable (review round 1): an unreadable /etc/crypttab is reported as unresolved, and the
// root volume is still a target.
func TestCrypttabTargetsUnreadable(t *testing.T) {
	root := fakeRoot(t, "", "/dev/vda3")
	if err := os.MkdirAll(filepath.Join(root, CrypttabFile), 0o755); err != nil {
		t.Fatal(err)
	}
	got := crypttabTargets(context.Background(), &crypttabTools{}, root, "/dev/vda3")
	if !reflect.DeepEqual(got, Targets{Devices: []string{"/dev/vda3"}, Unresolved: []string{CrypttabFile}}) {
		t.Fatalf("targets %+v", got)
	}
}

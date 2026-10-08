package revoke

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// fakeDev is a /dev tree below a temporary root with the udev links of /dev/disk, as relative symlinks like udev
// creates them.
func fakeDev(t *testing.T, links map[string]string, devices ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range devices {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, d)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range links {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, link)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// isLuksTools answers cryptsetup isLuks for the devices in luks (exit 0) and every other device (exit 1); it logs
// every call.
type isLuksTools struct {
	luks []string
	log  []string
}

func (f *isLuksTools) Command(_ context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	f.log = append(f.log, name+" "+strings.Join(args, " "))
	if name == "cryptsetup" && args[0] == "isLuks" && slices.Contains(f.luks, args[len(args)-1]) {
		return "", "", 0, nil
	}
	return "", "", 1, nil
}

// TestVolumes (plan M4c.1 decisions 1 and 3): a fake crypttab with the root volume, an extra LUKS volume, a plain
// dm-crypt swap and an unresolvable entry. The extra volume comes first and the root volume last, each once; the swap
// is no target; the unresolvable entries are reported and do not stop the others.
func TestVolumes(t *testing.T) {
	root := fakeDev(t, map[string]string{
		"/dev/disk/by-uuid/aaaa-root":     "../../vda3",
		"/dev/disk/by-uuid/bbbb-data":     "../../vdb1",
		"/dev/disk/by-partuuid/cccc-home": "../../vdc1",
	}, "/dev/vda3", "/dev/vdb1", "/dev/vdc1", "/dev/vda2")
	crypttab := []byte(`# <name> <device> <password> <options>
dm_crypt-0 UUID=aaaa-root none luks,discard
data UUID="bbbb-data" /etc/keys/data.key luks

home PARTUUID=cccc-home none luks
swap /dev/vda2 /dev/urandom swap,cipher=aes-xts-plain64
again /dev/disk/by-uuid/bbbb-data none luks
gone UUID=dddd-gone none luks
label LABEL=backup none luks
escape UUID=../../vdb1 none luks
noname
`)
	tools := &isLuksTools{luks: []string{"/dev/vda3", "/dev/vdb1", "/dev/vdc1"}}
	got := volumes(context.Background(), tools, "/dev/vda3", crypttab, func(s string) (string, error) { return resolveSource(root, s) })
	want := Targets{
		Devices:    []string{"/dev/vdb1", "/dev/vdc1", "/dev/vda3"},
		Unresolved: []string{"UUID=dddd-gone", "LABEL=backup", "UUID=../../vdb1", "noname"},
	}
	t.Logf("targets: %+v", got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets %+v\nwant %+v", got, want)
	}
	for _, entry := range tools.log {
		if !strings.HasPrefix(entry, "cryptsetup isLuks -- ") {
			t.Fatalf("target selection ran %q", entry)
		}
	}
}

// TestVolumesWithoutCrypttab: without /etc/crypttab the root volume is the only target.
func TestVolumesWithoutCrypttab(t *testing.T) {
	root := fakeDev(t, nil, "/dev/nvme0n1p3")
	got := volumes(context.Background(), &isLuksTools{}, "/dev/nvme0n1p3", nil, func(s string) (string, error) { return resolveSource(root, s) })
	if !reflect.DeepEqual(got, Targets{Devices: []string{"/dev/nvme0n1p3"}}) {
		t.Fatalf("targets %+v", got)
	}
}

// TestResolveSource: only UUID=, PARTUUID= and /dev paths resolve, and never to a path outside /dev.
func TestResolveSource(t *testing.T) {
	root := fakeDev(t, map[string]string{
		"/dev/disk/by-uuid/aaaa": "../../vda3",
		"/dev/disk/by-uuid/out":  "../../../etc/passwd",
		"/dev/mapper/dm_crypt-0": "../dm-0",
	}, "/dev/vda3", "/dev/dm-0", "/etc/passwd")
	cases := map[string]string{
		"UUID=aaaa":              "/dev/vda3",
		"UUID='aaaa'":            "/dev/vda3",
		"/dev/disk/by-uuid/aaaa": "/dev/vda3",
		"/dev/vda3":              "/dev/vda3",
		"/dev/mapper/dm_crypt-0": "/dev/dm-0",
		"UUID=out":               "",
		"UUID=":                  "",
		"UUID=a/../../../etc":    "",
		"/dev/../etc/passwd":     "",
		"/etc/passwd":            "",
		"LABEL=aaaa":             "",
		"UUID=missing":           "",
	}
	for source, want := range cases {
		got, err := resolveSource(root, source)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("%s: %q %v, want %q", source, got, err, want)
		}
	}
}

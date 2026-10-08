package luks

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDev is a /dev tree below a temporary root with the udev links of /dev/disk, as relative symlinks like udev
// creates them.
func fakeDev(t *testing.T, links map[string]string, files ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), nil, 0o600); err != nil {
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

// isLuksTools answers cryptsetup isLuks with exit 0 for the paths in luks and exit 1 for every other one, the exit
// of cryptsetup for a plain volume and for an unreadable one alike, and cryptsetup luksUUID with the entry of uuids
// (exit 1 without one). A path in hang blocks until release is closed, whatever the context says (a command stuck in
// the kernel). It logs every call.
type isLuksTools struct {
	luks    []string
	uuids   map[string]string
	hang    []string
	release chan struct{}
	mu      sync.Mutex
	log     []string
}

func (f *isLuksTools) Command(_ context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	f.mu.Lock()
	f.log = append(f.log, name+" "+strings.Join(args, " "))
	f.mu.Unlock()
	path := args[len(args)-1]
	for _, h := range f.hang {
		if h == path {
			<-f.release
		}
	}
	if name == "cryptsetup" && args[0] == "luksUUID" {
		if id, ok := f.uuids[path]; ok {
			return id + "\n", "", 0, nil
		}
		return "", "not a LUKS device", 1, nil
	}
	for _, l := range f.luks {
		if name == "cryptsetup" && args[0] == "isLuks" && l == path {
			return "", "", 0, nil
		}
	}
	return "", "", 1, nil
}

// TestParseCrypttab (plan M4c.1 decisions 1 and 3, review round 1, PDK-009): a fake crypttab with the root volume,
// an extra LUKS volume, a LUKS volume with a detached header, a plain swap, a volume whose isLuks fails with exit 1
// without plain options (an I/O error) and unresolvable entries. Every extra volume comes once, in crypttab order and
// with its LUKS UUID (upper case is normalized; one without a UUID keeps ""); the detached volume is read through its
// header; the swap is no volume; every other failure is unresolved.
func TestParseCrypttab(t *testing.T) {
	root := fakeDev(t, map[string]string{
		"/dev/disk/by-uuid/aaaa-root":     "../../vda3",
		"/dev/disk/by-uuid/bbbb-data":     "../../vdb1",
		"/dev/disk/by-partuuid/cccc-home": "../../vdc1",
	}, "/dev/vda3", "/dev/vdb1", "/dev/vdc1", "/dev/vda2", "/dev/vdd", "/dev/vde", "/boot/luks/vault.img")
	crypttab := []byte(`# <name> <device> <password> <options>
dm_crypt-0 UUID=aaaa-root none luks,discard
data UUID="bbbb-data" /etc/keys/data.key luks

home PARTUUID=cccc-home none luks
vault /dev/vdd none luks,header=/boot/luks/vault.img
swap /dev/vda2 /dev/urandom swap,cipher=aes-xts-plain64
broken /dev/vde none luks
again /dev/disk/by-uuid/bbbb-data none luks
gone UUID=dddd-gone none luks
lostheader /dev/vdd none header=/boot/luks/missing.img
label LABEL=backup none luks
escape UUID=../../vdb1 none luks
noname
`)
	tools := &isLuksTools{luks: []string{"/dev/vda3", "/dev/vdb1", "/dev/vdc1", "/boot/luks/vault.img"},
		uuids: map[string]string{"/dev/vdb1": "1b6a3c1e-0000-4000-8000-00000000000b", "/boot/luks/vault.img": "1B6A3C1E-0000-4000-8000-00000000000D"}}
	got := ParseCrypttab(context.Background(), tools, root, "/dev/vda3", crypttab, time.Minute)
	want := Crypttab{
		Root: "/dev/vda3",
		Volumes: []CrypttabVolume{{Header: "/dev/vdb1", UUID: "1b6a3c1e-0000-4000-8000-00000000000b"}, {Header: "/dev/vdc1"},
			{Header: "/boot/luks/vault.img", UUID: "1b6a3c1e-0000-4000-8000-00000000000d"}},
		Unresolved: []string{"/dev/vde", "UUID=dddd-gone", "/dev/vdd", "LABEL=backup", "UUID=../../vdb1", "noname"},
	}
	t.Logf("crypttab: %+v", got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crypttab %+v\nwant %+v", got, want)
	}
	for _, entry := range tools.log {
		if !strings.HasPrefix(entry, "cryptsetup isLuks -- ") && !strings.HasPrefix(entry, "cryptsetup luksUUID -- ") {
			t.Fatalf("the volume selection ran %q", entry)
		}
	}
}

// TestParseCrypttabSharedUUID (PDK-009, review round 1): two volumes with the same LUKS UUID (a cloned header) are
// both unresolved, and so is a volume with the root volume's UUID; the other volumes stay.
func TestParseCrypttabSharedUUID(t *testing.T) {
	root := fakeDev(t, nil, "/dev/vda3", "/dev/vdb", "/dev/vdc", "/dev/vdd", "/dev/vde")
	const shared, rootID = "1b6a3c1e-0000-4000-8000-0000000000ee", "1b6a3c1e-0000-4000-8000-0000000000aa"
	tools := &isLuksTools{luks: []string{"/dev/vdb", "/dev/vdc", "/dev/vdd", "/dev/vde"},
		uuids: map[string]string{"/dev/vda3": rootID, "/dev/vdb": shared, "/dev/vdc": "1b6a3c1e-0000-4000-8000-00000000000c",
			"/dev/vdd": shared, "/dev/vde": rootID}}
	crypttab := []byte("b /dev/vdb none luks\nc /dev/vdc none luks\nd /dev/vdd none luks\ne /dev/vde none luks\n")
	got := ParseCrypttab(context.Background(), tools, root, "/dev/vda3", crypttab, time.Minute)
	want := Crypttab{Root: "/dev/vda3", Volumes: []CrypttabVolume{{Header: "/dev/vdc", UUID: "1b6a3c1e-0000-4000-8000-00000000000c"}},
		Unresolved: []string{"/dev/vdb", "/dev/vdd", "/dev/vde"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crypttab %+v\nwant %+v", got, want)
	}
}

// TestReadCrypttabMissing: without /etc/crypttab the root volume is the only volume.
func TestReadCrypttabMissing(t *testing.T) {
	root := fakeDev(t, nil, "/dev/nvme0n1p3")
	got := ReadCrypttab(context.Background(), &isLuksTools{}, root, "/dev/nvme0n1p3", time.Minute)
	if !reflect.DeepEqual(got, Crypttab{Root: "/dev/nvme0n1p3"}) {
		t.Fatalf("crypttab %+v", got)
	}
}

// TestReadCrypttabUnreadable (review round 1): an unreadable /etc/crypttab is reported as unresolved.
func TestReadCrypttabUnreadable(t *testing.T) {
	root := fakeDev(t, nil, "/dev/vda3")
	// A directory in place of the file: reading it fails with EISDIR, as an unreadable file would.
	if err := os.MkdirAll(filepath.Join(root, CrypttabFile), 0o755); err != nil {
		t.Fatal(err)
	}
	got := ReadCrypttab(context.Background(), &isLuksTools{}, root, "/dev/vda3", time.Minute)
	if !reflect.DeepEqual(got, Crypttab{Root: "/dev/vda3", Unresolved: []string{CrypttabFile}}) {
		t.Fatalf("crypttab %+v", got)
	}
}

// TestParseCrypttabHungDevice (review round 1): a device whose isLuks hangs beyond every timeout does not hold up
// the selection; it and every entry after it are unresolved.
func TestParseCrypttabHungDevice(t *testing.T) {
	root := fakeDev(t, nil, "/dev/vda3", "/dev/vdb", "/dev/vdc", "/dev/vdd")
	tools := &isLuksTools{luks: []string{"/dev/vdb", "/dev/vdc", "/dev/vdd"}, hang: []string{"/dev/vdc"}, release: make(chan struct{})}
	t.Cleanup(func() { close(tools.release) })
	crypttab := []byte("b /dev/vdb none luks\nc /dev/vdc none luks\nd /dev/vdd none luks\n")
	start := time.Now()
	got := ParseCrypttab(context.Background(), tools, root, "/dev/vda3", crypttab, 100*time.Millisecond)
	want := Crypttab{Root: "/dev/vda3", Volumes: []CrypttabVolume{{Header: "/dev/vdb"}}, Unresolved: []string{"/dev/vdc", "/dev/vdd"}}
	if !reflect.DeepEqual(got, want) || time.Since(start) > 5*time.Second {
		t.Fatalf("crypttab %+v after %s", got, time.Since(start))
	}
}

// TestUUID: luksUUID output is trimmed and lowercased; anything that is no UUID is an error.
func TestUUID(t *testing.T) {
	tools := &isLuksTools{uuids: map[string]string{"/dev/a": "1B6A3C1E-0000-4000-8000-00000000000A", "/dev/b": "not-a-uuid"}}
	if id, err := UUID(context.Background(), tools, "/dev/a"); err != nil || id != "1b6a3c1e-0000-4000-8000-00000000000a" {
		t.Fatalf("uuid %q %v", id, err)
	}
	for _, d := range []string{"/dev/b", "/dev/c"} {
		if id, err := UUID(context.Background(), tools, d); err == nil {
			t.Fatalf("%s: uuid %q without error", d, id)
		}
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
		got, err := ResolveSource(root, source)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("%s: %q %v, want %q", source, got, err, want)
		}
	}
}

// TestResolveHeader: a detached header is a device like a source or an absolute file; relative paths and the
// path:device form are unresolved.
func TestResolveHeader(t *testing.T) {
	root := fakeDev(t, map[string]string{"/dev/disk/by-uuid/hhhh": "../../vdh", "/boot/h.link": "luks/h.img"},
		"/dev/vdh", "/boot/luks/h.img")
	cases := map[string]string{
		"/boot/luks/h.img":        "/boot/luks/h.img",
		"/boot/h.link":            "/boot/luks/h.img",
		"UUID=hhhh":               "/dev/vdh",
		"/dev/vdh":                "/dev/vdh",
		"luks/h.img":              "",
		"/boot/luks/h.img:UUID=x": "",
		"/boot/luks/missing.img":  "",
	}
	for header, want := range cases {
		got, err := resolveHeader(root, header)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("%s: %q %v, want %q", header, got, err, want)
		}
	}
}

package system

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// nssNoise is the line the guest printed during a sudo while himmelblaud was down (PDK-892).
const nssNoise = "2026-11-08T05:01:13.152453Z ERROR Unix socket stream setup error while connecting to " +
	"/var/run/himmelblaud/socket -> Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" }"

// fakeSSH puts an ssh on PATH that runs its last argument (the guest command) in a local shell.
func fakeSSH(t *testing.T) *VM {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nfor a; do cmd=$a; done\nexec sh -c \"$cmd\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return &VM{Name: "vm", port: "2224", dir: dir, t: t}
}

// TestMustReturnsStdoutAlone: a log line on the guest's standard error is not command output (PDK-892: it became the
// device argument of cryptsetup luksDump).
func TestMustReturnsStdoutAlone(t *testing.T) {
	v := fakeSSH(t)
	fakeSudo(t)
	if out := v.Must("echo '" + nssNoise + "' >&2; echo /dev/sda3"); out != "/dev/sda3" {
		t.Fatalf("Must = %q", out)
	}
	if out := v.MustDevice("echo '" + nssNoise + "' >&2; printf '/dev/sda3\\n/dev/loop0\\n'"); out != "/dev/sda3" {
		t.Fatalf("MustDevice = %q", out)
	}
	if out, _ := v.SSH(t.Context(), nil, "echo out; echo err >&2"); out != "out\nerr\n" {
		t.Fatalf("SSH = %q, want stdout and stderr", out)
	}
}

func TestDevicePaths(t *testing.T) {
	got, err := devicePaths("/dev/sda3\n/dev/loop0\n/dev/mapper/ubuntu--vg-ubuntu--lv\n/dev/disk/by-partuuid/0d8f4c62-01\n")
	if err != nil || !slices.Equal(got, []string{"/dev/sda3", "/dev/loop0", "/dev/mapper/ubuntu--vg-ubuntu--lv", "/dev/disk/by-partuuid/0d8f4c62-01"}) {
		t.Fatalf("devicePaths = %v, %v", got, err)
	}
	for name, out := range map[string]string{
		"noise before":     nssNoise + "\n/dev/sda3\n",
		"noise after":      "/dev/sda3\n" + nssNoise + "\n",
		"noise only":       nssNoise,
		"timestamp alone":  "2026-11-08T05:01:13.152453Z",
		"empty":            "",
		"relative":         "sda3",
		"traversal":        "/dev/../etc/shadow",
		"space in a path":  "/dev/sda3 /dev/sda4",
		"shell characters": "/dev/sda3;reboot",
	} {
		if got, err := devicePaths(out); err == nil {
			t.Errorf("%s: devicePaths = %v, want an error", name, got)
		}
	}
}

// fakeSudo puts a sudo on PATH that behaves like the guest's with himmelblaud down: it prints the NSS log line on its
// own standard output, then runs the command.
func fakeSudo(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\necho '" + nssNoise + "'\nif [ \"$1\" = -n ]; then shift; fi\nexec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())
}

// TestMustRootIgnoresSudoNoise: sudo's own standard output never reaches a parsed lookup (PDK-926), while the plain
// sudo form still shows the noise, so the test fails without the wrapper.
func TestMustRootIgnoresSudoNoise(t *testing.T) {
	v := fakeSSH(t)
	fakeSudo(t)
	if out := v.Must("sudo echo /dev/sda3"); !strings.Contains(out, "ERROR") {
		t.Fatalf("the fake sudo does not reproduce the noise: %q", out)
	}
	if out := v.MustRoot("echo /dev/sda3"); out != "/dev/sda3" {
		t.Fatalf("MustRoot = %q", out)
	}
	if out := v.MustDevice("printf '/dev/sda3\\n/dev/loop0\\n'"); out != "/dev/sda3" {
		t.Fatalf("MustDevice = %q", out)
	}
	if out := v.MustRootIn([]byte("from stdin"), "cat"); out != "from stdin" {
		t.Fatalf("MustRootIn = %q", out)
	}
}

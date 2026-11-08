package system

import (
	"os"
	"path/filepath"
	"slices"
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

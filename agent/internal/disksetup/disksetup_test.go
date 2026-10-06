package disksetup_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/disksetup"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// tools fakes the LUKS tools of a device whose root is on /dev/sda3; enroll answers systemd-cryptenroll.
type tools struct {
	keyFile string
	enrolls []string // NEWPIN values
	enroll  func() (exit int, stderr string)
}

func (f *tools) Command(_ context.Context, env []string, name string, args ...string) (string, string, int, error) {
	switch name {
	case "findmnt":
		return "/dev/mapper/vg-root\n", "", 0, nil
	case "lsblk":
		return `{"blockdevices":[{"name":"/dev/mapper/vg-root","type":"lvm","fstype":"ext4","children":[{"name":"/dev/mapper/dm_crypt-0","type":"crypt","fstype":"LVM2_member","children":[{"name":"/dev/sda3","type":"part","fstype":"crypto_LUKS"}]}]}]}`, "", 0, nil
	case "systemd-cryptenroll":
		if strings.Join(args, " ") != "--tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 --unlock-key-file="+f.keyFile+" /dev/sda3" {
			return "", "", -1, errors.New("unexpected arguments " + strings.Join(args, " "))
		}
		f.enrolls = append(f.enrolls, strings.TrimPrefix(env[0], "NEWPIN="))
		if f.enroll != nil {
			exit, stderr := f.enroll()
			return "", stderr, exit, nil
		}
		return "", "", 0, nil
	}
	return "", "", -1, errors.New("unexpected command " + name)
}

type fixture struct {
	layout paths.Layout
	tools  *tools
	out    bytes.Buffer
	echo   []bool
	tpm    bool
}

func newFixture(t *testing.T, minLength string) *fixture {
	t.Helper()
	f := &fixture{layout: paths.Layout{Root: t.TempDir()}, tpm: true}
	f.tools = &tools{keyFile: f.layout.InstallPassphrase()}
	for path, content := range map[string]string{
		f.layout.DiskSetupPending(): "", f.layout.InstallPassphrase(): "installpassphrase",
		f.layout.DiskSetupConfig(): `{"boot_pin_min_length":` + minLength + `}`,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fixture) run(t *testing.T, input string) error {
	t.Helper()
	return disksetup.Run(context.Background(), disksetup.Options{
		Layout: f.layout, Tools: f.tools, In: strings.NewReader(input), Out: &f.out,
		Echo:        func(on bool) error { f.echo = append(f.echo, on); return nil },
		TPM2Present: func() bool { return f.tpm },
	})
}

func (f *fixture) pending() bool {
	_, err := os.Stat(f.layout.DiskSetupPending())
	return err == nil
}

func TestPINAfterMistakes(t *testing.T) {
	f := newFixture(t, "10")
	input := "1234567890\n0987654321\n" + // differ
		"123456789\n123456789\n" + // too short for 10
		"1234567890\n1234567890\n"
	if err := f.run(t, input); err != nil {
		t.Fatal(err)
	}
	if len(f.tools.enrolls) != 1 || f.tools.enrolls[0] != "1234567890" || f.pending() {
		t.Fatalf("enrolls %v, pending %v", f.tools.enrolls, f.pending())
	}
	out := f.out.String()
	for _, want := range []string{"at least 10\ncharacters", "The two entries differ", "The PIN needs at least 10 characters", "The boot PIN is set"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "1234567890") {
		t.Fatal("the PIN was echoed")
	}
	// The echo is off while each of the six entries is read and on again afterwards.
	if len(f.echo) != 12 || f.echo[0] || !f.echo[len(f.echo)-1] {
		t.Fatalf("echo %v", f.echo)
	}
}

func TestSkip(t *testing.T) {
	f := newFixture(t, "8")
	if err := f.run(t, "\n\n"); err != nil {
		t.Fatal(err)
	}
	if len(f.tools.enrolls) != 0 || f.pending() || !strings.Contains(f.out.String(), "No boot PIN was set") {
		t.Fatalf("skip: enrolls %v, pending %v\n%s", f.tools.enrolls, f.pending(), f.out.String())
	}
	if _, err := os.Stat(f.layout.InstallPassphrase()); err != nil {
		t.Fatal("skipping must keep the install passphrase")
	}
}

func TestNoTPM(t *testing.T) {
	f := newFixture(t, "8")
	f.tpm = false
	if err := f.run(t, ""); err != nil {
		t.Fatal(err)
	}
	if len(f.tools.enrolls) != 0 || f.pending() || !strings.Contains(f.out.String(), "no TPM 2.0") {
		t.Fatalf("no TPM: enrolls %v, pending %v", f.tools.enrolls, f.pending())
	}
}

func TestEnrollFailuresKeepMarker(t *testing.T) {
	f := newFixture(t, "6")
	f.tools.enroll = func() (int, string) { return 1, "Failed to unseal secret using TPM2" }
	input := strings.Repeat("123456\n123456\n", disksetup.MaxEnrollFailures)
	if err := f.run(t, input); err != nil {
		t.Fatal(err)
	}
	if len(f.tools.enrolls) != disksetup.MaxEnrollFailures || !f.pending() || !strings.Contains(f.out.String(), "asks again at the next start") {
		t.Fatalf("enrolls %d, pending %v\n%s", len(f.tools.enrolls), f.pending(), f.out.String())
	}
	// A failure after which the user succeeds.
	f = newFixture(t, "6")
	n := 0
	f.tools.enroll = func() (int, string) {
		n++
		if n == 1 {
			return 1, "TPM busy"
		}
		return 0, ""
	}
	if err := f.run(t, "123456\n123456\n654321\n654321\n"); err != nil || f.pending() || f.tools.enrolls[1] != "654321" {
		t.Fatalf("retry: %v, pending %v, enrolls %v", err, f.pending(), f.tools.enrolls)
	}
}

func TestDefaultsAndNotPending(t *testing.T) {
	f := newFixture(t, `"x"`) // unreadable setting: the default length 8 applies
	if err := f.run(t, "1234567\n1234567\n12345678\n12345678\n"); err != nil {
		t.Fatal(err)
	}
	if len(f.tools.enrolls) != 1 || f.tools.enrolls[0] != "12345678" {
		t.Fatalf("enrolls %v", f.tools.enrolls)
	}
	// Without the marker nothing happens.
	f.out.Reset()
	if err := f.run(t, ""); err != nil || f.out.Len() != 0 || len(f.tools.enrolls) != 1 {
		t.Fatalf("not pending: %v %q", err, f.out.String())
	}
}

func TestConsoleClosed(t *testing.T) {
	f := newFixture(t, "8")
	if err := f.run(t, "1234"); err == nil {
		t.Fatal("an incomplete console input must fail")
	}
	if !f.pending() {
		t.Fatal("the marker must stay when the console fails")
	}
}

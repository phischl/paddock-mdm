package system

import (
	"errors"
	"os/exec"
	"slices"
	"testing"
)

// inhibitList is `systemd-inhibit --list --no-pager` on paddock-u2604 during the agent's first APT run (PDK-462),
// plus a delay inhibitor and a multi-word WHO.
const inhibitList = `WHO                          UID USER PID  COMM            WHAT                                                     WHY                                                   MODE
ModemManager                 0   root 812  ModemManager    sleep                                                    ModemManager needs to reset devices                   delay
APT                          0   root 5120 apt-get         shutdown:sleep                                           APT is installing or removing packages                block
Unattended Upgrades Shutdown 0   root 901  unattended-upgr shutdown                                                 Stop ongoing upgrades or perform upgrades before shutdown delay
GNOME Shell                  1000 ana  1500 gnome-shell     handle-power-key:handle-suspend-key:handle-lid-switch   GNOME handling keypresses                             block

4 inhibitors listed.
`

func TestShutdownBlockers(t *testing.T) {
	got := shutdownBlockers(inhibitList)
	want := []string{"APT 0 root 5120 apt-get shutdown:sleep APT is installing or removing packages block"}
	if !slices.Equal(got, want) {
		t.Fatalf("shutdownBlockers = %q, want %q", got, want)
	}
	if got := shutdownBlockers("0 inhibitors listed.\n"); len(got) != 0 {
		t.Fatalf("no inhibitors: got %q", got)
	}
	// A WHY that ends in "block" and mentions shutdown must not count without a WHAT column naming shutdown.
	if got := shutdownBlockers("x 0 root 1 x sleep keeps shutdown from a block\n"); len(got) != 0 {
		t.Fatalf("WHY text: got %q", got)
	}
}

func TestClassifyReboot(t *testing.T) {
	apt := []string{"APT 0 root 5120 apt-get shutdown:sleep APT is installing or removing packages block"}
	cases := []struct {
		name       string
		out        string
		code       int
		inhibitors []string
		want       rebootOutcome
	}{
		{"accepted", "", 0, nil, rebootAccepted},
		{"connection dropped by the shutdown", "Connection to 127.0.0.1 closed by remote host.", 255, nil, rebootAccepted},
		{"ssh killed while the guest went down", "", -1, nil, rebootAccepted},
		{"systemd 259 under APT's inhibitor", "Call to Reboot failed: Operation denied due to active block inhibitor", 1, apt, rebootInhibited},
		{"inhibitor message without a listed inhibitor", "Operation inhibited by \"APT\"", 1, nil, rebootInhibited},
		{"listed inhibitor with another message", "Failed to reboot", 1, apt, rebootInhibited},
		{"other refusal", "sudo: a password is required", 1, nil, rebootFailed},
	}
	for _, c := range cases {
		if got := classifyReboot(c.out, c.code, c.inhibitors); got != c.want {
			t.Errorf("%s: classifyReboot = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestSSHExitCode(t *testing.T) {
	if got := sshExitCode(nil); got != 0 {
		t.Fatalf("nil: %d", got)
	}
	if got := sshExitCode(errors.New("not started")); got != -1 {
		t.Fatalf("other error: %d", got)
	}
	err := exec.Command("sh", "-c", "exit 3").Run()
	if got := sshExitCode(err); got != 3 {
		t.Fatalf("exit 3: %d", got)
	}
}

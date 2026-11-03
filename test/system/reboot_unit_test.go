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

func TestSSHHandshakeFailedUnit(t *testing.T) {
	for name, tc := range map[string]struct {
		out  string
		want bool
	}{
		"kex reset":          {"kex_exchange_identification: read: Connection reset by peer\n", true},
		"kex reset by host":  {"Connection reset by 127.0.0.1 port 2222\n", true},
		"connection refused": {"ssh: connect to host 127.0.0.1 port 2222: Connection refused\n", true},
		"connect timeout":    {"ssh: connect to host 127.0.0.1 port 2222: Connection timed out\n", true},
		"banner timeout":     {"Connection timed out during banner exchange\n", true},
		"closed by remote":   {"Connection to 127.0.0.1 closed by remote host.\n", false},
		"drop mid-command":   {"client_loop: send disconnect: Connection reset by peer\n", false},
		"output then drop":   {"Removing obsolete files\nConnection to 127.0.0.1 closed by remote host.\n", false},
		"output then reset":  {"unpacking\nkex_exchange_identification: read: Connection reset by peer\n", false},
		"empty":              {"", false},
		"whitespace only":    {" \n", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := sshHandshakeFailed(tc.out); got != tc.want {
				t.Fatalf("sshHandshakeFailed(%q) = %v, want %v", tc.out, got, tc.want)
			}
		})
	}
}

package localadmin

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// Login is a PAM session pam_unix opened for a user (plan M4a decision 16).
type Login struct {
	Service string
	User    string
	At      time.Time
}

// sessionOpened matches pam_unix's "session opened for user <name>(uid=…) by …".
var sessionOpened = regexp.MustCompile(`^pam_unix\(([A-Za-z0-9_.@-]+):session\): session opened for user ([^ (]+)`)

// ParseJournal parses one entry of `journalctl -o json`. Sessions of the per-user systemd instance (service
// systemd-user) accompany every login and are not logins of their own.
func ParseJournal(line []byte) (Login, bool) {
	var e struct {
		Message  any    `json:"MESSAGE"` // a byte array for non-UTF-8 messages
		Realtime string `json:"__REALTIME_TIMESTAMP"`
	}
	if json.Unmarshal(line, &e) != nil {
		return Login{}, false
	}
	msg, ok := e.Message.(string)
	if !ok {
		return Login{}, false
	}
	m := sessionOpened.FindStringSubmatch(msg)
	if m == nil || m[1] == "systemd-user" {
		return Login{}, false
	}
	at := time.Now().UTC()
	if us, err := strconv.ParseInt(e.Realtime, 10, 64); err == nil {
		at = time.UnixMicro(us).UTC()
	}
	return Login{Service: m[1], User: m[2], At: at}, true
}

// FollowJournal sends every session opening of the system journal (authpriv) to out until ctx ends. It follows
// from now on and restarts journalctl 10 s after it exits.
func FollowJournal(ctx context.Context, out chan<- Login) {
	for ctx.Err() == nil {
		if err := follow(ctx, out); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "following the journal failed; restarting", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
	}
}

func follow(ctx context.Context, out chan<- Login) error {
	cmd := exec.CommandContext(ctx, "journalctl", "--follow", "--lines=0", "--output=json", "SYSLOG_FACILITY=10")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if l, ok := ParseJournal(sc.Bytes()); ok {
			select {
			case out <- l:
			case <-ctx.Done():
			}
		}
	}
	return cmd.Wait()
}

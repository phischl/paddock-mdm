// Package osupdates runs and reports the device's operating system updates (plan M5b decisions 6–8): `paddockd updates
// run` (regular updates, started by paddock-updates.timer) writes its result for the agent, which reports it, and the
// agent recognizes the runs of unattended-upgrades (daily security updates) from apt-daily-upgrade.service and its log.
// Paddock never reboots for updates; a pending reboot is only reported.
package osupdates

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// RunLimit bounds `paddockd updates run`, apt-get update and dist-upgrade together (plan M5b decision 6); the 15
// minutes of other package operations would cut a large upgrade short.
const RunLimit = 60 * time.Minute

// maxError bounds the error of a run (the server records at most 256 characters).
const maxError = 240

// AptGet runs apt-get non-interactively with a timeout; a run killed at the timeout returns an error wrapping
// context.DeadlineExceeded.
type AptGet func(ctx context.Context, timeout time.Duration, args ...string) (output string, exit int, err error)

// lockWait lets apt wait for a dpkg lock held by another package operation (plan M3b risk R1).
var lockWait = []string{"-o", "DPkg::Lock::Timeout=600"}

// RunRegular updates the package lists and upgrades every package that is not held (apt-get dist-upgrade with
// --force-confold), both within RunLimit, and returns the result of kind regular.
func RunRegular(ctx context.Context, apt AptGet, now func() time.Time, rebootRequired func() bool) protocol.UpdatesRun {
	r := protocol.UpdatesRun{Kind: protocol.UpdatesKindRegular, StartedAt: now().UTC(), HeldBack: []string{}}
	ctx, cancel := context.WithTimeout(ctx, RunLimit)
	defer cancel()
	step := func(args ...string) (string, error) {
		out, exit, err := apt(ctx, RunLimit, append(append([]string{}, lockWait...), args...)...)
		switch {
		case err != nil:
			return out, fmt.Errorf("apt-get %s: %w", args[len(args)-1], err)
		case exit != 0:
			return out, fmt.Errorf("apt-get %s: exit %d: %s", args[len(args)-1], exit, lastLine(out))
		}
		return out, nil
	}
	_, err := step("-q", "update")
	if err == nil {
		var out string
		out, err = step("-y", "-q", "-o", "Dpkg::Options::=--force-confold", "dist-upgrade")
		r.Upgraded, r.HeldBack = ParseDistUpgrade(out)
	}
	r.FinishedAt = now().UTC()
	r.RebootRequired = rebootRequired()
	r.Result = protocol.UpdatesResultOK
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		r.Result, r.Error = protocol.UpdatesResultTimeout, truncate(err.Error())
	case err != nil:
		r.Result, r.Error = protocol.UpdatesResultFailed, truncate(err.Error())
	}
	return r
}

var upgradedLine = regexp.MustCompile(`(?m)^(\d+) upgraded, \d+ newly installed`)

// ParseDistUpgrade reads the number of upgraded packages and the packages kept back from apt-get's output.
func ParseDistUpgrade(out string) (upgraded int, heldBack []string) {
	heldBack = []string{}
	if m := upgradedLine.FindStringSubmatch(out); m != nil {
		upgraded, _ = strconv.Atoi(m[1])
	}
	inKeptBack := false
	for line := range strings.Lines(out) {
		switch {
		case strings.HasPrefix(line, "The following packages have been kept back:"),
			strings.HasPrefix(line, "The following held packages will be changed:"),
			strings.HasPrefix(line, "The following upgrades have been deferred"):
			inKeptBack = true
		case inKeptBack && strings.HasPrefix(line, " "):
			for _, p := range strings.Fields(line) {
				if len(heldBack) < protocol.MaxHeldBack {
					heldBack = append(heldBack, p)
				}
			}
		default:
			inKeptBack = false
		}
	}
	return upgraded, heldBack
}

// ParseUnattendedLog reads the last run in the log of unattended-upgrades: when it started, how many packages it
// upgraded, which it kept back, and whether it logged an error. ok is false when the log has no run.
func ParseUnattendedLog(log []byte) (run protocol.UpdatesRun, ok bool) {
	run = protocol.UpdatesRun{Kind: protocol.UpdatesKindSecurity, HeldBack: []string{}, Result: protocol.UpdatesResultOK}
	sc := bufio.NewScanner(bytes.NewReader(log))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		at, level, msg, parsed := logLine(line)
		if !parsed {
			continue
		}
		switch {
		case strings.HasPrefix(msg, "Starting unattended upgrades script"):
			run = protocol.UpdatesRun{Kind: protocol.UpdatesKindSecurity, StartedAt: at, HeldBack: []string{}, Result: protocol.UpdatesResultOK}
			ok = true
		case strings.HasPrefix(msg, "Packages that will be upgraded:"):
			run.Upgraded = len(strings.Fields(strings.TrimPrefix(msg, "Packages that will be upgraded:")))
		case strings.HasPrefix(msg, "Packages that are kept back:"), strings.HasPrefix(msg, "Packages that are held back:"):
			for _, p := range strings.Fields(msg[strings.Index(msg, ":")+1:]) {
				if len(run.HeldBack) < protocol.MaxHeldBack {
					run.HeldBack = append(run.HeldBack, p)
				}
			}
		case level == "ERROR" && ok:
			run.Result, run.Error = protocol.UpdatesResultFailed, truncate(msg)
		}
	}
	return run, ok
}

// logLine splits "2026-10-08 06:12:01,123 INFO message".
func logLine(line string) (time.Time, string, string, bool) {
	f := strings.SplitN(line, " ", 4)
	if len(f) < 4 {
		return time.Time{}, "", "", false
	}
	at, err := time.ParseInLocation("2006-01-02 15:04:05,000", f[0]+" "+f[1], time.Local)
	if err != nil {
		return time.Time{}, "", "", false
	}
	return at.UTC(), f[2], f[3], true
}

// ParseUnitExit reads `systemctl show --timestamp=unix -p ActiveExitTimestamp,Result <unit>`: when the unit's last
// run ended and its result. ok is false before the first run.
func ParseUnitExit(out string) (exited time.Time, result string, ok bool) {
	for line := range strings.Lines(out) {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ActiveExitTimestamp":
			if sec, err := strconv.ParseInt(strings.TrimPrefix(v, "@"), 10, 64); err == nil && sec > 0 {
				exited, ok = time.Unix(sec, 0).UTC(), true
			}
		case "Result":
			result = v
		}
	}
	return exited, result, ok
}

// RebootRequired reports whether a package asked for a reboot (/var/run/reboot-required).
func RebootRequired(l paths.Layout) bool {
	_, err := os.Stat(l.RebootRequired())
	return err == nil
}

// WriteResult stores the result of a regular run for the agent.
func WriteResult(l paths.Layout, r protocol.UpdatesRun) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(l.UpdatesResult(), data, 0o600, 0o700)
}

// ReadResult returns the stored result of the last regular run; nil without one.
func ReadResult(l paths.Layout) (*protocol.UpdatesRun, error) {
	data, err := os.ReadFile(l.UpdatesResult())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r protocol.UpdatesRun
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("updates result: %w", err)
	}
	return &r, nil
}

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func truncate(s string) string {
	if len(s) > maxError {
		return s[:maxError]
	}
	return s
}

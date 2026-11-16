package system

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// TamperFileChanged is the audit code of a protected file changed outside Paddock.
const TamperFileChanged = "device.tamper_protected_file_changed"

// tamperFiles are the files of the device's TamperFileChanged events not in seen whose file starts with one of
// prefixes.
func (d *Device) tamperFiles(seen []string, prefixes ...string) []string {
	d.t.Helper()
	var files []string
	for _, e := range d.newEvents(TamperFileChanged, seen, nil) {
		f, _ := e.Params["file"].(string)
		for _, p := range prefixes {
			if strings.HasPrefix(f, p) {
				files = append(files, f)
				break
			}
		}
	}
	return files
}

// WaitIntegrityBaseline waits until the agent's first integrity pass has recorded /etc/paddock/disk-setup.json in its
// baseline (ADR 0056). A file written by hand before that pass would become the baseline instead of being reported.
func (d *Device) WaitIntegrityBaseline(t *testing.T) {
	t.Helper()
	Until(t, d.Name+": first integrity pass", 8*time.Minute, 5*time.Second, nil, func() bool {
		return d.Must(`sudo grep -qs '"/etc/paddock/disk-setup.json"' /var/lib/paddock/state/integrity.json && echo yes || echo no`) == "yes"
	})
}

// WaitIntegrityPass waits until checked_at in the device's integrity.json changed twice after the call, so that one
// whole pass started after the call (ADR 0056, plan M5a R12).
func (d *Device) WaitIntegrityPass(t *testing.T) {
	t.Helper()
	drift := 300 * time.Second
	if s, err := strconv.Atoi(d.Must(`sudo awk -F': *' '/^drift_interval_s:/ {v=$2} END {print v+0}' /etc/paddock/agent.yml`)); err == nil && s > 0 {
		drift = time.Duration(s) * time.Second
	}
	checkedAt := func() string {
		return d.Must(`sudo grep -o '"checked_at":"[^"]*"' /var/lib/paddock/state/integrity.json || true`)
	}
	last, changes := checkedAt(), 0
	Until(t, d.Name+": a whole integrity pass", 3*drift+2*time.Minute, 5*time.Second, nil, func() bool {
		if now := checkedAt(); now != last {
			last, changes = now, changes+1
		}
		return changes >= 2
	})
}

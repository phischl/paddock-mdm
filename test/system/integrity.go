package system

import (
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

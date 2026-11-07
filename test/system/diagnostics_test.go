package system

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestDiagnosticsGates runs gate DS1 of plan M12 on each VM, from a fresh base-installed: a real collect_status (ADR
// 0048) ends with a stored bundle whose archive, downloaded after a step-up, holds exactly the closed content list,
// the VM's own journal lines, a redacted Himmelblau configuration and nothing of a home directory; the agent leaves
// no temporary file behind and reports how many graphical sessions it notified.
func TestDiagnosticsGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		t.Run("DS1 diagnostics bundle", func(t *testing.T) {
			d.Bind(t)
			gateDS1(t, d)
		})
	})
}

// diagnosticsEntries are the archive names of the closed content list, read from the privacy document, which the
// agent's unit test (agent/internal/diagnostics TestPrivacyDocumentListsEntries) holds equal to Entries(); the agent's
// internal package cannot be imported from this module.
func diagnosticsEntries(t *testing.T, root string) []string {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join(root, "docs/compliance/privacy.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "\n## Diagnostics bundle (on request only)\n")
	if !ok {
		t.Fatal("privacy.md has no diagnostics section")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	var names []string
	for _, line := range strings.Split(section, "\n") {
		if cells := strings.Split(line, "|"); strings.HasPrefix(line, "| `") && len(cells) > 2 {
			names = append(names, strings.Trim(strings.TrimSpace(cells[1]), "`"))
		}
	}
	if len(names) == 0 {
		t.Fatal("privacy.md lists no diagnostics entries")
	}
	return names
}

// diagnosticsManifest is manifest.json of a diagnostics archive (paddock.diagnostics.v1).
type diagnosticsManifest struct {
	Schema  string `json:"schema"`
	Entries []struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
		Error  string `json:"error"`
		Files  []struct {
			Name string `json:"name"`
		} `json:"files"`
	} `json:"entries"`
}

// untar returns the regular files of a tar.gz by name.
func untar(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name] = data
	}
}

// userSessionsScript counts the active wayland and x11 sessions of class user, the sessions the agent notifies; a
// login screen (Ubuntu 24.04's GDM greeter is an active wayland session) is no user to tell (PDK-878).
const userSessionsScript = `for s in $(loginctl list-sessions --no-legend | awk '{print $1}'); do ` +
	`loginctl show-session "$s" -p Class -p Type -p State | sort | paste -sd' '; done | ` +
	`grep -cE '^Class=user State=active Type=(wayland|x11)$' || true`

// sessionsScript lists every session's class, type, state and user for a failure message.
const sessionsScript = `for s in $(loginctl list-sessions --no-legend | awk '{print $1}'); do ` +
	`loginctl show-session "$s" -p Id -p Class -p Type -p State -p Name | sort | paste -sd' '; done`

// ensureUserSession returns the number of active graphical user sessions on d, at least one. A fresh VM sits at the
// login screen (its image configures no autologin): DS1 then logs the VM's user in by a GDM autologin for this
// snapshot only, and fails loudly when that gives no user session, since DS1 proves that a user is told.
func ensureUserSession(t *testing.T, d *Device) int {
	t.Helper()
	count := func() int {
		n, err := strconv.Atoi(strings.TrimSpace(d.Must(userSessionsScript)))
		if err != nil {
			t.Fatalf("graphical user sessions: %v", err)
		}
		return n
	}
	if n := count(); n > 0 {
		return n
	}
	user := d.Must("id -un")
	t.Logf("%s: no active graphical user session (%s); logging %s in by a GDM autologin", d.Name,
		d.Must(sessionsScript), user)
	// GDM logs in automatically once per start; its ran-once marker in /run would skip the autologin after a restart.
	d.Must("printf '[daemon]\\nAutomaticLoginEnable=true\\nAutomaticLogin=%s\\n' '" + user + "'" +
		" | sudo tee /etc/gdm3/custom.conf >/dev/null && sudo rm -f /run/gdm3/ran-once-marker /run/gdm/ran-once-marker" +
		" && sudo systemctl restart display-manager.service")
	n := 0
	deadline := time.Now().Add(2 * time.Minute)
	for n = count(); n == 0 && time.Now().Before(deadline); n = count() {
		time.Sleep(5 * time.Second)
	}
	if n == 0 {
		t.Fatalf("%s: still no active graphical user session after the autologin: %s", d.Name, d.Must(sessionsScript))
	}
	return n
}

// secretLine is a Himmelblau configuration line the collector must redact (ADR 0048 decision 2).
var secretLine = regexp.MustCompile(`(?i)secret|password|key`)

func gateDS1(t *testing.T, d *Device) {
	sessions := ensureUserSession(t, d)
	t.Logf("%s: %d active graphical user sessions", d.Name, sessions)
	// The newest line of the agent's own work before the request; the archive's journal must hold it.
	lastApplied := d.Must("sudo journalctl -u paddock-supervisor.service -o short-iso --no-pager | grep 'bundle applied' | tail -n 1")
	if lastApplied == "" {
		t.Fatal("the agent's journal has no bundle applied line")
	}
	requested := time.Now()

	reason := "DS1 system test " + d.run
	var created struct {
		ID string `json:"id"`
	}
	res := d.s.Call(t, http.MethodPost, "/api/v1/devices/"+d.ID+"/diagnostics", map[string]string{"reason": reason}, http.StatusAccepted)
	if err := json.Unmarshal(res.Body, &created); err != nil || created.ID == "" {
		t.Fatalf("request: %v %s", err, res.Body)
	}
	path := "/api/v1/diagnostics/" + created.ID

	var bundle struct {
		State            string  `json:"state"`
		FailedReason     *string `json:"failed_reason"`
		NotifiedSessions *int    `json:"notified_sessions"`
	}
	last := time.Time{}
	Until(t, d.Name+": diagnostics bundle stored", 15*time.Minute, time.Second, func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}, func() bool {
		if err := json.Unmarshal(d.s.Call(t, http.MethodGet, path, nil, http.StatusOK).Body, &bundle); err != nil {
			t.Fatal(err)
		}
		if bundle.State == "failed" || bundle.State == "expired" {
			t.Fatalf("bundle %s %s (%v)", created.ID, bundle.State, bundle.FailedReason)
		}
		return bundle.State == "stored"
	})
	// The development stack counts retention days in seconds: a stored bundle would be deleted about 7 s later.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if got, err := paddockSQL(ctx, `WITH u AS (UPDATE device_diagnostics SET expires_at = now() + interval '1 hour'
		WHERE id = '`+created.ID+`' AND state = 'stored' RETURNING id) SELECT id FROM u`); err != nil || got != created.ID {
		t.Fatalf("extend the retention of %s: %v %q", created.ID, err, got)
	}

	if bundle.NotifiedSessions == nil {
		t.Fatal("the bundle reports no notified_sessions")
	}
	if *bundle.NotifiedSessions < 1 {
		since := requested.Add(-time.Minute).Format("2006-01-02 15:04:05")
		t.Errorf("notified_sessions %d with %d active graphical user sessions; agent journal: %s", *bundle.NotifiedSessions,
			sessions, d.Must("sudo journalctl -u paddock-supervisor.service --no-pager --since '"+since+"' | grep -i notif || true"))
	}
	if out := d.Must("sudo find /var/lib/paddock/diagnostics -mindepth 1 2>/dev/null || true"); out != "" {
		t.Errorf("temporary files left on the device: %s", out)
	}

	d.s.StepUp(t)
	files := untar(t, d.s.Call(t, http.MethodGet, path+"/download", nil, http.StatusOK).Body)
	var m diagnosticsManifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil || m.Schema != "paddock.diagnostics.v1" {
		t.Fatalf("manifest.json: %v %s", err, files["manifest.json"])
	}
	var names []string
	listed := map[string]bool{"manifest.json": true}
	for _, e := range m.Entries {
		names = append(names, e.Name)
		switch {
		case e.Error != "":
			t.Logf("%s: entry %s: %s", d.Name, e.Name, e.Error)
		case len(e.Files) > 0:
			for _, f := range e.Files {
				listed[f.Name] = true
			}
		case e.SHA256 != "":
			listed[e.Name] = true
		}
	}
	if want := diagnosticsEntries(t, d.s.root); !slices.Equal(names, want) {
		t.Errorf("manifest entries %v, want the content list %v", names, want)
	}
	for name := range files {
		if !listed[name] {
			t.Errorf("archive file %s is not an entry of the manifest", name)
		}
		if strings.HasPrefix(name, "home/") || strings.Contains(name, "/home/") {
			t.Errorf("archive file %s is below a home directory", name)
		}
	}
	for name := range listed {
		if _, ok := files[name]; !ok {
			t.Errorf("manifest lists %s, the archive lacks it", name)
		}
	}

	if !strings.Contains(string(files["journal/paddockd.log"]), lastApplied) {
		t.Errorf("journal/paddockd.log lacks the agent's last line %q", lastApplied)
	}
	if d.Must("sudo test -f /etc/himmelblau/himmelblau.conf && echo yes || true") == "yes" {
		conf, ok := files["etc/himmelblau/himmelblau.conf"]
		if !ok {
			t.Error("the archive lacks etc/himmelblau/himmelblau.conf")
		}
		for _, line := range strings.Split(string(conf), "\n") {
			if secretLine.MatchString(line) && !strings.HasSuffix(line, "<redacted>") {
				t.Errorf("himmelblau.conf line not redacted: %q", line)
			}
		}
	}
}

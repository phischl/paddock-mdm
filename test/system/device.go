package system

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Device is an enrolled VM with its device group and managed configuration.
type Device struct {
	*VM
	s     *Stack
	ID    string
	Group string
	run   string            // unique suffix of this run's names
	Files map[string]string // managed file path → id
	Unit  string
}

// managedPath is a managed file of this run.
func (d *Device) managedPath(name string) string {
	return "/etc/paddock-systest/" + d.run + "-" + name + ".conf"
}

// Install prepares the guest (hosts entries, Caddy CA), installs the packages from debDir and enrolls the device
// into a new device group with managed files a and b, a unit file and the unit itself. The drift interval is set
// to 30 s (development build).
func Install(t *testing.T, s *Stack, vm *VM, debDir string) *Device {
	t.Helper()
	d := &Device{VM: vm, s: s, run: unique(), Files: map[string]string{}}
	d.Unit = "systest-" + d.run + ".service"

	secrets, err := filepath.Abs(filepath.Join(s.root, "deploy", "compose", ".secrets", "caddy-root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	vm.Copy(secrets, "/tmp/paddock-dev-caddy-root.crt")
	vm.Must("sudo install -m 0644 /tmp/paddock-dev-caddy-root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates >/dev/null" +
		" && echo '" + guestHosts + "' | sudo tee -a /etc/hosts >/dev/null && getent hosts device.paddock.localhost")
	debs, err := filepath.Glob(filepath.Join(debDir, "*.deb"))
	if err != nil || len(debs) != 2 {
		t.Fatalf("want the two packages in %s (make deb), got %v", debDir, debs)
	}
	var remote []string
	for _, deb := range debs {
		r := "/tmp/" + filepath.Base(deb)
		vm.Copy(deb, r)
		remote = append(remote, r)
	}
	vm.Must("sudo dpkg -i " + strings.Join(remote, " ") + " && systemctl is-enabled paddock-supervisor && readlink /opt/paddock/agent/current")

	// Configuration of this device, before enrollment: the first bundle carries all of it.
	d.Group = s.ID(s.Call(http.MethodPost, "/api/v1/device-groups", map[string]string{"name": "systest " + vm.Name + " " + d.run}, http.StatusCreated))
	for _, name := range []string{"a", "b"} {
		res := s.Call(http.MethodPost, "/api/v1/managed-files", map[string]any{
			"path": d.managedPath(name), "content": "managed " + name + " " + d.run + "\n", "mode": "0640", "owner": "root",
			"group": "adm", "device_group_id": d.Group,
		}, http.StatusCreated)
		d.Files[d.managedPath(name)] = s.ID(res)
	}
	unitFile := "/etc/systemd/system/" + d.Unit
	res := s.Call(http.MethodPost, "/api/v1/managed-files", map[string]any{
		"path": unitFile, "mode": "0644", "device_group_id": d.Group,
		"content": "[Unit]\nDescription=Paddock system test unit\n\n[Service]\nExecStart=/bin/sleep infinity\n\n[Install]\nWantedBy=multi-user.target\n",
	}, http.StatusCreated)
	d.Files[unitFile] = s.ID(res)
	s.Call(http.MethodPost, "/api/v1/managed-units", map[string]any{"unit": d.Unit, "enabled": true, "active": true, "device_group_id": d.Group}, http.StatusCreated)

	tok := s.Call(http.MethodPost, "/api/v1/enrollment-tokens", map[string]any{
		"name": "systest " + vm.Name + " " + d.run, "max_uses": 1, "auto_approve": true, "device_group_id": d.Group,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, http.StatusCreated)
	var created struct {
		EnrollmentConfig json.RawMessage `json:"enrollment_config"`
	}
	if err := json.Unmarshal(tok.Body, &created); err != nil {
		t.Fatal(err)
	}
	vm.MustIn(created.EnrollmentConfig, "umask 077 && cat > /tmp/enroll.json")
	vm.Must("sudo paddockd enroll --config /tmp/enroll.json --remove-config && test ! -e /tmp/enroll.json")
	vm.Must("echo 'drift_interval_s: 30' | sudo tee -a /etc/paddock/agent.yml >/dev/null && sudo systemctl restart paddock-supervisor")
	d.ID = d.State()["device_id"].(string)
	t.Logf("%s enrolled as device %s (group %s)", vm.Name, d.ID, d.Group)
	return d
}

// State reads the agent's state.json.
func (d *Device) State() map[string]any {
	d.t.Helper()
	var st map[string]any
	if err := json.Unmarshal([]byte(d.Must("sudo cat /var/lib/paddock/state/state.json")), &st); err != nil {
		d.t.Fatal(err)
	}
	return st
}

// Checkin asks the agent for an immediate check-in (SIGHUP; at most one per minute, plan M2b decision 8).
func (d *Device) Checkin() {
	d.Must("sudo pkill -HUP -f '^/opt/paddock/agent/current/paddockd run' || true")
}

// AgentVersion is the version of the agent the supervisor runs.
func (d *Device) AgentVersion() string { return d.Must("/usr/bin/paddockd version") }

// Slot is the active A/B slot.
func (d *Device) Slot() string { return d.Must("readlink /opt/paddock/agent/current") }

// WaitEvent waits until an audit event of code for the device satisfies match, checking in every 65 s.
func (d *Device) WaitEvent(code string, timeout time.Duration, match func(params map[string]any) bool) map[string]any {
	d.t.Helper()
	var found map[string]any
	last := time.Time{}
	Until(d.t, fmt.Sprintf("%s: audit event %s", d.Name, code), timeout, 5*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}, func() bool {
		for _, e := range d.s.Events(code, d.ID) {
			if match == nil || match(e.Params) {
				found = e.Params
				return true
			}
		}
		return false
	})
	return found
}

// healthScript reads GET /health from the agent's unix socket (python3 is part of every Ubuntu desktop; curl is not).
const healthScript = `import socket
s = socket.socket(socket.AF_UNIX)
s.connect("/run/paddock/agent.sock")
s.sendall(b"GET /health HTTP/1.0\r\nHost: agent\r\n\r\n")
data = b""
while chunk := s.recv(4096):
    data += chunk
print(data.decode().split("\r\n\r\n", 1)[1])
`

// Health is the agent's health report.
func (d *Device) Health() string { return d.MustIn([]byte(healthScript), "sudo python3 -") }

// ownErrors returns the errors of a bundle.applied event that concern this run's resources or the time resource.
func (d *Device) ownErrors(params map[string]any) []any {
	errs, _ := params["errors"].([]any)
	var own []any
	for _, e := range errs {
		m, _ := e.(map[string]any)
		if id, _ := m["id"].(string); id == "time" || strings.Contains(id, d.run) {
			own = append(own, e)
		}
	}
	return own
}

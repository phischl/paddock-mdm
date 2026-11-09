package system

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
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
	// Bundle is the first compiled bundle version with this device's group.
	Bundle float64
}

// managedPath is a managed file of this run.
func (d *Device) managedPath(name string) string {
	return "/etc/paddock-systest/" + d.run + "-" + name + ".conf"
}

// debDir holds the packages under test (make deb).
func debDir(s *Stack) string {
	if d := os.Getenv("PADDOCK_SYSTEM_DEBS"); d != "" {
		return d
	}
	return filepath.Join(s.root, "bin", "deb")
}

// InstallOption changes what Install does after the enrollment.
type InstallOption func(*installOptions)

type installOptions struct{ reportOnly bool }

// ReportOnly leaves the device in report-only mode, as `paddockd enroll` creates an adopted device (plan M11 R6.9):
// no enforcement and no drift interval, so that the gate sees the report-only apply and calls Enforce and
// SetDriftInterval itself. Every other gate gets an enforced device.
func ReportOnly() InstallOption { return func(o *installOptions) { o.reportOnly = true } }

// prepareGuest adds the stack's hosts entries and CA (the lab's throwaway CA for the backup gates, whose names are the
// same) to the guest and installs the packages from debDir.
func prepareGuest(t *testing.T, s *Stack, vm *VM, debDir string) {
	t.Helper()
	ca := filepath.Join(s.root, "deploy", "compose", ".secrets", "caddy-root.crt")
	if s.lab != nil {
		ca = s.lab.caFile()
	}
	ca, err := filepath.Abs(ca)
	if err != nil {
		t.Fatal(err)
	}
	vm.Copy(ca, "/tmp/paddock-dev-caddy-root.crt")
	vm.Must("sudo install -m 0644 /tmp/paddock-dev-caddy-root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates >/dev/null" +
		" && echo '" + guestHosts + "' | sudo tee -a /etc/hosts >/dev/null && getent hosts device.paddock.localhost")
	debs, err := filepath.Glob(filepath.Join(debDir, "*.deb"))
	if err != nil || len(debs) != 3 {
		t.Fatalf("want the three packages in %s (make deb), got %v", debDir, debs)
	}
	var remote []string
	for _, deb := range debs {
		r := "/tmp/" + filepath.Base(deb)
		vm.Copy(deb, r)
		remote = append(remote, r)
	}
	vm.Must("sudo dpkg -i " + strings.Join(remote, " ") + " && systemctl is-enabled paddock-supervisor && readlink /opt/paddock/agent/current")
}

// Install prepares the guest (hosts entries, Caddy CA), installs the packages from debDir and enrolls the device
// into a new device group with managed files a and b, a unit file and the unit itself. The harness enrolls with
// `paddockd enroll`, so the device is adopted and report-only; Install enforces it (POST /enforce) unless
// ReportOnly is given, so that the gates see applied resources. The drift interval is set to 30 s (development
// build). Group, files, unit and enrollment token are removed when the test ends (plan M2.2 decision 7).
func Install(t *testing.T, s *Stack, vm *VM, debDir string, opts ...InstallOption) *Device {
	t.Helper()
	var o installOptions
	for _, opt := range opts {
		opt(&o)
	}
	d := &Device{VM: vm, s: s, run: unique(), Files: map[string]string{}}
	d.Unit = "systest-" + d.run + ".service"
	prepareGuest(t, s, vm, debDir)

	// Configuration of this device, before enrollment.
	d.Group = s.ID(t, s.Call(t, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": "systest " + vm.Name + " " + d.run}, http.StatusCreated))
	s.DeleteOnCleanup(t, "/api/v1/device-groups/"+d.Group)
	s.OperatorRoot(t, "/etc/paddock-systest/")
	for _, name := range []string{"a", "b"} {
		res := s.Call(t, http.MethodPost, "/api/v1/managed-files", map[string]any{
			"path": d.managedPath(name), "content": "managed " + name + " " + d.run + "\n", "mode": "0640", "owner": "root",
			"group": "adm", "device_group_id": d.Group,
		}, http.StatusCreated)
		d.Files[d.managedPath(name)] = s.ID(t, res)
		s.DeleteOnCleanup(t, "/api/v1/managed-files/"+d.Files[d.managedPath(name)])
	}
	s.StepUp(t) // a unit file is on a sensitive path (ADR 0034 decision 2)
	unitFile := "/etc/systemd/system/" + d.Unit
	res := s.Call(t, http.MethodPost, "/api/v1/managed-files", map[string]any{
		"path": unitFile, "mode": "0644", "device_group_id": d.Group,
		"content": "[Unit]\nDescription=Paddock system test unit\n\n[Service]\nExecStart=/bin/sleep infinity\n\n[Install]\nWantedBy=multi-user.target\n",
	}, http.StatusCreated)
	d.Files[unitFile] = s.ID(t, res)
	s.DeleteOnCleanup(t, "/api/v1/managed-files/"+d.Files[unitFile])
	res = s.Call(t, http.MethodPost, "/api/v1/managed-units", map[string]any{"unit": d.Unit, "enabled": true, "active": true, "device_group_id": d.Group}, http.StatusCreated)
	s.DeleteOnCleanup(t, "/api/v1/managed-units/"+s.ID(t, res))

	// The token names no group: a group that an enrollment token names cannot be deleted. The device joins the
	// group after enrollment, so its first bundle may lack this configuration (see Bundle).
	tok := s.Call(t, http.MethodPost, "/api/v1/enrollment-tokens", map[string]any{
		"name": "systest " + vm.Name + " " + d.run, "max_uses": 1, "auto_approve": true,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, http.StatusCreated)
	var created struct {
		Token struct {
			ID string `json:"id"`
		} `json:"token"`
		EnrollmentConfig json.RawMessage `json:"enrollment_config"`
	}
	if err := json.Unmarshal(tok.Body, &created); err != nil || created.Token.ID == "" {
		t.Fatalf("enrollment token %s: %v", tok.Body, err)
	}
	s.RevokeOnCleanup(t, created.Token.ID)
	// The runbook's path (plan M11 R6.8): not /etc/paddock/enroll.json, which the daemon's autoinstall loop reads.
	vm.MustIn(created.EnrollmentConfig, "sudo sh -c 'umask 077 && cat > /root/paddock-enroll.json'")
	vm.Must("sudo paddockd enroll --config /root/paddock-enroll.json --remove-config && sudo test ! -e /root/paddock-enroll.json")
	d.ID = d.State()["device_id"].(string)
	if method, mode := d.EnrollmentMode(); method != "adopted" || mode != "report_only" {
		t.Fatalf("%s enrolled with paddockd enroll as %s/%s, want adopted/report_only", vm.Name, method, mode)
	}
	d.joinGroup()
	if !o.reportOnly {
		d.Enforce()
		d.SetDriftInterval()
		// Every gate starts from an enforced device, not from the report-only apply of the enrollment bundle.
		d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, func(p map[string]any) bool {
			version, _ := p["bundle_version"].(float64)
			return p["mode"] != "report_only" && version >= d.Bundle
		})
	}
	t.Logf("%s enrolled as device %s (group %s, bundle %v)", vm.Name, d.ID, d.Group, d.Bundle)
	return d
}

// SetDriftInterval sets the agent's drift interval to 30 s (development build) and restarts the supervisor. A
// report-only device does not drift, so a gate of report-only calls it after the enforcement.
func (d *Device) SetDriftInterval() {
	d.t.Helper()
	d.Must("echo 'drift_interval_s: 30' | sudo tee -a /etc/paddock/agent.yml >/dev/null && sudo systemctl restart paddock-supervisor")
}

// EnrollmentMode is the device's enrollment method and configuration mode as the server stores them.
func (d *Device) EnrollmentMode() (method, mode string) {
	d.t.Helper()
	var dev struct {
		Method string `json:"enrollment_method"`
		Mode   string `json:"config_mode"`
	}
	if err := json.Unmarshal(d.s.Call(d.t, http.MethodGet, "/api/v1/devices/"+d.ID, nil, http.StatusOK).Body, &dev); err != nil {
		d.t.Fatal(err)
	}
	return dev.Method, dev.Mode
}

// Enforce ends the device's report-only mode with its hostname as the typed confirmation (plan M11 decision 42). It
// waits for the bundle the server compiles for the enforcement and makes it the device's Bundle, so that a wait for
// version >= Bundle sees an enforced apply, never the earlier report-only one.
func (d *Device) Enforce() {
	d.t.Helper()
	before := d.bundleVersion()
	d.s.Call(d.t, http.MethodPost, "/api/v1/devices/"+d.ID+"/enforce", map[string]string{"hostname": d.Must("hostname")}, http.StatusOK)
	Until(d.t, d.Name+": bundle compiled for the enforcement", 2*time.Minute, 2*time.Second, nil, func() bool {
		d.Bundle = d.bundleVersion()
		return d.Bundle > before
	})
}

// ResourceStatus is one row of GET /devices/{id}/config-status.
type ResourceStatus struct {
	ResourceID    string   `json:"resource_id"`
	Status        string   `json:"status"`
	Message       string   `json:"message"`
	Changes       []string `json:"changes"`
	BundleVersion float64  `json:"bundle_version"`
	ReportMode    string   `json:"report_mode"`
}

// ConfigStatus returns the device's apply status rows whose resource ID contains q ("" lists all, at most 100).
func (d *Device) ConfigStatus(q string) []ResourceStatus {
	d.t.Helper()
	path := "/api/v1/devices/" + d.ID + "/config-status?page_size=100&q=" + url.QueryEscape(q)
	var page struct {
		Items []ResourceStatus `json:"items"`
	}
	if err := json.Unmarshal(d.s.Call(d.t, http.MethodGet, path, nil, http.StatusOK).Body, &page); err != nil {
		d.t.Fatal(err)
	}
	return page.Items
}

// BundleMode is the version and the mode of the newest bundle the device reported on ("" when it reported none).
func (d *Device) BundleMode() (version float64, mode string) {
	d.t.Helper()
	var page struct {
		Items []struct {
			Version float64 `json:"version"`
			Report  *struct {
				Mode string `json:"mode"`
			} `json:"report"`
		} `json:"items"`
	}
	if err := json.Unmarshal(d.s.Call(d.t, http.MethodGet, "/api/v1/devices/"+d.ID+"/bundles?page_size=10", nil, http.StatusOK).Body, &page); err != nil {
		d.t.Fatal(err)
	}
	for _, b := range page.Items {
		if b.Report != nil {
			return b.Version, b.Report.Mode
		}
	}
	return 0, ""
}

// joinGroup makes the device a member of its group and sets Bundle. It waits for the bundle compiled at
// enrollment first, so that the next compiled version is one that started after the membership.
func (d *Device) joinGroup() {
	d.t.Helper()
	var enrolled float64
	Until(d.t, "bundle compiled at enrollment", time.Minute, 2*time.Second, nil, func() bool {
		enrolled = d.bundleVersion()
		return enrolled > 0
	})
	d.s.Call(d.t, http.MethodPut, "/api/v1/devices/"+d.ID+"/groups", map[string]any{"device_group_ids": []string{d.Group}}, http.StatusOK)
	Until(d.t, "bundle compiled with the device group", time.Minute, 2*time.Second, nil, func() bool {
		d.Bundle = d.bundleVersion()
		return d.Bundle > enrolled
	})
}

// bundleVersion is the latest bundle version the server compiled for the device (0 = none).
func (d *Device) bundleVersion() float64 {
	d.t.Helper()
	var dev struct {
		BundleVersion float64 `json:"bundle_version"`
	}
	if err := json.Unmarshal(d.s.Call(d.t, http.MethodGet, "/api/v1/devices/"+d.ID, nil, http.StatusOK).Body, &dev); err != nil {
		d.t.Fatal(err)
	}
	return dev.BundleVersion
}

// State reads the agent's state.json.
func (d *Device) State() map[string]any {
	d.t.Helper()
	var st map[string]any
	if err := json.Unmarshal([]byte(d.MustRoot("cat /var/lib/paddock/state/state.json")), &st); err != nil {
		d.t.Fatal(err)
	}
	return st
}

// Checkin asks the agent for an immediate check-in (SIGHUP; at most one per minute, plan M2b decision 8). It is best
// effort: an SSH failure (e.g. while sshd restarts during a package installation) is only logged.
func (d *Device) Checkin() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if out, err := d.SSH(ctx, nil, "sudo pkill -HUP -f '^/opt/paddock/agent/current/paddockd run' || true"); err != nil {
		d.t.Logf("%s: check-in trigger: %v: %s", d.Name, err, out)
	}
}

// AgentVersion is the version of the agent the supervisor runs.
func (d *Device) AgentVersion() string { return d.Must("/usr/bin/paddockd version") }

// Slot is the active A/B slot.
func (d *Device) Slot() string { return d.Must("readlink /opt/paddock/agent/current") }

// WaitEvent waits until an audit event of code for the device satisfies match, checking in every 65 s. A timeout fails
// t, the calling (sub)test.
func (d *Device) WaitEvent(t *testing.T, code string, timeout time.Duration, match func(params map[string]any) bool) map[string]any {
	t.Helper()
	var found map[string]any
	last := time.Time{}
	Until(t, fmt.Sprintf("%s: audit event %s", d.Name, code), timeout, 5*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}, func() bool {
		for _, e := range d.s.Events(d.t, code, d.ID) {
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
func (d *Device) Health() string { return d.MustRootIn([]byte(healthScript), "python3 -") }

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

// RequestUninstall asks, as alice after a step-up, to remove Paddock from the device with mode and the extra options
// (clear_tpm, keep_local_admin) and returns the response; status is the expected HTTP status.
func (d *Device) RequestUninstall(mode string, extra map[string]any, status int) portal.Response {
	d.t.Helper()
	body := map[string]any{"mode": mode, "confirm_hostname": d.Must("hostname"), "reason": "system gate " + d.run}
	for k, v := range extra {
		body[k] = v
	}
	d.s.StepUp(d.t)
	return d.s.Call(d.t, http.MethodPost, "/api/v1/devices/"+d.ID+"/uninstall", body, status)
}

// WaitRetired waits for the device's removal report and its retirement and returns the params of device.uninstalled.
func (d *Device) WaitRetired(t *testing.T, timeout time.Duration) map[string]any {
	t.Helper()
	p := d.WaitEvent(t, "device.uninstalled", timeout, nil)
	Until(t, d.Name+": retired after the removal", 2*time.Minute, 5*time.Second, nil, func() bool {
		var dev struct {
			State         string  `json:"state"`
			RetiredReason *string `json:"retired_reason"`
		}
		_ = json.Unmarshal(d.s.Call(t, http.MethodGet, "/api/v1/devices/"+d.ID, nil, http.StatusOK).Body, &dev)
		return dev.State == "retired" && dev.RetiredReason != nil && *dev.RetiredReason == "uninstalled"
	})
	return p
}

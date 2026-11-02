package system

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// quarantineDir holds the foreign sudoers files the agent removed from /etc/sudoers.d.
const quarantineDir = "/var/lib/paddock/quarantine/sudoers.d/"

// seedForeignAdmin gives the guest what an adopted laptop has and a managed one must not: a local user in the group
// sudo and a sudoers file of its own in /etc/sudoers.d, neither known to Paddock. Both are removed when the test
// ends (the agent may have quarantined the file by then).
func seedForeignAdmin(t *testing.T, vm *VM, run string) (file, user string) {
	t.Helper()
	user, file = "systest-"+run, "90-systest-"+run
	vm.Must("sudo useradd -m -s /bin/bash " + user + " && sudo gpasswd -a " + user + " sudo >/dev/null" +
		" && echo '" + user + " ALL=(ALL) NOPASSWD: /usr/bin/true' | sudo tee /etc/sudoers.d/" + file + " >/dev/null" +
		" && sudo chmod 0440 /etc/sudoers.d/" + file + " && sudo visudo -cf /etc/sudoers.d/" + file + " >/dev/null")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if out, err := vm.SSH(ctx, nil, "sudo rm -f /etc/sudoers.d/"+file+"; sudo sh -c 'rm -f "+quarantineDir+file+".*'; sudo userdel -r "+user+" >/dev/null 2>&1; true"); err != nil {
			t.Logf("%s: removing the seeded sudoers file and user: %v: %s", vm.Name, err, out)
		}
	})
	return file, user
}

// preflightCheck is one entry of `paddockd preflight --json`.
type preflightCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// runPreflight runs `paddockd preflight --json` on the guest and returns its checks by name. The supported Ubuntu
// VMs pass every check: exit code 0 and no check that failed. Stderr goes to a file so that it cannot break the JSON.
func runPreflight(t *testing.T, vm *VM) map[string]preflightCheck {
	t.Helper()
	out := vm.Must(`sudo paddockd preflight --json 2>/tmp/preflight.err; echo "exit=$?"`)
	i := strings.LastIndex(out, "exit=")
	if i < 0 {
		t.Fatalf("%s: preflight output without exit code: %s", vm.Name, out)
	}
	logErr := func() string { return vm.Must("cat /tmp/preflight.err") }
	exit, err := strconv.Atoi(strings.TrimSpace(out[i+len("exit="):]))
	if err != nil {
		t.Fatalf("%s: preflight exit code in %q: %v", vm.Name, out[i:], err)
	}
	var list []preflightCheck
	if err := json.Unmarshal([]byte(out[:i]), &list); err != nil {
		t.Fatalf("%s: preflight JSON: %v\n%s\nstderr: %s", vm.Name, err, out, logErr())
	}
	checks := map[string]preflightCheck{}
	for _, c := range list {
		checks[c.Name] = c
		if c.Status == "fail" {
			t.Errorf("%s: preflight check failed: %+v", vm.Name, c)
		}
	}
	if exit != 0 {
		t.Errorf("%s: preflight exits %d, want 0; stderr: %s", vm.Name, exit, logErr())
	}
	return checks
}

// TestPreflight is the VM gate of `paddockd preflight` (plan M11 decision 11, PDK-162): on a guest that has the
// packages but is not enrolled, the check reads the system without changing it, reports the Ubuntu, systemd and root
// checks as ok, and warns about a foreign sudoers file and a member of the group sudo once the test seeds them.
func TestPreflight(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		prepareGuest(t, s, vm, debDir(s))
		checks := runPreflight(t, vm)
		for _, name := range []string{"os", "systemd", "root"} {
			if checks[name].Status != "ok" {
				t.Errorf("preflight %s: %+v, want ok", name, checks[name])
			}
		}
		// paddock is the VM's administrator and a member of sudo before anything is seeded.
		if c := checks["privileged_groups"]; c.Status != "warn" || !strings.Contains(c.Detail, "paddock") {
			t.Errorf("preflight privileged_groups: %+v, want warn naming paddock", c)
		}

		file, user := seedForeignAdmin(t, vm, unique())
		before := vm.Must("sudo sha256sum /etc/sudoers.d/" + file + " && getent group sudo")
		checks = runPreflight(t, vm)
		if c := checks["sudoers_d"]; c.Status != "warn" || !strings.Contains(c.Detail, file) {
			t.Errorf("preflight sudoers_d: %+v, want warn naming %s", c, file)
		}
		if c := checks["privileged_groups"]; c.Status != "warn" || !strings.Contains(c.Detail, user) {
			t.Errorf("preflight privileged_groups: %+v, want warn naming %s", c, user)
		}
		if after := vm.Must("sudo sha256sum /etc/sudoers.d/" + file + " && getent group sudo"); after != before {
			t.Errorf("preflight changed the guest:\n%s\n→\n%s", before, after)
		}
	})
}

// TestAdoptionGates is the VM gate of adoption (plan M11 §3.11 and §8, PDK-162): a guest with a foreign sudoers file
// and a foreign member of sudo enrolls with `paddockd enroll` and is adopted and report-only. The report-only apply
// changes nothing on it and lists what enforcement would change. Enforcement through the API (typed hostname)
// quarantines the file, removes the member, writes the managed files and audits both tamper events.
func TestAdoptionGates(t *testing.T) {
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		// Enforcement removes every member of sudo that is no break-glass account.
		requireBreakGlass(t, s)
		vm.Fresh()
		file, user := seedForeignAdmin(t, vm, unique())
		sum := vm.Must("sudo sha256sum /etc/sudoers.d/" + file + " | cut -c1-64")
		members := vm.Must("getent group sudo")
		d := Install(t, s, vm, debDir(s), ReportOnly())
		if !t.Run("A1 report-only", func(t *testing.T) { d.Bind(t); gateAdoptionReportOnly(t, d, file, user, sum, members) }) {
			t.FailNow()
		}
		t.Run("A2 enforcement", func(t *testing.T) { d.Bind(t); gateAdoptionEnforce(t, d, file, user, sum) })
	})
}

// waitConfig waits until cond holds for the device's apply status rows containing q, checking in every 65 s.
func waitConfig(t *testing.T, d *Device, what, q string, timeout time.Duration, cond func([]ResourceStatus) bool) []ResourceStatus {
	t.Helper()
	var rows []ResourceStatus
	last := time.Time{}
	Until(t, d.Name+": "+what, timeout, 5*time.Second, func() {
		if time.Since(last) > 65*time.Second {
			d.Checkin()
			last = time.Now()
		}
	}, func() bool {
		rows = d.ConfigStatus(q)
		return cond(rows)
	})
	return rows
}

// hasChange reports whether one of the planned changes of the row contains want.
func hasChange(r ResourceStatus, want string) bool {
	for _, c := range r.Changes {
		if strings.Contains(c, want) {
			return true
		}
	}
	return false
}

func gateAdoptionReportOnly(t *testing.T, d *Device, file, user, sum, members string) {
	applied := d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, func(p map[string]any) bool {
		version, _ := p["bundle_version"].(float64)
		return p["mode"] == "report_only" && version >= d.Bundle
	})
	version := applied["bundle_version"].(float64)
	if changed, _ := applied["changed"].(float64); changed != 0 {
		t.Errorf("the report-only apply changed %v resources", changed)
	}
	Until(t, "the report-only bundle report", time.Minute, 2*time.Second, nil, func() bool {
		v, mode := d.BundleMode()
		return v >= version && mode == "report_only"
	})

	if got := d.Must("sudo sha256sum /etc/sudoers.d/" + file + " | cut -c1-64"); got != sum {
		t.Errorf("%s changed during report-only: %s → %s", file, sum, got)
	}
	if got := d.Must("getent group sudo"); got != members {
		t.Errorf("group sudo changed during report-only: %s → %s", members, got)
	}
	if got := d.Must("sudo ls " + quarantineDir + " 2>/dev/null | grep -c '^" + file + "' || true"); got != "0" {
		t.Errorf("%s was quarantined during report-only", file)
	}
	for path := range d.Files {
		if got := d.Must("test -e " + path + " && echo present || echo absent"); got != "absent" {
			t.Errorf("%s was written during report-only", path)
		}
	}
	if got := d.Must("systemctl is-enabled " + d.Unit + " 2>&1 || true"); strings.Contains(got, "enabled") && !strings.Contains(got, "disabled") {
		t.Errorf("unit %s was enabled during report-only: %s", d.Unit, got)
	}
	for _, e := range d.s.Events(t, "device.tamper_sudoers_d_file", d.ID) {
		if e.Params["file"] == file {
			t.Errorf("tamper.sudoers_d_file for %s during report-only", file)
		}
	}

	rows := waitConfig(t, d, "report-only status of sudo", "sudo", 2*time.Minute, func(r []ResourceStatus) bool {
		for _, row := range r {
			if row.ResourceID == "sudo" && row.Status == "pending" {
				return true
			}
		}
		return false
	})
	for _, row := range rows {
		if row.ResourceID != "sudo" {
			continue
		}
		for _, want := range []string{"quarantine " + file, "remove " + user + " from sudo"} {
			if !hasChange(row, want) {
				t.Errorf("sudo changes %q lack %q", row.Changes, want)
			}
		}
	}
	for path := range d.Files {
		rows := d.ConfigStatus("file:" + path)
		if len(rows) != 1 || rows[0].Status != "pending" || len(rows[0].Changes) == 0 || rows[0].ReportMode != "report_only" {
			t.Errorf("status of %s: %+v, want one pending row of a report-only report with its planned changes", path, rows)
		}
	}
	res := d.s.Call(t, http.MethodGet, "/api/v1/attention?"+url.Values{"q": {d.Must("hostname")}, "kind": {"report_only"}}.Encode(), nil, http.StatusOK)
	if !strings.Contains(string(res.Body), d.ID) {
		t.Errorf("no report_only attention item for the device: %s", res.Body)
	}
}

func gateAdoptionEnforce(t *testing.T, d *Device, file, user, sum string) {
	d.Enforce()
	d.SetDriftInterval()
	applied := d.WaitEvent(t, "device.bundle_applied", 5*time.Minute, func(p map[string]any) bool {
		version, _ := p["bundle_version"].(float64)
		return p["mode"] != "report_only" && version >= d.Bundle
	})
	t.Logf("enforced apply of bundle %v: changed %v", applied["bundle_version"], applied["changed"])
	d.WaitEvent(t, "device.tamper_sudoers_d_file", 3*time.Minute, func(p map[string]any) bool { return p["file"] == file })
	d.WaitEvent(t, "device.tamper_sudo_group_member", 3*time.Minute, func(p map[string]any) bool {
		return p["username"] == user && p["group"] == "sudo" && p["removed"] == true
	})

	if got := d.Must("sudo test -e /etc/sudoers.d/" + file + " && echo present || echo gone"); got != "gone" {
		t.Errorf("%s is still in /etc/sudoers.d", file)
	}
	if got := d.Must("sudo sh -c 'sha256sum " + quarantineDir + file + ".*' | cut -c1-64"); got != sum {
		t.Errorf("quarantined copy of %s: %s, want %s", file, got, sum)
	}
	if got := d.Must("id -nG " + user); strings.Contains(" "+got+" ", " sudo ") {
		t.Errorf("%s is still in sudo: %s", user, got)
	}
	if got := d.Must("id -nG paddock"); !strings.Contains(" "+got+" ", " sudo ") {
		t.Errorf("the break-glass account paddock left sudo: %s", got)
	}
	for path := range d.Files {
		if strings.HasPrefix(path, "/etc/paddock-systest/") {
			if got := d.Must("sudo stat -c '%a %U:%G' " + path); got != "640 root:adm" {
				t.Errorf("%s: %s, want 640 root:adm", path, got)
			}
		}
	}

	Until(t, "the enforced bundle report", time.Minute, 2*time.Second, nil, func() bool {
		v, mode := d.BundleMode()
		return v >= d.Bundle && mode == "enforce"
	})
	waitConfig(t, d, "enforced status of the managed files", "file:/etc/paddock-systest/"+d.run, 2*time.Minute, func(rows []ResourceStatus) bool {
		for _, r := range rows {
			if r.Status != "applied" {
				return false
			}
		}
		return len(rows) == 2
	})
	for _, r := range d.ConfigStatus("sudo") {
		if r.ResourceID == "sudo" && r.Status == "pending" {
			t.Errorf("sudo is still pending after enforcement: %+v", r)
		}
	}
	if method, mode := d.EnrollmentMode(); method != "adopted" || mode != "enforce" {
		t.Errorf("device %s/%s after enforcement, want adopted/enforce", method, mode)
	}
	if got := len(d.s.Events(t, "device.enforcement_enabled", d.ID)); got != 1 {
		t.Errorf("%d device.enforcement_enabled events, want 1", got)
	}
	res := d.s.Call(t, http.MethodGet, "/api/v1/attention?"+url.Values{"q": {d.Must("hostname")}, "kind": {"report_only"}}.Encode(), nil, http.StatusOK)
	if strings.Contains(string(res.Body), d.ID) {
		t.Errorf("report_only attention item after enforcement: %s", res.Body)
	}
}

// rolloutGate names the rendezvous steps of TestConfigRolloutGates.
const rolloutGate = "config rollout"

// rolloutShared is what both VMs of TestConfigRolloutGates share: the group they are both in, the organization's
// rollout settings from before the gate and everything the gate created, which the cleanup ends and removes in the
// order the server demands (an open rollout blocks deleting the group; deleting while rollouts are on stages the
// deletion).
type rolloutShared struct {
	mu       sync.Mutex
	group    string
	run      string
	settings json.RawMessage
	deletes  []string
	cleaned  bool
}

// rolloutSettings are the fields of GET and PUT /api/v1/settings/rollout the gate reads and restores.
type rolloutSettings struct {
	Enabled          bool    `json:"enabled"`
	Waves            []int   `json:"waves"`
	MinWaveMinutes   int     `json:"min_wave_minutes"`
	ThresholdPercent int     `json:"failure_threshold_percent"`
	ThresholdMin     int     `json:"failure_threshold_min"`
	Canary           *string `json:"canary_device_group_id"`
}

// configRollout is the part of ConfigRollout the gate reads.
type configRollout struct {
	ID          string `json:"id"`
	ChangeSetID string `json:"change_set_id"`
	Status      string `json:"status"`
}

func listRollouts(t *testing.T, s *Stack, status string) []configRollout {
	t.Helper()
	var page struct {
		Items []configRollout `json:"items"`
	}
	res := s.Call(t, http.MethodGet, "/api/v1/config-rollouts?page_size=25&status="+status, nil, http.StatusOK)
	if err := json.Unmarshal(res.Body, &page); err != nil {
		t.Fatal(err)
	}
	return page.Items
}

// sessionDo sends a request as alice and signs in again once if the session ended, as cleanupCall does.
func (s *Stack) sessionDo(t *testing.T, ctx context.Context, method, path string, body any) (portal.Response, error) {
	t.Helper()
	res, err := s.session().Do(ctx, method, path, body)
	if err == nil && res.Status == http.StatusUnauthorized {
		s.Login(t)
		res, err = s.session().Do(ctx, method, path, body)
	}
	return res, err
}

// revertChangeSet reverts a change set with a dry run and its plan hash. The revert of the open rollout's own change
// set ends that rollout as reverted and reaches every device at once.
func (s *Stack) revertChangeSet(t *testing.T, id string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	path := "/api/v1/change-sets/" + id + "/revert"
	res, err := s.sessionDo(t, ctx, http.MethodPost, path+"?dry_run=true", nil)
	var dry struct {
		Hash string `json:"plan_sha256"`
	}
	if err != nil || res.Status != http.StatusOK || json.Unmarshal(res.Body, &dry) != nil || dry.Hash == "" {
		return fmt.Errorf("dry run of the revert of %s: HTTP %d %v %s", id, res.Status, err, res.Body)
	}
	res, err = s.sessionDo(t, ctx, http.MethodPost, path+"?"+url.Values{"expected_plan": {dry.Hash}}.Encode(), nil)
	if err != nil || res.Status != http.StatusOK {
		return fmt.Errorf("revert of %s: HTTP %d %v %s", id, res.Status, err, res.Body)
	}
	return nil
}

// cleanup ends the open rollouts, puts the organization's rollout settings back and removes what the gate created.
// A running rollout is completed; a halted one carries a unit that fails, which must not reach the other devices, so
// its change set is reverted. Both VMs call it; the first does the work.
func (r *rolloutShared) cleanup(t *testing.T, s *Stack) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cleaned || r.group == "" {
		return
	}
	r.cleaned = true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, status := range []string{"running", "halted"} {
		res, err := s.sessionDo(t, ctx, http.MethodGet, "/api/v1/config-rollouts?page_size=25&status="+status, nil)
		var page struct {
			Items []configRollout `json:"items"`
		}
		if err != nil || res.Status != http.StatusOK || json.Unmarshal(res.Body, &page) != nil {
			t.Errorf("cleanup: listing %s rollouts: HTTP %d %v %s", status, res.Status, err, res.Body)
			continue
		}
		for _, ro := range page.Items {
			if status == "running" {
				s.cleanupCall(t, http.MethodPost, "/api/v1/config-rollouts/"+ro.ID+"/complete", http.StatusOK)
			} else if err := s.revertChangeSet(t, ro.ChangeSetID); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	}
	if r.settings != nil {
		var orig rolloutSettings
		if err := json.Unmarshal(r.settings, &orig); err != nil {
			t.Errorf("cleanup: rollout settings %s: %v", r.settings, err)
		} else if res, err := s.sessionDo(t, ctx, http.MethodPut, "/api/v1/settings/rollout", orig); err != nil || res.Status != http.StatusOK {
			t.Errorf("cleanup: restoring the rollout settings: HTTP %d %v %s", res.Status, err, res.Body)
		}
	}
	for _, path := range r.deletes {
		s.cleanupCall(t, http.MethodDelete, path, http.StatusNoContent, http.StatusNotFound)
	}
	s.cleanupCall(t, http.MethodDelete, "/api/v1/device-groups/"+r.group, http.StatusNoContent, http.StatusNotFound)
}

// configBucket is the Go twin of paddock_config_rollout_bucket: FNV-1a (32 bit) over "device:rollout", modulo 100. The
// server's own copy is internal to the server module.
func configBucket(device, rollout string) int {
	h := uint32(2166136261)
	for _, b := range []byte(device + ":" + rollout) {
		h ^= uint32(b)
		h *= 16777619
	}
	return int(h % 100)
}

// bundleCarries reports whether the device's newest bundle that carries a rollout carries rollout.
func bundleCarries(t *testing.T, d *Device, rollout string) bool {
	t.Helper()
	var page struct {
		Items []struct {
			RolloutID *string `json:"config_rollout_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(d.s.Call(t, http.MethodGet, "/api/v1/devices/"+d.ID+"/bundles?page_size=25", nil, http.StatusOK).Body, &page); err != nil {
		t.Fatal(err)
	}
	for _, b := range page.Items {
		if b.RolloutID != nil && *b.RolloutID == rollout {
			return true
		}
	}
	return false
}

// TestConfigRolloutGates is the VM gate of staged configuration rollouts (plan M11 §8, PDK-162). It needs both VMs
// (the first is the canary): with waves [1,100], a managed file for a group both are in reaches the canary VM only
// until the rollout is completed, and a staged unit that does not exist on the VMs fails on the canary VM, which makes
// the worker halt the rollout, and its revert ends the rollout. Rollout settings and rollouts are organization state:
// the VMs share one set, and no other gate may run at the same time.
func TestConfigRolloutGates(t *testing.T) {
	names := vms(t)
	if len(names) < 2 {
		t.Skip("the rollout gate needs both VMs: make system-test VM=all")
	}
	canary := names[0]
	shared := &rolloutShared{}
	forEachVM(t, func(t *testing.T, s *Stack, vm *VM) {
		vm.Fresh()
		d := Install(t, s, vm, debDir(s))
		// Registered after Install's cleanups, so it runs before they delete the device group.
		t.Cleanup(func() { shared.cleanup(t, s) })
		vm.Share("device", d.ID)
		vm.Share("group", d.Group)
		t.Run("R1 staged file, complete, failing staged unit, halt, revert", func(t *testing.T) {
			d.Bind(t)
			gateConfigRollout(t, s, vm, d, shared, canary)
		})
	})
}

func gateConfigRollout(t *testing.T, s *Stack, vm *VM, d *Device, shared *rolloutShared, canary string) {
	vm.Gate(t, rolloutGate)
	isCanary := vm.Name == canary
	for _, status := range []string{"running", "halted"} {
		if open := listRollouts(t, s, status); len(open) > 0 {
			t.Fatalf("rollout %s of the organization is %s; complete it first", open[0].ID, status)
		}
	}

	vm.Together(t, rolloutGate, "setup", func() string {
		devices, groups := vm.Shared("device"), vm.Shared("group")
		shared.mu.Lock()
		defer shared.mu.Unlock()
		shared.run = unique()
		shared.group = s.ID(t, s.Call(t, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": "systest rollout " + shared.run}, http.StatusCreated))
		for name, id := range devices {
			s.Call(t, http.MethodPut, "/api/v1/devices/"+id+"/groups", map[string]any{"device_group_ids": []string{groups[name], shared.group}}, http.StatusOK)
		}
		shared.settings = s.Call(t, http.MethodGet, "/api/v1/settings/rollout", nil, http.StatusOK).Body
		// A threshold of one failed device: the development stack's simulated devices count as eligible, so a
		// percentage would raise it. The long wave keeps the worker from advancing within the gate.
		s.Call(t, http.MethodPut, "/api/v1/settings/rollout", rolloutSettings{
			Enabled: true, Waves: []int{1, 100}, MinWaveMinutes: 60, ThresholdPercent: 0, ThresholdMin: 1, Canary: ptr(groups[canary]),
		}, http.StatusOK)
		return ""
	})
	shared.mu.Lock()
	run, group := shared.run, shared.group
	shared.mu.Unlock()
	var outside string // the device that is no canary
	for name, id := range vm.Shared("device") {
		if name != canary {
			outside = id
		}
	}
	// With waves [1,100] the first wave holds the devices of bucket 0 besides the canary group.
	inWave := func(rollout string) bool { return configBucket(outside, rollout) < 1 }

	// The file is staged under a new path until the device outside the canary group is outside the first wave too:
	// its bucket depends on the rollout ID, which exists only after staging. This selects the fixture, no assertion
	// is repeated.
	content := "staged " + run + "\n"
	staged := vm.Together(t, rolloutGate, "stage file", func() string {
		for attempt := range 3 {
			path := fmt.Sprintf("/etc/paddock-systest/%s-staged%d.conf", run, attempt)
			res := s.Call(t, http.MethodPost, "/api/v1/managed-files", map[string]any{
				"path": path, "content": content, "mode": "0640", "owner": "root", "group": "adm", "device_group_id": group,
			}, http.StatusCreated)
			shared.mu.Lock()
			shared.deletes = append(shared.deletes, "/api/v1/managed-files/"+s.ID(t, res))
			shared.mu.Unlock()
			open := listRollouts(t, s, "running")
			if len(open) != 1 {
				t.Fatalf("%d running rollouts after the staged file, want 1", len(open))
			}
			if !inWave(open[0].ID) {
				return fmt.Sprintf("%s %d %s", open[0].ID, attempt, path)
			}
			t.Logf("device %s is in the first wave of rollout %s; staging again", outside, open[0].ID)
			if err := s.revertChangeSet(t, open[0].ChangeSetID); err != nil {
				t.Fatal(err)
			}
		}
		t.Fatal("the device outside the canary group was in the first wave in three draws")
		return ""
	})
	rolloutID, rest, _ := strings.Cut(staged, " ")
	attempt, path, _ := strings.Cut(rest, " ")
	redrawn := attempt != "0"
	resource := "file:" + path
	before := d.bundleVersion()
	if isCanary {
		waitConfig(t, d, "staged file applied", resource, 6*time.Minute, func(r []ResourceStatus) bool {
			return len(r) == 1 && r[0].Status == "applied"
		})
		if got := d.Must("sudo cat " + path); got != strings.TrimSpace(content) {
			t.Errorf("staged file on the canary VM: %q", got)
		}
		if !bundleCarries(t, d, rolloutID) {
			t.Error("the canary VM's bundle does not carry the rollout")
		}
	} else {
		start := time.Now()
		for time.Since(start) < 2*time.Minute {
			d.Checkin()
			time.Sleep(40 * time.Second)
			// A redraw's revert and second staging recompile asynchronously, so the version may move; the content
			// checks below hold either way.
			if v := d.bundleVersion(); v != before && !redrawn {
				t.Fatalf("the VM outside the wave got bundle %v (had %v)", v, before)
			}
		}
		if bundleCarries(t, d, rolloutID) {
			t.Error("the bundle of the VM outside the wave carries the rollout")
		}
		if got := d.Must("sudo test -e " + path + " && echo present || echo absent"); got != "absent" || len(d.ConfigStatus(resource)) != 0 {
			t.Errorf("the staged file reached the VM outside the wave (%s)", got)
		}
	}

	vm.Together(t, rolloutGate, "complete", func() string {
		s.StepUp(t)
		s.Call(t, http.MethodPost, "/api/v1/config-rollouts/"+rolloutID+"/complete", nil, http.StatusOK)
		return ""
	})
	waitConfig(t, d, "staged file applied after the completion", resource, 6*time.Minute, func(r []ResourceStatus) bool {
		return len(r) == 1 && r[0].Status == "applied"
	})
	if got := d.Must("sudo cat " + path); got != strings.TrimSpace(content) {
		t.Errorf("staged file after the completion: %q", got)
	}

	// The unit exists on no VM: the canary VM reports it failed and the worker halts the rollout. The other VM
	// reports it only when its bucket puts it in the first wave.
	unit := "systest-missing-" + run + ".service"
	unitResource := "unit:" + unit
	failing := vm.Together(t, rolloutGate, "stage unit", func() string {
		res := s.Call(t, http.MethodPost, "/api/v1/managed-units", map[string]any{"unit": unit, "enabled": true, "active": true, "device_group_id": group}, http.StatusCreated)
		shared.mu.Lock()
		shared.deletes = append(shared.deletes, "/api/v1/managed-units/"+s.ID(t, res))
		shared.mu.Unlock()
		open := listRollouts(t, s, "running")
		if len(open) != 1 {
			t.Fatalf("%d running rollouts after the staged unit, want 1", len(open))
		}
		return open[0].ID + " " + open[0].ChangeSetID
	})
	failingID, changeSet, _ := strings.Cut(failing, " ")
	reportsUnit := isCanary || inWave(failingID)
	if reportsUnit {
		rows := waitConfig(t, d, "staged unit failed", unitResource, 6*time.Minute, func(r []ResourceStatus) bool {
			return len(r) == 1 && r[0].Status == "failed"
		})
		if !strings.Contains(rows[0].Message, "unknown unit") {
			t.Errorf("failure of %s: %q, want unknown unit", unitResource, rows[0].Message)
		}
	}
	vm.Together(t, rolloutGate, "halted", func() string {
		Until(t, "rollout halted by the worker", 5*time.Minute, 10*time.Second, nil, func() bool {
			return len(haltEvents(t, s, failingID)) > 0
		})
		if got := haltEvents(t, s, failingID); len(got) != 1 || got[0] != "worker/success" {
			t.Fatalf("halt events %v, want exactly one successful halt by the worker", got)
		}
		if ro := listRollouts(t, s, "halted"); len(ro) != 1 || ro[0].ID != failingID {
			t.Fatalf("halted rollouts %+v, want %s", ro, failingID)
		}
		return ""
	})
	if !reportsUnit && len(d.ConfigStatus(unitResource)) != 0 {
		t.Errorf("the VM outside the wave reports %s", unitResource)
	}

	vm.Together(t, rolloutGate, "revert", func() string {
		s.StepUp(t)
		if err := s.revertChangeSet(t, changeSet); err != nil {
			t.Fatal(err)
		}
		if ro := listRollouts(t, s, "reverted"); len(ro) == 0 || ro[0].ID != failingID {
			t.Fatalf("reverted rollouts %+v, want %s first", ro, failingID)
		}
		return ""
	})
	if reportsUnit {
		waitConfig(t, d, "staged unit gone from the apply status", unitResource, 6*time.Minute, func(r []ResourceStatus) bool { return len(r) == 0 })
	}
	if got := len(haltEvents(t, s, failingID)); got != 1 {
		t.Errorf("%d halt events after the revert, want 1", got)
	}
	vm.Together(t, rolloutGate, "done", func() string { return "" })
}

// haltEvents lists "actor/outcome" of the config_rollout.halted events of the rollout.
func haltEvents(t *testing.T, s *Stack, rollout string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	all, err := s.session().AuditEvents(ctx, "config_rollout.halted")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range all {
		if e.Params["rollout_id"] == rollout {
			out = append(out, e.Actor.Display+"/"+e.Outcome)
		}
	}
	return out
}

func ptr[T any](v T) *T { return &v }

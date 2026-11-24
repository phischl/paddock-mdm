package system

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

const platformOrganizations = "/api/platform/v1/organizations"

// orgAdmin is a temporary administrator of a gate organization with a TOTP authenticator. A Stack that has one acts
// as this administrator instead of alice (gate OS1: the VMs enroll into an organization of their own).
type orgAdmin struct {
	username, password string
	totp               *portal.TOTP
}

// login signs the administrator in.
func (a *orgAdmin) login(ctx context.Context) (*portal.Session, error) {
	return portal.LoginAs(ctx, a.username, a.password)
}

// stepUp runs a step-up of session, repeated once after the maximum auth age (see Stack.StepUp).
func (a *orgAdmin) stepUp(t *testing.T, session *portal.Session) {
	t.Helper()
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		final, err := portal.StepUpAs(ctx, session, a.username, a.password, a.totp)
		cancel()
		if err == nil && !strings.Contains(final, "stepup=failed") {
			return
		}
		if attempt == 2 {
			t.Fatalf("step-up of %s: %v (returned to %s)", a.username, err, final)
		}
		time.Sleep(stepUpRetryAfter)
	}
}

// offboardingGate is the organization of gate OS1 with one administrator per VM: parallel step-ups on one session
// make Paddock refuse all but one (PDK-445).
type offboardingGate struct {
	slug, id string
	admins   map[string]*orgAdmin

	mu   sync.Mutex
	root *portal.Session
}

// offboardingOffVM is the VM that is switched off while the deletion runs: the last of the run, so that a run of one
// VM still covers the case that needs the tombstone path.
func offboardingOffVM(names []string) string { return names[len(names)-1] }

// newOffboardingGate creates a gate organization ("Gate gate-…", the naming the acceptance gates use) and one
// administrator per VM. The administrators are deleted, and the organization with them if it still exists, in the
// AfterAll of vm, once every VM's subtest ended.
func newOffboardingGate(t *testing.T, vm *VM, names []string) *offboardingGate {
	t.Helper()
	slug := "gate-" + unique()
	g := &offboardingGate{slug: slug, admins: map[string]*orgAdmin{}}
	g.root = g.platformSession(t)

	// The server provisions the organization in Authentik synchronously, up to a minute.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	client := *g.root.Client
	client.Timeout = 90 * time.Second
	res, err := (&portal.Session{User: g.root.User, Client: &client}).Do(ctx, http.MethodPost, platformOrganizations,
		map[string]string{"slug": slug, "name": "Gate " + slug})
	if err != nil || res.Status != http.StatusCreated {
		t.Fatalf("create organization %s: %v HTTP %d %s", slug, err, res.Status, res.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body, &created); err != nil || created.ID == "" {
		t.Fatalf("organization %s without id: %s", slug, res.Body)
	}
	g.id = created.ID
	vm.AfterAll(t, g.ensureDeleted)

	ak, err := portal.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		// Each administrator gets its own budget: an `ak shell` for the TOTP authenticator is slow under load.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		a := &orgAdmin{username: "systest-os1-" + unique() + "@" + slug + ".test", password: "pw-" + uuid.NewString()}
		pk, err := ak.CreateUser(ctx, a.username, a.password, portal.RoleGroup(slug, "admins"))
		vm.AfterAll(t, func(*testing.T) {
			if pk != 0 {
				_ = ak.DeleteUser(context.Background(), pk)
			}
		})
		if err != nil {
			t.Fatalf("create %s: %v", a.username, err)
		}
		if a.totp, err = portal.AddTOTP(ctx, a.username); err != nil {
			t.Fatal(err)
		}
		g.admins[name] = a
	}
	setTestVMLoginSettings(t, &Stack{gate: g.admins[names[0]]})
	return g
}

// setTestVMLoginSettings gives the organization the login settings of the test VMs, as `make dev-seed` does for acme
// and (*Lab).stack for the lab: without the install administrator as break-glass account and 90-paddock in the
// allowlist, the first enforcement quarantines the sudoers file the harness runs on.
func setTestVMLoginSettings(t *testing.T, s *Stack) {
	t.Helper()
	s.Login(t)
	var settings map[string]any
	if err := json.Unmarshal(s.Call(t, http.MethodGet, "/api/v1/settings/login", nil, http.StatusOK).Body, &settings); err != nil {
		t.Fatal(err)
	}
	delete(settings, "updated_at")
	settings["break_glass_accounts"] = []string{vmAdmin}
	settings["sudoers_d_allowlist"] = []string{"README", "90-paddock"}
	s.StepUp(t)
	s.Call(t, http.MethodPut, "/api/v1/settings/login", settings, http.StatusOK)
}

func (g *offboardingGate) platformSession(t *testing.T) *portal.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root, err := portal.Login(ctx, portal.PlatformAdmin)
	if err != nil {
		t.Fatalf("login platform administrator (run make dev-seed): %v", err)
	}
	return root
}

// status reads the organization's status as the platform administrator, signing in again once when the session ended.
func (g *offboardingGate) status(t *testing.T) string {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := g.root.Do(ctx, http.MethodGet, platformOrganizations+"/"+g.id, nil)
	if err == nil && res.Status == http.StatusUnauthorized {
		g.root = g.platformSession(t)
		res, err = g.root.Do(ctx, http.MethodGet, platformOrganizations+"/"+g.id, nil)
	}
	var org struct {
		Status string `json:"status"`
	}
	if err != nil || res.Status != http.StatusOK || json.Unmarshal(res.Body, &org) != nil {
		t.Fatalf("organization %s: %v HTTP %d %s", g.slug, err, res.Status, res.Body)
	}
	return org.Status
}

// requestDeletion asks, as the platform administrator after a step-up, to delete the organization without a grace
// period (accepted by development builds only).
func (g *offboardingGate) requestDeletion(t *testing.T) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	// The session was idle through the VM setup, longer than the server's idle timeout (30 min).
	g.root = g.platformSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	final, err := g.root.StepUp(ctx, portal.PlatformAdmin, "/")
	if err != nil || strings.Contains(final, "stepup=failed") {
		t.Fatalf("step-up of the platform administrator: %v (returned to %s)", err, final)
	}
	res, err := g.root.Do(ctx, http.MethodPost, platformOrganizations+"/"+g.id+"/delete",
		map[string]any{"confirm_slug": g.slug, "reason": "system gate OS1", "grace_days": 0})
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("delete organization %s: %v HTTP %d %s", g.slug, err, res.Status, res.Body)
	}
}

// waitDeleted waits until the organization is `deleted`.
func (g *offboardingGate) waitDeleted(t *testing.T, timeout time.Duration) {
	t.Helper()
	Until(t, "organization "+g.slug+" deleted", timeout, 10*time.Second, nil, func() bool { return g.status(t) == "deleted" })
}

// ensureDeleted leaves no gate organization behind: a run that failed before the deletion request deletes the
// organization here (OFB-8). Failures are reported on t, which is the parent test.
func (g *offboardingGate) ensureDeleted(t *testing.T) {
	st := g.status(t)
	if st == "active" || st == "provisioning_failed" {
		g.requestDeletion(t)
	}
	if st != "deleted" {
		g.waitDeleted(t, 10*time.Minute)
	}
}

// guestPhase is what the guest shows of a device that is being offboarded: the Paddock packages with the dead man's
// switch token still stored (armed), the packages with the token deleted (disarmed), or the packages gone (removed).
type guestPhase string

const (
	phaseArmed    guestPhase = "armed"
	phaseDisarmed guestPhase = "disarmed"
	phaseRemoved  guestPhase = "removed"
)

// guestPhaseScript prints "<phase> <triggered>", triggered being "yes" once the agent's dead man's switch state says
// so. It runs as a plain command, as the guest may be in the middle of a package removal.
const guestPhaseScript = `if dpkg-query -W -f '${Package} ${db:Status-Abbrev}\n' 'paddock-*' fleet-osquery 2>/dev/null | grep -q ' ii'; then
  if sudo test -e /var/lib/paddock/revoke/self-lock.dsse; then p=armed; else p=disarmed; fi
else p=removed; fi
t=no
sudo grep -Eq '"triggered":[[:space:]]*true' /var/lib/paddock/state/dms.json 2>/dev/null && t=yes
echo "$p $t"`

// parseGuestPhase splits the output of guestPhaseScript.
func parseGuestPhase(out string) (guestPhase, bool, error) {
	f := strings.Fields(out)
	if len(f) != 2 || (f[1] != "yes" && f[1] != "no") {
		return "", false, fmt.Errorf("guest phase %q", out)
	}
	switch p := guestPhase(f[0]); p {
	case phaseArmed, phaseDisarmed, phaseRemoved:
		return p, f[1] == "yes", nil
	}
	return "", false, fmt.Errorf("guest phase %q", out)
}

// phaseTrace is the sequence of phases a guest was seen in.
type phaseTrace []guestPhase

// add records p unless it is the last phase seen.
func (tr *phaseTrace) add(p guestPhase) {
	if n := len(*tr); n == 0 || (*tr)[n-1] != p {
		*tr = append(*tr, p)
	}
}

// check fails for a sequence that goes back (a removed guest with Paddock again, a disarmed one with a token again)
// or does not end in removed.
func (tr phaseTrace) check() error {
	rank := map[guestPhase]int{phaseArmed: 0, phaseDisarmed: 1, phaseRemoved: 2}
	for i := 1; i < len(tr); i++ {
		if rank[tr[i]] < rank[tr[i-1]] {
			return fmt.Errorf("phases went back: %v", tr)
		}
	}
	if len(tr) == 0 || tr[len(tr)-1] != phaseRemoved {
		return fmt.Errorf("phases do not end in removal: %v", tr)
	}
	return nil
}

// watchScript runs on the guest from before the deletion to the removal and timestamps (wall clock, seconds) the
// first time the dead man's switch token is seen, the first time it is gone, and the removal of the Paddock packages.
// A package list file exists while the package is installed. The loop is cheap enough to catch a change within 0.2 s,
// and the log, unlike a poll over SSH, shows which came first.
const watchScript = `#!/bin/bash
log=/var/log/os1-watch.log
tok=/var/lib/paddock/revoke/self-lock.dsse
seen=0; gone=0; rem=0
while :; do
  if compgen -G '/var/lib/dpkg/info/paddock-*.list' >/dev/null; then inst=yes; else inst=no; fi
  if [ -e "$tok" ]; then
    [ $seen = 0 ] && { echo "$(date +%s.%N) armed" >>$log; seen=1; }
  elif [ $seen = 1 ] && [ $gone = 0 ]; then
    echo "$(date +%s.%N) token_gone installed=$inst" >>$log; gone=1
  fi
  if [ $inst = no ] && [ $rem = 0 ]; then echo "$(date +%s.%N) removed" >>$log; rem=1; fi
  [ $rem = 1 ] && [ $gone = 1 ] && exit 0
  sleep 0.2
done
`

const watchUnit = `[Unit]
Description=Gate OS1 watcher of the dead man's switch token
# The watcher must hold the token in view before the agent's first check-in can disarm it after the boot.
Before=paddock-supervisor.service

[Service]
ExecStart=/usr/local/sbin/os1-watch.sh

[Install]
WantedBy=multi-user.target
`

const watchLog = "/var/log/os1-watch.log"

// installWatcher starts the watcher now and at every boot; it is a guest file of the gate, not of Paddock, and
// survives the removal.
func installWatcher(vm *VM) {
	vm.t.Helper()
	vm.MustIn([]byte(watchScript), "sudo tee /usr/local/sbin/os1-watch.sh >/dev/null && sudo chmod 0755 /usr/local/sbin/os1-watch.sh")
	vm.MustIn([]byte(watchUnit), "sudo tee /etc/systemd/system/os1-watch.service >/dev/null")
	vm.Must("sudo systemctl daemon-reload && sudo systemctl enable --now os1-watch.service")
}

// checkWatchLog fails unless the log shows the token gone while the packages were still installed, before they were
// removed: the disarm came first.
func checkWatchLog(log string) error {
	// Line order, not the timestamps, decides: a clock step after the boot must not fail the gate.
	gone, removed := -1, -1
	var goneInstalled bool
	for i, line := range strings.Split(log, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if _, err := strconv.ParseFloat(f[0], 64); err != nil {
			return fmt.Errorf("watch log line %q: %w", line, err)
		}
		switch f[1] {
		case "token_gone":
			gone, goneInstalled = i, len(f) > 2 && f[2] == "installed=yes"
		case "removed":
			removed = i
		}
	}
	switch {
	case gone < 0:
		return fmt.Errorf("the token was never seen to go (log %q)", log)
	case removed < 0:
		return fmt.Errorf("the removal was never seen (log %q)", log)
	case !goneInstalled:
		return fmt.Errorf("the token went only after the packages were removed: the disarm did not come first (log %q)", log)
	case gone > removed:
		return fmt.Errorf("the token went after the removal (log %q)", log)
	}
	return nil
}

package acceptance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/pkg/sudoers"
	"github.com/paddock-mdm/paddock/test/acceptance/devicesim"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
)

// v2Device enrolls an active acme device whose agent reports schema_versions, optionally in a device group.
func v2Device(t *testing.T, alice *env.Portal, group string, versions ...int) *devicesim.Device {
	t.Helper()
	d := activeDevice(t, alice, group, "m3a-"+uniqueSuffix())
	d.SchemaVersions = versions
	return d
}

// latestBundle checks in until the device is offered a bundle that satisfies cond and returns it (applied).
func latestBundle(t *testing.T, d *devicesim.Device, timeout time.Duration, cond func(*bundle.Bundle) bool) *bundle.Bundle {
	t.Helper()
	ctx := testContext(t, timeout+time.Minute)
	var got *bundle.Bundle
	checkinUntil(t, d, timeout, func(out protocol.CheckinResponse) bool {
		if out.Bundle == nil {
			return false
		}
		b, err := d.Fetch(ctx, out.Bundle)
		if err != nil {
			t.Fatalf("fetch bundle %d: %v", out.Bundle.Version, err)
		}
		got = b
		return cond(b)
	})
	return got
}

func resourceSpec[T any](t *testing.T, b *bundle.Bundle, id string) (T, bool) {
	t.Helper()
	var out T
	for _, r := range b.Resources {
		if r.ID == id {
			if err := json.Unmarshal(r.Spec, &out); err != nil {
				t.Fatal(err)
			}
			return out, true
		}
	}
	return out, false
}

func hasLoginAndSudo(b *bundle.Bundle) bool {
	ids := []string{}
	for _, r := range b.Resources {
		ids = append(ids, r.ID)
	}
	return b.SchemaVersion == bundle.SchemaVersion2 && slices.Contains(ids, "login") && slices.Contains(ids, "sudo")
}

// TestIdentityBundles is gate I3 (plan M3a §6): an agent reporting schema 2 gets login and sudo, one reporting 1 gets
// v1 unchanged; a lock reaches the bundle within 10 s; a suspension empties the allow list; a directly assigned user
// gets the per-device group into the allow list and into Authentik.
func TestIdentityBundles(t *testing.T) {
	alice := login(t, env.Alice)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	dev := v2Device(t, alice, "", 1, 2)
	old := v2Device(t, alice, "", 1)
	// The first bundle is compiled at enrollment, before any check-in reported the schema; the compiler's reconcile
	// recompiles once the heartbeat recorded schema 2 (plan M3a decision 14a).
	b := latestBundle(t, dev, 3*time.Minute, hasLoginAndSudo)
	login, _ := resourceSpec[bundle.LoginSpec](t, b, "login")
	if login.Provider != "himmelblau" || login.Himmelblau.AppID != "paddock-device-acme" || login.Himmelblau.Domain != "acme.test" ||
		!slices.Equal(login.Himmelblau.PamAllowGroups, []string{"paddock.acme"}) || login.Suspended ||
		!slices.Equal(login.BreakGlassAccounts, []string{"paddock"}) {
		t.Fatalf("login resource %+v", login)
	}
	sudo, _ := resourceSpec[bundle.SudoSpec](t, b, "sudo")
	if !slices.Equal(sudo.SudoersDAllowlist, []string{"README", "90-paddock"}) || !slices.Equal(sudo.PrivilegedGroups, []string{"sudo", "admin", "wheel"}) {
		t.Fatalf("sudo resource %+v", sudo)
	}
	ob := latestBundle(t, old, time.Minute, func(*bundle.Bundle) bool { return true })
	if ob.SchemaVersion != bundle.SchemaVersion {
		t.Fatalf("an agent reporting [1] got schema %d", ob.SchemaVersion)
	}
	for _, r := range ob.Resources {
		if r.Type == bundle.TypeLogin || r.Type == bundle.TypeSudo {
			t.Fatalf("v1 bundle with %s", r.ID)
		}
	}

	// Lock: the user (allowed everywhere by the empty assignment) is in locked_users within 10 s.
	user := createLocalUser(t, alice, "i3")
	res := call(t, alice, http.MethodPost, "/api/v1/users/"+user.ID+"/lock", nil)
	expectStatus(t, res, http.StatusOK, "")
	lockedAt := time.Now()
	latestBundle(t, dev, 30*time.Second, func(b *bundle.Bundle) bool {
		l, _ := resourceSpec[bundle.LoginSpec](t, b, "login")
		return slices.Contains(l.LockedUsers, user.Username)
	})
	if took := time.Since(lockedAt); took > 10*time.Second {
		t.Fatalf("the lock reached the bundle after %s, want at most 10 s", took)
	}
	expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/users/"+user.ID+"/unlock", nil), http.StatusOK, "")

	// Suspension: present and empty allow list.
	expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/devices/"+dev.DeviceID+"/suspend-logins", nil), http.StatusOK, "")
	latestBundle(t, dev, 30*time.Second, func(b *bundle.Bundle) bool {
		l, _ := resourceSpec[bundle.LoginSpec](t, b, "login")
		return l.Suspended && l.Himmelblau.PamAllowGroups != nil && len(l.Himmelblau.PamAllowGroups) == 0
	})
	expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/devices/"+dev.DeviceID+"/resume-logins", nil), http.StatusOK, "")

	// A directly assigned user: the per-device group exists in Authentik with the user and is the allow list.
	direct := createLocalUser(t, alice, "i3-direct")
	res = call(t, alice, http.MethodPut, "/api/v1/devices/"+dev.DeviceID+"/login-assignment", map[string]any{"users": []string{direct.ID}, "groups": []string{}})
	expectStatus(t, res, http.StatusOK, "")
	perDevice := "paddock.acme.d." + dev.DeviceID
	t.Cleanup(func() {
		call(t, alice, http.MethodPut, "/api/v1/devices/"+dev.DeviceID+"/login-assignment", map[string]any{"users": []string{}, "groups": []string{}})
	})
	members, err := ak.GroupMembers(testContext(t, time.Minute), perDevice)
	if err != nil || !slices.Equal(members, []string{direct.Username}) {
		t.Fatalf("Authentik group %s members %v (%v)", perDevice, members, err)
	}
	latestBundle(t, dev, 30*time.Second, func(b *bundle.Bundle) bool {
		l, _ := resourceSpec[bundle.LoginSpec](t, b, "login")
		return slices.Equal(l.Himmelblau.PamAllowGroups, []string{perDevice})
	})
}

// TestRootEquivalenceGate is gate P2 (plan M3a §6): two restricted profiles that are harmless on their own combine
// into a root-equivalent set; the user's effective profile is flagged and reported as full (the portal warning is
// part of E3).
func TestRootEquivalenceGate(t *testing.T) {
	alice := login(t, env.Alice)
	user := createLocalUser(t, alice, "p2")
	group := userGroup(t, alice)
	expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/user-groups/"+group+"/members", map[string]string{"user_id": user.ID}), http.StatusNoContent, "")
	copyHelper := profile(t, alice, "restricted", "/usr/bin/cp /srv/build/helper /opt/tools/helper")
	runHelper := profile(t, alice, "restricted", "/opt/tools/helper --sync")
	for _, p := range []string{copyHelper, runHelper} {
		var got struct {
			RootEquivalent bool `json:"root_equivalent"`
		}
		if err := call(t, alice, http.MethodGet, "/api/v1/permission-profiles/"+p, nil).JSON(&got); err != nil || got.RootEquivalent {
			t.Fatalf("a harmless profile is flagged (%v)", err)
		}
	}
	for _, a := range []map[string]any{
		{"profile_id": copyHelper, "subject_type": "user", "subject_id": user.ID},
		{"profile_id": runHelper, "subject_type": "group", "subject_id": group},
	} {
		res := call(t, alice, http.MethodPost, "/api/v1/profile-assignments", a)
		expectStatus(t, res, http.StatusCreated, "")
		createdID(t, alice, "/api/v1/profile-assignments", res)
	}
	var eff struct {
		Class                  string   `json:"class"`
		ReportedClass          string   `json:"reported_class"`
		RootEquivalent         bool     `json:"root_equivalent"`
		RootEquivalentCommands []string `json:"root_equivalent_commands"`
		Derivation             []struct {
			Kind string `json:"kind"`
		} `json:"derivation"`
	}
	res := call(t, alice, http.MethodGet, "/api/v1/users/"+user.ID+"/effective-profile", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&eff); err != nil {
		t.Fatal(err)
	}
	if eff.Class != "restricted" || eff.ReportedClass != "full" || !eff.RootEquivalent || len(eff.RootEquivalentCommands) != 2 || len(eff.Derivation) == 0 {
		t.Fatalf("effective profile %s", res.Body)
	}
}

// TestEffectiveProfileGate is the end-to-end part of gate P1 (plan M3a §6): two devices with identical inputs get
// byte-identical sudo entries, and every entry rendered with pkg/sudoers passes visudo -cf in the compiler container.
// (The property and golden tests of P1 are the unit tests of server/internal/domain/privilege.)
func TestEffectiveProfileGate(t *testing.T) {
	alice := login(t, env.Alice)
	group := namedGroup(t, alice, "p1 devices")
	a, b := v2Device(t, alice, group, 1, 2), v2Device(t, alice, group, 1, 2)
	user := createLocalUser(t, alice, "p1")
	full := createLocalUser(t, alice, "p1-full")
	restricted := profile(t, alice, "restricted", "/usr/bin/systemctl restart nginx.service", "/usr/bin/journalctl -u nginx.service")
	root := profile(t, alice, "full")
	stepUp(t, alice, env.Alice, true) // assigning a full profile (plan M4a decision 7)
	for _, x := range []map[string]any{
		{"profile_id": restricted, "subject_type": "user", "subject_id": user.ID, "device_group_id": group},
		{"profile_id": root, "subject_type": "user", "subject_id": full.ID, "device_group_id": group},
	} {
		res := call(t, alice, http.MethodPost, "/api/v1/profile-assignments", x)
		expectStatus(t, res, http.StatusCreated, "")
		createdID(t, alice, "/api/v1/profile-assignments", res)
	}
	entries := func(d *devicesim.Device) []sudoers.Entry {
		bd := latestBundle(t, d, 3*time.Minute, func(bd *bundle.Bundle) bool {
			s, ok := resourceSpec[bundle.SudoSpec](t, bd, "sudo")
			return ok && len(s.Entries) == 2
		})
		s, _ := resourceSpec[bundle.SudoSpec](t, bd, "sudo")
		return s.Entries
	}
	ea, eb := entries(a), entries(b)
	ja, _ := json.Marshal(ea)
	jb, _ := json.Marshal(eb)
	if !bytes.Equal(ja, jb) {
		t.Fatalf("identical inputs, different entries:\n%s\n%s", ja, jb)
	}
	for i, e := range ea {
		out, err := sudoers.Render(e, sudoers.PlaceholderUID, sudoers.Classic)
		if err != nil {
			t.Fatal(err)
		}
		// The compiler's root file system is read-only: visudo reads the entry from stdin.
		ctx := testContext(t, time.Minute)
		if out, err := stack.ComposeInput(ctx, bytes.NewReader(out), "exec", "-T", "paddock-compiler", "/usr/sbin/visudo", "-cf", "-"); err != nil {
			t.Fatalf("entry %d (%s) fails visudo in the compiler container: %v\n%s", i, e.Username, err, out)
		}
	}
}

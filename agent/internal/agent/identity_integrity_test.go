package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/apply"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// diskSys is a fake system whose file writes also land below the test root, where the integrity check reads them.
type diskSys struct {
	*fakesys.System
	root string
}

func (s diskSys) WriteFileAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if err := s.System.WriteFileAtomic(path, data, mode, uid, gid); err != nil {
		return err
	}
	full := filepath.Join(s.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, data, mode)
}

func (s diskSys) Remove(path string) error {
	if err := s.System.Remove(path); err != nil {
		return err
	}
	return os.Remove(filepath.Join(s.root, path))
}

// write changes a file outside Paddock, on the fake system and on the disk.
func (s diskSys) write(t *testing.T, path, content string) {
	t.Helper()
	s.Files[path] = &fakesys.File{Data: []byte(content), Mode: 0o644}
	writeFile(t, filepath.Join(s.root, path), content)
}

// withLogin gives the agent the applier of New on an Ubuntu 24.04 fake system with the paddock-deny PAM profile and
// the integrity check, wired as its file guard unless the agent predates it.
func withLogin(t *testing.T, g *testgw.Gateway, guard bool) (*Agent, diskSys) {
	t.Helper()
	a := newAgent(t, g)
	sys := diskSys{System: fakesys.New(), root: a.d.Layout.Root}
	sys.AptVersion = "4.0.4-ubuntu24.04"
	for path, content := range map[string]string{
		"/usr/lib/os-release": "ID=ubuntu\nVERSION_ID=\"24.04\"\n", "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
		"/etc/pam.d/common-auth":    "auth\trequisite\tpam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed\n",
		"/etc/pam.d/common-account": "account\trequired\tpam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed\n",
	} {
		sys.Files[path] = &fakesys.File{Data: []byte(content), Mode: 0o644}
	}
	sys.Files["/etc/os-release"] = &fakesys.File{Symlink: true}
	for _, u := range []string{"himmelblaud.service", "himmelblaud-tasks.service"} {
		sys.Units[u] = &fakesys.Unit{State: "enabled"}
	}
	a.d.Events = &reconcile.Events{}
	a.d.Applier = apply.New(sys, &reconcile.Managed{Files: map[string]string{}}, a.d.Events)
	a = withIntegrity(t, a)
	if guard {
		a.d.Applier.WithFileGuard(a.d.Integrity)
	}
	return a, sys
}

func loginBundle(t *testing.T, version int64, hello bool, locked ...string) bundle.Bundle {
	t.Helper()
	r, err := bundle.LoginResource(bundle.LoginSpec{
		Provider: bundle.ProviderHimmelblau,
		Himmelblau: bundle.HimmelblauSpec{OIDCIssuerURL: "https://auth.paddock.localhost:8443/application/o/paddock-device-acme/", AppID: "paddock-device-acme",
			Domain: "acme.test", PamAllowGroups: []string{"paddock.acme"}, EnableHello: hello, HelloPinMinLength: 6,
			PackageVersion: "4.0.4"},
		SessionAction: bundle.SessionActionLockScreen, BreakGlassAccounts: []string{"paddock"}, LockedUsers: locked,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle.Bundle{SchemaVersion: 1, BundleVersion: version, DeviceID: testgw.DeviceID, OrganizationID: testgw.OrgID,
		IssuedAt: time.Now(), Resources: []bundle.Resource{r}}
}

// identityEvents returns the files of the tamper reports and the changed lists of login.applied since the last call.
func identityEvents(t *testing.T, a *Agent, g *testgw.Gateway) (files []string, applied [][]any) {
	t.Helper()
	files = tampered(t, a, g)
	events := append(spooled(t, a), eventsOf(g, protocol.EventLoginApplied)...)
	for _, e := range events {
		if e.Type == protocol.EventLoginApplied {
			applied = append(applied, eventData(t, e)["changed"].([]any))
		}
	}
	g.Mu.Lock()
	g.Events = nil
	g.Mu.Unlock()
	a.Cycle(context.Background())
	g.Mu.Lock()
	g.Events = nil
	g.Mu.Unlock()
	return files, applied
}

// 1126c-1: root edits himmelblau.conf on an enforced device; the next drift pass reports it once, then restores it.
func TestIdentityFileManipulationReported(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a, sys := withLogin(t, g, true)
	g.OfferBundle(testgw.SignedBundleOffer(t, loginBundle(t, 1, true)))
	a.Cycle(ctx)
	if files, applied := identityEvents(t, a, g); len(files) != 0 || len(applied) != 1 {
		t.Fatalf("first apply: tamper %v, login.applied %v", files, applied)
	}
	render := string(sys.Files[reconcile.HimmelblauConf].Data)
	sys.write(t, reconcile.HimmelblauConf, render+"pam_allow_groups = everyone\n")
	a.drift(ctx)
	files, applied := identityEvents(t, a, g)
	if !slices.Equal(files, []string{reconcile.HimmelblauConf}) || len(applied) != 1 || !slices.Contains(applied[0], any("config")) {
		t.Fatalf("tamper %v, login.applied %v", files, applied)
	}
	if got, _ := os.ReadFile(filepath.Join(sys.root, reconcile.HimmelblauConf)); string(got) != render {
		t.Fatalf("himmelblau.conf not restored: %q", got)
	}
	a.drift(ctx)
	ticks(t, a, g, 2)
}

// restarted replaces the agent as an agent update does; guard tells whether the new agent has the identity check.
func restarted(t *testing.T, a *Agent, guard bool) *Agent {
	t.Helper()
	a = withIntegrity(t, a)
	if guard {
		a.d.Applier.WithFileGuard(a.d.Integrity)
	}
	return a
}

// enforcedBeforeUpdate is a device on which an agent without the identity check applied b, before the socket
// drop-ins existed.
func enforcedBeforeUpdate(t *testing.T, g *testgw.Gateway, b bundle.Bundle) (*Agent, diskSys) {
	t.Helper()
	a, sys := withLogin(t, g, false)
	g.OfferBundle(testgw.SignedBundleOffer(t, b))
	a.Cycle(context.Background())
	for _, p := range reconcile.HimmelblauSocketDropIns {
		delete(sys.Files, p)
		_ = os.Remove(filepath.Join(sys.root, p))
	}
	identityEvents(t, a, g)
	return a, sys
}

// 1126c-3 and 1126c-2: the first start after the update reports nothing, writes the drop-ins without a report, and
// the first new lock after it rewrites the files without a report.
func TestIdentityUpdateThenNewLockNotReported(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a, _ := enforcedBeforeUpdate(t, g, loginBundle(t, 1, true))
	a = restarted(t, a, true)
	ticks(t, a, g, 1)
	a.drift(ctx)
	ticks(t, a, g, 1)
	if files, applied := identityEvents(t, a, g); len(files) != 0 || len(applied) != 1 || !slices.Contains(applied[0], any("config")) {
		t.Fatalf("first start: tamper %v, login.applied %v", files, applied)
	}
	g.OfferBundle(testgw.SignedBundleOffer(t, loginBundle(t, 2, false, "erin@acme.test")))
	a.Cycle(ctx)
	files, applied := identityEvents(t, a, g)
	if len(files) != 0 || len(applied) != 1 || !slices.Contains(applied[0], any("config")) || !slices.Contains(applied[0], any("deny_list")) {
		t.Fatalf("new lock: tamper %v, login.applied %v", files, applied)
	}
	ticks(t, a, g, 2)
}

// 1126c-4: a change made before the update is judged against what Paddock wrote before it, reported once at the
// first correction and restored.
func TestIdentityChangeBeforeUpdateReported(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		change     func(t *testing.T, sys diskSys)
	}{
		{"conf edited", reconcile.HimmelblauConf, func(t *testing.T, sys diskSys) {
			sys.write(t, reconcile.HimmelblauConf, string(sys.Files[reconcile.HimmelblauConf].Data)+"pam_allow_groups = everyone\n")
		}},
		{"deny list deleted", reconcile.DenyList, func(t *testing.T, sys diskSys) {
			delete(sys.Files, reconcile.DenyList)
			_ = os.Remove(filepath.Join(sys.root, reconcile.DenyList))
		}},
		{"locked name removed", reconcile.DenyList, func(t *testing.T, sys diskSys) {
			sys.write(t, reconcile.DenyList, "erin@acme.test\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			g := testgw.New(t)
			a, sys := enforcedBeforeUpdate(t, g, loginBundle(t, 1, true, "erin@acme.test"))
			want := sys.Files[tc.file].Data
			tc.change(t, sys)
			a = restarted(t, a, true)
			a.drift(ctx)
			if files, _ := identityEvents(t, a, g); !slices.Equal(files, []string{tc.file}) {
				t.Fatalf("tamper %v, want [%s]", files, tc.file)
			}
			if got, _ := os.ReadFile(filepath.Join(sys.root, tc.file)); string(got) != string(want) {
				t.Fatalf("%s not restored: %q", tc.file, got)
			}
			a.drift(ctx)
			ticks(t, a, g, 2)
		})
	}
}

// Without a login resource the agent keeps the deny list of the PAM profile: its absence is a change after an
// enforced bundle, and none on a device that never applied one.
func TestIdentityDenyListWithoutLogin(t *testing.T) {
	ctx := context.Background()
	empty := bundle.Bundle{SchemaVersion: 1, BundleVersion: 1, DeviceID: testgw.DeviceID, OrganizationID: testgw.OrgID, IssuedAt: time.Now()}

	g := testgw.New(t)
	a, sys := withLogin(t, g, true)
	g.OfferBundle(testgw.SignedBundleOffer(t, empty))
	a.Cycle(ctx)
	if files, _ := identityEvents(t, a, g); len(files) != 0 || sys.Files[reconcile.DenyList] == nil {
		t.Fatalf("fresh device: tamper %v, deny list %v", files, sys.Files[reconcile.DenyList])
	}

	g = testgw.New(t)
	a, sys = enforcedBeforeUpdate(t, g, empty)
	delete(sys.Files, reconcile.DenyList)
	_ = os.Remove(filepath.Join(sys.root, reconcile.DenyList))
	a = restarted(t, a, true)
	a.drift(ctx)
	if files, _ := identityEvents(t, a, g); !slices.Equal(files, []string{reconcile.DenyList}) || sys.Files[reconcile.DenyList] == nil {
		t.Fatalf("tamper %v, deny list %v", files, sys.Files[reconcile.DenyList])
	}
	ticks(t, a, g, 2)
}

// A report-only bundle wrote nothing: after an update the first enforced bundle writes the files without a report.
func TestIdentityReportOnlyBeforeUpdateNotReported(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	b := loginBundle(t, 1, true)
	b.Mode = bundle.ModeReportOnly
	a, sys := enforcedBeforeUpdate(t, g, b)
	if sys.Files[reconcile.HimmelblauConf] != nil {
		t.Fatal("the report-only bundle wrote himmelblau.conf")
	}
	a = restarted(t, a, true)
	g.OfferBundle(testgw.SignedBundleOffer(t, loginBundle(t, 2, true)))
	a.Cycle(ctx)
	if files, applied := identityEvents(t, a, g); len(files) != 0 || len(applied) != 1 {
		t.Fatalf("tamper %v, login.applied %v", files, applied)
	}
	ticks(t, a, g, 2)
}

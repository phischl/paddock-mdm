package reconcile_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func availableApt(name string) bundle.SoftwarePackage {
	return bundle.SoftwarePackage{Package: name, Intent: bundle.SoftwareAvailable, CatalogEntryID: otherEntry,
		Audience: &bundle.SoftwareAudience{All: true}}
}

// TestInstallOneAPT: a self-service install simulates, installs with --no-remove and reports the installed version,
// without emitting the reconciler's own events.
func TestInstallOneAPT(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	res := s.InstallOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 200001)
	if res.Failed() || res.Version != "7.2-1" || !sys.Packages["code"] {
		t.Fatalf("result %+v, installed %v", res, sys.Packages["code"])
	}
	if !slices.Equal(sys.Calls, []string{"apt-get -s install code", "apt-get install code"}) {
		t.Errorf("calls %v", sys.Calls)
	}
	if !slices.Contains(sys.AptArgs[1], "--no-remove") {
		t.Errorf("real run without --no-remove: %v", sys.AptArgs[1])
	}
	if len(*events) != 0 {
		t.Errorf("events %v", *events)
	}
}

// TestInstallOneSimulationGuard: the guard of Apply — an install that would remove another package is not run.
func TestInstallOneSimulationGuard(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	sys.Packages["vim"] = true
	sys.Conflicts = map[string]string{"code": "vim"}
	res := s.InstallOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 200001)
	if res.Reason != protocol.SoftwareWouldRemoveDependents || !strings.Contains(res.Error, "vim") {
		t.Fatalf("result %+v", res)
	}
	if sys.Packages["code"] || !sys.Packages["vim"] || slices.Contains(sys.Calls, "apt-get install code") {
		t.Errorf("the install ran: %v", sys.Calls)
	}
}

// TestInstallOneProtected: an install that would touch a fully protected package is refused.
func TestInstallOneProtected(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	sys.AptScript = map[string]fakesys.AptReply{"apt-get -s install code": {Output: "Inst code (1.0 x [amd64])\nInst paddock-agent (2.0 x [amd64])\n" +
		"0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.\n"}}
	res := s.InstallOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 0)
	if res.Reason != protocol.SoftwareProtectedAffected || sys.Packages["code"] {
		t.Fatalf("result %+v", res)
	}
}

// TestInstallOneFailures: an unknown name refreshes the source once and fails as no_candidate; the dpkg lock (F7), a
// timeout and an unreachable source (F5, F6) carry their reasons.
func TestInstallOneFailures(t *testing.T) {
	t.Run("no candidate", func(t *testing.T) {
		sys, s, _, _ := softwareFixture(t)
		sys.Unknown = map[string]bool{"code": true}
		p := availableApt("code")
		p.Source = "vendor"
		res := s.InstallOne(context.Background(), bundle.SoftwareSpec{}, p, 0)
		if res.Reason != protocol.SoftwareNoCandidate {
			t.Fatalf("result %+v", res)
		}
		if !slices.Equal(sys.Calls, []string{"apt-get update"}) || !slices.Contains(sys.AptArgs[0], "Dir::Etc::sourcelist=sources.list.d/paddock-vendor.sources") {
			t.Errorf("calls %v %v", sys.Calls, sys.AptArgs)
		}
	})
	t.Run("dpkg locked", func(t *testing.T) {
		sys, s, _, _ := softwareFixture(t)
		sys.FailCmd = "apt-get install code"
		if res := s.InstallOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 0); res.Reason != protocol.SoftwareDpkgLocked {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		sys, s, _, _ := softwareFixture(t)
		sys.AptTimeout = true
		if res := s.InstallOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 0); res.Reason != protocol.SelfServiceTimeout {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("source unreachable", func(t *testing.T) {
		sys, s, _, _ := softwareFixture(t)
		sys.AptScript = map[string]fakesys.AptReply{"apt-get install code": {Output: "E: Failed to fetch https://repo.example.com/code.deb  Temporary failure resolving 'repo.example.com'\n", Exit: 100}}
		if res := s.InstallOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 0); res.Reason != protocol.SoftwareSourceUnreachable {
			t.Fatalf("result %+v", res)
		}
	})
}

// TestRemoveOneAPT: a removal removes exactly the package; one that would take another package along is refused, and
// a package that is gone is done.
func TestRemoveOneAPT(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	sys.Packages["code"] = true
	if res := s.RemoveOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 0); res.Failed() || sys.Packages["code"] {
		t.Fatalf("result %+v", res)
	}
	sys.Calls = nil
	if res := s.RemoveOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 0); res.Failed() || len(sys.Calls) != 0 {
		t.Fatalf("result %+v, calls %v", res, sys.Calls)
	}
	sys.Packages["code"] = true
	sys.AptScript = map[string]fakesys.AptReply{"apt-get -s remove code": {Output: "Remv code [1.0]\nRemv code-extras [1.0]\n" +
		"0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n"}}
	if res := s.RemoveOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 0); res.Reason != protocol.SoftwareWouldRemoveDependents || !sys.Packages["code"] {
		t.Fatalf("result %+v", res)
	}
}

// TestUpdateOneAPT: an update upgrades only an installed package.
func TestUpdateOneAPT(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	if res := s.UpdateOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 0); res.Reason != protocol.SoftwareAptFailed {
		t.Fatalf("update of a missing package: %+v", res)
	}
	sys.Packages["code"], sys.Versions["code"] = true, "7.1-1"
	res := s.UpdateOne(context.Background(), bundle.SoftwareSpec{}, availableApt("code"), 0)
	if res.Failed() || res.Version != "7.2-1" || !slices.Contains(sys.AptArgs[len(sys.AptArgs)-1], "--only-upgrade") {
		t.Fatalf("result %+v, args %v", res, sys.AptArgs)
	}
}

// TestFlatpakOne: system scope through Paddock's system remote; user scope in the asking user's own installation
// through systemd-run with the source's key, never in the system one; a user without a service manager fails as
// flatpak_failed (F8); without the runtime as flatpak_missing.
func TestFlatpakOne(t *testing.T) {
	ctx := context.Background()
	sys, s, _, _ := flatpakFixture(t)
	src := flathubSource(t)
	sp := bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{src}}
	system := flatpakApp(gimp, bundle.SoftwareAvailable, "flathub", "")
	if res := s.InstallOne(ctx, sp, system, 0); res.Reason != protocol.SoftwareFlatpakFailed || !strings.Contains(res.Error, "not in place") {
		t.Fatalf("install without the remote: %+v", res)
	}
	sys.FlatpakSystem.Remotes[flathubRemote] = &fakesys.FlatpakRemote{URL: flathubURL}
	if res := s.InstallOne(ctx, sp, system, 0); res.Failed() || res.Version != "1.0" {
		t.Fatalf("system install: %+v", res)
	}
	if res := s.UpdateOne(ctx, sp, system, 0); res.Failed() || res.Version != "2.0" {
		t.Fatalf("system update: %+v", res)
	}
	if res := s.RemoveOne(ctx, sp, system, 0); res.Failed() || len(sys.FlatpakSystem.Apps) != 0 {
		t.Fatalf("system remove: %+v", res)
	}

	user := flatpakApp(gimp, bundle.SoftwareAvailable, "flathub", bundle.SoftwareScopeUser)
	if res := s.InstallOne(ctx, sp, user, 200001); res.Reason != protocol.SoftwareFlatpakFailed {
		t.Fatalf("user without a service manager: %+v", res)
	}
	sys.FlatpakUsers = map[int]*fakesys.FlatpakInstallation{200001: fakesys.NewFlatpakInstallation()}
	if res := s.InstallOne(ctx, sp, user, 200001); res.Failed() {
		t.Fatalf("user install: %+v", res)
	}
	if _, ok := sys.FlatpakUsers[200001].Apps[gimp]; !ok || len(sys.FlatpakSystem.Apps) != 0 {
		t.Errorf("user %v system %v", sys.FlatpakUsers[200001].Apps, sys.FlatpakSystem.Apps)
	}
	if r := sys.FlatpakUsers[200001].Remotes[flathubRemote]; r == nil || len(r.Key) == 0 {
		t.Errorf("the user's remote has no key: %+v", r)
	}
	if installed, _, err := s.SelfServiceInstalled(ctx, user, 200001); err != nil || !installed {
		t.Errorf("installed %v %v", installed, err)
	}
	if res := s.RemoveOne(ctx, sp, user, 200001); res.Failed() || len(sys.FlatpakUsers[200001].Apps) != 0 {
		t.Fatalf("user remove: %+v", res)
	}

	delete(sys.Packages, "flatpak")
	if res := s.InstallOne(ctx, sp, system, 0); res.Reason != protocol.SoftwareFlatpakMissing {
		t.Fatalf("without the runtime: %+v", res)
	}
}

// TestInstallOnePresent (ADR 0049 decision 3): an install of an application that is already installed — an APT
// package or a system Flatpak application — runs nothing and reports it Present, so self-service never claims it.
func TestInstallOnePresent(t *testing.T) {
	ctx := context.Background()
	sys, s, _, _ := softwareFixture(t)
	sys.Packages["code"] = true
	res := s.InstallOne(ctx, bundle.SoftwareSpec{}, availableApt("code"), 200001)
	if res.Failed() || !res.Present || len(sys.Calls) != 0 {
		t.Fatalf("apt: result %+v, calls %v", res, sys.Calls)
	}

	fsys, fsw, _, _ := flatpakFixture(t)
	fsys.FlatpakSystem = fakesys.NewFlatpakInstallation()
	fsys.FlatpakSystem.Remotes[flathubRemote] = &fakesys.FlatpakRemote{URL: flathubURL}
	fsys.FlatpakSystem.Apps[gimp] = "1.0"
	sp := bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{flathubSource(t)}}
	res = fsw.InstallOne(ctx, sp, flatpakApp(gimp, bundle.SoftwareAvailable, "flathub", ""), 0)
	if res.Failed() || !res.Present || res.Version != "1.0" {
		t.Fatalf("flatpak: result %+v", res)
	}
	if res := fsw.InstallOne(ctx, sp, flatpakApp("org.example.Other", bundle.SoftwareAvailable, "flathub", ""), 0); res.Present {
		t.Errorf("a fresh install is reported present: %+v", res)
	}
}

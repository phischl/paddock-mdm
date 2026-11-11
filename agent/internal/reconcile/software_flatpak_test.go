package reconcile_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const (
	gimp           = "org.gimp.GIMP"
	gimpItem       = "flatpak:org.gimp.GIMP"
	flathubURL     = "https://dl.flathub.org/repo/"
	flathubRemote  = "paddock-flathub"
	remotesRecord  = "/var/lib/paddock/state/flatpak-remotes"
	masksRecord    = "/var/lib/paddock/state/flatpak-masks"
	flatpakKeyFile = "/var/lib/paddock/state/flatpak-import.gpg"
	remoteAdd      = "flatpak remote-add --if-not-exists --system --gpg-import=" + flatpakKeyFile + " paddock-flathub " + flathubURL
)

func flathubSource(t *testing.T) bundle.SoftwareSource {
	t.Helper()
	v := vendorSource(t)
	return bundle.SoftwareSource{Slug: "flathub", Kind: bundle.SoftwareSourceFlatpak, URIs: []string{flathubURL}, Keyring: v.Keyring,
		Fingerprint: v.Fingerprint}
}

func flatpakApp(ref, intent, source, scope string) bundle.SoftwarePackage {
	return bundle.SoftwarePackage{FlatpakRef: ref, Intent: intent, Source: source, Scope: scope, CatalogEntryID: otherEntry}
}

// userApp is a user-scope application for the listed users (A10-11).
func userApp(ref, intent string, users ...string) bundle.SoftwarePackage {
	p := flatpakApp(ref, intent, "", bundle.SoftwareScopeUser)
	if intent == bundle.SoftwareRequired {
		p.Source = "flathub"
	}
	p.Users = &users
	return p
}

func flatpakRuntime() bundle.SoftwarePackage {
	return bundle.SoftwarePackage{Package: "flatpak", Intent: bundle.SoftwareRequired, CatalogEntryID: bundle.SoftwareRuntimeEntryID}
}

// flatpakFixture is a software fixture with the flatpak runtime installed.
func flatpakFixture(t *testing.T) (*fakesys.System, *reconcile.Software, *[]event, *bool) {
	t.Helper()
	sys, s, events, reachable := softwareFixture(t)
	sys.Packages["flatpak"], sys.Versions["flatpak"] = true, "1.14.6-1"
	return sys, s, events, reachable
}

func flatpakCalls(sys *fakesys.System, prefix string) []string {
	return slices.DeleteFunc(slices.Clone(sys.FlatpakCalls), func(c string) bool { return !strings.HasPrefix(c, prefix) })
}

func tampers(events []event) []string {
	var out []string
	for _, e := range events {
		if e.typ == protocol.EventTamperProtectedFileChanged {
			out = append(out, e.data)
		}
	}
	return out
}

// TestFlatpakRemoteAndSystemInstall (plan M13b decision 10): the remote is added with --gpg-import of the decoded,
// checked key from a file that lives only for the call, recorded, and the required system application installed;
// a second pass changes nothing.
func TestFlatpakRemoteAndSystemInstall(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	ctx := context.Background()
	r := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(),
		flatpakApp(gimp, bundle.SoftwareRequired, "flathub", bundle.SoftwareScopeSystem))
	plan, err := s.Plan(ctx, r)
	if err != nil || !slices.Equal(plan, []string{"install flatpak"}) {
		t.Fatalf("plan before the runtime %q, %v", plan, err)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if !sys.Packages["flatpak"] {
		t.Fatal("the runtime was not installed by the APT step")
	}
	remote := sys.FlatpakSystem.Remotes[flathubRemote]
	if remote == nil || remote.URL != flathubURL || string(remote.Key) != string(reconcile.HimmelblauKey()) {
		t.Fatalf("remote %+v", remote)
	}
	if !slices.Contains(sys.FlatpakCalls, remoteAdd) {
		t.Fatalf("calls %q", sys.FlatpakCalls)
	}
	if sys.Files[flatpakKeyFile] != nil {
		t.Fatal("the key file outlived the remote-add")
	}
	if f := sys.Files[remotesRecord]; f == nil || f.Mode != 0o600 || string(f.Data) != "paddock-flathub "+flathubURL+" "+flathubSource(t).Fingerprint+"\n" {
		t.Fatalf("record %+v", f)
	}
	if got := flatpakCalls(sys, "flatpak install"); !slices.Equal(got, []string{"flatpak install -y --noninteractive --system paddock-flathub " + gimp}) {
		t.Fatalf("install calls %q", got)
	}
	if it := status(t, s, gimpItem); it.State != protocol.SoftwareStateInstalled || it.Version != "1.0" || it.CatalogEntryID != otherEntry {
		t.Fatalf("item %+v", it)
	}
	if !slices.ContainsFunc(*events, func(e event) bool {
		return e.typ == protocol.EventSoftwareInstalled && strings.Contains(e.data, `"package":"flatpak:org.gimp.GIMP"`) && strings.Contains(e.data, `"version":"1.0"`)
	}) {
		t.Fatalf("events %v", *events)
	}
	if _, ok := sys.Files["/etc/apt/sources.list.d/paddock-flathub.sources"]; ok {
		t.Fatal("a Flatpak source was written as an APT source")
	}
	sys.FlatpakCalls, *events = nil, nil
	if plan, err := s.Plan(ctx, r); err != nil || len(plan) != 0 {
		t.Fatalf("plan after the pass %q, %v", plan, err)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.OK || len(*events) != 0 {
		t.Fatalf("second apply %+v, events %v", res, *events)
	}
	if slices.ContainsFunc(sys.FlatpakCalls, func(c string) bool { return !strings.Contains(c, " remotes ") && !strings.Contains(c, " list ") }) {
		t.Fatalf("second pass changed something: %q", sys.FlatpakCalls)
	}
}

// TestFlatpakFingerprintMismatch (F12): a key that fails its fingerprint writes nothing — no key file, no remote, no
// record — and fails the remote's applications as fingerprint_mismatch, reported once.
func TestFlatpakFingerprintMismatch(t *testing.T) {
	sys, s, events, _ := flatpakFixture(t)
	ctx := context.Background()
	src := flathubSource(t)
	src.Fingerprint = strings.Repeat("A", 40)
	r := softwareResource(t, []bundle.SoftwareSource{src}, flatpakRuntime(), flatpakApp(gimp, bundle.SoftwareRequired, "flathub", ""))
	if res := s.Apply(ctx, r); res.Status != reconcile.Error {
		t.Fatalf("apply %+v", res)
	}
	if len(sys.FlatpakSystem.Remotes) != 0 || len(flatpakCalls(sys, "flatpak remote-add")) != 0 || len(flatpakCalls(sys, "flatpak install")) != 0 {
		t.Fatalf("calls %q", sys.FlatpakCalls)
	}
	for _, f := range []string{flatpakKeyFile, remotesRecord} {
		if sys.Files[f] != nil {
			t.Fatalf("%s written", f)
		}
	}
	if it := status(t, s, gimpItem); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareFingerprintMismatch {
		t.Fatalf("item %+v", it)
	}
	want := event{protocol.EventSoftwareApplyFailed, ""}
	var failed []event
	for _, e := range *events {
		if e.typ == want.typ {
			failed = append(failed, e)
		}
	}
	if len(failed) != 1 || !strings.Contains(failed[0].data, `"source":"flathub","stage":"keyring","reason":"fingerprint_mismatch"`) {
		t.Fatalf("events %v", *events)
	}
	*events = nil
	s.Apply(ctx, r)
	if len(*events) != 0 {
		t.Fatalf("unchanged failure reported again: %v", *events)
	}
}

// TestFlatpakRemoteTamper (ADR 0049 decision 4): a recorded remote with a changed URL, disabled or without GPG
// verification, and a missing one, is removed and added again with the tamper event; a paddock-* remote Paddock never
// added is removed with the event; the device's own remotes stay.
func TestFlatpakRemoteTamper(t *testing.T) {
	for name, change := range map[string]func(*fakesys.FlatpakInstallation){
		"url":      func(i *fakesys.FlatpakInstallation) { i.Remotes[flathubRemote].URL = "https://evil.example.org/repo/" },
		"disabled": func(i *fakesys.FlatpakInstallation) { i.Remotes[flathubRemote].Disabled = true },
		"no-gpg":   func(i *fakesys.FlatpakInstallation) { i.Remotes[flathubRemote].NoGPGVerify = true },
		"missing":  func(i *fakesys.FlatpakInstallation) { delete(i.Remotes, flathubRemote) },
	} {
		t.Run(name, func(t *testing.T) {
			sys, s, events, _ := flatpakFixture(t)
			ctx := context.Background()
			r := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(), flatpakApp(gimp, bundle.SoftwareRequired, "flathub", ""))
			s.Apply(ctx, r)
			change(sys.FlatpakSystem)
			sys.FlatpakSystem.Remotes["flathub"] = &fakesys.FlatpakRemote{URL: flathubURL}
			*events, sys.FlatpakCalls = nil, nil
			if plan, _ := s.Plan(ctx, r); !slices.Equal(plan, []string{"remote flathub"}) {
				t.Fatalf("plan %q", plan)
			}
			if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
				t.Fatalf("apply %+v", res)
			}
			if got := tampers(*events); !slices.Equal(got, []string{`{"file":"flatpak:remote/paddock-flathub"}`}) {
				t.Fatalf("tamper events %q", got)
			}
			remote := sys.FlatpakSystem.Remotes[flathubRemote]
			if remote == nil || remote.URL != flathubURL || remote.Disabled || remote.NoGPGVerify || string(remote.Key) != string(reconcile.HimmelblauKey()) {
				t.Fatalf("remote %+v", remote)
			}
			if name != "missing" && !slices.Contains(sys.FlatpakCalls, "flatpak remote-delete --system --force paddock-flathub") {
				t.Fatalf("calls %q", sys.FlatpakCalls)
			}
			if sys.FlatpakSystem.Remotes["flathub"] == nil {
				t.Fatal("the device's own remote was touched")
			}
			if _, ok := sys.FlatpakSystem.Apps[gimp]; !ok {
				t.Fatal("restoring the remote removed its application")
			}
		})
	}

	sys, s, events, _ := flatpakFixture(t)
	ctx := context.Background()
	r := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(), flatpakApp(gimp, bundle.SoftwareRequired, "flathub", ""))
	s.Apply(ctx, r)
	sys.FlatpakSystem.Remotes["paddock-rogue"] = &fakesys.FlatpakRemote{URL: "https://evil.example.org/repo/"}
	sys.FlatpakSystem.Remotes["fedora"] = &fakesys.FlatpakRemote{URL: "https://registry.fedoraproject.org/"}
	*events = nil
	if plan, _ := s.Plan(ctx, r); !slices.Equal(plan, []string{"remove-remote paddock-rogue"}) {
		t.Fatalf("plan %q", plan)
	}
	s.Apply(ctx, r)
	if sys.FlatpakSystem.Remotes["paddock-rogue"] != nil || sys.FlatpakSystem.Remotes["fedora"] == nil || sys.FlatpakSystem.Remotes[flathubRemote] == nil {
		t.Fatalf("remotes %v", sys.FlatpakSystem.Remotes)
	}
	if got := tampers(*events); !slices.Equal(got, []string{`{"file":"flatpak:remote/paddock-rogue"}`}) {
		t.Fatalf("tamper events %q", got)
	}
}

// TestFlatpakRemoteRemovedWithTheSource: a source the spec no longer names is removed without a tamper event; a bundle
// without the section removes only the recorded remotes, never one it cannot prove it added.
func TestFlatpakRemoteRemovedWithTheSource(t *testing.T) {
	sys, s, events, _ := flatpakFixture(t)
	ctx := context.Background()
	s.Apply(ctx, softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(), flatpakApp(gimp, bundle.SoftwareRequired, "flathub", "")))
	*events = nil
	s.Apply(ctx, softwareResource(t, nil, flatpakRuntime()))
	if sys.FlatpakSystem.Remotes[flathubRemote] != nil || len(tampers(*events)) != 0 || sys.Files[remotesRecord] != nil {
		t.Fatalf("remotes %v, events %v", sys.FlatpakSystem.Remotes, *events)
	}
	if _, ok := sys.FlatpakSystem.Apps[gimp]; !ok {
		t.Fatal("removing the remote removed its application")
	}

	sys, s, _, _ = flatpakFixture(t)
	s.Apply(ctx, softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime()))
	sys.FlatpakSystem.Remotes["paddock-other"] = &fakesys.FlatpakRemote{URL: "https://example.org/repo/"}
	if !s.Residue() {
		t.Fatal("no residue with a recorded remote")
	}
	empty, err := bundle.SoftwareResource(bundle.SoftwareSpec{})
	if err != nil {
		t.Fatal(err)
	}
	s.Apply(ctx, empty)
	if sys.FlatpakSystem.Remotes[flathubRemote] != nil || sys.FlatpakSystem.Remotes["paddock-other"] == nil {
		t.Fatalf("remotes %v", sys.FlatpakSystem.Remotes)
	}
	if s.Residue() {
		t.Fatal("residue after the empty section")
	}
}

// TestFlatpakForbidUninstallHold (plan M13b decision 10, A10-7): forbid uninstalls and masks, uninstall uninstalls,
// hold masks; none names a source or brings the runtime; a mask Paddock set is removed when its intent ends, never a
// mask of the device's own. No APT pin or package operation is planned for an application.
func TestFlatpakForbidUninstallHold(t *testing.T) {
	sys, s, events, _ := flatpakFixture(t)
	ctx := context.Background()
	sys.FlatpakSystem = fakesys.NewFlatpakInstallation()
	sys.FlatpakSystem.Apps = map[string]string{gimp: "2.10", "org.videolan.VLC": "3.0", "org.mozilla.firefox": "130"}
	sys.FlatpakSystem.Masks["org.example.Own"] = true
	r := softwareResource(t, nil,
		bundle.SoftwarePackage{FlatpakRef: gimp, Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry},
		bundle.SoftwarePackage{FlatpakRef: "org.mozilla.firefox", Intent: bundle.SoftwareHold, CatalogEntryID: nanoEntry},
		bundle.SoftwarePackage{FlatpakRef: "org.videolan.VLC", Intent: bundle.SoftwareUninstall, CatalogEntryID: "2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a"})
	plan, err := s.Plan(ctx, r)
	want := []string{"mask org.gimp.GIMP", "mask org.mozilla.firefox", "flatpak-remove org.gimp.GIMP", "flatpak-remove org.videolan.VLC"}
	if err != nil || !slices.Equal(plan, want) {
		t.Fatalf("plan %q, %v", plan, err)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if got := flatpakCalls(sys, "flatpak uninstall"); !slices.Equal(got, []string{
		"flatpak uninstall -y --noninteractive --system --app org.gimp.GIMP", "flatpak uninstall -y --noninteractive --system --app org.videolan.VLC"}) {
		t.Fatalf("uninstall calls %q", got)
	}
	if !sys.FlatpakSystem.Masks[gimp] || !sys.FlatpakSystem.Masks["org.mozilla.firefox"] || sys.FlatpakSystem.Masks["org.videolan.VLC"] {
		t.Fatalf("masks %v", sys.FlatpakSystem.Masks)
	}
	if it := status(t, s, "flatpak:org.mozilla.firefox"); it.State != protocol.SoftwareStateHeld || it.Version != "130" {
		t.Fatalf("hold item %+v", it)
	}
	for _, item := range []string{gimpItem, "flatpak:org.videolan.VLC"} {
		if it := status(t, s, item); it.State != protocol.SoftwareStateAbsent {
			t.Fatalf("%s item %+v", item, it)
		}
	}
	if n := strings.Count(strings.Join(typesOf(*events), " "), protocol.EventSoftwareRemoved); n != 2 {
		t.Fatalf("events %v", *events)
	}
	if sys.Files[reconcile.SoftwareForbidFile] != nil || len(aptCalls(sys)) != 0 || len(sys.FlatpakSystem.Remotes) != 0 {
		t.Fatalf("APT touched: forbid file %v, apt calls %q, remotes %v", sys.Files[reconcile.SoftwareForbidFile], aptCalls(sys), sys.FlatpakSystem.Remotes)
	}

	s.Apply(ctx, softwareResource(t, nil, bundle.SoftwarePackage{FlatpakRef: "org.mozilla.firefox", Intent: bundle.SoftwareHold, CatalogEntryID: nanoEntry}))
	if sys.FlatpakSystem.Masks[gimp] || !sys.FlatpakSystem.Masks["org.mozilla.firefox"] || !sys.FlatpakSystem.Masks["org.example.Own"] {
		t.Fatalf("masks after the forbid ended %v", sys.FlatpakSystem.Masks)
	}
	if f := sys.Files[masksRecord]; f == nil || string(f.Data) != "org.mozilla.firefox\n" {
		t.Fatalf("mask record %+v", f)
	}
}

// TestFlatpakDeviceMaskSurvives (PDK-800 Review 1): a mask the device set before Paddock forbade the application is
// not adopted into the record, so it stays when the forbid ends.
func TestFlatpakDeviceMaskSurvives(t *testing.T) {
	sys, s, _, _ := flatpakFixture(t)
	ctx := context.Background()
	sys.FlatpakSystem = fakesys.NewFlatpakInstallation()
	sys.FlatpakSystem.Masks[gimp] = true
	s.Apply(ctx, softwareResource(t, nil, bundle.SoftwarePackage{FlatpakRef: gimp, Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry}))
	if got := flatpakCalls(sys, "flatpak mask --system "+gimp); len(got) != 0 {
		t.Fatalf("mask calls %q", got)
	}
	if f := sys.Files[masksRecord]; f != nil {
		t.Fatalf("mask record %q", f.Data)
	}
	s.Apply(ctx, softwareResource(t, nil))
	if !sys.FlatpakSystem.Masks[gimp] || len(flatpakCalls(sys, "flatpak mask --remove")) != 0 || sys.Files[masksRecord] != nil {
		t.Fatalf("masks %v, calls %q", sys.FlatpakSystem.Masks, flatpakCalls(sys, "flatpak mask --remove"))
	}
}

// TestFlatpakRemovalOffline (ADR 0042 H2): outside the 15-minute window nothing is uninstalled.
func TestFlatpakRemovalOffline(t *testing.T) {
	sys, s, _, reachable := flatpakFixture(t)
	ctx := context.Background()
	*reachable = false
	sys.FlatpakSystem = fakesys.NewFlatpakInstallation()
	sys.FlatpakSystem.Apps[gimp] = "2.10"
	s.Apply(ctx, softwareResource(t, nil, bundle.SoftwarePackage{FlatpakRef: gimp, Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry}))
	if _, ok := sys.FlatpakSystem.Apps[gimp]; !ok || len(flatpakCalls(sys, "flatpak uninstall")) != 0 {
		t.Fatalf("removed offline: %q", sys.FlatpakCalls)
	}
	if it := status(t, s, gimpItem); it.State != protocol.SoftwareStatePending || it.Reason != protocol.SoftwareDeferredOffline {
		t.Fatalf("item %+v", it)
	}
	if !sys.FlatpakSystem.Masks[gimp] {
		t.Fatal("the mask waited for the server: it removes nothing")
	}
}

// TestFlatpakMissing (F13, A10-7): without the runtime every required application fails as flatpak_missing; forbid,
// uninstall and hold need nothing and run no flatpak command.
func TestFlatpakMissing(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	ctx := context.Background()
	r := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)},
		flatpakApp(gimp, bundle.SoftwareRequired, "flathub", ""),
		flatpakApp("org.example.User", bundle.SoftwareRequired, "flathub", bundle.SoftwareScopeUser),
		bundle.SoftwarePackage{FlatpakRef: "org.videolan.VLC", Intent: bundle.SoftwareForbid, CatalogEntryID: nanoEntry})
	if plan, _ := s.Plan(ctx, r); len(plan) != 0 {
		t.Fatalf("plan %q", plan)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Error || !strings.Contains(res.Message, "flatpak_missing") {
		t.Fatalf("apply %+v", res)
	}
	for _, item := range []string{gimpItem, "flatpak:org.example.User"} {
		if it := status(t, s, item); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareFlatpakMissing {
			t.Fatalf("%s item %+v", item, it)
		}
	}
	if it := status(t, s, "flatpak:org.videolan.VLC"); it.State != protocol.SoftwareStateAbsent {
		t.Fatalf("forbid item %+v", it)
	}
	if len(sys.FlatpakCalls) != 0 || len(aptCalls(sys)) != 0 {
		t.Fatalf("flatpak calls %q, apt calls %q", sys.FlatpakCalls, aptCalls(sys))
	}
}

// TestFlatpakUserScope (decision Q14, A10-11): a user-scope application is installed through systemd-run in the
// service manager of every listed user with a session, the remote added there first with the key on stdin; a greeter
// is no user, and a signed-in user the list does not name gets nothing. A listed user without a reachable manager
// fails the item for the pass, never the system installation.
func TestFlatpakUserScope(t *testing.T) {
	sys, s, events, _ := flatpakFixture(t)
	ctx := context.Background()
	sys.Sessions = []fakesys.Session{
		{ID: "2", UID: 70001, User: "alice", Class: "user", Type: "wayland", State: "active"},
		{ID: "3", UID: 70002, User: "bob", Class: "user", Type: "tty", State: "online"},
		{ID: "5", UID: 70004, User: "dave", Class: "user", Type: "wayland", State: "active"},
		{ID: "c1", UID: 120, User: "gdm", Class: "greeter", Type: "wayland", State: "active"},
	}
	sys.FlatpakUsers = map[int]*fakesys.FlatpakInstallation{70001: fakesys.NewFlatpakInstallation(), 70002: fakesys.NewFlatpakInstallation(),
		70004: fakesys.NewFlatpakInstallation(), 120: fakesys.NewFlatpakInstallation()}
	r := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(),
		userApp(gimp, bundle.SoftwareRequired, "alice", "bob", "carol"))
	if plan, _ := s.Plan(ctx, r); !slices.Equal(plan, []string{"remote flathub", "flatpak-install org.gimp.GIMP uid 70001", "flatpak-install org.gimp.GIMP uid 70002"}) {
		t.Fatalf("plan %q", plan)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	prefix := "systemd-run --machine=70001@.host --user --wait --pipe --quiet --collect --property=RuntimeMaxSec=900 --setenv=LC_ALL=C flatpak "
	for _, want := range []string{prefix + "remote-add --user --if-not-exists --gpg-import=/run/paddock/flatpak-keys/70001-1.gpg paddock-flathub " + flathubURL,
		prefix + "install -y --noninteractive --user paddock-flathub " + gimp} {
		if !slices.Contains(sys.FlatpakCalls, want) {
			t.Fatalf("no %q in %q", want, sys.FlatpakCalls)
		}
	}
	if installs := flatpakCalls(sys, "systemd-run"); len(slices.DeleteFunc(installs, func(c string) bool { return !strings.Contains(c, " install ") })) != 2 {
		t.Fatalf("one install per user: %q", sys.FlatpakCalls)
	}
	for _, uid := range []int{70001, 70002} {
		u := sys.FlatpakUsers[uid]
		if _, ok := u.Apps[gimp]; !ok || u.Remotes[flathubRemote] == nil || string(u.Remotes[flathubRemote].Key) != string(reconcile.HimmelblauKey()) {
			t.Fatalf("uid %d: %+v", uid, u)
		}
	}
	for _, path := range []string{"/run/paddock/flatpak-keys/70001-1.gpg", "/run/paddock/flatpak-keys/70002-2.gpg"} {
		if !slices.Contains(sys.Calls, "write "+path) || !slices.Contains(sys.Calls, "remove "+path) || sys.Files[path] != nil {
			t.Fatalf("key file %s not written for the call alone: %q", path, sys.Calls)
		}
	}
	if len(sys.FlatpakUsers[120].Apps) != 0 || len(sys.FlatpakUsers[70004].Apps) != 0 || len(sys.FlatpakSystem.Apps) != 0 {
		t.Fatalf("installed for the greeter, a user not listed or system wide: %v %v %v", sys.FlatpakUsers[120].Apps,
			sys.FlatpakUsers[70004].Apps, sys.FlatpakSystem.Apps)
	}
	if got := flatpakCalls(sys, "systemd-run --machine=70004@.host"); len(got) != 0 {
		t.Fatalf("acted for a user not listed: %q", got)
	}
	if it := status(t, s, gimpItem); it.State != protocol.SoftwareStateInstalled {
		t.Fatalf("item %+v", it)
	}
	if n := strings.Count(strings.Join(typesOf(*events), " "), protocol.EventSoftwareInstalled); n != 2 {
		t.Fatalf("events %v", *events)
	}

	sys.Sessions = append(sys.Sessions, fakesys.Session{ID: "4", UID: 70003, User: "carol", Class: "user", Type: "wayland", State: "active"})
	if res := s.Apply(ctx, r); res.Status != reconcile.Error {
		t.Fatalf("apply with an unreachable manager %+v", res)
	}
	if it := status(t, s, gimpItem); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareFlatpakFailed {
		t.Fatalf("item %+v", it)
	}
	if len(sys.FlatpakSystem.Apps) != 0 {
		t.Fatal("escalated to the system installation")
	}
}

// TestFlatpakUserScopeWithoutSession (decision Q14): without a user session the application stays pending and is not
// installed system wide; NewUserSession tells the agent when a user logs in.
func TestFlatpakUserScopeWithoutSession(t *testing.T) {
	sys, s, _, _ := flatpakFixture(t)
	ctx := context.Background()
	r := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(), userApp(gimp, bundle.SoftwareRequired, "alice"))
	if s.NewUserSession(ctx) {
		t.Fatal("a session before any pass")
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if it := status(t, s, gimpItem); it.State != protocol.SoftwareStatePending || it.Reason != protocol.SoftwareNotYetApplied {
		t.Fatalf("item %+v", it)
	}
	if len(sys.FlatpakSystem.Apps) != 0 || len(flatpakCalls(sys, "systemd-run")) != 0 {
		t.Fatalf("calls %q", sys.FlatpakCalls)
	}
	if s.NewUserSession(ctx) {
		t.Fatal("no session yet")
	}
	sys.Sessions = []fakesys.Session{{ID: "2", UID: 70001, User: "alice", Class: "user", Type: "wayland", State: "active"}}
	sys.FlatpakUsers = map[int]*fakesys.FlatpakInstallation{70001: fakesys.NewFlatpakInstallation()}
	if !s.NewUserSession(ctx) || s.NewUserSession(ctx) {
		t.Fatal("the login is reported once")
	}
	s.Apply(ctx, r)
	if _, ok := sys.FlatpakUsers[70001].Apps[gimp]; !ok {
		t.Fatal("not installed at the session")
	}
}

// TestFlatpakUserScopeUnreadableInstallation (PDK-996): a drift pass applies only what the plan lists, so a listed
// user with a session whose installation cannot be read is planned with the application's intent: Apply then reports
// the failure instead of the item staying pending/not_yet_applied with the cause hidden.
func TestFlatpakUserScopeUnreadableInstallation(t *testing.T) {
	sys, s, _, _ := flatpakFixture(t)
	ctx := context.Background()
	r := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(), userApp(gimp, bundle.SoftwareRequired, "alice"))
	s.Apply(ctx, r)
	if it := status(t, s, gimpItem); it.State != protocol.SoftwareStatePending || it.Reason != protocol.SoftwareNotYetApplied {
		t.Fatalf("item without a session %+v", it)
	}

	sys.Sessions = []fakesys.Session{{ID: "2", UID: 70001, User: "alice", Class: "user", Type: "wayland", State: "active"}}
	if plan, _ := s.Plan(ctx, r); !slices.Equal(plan, []string{"flatpak-install org.gimp.GIMP uid 70001"}) {
		t.Fatalf("plan %q", plan)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Error {
		t.Fatalf("apply %+v", res)
	}
	it := status(t, s, gimpItem)
	if it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareFlatpakFailed || !strings.Contains(it.Error, "uid 70001") {
		t.Fatalf("item %+v", it)
	}
	if len(sys.FlatpakSystem.Apps) != 0 {
		t.Fatal("escalated to the system installation")
	}

	forbid := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, userApp(gimp, bundle.SoftwareForbid, "alice"))
	if plan, _ := s.Plan(ctx, forbid); !slices.Equal(plan, []string{"flatpak-remove org.gimp.GIMP uid 70001"}) {
		t.Fatalf("removal plan %q", plan)
	}
}

// TestFlatpakUserScopeRemovalListedOnly (A10-11): a user-scope forbid or uninstall removes the application from the
// installations of the listed users with a session only (the session's user name matched case-insensitively, local
// accounts never); another signed-in user's installation and the system installation stay, and nothing is masked.
func TestFlatpakUserScopeRemovalListedOnly(t *testing.T) {
	sys, s, events, _ := flatpakFixture(t)
	ctx := context.Background()
	sys.Sessions = []fakesys.Session{
		{ID: "2", UID: 70001, User: "Alice", Class: "user", Type: "wayland", State: "active"},
		{ID: "3", UID: 70002, User: "bob", Class: "user", Type: "wayland", State: "active"},
		{ID: "4", UID: 1000, User: "eve", Class: "user", Type: "tty", State: "active"},
	}
	sys.FlatpakSystem = fakesys.NewFlatpakInstallation()
	sys.FlatpakSystem.Apps[gimp] = "2.10"
	sys.FlatpakUsers = map[int]*fakesys.FlatpakInstallation{}
	for _, uid := range []int{70001, 70002, 1000} {
		sys.FlatpakUsers[uid] = fakesys.NewFlatpakInstallation()
		sys.FlatpakUsers[uid].Apps[gimp], sys.FlatpakUsers[uid].Apps["org.videolan.VLC"] = "2.10", "3.0"
	}
	r := softwareResource(t, nil, userApp(gimp, bundle.SoftwareForbid, "alice", "eve"),
		userApp("org.videolan.VLC", bundle.SoftwareUninstall, "alice"))
	if plan, _ := s.Plan(ctx, r); !slices.Equal(plan, []string{"flatpak-remove org.gimp.GIMP uid 70001", "flatpak-remove org.videolan.VLC uid 70001"}) {
		t.Fatalf("plan %q", plan)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if a := sys.FlatpakUsers[70001].Apps; len(a) != 0 {
		t.Fatalf("listed user keeps %v", a)
	}
	for _, uid := range []int{70002, 1000} {
		if a := sys.FlatpakUsers[uid].Apps; len(a) != 2 {
			t.Fatalf("uid %d lost %v", uid, a)
		}
	}
	if _, ok := sys.FlatpakSystem.Apps[gimp]; !ok || len(sys.FlatpakSystem.Masks) != 0 || len(flatpakCalls(sys, "flatpak uninstall")) != 0 {
		t.Fatalf("system installation touched: %v %v %q", sys.FlatpakSystem.Apps, sys.FlatpakSystem.Masks, sys.FlatpakCalls)
	}
	if n := strings.Count(strings.Join(typesOf(*events), " "), protocol.EventSoftwareRemoved); n != 2 {
		t.Fatalf("events %v", *events)
	}
}

// TestFlatpakUserScopeWithoutList (A10-11): a user-scope entry without a user list acts in system scope, never for
// every user. A required one is installed system wide; a forbid uninstalls and masks it system wide and an uninstall
// uninstalls it system wide, while the users' own installations of the application stay untouched (the conservative
// choice: the agent acts in a user's installation only for listed users).
func TestFlatpakUserScopeWithoutList(t *testing.T) {
	sys, s, events, _ := flatpakFixture(t)
	ctx := context.Background()
	sys.Sessions = []fakesys.Session{{ID: "2", UID: 70001, User: "alice", Class: "user", Type: "wayland", State: "active"}}
	sys.FlatpakSystem = fakesys.NewFlatpakInstallation()
	sys.FlatpakSystem.Apps = map[string]string{gimp: "2.10", "org.videolan.VLC": "3.0"}
	sys.FlatpakUsers = map[int]*fakesys.FlatpakInstallation{70001: fakesys.NewFlatpakInstallation()}
	sys.FlatpakUsers[70001].Apps = map[string]string{gimp: "2.10", "org.videolan.VLC": "3.0"}
	r := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(),
		flatpakApp("org.example.Editor", bundle.SoftwareRequired, "flathub", bundle.SoftwareScopeUser),
		flatpakApp(gimp, bundle.SoftwareForbid, "", bundle.SoftwareScopeUser),
		flatpakApp("org.videolan.VLC", bundle.SoftwareUninstall, "", bundle.SoftwareScopeUser))
	want := []string{"remote flathub", "mask org.gimp.GIMP", "flatpak-install org.example.Editor", "flatpak-remove org.gimp.GIMP",
		"flatpak-remove org.videolan.VLC"}
	if plan, _ := s.Plan(ctx, r); !slices.Equal(plan, want) {
		t.Fatalf("plan %q", plan)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if got := flatpakCalls(sys, "systemd-run"); len(got) != 0 {
		t.Fatalf("acted in a user's installation: %q", got)
	}
	if _, ok := sys.FlatpakSystem.Apps["org.example.Editor"]; !ok || len(sys.FlatpakSystem.Apps) != 1 || !sys.FlatpakSystem.Masks[gimp] {
		t.Fatalf("system installation %v, masks %v", sys.FlatpakSystem.Apps, sys.FlatpakSystem.Masks)
	}
	if a := sys.FlatpakUsers[70001].Apps; len(a) != 2 {
		t.Fatalf("user installation changed: %v", a)
	}
	if it := status(t, s, "flatpak:org.example.Editor"); it.State != protocol.SoftwareStateInstalled {
		t.Fatalf("required item %+v", it)
	}
	for _, item := range []string{gimpItem, "flatpak:org.videolan.VLC"} {
		if it := status(t, s, item); it.State != protocol.SoftwareStateAbsent {
			t.Fatalf("%s item %+v", item, it)
		}
	}
	if s.NewUserSession(ctx) {
		t.Fatal("a session matters only for listed users")
	}
	if n := strings.Count(strings.Join(typesOf(*events), " "), protocol.EventSoftwareRemoved); n != 2 {
		t.Fatalf("events %v", *events)
	}
}

// TestFlatpakInstallFailureWaits: a failed installation is reported once and retried after softwareRetryPasses passes
// of the same spec, like an APT installation.
func TestFlatpakInstallFailureWaits(t *testing.T) {
	sys, s, events, _ := flatpakFixture(t)
	ctx := context.Background()
	install := "flatpak install -y --noninteractive --system paddock-flathub " + gimp
	sys.FlatpakScript = map[string]fakesys.OutputReply{install: {Data: []byte("error: Unable to load summary from remote\n"), Exit: 1}}
	r := softwareResource(t, []bundle.SoftwareSource{flathubSource(t)}, flatpakRuntime(), flatpakApp(gimp, bundle.SoftwareRequired, "flathub", ""))
	s.Apply(ctx, r)
	if it := status(t, s, gimpItem); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareFlatpakFailed ||
		!strings.Contains(it.Error, "Unable to load summary") {
		t.Fatalf("item %+v", it)
	}
	for range 11 {
		s.Apply(ctx, r)
	}
	if n := len(flatpakCalls(sys, install)); n != 1 {
		t.Fatalf("%d installs while waiting", n)
	}
	if n := strings.Count(strings.Join(typesOf(*events), " "), protocol.EventSoftwareApplyFailed); n != 1 {
		t.Fatalf("events %v", *events)
	}
	delete(sys.FlatpakScript, install)
	s.Apply(ctx, r)
	if it := status(t, s, gimpItem); it.State != protocol.SoftwareStateInstalled {
		t.Fatalf("item after the wait %+v", it)
	}
}

// TestSoftwareAvailableStatus (plan M13b decision 7): an available package is installed or absent, never pending; the
// reconciler neither installs nor removes it.
func TestSoftwareAvailableStatus(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	ctx := context.Background()
	sys.Packages["nano"], sys.Versions["nano"] = true, "7.2-1"
	r := softwareResource(t, nil,
		bundle.SoftwarePackage{Package: "nano", Intent: bundle.SoftwareAvailable, CatalogEntryID: nanoEntry, Audience: &bundle.SoftwareAudience{All: true}},
		bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareAvailable, CatalogEntryID: otherEntry, Audience: &bundle.SoftwareAudience{All: true}})
	if plan, _ := s.Plan(ctx, r); len(plan) != 0 {
		t.Fatalf("plan %q", plan)
	}
	s.Apply(ctx, r)
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateInstalled {
		t.Fatalf("nano %+v", it)
	}
	if it := status(t, s, "vim"); it.State != protocol.SoftwareStateAbsent {
		t.Fatalf("vim %+v", it)
	}
	if len(aptCalls(sys)) != 0 {
		t.Fatalf("apt calls %q", aptCalls(sys))
	}
}

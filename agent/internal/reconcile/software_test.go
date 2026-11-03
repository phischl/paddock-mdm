package reconcile_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const (
	nanoEntry  = "0b9e2c4e-4b7a-4f43-9a51-1c2d3e4f5a6b"
	otherEntry = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
	vendorList = "/etc/apt/sources.list.d/paddock-vendor.sources"
	vendorKey  = "/etc/apt/keyrings/paddock-vendor.gpg"
	record     = "/var/lib/paddock/state/software-installed"
)

// softwareFixture is a device whose server is reachable unless *reachable is set to false.
func softwareFixture(t *testing.T) (*fakesys.System, *reconcile.Software, *[]event, *bool) {
	t.Helper()
	sys := fakesys.New()
	sys.AptVersion = "7.2-1"
	reachable := true
	var events []event
	s := &reconcile.Software{Sys: sys, ServerReachable: func() bool { return reachable }, Events: &reconcile.Events{Emit: func(typ string, data any) {
		b, _ := json.Marshal(data)
		events = append(events, event{typ, string(b)})
	}}}
	return sys, s, &events, &reachable
}

func vendorSource(t *testing.T) bundle.SoftwareSource {
	t.Helper()
	fp, err := openpgpkey.FingerprintBinary(reconcile.HimmelblauKey())
	if err != nil {
		t.Fatal(err)
	}
	return bundle.SoftwareSource{Slug: "vendor", URIs: []string{"https://repo.example.com/apt", "https://mirror.example.com/apt"},
		Suites: []string{"stable"}, Components: []string{"main", "extra"}, Keyring: b64(reconcile.HimmelblauKey()), Fingerprint: fp}
}

func b64(b []byte) string {
	data, _ := json.Marshal(b) // []byte encodes as standard base64
	return strings.Trim(string(data), `"`)
}

func softwareResource(t *testing.T, sources []bundle.SoftwareSource, pkgs ...bundle.SoftwarePackage) bundle.Resource {
	t.Helper()
	s := bundle.SoftwareSpec{Sources: sources, Packages: pkgs}
	if err := bundle.ValidateSoftware(s); err != nil {
		t.Fatal(err)
	}
	r, err := bundle.SoftwareResource(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func required(pkg, source string) bundle.SoftwarePackage {
	return bundle.SoftwarePackage{Package: pkg, Intent: bundle.SoftwareRequired, Source: source, CatalogEntryID: nanoEntry}
}

func status(t *testing.T, s *reconcile.Software, pkg string) protocol.SoftwareItem {
	t.Helper()
	st := s.Status()
	if st == nil || st.Items == nil {
		t.Fatal("no software status")
	}
	for _, it := range *st.Items {
		if it.Package == pkg {
			return it
		}
	}
	t.Fatalf("no status of %s in %+v", pkg, *st.Items)
	return protocol.SoftwareItem{}
}

func typesOf(events []event) []string {
	var out []string
	for _, e := range events {
		out = append(out, e.typ)
	}
	return out
}

func aptCalls(sys *fakesys.System) []string {
	return slices.DeleteFunc(slices.Clone(sys.Calls), func(c string) bool { return !strings.HasPrefix(c, "apt-") && !strings.HasPrefix(c, "dpkg") })
}

func TestSoftwareFreshInstall(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	ctx := context.Background()
	r := softwareResource(t, []bundle.SoftwareSource{vendorSource(t)}, required("nano", "vendor"))
	if s.Status() != nil {
		t.Fatal("status before the first Apply")
	}
	plan, err := s.Plan(ctx, r)
	if err != nil || !slices.Equal(plan, []string{"source vendor", "keyring vendor", "install nano"}) {
		t.Fatalf("plan %q, %v", plan, err)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	want := "# Managed by Paddock. Do not edit: local changes are reverted.\nTypes: deb\n" +
		"URIs: https://repo.example.com/apt https://mirror.example.com/apt\nSuites: stable\nComponents: main extra\n" +
		"Signed-By: /etc/apt/keyrings/paddock-vendor.gpg\n"
	if got := fileContent(t, sys, vendorList); got != want {
		t.Fatalf("source file:\n%s\nwant:\n%s", got, want)
	}
	if f := sys.Files[vendorKey]; f == nil || string(f.Data) != string(reconcile.HimmelblauKey()) || f.Mode != 0o644 || f.UID != 0 || f.GID != 0 {
		t.Fatalf("keyring %+v", f)
	}
	if f := sys.Files[vendorList]; f.Mode != 0o644 || f.UID != 0 {
		t.Fatalf("source file mode %v uid %d", f.Mode, f.UID)
	}
	if got := aptCalls(sys); !slices.Equal(got, []string{"apt-get update", "apt-get -s install nano", "apt-get install nano"}) {
		t.Fatalf("apt calls %q", got)
	}
	wantArgs := [][]string{
		{"update", "-q", "-o", "Dir::Etc::sourcelist=sources.list.d/paddock-vendor.sources", "-o", "Dir::Etc::sourceparts=-",
			"-o", "APT::Get::List-Cleanup=0", "-o", "DPkg::Lock::Timeout=60"},
		{"-s", "install", "-y", "-q", "-o", "DPkg::Lock::Timeout=60", "-o", "Dpkg::Options::=--force-confdef", "-o",
			"Dpkg::Options::=--force-confold", "--allow-downgrades", "nano"},
		{"install", "-y", "-q", "-o", "DPkg::Lock::Timeout=60", "-o", "Dpkg::Options::=--force-confdef", "-o",
			"Dpkg::Options::=--force-confold", "--allow-downgrades", "nano"},
	}
	if !slices.EqualFunc(sys.AptArgs, wantArgs, slices.Equal) {
		t.Fatalf("apt arguments %q", sys.AptArgs)
	}
	if f := sys.Files[record]; f == nil || string(f.Data) != "nano\n" || f.Mode != 0o600 {
		t.Fatalf("record %+v", f)
	}
	if len(*events) != 1 || (*events)[0].typ != protocol.EventSoftwareInstalled ||
		(*events)[0].data != `{"package":"nano","version":"7.2-1","intent":"required","catalog_entry_id":"`+nanoEntry+`","reason":"first_install"}` {
		t.Fatalf("events %+v", *events)
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateInstalled || it.Version != "7.2-1" || it.CatalogEntryID != nanoEntry {
		t.Fatalf("status %+v", it)
	}
	digest := s.Status().Digest
	*events = nil
	sys.TakeCalls()
	sys.AptArgs = nil
	if plan, err := s.Plan(ctx, r); err != nil || len(plan) != 0 {
		t.Fatalf("second plan %q, %v", plan, err)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.OK {
		t.Fatalf("second apply %+v", res)
	}
	if len(*events) != 0 || len(sys.AptArgs) != 0 || len(sys.TakeCalls()) != 0 || s.Status().Digest != digest {
		t.Fatalf("second apply: events %+v, apt %q", *events, sys.AptArgs)
	}
}

// TestSoftwarePlanHasNoSideEffects: report-only devices run Plan alone (plan M13a amendment R2.5).
func TestSoftwarePlanHasNoSideEffects(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.Packages["vim"], sys.Packages["libreoffice"] = true, true
	sys.Files["/etc/apt/sources.list.d/paddock-rogue.sources"] = &fakesys.File{Data: []byte("x"), Mode: 0o644}
	sys.Files[vendorList] = &fakesys.File{Data: []byte("changed"), Mode: 0o644}
	r := softwareResource(t, []bundle.SoftwareSource{vendorSource(t)},
		bundle.SoftwarePackage{Package: "libreoffice", Intent: bundle.SoftwareUninstall, CatalogEntryID: otherEntry},
		required("nano", "vendor"), bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry})
	plan, err := s.Plan(context.Background(), r)
	want := []string{"remove-unmanaged /etc/apt/sources.list.d/paddock-rogue.sources", "source vendor", "keyring vendor",
		"file " + reconcile.SoftwareForbidFile, "remove libreoffice", "install nano", "remove vim"}
	if err != nil || !slices.Equal(plan, want) {
		t.Fatalf("plan %q, %v", plan, err)
	}
	if len(sys.Calls) != 0 || len(sys.AptArgs) != 0 || len(*events) != 0 {
		t.Fatalf("Plan changed the system: %q %q %+v", sys.Calls, sys.AptArgs, *events)
	}
}

func TestSoftwarePinnedVersion(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.Packages["nano"], sys.Versions["nano"] = true, "0.9"
	sys.Files[record] = &fakesys.File{Data: []byte("nano\n"), Mode: 0o600}
	p := required("nano", "")
	p.Version = ver("1.0")
	r := softwareResource(t, nil, p)
	if plan, err := s.Plan(context.Background(), r); err != nil || !slices.Equal(plan, []string{"install nano=1.0"}) {
		t.Fatalf("plan %q, %v", plan, err)
	}
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if got := sys.AptArgs[len(sys.AptArgs)-1]; got[len(got)-1] != "nano=1.0" || !slices.Contains(got, "--allow-downgrades") {
		t.Fatalf("install %q", got)
	}
	if sys.Versions["nano"] != "1.0" || status(t, s, "nano").Version != "1.0" {
		t.Fatalf("version %q", sys.Versions["nano"])
	}
	for _, c := range sys.Calls {
		if strings.HasPrefix(c, "apt-mark") || c == "write "+reconcile.PinFile {
			t.Fatalf("software touched the holds of the updates reconciler: %q", sys.Calls)
		}
	}
	if len(*events) != 0 {
		t.Fatalf("a pinned upgrade of an installed package is no installation: %+v", *events)
	}
}

func TestSoftwareReinstall(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.Files[record] = &fakesys.File{Data: []byte("nano\n"), Mode: 0o600}
	r := softwareResource(t, nil, required("nano", ""))
	if plan, err := s.Plan(context.Background(), r); err != nil || !slices.Equal(plan, []string{"reinstall nano"}) {
		t.Fatalf("plan %q, %v", plan, err)
	}
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if len(*events) != 1 || (*events)[0].typ != protocol.EventSoftwareReinstalled || !strings.Contains((*events)[0].data, `"reason":"locally_removed"`) {
		t.Fatalf("events %+v", *events)
	}
}

func TestSoftwareRemovalWaitsForTheServer(t *testing.T) {
	sys, s, events, reachable := softwareFixture(t)
	sys.Packages["nano"], sys.Versions["nano"] = true, "7.2-1"
	r := softwareResource(t, nil, bundle.SoftwarePackage{Package: "nano", Intent: bundle.SoftwareUninstall, CatalogEntryID: nanoEntry})
	*reachable = false
	if res := s.Apply(context.Background(), r); res.Status != reconcile.OK {
		t.Fatalf("offline apply %+v", res)
	}
	if len(aptCalls(sys)) != 0 || !sys.Packages["nano"] || len(*events) != 0 {
		t.Fatalf("offline: apt %q, events %+v", aptCalls(sys), *events)
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStatePending || it.Reason != protocol.SoftwareDeferredOffline {
		t.Fatalf("offline status %+v", it)
	}
	*reachable = true
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Changed {
		t.Fatalf("online apply %+v", res)
	}
	if got := aptCalls(sys); !slices.Equal(got, []string{"apt-get -s remove nano", "apt-get remove nano"}) {
		t.Fatalf("apt calls %q", got)
	}
	if got := sys.AptArgs[1]; !slices.Equal(got, []string{"remove", "-y", "-q", "-o", "DPkg::Lock::Timeout=60", "nano"}) {
		t.Fatalf("remove arguments %q (no purge)", got)
	}
	if len(*events) != 1 || (*events)[0].typ != protocol.EventSoftwareRemoved ||
		(*events)[0].data != `{"package":"nano","version":"7.2-1","intent":"uninstall","catalog_entry_id":"`+nanoEntry+`"}` {
		t.Fatalf("events %+v", *events)
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateAbsent {
		t.Fatalf("status %+v", it)
	}
}

// TestSoftwareOfflineInstallRemovesNothing: an installation that would remove a package planned for removal is
// refused while the server is unreachable; removals wait for it.
func TestSoftwareOfflineInstallRemovesNothing(t *testing.T) {
	sys, s, _, reachable := softwareFixture(t)
	*reachable = false
	sys.Packages["vim"] = true
	sys.AptScript = map[string]fakesys.AptReply{"apt-get -s install nano": {Output: "The following packages will be REMOVED:\n  vim\n" +
		"Remv vim [9.1]\nInst nano (7.2 Ubuntu:26.04/resolute [amd64])\n0 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.\n"}}
	r := softwareResource(t, nil, required("nano", ""), bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry})
	s.Apply(context.Background(), r)
	if slices.Contains(sys.Calls, "apt-get install nano") || !sys.Packages["vim"] {
		t.Fatalf("calls %q", sys.Calls)
	}
	if it := status(t, s, "nano"); it.Reason != protocol.SoftwareWouldRemoveDependents {
		t.Fatalf("status %+v", it)
	}
}

func TestSoftwareWouldRemoveDependents(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.AptScript = map[string]fakesys.AptReply{"apt-get -s install nano": {Output: "Reading package lists...\nThe following packages will be REMOVED:\n  libfoo\n" +
		"The following NEW packages will be installed:\n  nano\n0 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.\n" +
		"Remv libfoo [1.0]\nInst nano (7.2 Ubuntu:26.04/resolute [amd64])\n"}}
	r := softwareResource(t, nil, required("nano", ""))
	for range 2 {
		if res := s.Apply(context.Background(), r); res.Status != reconcile.Error || !strings.Contains(res.Message, "would_remove_dependents") {
			t.Fatalf("apply %+v", res)
		}
	}
	if slices.Contains(sys.Calls, "apt-get install nano") || sys.Packages["nano"] {
		t.Fatalf("installed despite the simulation: %q", sys.Calls)
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareWouldRemoveDependents ||
		!strings.Contains(it.Error, "libfoo") {
		t.Fatalf("status %+v", it)
	}
	if !slices.Equal(typesOf(*events), []string{protocol.EventSoftwareApplyFailed}) ||
		!strings.Contains((*events)[0].data, `"stage":"simulate","reason":"would_remove_dependents"`) {
		t.Fatalf("events over two passes %+v", *events)
	}
}

func TestSoftwareDpkgLocked(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.AptScript = map[string]fakesys.AptReply{"apt-get -s install nano": {Output: "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (unattended-upgr)\n", Exit: 100}}
	r := softwareResource(t, nil, required("nano", ""))
	res := s.Apply(context.Background(), r)
	if res.Status != reconcile.Error || !strings.Contains(res.Message, "dpkg locked") {
		t.Fatalf("apply %+v", res)
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStatePending || it.Reason != protocol.SoftwareDpkgLocked {
		t.Fatalf("status %+v", it)
	}
	if len(*events) != 0 {
		t.Fatalf("a held lock is no failure event: %+v", *events)
	}
	sys.AptScript = nil
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Changed || !sys.Packages["nano"] {
		t.Fatalf("after the lock: %+v", res)
	}
}

func TestSoftwareDpkgInterrupted(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	sys.DpkgInterrupted = true
	r := softwareResource(t, nil, required("nano", ""))
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if got := aptCalls(sys); !slices.Equal(got, []string{"apt-get -s install nano", "dpkg --configure -a", "apt-get -s install nano", "apt-get install nano"}) {
		t.Fatalf("calls %q", got)
	}
}

// TestSoftwareFingerprintMismatch: a source whose keyring is not the key of its fingerprint writes nothing and fails
// its packages only (plan M13a decision 21).
func TestSoftwareFingerprintMismatch(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	bad := vendorSource(t)
	bad.Fingerprint = strings.Repeat("AB", 20)
	good := vendorSource(t)
	good.Slug = "good"
	other := required("vim", "good")
	other.CatalogEntryID = otherEntry
	r := softwareResource(t, []bundle.SoftwareSource{good, bad}, required("nano", "vendor"), other)
	plan, err := s.Plan(context.Background(), r)
	if err != nil || slices.Contains(plan, "source vendor") || !slices.Contains(plan, "source good") {
		t.Fatalf("plan %q, %v", plan, err)
	}
	for range 2 {
		if res := s.Apply(context.Background(), r); res.Status != reconcile.Error {
			t.Fatalf("apply %+v", res)
		}
	}
	if sys.Files[vendorList] != nil || sys.Files[vendorKey] != nil {
		t.Fatal("files of the refused source written")
	}
	if sys.Files[reconcile.SoftwareSourcePath("good")] == nil || !sys.Packages["vim"] || sys.Packages["nano"] {
		t.Fatalf("the good source was not applied: %q", sys.Calls)
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareFingerprintMismatch {
		t.Fatalf("status %+v", it)
	}
	var failed []event
	for _, e := range *events {
		if e.typ == protocol.EventSoftwareApplyFailed {
			failed = append(failed, e)
		}
	}
	if len(failed) != 1 || !strings.Contains(failed[0].data, `"source":"vendor","stage":"keyring","reason":"fingerprint_mismatch"`) {
		t.Fatalf("failure events %+v", failed)
	}
}

func TestSoftwareUnmanagedFilesAndTamper(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	ctx := context.Background()
	himmelblau := []string{"/etc/apt/sources.list.d/paddock-himmelblau.list", "/etc/apt/keyrings/himmelblau.gpg"}
	for _, f := range himmelblau {
		sys.Files[f] = &fakesys.File{Data: []byte("login"), Mode: 0o644}
	}
	r := softwareResource(t, []bundle.SoftwareSource{vendorSource(t)}, required("nano", "vendor"))
	s.Apply(ctx, r)
	*events = nil
	rogue := "/etc/apt/sources.list.d/paddock-rogue.sources"
	sys.Files[rogue] = &fakesys.File{Data: []byte("Types: deb\n"), Mode: 0o644}
	sys.Files[vendorList].Data = []byte("Types: deb\nURIs: https://evil.example.com\n")
	plan, err := s.Plan(ctx, r)
	if err != nil || !slices.Equal(plan, []string{"remove-unmanaged " + rogue, "source vendor"}) {
		t.Fatalf("plan %q, %v", plan, err)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if sys.Files[rogue] != nil || !strings.Contains(fileContent(t, sys, vendorList), "repo.example.com") {
		t.Fatal("not restored")
	}
	want := []event{
		{protocol.EventTamperProtectedFileChanged, `{"file":"` + rogue + `"}`},
		{protocol.EventTamperProtectedFileChanged, `{"file":"` + vendorList + `"}`},
	}
	if !slices.Equal(*events, want) {
		t.Fatalf("events %+v", *events)
	}
	for _, f := range himmelblau {
		if sys.Files[f] == nil {
			t.Fatalf("%s removed", f)
		}
	}
	// A source that leaves the spec is removed without a tamper event.
	*events = nil
	if res := s.Apply(ctx, softwareResource(t, nil, required("nano", ""))); res.Status != reconcile.Changed || sys.Files[vendorList] != nil ||
		sys.Files[vendorKey] != nil || len(*events) != 0 {
		t.Fatalf("removed source: %+v, events %+v", res, *events)
	}
	for _, f := range himmelblau {
		if sys.Files[f] == nil {
			t.Fatalf("%s removed", f)
		}
	}
}

func TestSoftwareForbidPins(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	forbid := func(pkg string) bundle.SoftwarePackage {
		return bundle.SoftwarePackage{Package: pkg, Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry}
	}
	if res := s.Apply(context.Background(), softwareResource(t, nil, forbid("nano"), forbid("vim"))); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	want := "# Managed by Paddock. Do not edit: local changes are reverted.\n\n" +
		"Package: nano\nPin: release *\nPin-Priority: -1\n\nPackage: vim\nPin: release *\nPin-Priority: -1\n"
	if got := fileContent(t, sys, reconcile.SoftwareForbidFile); got != want {
		t.Fatalf("pins:\n%s", got)
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateAbsent {
		t.Fatalf("status %+v", it)
	}
	if res := s.Apply(context.Background(), softwareResource(t, nil, required("nano", ""))); res.Status != reconcile.Changed ||
		sys.Files[reconcile.SoftwareForbidFile] != nil {
		t.Fatalf("pins left: %+v", res)
	}
}

func TestSoftwareNoCandidate(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	missing := fakesys.AptReply{Output: "E: Unable to locate package vim\n", Exit: 100}
	sys.AptScript = map[string]fakesys.AptReply{"apt-get -s install nano vim": missing, "apt-get -s install vim": missing}
	vim := required("vim", "")
	vim.CatalogEntryID = otherEntry
	r := softwareResource(t, nil, required("nano", ""), vim)
	s.Apply(context.Background(), r)
	if got := aptCalls(sys); !slices.Equal(got, []string{"apt-get -s install nano vim", "apt-get update", "apt-get -s install nano vim",
		"apt-get -s install nano", "apt-get install nano"}) {
		t.Fatalf("calls %q", got)
	}
	if slices.Contains(sys.AptArgs[1], "Dir::Etc::sourceparts=-") {
		t.Fatalf("the retry needs a full update: %q", sys.AptArgs[1])
	}
	if it := status(t, s, "vim"); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareNoCandidate {
		t.Fatalf("vim %+v", it)
	}
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateInstalled {
		t.Fatalf("nano %+v", it)
	}
	if !slices.Equal(typesOf(*events), []string{protocol.EventSoftwareApplyFailed, protocol.EventSoftwareInstalled}) {
		t.Fatalf("events %+v", *events)
	}
	// The same failure at the next pass neither refreshes every list again nor reports again.
	sys.TakeCalls()
	*events = nil
	s.Apply(context.Background(), r)
	if got := aptCalls(sys); !slices.Equal(got, []string{"apt-get -s install vim"}) || len(*events) != 0 {
		t.Fatalf("second pass: %q %+v", got, *events)
	}
}

// TestSoftwareProtectedRefused: the agent refuses a spec the protected tiers forbid, before planning anything (plan
// M13a amendment 2026-11-02 M3).
func TestSoftwareProtectedRefused(t *testing.T) {
	for _, p := range []bundle.SoftwarePackage{
		{Package: "sudo", Intent: bundle.SoftwareForbid, CatalogEntryID: nanoEntry},
		{Package: "paddock-agent", Intent: bundle.SoftwareRequired, CatalogEntryID: nanoEntry},
		{Package: "himmelblau-extra", Intent: bundle.SoftwareUninstall, CatalogEntryID: nanoEntry},
		{Package: "initramfs-tools", Intent: bundle.SoftwareRequired, CatalogEntryID: nanoEntry},
		// A name apt reads as a pattern that selects a protected package (vi. matches paddock-supervisor).
		{Package: "vi.", Intent: bundle.SoftwareUninstall, CatalogEntryID: nanoEntry},
	} {
		sys, s, events, _ := softwareFixture(t)
		sys.Packages[p.Package] = true
		spec, _ := json.Marshal(bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{}, Packages: []bundle.SoftwarePackage{p, required("nano", "")}})
		r := bundle.Resource{ID: bundle.TypeSoftware, Type: bundle.TypeSoftware, Spec: spec}
		if _, err := s.Plan(context.Background(), r); err == nil || !strings.Contains(err.Error(), "protected") {
			t.Fatalf("%s: plan error %v", p.Package, err)
		}
		if res := s.Apply(context.Background(), r); res.Status != reconcile.Error || !strings.Contains(res.Message, "protected") {
			t.Fatalf("%s: apply %+v", p.Package, res)
		}
		if len(sys.Calls) != 0 || len(*events) != 0 || !sys.Packages[p.Package] {
			t.Fatalf("%s: refused spec changed the system: %q", p.Package, sys.Calls)
		}
	}
}

func TestSoftwareSupersededHoldInMessage(t *testing.T) {
	_, s, _, _ := softwareFixture(t)
	r := softwareResource(t, nil, bundle.SoftwarePackage{Package: "nano", Intent: bundle.SoftwareForbid, CatalogEntryID: nanoEntry, SupersededHold: true},
		bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareUninstall, CatalogEntryID: otherEntry})
	for range 2 {
		if res := s.Apply(context.Background(), r); res.Message != "package hold superseded by forbid or uninstall: nano" {
			t.Fatalf("apply %+v", res)
		}
	}
}

func TestSoftwareStatusErrorIsCut(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	sys.AptScript = map[string]fakesys.AptReply{"apt-get -s install nano": {Output: "E: " + strings.Repeat("ü", 300) + "\n", Exit: 100}}
	s.Apply(context.Background(), softwareResource(t, nil, required("nano", "")))
	if it := status(t, s, "nano"); len([]rune(it.Error)) != 120 || it.Reason != protocol.SoftwareAptFailed {
		t.Fatalf("status %+v (%d characters)", it, len([]rune(it.Error)))
	}
}

func TestSoftwareResidue(t *testing.T) {
	sys, s, _, _ := softwareFixture(t)
	if s.Residue() {
		t.Fatal("residue on a clean device")
	}
	for _, f := range []string{"/etc/apt/sources.list.d/paddock-himmelblau.list", "/etc/apt/keyrings/himmelblau.gpg",
		"/etc/apt/sources.list.d/paddock-mine.sources", reconcile.SoftwareForbidFile} {
		sys.Files[f] = &fakesys.File{Data: []byte("x")}
	}
	if s.Residue() {
		t.Fatal("files Paddock did not write are no residue")
	}
	sys.Files[reconcile.SoftwareForbidFile].Data = []byte("# Managed by Paddock. Do not edit: local changes are reverted.\n")
	if !s.Residue() {
		t.Fatal("Paddock's forbid pins are residue")
	}
	delete(sys.Files, reconcile.SoftwareForbidFile)
	sys.Files[record] = &fakesys.File{Data: []byte("nano\n")}
	if !s.Residue() {
		t.Fatal("the record of installed packages is residue")
	}
}

// TestSoftwareResiduePass (architect decision 2026-11-03): the empty section of a bundle without one removes the
// sources, keyrings and forbid pins Paddock wrote and nothing else — not a user's own source, not a paddock-* file it
// did not record, not a forbid file without its header, and no package; a second pass changes nothing.
func TestSoftwareResiduePass(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	ctx := context.Background()
	forbid := bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry}
	s.Apply(ctx, softwareResource(t, []bundle.SoftwareSource{vendorSource(t)}, required("nano", "vendor"), forbid))
	if f := sys.Files["/var/lib/paddock/state/software-sources"]; f == nil || string(f.Data) != "vendor\n" || f.Mode != 0o600 {
		t.Fatalf("source record %+v", f)
	}
	user := map[string]string{"/etc/apt/sources.list.d/docker.sources": "Types: deb\n", "/etc/apt/keyrings/docker.gpg": "key",
		"/etc/apt/sources.list.d/paddock-mine.sources": "Types: deb\n", "/etc/apt/keyrings/paddock-mine.gpg": "key"}
	for f, data := range user {
		sys.Files[f] = &fakesys.File{Data: []byte(data), Mode: 0o644}
	}
	*events = nil
	sys.TakeCalls()
	empty := softwareResource(t, nil)
	if !s.Residue() {
		t.Fatal("no residue after a section")
	}
	plan, err := s.Plan(ctx, empty)
	if err != nil || !slices.Equal(plan, []string{"remove-unmanaged " + vendorList, "remove-unmanaged " + vendorKey, "file " + reconcile.SoftwareForbidFile}) {
		t.Fatalf("plan %q, %v", plan, err)
	}
	if res := s.Apply(ctx, empty); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	for _, gone := range []string{vendorList, vendorKey, reconcile.SoftwareForbidFile, record, "/var/lib/paddock/state/software-sources"} {
		if sys.Files[gone] != nil {
			t.Errorf("%s left", gone)
		}
	}
	for f := range user {
		if sys.Files[f] == nil {
			t.Errorf("%s removed", f)
		}
	}
	if !sys.Packages["nano"] || len(*events) != 0 || slices.ContainsFunc(sys.Calls, func(c string) bool { return strings.HasPrefix(c, "apt-get") }) {
		t.Fatalf("residue pass touched packages: %q %+v", sys.Calls, *events)
	}
	if s.Residue() {
		t.Fatal("residue after the pass")
	}
	sys.TakeCalls()
	if res := s.Apply(ctx, empty); res.Status != reconcile.OK || len(sys.TakeCalls()) != 0 {
		t.Fatalf("second pass %+v", res)
	}
	// A forbid file a user wrote under the same name is not Paddock's.
	sys.Files[reconcile.SoftwareForbidFile] = &fakesys.File{Data: []byte("Package: vim\n"), Mode: 0o644}
	if plan, _ := s.Plan(ctx, empty); len(plan) != 0 {
		t.Fatalf("plan %q", plan)
	}
}

// TestSoftwareLockWaitThatSucceeds: apt prints the lock message while it waits and then succeeds; that is a change
// with its event, not a held lock (review 1 B1).
func TestSoftwareLockWaitThatSucceeds(t *testing.T) {
	sys, s, events, reachable := softwareFixture(t)
	wait := "Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (unattended-upgr)\n"
	sys.AptScript = map[string]fakesys.AptReply{"apt-get install nano": {Output: wait, Apply: true}, "apt-get remove vim": {Output: wait, Apply: true},
		"apt-get update": {Output: wait, Apply: true}}
	sys.Packages["vim"] = true
	*reachable = true
	r := softwareResource(t, []bundle.SoftwareSource{vendorSource(t)}, required("nano", "vendor"),
		bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareUninstall, CatalogEntryID: otherEntry})
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if !slices.Equal(typesOf(*events), []string{protocol.EventSoftwareInstalled, protocol.EventSoftwareRemoved}) {
		t.Fatalf("events %+v", *events)
	}
	sys.TakeCalls()
	if res := s.Apply(context.Background(), r); res.Status != reconcile.OK || slices.Contains(sys.TakeCalls(), "apt-get update") {
		t.Fatalf("the source was refreshed: no second update; %+v", res)
	}
}

// TestSoftwareLockDuringSourceUpdate: a source whose update found the lock is refreshed at the next pass.
func TestSoftwareLockDuringSourceUpdate(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.AptScript = map[string]fakesys.AptReply{"apt-get update": {Output: "E: Could not get lock /var/lib/dpkg/lock-frontend\n", Exit: 100}}
	r := softwareResource(t, []bundle.SoftwareSource{vendorSource(t)}, required("nano", "vendor"))
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Error || !strings.Contains(res.Message, "dpkg locked") {
		t.Fatalf("apply %+v", res)
	}
	if it := status(t, s, "nano"); it.Reason != protocol.SoftwareDpkgLocked || len(*events) != 0 {
		t.Fatalf("status %+v events %+v", it, *events)
	}
	sys.AptScript = nil
	sys.TakeCalls()
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Changed {
		t.Fatalf("second apply %+v", res)
	}
	if got := aptCalls(sys); !slices.Equal(got, []string{"apt-get update", "apt-get -s install nano", "apt-get install nano"}) {
		t.Fatalf("calls %q", got)
	}
}

func TestSoftwareLockDuringRemoval(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.Packages["vim"] = true
	sys.AptScript = map[string]fakesys.AptReply{"apt-get remove vim": {Output: "E: Could not get lock /var/lib/dpkg/lock-frontend\n", Exit: 100}}
	r := softwareResource(t, nil, bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry})
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Error || !strings.Contains(res.Message, "dpkg locked") {
		t.Fatalf("apply %+v", res)
	}
	if it := status(t, s, "vim"); it.State != protocol.SoftwareStatePending || it.Reason != protocol.SoftwareDpkgLocked || len(*events) != 0 {
		t.Fatalf("status %+v events %+v", it, *events)
	}
}

// TestSoftwareExactRemoval: a removal whose simulation removes another package is refused (review 1 B5).
func TestSoftwareExactRemoval(t *testing.T) {
	for name, out := range map[string]string{
		"classic": "The following packages will be REMOVED:\n  libpam-modules-bin paddock-agent\n" +
			"Remv paddock-agent [1.0]\nRemv libpam-modules-bin [1.5]\n0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n",
		"apt 3": "REMOVING:\n  libpam-modules-bin  paddock-agent\n\nSummary:\n  Upgrading: 0, Installing: 0, Removing: 2, Not Upgrading: 0\n" +
			"Remv paddock-agent:amd64 [1.0]\nRemv libpam-modules-bin:amd64 [1.5]\n",
		"no Remv lines": "REMOVING:\n  libpam-modules-bin  paddock-agent\n\nSummary:\n  Upgrading: 0, Installing: 0, Removing: 2, Not Upgrading: 0\n",
		"no summary":    "Remv libpam-modules-bin [1.5]\n",
	} {
		t.Run(name, func(t *testing.T) {
			sys, s, events, _ := softwareFixture(t)
			sys.Packages["libpam-modules-bin"] = true
			sys.AptScript = map[string]fakesys.AptReply{"apt-get -s remove libpam-modules-bin": {Output: out}}
			s.Apply(context.Background(), softwareResource(t, nil,
				bundle.SoftwarePackage{Package: "libpam-modules-bin", Intent: bundle.SoftwareUninstall, CatalogEntryID: nanoEntry}))
			if slices.Contains(sys.Calls, "apt-get remove libpam-modules-bin") || !sys.Packages["libpam-modules-bin"] {
				t.Fatalf("removed: %q", sys.Calls)
			}
			if it := status(t, s, "libpam-modules-bin"); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareWouldRemoveDependents {
				t.Fatalf("status %+v", it)
			}
			if !slices.Equal(typesOf(*events), []string{protocol.EventSoftwareApplyFailed}) {
				t.Fatalf("events %+v", *events)
			}
		})
	}
}

// TestSoftwareInstallFailsClosed: an install simulation in apt 3's format that removes a package, or whose removals
// cannot be told, is refused.
func TestSoftwareInstallFailsClosed(t *testing.T) {
	for name, out := range map[string]string{
		"apt 3": "REMOVING:\n  dracut\n\nSummary:\n  Upgrading: 0, Installing: 1, Removing: 1, Not Upgrading: 0\n" +
			"Remv dracut:amd64 [106]\nInst initramfs-tools (0.142 Ubuntu:26.04/resolute [all])\n",
		"unreadable": "Inst nano (7.2 Ubuntu:26.04/resolute [amd64])\n",
	} {
		t.Run(name, func(t *testing.T) {
			sys, s, _, _ := softwareFixture(t)
			sys.AptScript = map[string]fakesys.AptReply{"apt-get -s install nano": {Output: out}}
			s.Apply(context.Background(), softwareResource(t, nil, required("nano", "")))
			if slices.Contains(sys.Calls, "apt-get install nano") {
				t.Fatalf("installed: %q", sys.Calls)
			}
			if it := status(t, s, "nano"); it.Reason != protocol.SoftwareWouldRemoveDependents {
				t.Fatalf("status %+v", it)
			}
		})
	}
}

// TestSoftwareInstallRemovesAPlannedRemoval: while the server is reachable an installation may remove a package that
// is to be removed anyway; its removal event carries the version it had before the pass (review 1 L1).
func TestSoftwareInstallRemovesAPlannedRemoval(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.Packages["vim"], sys.Versions["vim"] = true, "9.1"
	sys.AptScript = map[string]fakesys.AptReply{
		"apt-get -s install nano": {Output: "Remv vim [9.1]\nInst nano (7.2)\n0 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.\n"},
		"apt-get install nano":    {Apply: true},
	}
	r := softwareResource(t, nil, required("nano", ""), bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry})
	s.Apply(context.Background(), r)
	if !sys.Packages["nano"] || sys.Packages["vim"] {
		t.Fatalf("calls %q", sys.Calls)
	}
	if len(*events) != 2 || (*events)[1].typ != protocol.EventSoftwareRemoved || !strings.Contains((*events)[1].data, `"version":"9.1"`) {
		t.Fatalf("events %+v", *events)
	}
}

// TestSoftwareRegexNamesNeverReachApt: apt-get reads a name it has no package of as a regular expression; such names
// are refused before any apt-get call (review 1 B2, external review H1).
func TestSoftwareRegexNamesNeverReachApt(t *testing.T) {
	for _, p := range []bundle.SoftwarePackage{
		{Package: "nano.", Intent: bundle.SoftwareRequired, CatalogEntryID: nanoEntry},
		{Package: "nan+o", Intent: bundle.SoftwareRequired, CatalogEntryID: nanoEntry},
		{Package: "nan.", Intent: bundle.SoftwareUninstall, CatalogEntryID: nanoEntry},
		{Package: "nan++o", Intent: bundle.SoftwareRequired, CatalogEntryID: nanoEntry},
		{Package: "nan++o", Intent: bundle.SoftwareForbid, CatalogEntryID: nanoEntry},
	} {
		sys, s, _, _ := softwareFixture(t)
		sys.Unknown = map[string]bool{p.Package: true}
		sys.Packages[p.Package] = p.Intent != bundle.SoftwareRequired
		s.Apply(context.Background(), softwareResource(t, nil, p))
		for _, args := range sys.AptArgs {
			if slices.Contains(args, p.Package) {
				t.Fatalf("%s reached apt-get: %q", p.Package, args)
			}
		}
		if it := status(t, s, p.Package); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareNoCandidate {
			t.Fatalf("%s: status %+v", p.Package, it)
		}
	}
}

// TestSoftwareInstallBackOff: a package whose real installation failed waits for its next attempt while the spec is
// unchanged; a changed spec retries at once (review 1 L5).
func TestSoftwareInstallBackOff(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.AptScript = map[string]fakesys.AptReply{"apt-get install nano": {Output: "E: Sub-process /usr/bin/dpkg returned an error code (1)\n", Exit: 100}}
	r := softwareResource(t, nil, required("nano", ""))
	installs := func() int {
		return len(slices.DeleteFunc(sys.TakeCalls(), func(c string) bool { return !strings.HasPrefix(c, "apt-get install nano") }))
	}
	s.Apply(context.Background(), r)
	if installs() != 1 {
		t.Fatal("no first installation")
	}
	for range 11 {
		if res := s.Apply(context.Background(), r); res.Status != reconcile.Error {
			t.Fatalf("apply %+v", res)
		}
		if it := status(t, s, "nano"); it.Reason != protocol.SoftwareAptFailed || !strings.Contains(it.Error, "dpkg returned") {
			t.Fatalf("status while waiting %+v", it)
		}
	}
	if n := installs(); n != 0 {
		t.Fatalf("%d installations while waiting", n)
	}
	s.Apply(context.Background(), r)
	if installs() != 1 || len(*events) != 1 {
		t.Fatalf("no retry after the back-off, events %+v", *events)
	}
	s.Apply(context.Background(), softwareResource(t, nil, required("nano", ""), required("vim", "")))
	if installs() != 1 {
		t.Fatal("a changed spec must retry at once")
	}
}

// TestSoftwareStatusAfterRefusal: a refused spec replaces the status of the earlier pass (review 1 L2).
func TestSoftwareStatusAfterRefusal(t *testing.T) {
	_, s, _, _ := softwareFixture(t)
	s.Apply(context.Background(), softwareResource(t, nil, required("nano", "")))
	spec, _ := json.Marshal(bundle.SoftwareSpec{Sources: []bundle.SoftwareSource{}, Packages: []bundle.SoftwarePackage{
		required("nano", ""), {Package: "sudo", Intent: bundle.SoftwareForbid, CatalogEntryID: otherEntry}}})
	s.Apply(context.Background(), bundle.Resource{ID: bundle.TypeSoftware, Type: bundle.TypeSoftware, Spec: spec})
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateFailed || !strings.Contains(it.Error, "protected") {
		t.Fatalf("status %+v", it)
	}
}

// TestSoftwareApt3Summary: under APT::Output-Version=30 apt 3.2 prints the summary on one line; an exact removal and a
// plain installation in that format are carried out (review 2 R2-B3).
func TestSoftwareApt3Summary(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.Packages["vim"] = true
	sys.AptScript = map[string]fakesys.AptReply{
		"apt-get -s install nano": {Output: "Installing:\n  nano\n\nSummary:\n  Upgrading: 0, Installing: 1, Removing: 0, Not Upgrading: 0\n" +
			"Inst nano (7.2 Ubuntu:26.04/resolute [amd64])\n"},
		"apt-get -s remove vim": {Output: "REMOVING:\n  vim\n\nSummary:\n  Upgrading: 0, Installing: 0, Removing: 1, Not Upgrading: 0\n" +
			"Remv vim:amd64 [9.1]\n"},
	}
	r := softwareResource(t, nil, required("nano", ""), bundle.SoftwarePackage{Package: "vim", Intent: bundle.SoftwareUninstall, CatalogEntryID: otherEntry})
	if res := s.Apply(context.Background(), r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if !sys.Packages["nano"] || sys.Packages["vim"] ||
		!slices.Equal(typesOf(*events), []string{protocol.EventSoftwareInstalled, protocol.EventSoftwareRemoved}) {
		t.Fatalf("calls %q events %+v", sys.Calls, *events)
	}
}

// TestSoftwareLockWaitThenFailure: a run that waited for the lock and then failed for another reason is that failure,
// not a held lock (review 2 N1).
func TestSoftwareLockWaitThenFailure(t *testing.T) {
	sys, s, events, _ := softwareFixture(t)
	sys.AptScript = map[string]fakesys.AptReply{"apt-get install nano": {Output: "Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242\n" +
		"E: Sub-process /usr/bin/dpkg returned an error code (1)\n", Exit: 100}}
	s.Apply(context.Background(), softwareResource(t, nil, required("nano", "")))
	if it := status(t, s, "nano"); it.State != protocol.SoftwareStateFailed || it.Reason != protocol.SoftwareAptFailed {
		t.Fatalf("status %+v", it)
	}
	if !slices.Equal(typesOf(*events), []string{protocol.EventSoftwareApplyFailed}) {
		t.Fatalf("events %+v", *events)
	}
}

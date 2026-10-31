package apply_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/apply"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func newBundle(t *testing.T, version int64, files map[string]string, units ...bundle.UnitSpec) *bundle.Bundle {
	t.Helper()
	mustRes := func(r bundle.Resource, err error) bundle.Resource {
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	rs := []bundle.Resource{mustRes(bundle.TimeResource(bundle.TimeSpec{NTP: true}))}
	for p, c := range files {
		rs = append(rs, mustRes(bundle.FileResource(bundle.FileSpec{Path: p, Mode: "0644", Owner: "root", Group: "root", Content: c})))
	}
	for _, u := range units {
		rs = append(rs, mustRes(bundle.UnitResource(u)))
	}
	bundle.SortResources(rs)
	return &bundle.Bundle{SchemaVersion: 1, BundleVersion: version, Resources: rs}
}

func fixture(t *testing.T) (*fakesys.System, *apply.Applier) {
	t.Helper()
	sys := fakesys.New()
	sys.Packages["systemd-timesyncd"] = true
	sys.Units["systemd-timesyncd.service"] = &fakesys.Unit{State: "enabled", Active: true}
	sys.NTP = true
	sys.Units["app.service"] = &fakesys.Unit{State: "disabled"}
	m, err := reconcile.LoadManaged(filepath.Join(t.TempDir(), "managed.json"))
	if err != nil {
		t.Fatal(err)
	}
	return sys, apply.New(sys, m, nil)
}

func TestApplyOrderAndIdempotency(t *testing.T) {
	ctx := context.Background()
	sys, a := fixture(t)
	sys.NTP = false
	b := newBundle(t, 3, map[string]string{"/etc/app.conf": "a=1\n"}, bundle.UnitSpec{Unit: "app.service", Enabled: true, Active: true})
	rep := a.Apply(ctx, b)
	if rep.Version != 3 || rep.Changed != 3 || len(rep.Errors) != 0 {
		t.Fatalf("first apply %+v", rep)
	}
	want := []string{"timedatectl set-ntp true", "write /etc/app.conf", "systemctl enable app.service", "systemctl start app.service"}
	if calls := sys.TakeCalls(); !slices.Equal(calls, want) {
		t.Fatalf("calls %v, want time → file → unit %v", calls, want)
	}
	if rep := a.Apply(ctx, b); rep.Changed != 0 || len(rep.Errors) != 0 {
		t.Fatalf("second apply must change nothing: %+v", rep)
	}
	if ids := apply.Drifted(a.Plan(ctx, b)); len(ids) != 0 || len(sys.TakeCalls()) != 0 {
		t.Fatalf("plan after apply: %v", ids)
	}
}

func TestErrorsDoNotStopOtherResources(t *testing.T) {
	sys, a := fixture(t)
	b := newBundle(t, 1, map[string]string{"/etc/a": "a"}, bundle.UnitSpec{Unit: "ghost.service", Enabled: true}, bundle.UnitSpec{Unit: "app.service", Enabled: true})
	b.Resources = append(b.Resources, bundle.Resource{ID: "future:x", Type: "future"})
	rep := a.Apply(context.Background(), b)
	if rep.Changed != 2 || len(rep.Errors) != 2 || rep.Errors[0].ID != "unit:ghost.service" || rep.Errors[1].ID != "future:x" {
		t.Fatalf("report %+v", rep)
	}
	if sys.Units["app.service"].State != "enabled" {
		t.Fatal("app.service skipped after an error")
	}
}

func TestRemovedFileResource(t *testing.T) {
	ctx := context.Background()
	sys, a := fixture(t)
	a.Apply(ctx, newBundle(t, 1, map[string]string{"/etc/keep": "k", "/etc/clean": "c", "/etc/edited": "e"}))
	sys.Files["/etc/edited"].Data = []byte("local change")
	rep := a.Apply(ctx, newBundle(t, 2, map[string]string{"/etc/keep": "k"}))
	if _, ok := sys.Files["/etc/clean"]; ok {
		t.Fatal("unmodified file of a removed resource not deleted")
	}
	if _, ok := sys.Files["/etc/edited"]; !ok {
		t.Fatal("locally modified file deleted")
	}
	if len(rep.Errors) != 1 || rep.Errors[0].ID != "file:/etc/edited" || rep.Errors[0].Message != "left_modified_file" || rep.Changed != 1 {
		t.Fatalf("report %+v", rep)
	}
	if rep := a.Apply(ctx, newBundle(t, 3, map[string]string{"/etc/keep": "k"})); len(rep.Errors) != 0 || rep.Changed != 0 {
		t.Fatalf("the modified file is reported once: %+v", rep)
	}
}

func TestDriftCorrection(t *testing.T) {
	ctx := context.Background()
	sys, a := fixture(t)
	b := newBundle(t, 1, map[string]string{"/etc/a": "a", "/etc/b": "b"})
	a.Apply(ctx, b)
	sys.Files["/etc/b"].Data = []byte("tampered")
	ids := apply.Drifted(a.Plan(ctx, b))
	if !slices.Equal(ids, []string{"file:/etc/b"}) {
		t.Fatalf("drifted %v", ids)
	}
	rep := a.ApplyResources(ctx, b, ids)
	if !slices.Equal(rep.ChangedIDs, ids) || string(sys.Files["/etc/b"].Data) != "b" {
		t.Fatalf("drift apply %+v", rep)
	}
}

// TestDenyListWithoutLoginResource: with the PAM profile enabled, a device without a login resource gets an empty
// deny list, restored by the drift pass; an existing list is kept (plan M4a step 0c).
func TestDenyListWithoutLoginResource(t *testing.T) {
	ctx := context.Background()
	sys, a := fixture(t)
	b := newBundle(t, 1, nil)
	a.Apply(ctx, b)
	if _, ok := sys.Files[reconcile.DenyList]; ok {
		t.Fatal("deny list written without the PAM profile")
	}
	sys.Files["/etc/pam.d/common-auth"] = &fakesys.File{Data: []byte(reconcile.DenyAuthLine + "\n"), Mode: 0o644}
	rep := a.Apply(ctx, b)
	if f := sys.Files[reconcile.DenyList]; f == nil || len(f.Data) != 0 || f.Mode != 0o644 || !slices.Equal(rep.ChangedIDs, []string{reconcile.DenyListID}) {
		t.Fatalf("deny list %+v, report %+v", f, rep)
	}
	if ids := apply.Drifted(a.Plan(ctx, b)); len(ids) != 0 {
		t.Fatalf("drifted %v", ids)
	}
	delete(sys.Files, reconcile.DenyList)
	ids := apply.Drifted(a.Plan(ctx, b))
	if !slices.Equal(ids, []string{reconcile.DenyListID}) {
		t.Fatalf("drifted %v", ids)
	}
	if rep := a.ApplyResources(ctx, b, ids); !slices.Equal(rep.ChangedIDs, ids) || sys.Files[reconcile.DenyList] == nil {
		t.Fatalf("drift apply %+v", rep)
	}
	sys.Files[reconcile.DenyList].Data = []byte("eve@acme.test\n")
	if rep := a.Apply(ctx, b); rep.Changed != 0 || string(sys.Files[reconcile.DenyList].Data) != "eve@acme.test\n" {
		t.Fatalf("existing list changed: %+v", rep)
	}
}

func TestRejectReason(t *testing.T) {
	for err, want := range map[error]string{
		bundle.ErrSignature: "signature", bundle.ErrWrongDevice: "wrong_device", bundle.ErrDowngrade: "downgrade", bundle.ErrSchema: "schema",
	} {
		if got := apply.RejectReason(err); got != want {
			t.Errorf("%v: %s", err, got)
		}
	}
}

// TestInventorySection (plan M5a decision 5): the bundle's inventory section is planned and applied after the
// resources and drift-corrected like one; an applier without inventory reconciler ignores it, and a bundle that names
// "inventory" as a resource type is refused.
func TestInventorySection(t *testing.T) {
	ctx := context.Background()
	sys, a := fixture(t)
	b := newBundle(t, 4, nil)
	sum := sha256.Sum256([]byte("deb"))
	b.Inventory = &bundle.Inventory{FleetURL: "https://fleet.example.org", EnrollSecret: "s", Package: bundle.InventoryPackage{
		Version: "1.61.0", URLPath: "packages/1.2.0/fleet-osquery_1.61.0_amd64.deb", SHA256: hex.EncodeToString(sum[:])}}
	if plan := a.Plan(ctx, b); slices.ContainsFunc(plan, func(p apply.Planned) bool { return p.ID == reconcile.InventoryID }) {
		t.Fatalf("planned without an inventory reconciler: %+v", plan)
	}
	a.WithInventory(&reconcile.Inventory{Sys: sys, BundlesURL: "https://bundles.example.org",
		Download: func(context.Context, string, int64) ([]byte, error) { return []byte("deb"), nil }})
	plan := a.Plan(ctx, b)
	if last := plan[len(plan)-1]; last.ID != reconcile.InventoryID || len(last.Changes) == 0 {
		t.Fatalf("plan %+v", plan)
	}
	if rep := a.Apply(ctx, b); len(rep.Errors) != 0 || !slices.Contains(rep.ChangedIDs, reconcile.InventoryID) {
		t.Fatalf("apply %+v", rep)
	}
	sys.Units["orbit.service"].Active = false
	ids := apply.Drifted(a.Plan(ctx, b))
	if !slices.Equal(ids, []string{reconcile.InventoryID}) {
		t.Fatalf("drifted %v", ids)
	}
	if rep := a.ApplyResources(ctx, b, ids); !slices.Equal(rep.ChangedIDs, []string{reconcile.InventoryID}) || !sys.Units["orbit.service"].Active {
		t.Fatalf("drift correction %+v", rep)
	}
	b.Resources = append(b.Resources, bundle.Resource{ID: "inventory", Type: "inventory", Spec: []byte("{}")})
	if err := a.CheckTypes(b); err == nil {
		t.Fatal("a resource of type inventory was accepted")
	}
}

// TestUpdatesSection (plan M5b decisions 4 and 5): the updates section is applied as resource "updates" after the
// units and planned for drift like any resource; a bundle without it leaves updates alone.
func TestUpdatesSection(t *testing.T) {
	sys, a := fixture(t)
	sys.Packages["unattended-upgrades"] = true
	for _, u := range []string{"apt-daily.timer", "apt-daily-upgrade.timer"} {
		sys.Units[u] = &fakesys.Unit{State: "enabled", Active: true}
	}
	b := newBundle(t, 1, nil, bundle.UnitSpec{Unit: "cron.service", Enabled: true, Active: true})
	sys.Units["cron.service"] = &fakesys.Unit{State: "disabled"}
	b.Updates = &bundle.UpdatesSpec{SecurityDailyAt: "03:00", RegularSchedule: "Sat 04:00", RegularUpdatesEnabled: true,
		MaxRandomDelayMin: 60, Holds: []bundle.Hold{{Package: "curl"}}}
	if err := a.CheckTypes(b); err != nil {
		t.Fatal(err)
	}
	rep := a.Apply(context.Background(), b)
	if len(rep.Errors) != 0 || !slices.Equal(rep.ChangedIDs, []string{"unit:cron.service", "updates"}) {
		t.Fatalf("report %+v", rep)
	}
	if !sys.Held["curl"] {
		t.Fatal("hold not applied")
	}
	if drifted := apply.Drifted(a.Plan(context.Background(), b)); len(drifted) != 0 {
		t.Fatalf("drift after apply %v", drifted)
	}
	delete(sys.Files, reconcile.UnattendedConf)
	if drifted := apply.Drifted(a.Plan(context.Background(), b)); !slices.Equal(drifted, []string{"updates"}) {
		t.Fatalf("drift %v", drifted)
	}
	b.Updates = nil
	if plan := a.Plan(context.Background(), b); slices.ContainsFunc(plan, func(p apply.Planned) bool { return p.ID == "updates" }) {
		t.Fatalf("plan without the section %+v", plan)
	}
}

// TestHostnameSection (plan M8h decision 14): the hostname section is applied as resource "hostname" before the
// time resource, corrected as drift after a local rename, and leaves a managed /etc/hosts alone; a bundle without it
// plans nothing for the hostname.
func TestHostnameSection(t *testing.T) {
	ctx := context.Background()
	sys, a := fixture(t)
	sys.NTP = false
	sys.Hostnames = fakesys.Hostnames{Static: "ubuntu", Transient: "ubuntu", Pretty: "ubuntu"}
	sys.Files[reconcile.HostsFile] = &fakesys.File{Data: []byte("127.0.0.1 localhost\n127.0.1.1 ubuntu\n"), Mode: 0o644}
	b := newBundle(t, 1, nil)
	b.SchemaVersion = bundle.SchemaVersion2
	b.Hostname = &bundle.HostnameSpec{Name: "lap-0421"}
	if err := a.CheckTypes(b); err != nil {
		t.Fatal(err)
	}
	rep := a.Apply(ctx, b)
	if len(rep.Errors) != 0 || !slices.Equal(rep.ChangedIDs, []string{"hostname", "time"}) {
		t.Fatalf("report %+v", rep)
	}
	want := []string{"hostnamectl hostname lap-0421", "write /etc/hosts", "timedatectl set-ntp true"}
	if calls := sys.TakeCalls(); !slices.Equal(calls, want) {
		t.Fatalf("calls %v, want hostname first %v", calls, want)
	}
	if drifted := apply.Drifted(a.Plan(ctx, b)); len(drifted) != 0 {
		t.Fatalf("drift after apply %v", drifted)
	}
	sys.Hostnames = fakesys.Hostnames{Static: "other", Transient: "other", Pretty: "other"}
	drifted := apply.Drifted(a.Plan(ctx, b))
	if !slices.Equal(drifted, []string{"hostname"}) {
		t.Fatalf("drift %v", drifted)
	}
	if rep := a.ApplyResources(ctx, b, drifted); !slices.Equal(rep.ChangedIDs, []string{"hostname"}) || sys.Hostnames.Static != "lap-0421" {
		t.Fatalf("drift apply %+v, names %+v", rep, sys.Hostnames)
	}

	managed, err := bundle.FileResource(bundle.FileSpec{Path: reconcile.HostsFile, Mode: "0644", Owner: "root", Group: "root",
		Content: "127.0.0.1 localhost\n"})
	if err != nil {
		t.Fatal(err)
	}
	b.Resources = append(b.Resources, managed)
	bundle.SortResources(b.Resources)
	sys.Hostnames.Pretty = "other"
	a.Apply(ctx, b)
	if string(sys.Files[reconcile.HostsFile].Data) != "127.0.0.1 localhost\n" || sys.Hostnames.Pretty != "" {
		t.Fatalf("managed hosts %q, names %+v", sys.Files[reconcile.HostsFile].Data, sys.Hostnames)
	}
	if drifted := apply.Drifted(a.Plan(ctx, b)); len(drifted) != 0 {
		t.Fatalf("drift with a managed /etc/hosts %v", drifted)
	}

	b.Hostname = nil
	sys.Hostnames = fakesys.Hostnames{Static: "other", Transient: "other", Pretty: "other"}
	if plan := a.Plan(ctx, b); slices.ContainsFunc(plan, func(p apply.Planned) bool { return p.ID == "hostname" }) {
		t.Fatalf("plan without the section %+v", plan)
	}
}

func TestPerResourceOutcomes(t *testing.T) {
	_, a := fixture(t)
	b := newBundle(t, 1, map[string]string{"/etc/a": "a"}, bundle.UnitSpec{Unit: "app.service", Enabled: true})
	b.Resources = append(b.Resources, bundle.Resource{ID: "future:x", Type: "future"})
	rep := a.Apply(context.Background(), b)
	if rep.Mode != protocol.BundleModeEnforce {
		t.Fatalf("mode %q", rep.Mode)
	}
	want := []protocol.BundleAppliedResource{
		{ID: "time", Status: protocol.ResourceApplied},
		{ID: "file:/etc/a", Status: protocol.ResourceApplied},
		{ID: "unit:app.service", Status: protocol.ResourceApplied},
		{ID: "future:x", Status: protocol.ResourceFailed, Message: "unsupported resource type future"},
	}
	if !reflect.DeepEqual(rep.Resources, want) || len(rep.Errors) != 1 || rep.Errors[0].Message != want[3].Message {
		t.Fatalf("resources %+v errors %+v", rep.Resources, rep.Errors)
	}

	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "changed", "errors", "mode", "resources"} {
		if _, ok := m[k]; !ok {
			t.Errorf("event data lacks %q", k)
		}
	}
	if _, ok := m["ChangedIDs"]; ok || len(m) != 5 {
		t.Errorf("event data keys %v", m)
	}
}

func TestReportOnlyModeIsReported(t *testing.T) {
	_, a := fixture(t)
	b := newBundle(t, 1, nil)
	b.Mode = bundle.ModeReportOnly
	if rep := a.Apply(context.Background(), b); rep.Mode != protocol.BundleModeReportOnly {
		t.Fatalf("mode %q", rep.Mode)
	}
}

func TestStaleFileOutcomes(t *testing.T) {
	ctx := context.Background()
	sys, a := fixture(t)
	a.Apply(ctx, newBundle(t, 1, map[string]string{"/etc/clean": "c", "/etc/edited": "e"}))
	sys.Files["/etc/edited"].Data = []byte("local change")
	rep := a.Apply(ctx, newBundle(t, 2, nil))
	got := map[string]protocol.BundleAppliedResource{}
	for _, r := range rep.Resources {
		got[r.ID] = r
	}
	if got["file:/etc/clean"].Status != protocol.ResourceApplied {
		t.Errorf("removed file: %+v", got["file:/etc/clean"])
	}
	if e := got["file:/etc/edited"]; e.Status != protocol.ResourceFailed || e.Message != "left_modified_file" {
		t.Errorf("kept file: %+v", e)
	}
}

func denyListOutcome(rep apply.Report) (protocol.BundleAppliedResource, bool) {
	for _, r := range rep.Resources {
		if r.ID == reconcile.DenyListID {
			return r, true
		}
	}
	return protocol.BundleAppliedResource{}, false
}

func TestDenyListOutcomes(t *testing.T) {
	ctx := context.Background()
	sys, a := fixture(t)
	b := newBundle(t, 1, nil)
	if _, ok := denyListOutcome(a.Apply(ctx, b)); ok {
		t.Fatal("deny list reported without the PAM profile")
	}
	sys.Files["/etc/pam.d/common-auth"] = &fakesys.File{Data: []byte(reconcile.DenyAuthLine + "\n"), Mode: 0o644}
	want := protocol.BundleAppliedResource{ID: reconcile.DenyListID, Status: protocol.ResourceApplied}
	for _, step := range []string{"written", "already in place"} {
		if got, ok := denyListOutcome(a.Apply(ctx, b)); !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %+v, %v", step, got, ok)
		}
	}
	delete(sys.Files, reconcile.DenyList)
	m, err := reconcile.LoadManaged(filepath.Join(t.TempDir(), "managed.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep := apply.New(failingWrites{sys}, m, nil).Apply(ctx, b)
	if got, ok := denyListOutcome(rep); !ok || got.Status != protocol.ResourceFailed || got.Message == "" || len(rep.Errors) != 1 {
		t.Fatalf("failed: %+v, %v, errors %+v", got, ok, rep.Errors)
	}
}

// failingWrites makes every write fail like a full disk.
type failingWrites struct{ *fakesys.System }

func (failingWrites) WriteFileAtomic(string, []byte, fs.FileMode, int, int) error {
	return errors.New("disk full")
}

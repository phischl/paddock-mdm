package apply_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

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

// TestWatchSection (plan M9 decision 40): the watch section is planned and applied last, on every apply and drift
// pass; it reports a stopped unit once and never counts as a change. An applier without watch reconciler (an older
// agent) applies the bundle and ignores the section, and a bundle that names "watch" as a resource type is refused.
func TestWatchSection(t *testing.T) {
	ctx := context.Background()
	sys, a := fixture(t)
	sys.Units["wazuh-agent.service"] = &fakesys.Unit{State: "enabled"}
	b := newBundle(t, 5, nil)
	b.Watch = &bundle.WatchSpec{Units: []string{"wazuh-agent.service"}}
	if rep := a.Apply(ctx, b); len(rep.Errors) != 0 || slices.Contains(rep.ChangedIDs, bundle.TypeWatch) {
		t.Fatalf("apply without watch reconciler %+v", rep)
	}
	if plan := a.Plan(ctx, b); slices.ContainsFunc(plan, func(p apply.Planned) bool { return p.ID == bundle.TypeWatch }) {
		t.Fatalf("planned without a watch reconciler: %+v", plan)
	}

	var reported []string
	a.WithWatch(&reconcile.Watch{Sys: sys, Events: &reconcile.Events{Emit: func(typ string, data any) {
		reported = append(reported, typ+" "+data.(protocol.TamperServiceStopped).Unit+" "+data.(protocol.TamperServiceStopped).State)
	}}})
	plan := a.Plan(ctx, b)
	if last := plan[len(plan)-1]; last.ID != bundle.TypeWatch || !slices.Equal(last.Changes, []string{"report wazuh-agent.service inactive"}) {
		t.Fatalf("plan %+v", plan)
	}
	if rep := a.Apply(ctx, b); len(rep.Errors) != 0 || rep.Changed != 0 {
		t.Fatalf("apply %+v", rep)
	}
	want := []string{protocol.EventTamperServiceStopped + " wazuh-agent.service inactive"}
	if !slices.Equal(reported, want) {
		t.Fatalf("reported %v", reported)
	}
	if ids := apply.Drifted(a.Plan(ctx, b)); len(ids) != 0 {
		t.Fatalf("drifted while the stop is reported: %v", ids)
	}

	// The drift pass sees the unit running again and, after the next stop, reports it again.
	sys.Units["wazuh-agent.service"].Active = true
	ids := apply.Drifted(a.Plan(ctx, b))
	if !slices.Equal(ids, []string{bundle.TypeWatch}) {
		t.Fatalf("drifted %v", ids)
	}
	if rep := a.ApplyResources(ctx, b, ids); len(rep.Errors) != 0 || len(rep.ChangedIDs) != 0 {
		t.Fatalf("drift pass %+v", rep)
	}
	sys.Units["wazuh-agent.service"].Active = false
	a.ApplyResources(ctx, b, apply.Drifted(a.Plan(ctx, b)))
	if want = append(want, want[0]); !slices.Equal(reported, want) {
		t.Fatalf("reported after the second stop %v", reported)
	}

	// A bundle without the section forgets the reported stop: watched again, the unit is reported again.
	a.Apply(ctx, newBundle(t, 6, nil))
	b.BundleVersion = 7
	a.Apply(ctx, b)
	if want = append(want, want[0]); !slices.Equal(reported, want) {
		t.Fatalf("reported after the section returned %v", reported)
	}
	if sys.Units["wazuh-agent.service"].Active || slices.ContainsFunc(sys.TakeCalls(), func(c string) bool { return strings.Contains(c, "wazuh-agent") }) {
		t.Fatal("the watch changed the watched unit")
	}

	b.Resources = append(b.Resources, bundle.Resource{ID: "watch", Type: bundle.TypeWatch, Spec: []byte("{}")})
	if err := a.CheckTypes(b); err == nil {
		t.Fatal("a resource of type watch was accepted")
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

// device is a snapshot of everything a report-only apply must leave alone.
type device struct {
	files   map[string]string
	units   map[string]fakesys.Unit
	members map[string][]string
	ntp     bool
	held    map[string]bool
	names   fakesys.Hostnames
}

func snapshot(sys *fakesys.System) device {
	d := device{files: map[string]string{}, units: map[string]fakesys.Unit{}, members: map[string][]string{}, ntp: sys.NTP,
		held: maps.Clone(sys.Held), names: sys.Hostnames}
	for p, f := range sys.Files {
		d.files[p] = string(f.Data) + "|" + f.Mode.String()
	}
	for n, u := range sys.Units {
		d.units[n] = *u
	}
	for g, m := range sys.Members {
		d.members[g] = slices.Clone(m)
	}
	return d
}

// assertUntouched fails unless the fake recorded no state-changing call and its state equals before.
func assertUntouched(t *testing.T, sys *fakesys.System, before device) {
	t.Helper()
	if calls := sys.TakeCalls(); len(calls) != 0 {
		t.Fatalf("report-only apply changed the device: %v", calls)
	}
	if after := snapshot(sys); !reflect.DeepEqual(after, before) {
		t.Fatalf("device state changed:\nbefore %+v\nafter  %+v", before, after)
	}
}

// adoptedDevice is a laptop as the adoption finds it: a foreign sudoers file, a foreign member of sudo beside the
// break-glass account, an edited configuration file and a stopped unit.
func adoptedDevice(t *testing.T) (*fakesys.System, *apply.Applier, *[]string, string) {
	t.Helper()
	sys := fakesys.New()
	sys.Packages["systemd-timesyncd"] = true
	sys.Units["systemd-timesyncd.service"] = &fakesys.Unit{State: "enabled", Active: true}
	sys.NTP = true
	sys.Units["app.service"] = &fakesys.Unit{State: "enabled"}
	sys.Files["/etc/sudoers"] = &fakesys.File{Data: []byte("Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n"), Mode: 0o440}
	sys.Files["/etc/sudoers.d/README"] = &fakesys.File{Data: []byte("# README\n"), Mode: 0o440}
	sys.Files["/etc/shadow"] = &fakesys.File{Data: []byte("root:*:20000:0:99999:7:::\npaddock:$y$j9T$x:20000:0:99999:7:::\n"), Mode: 0o640}
	sys.Passwd = map[string]int{"paddock": 1000, "groot": 1002}
	sys.Members = map[string][]string{"sudo": {"groot", "paddock"}}
	managed := filepath.Join(t.TempDir(), "managed.json")
	m, err := reconcile.LoadManaged(managed)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	a := apply.New(sys, m, &reconcile.Events{Emit: func(typ string, _ any) { events = append(events, typ) }})
	return sys, a, &events, managed
}

func sudoSpec(t *testing.T) bundle.Resource {
	t.Helper()
	r, err := bundle.SudoResource(bundle.SudoSpec{LectureText: "Be careful.\n", PrivilegedGroups: []string{"sudo"},
		SudoersDAllowlist: []string{"README"}, BreakGlassAccounts: []string{"paddock"}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func outcomes(rep apply.Report) map[string]protocol.BundleAppliedResource {
	out := map[string]protocol.BundleAppliedResource{}
	for _, r := range rep.Resources {
		out[r.ID] = r
	}
	return out
}

// TestReportOnlyApplyChangesNothing (plan M11 decision 9): a report-only bundle is planned, never applied — no write,
// removal, rename, group change, unit change or package operation, no device event — and the report lists the plan
// lines per resource as pending, the stale managed file as pending "remove" and the unchanged time resource as
// applied.
func TestReportOnlyApplyChangesNothing(t *testing.T) {
	ctx := context.Background()
	sys, a, events, managed := adoptedDevice(t)
	if rep := a.Apply(ctx, newBundle(t, 1, map[string]string{"/etc/old.conf": "o\n", "/etc/app.conf": "a=1\n"})); len(rep.Errors) != 0 {
		t.Fatalf("enforced setup %+v", rep)
	}
	sys.Files["/etc/app.conf"].Data = []byte("a=2\n")
	sys.Files["/etc/sudoers.d/90-test"] = &fakesys.File{Data: []byte("bob ALL=(ALL) ALL\n"), Mode: 0o440}
	sys.TakeCalls()
	*events = nil
	managedBefore, err := os.ReadFile(managed)
	if err != nil {
		t.Fatal(err)
	}

	b := newBundle(t, 2, map[string]string{"/etc/app.conf": "a=1\n"}, bundle.UnitSpec{Unit: "app.service", Enabled: true, Active: true})
	b.Resources = append(b.Resources, sudoSpec(t))
	bundle.SortResources(b.Resources)
	b.Mode = bundle.ModeReportOnly
	plan := map[string][]string{}
	for _, p := range a.Plan(ctx, b) {
		plan[p.ID] = p.Changes
	}
	before := snapshot(sys)

	rep := a.Apply(ctx, b)
	assertUntouched(t, sys, before)
	if len(*events) != 0 {
		t.Fatalf("report-only apply emitted %v", *events)
	}
	if after, _ := os.ReadFile(managed); string(after) != string(managedBefore) {
		t.Fatalf("record of managed files changed: %s", after)
	}
	if rep.Mode != protocol.BundleModeReportOnly || rep.Changed != 0 || len(rep.ChangedIDs) != 0 || rep.Errors == nil || len(rep.Errors) != 0 || rep.Version != 2 {
		t.Fatalf("report %+v", rep)
	}
	got := outcomes(rep)
	if len(got) != len(rep.Resources) || len(rep.Resources) != 5 {
		t.Fatalf("resources %+v", rep.Resources)
	}
	if !reflect.DeepEqual(got["time"], protocol.BundleAppliedResource{ID: "time", Status: protocol.ResourceApplied}) {
		t.Errorf("time: %+v", got["time"])
	}
	for _, id := range []string{"file:/etc/app.conf", "unit:app.service", "sudo"} {
		if r := got[id]; r.Status != protocol.ResourcePending || len(r.Changes) == 0 || !slices.Equal(r.Changes, plan[id]) {
			t.Errorf("%s: %+v, plan %v", id, r, plan[id])
		}
	}
	if s := got["sudo"].Changes; !slices.Contains(s, "quarantine 90-test") || !slices.Contains(s, "remove groot from sudo") {
		t.Errorf("sudo changes %v", s)
	}
	if r := got["file:/etc/old.conf"]; r.Status != protocol.ResourcePending || !slices.Equal(r.Changes, []string{"remove"}) {
		t.Errorf("stale file: %+v", r)
	}
	if rep.Resources[len(rep.Resources)-1].ID != "file:/etc/old.conf" {
		t.Errorf("stale files come last: %+v", rep.Resources)
	}
}

// TestReportOnlyPlanErrorsAndCutOff: a resource whose plan fails is reported failed with the message and Errors stays
// empty (plan M11 amendment R6.6); more than 50 plan lines are cut with "… and N more" and every line is at most 256
// bytes of valid UTF-8.
func TestReportOnlyPlanErrorsAndCutOff(t *testing.T) {
	ctx := context.Background()
	sys, a, _, _ := adoptedDevice(t)
	for i := range 60 {
		name := "/etc/sudoers.d/" + string(rune('a'+i/26)) + string(rune('a'+i%26))
		sys.Files[name] = &fakesys.File{Data: []byte("x ALL=(ALL) ALL\n"), Mode: 0o440}
	}
	long := "0" + strings.Repeat("ä", 200)
	sys.Files["/etc/sudoers.d/"+long] = &fakesys.File{Data: []byte("x ALL=(ALL) ALL\n"), Mode: 0o440}
	b := newBundle(t, 3, nil, bundle.UnitSpec{Unit: "ghost.service", Enabled: true})
	b.Resources = append(b.Resources, sudoSpec(t), bundle.Resource{ID: "future:x", Type: "future"})
	bundle.SortResources(b.Resources)
	b.Mode = bundle.ModeReportOnly
	var sudoLines int
	unitErr := ""
	for _, p := range a.Plan(ctx, b) {
		switch p.ID {
		case "sudo":
			sudoLines = len(p.Changes)
		case "unit:ghost.service":
			unitErr = p.Error
		}
	}
	if sudoLines <= 50 || unitErr == "" {
		t.Fatalf("fixture: %d sudo lines, unit error %q", sudoLines, unitErr)
	}
	before := snapshot(sys)

	rep := a.Apply(ctx, b)
	assertUntouched(t, sys, before)
	got := outcomes(rep)
	if r := got["unit:ghost.service"]; r.Status != protocol.ResourceFailed || r.Message != unitErr {
		t.Errorf("plan error: %+v", r)
	}
	if r := got["future:x"]; r.Status != protocol.ResourceFailed || r.Message != "unsupported resource type future" {
		t.Errorf("unsupported type: %+v", r)
	}
	if rep.Errors == nil || len(rep.Errors) != 0 || rep.Changed != 0 {
		t.Errorf("errors %+v, changed %d", rep.Errors, rep.Changed)
	}
	s := got["sudo"]
	if s.Status != protocol.ResourcePending || len(s.Changes) != 50 || s.Changes[49] != fmt.Sprintf("… and %d more", sudoLines-49) {
		t.Fatalf("sudo %d lines, last %q", len(s.Changes), s.Changes[len(s.Changes)-1])
	}
	cut := false
	for _, l := range s.Changes {
		if len(l) > 256 || !utf8.ValidString(l) {
			t.Errorf("line of %d bytes, valid UTF-8 %v", len(l), utf8.ValidString(l))
		}
		cut = cut || strings.HasPrefix(l, "quarantine 0ää")
	}
	if !cut {
		t.Errorf("the long line is missing: %v", s.Changes)
	}
}

// TestReportOnlyCoversEveryReconciler (plan M11 amendment 2026-10-31 R2.6): the hostname, updates, login and
// inventory reconcilers and the deny list are planned without side effects and never applied in report-only mode.
func TestReportOnlyCoversEveryReconciler(t *testing.T) {
	ctx := context.Background()
	sys, a, events, _ := adoptedDevice(t)
	sys.Hostnames = fakesys.Hostnames{Static: "ubuntu", Transient: "ubuntu", Pretty: "ubuntu"}
	sys.Packages["unattended-upgrades"] = true
	for _, u := range []string{"apt-daily.timer", "apt-daily-upgrade.timer"} {
		sys.Units[u] = &fakesys.Unit{State: "enabled", Active: true}
	}
	sys.Files["/etc/passwd"] = &fakesys.File{Data: []byte("root:x:0:0:root:/root:/bin/bash\npaddock:x:1000:1000::/home/paddock:/bin/bash\n"), Mode: 0o644}
	sys.Files["/etc/group"] = &fakesys.File{Data: []byte("sudo:x:27:groot,paddock\n"), Mode: 0o644}
	sys.Files["/etc/pam.d/common-auth"] = &fakesys.File{Data: []byte(reconcile.DenyAuthLine + "\n"), Mode: 0o644}
	sum := sha256.Sum256([]byte("deb"))
	a.WithInventory(&reconcile.Inventory{Sys: sys, BundlesURL: "https://bundles.example.org",
		Download: func(context.Context, string, int64) ([]byte, error) {
			t.Error("report-only apply downloaded the fleetd package")
			return nil, errors.New("no download")
		}})
	b := newBundle(t, 5, nil)
	b.SchemaVersion = bundle.SchemaVersion2
	b.Mode = bundle.ModeReportOnly
	b.Hostname = &bundle.HostnameSpec{Name: "lap-0421"}
	b.Updates = &bundle.UpdatesSpec{SecurityDailyAt: "03:00", RegularSchedule: "Sat 04:00", RegularUpdatesEnabled: true,
		MaxRandomDelayMin: 60, Holds: []bundle.Hold{{Package: "curl"}}}
	b.Inventory = &bundle.Inventory{FleetURL: "https://fleet.example.org", EnrollSecret: "s", Package: bundle.InventoryPackage{
		Version: "1.61.0", URLPath: "packages/1.2.0/fleet-osquery_1.61.0_amd64.deb", SHA256: hex.EncodeToString(sum[:])}}

	before := snapshot(sys)
	rep := a.Apply(ctx, b)
	assertUntouched(t, sys, before)
	got := outcomes(rep)
	if r := got[reconcile.DenyListID]; r.Status != protocol.ResourcePending || !slices.Equal(r.Changes, []string{"create"}) {
		t.Errorf("deny list: %+v", r)
	}

	login, err := bundle.LoginResource(bundle.LoginSpec{Provider: bundle.ProviderHimmelblau, SessionAction: bundle.SessionActionLockScreen,
		BreakGlassAccounts: []string{"paddock"}, LocalAdmin: &bundle.LocalAdminSpec{Username: "paddock", RotationDays: 30},
		Himmelblau: bundle.HimmelblauSpec{OIDCIssuerURL: "https://auth.example.org/application/o/acme/", AppID: "acme",
			Domain: "acme.test", PamAllowGroups: []string{"paddock.acme"}, PackageVersion: "4.0.4"}})
	if err != nil {
		t.Fatal(err)
	}
	b.Resources = append(b.Resources, login)
	bundle.SortResources(b.Resources)
	rep = a.Apply(ctx, b)
	assertUntouched(t, sys, before)
	if len(*events) != 0 {
		t.Fatalf("report-only apply emitted %v", *events)
	}
	got = outcomes(rep)
	for _, id := range []string{"hostname", "updates", "login"} {
		if got[id].Status != protocol.ResourcePending {
			t.Errorf("%s: %+v", id, got[id])
		}
	}
	wantInventory := protocol.ResourcePending
	if runtime.GOARCH != "amd64" { // fleetd is amd64 only; elsewhere the section plans nothing
		wantInventory = protocol.ResourceApplied
	}
	if r := got[reconcile.InventoryID]; r.Status != wantInventory {
		t.Errorf("inventory: %+v", r)
	}
	if rep.Changed != 0 || len(rep.ChangedIDs) != 0 {
		t.Errorf("report %+v", rep)
	}
}

// TestReportOnlyDriftCorrectionChangesNothing: ApplyResources of a report-only bundle leaves the device alone too.
func TestReportOnlyDriftCorrectionChangesNothing(t *testing.T) {
	sys, a, _, _ := adoptedDevice(t)
	sys.NTP = false
	b := newBundle(t, 1, map[string]string{"/etc/app.conf": "a=1\n"})
	b.Mode = bundle.ModeReportOnly
	before := snapshot(sys)
	rep := a.ApplyResources(context.Background(), b, []string{"time", "file:/etc/app.conf"})
	assertUntouched(t, sys, before)
	if rep.Changed != 0 || len(rep.Resources) != 0 {
		t.Fatalf("report %+v", rep)
	}
}

// TestEnforcedAfterReportOnly: the mode belongs to the bundle; the next enforced bundle applies normally.
func TestEnforcedAfterReportOnly(t *testing.T) {
	ctx := context.Background()
	sys, a, _, _ := adoptedDevice(t)
	sys.Files["/etc/sudoers.d/90-test"] = &fakesys.File{Data: []byte("bob ALL=(ALL) ALL\n"), Mode: 0o440}
	b := newBundle(t, 1, map[string]string{"/etc/app.conf": "a=1\n"})
	b.Resources = append(b.Resources, sudoSpec(t))
	bundle.SortResources(b.Resources)
	b.Mode = bundle.ModeReportOnly
	a.Apply(ctx, b)
	if len(sys.TakeCalls()) != 0 {
		t.Fatal("report-only apply changed the device")
	}
	enforced := *b
	enforced.BundleVersion, enforced.Mode = 2, bundle.ModeEnforce
	rep := a.Apply(ctx, &enforced)
	if rep.Mode != protocol.BundleModeEnforce || rep.Changed == 0 || sys.Files["/etc/sudoers.d/90-test"] != nil || string(sys.Files["/etc/app.conf"].Data) != "a=1\n" {
		t.Fatalf("enforced apply %+v", rep)
	}
	if !slices.Contains(sys.TakeCalls(), "gpasswd -d groot sudo") {
		t.Fatal("foreign group member kept by the enforced bundle")
	}
}

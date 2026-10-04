package apply_test

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/paddock-mdm/paddock/agent/internal/apply"
	"github.com/paddock-mdm/paddock/agent/internal/reconcile"
	"github.com/paddock-mdm/paddock/agent/internal/reconcile/fakesys"
	"github.com/paddock-mdm/paddock/pkg/bundle"
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
	return sys, apply.New(sys, m)
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

func TestRejectReason(t *testing.T) {
	for err, want := range map[error]string{
		bundle.ErrSignature: "signature", bundle.ErrWrongDevice: "wrong_device", bundle.ErrDowngrade: "downgrade", bundle.ErrSchema: "schema",
	} {
		if got := apply.RejectReason(err); got != want {
			t.Errorf("%v: %s", err, got)
		}
	}
}

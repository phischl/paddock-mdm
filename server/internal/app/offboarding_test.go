package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

// offboardPurger records the prefixes it purges with their until and answers each with its configured result; a
// prefix in partial stops before the end of its listing (Done false), every other one reaches it.
type offboardPurger struct {
	calls   []string
	until   []time.Time
	results map[string]objectstore.Purge
	errs    map[string]error
	partial map[string]bool
}

func (f *offboardPurger) purge(prefix string, until time.Time) (objectstore.Purge, error) {
	f.calls = append(f.calls, prefix)
	f.until = append(f.until, until)
	p := f.results[prefix]
	p.Done = !f.partial[prefix] && f.errs[prefix] == nil || errors.Is(f.errs[prefix], objectstore.ErrRetained)
	return p, f.errs[prefix]
}

type offboardBundles struct{ offboardPurger }

func (f *offboardBundles) PurgeObjects(_ context.Context, prefix string, until time.Time) (objectstore.Purge, error) {
	return f.purge(prefix, until)
}

type offboardEscrow struct{ offboardPurger }

func (f *offboardEscrow) PurgeVersions(_ context.Context, prefix string, until time.Time) (objectstore.Purge, error) {
	return f.purge(prefix, until)
}

func offboardingCode(err error) string {
	var oe *app.OffboardingError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return ""
}

// TestOffboardingDeleteObjects: the organization's prefixes in bundles (org/, apt/) and escrow (org/) are purged and
// the deletions counted; nothing else is touched.
func TestOffboardingDeleteObjects(t *testing.T) {
	org := uuid.New()
	o := "org/" + org.String() + "/"
	a := "apt/" + org.String() + "/"
	bundles := &offboardBundles{offboardPurger{results: map[string]objectstore.Purge{o: {Deleted: 2}, a: {Deleted: 3}}}}
	escrow := &offboardEscrow{offboardPurger{results: map[string]objectstore.Purge{o: {Deleted: 4}}}}
	n, err := app.NewOffboarding(app.OffboardingObjects{Bundles: bundles, Escrow: escrow}).DeleteObjects(context.Background(), org, time.Time{})
	if err != nil || n != 9 {
		t.Fatalf("DeleteObjects = %d, %v; want 9", n, err)
	}
	if !slices.Equal(bundles.calls, []string{o, a}) || !slices.Equal(escrow.calls, []string{o}) {
		t.Fatalf("purged bundles %v, escrow %v", bundles.calls, escrow.calls)
	}
}

// TestOffboardingDeleteObjectsWithoutCredentials: missing credential files fail the step closed with
// object_store_unavailable (plan M17 amendment k point 2).
func TestOffboardingDeleteObjectsWithoutCredentials(t *testing.T) {
	escrow := &offboardEscrow{}
	for name, objects := range map[string]app.OffboardingObjects{
		"none":         {},
		"bundles only": {Bundles: &offboardBundles{}},
		"escrow only":  {Escrow: escrow},
	} {
		n, err := app.NewOffboarding(objects).DeleteObjects(context.Background(), uuid.New(), time.Time{})
		if code := offboardingCode(err); code != app.OffboardingObjectStoreUnavailable || n != 0 {
			t.Errorf("%s: %d, %v; want object_store_unavailable", name, n, err)
		}
	}
	if len(escrow.calls) != 0 {
		t.Fatalf("purged with a credential missing: %v", escrow.calls)
	}
}

// TestOffboardingDeleteObjectsRetained: a version Object Lock keeps fails the step with object_retained, never as
// complete; the other prefixes are still purged and counted (main's binding point 1 for PDK-1054).
func TestOffboardingDeleteObjectsRetained(t *testing.T) {
	org := uuid.New()
	o := "org/" + org.String() + "/"
	a := "apt/" + org.String() + "/"
	bundles := &offboardBundles{offboardPurger{results: map[string]objectstore.Purge{o: {Deleted: 1}, a: {Deleted: 1}}}}
	escrow := &offboardEscrow{offboardPurger{
		results: map[string]objectstore.Purge{o: {Deleted: 2, Retained: []string{o + "devices/d/luks-header/1"}}},
		errs:    map[string]error{o: objectstore.ErrRetained},
	}}
	n, err := app.NewOffboarding(app.OffboardingObjects{Bundles: bundles, Escrow: escrow}).DeleteObjects(context.Background(), org, time.Time{})
	if offboardingCode(err) != app.OffboardingObjectRetained || !errors.Is(err, objectstore.ErrRetained) || n != 4 {
		t.Fatalf("DeleteObjects = %d, %v; want 4 deleted and object_retained", n, err)
	}
	bundles = &offboardBundles{offboardPurger{
		results: map[string]objectstore.Purge{o: {Retained: []string{o + "x"}}},
		errs:    map[string]error{o: objectstore.ErrRetained},
	}}
	escrow = &offboardEscrow{}
	_, err = app.NewOffboarding(app.OffboardingObjects{Bundles: bundles, Escrow: escrow}).DeleteObjects(context.Background(), org, time.Time{})
	if offboardingCode(err) != app.OffboardingObjectRetained || !slices.Equal(bundles.calls, []string{o, a}) || len(escrow.calls) != 1 {
		t.Fatalf("after a retained bundle: %v, bundles %v, escrow %v", err, bundles.calls, escrow.calls)
	}
}

// TestOffboardingDeleteObjectsStoreError: any other store error, AccessDenied of a prefix the credential may not
// delete included, is object_store_unavailable and stops the step.
func TestOffboardingDeleteObjectsStoreError(t *testing.T) {
	org := uuid.New()
	o := "org/" + org.String() + "/"
	bundles := &offboardBundles{offboardPurger{errs: map[string]error{o: errors.New("AccessDenied")}}}
	escrow := &offboardEscrow{}
	_, err := app.NewOffboarding(app.OffboardingObjects{Bundles: bundles, Escrow: escrow}).DeleteObjects(context.Background(), org, time.Time{})
	if offboardingCode(err) != app.OffboardingObjectStoreUnavailable || len(escrow.calls) != 0 {
		t.Fatalf("DeleteObjects: %v, escrow %v; want object_store_unavailable before escrow", err, escrow.calls)
	}
}

// TestOffboardingDeleteObjectsYields (amendment 2026-11-16 s point 1.4): every purge gets the call's until; when one
// stops before the end of its listing, DeleteObjects returns OffboardingYield with what it deleted so far and purges
// no further prefix. The next call lists every prefix from its start again.
func TestOffboardingDeleteObjectsYields(t *testing.T) {
	org := uuid.New()
	o := "org/" + org.String() + "/"
	a := "apt/" + org.String() + "/"
	until := time.Now().Add(-time.Second)
	bundles := &offboardBundles{offboardPurger{results: map[string]objectstore.Purge{o: {Deleted: 2}, a: {Deleted: 1000}},
		partial: map[string]bool{a: true}}}
	escrow := &offboardEscrow{offboardPurger{results: map[string]objectstore.Purge{o: {Deleted: 4}}}}
	job := app.NewOffboarding(app.OffboardingObjects{Bundles: bundles, Escrow: escrow})
	n, err := job.DeleteObjects(context.Background(), org, until)
	var yield app.OffboardingYield
	if !errors.As(err, &yield) || yield.Step != "objects" || n != 1002 || len(escrow.calls) != 0 {
		t.Fatalf("DeleteObjects = %d, %v, escrow %v; want 1002 and a yield of objects before escrow", n, err, escrow.calls)
	}
	if !slices.Equal(bundles.until, []time.Time{until, until}) {
		t.Fatalf("until passed %v, want %v twice", bundles.until, until)
	}
	bundles.partial, bundles.results[o], bundles.results[a] = nil, objectstore.Purge{}, objectstore.Purge{Deleted: 7}
	if n, err := job.DeleteObjects(context.Background(), org, until); err != nil || n != 11 {
		t.Fatalf("second call = %d, %v; want 11", n, err)
	}
	if !slices.Equal(bundles.calls, []string{o, a, o, a}) || !slices.Equal(escrow.calls, []string{o}) {
		t.Fatalf("purged bundles %v, escrow %v", bundles.calls, escrow.calls)
	}
}

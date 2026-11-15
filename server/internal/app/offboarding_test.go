package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

// offboardPurger records the prefixes it purges and answers each with its configured result.
type offboardPurger struct {
	calls   []string
	results map[string]objectstore.Purge
	errs    map[string]error
}

func (f *offboardPurger) purge(prefix string) (objectstore.Purge, error) {
	f.calls = append(f.calls, prefix)
	return f.results[prefix], f.errs[prefix]
}

type offboardBundles struct{ offboardPurger }

func (f *offboardBundles) PurgeObjects(_ context.Context, prefix string) (objectstore.Purge, error) {
	return f.purge(prefix)
}

type offboardEscrow struct{ offboardPurger }

func (f *offboardEscrow) PurgeVersions(_ context.Context, prefix string) (objectstore.Purge, error) {
	return f.purge(prefix)
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
	n, err := app.NewOffboarding(app.OffboardingObjects{Bundles: bundles, Escrow: escrow}).DeleteObjects(context.Background(), org)
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
		n, err := app.NewOffboarding(objects).DeleteObjects(context.Background(), uuid.New())
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
	n, err := app.NewOffboarding(app.OffboardingObjects{Bundles: bundles, Escrow: escrow}).DeleteObjects(context.Background(), org)
	if offboardingCode(err) != app.OffboardingObjectRetained || !errors.Is(err, objectstore.ErrRetained) || n != 4 {
		t.Fatalf("DeleteObjects = %d, %v; want 4 deleted and object_retained", n, err)
	}
	bundles = &offboardBundles{offboardPurger{
		results: map[string]objectstore.Purge{o: {Retained: []string{o + "x"}}},
		errs:    map[string]error{o: objectstore.ErrRetained},
	}}
	escrow = &offboardEscrow{}
	_, err = app.NewOffboarding(app.OffboardingObjects{Bundles: bundles, Escrow: escrow}).DeleteObjects(context.Background(), org)
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
	_, err := app.NewOffboarding(app.OffboardingObjects{Bundles: bundles, Escrow: escrow}).DeleteObjects(context.Background(), org)
	if offboardingCode(err) != app.OffboardingObjectStoreUnavailable || len(escrow.calls) != 0 {
		t.Fatalf("DeleteObjects: %v, escrow %v; want object_store_unavailable before escrow", err, escrow.calls)
	}
}

package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

// The error codes of an offboarding step stored in organization.offboarding_error_code and recorded as error_code of
// organization.deletion_step_failed (plan M17 decision 6, §6).
const (
	// OffboardingObjectStoreUnavailable: the object store failed, or the deletion's credentials are not configured.
	OffboardingObjectStoreUnavailable = "object_store_unavailable"
	// OffboardingObjectRetained: Object Lock retention or a legal hold kept objects of the organization; the step
	// never completes as if they were gone (plan M17 amendment k, RR-140).
	OffboardingObjectRetained = "object_retained"
)

// OffboardingError is a failed offboarding step with its error code.
type OffboardingError struct {
	Code string
	Err  error
}

func (e *OffboardingError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *OffboardingError) Unwrap() error { return e.Err }

// OffboardingBundles is the bundles bucket with the deletion's credential paddock-bundles-offboard: list and delete
// below org/ and apt/, no read (plan M17 amendment k point 1).
type OffboardingBundles interface {
	PurgeObjects(ctx context.Context, prefix string) (objectstore.Purge, error)
}

// OffboardingEscrow is the escrow bucket with the deletion's credential paddock-escrow-offboard: list versions and
// delete header and diagnostics versions, no read.
type OffboardingEscrow interface {
	PurgeVersions(ctx context.Context, prefix string) (objectstore.Purge, error)
}

// OffboardingObjects are the organization deletion's object-store credentials. A nil field means its credential
// files are not configured: the objects step then fails closed and the rest of the worker runs.
type OffboardingObjects struct {
	Bundles OffboardingBundles
	Escrow  OffboardingEscrow
}

// Offboarding deletes what remains of an organization whose grace period ended (plan M17, ADR 0052). It alone holds
// the deletion's object-store credentials (amendment k point 2); the steps' job is PDK-1015.
type Offboarding struct {
	objects OffboardingObjects
}

// NewOffboarding returns the organization deletion with its object-store credentials.
func NewOffboarding(objects OffboardingObjects) *Offboarding {
	return &Offboarding{objects: objects}
}

// DeleteObjects is the object-store part of the step objects (plan M17 decision 12): every object below org/<org>/
// and apt/<org>/ of bundles and every version below org/<org>/ of escrow. It returns how many objects and versions it
// deleted. An *OffboardingError carries the step's error code: object_store_unavailable without credentials or on a
// store error, object_retained when Object Lock kept something; the other prefixes are still purged then, so a retry
// only meets what is kept.
func (o *Offboarding) DeleteObjects(ctx context.Context, org uuid.UUID) (int, error) {
	if o.objects.Bundles == nil || o.objects.Escrow == nil {
		return 0, &OffboardingError{Code: OffboardingObjectStoreUnavailable,
			Err: errors.New("the organization deletion's object-store credentials are not configured")}
	}
	purges := []struct {
		name   string
		purge  func(context.Context, string) (objectstore.Purge, error)
		prefix string
	}{
		{"bundles", o.objects.Bundles.PurgeObjects, "org/" + org.String() + "/"},
		{"bundles", o.objects.Bundles.PurgeObjects, "apt/" + org.String() + "/"},
		{"escrow", o.objects.Escrow.PurgeVersions, "org/" + org.String() + "/"},
	}
	deleted, retained := 0, 0
	for _, p := range purges {
		res, err := p.purge(ctx, p.prefix)
		deleted += res.Deleted
		retained += len(res.Retained)
		if err != nil && !errors.Is(err, objectstore.ErrRetained) {
			return deleted, &OffboardingError{Code: OffboardingObjectStoreUnavailable, Err: fmt.Errorf("%s %s: %w", p.name, p.prefix, err)}
		}
	}
	if retained > 0 {
		return deleted, &OffboardingError{Code: OffboardingObjectRetained,
			Err: fmt.Errorf("%w: %d objects or versions of organization %s", objectstore.ErrRetained, retained, org)}
	}
	return deleted, nil
}

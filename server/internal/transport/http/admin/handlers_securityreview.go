package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// GetSecurityReview answers the review of existing data (ADR 0034 decision 7); one object, not a list endpoint.
func (h *handlers) GetSecurityReview(ctx context.Context, _ adminapi.GetSecurityReviewRequestObject) (adminapi.GetSecurityReviewResponseObject, error) {
	r, err := h.securityReview.Get(ctx)
	if err != nil {
		return nil, err
	}
	out := adminapi.SecurityReview{
		GeneratedAt:    r.GeneratedAt,
		RootGrants:     adminapi.SecurityReviewProfiles{Total: r.RootGrantTotal, Items: make([]adminapi.SecurityReviewProfile, len(r.RootGrants))},
		SensitiveFiles: adminapi.SecurityReviewFiles{Total: r.SensitiveTotal, Items: toManagedFiles(r.Sensitive)},
		DeniedFiles:    adminapi.SecurityReviewFiles{Total: r.DeniedTotal, Items: toManagedFiles(r.Denied)},
	}
	for i, p := range r.RootGrants {
		out.RootGrants.Items[i] = adminapi.SecurityReviewProfile{Profile: toPermissionProfile(p.Profile), Assignments: p.Assignments}
	}
	return adminapi.GetSecurityReview200JSONResponse(out), nil
}

func toManagedFiles(files []pgstore.ManagedFile) []adminapi.ManagedFile {
	out := make([]adminapi.ManagedFile, len(files))
	for i, f := range files {
		out[i] = toManagedFile(f)
	}
	return out
}

// ConfirmPermissionProfileRootGrant confirms an effectively Full profile with a step-up.
func (h *handlers) ConfirmPermissionProfileRootGrant(ctx context.Context, req adminapi.ConfirmPermissionProfileRootGrantRequestObject) (adminapi.ConfirmPermissionProfileRootGrantResponseObject, error) {
	p, err := h.privileges.ConfirmRootGrant(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.ConfirmPermissionProfileRootGrant200JSONResponse(toPermissionProfile(p)), nil
}

// ConfirmManagedFileSensitive confirms a managed file on a sensitive path with a step-up.
func (h *handlers) ConfirmManagedFileSensitive(ctx context.Context, req adminapi.ConfirmManagedFileSensitiveRequestObject) (adminapi.ConfirmManagedFileSensitiveResponseObject, error) {
	f, err := h.managed.ConfirmSensitive(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.ConfirmManagedFileSensitive200JSONResponse(toManagedFile(f)), nil
}

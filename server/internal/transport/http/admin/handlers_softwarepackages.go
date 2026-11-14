package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// softwarePackageList is the list definition of GET /api/v1/software-packages (plan M13c decision 12).
var softwarePackageList = listing.Spec{Sort: []string{"package", "size", "uploaded_at"}, DefaultSort: "-uploaded_at"}

// packageUploadPath is the upload route; its body is bounded by maxPackageUploadBytes instead of maxBodyBytes.
const packageUploadPath = "/api/v1/software-packages"

// maxPackageUploadBytes bounds the multipart body of a package upload: the largest package and room for the multipart
// framing and the optional text fields; the edge allows the same (guards.caddy, 268959744 bytes).
const maxPackageUploadBytes = software.MaxPackageBytes + 512<<10

// maxUploadField bounds an optional text field of the upload form.
const maxUploadField = 256

func (h *handlers) ListSoftwarePackages(ctx context.Context, req adminapi.ListSoftwarePackagesRequestObject) (adminapi.ListSoftwarePackagesResponseObject, error) {
	params, err := listing.Parse(softwarePackageList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.softwarePackages.List(ctx, params.ListPage(), (*string)(req.Params.Architecture))
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.SoftwarePackage, len(res.Items))
	for i, p := range res.Items {
		items[i] = toSoftwarePackage(p)
	}
	return adminapi.ListSoftwarePackages200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) UploadSoftwarePackage(ctx context.Context, req adminapi.UploadSoftwarePackageRequestObject) (adminapi.UploadSoftwarePackageResponseObject, error) {
	if err := h.softwarePackages.AuthorizeUpload(ctx); err != nil {
		return nil, err
	}
	in, err := readPackageUpload(req.Body)
	if err != nil {
		return nil, h.softwarePackages.RejectUpload(ctx, err)
	}
	p, err := h.softwarePackages.Upload(ctx, in)
	if err != nil {
		return nil, err
	}
	loc := packageUploadPath + "/" + p.ID.String()
	return adminapi.UploadSoftwarePackage201JSONResponse{Body: toSoftwarePackage(p),
		Headers: adminapi.UploadSoftwarePackage201ResponseHeaders{Location: &loc}}, nil
}

// readPackageUpload reads the parts of the upload form: file (one, at most one byte above software.MaxPackageBytes,
// so that the use case refuses a larger one and the attempt is audited) and the optional package, version and
// architecture. Other parts are refused.
func readPackageUpload(r *multipart.Reader) (app.PackageUpload, error) {
	var in app.PackageUpload
	if r == nil {
		return in, problem.InvalidRequest.WithDetail("a multipart/form-data body is required")
	}
	seen := map[string]bool{}
	for {
		part, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return in, unreadableUpload(err)
		}
		name := part.FormName()
		if seen[name] {
			return in, problem.InvalidRequest.WithDetail("the form field " + name + " appears twice")
		}
		seen[name] = true
		limit := int64(maxUploadField)
		if name == "file" {
			limit = software.MaxPackageBytes
		}
		data, err := io.ReadAll(io.LimitReader(part, limit+1))
		if err != nil {
			return in, unreadableUpload(err)
		}
		if name != "file" && int64(len(data)) > limit {
			return in, problem.InvalidRequest.WithDetail("the form field " + name + " is too long")
		}
		switch name {
		case "file":
			in.File = data
		case "package":
			in.Package = string(data)
		case "version":
			in.Version = string(data)
		case "architecture":
			in.Architecture = string(data)
		default:
			return in, problem.InvalidRequest.WithDetail("unknown form field; expected file, package, version and architecture")
		}
	}
	return in, nil
}

// unreadableUpload is the problem of a form that could not be read: a body above maxPackageUploadBytes or a malformed
// one.
func unreadableUpload(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return problem.InvalidRequest.WithDetail(fmt.Sprintf("the request body exceeds %d bytes", maxPackageUploadBytes))
	}
	return problem.InvalidRequest.WithDetail("unreadable multipart body")
}

func (h *handlers) DeleteSoftwarePackage(ctx context.Context, req adminapi.DeleteSoftwarePackageRequestObject) (adminapi.DeleteSoftwarePackageResponseObject, error) {
	if err := h.softwarePackages.Delete(ctx, req.Id); err != nil {
		return nil, err
	}
	return adminapi.DeleteSoftwarePackage204Response{}, nil
}

func (h *handlers) GetSoftwareRepository(ctx context.Context, _ adminapi.GetSoftwareRepositoryRequestObject) (adminapi.GetSoftwareRepositoryResponseObject, error) {
	v, err := h.softwarePackages.Repository(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetSoftwareRepository200JSONResponse(toSoftwareRepository(v)), nil
}

func (h *handlers) RotateSoftwareRepositoryKey(ctx context.Context, _ adminapi.RotateSoftwareRepositoryKeyRequestObject) (adminapi.RotateSoftwareRepositoryKeyResponseObject, error) {
	v, err := h.softwarePackages.RotateKey(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.RotateSoftwareRepositoryKey202JSONResponse(toSoftwareRepository(v)), nil
}

func toSoftwareRepository(v app.SoftwareRepositoryView) adminapi.SoftwareRepository {
	r := v.Repository
	out := adminapi.SoftwareRepository{
		State: adminapi.SoftwareRepositoryState(v.State), Url: v.URL, Fingerprint: r.SigningFingerprint,
		PreviousFingerprint: r.PreviousFingerprint, KeyRotationRequestedAt: utcPtr(r.KeyRotationRequestedAt),
		Generation: r.Generation, LastBuiltAt: utcPtr(r.LastBuiltAt),
		LastError: r.LastError, PackageCount: int(v.PackageCount), CredentialRotatedAt: r.CredentialRotatedAt.UTC(),
		PreviousCredentialValidUntil: utcPtr(r.PreviousCredentialExpiresAt),
	}
	if v.Source != nil {
		src := toSoftwareSourceSummary(*v.Source)
		out.Source = &src
	}
	return out
}

func (h *handlers) RotateSoftwareRepositoryCredential(ctx context.Context, _ adminapi.RotateSoftwareRepositoryCredentialRequestObject) (adminapi.RotateSoftwareRepositoryCredentialResponseObject, error) {
	c, err := h.softwarePackages.RotateCredential(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.RotateSoftwareRepositoryCredential200JSONResponse{Username: app.RepositoryUsername, Secret: c.Secret,
		Url: c.URL, PreviousValidUntil: c.PreviousValidUntil}, nil
}

func toSoftwarePackage(p app.SoftwarePackageView) adminapi.SoftwarePackage {
	return adminapi.SoftwarePackage{
		Id: p.ID, Package: p.Package, Version: p.Version, Architecture: adminapi.SoftwarePackageArchitecture(p.Architecture),
		Size: p.Size, Sha256: p.Sha256, Filename: p.Filename, Control: p.Fields, UploadedBy: p.UploadedBy,
		UploadedAt: p.UploadedAt.UTC(),
	}
}

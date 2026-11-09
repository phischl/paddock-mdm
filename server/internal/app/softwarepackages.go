package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the stored packages and the repository credential (plan M13c decision 12, ADR 0050 decisions 2 and 4):
// uploading a package is root-equivalent on every device it is assigned to, and the credential guards every
// organization package, so each needs an organization administrator with a fresh step-up.
var (
	SpecSoftwarePackageUpload    = ActionSpec{Code: audit.CodeSoftwarePackageUploaded, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecSoftwarePackageDelete    = ActionSpec{Code: audit.CodeSoftwarePackageDeleted, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecSoftwareRepositoryRotate = ActionSpec{Code: audit.CodeSoftwareRepositoryCredentialRotated, AllowedRoles: RolesAdmin, RequiresStepUp: true}
)

// SoftwareRepoCredentialKey is the Transit key of the repositories' read credentials: the api encrypts, the compiler
// alone decrypts, and no role holds it together with software-repo-wrap, the key of the signing keys (plan M13c
// amendment 2026-11-09 (PDK-812)).
const SoftwareRepoCredentialKey = "software-repo-credential" //nolint:gosec // a Transit key name, not a credential

// Repository access (plan M13c decisions 14 and 15, §3.8 L6).
const (
	// RepositoryUsername is the basic-auth user of every repository.
	RepositoryUsername = "paddock"
	// RepositoryCredentialOverlap is how long the previous credential stays valid after a rotation, so a device that
	// checks in within it receives the new one before the old one stops working.
	RepositoryCredentialOverlap = 24 * time.Hour
	// RepositoryURLTTL is the validity of the presigned URL apt is redirected to.
	RepositoryURLTTL = 10 * time.Minute
	// repositorySecretBytes is the entropy of a credential (ADR 0050 decision 4).
	repositorySecretBytes = 32
)

// Errors of SoftwareRepository.Locate; the transport answers 401 and 404.
var (
	ErrRepositoryUnauthorized = errors.New("repository credential refused")
	ErrRepositoryNotFound     = errors.New("repository object not found")
)

// Repository states of SoftwareRepositoryView.State.
const (
	RepositoryDisabled = "disabled"
	RepositoryPending  = "pending"
	RepositoryBuilt    = "built"
	RepositoryFailed   = "failed"
)

var (
	repositorySlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	repositoryPath = regexp.MustCompile(`^(dists|pool)(/[A-Za-z0-9._+~-]+)+$`)
)

// RepositoryKeys encrypts a repository credential for the compiler (the bao client).
type RepositoryKeys interface {
	Encrypt(ctx context.Context, key string, org uuid.UUID, field bao.ContextField, plaintext []byte) (string, error)
}

// PackageStore is the bundles bucket below apt/<organization_id>/ (the api's own object store user).
type PackageStore interface {
	PutReader(ctx context.Context, key string, body io.ReadSeeker, size int64) error
	Delete(ctx context.Context, key string) error
	Size(ctx context.Context, key string) (size int64, found bool, err error)
}

// URLPresigner presigns the GET apt is redirected to.
type URLPresigner interface {
	PresignGet(ctx context.Context, key string, ttl time.Duration) (string, error)
}

// SoftwarePackages are the use cases of the packages stored in Paddock and of the organization's repository (plan
// M13c decisions 11, 12, 14 and 15; ADR 0050). The signing key and the published index are the worker's (PDK-813).
type SoftwarePackages struct {
	runner     *ActionRunner
	org        *db.OrgPool
	keys       RepositoryKeys
	store      PackageStore
	presign    URLPresigner
	bundlesURL string
	now        func() time.Time
}

// NewSoftwarePackages creates the use cases; bundlesURL is the public bundles host (https://bundles.<domain>).
func NewSoftwarePackages(runner *ActionRunner, org *db.OrgPool, keys RepositoryKeys, store PackageStore,
	presign URLPresigner, bundlesURL string) *SoftwarePackages {
	return &SoftwarePackages{runner: runner, org: org, keys: keys, store: store, presign: presign,
		bundlesURL: strings.TrimRight(bundlesURL, "/"), now: time.Now}
}

// PackageUpload is an uploaded file with the control fields the request expects ("" = not given).
type PackageUpload struct {
	File                           []byte
	Package, Version, Architecture string
}

// SoftwarePackageView is a stored package with its control fields and its path in the repository.
type SoftwarePackageView struct {
	pgstore.SoftwarePackage
	Fields   map[string]string
	Filename string
}

// SoftwareRepositoryView is the organization's repository as GET /api/v1/software-repository shows it.
type SoftwareRepositoryView struct {
	Repository   pgstore.SoftwareRepository
	State        string
	URL          string
	Source       *SoftwareSourceView
	PackageCount int64
}

// RotatedCredential is a new credential, returned once.
type RotatedCredential struct {
	Secret, URL        string
	PreviousValidUntil time.Time
}

// List returns one page of stored packages; q matches package and version, architecture filters.
func (s *SoftwarePackages) List(ctx context.Context, page ListPage, architecture *string) (Listed[SoftwarePackageView], error) {
	var out Listed[SoftwarePackageView]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountSoftwarePackages(ctx, pgstore.CountSoftwarePackagesParams{QPattern: page.QPattern,
			Architecture: architecture, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count software packages: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListSoftwarePackages(ctx, pgstore.ListSoftwarePackagesParams{QPattern: page.QPattern,
			Architecture: architecture, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit})
		if err != nil {
			return fmt.Errorf("list software packages: %w", err)
		}
		out.Items = make([]SoftwarePackageView, len(rows))
		for i, r := range rows {
			out.Items[i] = packageView(r)
		}
		return nil
	})
	return out, err
}

// AuthorizeUpload checks the role and the step-up of an upload before its body is read, so that a caller who may not
// upload cannot make the api buffer a package (up to software.MaxPackageBytes); a refusal is recorded once as denied.
// Upload checks both again.
func (s *SoftwarePackages) AuthorizeUpload(ctx context.Context) error {
	p, ok := principal.From(ctx)
	if !ok {
		return problem.Unauthenticated
	}
	err := authorizeRole(p, ScopeOrg, SpecSoftwarePackageUpload)
	if err == nil {
		err = s.runner.checkStepUp(p)
	}
	if err == nil {
		return nil
	}
	return s.runner.RecordRejected(ctx, ScopeOrg, SpecSoftwarePackageUpload, err)
}

// RejectUpload records an upload whose form could not be read (malformed, above the size limit) once and returns the
// error to send.
func (s *SoftwarePackages) RejectUpload(ctx context.Context, rejection error) error {
	return s.runner.RecordRejected(ctx, ScopeOrg, SpecSoftwarePackageUpload, rejection)
}

// Upload stores a package (audited: software_package.uploaded with its hash). The repository is created on the first
// attempt of an administrator, outside the audited transaction, so that a refused upload still leaves the key
// generation queued; while the signing key does not exist the upload is refused with repository_not_ready (architect
// decision A10-21). The file is parsed, never executed (software.ParseDeb).
func (s *SoftwarePackages) Upload(ctx context.Context, in PackageUpload) (SoftwarePackageView, error) {
	var out SoftwarePackageView
	s.ensureForAdmin(ctx)
	sum := sha256.Sum256(in.File)
	spec := SpecSoftwarePackageUpload
	spec.Params = map[string]any{"sha256": hex.EncodeToString(sum[:]), "size": len(in.File),
		"package": software.DisplayParam(in.Package, 128), "version": software.DisplayParam(in.Version, 128),
		"architecture": software.DisplayParam(in.Architecture, 16)}
	err := s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		repo, err := q.GetSoftwareRepository(ctx)
		if err != nil || repo.SigningFingerprint == nil {
			return problem.RepositoryNotReady.WithDetail("the repository's signing key is being generated; retry shortly")
		}
		c, err := software.ParseDeb(in.File)
		if err != nil {
			return packageProblem(err)
		}
		rec.SetParam("package", c.Package)
		rec.SetParam("version", c.Version)
		rec.SetParam("architecture", c.Architecture)
		for _, f := range []struct{ name, want, got string }{
			{"package", in.Package, c.Package}, {"version", in.Version, c.Version}, {"architecture", in.Architecture, c.Architecture},
		} {
			if f.want != "" && f.want != f.got {
				return problem.InvalidRequest.WithDetail(fmt.Sprintf("%s %q differs from the control file's %q", f.name,
					software.DisplayParam(f.want, 128), f.got))
			}
		}
		control, err := json.Marshal(c.Fields)
		if err != nil {
			return err
		}
		filename := software.PoolPath(c.Package, c.Version, c.Architecture)
		p, _ := principal.From(ctx)
		row, err := q.InsertSoftwarePackage(ctx, pgstore.InsertSoftwarePackageParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: org, Package: c.Package, Version: c.Version,
			Architecture: c.Architecture, Size: int64(len(in.File)), Sha256: hex.EncodeToString(sum[:]),
			ObjectKey: packageObjectKey(org, filename), Control: control, UploadedBy: uploader(p),
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("this package version and architecture is already stored")
		}
		if err != nil {
			return err
		}
		rec.SetTarget(packageTarget(row))
		if err := q.RequestSoftwareRepositoryRebuild(ctx, org); err != nil {
			return err
		}
		// Last, after every check: a failed write leaves no row, and a commit that fails after it leaves an object no
		// row names, which the next upload of the same file replaces.
		if err := s.store.PutReader(ctx, row.ObjectKey, bytes.NewReader(in.File), int64(len(in.File))); err != nil {
			return fmt.Errorf("store package %s: %w", row.ObjectKey, err)
		}
		out = packageView(row)
		return nil
	})
	return out, err
}

// Delete removes a stored package (audited: software_package.deleted) and queues the rebuild. A catalog entry of the
// Paddock source that names the package keeps it (409 in_use, §3.8 L9). The object goes after the commit: a commit
// that fails keeps row and object together, and an object whose deletion fails only stays behind without a row, so no
// index names it and the next upload of the same file replaces it.
func (s *SoftwarePackages) Delete(ctx context.Context, id uuid.UUID) error {
	spec := SpecSoftwarePackageDelete
	spec.Target = &audit.Target{Type: "software_package", ID: id.String()}
	var objectKey string
	err := s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		row, err := q.GetSoftwarePackage(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(packageTarget(row))
		rec.SetParam("package", row.Package)
		rec.SetParam("version", row.Version)
		rec.SetParam("architecture", row.Architecture)
		rec.SetParam("sha256", row.Sha256)
		// Queuing the rebuild locks the repository row first, so the deletes of one organization run one after the other;
		// a refusal rolls back.
		if err := q.RequestSoftwareRepositoryRebuild(ctx, row.OrganizationID); err != nil {
			return err
		}
		n, err := q.DeleteSoftwarePackage(ctx, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return problem.NotFound
		}
		if err := packageInUse(ctx, q, row); err != nil {
			return err
		}
		objectKey = row.ObjectKey
		return nil
	})
	if err != nil {
		return err
	}
	if err := s.store.Delete(ctx, objectKey); err != nil {
		slog.WarnContext(ctx, "deleted package's object not removed", "object", objectKey, "error", err)
	}
	return nil
}

// packageInUse refuses the deletion of a package that a catalog entry of the Paddock source names, on any
// architecture and in any version (plan M13c decision 12, §3.8 L9): an assignment may pin the version this row holds,
// so another stored version does not make it safe to remove.
func packageInUse(ctx context.Context, q *pgstore.Queries, row pgstore.SoftwarePackage) error {
	entries, err := q.ListPaddockCatalogPackages(ctx)
	if err != nil {
		return err
	}
	for _, e := range entries {
		refs, err := software.DecodePackages(e.Packages)
		if err != nil {
			return fmt.Errorf("catalog entry %s: %w", e.ID, err)
		}
		if slices.ContainsFunc(refs, func(r software.PackageRef) bool { return r.Package == row.Package }) {
			return problem.InUse.WithDetail("a catalog entry of the Paddock source installs this package; change or delete the entry first")
		}
	}
	return nil
}

// Repository returns the organization's repository, created with its credential on the first call (architect
// decision A10-21).
func (s *SoftwarePackages) Repository(ctx context.Context) (SoftwareRepositoryView, error) {
	var out SoftwareRepositoryView
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	if err := s.ensureRepository(ctx); err != nil {
		return out, err
	}
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if out.Repository, err = q.GetSoftwareRepository(ctx); err != nil {
			return err
		}
		if out.URL, err = s.repositoryURL(ctx, q, out.Repository.OrganizationID); err != nil {
			return err
		}
		if out.PackageCount, err = q.CountAllSoftwarePackages(ctx); err != nil {
			return err
		}
		out.State = repositoryState(out.Repository)
		if out.Repository.SigningFingerprint == nil {
			return nil
		}
		src, err := q.GetPaddockSoftwareSource(ctx)
		switch {
		case db.IsNoRows(err):
			return nil
		case err != nil:
			return err
		}
		n, err := q.CountSoftwareCatalogEntriesBySource(ctx, uuid.NullUUID{UUID: src.ID, Valid: true})
		if err != nil {
			return err
		}
		out.Source = &SoftwareSourceView{SoftwareSource: src, EntryCount: n}
		return nil
	})
	return out, err
}

// RotateCredential replaces the repository's read credential (audited: software_repository.credential_rotated) and
// returns the new secret once; the previous one stays valid for RepositoryCredentialOverlap. Every device's bundle
// changes with it (§3.8 L6), which the compiler sees as a state change of the organization.
func (s *SoftwarePackages) RotateCredential(ctx context.Context) (RotatedCredential, error) {
	var out RotatedCredential
	s.ensureForAdmin(ctx)
	err := s.runner.RunTx(ctx, ScopeOrg, SpecSoftwareRepositoryRotate, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "software_repository", ID: org.String()})
		_, err = q.GetSoftwareRepositoryForUpdate(ctx)
		if db.IsNoRows(err) {
			return problem.RepositoryNotReady.WithDetail("the repository is being created; retry shortly")
		}
		if err != nil {
			return err
		}
		secret, ciphertext, hash, err := s.newCredential(ctx, org)
		if err != nil {
			return err
		}
		until := s.now().Add(RepositoryCredentialOverlap).UTC()
		if _, err := q.RotateSoftwareRepositoryCredential(ctx, pgstore.RotateSoftwareRepositoryCredentialParams{
			PreviousExpiresAt: &until, CredentialCiphertext: ciphertext, CredentialSha256: hash, OrganizationID: org,
		}); err != nil {
			return err
		}
		if out.URL, err = s.repositoryURL(ctx, q, org); err != nil {
			return err
		}
		rec.SetParam("previous_valid_until", until.Format(time.RFC3339))
		rec.StateChanged(statechange.ScopeOrg, org)
		out.Secret, out.PreviousValidUntil = secret, until
		return nil
	})
	return out, err
}

// Locate answers a request of apt on the bundles host (plan M13c decision 14): the organization by its slug, the
// basic-auth credential checked in constant time against the current and, within its overlap, the previous one, and
// path mapped to the object below apt/<organization_id>/. It returns a presigned URL valid for RepositoryURLTTL,
// ErrRepositoryUnauthorized for any credential that does not match (also, with the same answer, for an unknown
// organization), and ErrRepositoryNotFound for a path outside the repository, an object that does not exist, or a
// repository without its signing key, which publishes nothing (A10-21).
func (s *SoftwarePackages) Locate(ctx context.Context, slug, username, password, path string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(RepositoryUsername)) == 1
	org := uuid.Nil
	if repositorySlug.MatchString(slug) {
		var err error
		if org, err = s.org.ResolveSlug(ctx, slug); err != nil {
			return "", err
		}
	}
	if org == uuid.Nil {
		// The same answer as a wrong credential. A known slug costs a second lookup, so the response time may tell it
		// from an unknown one; that reveals no more than the slug, which every repository URL and login already shows.
		return "", ErrRepositoryUnauthorized
	}
	ctx = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "bundles", OrganizationID: org})
	var repo pgstore.SoftwareRepository
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		repo, err = q.GetSoftwareRepository(ctx)
		return err
	})
	if db.IsNoRows(err) {
		return "", ErrRepositoryUnauthorized
	}
	if err != nil {
		return "", err
	}
	current := subtle.ConstantTimeCompare(sum[:], repo.CredentialSha256) == 1
	previous := repo.PreviousCredentialSha256 != nil && repo.PreviousCredentialExpiresAt != nil &&
		s.now().Before(*repo.PreviousCredentialExpiresAt) &&
		subtle.ConstantTimeCompare(sum[:], repo.PreviousCredentialSha256) == 1
	if !userOK || (!current && !previous) {
		return "", ErrRepositoryUnauthorized
	}
	if repo.SigningFingerprint == nil || !validRepositoryPath(path) {
		return "", ErrRepositoryNotFound
	}
	key := "apt/" + org.String() + "/" + path
	_, found, err := s.store.Size(ctx, key)
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrRepositoryNotFound
	}
	return s.presign.PresignGet(ctx, key, RepositoryURLTTL)
}

// validRepositoryPath reports whether path names a file of the repository layout: below dists/ or pool/, segments of
// the characters of Debian file names, no "." or ".." segment.
func validRepositoryPath(path string) bool {
	if len(path) > maxRepositoryPath || !repositoryPath.MatchString(path) {
		return false
	}
	segments := strings.Split(path, "/")
	return len(segments) <= maxRepositorySegments &&
		!slices.ContainsFunc(segments, func(seg string) bool { return seg == "." || seg == ".." })
}

// Bounds of a repository path: the longest the layout of ADR 0050 decision 1 produces is
// pool/main/<p>/<package>/<file> or dists/paddock/main/binary-<arch>/Packages.gz, far below both.
const (
	maxRepositoryPath     = 512
	maxRepositorySegments = 8
)

// ensureForAdmin creates the repository for an organization administrator before an audited action. A failure (OpenBao
// sealed) is only logged: the action then records its own refusal or failure, so every attempt is still audited once.
func (s *SoftwarePackages) ensureForAdmin(ctx context.Context) {
	if _, err := RequireOrg(ctx, RolesAdmin); err != nil {
		return
	}
	if err := s.ensureRepository(ctx); err != nil {
		slog.WarnContext(ctx, "software repository not created", "error", err)
	}
}

// ensureRepository creates the repository of the context's organization with its first credential unless it exists,
// in a transaction of its own, and queues the worker's first rebuild, which generates the signing key.
func (s *SoftwarePackages) ensureRepository(ctx context.Context) error {
	org, err := orgOf(ctx)
	if err != nil {
		return err
	}
	exists := false
	if err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.GetSoftwareRepository(ctx)
		if db.IsNoRows(err) {
			return nil
		}
		exists = err == nil
		return err
	}); err != nil || exists {
		return err
	}
	_, ciphertext, hash, err := s.newCredential(ctx, org)
	if err != nil {
		return err
	}
	return s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.InsertSoftwareRepository(ctx, pgstore.InsertSoftwareRepositoryParams{OrganizationID: org,
			CredentialCiphertext: ciphertext, CredentialSha256: hash})
		return err
	})
}

// newCredential returns a new random secret, its Transit ciphertext for the compiler and its SHA-256 for the api.
func (s *SoftwarePackages) newCredential(ctx context.Context, org uuid.UUID) (secret, ciphertext string, hash []byte, err error) {
	raw := make([]byte, repositorySecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", nil, err
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	ciphertext, err = s.keys.Encrypt(ctx, SoftwareRepoCredentialKey, org, bao.FieldRepositoryCredential, []byte(secret))
	if err != nil {
		return "", "", nil, fmt.Errorf("encrypt the repository credential: %w", err)
	}
	sum := sha256.Sum256([]byte(secret))
	return secret, ciphertext, sum[:], nil
}

// repositoryURL is the repository's URL on the bundles host.
func (s *SoftwarePackages) repositoryURL(ctx context.Context, q *pgstore.Queries, org uuid.UUID) (string, error) {
	o, err := q.GetOrganization(ctx, org)
	if err != nil {
		return "", fmt.Errorf("organization %s: %w", org, err)
	}
	return s.bundlesURL + "/apt/" + o.Slug + "/", nil
}

// repositoryState derives the state GET /api/v1/software-repository reports.
func repositoryState(r pgstore.SoftwareRepository) string {
	switch {
	case r.SigningFingerprint == nil:
		return RepositoryDisabled
	case r.RebuildRequestedAt != nil && (r.LastBuiltAt == nil || r.RebuildRequestedAt.After(*r.LastBuiltAt)):
		if r.LastError != nil {
			return RepositoryFailed
		}
		return RepositoryPending
	case r.LastError != nil:
		return RepositoryFailed
	}
	return RepositoryBuilt
}

// packageObjectKey is the object of a package in the bundles bucket: apt/<organization_id>/<pool path>.
func packageObjectKey(org uuid.UUID, filename string) string {
	return "apt/" + org.String() + "/" + filename
}

func packageView(r pgstore.SoftwarePackage) SoftwarePackageView {
	v := SoftwarePackageView{SoftwarePackage: r, Fields: map[string]string{},
		Filename: software.PoolPath(r.Package, r.Version, r.Architecture)}
	_ = json.Unmarshal(r.Control, &v.Fields) // written by Upload from a map of strings
	return v
}

func packageTarget(r pgstore.SoftwarePackage) audit.Target {
	return audit.Target{Type: "software_package", ID: r.ID.String(), Display: r.Package + " " + r.Version + " " + r.Architecture}
}

// uploader is the display name recorded with a package.
func uploader(p principal.Principal) string {
	if p.Display != "" {
		return software.DisplayParam(p.Display, 256)
	}
	return string(p.Kind)
}

// packageProblem maps a parse error of the domain to its problem; the detail is the rule without the sentinel.
func packageProblem(err error) error {
	switch {
	case errors.Is(err, software.ErrDebCompression):
		return problem.UnsupportedCompression.WithDetail(strings.TrimPrefix(err.Error(), software.ErrDebCompression.Error()+": "))
	case errors.Is(err, software.ErrDeb):
		return problem.InvalidRequest.WithDetail(strings.TrimPrefix(err.Error(), software.ErrDeb.Error()+": "))
	}
	return err
}

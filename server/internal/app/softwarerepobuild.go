package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// SoftwareRepoWrapKey is the Transit key of the repositories' private signing keys: the worker alone encrypts and
// decrypts with it (ADR 0050 decision 3, amendment 2026-11-09).
const SoftwareRepoWrapKey = "software-repo-wrap"

const (
	// RepositoryKeyRetention is how long the previous signing key keeps signing the index alongside the new one after the
	// new one was first published, so a device that has not received the new key yet keeps verifying the repository
	// (ADR 0050 decision 3; plan M13c §3.8 L5; decisions-alpha10 Q16).
	RepositoryKeyRetention = 30 * 24 * time.Hour
	// paddockSourceSlug and paddockSourceName name the system source of the repository (plan M13c decision 11).
	paddockSourceSlug = "paddock"
	paddockSourceName = "Paddock repository"
	// maxBuildError bounds the error a failed build records.
	maxBuildError = 500
)

// Events of the build, recorded by the worker (actor: system).
var (
	specRepositoryBuilt       = ActionSpec{Code: audit.CodeSoftwareRepositoryBuilt}
	specRepositoryBuildFailed = ActionSpec{Code: audit.CodeSoftwareRepositoryBuildFailed}
)

// errKeyChanged stops a build whose repository got another signing key since it was read.
var errKeyChanged = errors.New("the signing key changed during the build; the next round builds again")

// SigningKeyVault encrypts and decrypts a repository's private signing key with the derived Transit key
// software-repo-wrap (the worker's bao client).
type SigningKeyVault interface {
	Encrypt(ctx context.Context, key string, org uuid.UUID, field bao.ContextField, plaintext []byte) (string, error)
	DecryptContext(ctx context.Context, key string, org uuid.UUID, field bao.ContextField, ciphertext string) ([]byte, error)
}

// RepositorySigner generates repository keys and signs Release files (adapters/aptsign). The private key it returns
// or receives is the unencrypted binary secret key; the caller zeroes it.
type RepositorySigner interface {
	GenerateKey(slug string, now time.Time) (publicKey, fingerprint string, private []byte, err error)
	Sign(privates [][]byte, release []byte, now time.Time) (inRelease, releaseGPG []byte, err error)
}

// IndexStore is the bundles bucket the worker writes the index to (below apt/<organization_id>/dists/).
type IndexStore interface {
	PutReader(ctx context.Context, key string, body io.ReadSeeker, size int64) error
}

// SoftwareRepositoryBuilds is the worker's build of an organization's Paddock repository (plan M13c decision 13,
// §3.7 "Repository build", §3.8 L5 and L8; ADR 0050 decision 3).
type SoftwareRepositoryBuilds struct {
	runner     *ActionRunner
	org        *db.OrgPool
	keys       SigningKeyVault
	signer     RepositorySigner
	store      IndexStore
	bundlesURL string
	now        func() time.Time
}

// NewSoftwareRepositoryBuilds creates the build; bundlesURL is the public bundles host (https://bundles.<domain>).
func NewSoftwareRepositoryBuilds(runner *ActionRunner, org *db.OrgPool, keys SigningKeyVault, signer RepositorySigner,
	store IndexStore, bundlesURL string) *SoftwareRepositoryBuilds {
	return &SoftwareRepositoryBuilds{runner: runner, org: org, keys: keys, signer: signer, store: store,
		bundlesURL: strings.TrimRight(bundlesURL, "/"), now: time.Now}
}

// WithClock replaces time.Now (tests).
func (b *SoftwareRepositoryBuilds) WithClock(now func() time.Time) *SoftwareRepositoryBuilds {
	b.now = now
	return b
}

// Build builds the repository of the context's organization (a system principal) when it is due: it has no signing
// key yet, a rotation or a rebuild is queued, or the last build failed. A previous key older than
// RepositoryKeyRetention is dropped first, which queues a rebuild signed by the current key alone. A failed build records last_error (and software_repository.build_failed
// when the error is new) and is returned; the previous index stays published.
func (b *SoftwareRepositoryBuilds) Build(ctx context.Context) error {
	org, err := orgOf(ctx)
	if err != nil {
		return err
	}
	now := b.now()
	var repo pgstore.SoftwareRepository
	var slug string
	err = b.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		before := now.Add(-RepositoryKeyRetention)
		if err := q.ExpireSoftwareRepositoryPreviousKey(ctx, pgstore.ExpireSoftwareRepositoryPreviousKeyParams{
			OrganizationID: org, RetiredBefore: &before}); err != nil {
			return err
		}
		if repo, err = q.GetSoftwareRepository(ctx); err != nil {
			return err
		}
		o, err := q.GetOrganization(ctx, org)
		slug = o.Slug
		return err
	})
	if db.IsNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if repo.SigningFingerprint != nil && repo.KeyRotationRequestedAt == nil && repo.RebuildRequestedAt == nil &&
		repo.LastError == nil {
		return nil
	}
	if err := b.publish(ctx, org, slug, repo, now); err != nil {
		return errors.Join(err, b.recordFailure(ctx, org, err))
	}
	return nil
}

// publish generates a key when needed, writes the signed index and records the build. The files go up in the order of
// §3.7: the lists and Release first, InRelease last, so a reader sees either the old InRelease with the old hashes or
// the new one with the new hashes. The system source gets a new key only after InRelease is signed with it, so a
// device that received the key always finds the repository signed with it; while the previous key is kept, the index is
// signed with it too, so a device that still has only the previous key keeps verifying it (§3.8 L5).
func (b *SoftwareRepositoryBuilds) publish(ctx context.Context, org uuid.UUID, slug string, repo pgstore.SoftwareRepository,
	now time.Time) error {
	generated := repo.SigningFingerprint == nil || repo.KeyRotationRequestedAt != nil
	if generated {
		var err error
		if repo, err = b.newKey(ctx, org, slug, repo, now); err != nil {
			return err
		}
	}
	var rows []pgstore.SoftwarePackage
	if err := b.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		rows, err = q.ListSoftwarePackagesForIndex(ctx)
		return err
	}); err != nil {
		return err
	}
	pkgs := make([]software.IndexPackage, 0, len(rows))
	for _, r := range rows {
		p := software.IndexPackage{Package: r.Package, Version: r.Version, Architecture: r.Architecture,
			Filename: software.PoolPath(r.Package, r.Version, r.Architecture), Size: r.Size, SHA256: r.Sha256}
		if err := json.Unmarshal(r.Control, &p.Fields); err != nil {
			return fmt.Errorf("control fields of %s %s %s: %w", r.Package, r.Version, r.Architecture, err)
		}
		pkgs = append(pkgs, p)
	}
	index, err := software.BuildIndex(pkgs, now)
	if err != nil {
		return err
	}
	ciphertexts := []string{*repo.SigningPrivateCiphertext}
	if repo.PreviousPrivateCiphertext != nil {
		ciphertexts = append(ciphertexts, *repo.PreviousPrivateCiphertext)
	}
	inRelease, releaseGPG, err := b.sign(ctx, org, ciphertexts, index.Release, now)
	if err != nil {
		return err
	}
	files := append(slices.Concat(index.ByHash, index.Files), software.IndexFile{Path: "Release", Data: index.Release},
		software.IndexFile{Path: "Release.gpg", Data: releaseGPG}, software.IndexFile{Path: "InRelease", Data: inRelease})
	prefix := "apt/" + org.String() + "/dists/" + software.RepositorySuite + "/"
	for _, f := range files {
		if err := b.store.PutReader(ctx, prefix+f.Path, bytes.NewReader(f.Data), int64(len(f.Data))); err != nil {
			return &buildStepError{step: "upload " + f.Path, err: err}
		}
	}
	_, err = b.runner.RecordOnceInScope(ctx, ScopeOrg, specRepositoryBuilt, func(ctx context.Context, q *pgstore.Queries, rec Recorder) (bool, error) {
		n, err := q.MarkSoftwareRepositoryBuilt(ctx, pgstore.MarkSoftwareRepositoryBuiltParams{OrganizationID: org,
			BuiltOn: repo.Generation, ServedRequest: repo.RebuildRequestedAt})
		if err != nil || n == 0 {
			return false, err
		}
		changed, err := b.syncSource(ctx, q, org, slug, repo)
		if err != nil {
			return false, err
		}
		if changed {
			rec.StateChanged(statechange.ScopeOrg, org)
		}
		rec.SetTarget(audit.Target{Type: "software_repository", ID: org.String()})
		rec.SetParam("generation", repo.Generation+1)
		rec.SetParam("fingerprint", *repo.SigningFingerprint)
		rec.SetParam("package_count", len(rows))
		rec.SetParam("key_generated", generated)
		return true, nil
	})
	return err
}

// newKey generates a signing key, stores it Transit-wrapped (a published current key becomes the previous one, an
// unpublished one is replaced) and returns the repository as stored. The plaintext private key is zeroed before it returns.
func (b *SoftwareRepositoryBuilds) newKey(ctx context.Context, org uuid.UUID, slug string, repo pgstore.SoftwareRepository,
	now time.Time) (pgstore.SoftwareRepository, error) {
	pub, fingerprint, private, err := b.signer.GenerateKey(slug, now)
	defer clear(private)
	if err != nil {
		return repo, err
	}
	ciphertext, err := b.keys.Encrypt(ctx, SoftwareRepoWrapKey, org, bao.FieldRepositorySigningKey, private)
	if err != nil {
		return repo, &buildStepError{step: "encrypt the signing key", err: err}
	}
	err = b.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.StoreSoftwareRepositorySigningKey(ctx, pgstore.StoreSoftwareRepositorySigningKeyParams{
			SigningPublicKey: &pub, SigningFingerprint: &fingerprint,
			SigningPrivateCiphertext: &ciphertext, ServedRotation: repo.KeyRotationRequestedAt, OrganizationID: org,
			ExpectedFingerprint: repo.SigningFingerprint,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return errKeyChanged
		}
		repo, err = q.GetSoftwareRepository(ctx)
		return err
	})
	return repo, err
}

// sign decrypts the private keys for this one build, signs release with each of them and zeroes the plaintext keys.
func (b *SoftwareRepositoryBuilds) sign(ctx context.Context, org uuid.UUID, ciphertexts []string, release []byte,
	now time.Time) (inRelease, releaseGPG []byte, err error) {
	privates := make([][]byte, 0, len(ciphertexts))
	defer func() {
		for _, p := range privates {
			clear(p)
		}
	}()
	for _, ciphertext := range ciphertexts {
		private, err := b.keys.DecryptContext(ctx, SoftwareRepoWrapKey, org, bao.FieldRepositorySigningKey, ciphertext)
		privates = append(privates, private)
		if err != nil {
			return nil, nil, &buildStepError{step: "decrypt the signing key", err: err}
		}
	}
	inRelease, releaseGPG, err = b.signer.Sign(privates, release, now)
	if err != nil {
		return nil, nil, fmt.Errorf("sign the release: %w", err)
	}
	return inRelease, releaseGPG, nil
}

// syncSource creates the system source of the repository or gives it the current key and URL; it reports whether the
// source changed, which changes the devices' bundles.
func (b *SoftwareRepositoryBuilds) syncSource(ctx context.Context, q *pgstore.Queries, org uuid.UUID, slug string,
	repo pgstore.SoftwareRepository) (bool, error) {
	uris := []string{b.bundlesURL + "/apt/" + slug + "/"}
	src, err := q.GetPaddockSoftwareSource(ctx)
	if db.IsNoRows(err) {
		_, err = q.InsertPaddockSoftwareSource(ctx, pgstore.InsertPaddockSoftwareSourceParams{ID: uuid.Must(uuid.NewV7()),
			OrganizationID: org, Slug: paddockSourceSlug, Name: paddockSourceName, Uris: uris,
			SigningKey: *repo.SigningPublicKey, Fingerprint: *repo.SigningFingerprint})
		if db.IsUniqueViolation(err, "") {
			return false, fmt.Errorf("a software source with the slug %q or the name %q exists; rename it so Paddock can add the source of its repository",
				paddockSourceSlug, paddockSourceName)
		}
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	if src.Fingerprint == *repo.SigningFingerprint && src.SigningKey == *repo.SigningPublicKey && slices.Equal(src.Uris, uris) {
		return false, nil
	}
	_, err = q.UpdatePaddockSoftwareSource(ctx, pgstore.UpdatePaddockSoftwareSourceParams{ID: src.ID, Uris: uris,
		SigningKey: *repo.SigningPublicKey, Fingerprint: *repo.SigningFingerprint})
	return err == nil, err
}

// recordFailure stores the error of a failed build as last_error and records software_repository.build_failed when it
// differs from the recorded one, so a failure repeated every round is recorded once. The recorded error is
// buildFailure's stable form; the caller logs the full one.
func (b *SoftwareRepositoryBuilds) recordFailure(ctx context.Context, org uuid.UUID, cause error) error {
	msg := buildFailure(cause)
	if len(msg) > maxBuildError {
		msg = msg[:maxBuildError]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
	}
	_, err := b.runner.RecordOnceInScope(ctx, ScopeOrg, specRepositoryBuildFailed, func(ctx context.Context, q *pgstore.Queries, rec Recorder) (bool, error) {
		n, err := q.MarkSoftwareRepositoryBuildFailed(ctx, pgstore.MarkSoftwareRepositoryBuildFailedParams{
			LastError: &msg, OrganizationID: org})
		if err != nil || n == 0 {
			return false, err
		}
		rec.SetTarget(audit.Target{Type: "software_repository", ID: org.String()})
		rec.SetParam("error", msg)
		return true, nil
	})
	return err
}

// buildStepError is a failed call to OpenBao or the bundles bucket during a build, named by its step.
type buildStepError struct {
	step string
	err  error
}

func (e *buildStepError) Error() string { return e.step + ": " + e.err.Error() }

func (e *buildStepError) Unwrap() error { return e.err }

// buildFailure returns the form of a failed build's error that last_error and software_repository.build_failed record.
// An error of OpenBao or the bucket is reduced to its step and its class (API error code, HTTP status, network error):
// the full message carries a request ID or a client port that differs on every round and would record the same
// failure every round.
func buildFailure(err error) string {
	var step *buildStepError
	if !errors.As(err, &step) {
		return err.Error()
	}
	var class []string
	var code interface{ ErrorCode() string }
	if errors.As(step.err, &code) && code.ErrorCode() != "" {
		class = append(class, code.ErrorCode())
	}
	var status interface{ HTTPStatusCode() int }
	if errors.As(step.err, &status) && status.HTTPStatusCode() != 0 {
		class = append(class, fmt.Sprintf("HTTP %d", status.HTTPStatusCode()))
	}
	var netErr net.Error
	switch {
	case len(class) > 0:
	case errors.As(step.err, &netErr) && netErr.Timeout(), errors.Is(step.err, context.DeadlineExceeded):
		class = append(class, "network timeout")
	case errors.As(step.err, &netErr):
		class = append(class, "network error")
	default:
		return step.Error()
	}
	return step.step + ": " + strings.Join(class, ", ")
}

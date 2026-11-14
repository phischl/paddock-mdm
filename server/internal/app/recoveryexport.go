package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/recoveryexport"
)

// Requester scopes of an encrypted recovery export (audit param requester_scope, plan M17 amendment b decision 25).
const (
	RequesterOrganization = "organization"
	RequesterPlatform     = "platform"
)

// The specs of the encrypted recovery export: one event per attempt in the organization's log, with a step-up.
var (
	SpecRecoveryExport = ActionSpec{Code: audit.CodeOrganizationRecoveryExported, AllowedRoles: RolesAdmin,
		RequiresStepUp: true}
	SpecPlatformRecoveryExport = ActionSpec{Code: audit.CodeOrganizationRecoveryExported, AllowedRoles: RolesPlatform,
		RequiresStepUp: true}
)

// ErrEscrowNotPending is wrapped by a RecoveryExporter when the escrow-reader found no pending deletion of the
// organization.
var ErrEscrowNotPending = errors.New("the escrow reader found no pending deletion of the organization")

// RecoveryExportCall asks the escrow-reader for the encrypted recovery export of an organization (plan M17 amendment b
// decision 24), proven by the step-up ID token of the requester. It carries the recipient as the requester sent it.
type RecoveryExportCall struct {
	OrganizationID     uuid.UUID
	Slug               string
	ExportedAt         time.Time
	Scope              string // RequesterOrganization or RequesterPlatform
	StepUpIDToken      string
	LocalAdminUsername string
	Recipient          string
	PublicKey          string
	Passphrase         string
}

// RecoveryExportCounts are the device lines and the secrets of an export.
type RecoveryExportCounts struct {
	Devices int
	Secrets int
}

// RecoveryExporter streams the encrypted recovery export of the escrow-reader (escrowreader.Client). It calls open
// once the escrow-reader accepted the request, before the first byte, and copies the message into the writer open
// returns. A refusal of the step-up proof wraps ErrEscrowRefused, a missing pending deletion ErrEscrowNotPending.
type RecoveryExporter interface {
	Export(ctx context.Context, call RecoveryExportCall, open func(RecoveryExportCounts) io.Writer) (RecoveryExportCounts, error)
}

// RecoveryExportInput is the request body of an export (RecoveryExportRequest). It is never logged.
type RecoveryExportInput struct {
	Recipient  string
	PublicKey  string
	Passphrase string
}

// RecoveryExportFile is the download an export starts.
type RecoveryExportFile struct {
	Slug       string
	ExportedAt time.Time
}

// Name is paddock-recovery-<slug>-<UTC yyyymmddThhmmssZ>.asc (decision 23).
func (f RecoveryExportFile) Name() string {
	return "paddock-recovery-" + f.Slug + "-" + f.ExportedAt.UTC().Format("20060102T150405Z") + ".asc"
}

// RecoveryExports exports all recovery keys and local administrator passwords of an organization whose deletion is
// pending, encrypted to the requester's public key or passphrase (plan M17 amendment b decisions 21–25; ADR 0052
// amendment b decision 8).
type RecoveryExports struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	tokens   StepUpTokens
	exporter RecoveryExporter
	now      func() time.Time
}

// NewRecoveryExports creates the use case.
func NewRecoveryExports(runner *ActionRunner, platform *db.PlatformPool, tokens StepUpTokens, exporter RecoveryExporter,
	now func() time.Time) *RecoveryExports {
	return &RecoveryExports{runner: runner, platform: platform, tokens: tokens, exporter: exporter, now: now}
}

// Export exports the organization of an organization administrator (POST /api/v1/recovery-export).
func (e *RecoveryExports) Export(ctx context.Context, in RecoveryExportInput, open func(RecoveryExportFile) io.Writer) error {
	p, _ := principal.From(ctx)
	ex := e.export(p.OrganizationID, RequesterOrganization, in, open)
	return e.runner.RunExternal(ctx, ScopeOrg, ex.spec(SpecRecoveryExport), ex.prepare, ex.external, ex.finalize)
}

// ExportPlatform exports an organization for a platform administrator
// (POST /api/platform/v1/organizations/{id}/recovery-export): the action runs inside the organization through
// ActionRunner.RunExternalInPendingDeletion, and its event lands in the organization's own log.
func (e *RecoveryExports) ExportPlatform(ctx context.Context, org uuid.UUID, in RecoveryExportInput,
	open func(RecoveryExportFile) io.Writer) error {
	// An organization that is deleting or deleted gets no row in its own log (the writer gate); its attempt is recorded
	// in the platform pseudo-organization, as for an unknown one.
	known := false
	if p, ok := principal.From(ctx); ok && p.Kind == principal.KindPlatformAdmin {
		var status string
		err := e.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			o, err := q.GetOrganization(ctx, org)
			status = o.Status
			return err
		})
		if err != nil && !db.IsNoRows(err) {
			return err
		}
		known = err == nil && status != organization.StatusDeleting && status != organization.StatusDeleted
	}
	ex := e.export(org, RequesterPlatform, in, open)
	return e.runner.RunExternalInPendingDeletion(ctx, org, known, ex.spec(SpecPlatformRecoveryExport), ex.prepare,
		ex.external, ex.finalize)
}

func (e *RecoveryExports) export(org uuid.UUID, scope string, in RecoveryExportInput, open func(RecoveryExportFile) io.Writer) *export {
	return &export{e: e, org: org, scope: scope, in: in, open: open}
}

// export is one attempt: prepare reserves it in the organization, external streams it, finalize records the counts
// and gives the reservation back when the export failed.
type export struct {
	e     *RecoveryExports
	org   uuid.UUID
	scope string
	in    RecoveryExportInput
	open  func(RecoveryExportFile) io.Writer

	file     RecoveryExportFile
	username string
	since    *time.Time
	counts   RecoveryExportCounts
	started  bool
}

func (x *export) spec(base ActionSpec) ActionSpec {
	base.Target = &audit.Target{Type: "organization", ID: x.org.String()}
	base.Params = map[string]any{"requester_scope": x.scope}
	// Only the two recipient types are recorded; any other value is a request error, never evidence.
	if x.in.Recipient == recoveryexport.RecipientPublicKey || x.in.Recipient == recoveryexport.RecipientPassphrase {
		base.Params["recipient"] = x.in.Recipient
	}
	return base
}

func (x *export) prepare(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
	cur, err := q.GetOrganization(ctx, x.org)
	if err != nil {
		return notFound(err)
	}
	rec.SetTarget(audit.Target{Type: "organization", ID: cur.ID.String(), Display: cur.Slug})
	if cur.Status == organization.StatusDeleting || cur.Status == organization.StatusDeleted {
		return db.OrganizationUnavailable(cur.ID, cur.Status)
	}
	// Pending: active or provisioning_failed with delete_after set (plan M17 amendment g point 5).
	if !organization.Deletable(cur.Status) || cur.DeleteAfter == nil {
		return problem.InvalidState.WithDetail("the recovery export is available only while the organization's deletion is pending")
	}
	r, err := recoveryexport.ParseRecipient(x.in.Recipient, x.in.PublicKey, x.in.Passphrase)
	if err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	r.Clear()
	if fp := r.Fingerprint(); fp != "" {
		rec.SetParam("key_fingerprint", fp)
	}
	settings, err := q.GetLoginSettings(ctx)
	if err != nil {
		return err
	}
	res, err := q.ReserveRecoveryExport(ctx, pgstore.ReserveRecoveryExportParams{ID: cur.ID, MaxExports: recoveryexport.MaxExports})
	if db.IsNoRows(err) {
		return problem.ExportLimit.WithDetail("the organization was exported 5 times during this grace period already")
	}
	if err != nil {
		return err
	}
	x.since, x.username = res.RecoveryExportsSince, settings.LocalAdminUsername
	x.file = RecoveryExportFile{Slug: cur.Slug, ExportedAt: audit.Timestamp(x.e.now())}
	return nil
}

func (x *export) external(ctx context.Context) error {
	p, ok := principal.From(ctx)
	if !ok || p.StepUpJTI == "" {
		return problem.StepUpRequired
	}
	raw, ok, err := x.e.tokens.Get(ctx, p.StepUpJTI)
	if err != nil {
		slog.ErrorContext(ctx, "reading the step-up token failed", "error", err)
		return problem.UpstreamUnavailable.WithDetail("the step-up proof could not be read")
	}
	if !ok {
		return problem.StepUpRequired.WithDetail("the step-up proof expired; authenticate again")
	}
	counts, err := x.e.exporter.Export(ctx, RecoveryExportCall{
		OrganizationID: x.org, Slug: x.file.Slug, ExportedAt: x.file.ExportedAt, Scope: x.scope, StepUpIDToken: raw,
		LocalAdminUsername: x.username, Recipient: x.in.Recipient, PublicKey: x.in.PublicKey, Passphrase: x.in.Passphrase,
	}, func(c RecoveryExportCounts) io.Writer {
		x.started, x.counts = true, c
		return x.open(x.file)
	})
	switch {
	case err == nil:
		x.counts = counts
		return nil
	case errors.Is(err, ErrEscrowRefused):
		slog.WarnContext(ctx, "the escrow reader refused a recovery export", "organization_id", x.org, "error", err)
		return problem.StepUpRequired.WithDetail("the escrow reader refused the step-up proof; authenticate again")
	case errors.Is(err, ErrEscrowNotPending):
		return problem.InvalidState.WithDetail("the recovery export is available only while the organization's deletion is pending")
	}
	slog.ErrorContext(ctx, "recovery export failed", "organization_id", x.org, "started", x.started, "error", err)
	return problem.UpstreamUnavailable.WithDetail("the escrow reader could not complete the export")
}

func (x *export) finalize(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error {
	rec.SetParam("devices", x.counts.Devices)
	rec.SetParam("secrets", x.counts.Secrets)
	if externalErr == nil || x.since == nil {
		return nil
	}
	return q.ReleaseRecoveryExport(ctx, pgstore.ReleaseRecoveryExportParams{ID: x.org, Since: *x.since})
}

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the administrator's access to diagnostics bundles (plan M12 decision 4, ADR 0048 decision 4).
var (
	SpecDiagnosticsDownload = ActionSpec{Code: audit.CodeDeviceDiagnosticsDownloaded, AllowedRoles: RolesWrite, RequiresStepUp: true}
	SpecDiagnosticsPurge    = ActionSpec{Code: audit.CodeDeviceDiagnosticsPurged, AllowedRoles: RolesAdmin}
)

// DiagnosticsBundles reads and deletes sealed diagnostics bundles in the escrow bucket with the api's credential
// (objectstore.Store); found is false when the object does not exist.
type DiagnosticsBundles interface {
	Size(ctx context.Context, key string) (size int64, found bool, err error)
	GetIfExists(ctx context.Context, key string) (data []byte, found bool, err error)
	DeleteAllVersions(ctx context.Context, prefix string) (int, error)
}

// DiagnosticsRow is a diagnostics bundle with the hostname of its device.
type DiagnosticsRow struct {
	pgstore.DeviceDiagnostic
	Hostname string
}

// DiagnosticsQuery selects a page of diagnostics bundles.
type DiagnosticsQuery struct {
	Page   ListPage
	States []string
}

// Bundle is a decrypted diagnostics archive for its download.
type Bundle struct {
	Name   string
	Size   int64
	Reader io.Reader
}

// errDiagnosticsObjectMismatch refuses a download whose object is not the one the worker verified: the device can
// overwrite it with a blob of the same size while its presigned PUT is still valid (PDK-747 review finding 5).
var errDiagnosticsObjectMismatch = problem.InvalidState.WithDetail(
	"the stored object does not match the bundle's size and SHA-256; nothing was served")

// WithDownload adds what the api needs to download and purge bundles: the escrow-reader access and the escrow bucket.
func (d *Diagnostics) WithDownload(escrow *EscrowAccess, bundles DiagnosticsBundles) *Diagnostics {
	d.escrow, d.bundles = escrow, bundles
	return d
}

// Get returns one bundle; an unknown or foreign bundle is not_found. The auditor role is refused: a bundle's metadata
// names the operator's reason, its content may name users (ADR 0048 decision 4).
func (d *Diagnostics) Get(ctx context.Context, id uuid.UUID) (DiagnosticsRow, error) {
	var out DiagnosticsRow
	if _, err := RequireOrg(ctx, RolesWrite); err != nil {
		return out, err
	}
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		r, err := q.GetDeviceDiagnosticsWithHost(ctx, id)
		if err != nil {
			return notFound(err)
		}
		out = DiagnosticsRow{DeviceDiagnostic: r.DeviceDiagnostic, Hostname: r.Hostname}
		return nil
	})
	return out, err
}

// List returns one page of the bundles of a device; an unknown or foreign device is not_found.
func (d *Diagnostics) List(ctx context.Context, deviceID uuid.UUID, query DiagnosticsQuery) (Listed[DiagnosticsRow], error) {
	var out Listed[DiagnosticsRow]
	if _, err := RequireOrg(ctx, RolesWrite); err != nil {
		return out, err
	}
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDevice(ctx, deviceID); err != nil {
			return notFound(err)
		}
		states := nilIfEmpty(query.States)
		n, err := q.CountDeviceDiagnostics(ctx, pgstore.CountDeviceDiagnosticsParams{DeviceID: deviceID, QPattern: query.Page.QPattern, States: states, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count diagnostics: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListDeviceDiagnostics(ctx, pgstore.ListDeviceDiagnosticsParams{DeviceID: deviceID, QPattern: query.Page.QPattern, States: states,
			Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit})
		if err != nil {
			return fmt.Errorf("list diagnostics: %w", err)
		}
		for _, r := range rows {
			out.Items = append(out.Items, DiagnosticsRow{DeviceDiagnostic: r.DeviceDiagnostic, Hostname: r.Hostname})
		}
		return nil
	})
	return out, err
}

// ListAll returns one page of every bundle of the organization.
func (d *Diagnostics) ListAll(ctx context.Context, query DiagnosticsQuery) (Listed[DiagnosticsRow], error) {
	var out Listed[DiagnosticsRow]
	if _, err := RequireOrg(ctx, RolesWrite); err != nil {
		return out, err
	}
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		states := nilIfEmpty(query.States)
		n, err := q.CountAllDeviceDiagnostics(ctx, pgstore.CountAllDeviceDiagnosticsParams{QPattern: query.Page.QPattern,
			States: states, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count diagnostics: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListAllDeviceDiagnostics(ctx, pgstore.ListAllDeviceDiagnosticsParams{QPattern: query.Page.QPattern,
			States: states, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit})
		if err != nil {
			return fmt.Errorf("list diagnostics: %w", err)
		}
		for _, r := range rows {
			out.Items = append(out.Items, DiagnosticsRow{DeviceDiagnostic: r.DeviceDiagnostic, Hostname: r.Hostname})
		}
		return nil
	})
	return out, err
}

// Download decrypts a stored bundle for an administrator or operator with a fresh step-up (audited:
// device.diagnostics_downloaded with the hash, size and file count of what was served). The whole sealed object is
// read and checked against the bundle's size and SHA-256 before anything is decrypted; an object that does not match
// or is gone is refused with invalid_state. The escrow-reader unwraps the data key for purpose diagnostics.
func (d *Diagnostics) Download(ctx context.Context, id uuid.UUID) (Bundle, error) {
	spec := SpecDiagnosticsDownload
	spec.Params = map[string]any{"request_id": id.String()}
	var out Bundle
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		b, err := d.lockedBundle(ctx, q, rec, id)
		if err != nil {
			return err
		}
		sealed, err := d.verifiedObject(ctx, b.DeviceDiagnostic)
		if err != nil {
			return err
		}
		plain, err := d.escrow.decrypt(ctx, b.DeviceID, []uuid.UUID{id}, PurposeDiagnostics)
		if err != nil {
			return err
		}
		dek := plain[id]
		defer clear(dek)
		archive, err := escrow.OpenObject(dek, b.Nonce, id.String(), sealed)
		if err != nil {
			return fmt.Errorf("open diagnostics bundle %s: %w", id, err)
		}
		n, err := q.CountDeviceDiagnosticsDownload(ctx, pgstore.CountDeviceDiagnosticsDownloadParams{
			DownloadedAt: d.now().UTC(), ID: id,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return problem.InvalidState.WithDetail("the bundle is not stored")
		}
		rec.SetParam("sha256", *b.Sha256)
		rec.SetParam("bytes", *b.Size)
		rec.SetParam("files", derefInt32(b.Files))
		out = Bundle{Name: fmt.Sprintf("paddock-diagnostics-%s-%s.tar.gz", b.Hostname, id), Size: int64(len(archive)),
			Reader: bytes.NewReader(archive)}
		return nil
	})
	return out, err
}

// Purge deletes a stored bundle at once (organization administrators; audited: device.diagnostics_purged): every
// version of its object by the derived key, and its key material; the metadata stays. A failed purge leaves the bundle
// stored, possibly with some versions of its object deleted already; repeating it completes the deletion.
func (d *Diagnostics) Purge(ctx context.Context, id uuid.UUID) (DiagnosticsRow, error) {
	spec := SpecDiagnosticsPurge
	spec.Params = map[string]any{"request_id": id.String()}
	var out DiagnosticsRow
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		b, err := d.lockedBundle(ctx, q, rec, id)
		if err != nil {
			return err
		}
		now := d.now().UTC()
		n, err := q.PurgeDeviceDiagnostics(ctx, pgstore.PurgeDeviceDiagnosticsParams{PurgedAt: now,
			ObjectsUntil: now.Add(DiagnosticsUploadWindow), ID: id})
		if err != nil {
			return err
		}
		if n != 1 {
			return problem.InvalidState.WithDetail("only a stored bundle can be purged")
		}
		key := escrow.DiagnosticsObjectKey(b.OrganizationID.String(), b.DeviceID.String(), id.String())
		if _, err := d.bundles.DeleteAllVersions(ctx, key); err != nil {
			slog.ErrorContext(ctx, "deleting a diagnostics bundle failed", "device_id", b.DeviceID, "diagnostics_id", id, "error", err)
			return problem.UpstreamUnavailable.WithDetail("the escrow bucket did not delete the bundle")
		}
		r, err := q.GetDeviceDiagnosticsWithHost(ctx, id)
		out = DiagnosticsRow{DeviceDiagnostic: r.DeviceDiagnostic, Hostname: r.Hostname}
		return err
	})
	return out, err
}

// lockedBundle loads and locks a stored bundle for a download or purge until the transaction ends and records its
// device as target; an unknown or foreign bundle is not_found, one that is not stored invalid_state.
func (d *Diagnostics) lockedBundle(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID) (DiagnosticsRow, error) {
	r, err := q.LockDeviceDiagnosticsWithHost(ctx, id)
	if err != nil {
		return DiagnosticsRow{}, notFound(err)
	}
	b := DiagnosticsRow{DeviceDiagnostic: r.DeviceDiagnostic, Hostname: r.Hostname}
	rec.SetTarget(audit.Target{Type: "device", ID: b.DeviceID.String(), Display: b.Hostname})
	rec.SetParam("hostname", b.Hostname)
	if b.State != DiagnosticsStored || b.ObjectKey == nil || b.Size == nil || b.Sha256 == nil || b.Nonce == nil || b.WrappedDek == nil {
		return b, problem.InvalidState.WithDetail("the bundle is not stored")
	}
	return b, nil
}

// verifiedObject reads the whole sealed object of a stored bundle and returns it only when its size and SHA-256 are
// the ones the worker verified; its size is checked before it is read.
func (d *Diagnostics) verifiedObject(ctx context.Context, b pgstore.DeviceDiagnostic) ([]byte, error) {
	unavailable := problem.UpstreamUnavailable.WithDetail("the escrow bucket does not answer with the bundle")
	size, found, err := d.bundles.Size(ctx, *b.ObjectKey)
	if err != nil {
		slog.ErrorContext(ctx, "sizing a diagnostics bundle failed", "device_id", b.DeviceID, "diagnostics_id", b.ID, "error", err)
		return nil, unavailable
	}
	if !found || size != *b.Size {
		return nil, d.mismatch(ctx, b, found)
	}
	sealed, found, err := d.bundles.GetIfExists(ctx, *b.ObjectKey)
	if err != nil {
		slog.ErrorContext(ctx, "reading a diagnostics bundle failed", "device_id", b.DeviceID, "diagnostics_id", b.ID, "error", err)
		return nil, unavailable
	}
	sum := sha256.Sum256(sealed)
	if !found || int64(len(sealed)) != *b.Size || hex.EncodeToString(sum[:]) != *b.Sha256 {
		return nil, d.mismatch(ctx, b, found)
	}
	return sealed, nil
}

// mismatch logs an object that is not the verified one and returns the refusal.
func (d *Diagnostics) mismatch(ctx context.Context, b pgstore.DeviceDiagnostic, found bool) error {
	slog.WarnContext(ctx, "diagnostics bundle object does not match its record; download refused", "device_id", b.DeviceID,
		"diagnostics_id", b.ID, "found", found)
	return errDiagnosticsObjectMismatch
}

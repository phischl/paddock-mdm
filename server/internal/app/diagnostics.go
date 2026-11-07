package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecDiagnosticsRequest records a diagnostics request (plan M12 decision 4).
var SpecDiagnosticsRequest = ActionSpec{Code: audit.CodeDeviceDiagnosticsRequested, AllowedRoles: RolesWrite}

// States of a diagnostics bundle (plan M12 decision 3).
const (
	DiagnosticsRequested = "requested"
	DiagnosticsUploaded  = "uploaded"
	DiagnosticsStored    = "stored"
	DiagnosticsFailed    = "failed"
	DiagnosticsExpired   = "expired"
	DiagnosticsPurged    = "purged"
)

// Reasons of a bundle the worker failed (plan M12 decision 5).
const (
	DiagnosticsSizeMismatch   = "size_mismatch"
	DiagnosticsSHA256Mismatch = "sha256_mismatch"
	DiagnosticsMissing        = "missing"
)

// DiagnosticsVerifyDelay is how long a bundle reported uploaded waits before the worker reads its object, so an
// object store that lists a fresh object late is not taken for a missing one.
const DiagnosticsVerifyDelay = 10 * time.Second

// DiagnosticsUploadWindow is how long after the device reported the upload its object may still be missing: the
// presigned PUT is valid 10 minutes, the rest is slack (the header escrow's window). It is also how long after a bundle
// ended unstored (failed, expired) the retention round waits before it deletes the object by its derived key, so that
// a PUT presigned before the end cannot land after the deletion.
const DiagnosticsUploadWindow = 15 * time.Minute

// DiagnosticsRetentionDays is how long a stored bundle is kept (ADR 0048 decision 5).
const DiagnosticsRetentionDays = 7

// Bounds of the administrator's reason (ADR 0048 decision 1).
const (
	minDiagnosticsReason = 2
	maxDiagnosticsReason = 500
)

// maxTruncatedEntries bounds the truncated entries a result may report: more than the closed content list has
// (ADR 0048 decision 2).
const maxTruncatedEntries = 64

// truncatedEntryName is the shape of an archive entry name (plan M12 §6.5: "journal/himmelblaud.log",
// "etc/sudoers.d/<file>", "journal:himmelblaud"): no spaces, at most 64 characters.
var truncatedEntryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@/+-]{0,63}$`)

// DiagnosticsObjects reads the sealed bundles in the escrow bucket (objectstore.Store).
type DiagnosticsObjects interface {
	Size(ctx context.Context, key string) (size int64, found bool, err error)
	SHA256(ctx context.Context, key string) (sum string, found bool, err error)
}

// Diagnostics are the use cases of diagnostics bundles (ADR 0048, plan M12 decisions 3–7): the request (api), and for
// the worker the device's announcement and the verification of the uploaded object.
type Diagnostics struct {
	runner  *ActionRunner
	org     *db.OrgPool
	objects DiagnosticsObjects
	// escrow and bundles (api) download and purge bundles (WithDownload).
	escrow  *EscrowAccess
	bundles DiagnosticsBundles
	// unit is the length of a retention day: 24 hours, a second in development (PADDOCK_RETENTION_UNIT).
	unit time.Duration
	now  func() time.Time
}

// NewDiagnostics creates the use cases; objects (worker) verifies uploads, unit is the length of a retention day.
func NewDiagnostics(runner *ActionRunner, org *db.OrgPool, objects DiagnosticsObjects, unit time.Duration) *Diagnostics {
	return &Diagnostics{runner: runner, org: org, objects: objects, unit: unit, now: time.Now}
}

// Request asks an active device for a diagnostics bundle (audited: device.diagnostics_requested): it inserts the
// bundle in state requested and issues collect_status with {request_id, reason}; the bundle's ID is the command's.
// A device that is not active, or that has a collection pending, is refused with invalid_state.
func (d *Diagnostics) Request(ctx context.Context, deviceID uuid.UUID, reason string) (DiagnosticsRow, error) {
	spec := SpecDiagnosticsRequest
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	spec.Params = map[string]any{"reason": truncateRunes(reason, maxDiagnosticsReason)}
	var out DiagnosticsRow
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.LockDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		if n := utf8.RuneCountInString(reason); n < minDiagnosticsReason || n > maxDiagnosticsReason {
			return problem.InvalidRequestUnprocessed.WithDetail("reason must have 2 to 500 characters")
		}
		if dev.State != device.StateActive {
			return problem.InvalidState.WithDetail("diagnostics are collected from active devices only")
		}
		pending, err := q.DeviceHasPendingDiagnostics(ctx, deviceID)
		if err != nil {
			return err
		}
		if pending {
			return problem.InvalidState.WithDetail("a collection is pending")
		}
		id := uuid.Must(uuid.NewV7())
		rec.SetParam("request_id", id.String())
		now := d.now().UTC()
		if _, err := issueCommandID(ctx, q, rec, id, deviceID, command.TypeCollectStatus,
			map[string]any{"request_id": id.String(), "reason": reason}, now, nil); err != nil {
			return err
		}
		row, err := q.InsertDeviceDiagnostics(ctx, pgstore.InsertDeviceDiagnosticsParams{ID: id,
			OrganizationID: dev.OrganizationID, DeviceID: deviceID, RequestedBy: actorDisplay(ctx),
			RequestedAt: now.Truncate(time.Second), Reason: reason})
		out = DiagnosticsRow{DeviceDiagnostic: row, Hostname: dev.Hostname}
		return err
	})
	return out, err
}

// truncateRunes cuts s to at most n runes, for the audit params of a refused request.
func truncateRunes(s string, n int) string {
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}

// Announce records the object a device announced for its bundle (worker, POST /v1/diagnostics); only the first
// announcement of a bundle that is still requested or uploaded counts. An announcement of a bundle that ended unstored
// keeps its object due for deletion until DiagnosticsUploadWindow from now, so that the PUT it was presigned for cannot
// outlive the retention round. It reports whether it counted.
func (d *Diagnostics) Announce(ctx context.Context, m ingest.DiagnosticsAnnounced) (bool, error) {
	var n int64
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		n, err = q.AnnounceDeviceDiagnostics(ctx, pgstore.AnnounceDeviceDiagnosticsParams{
			ObjectKey: &m.ObjectKey, Size: &m.Size, Sha256: &m.SHA256, Nonce: m.Nonce, WrappedDek: m.WrappedDEK,
			KeyVersion: announcedKeyVersion(m.KeyVersion), ID: m.DiagnosticsID, DeviceID: m.DeviceID,
		})
		if err != nil || n == 1 {
			return err
		}
		_, err = q.RearmEndedDeviceDiagnostics(ctx, pgstore.RearmEndedDeviceDiagnosticsParams{
			ObjectsUntil: d.now().Add(DiagnosticsUploadWindow), ID: m.DiagnosticsID, DeviceID: m.DeviceID,
		})
		return err
	})
	return n == 1, err
}

// announcedKeyVersion is the escrow-wrap version an announcement reported; nil when the agent did not (before PDK-749).
func announcedKeyVersion(v int) *int32 {
	if v < 1 || v > 1<<31-1 {
		return nil
	}
	k := int32(v) //nolint:gosec // bounded above
	return &k
}

// diagnosticsFailure is a collect_status result that failed the bundle.
type diagnosticsFailure struct{ reason string }

// diagnosticsRefusals are the reasons a device may report (command.CollectStatusResult.Reason); any other is recorded
// as unknown, so a device cannot write arbitrary text into the bundle and its audit event.
var diagnosticsRefusals = []string{command.CollectStatusInvalidParams, command.CollectStatusUploadRefused,
	command.CollectStatusUploadFailed, command.CollectStatusCollectFailed, command.CollectStatusTooLarge}

// finishDiagnostics applies a collect_status result inside the result's transaction: {uploaded: true} with status
// succeeded finishes the command and moves the bundle from requested to uploaded. Any other result changes nothing
// here and is returned as the failure for failDiagnostics, which records it with its audit event.
func finishDiagnostics(ctx context.Context, q *pgstore.Queries, r ingest.CommandResult, result json.RawMessage) (*diagnosticsFailure, error) {
	var res command.CollectStatusResult
	parsed := json.Unmarshal(result, &res) == nil
	if !parsed || r.Status != "succeeded" || !res.Uploaded {
		reason := "unknown"
		if parsed && slices.Contains(diagnosticsRefusals, res.Reason) {
			reason = res.Reason
		}
		return &diagnosticsFailure{reason: reason}, nil
	}
	n, err := q.FinishDeviceCommand(ctx, pgstore.FinishDeviceCommandParams{
		ID: r.CommandID, DeviceID: r.DeviceID, Status: r.Status, Result: result, FinishedAt: r.ReceivedAt,
	})
	if err != nil || n != 1 {
		return nil, err
	}
	files, sessions := int32(min(max(res.Files, 0), 1<<31-1)), int32(min(max(res.NotifiedSessions, 0), 1<<31-1)) //nolint:gosec // clamped
	_, err = q.MarkDeviceDiagnosticsUploaded(ctx, pgstore.MarkDeviceDiagnosticsUploadedParams{
		UploadedAt: r.ReceivedAt, Files: &files, TruncatedEntries: truncatedEntries(res.TruncatedEntries), NotifiedSessions: &sessions,
		ID: r.CommandID, DeviceID: r.DeviceID,
	})
	return nil, err
}

// truncatedEntries keeps the first maxTruncatedEntries reported entries that have the shape of an entry name and drops
// the rest, so a device cannot write free text into the bundle and its audit event (as with the refusal reason).
func truncatedEntries(reported []string) []string {
	out := []string{}
	for _, e := range reported {
		if len(out) == maxTruncatedEntries {
			break
		}
		if truncatedEntryName.MatchString(e) {
			out = append(out, e)
		}
	}
	return out
}

// failDiagnostics finishes a collect_status command whose result failed its bundle and fails the bundle, recording
// device.diagnostics_collected (failure, actor the device) once: a redelivered result finds the command finished.
func failDiagnostics(ctx context.Context, runner *ActionRunner, r ingest.CommandResult, result json.RawMessage, f diagnosticsFailure) error {
	spec := collectedSpec(r.DeviceID, r.CommandID)
	spec.Params["reason"] = f.reason
	_, err := runner.RecordOnceRefusal(ctx, spec, problem.InvalidRequest.WithDetail(f.reason),
		func(ctx context.Context, q *pgstore.Queries) (bool, error) {
			n, err := q.FinishDeviceCommand(ctx, pgstore.FinishDeviceCommandParams{
				ID: r.CommandID, DeviceID: r.DeviceID, Status: r.Status, Result: result, FinishedAt: r.ReceivedAt,
			})
			if err != nil || n != 1 {
				return false, err
			}
			// The window runs from processing, not receipt: the gateway keeps presigning PUTs for the command until this
			// result is processed, so a lagging result queue would otherwise schedule the deletion before the last PUT lands.
			processed := time.Now()
			if r.ReceivedAt.After(processed) {
				processed = r.ReceivedAt
			}
			_, err = q.FailRequestedDeviceDiagnostics(ctx, pgstore.FailRequestedDeviceDiagnosticsParams{
				FailedReason: &f.reason, ObjectsUntil: processed.Add(DiagnosticsUploadWindow), ID: r.CommandID, DeviceID: r.DeviceID,
			})
			return err == nil, err
		})
	return err
}

// collectedSpec is device.diagnostics_collected of a bundle, by its device.
func collectedSpec(deviceID, id uuid.UUID) ActionSpec {
	return ActionSpec{
		Code:   audit.CodeDeviceDiagnosticsCollected,
		Actor:  &audit.Actor{Type: audit.ActorDevice, ID: deviceID.String()},
		Target: &audit.Target{Type: "device", ID: deviceID.String()},
		Params: map[string]any{"request_id": id.String()},
	}
}

// Verify checks the bundles of the caller's organization the device reported uploaded at least DiagnosticsVerifyDelay
// ago (worker): an object with the announced size and SHA-256 makes the bundle stored with its retention, recording
// device.diagnostics_collected once; an object of another size or hash, or none within DiagnosticsUploadWindow, fails
// it (size_mismatch, sha256_mismatch, missing). The object's size is checked before it is read. A bundle that cannot
// be checked is logged and retried next round, so that it never holds up the others; the error then counts them.
func (d *Diagnostics) Verify(ctx context.Context) error {
	if p, ok := principal.From(ctx); !ok || p.Kind != principal.KindSystem {
		return problem.Unauthenticated
	}
	now := d.now()
	var uploaded []pgstore.DeviceDiagnostic
	if err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		uploaded, err = q.ListUploadedDeviceDiagnostics(ctx, now.Add(-DiagnosticsVerifyDelay))
		return err
	}); err != nil {
		return err
	}
	var errs []error
	for _, b := range uploaded {
		if err := d.verify(ctx, b, now); err != nil {
			slog.WarnContext(ctx, "diagnostics bundle not checked; retrying next round", "diagnostics_id", b.ID, "error", err)
			errs = append(errs, fmt.Errorf("bundle %s: %w", b.ID, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d uploaded bundles not checked: %w", len(errs), len(uploaded), errors.Join(errs...))
	}
	return nil
}

// verify checks one uploaded bundle and records its outcome; a bundle whose object may still arrive stays uploaded.
func (d *Diagnostics) verify(ctx context.Context, b pgstore.DeviceDiagnostic, now time.Time) error {
	overdue := b.UploadedAt == nil || now.Sub(*b.UploadedAt) > DiagnosticsUploadWindow
	if b.ObjectKey == nil || b.Size == nil || b.Sha256 == nil {
		if overdue {
			return d.fail(ctx, b, DiagnosticsMissing)
		}
		return nil
	}
	size, found, err := d.objects.Size(ctx, *b.ObjectKey)
	switch {
	case err != nil:
		return err
	case !found && overdue:
		return d.fail(ctx, b, DiagnosticsMissing)
	case !found:
		return nil
	case size != *b.Size:
		return d.fail(ctx, b, DiagnosticsSizeMismatch)
	}
	sum, found, err := d.objects.SHA256(ctx, *b.ObjectKey)
	switch {
	case err != nil:
		return err
	case !found:
		return d.fail(ctx, b, DiagnosticsMissing)
	case sum != *b.Sha256:
		return d.fail(ctx, b, DiagnosticsSHA256Mismatch)
	}
	return d.store(ctx, b, now)
}

// store marks a verified bundle stored until DiagnosticsRetentionDays retention days later and records
// device.diagnostics_collected with the hash only; a round that finds it stored already records nothing.
func (d *Diagnostics) store(ctx context.Context, b pgstore.DeviceDiagnostic, now time.Time) error {
	spec := collectedSpec(b.DeviceID, b.ID)
	spec.Params["files"] = derefInt32(b.Files)
	spec.Params["bytes"] = *b.Size
	spec.Params["sha256"] = *b.Sha256
	spec.Params["truncated_entries"] = b.TruncatedEntries
	spec.Params["notified_sessions"] = derefInt32(b.NotifiedSessions)
	stored := now.UTC().Truncate(time.Second)
	_, err := d.runner.RecordOnce(ctx, spec, func(ctx context.Context, q *pgstore.Queries) (bool, error) {
		n, err := q.StoreDeviceDiagnostics(ctx, pgstore.StoreDeviceDiagnosticsParams{
			StoredAt: stored, ExpiresAt: stored.Add(DiagnosticsRetentionDays * d.unit), ID: b.ID,
		})
		return n == 1, err
	})
	if err == nil {
		slog.InfoContext(ctx, "diagnostics bundle stored", "device_id", b.DeviceID, "diagnostics_id", b.ID)
	}
	return err
}

// fail fails an uploaded bundle with reason and records device.diagnostics_collected as failure once.
func (d *Diagnostics) fail(ctx context.Context, b pgstore.DeviceDiagnostic, reason string) error {
	spec := collectedSpec(b.DeviceID, b.ID)
	spec.Params["reason"] = reason
	_, err := d.runner.RecordOnceRefusal(ctx, spec, problem.InvalidRequest.WithDetail(reason),
		func(ctx context.Context, q *pgstore.Queries) (bool, error) {
			n, err := q.FailUploadedDeviceDiagnostics(ctx, pgstore.FailUploadedDeviceDiagnosticsParams{
				FailedReason: &reason, ObjectsUntil: d.now().Add(DiagnosticsUploadWindow), ID: b.ID,
			})
			return n == 1, err
		})
	if err == nil {
		slog.InfoContext(ctx, "diagnostics bundle failed", "device_id", b.DeviceID, "diagnostics_id", b.ID, "reason", reason)
	}
	return err
}

func derefInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/revocation"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// HeaderObjects reads sealed LUKS headers from the escrow bucket paddock-escrow (objectstore.Store); found is false
// when the object does not exist.
type HeaderObjects interface {
	GetIfExists(ctx context.Context, key string) (data []byte, found bool, err error)
}

// HeaderUploadWindow is how long a header may stay pending: the device has the 10 minutes of its presigned PUT, and
// the rest is slack for a slow upload.
const HeaderUploadWindow = 15 * time.Minute

// Escrow stores the secrets and LUKS headers devices escrow (worker, plan M4a decisions 11 and 12, M4b decisions 10
// and 13). The caller's context carries a system principal of the device's organization.
type Escrow struct {
	runner  *ActionRunner
	org     *db.OrgPool
	headers HeaderObjects
	now     func() time.Time
}

// NewEscrow creates the use case; headers may be nil where no header is verified.
func NewEscrow(runner *ActionRunner, org *db.OrgPool, headers HeaderObjects) *Escrow {
	return &Escrow{runner: runner, org: org, headers: headers, now: time.Now}
}

// MaxHeaderVolumes is the number of distinct volumes a device may escrow headers of: the volumes a revocation token
// carries at most (revocation.MaxVolumes, PDK-009 review round 1).
const MaxHeaderVolumes = revocation.MaxVolumes

// Store records an upload and returns the status the device polls: stored, pending for a header until its object is
// verified, or failed for a generation that is not above the active administrator password or the last generation
// of a LUKS kind, or refused for a header of a volume beyond MaxHeaderVolumes (audited as
// device.header_escrow_refused). A repeated message reports the recorded status.
func (e *Escrow) Store(ctx context.Context, m ingest.Escrow) (string, error) {
	status := escrow.StatusFailed
	refused := -1
	err := e.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if cur, err := q.GetEscrowSecret(ctx, m.EscrowID); err == nil {
			switch {
			case cur.DeviceID != m.DeviceID:
			case cur.Status != escrow.StatusFailed:
				status = cur.Status
				if status == escrowActive || status == "superseded" {
					status = escrow.StatusStored
				}
			case cur.Kind == escrow.KindLUKSHeader && cur.Volume.Valid:
				// A redelivered refusal reports refused again, without a second audit event (review round 3).
				if n, err := overCap(ctx, q, cur.DeviceID, cur.Volume.UUID); err != nil {
					return err
				} else if n >= 0 {
					status = escrow.StatusRefused
				}
			}
			return nil
		} else if !db.IsNoRows(err) {
			return err
		}
		floor, err := e.generationFloor(ctx, q, m)
		if err != nil {
			return err
		}
		if m.Generation <= int64(floor) || m.Generation > 1<<31-1 {
			return nil
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		if m.Kind == escrow.KindLUKSHeader && m.Volume != nil {
			if refused, err = overCap(ctx, q, m.DeviceID, *m.Volume); err != nil || refused >= 0 {
				return err
			}
		}
		n, inserted := int64(0), escrow.StatusStored
		if m.Kind == escrow.KindLUKSHeader {
			inserted = statusPending
			n, err = q.InsertEscrowHeader(ctx, pgstore.InsertEscrowHeaderParams{
				ID: m.EscrowID, OrganizationID: org, DeviceID: m.DeviceID, Generation: int32(m.Generation), //nolint:gosec // bounded above
				KeyVersion: int32(m.KeyVersion), ObjectKey: &m.ObjectKey, WrappedDek: m.WrappedDEK, Nonce: m.Nonce, //nolint:gosec // bounded by the gateway
				Sha256: &m.SHA256, Size: &m.Size, CreatedAt: m.ReceivedAt, Volume: nullUUID(m.Volume),
			})
		} else {
			n, err = q.InsertEscrowSecret(ctx, pgstore.InsertEscrowSecretParams{
				ID: m.EscrowID, OrganizationID: org, DeviceID: m.DeviceID, Kind: m.Kind,
				Generation: int32(m.Generation), Ciphertext: m.Ciphertext, KeyVersion: int32(m.KeyVersion), //nolint:gosec // bounded above and by the gateway
				CreatedAt: m.ReceivedAt,
			})
		}
		if err != nil {
			return fmt.Errorf("insert escrow %s: %w", m.Kind, err)
		}
		if n == 1 {
			status = inserted
		}
		return nil
	})
	if err != nil || refused < 0 {
		return status, err
	}
	return e.refuse(ctx, m, refused)
}

// overCap takes the device's volume cap lock for the transaction and returns the number of volumes the device escrows
// when volume is a new one beyond MaxHeaderVolumes, -1 otherwise (PDK-009 review round 3: workers must not let two new
// volumes pass at 31).
func overCap(ctx context.Context, q *pgstore.Queries, device, volume uuid.UUID) (int, error) {
	if err := q.LockDeviceHeaderVolumes(ctx, device); err != nil {
		return 0, err
	}
	v, err := q.DeviceHeaderVolumeKnown(ctx, pgstore.DeviceHeaderVolumeKnownParams{Volume: volume, DeviceID: device})
	if err != nil {
		return 0, err
	}
	if v.Known || int(v.Volumes) < MaxHeaderVolumes {
		return -1, nil
	}
	return int(v.Volumes), nil
}

// refuse records a refused header as a failed row together with its audit event, once per escrow ID: a redelivered
// message finds the row and is not audited again (review round 3).
func (e *Escrow) refuse(ctx context.Context, m ingest.Escrow, volumes int) (string, error) {
	spec := ActionSpec{
		Code:   audit.CodeDeviceHeaderEscrowRefused,
		Actor:  &audit.Actor{Type: audit.ActorDevice, ID: m.DeviceID.String()},
		Target: &audit.Target{Type: "device", ID: m.DeviceID.String()},
		Params: map[string]any{"volume": m.Volume.String(), "generation": m.Generation, "volumes": volumes},
	}
	_, err := e.runner.RecordOnceRefusal(ctx, spec, problem.TooManyVolumes, func(ctx context.Context, q *pgstore.Queries) (bool, error) {
		org, err := orgOf(ctx)
		if err != nil {
			return false, err
		}
		n, err := q.InsertRefusedEscrowHeader(ctx, pgstore.InsertRefusedEscrowHeaderParams{
			ID: m.EscrowID, OrganizationID: org, DeviceID: m.DeviceID, Generation: int32(m.Generation), //nolint:gosec // bounded by Store
			KeyVersion: int32(m.KeyVersion), ObjectKey: &m.ObjectKey, WrappedDek: m.WrappedDEK, Nonce: m.Nonce, //nolint:gosec // bounded by the gateway
			Sha256: &m.SHA256, Size: &m.Size, CreatedAt: m.ReceivedAt, Volume: *m.Volume,
		})
		return n == 1, err
	})
	return escrow.StatusRefused, err
}

// nullUUID is a column value of an optional UUID.
func nullUUID(id *uuid.UUID) uuid.NullUUID {
	if id == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *id, Valid: true}
}

// statusPending is a header whose object the worker has not verified yet; devices see pending too.
const statusPending = escrow.StatusPending

// generationFloor is the generation a new upload must exceed: the active administrator password, or the last
// generation of a LUKS kind that did not fail.
func (e *Escrow) generationFloor(ctx context.Context, q *pgstore.Queries, m ingest.Escrow) (int32, error) {
	if m.Kind == escrow.KindAdminPassword {
		active, err := q.ActiveEscrowGeneration(ctx, pgstore.ActiveEscrowGenerationParams{DeviceID: m.DeviceID, Kind: m.Kind})
		if err != nil {
			return 0, fmt.Errorf("active generation: %w", err)
		}
		return active, nil
	}
	latest, err := q.LatestEscrowGeneration(ctx, pgstore.LatestEscrowGenerationParams{DeviceID: m.DeviceID, Kind: m.Kind})
	if err != nil {
		return 0, fmt.Errorf("latest generation: %w", err)
	}
	return latest, nil
}

// HeaderOutcome is a header whose verification finished.
type HeaderOutcome struct {
	EscrowID, DeviceID uuid.UUID
	Status             string // stored or failed
}

// VerifyHeaders checks the pending headers of the caller's organization: a header whose object exists with the
// announced size and SHA-256 is stored, a mismatching object or one that did not arrive within HeaderUploadWindow
// fails; the others stay pending. It returns the finished headers.
func (e *Escrow) VerifyHeaders(ctx context.Context) ([]HeaderOutcome, error) {
	var pending []pgstore.EscrowSecret
	if err := e.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		pending, err = q.ListPendingEscrowHeaders(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	var out []HeaderOutcome
	for _, h := range pending {
		status, err := e.check(ctx, h)
		if err != nil {
			return out, fmt.Errorf("header %s: %w", h.ID, err)
		}
		if status == statusPending {
			continue
		}
		var n int64
		if err := e.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			n, err = q.FinishEscrowHeader(ctx, pgstore.FinishEscrowHeaderParams{ID: h.ID, Status: status})
			return err
		}); err != nil {
			return out, err
		}
		if n == 1 {
			slog.InfoContext(ctx, "escrowed LUKS header verified", "device_id", h.DeviceID, "escrow_id", h.ID, "generation", h.Generation, "status", status)
			out = append(out, HeaderOutcome{EscrowID: h.ID, DeviceID: h.DeviceID, Status: status})
		}
	}
	return out, nil
}

// check returns the status of one pending header.
func (e *Escrow) check(ctx context.Context, h pgstore.EscrowSecret) (string, error) {
	if h.ObjectKey == nil || h.Sha256 == nil || h.Size == nil {
		return escrow.StatusFailed, nil
	}
	data, found, err := e.headers.GetIfExists(ctx, *h.ObjectKey)
	switch {
	case err != nil:
		return "", err
	case !found && e.now().Sub(h.CreatedAt) > HeaderUploadWindow:
		return escrow.StatusFailed, nil
	case !found:
		return statusPending, nil
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != *h.Size || hex.EncodeToString(sum[:]) != *h.Sha256 {
		return escrow.StatusFailed, nil
	}
	return escrow.StatusStored, nil
}

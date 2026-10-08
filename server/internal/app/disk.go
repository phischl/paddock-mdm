package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the disk recovery actions (plan M4b decision 14).
var (
	SpecDiskRecoveryKeyReveal = ActionSpec{Code: audit.CodeDiskRecoveryKeyRevealed, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecDiskHeaderDownload    = ActionSpec{Code: audit.CodeDiskHeaderDownloaded, AllowedRoles: RolesAdmin, RequiresStepUp: true}
)

// Disk holds the use cases of a device's disk encryption: its state, and the recovery of the recovery key and the
// LUKS header for an organization administrator.
type Disk struct {
	runner  *ActionRunner
	org     *db.OrgPool
	escrow  *EscrowAccess
	headers HeaderObjects
}

// NewDisk creates the use cases; escrow and headers are used by the recovery only.
func NewDisk(runner *ActionRunner, org *db.OrgPool, escrow *EscrowAccess, headers HeaderObjects) *Disk {
	return &Disk{runner: runner, org: org, escrow: escrow, headers: headers}
}

// KeyslotChange is the last tamper.keyslot_changed of a device.
type KeyslotChange struct {
	At            time.Time
	Before, After []string
}

// DiskState is the disk encryption of a device: the health of its last check-in, its escrowed LUKS generations
// (newest first) and its last keyslot change.
type DiskState struct {
	Health            *protocol.DiskHealth
	ReportedAt        *time.Time
	Escrows           []pgstore.EscrowSecret
	LastKeyslotChange *KeyslotChange
}

// Get returns the disk encryption of a device; an unknown or foreign device is not_found.
func (d *Disk) Get(ctx context.Context, deviceID uuid.UUID) (DiskState, error) {
	var out DiskState
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDevice(ctx, deviceID); err != nil {
			return notFound(err)
		}
		status, err := q.GetDeviceStatus(ctx, deviceID)
		switch {
		case err == nil:
			out.ReportedAt = status.LastContactAt
			out.Health = diskHealth(status.Health)
			out.LastKeyslotChange = lastKeyslotChange(status.LoginState)
		case !db.IsNoRows(err):
			return err
		}
		out.Escrows, err = q.ListDiskEscrows(ctx, deviceID)
		return err
	})
	return out, err
}

// diskHealth reads health.disk of a check-in; nil when the device reports none or an unknown state.
func diskHealth(health json.RawMessage) *protocol.DiskHealth {
	var h struct {
		Disk *protocol.DiskHealth `json:"disk"`
	}
	if json.Unmarshal(health, &h) != nil || h.Disk == nil || !slices.Contains(protocol.DiskStates, h.Disk.State) {
		return nil
	}
	return h.Disk
}

// lastKeyslotChange reads the "disk" area of device_status.login_state.
func lastKeyslotChange(state json.RawMessage) *KeyslotChange {
	var areas map[string]struct {
		OccurredAt time.Time `json:"occurred_at"`
		Params     struct {
			Before []string `json:"before"`
			After  []string `json:"after"`
		} `json:"params"`
	}
	if json.Unmarshal(state, &areas) != nil {
		return nil
	}
	last, ok := areas["disk"]
	if !ok {
		return nil
	}
	return &KeyslotChange{At: last.OccurredAt, Before: last.Params.Before, After: last.Params.After}
}

// RevealRecoveryKey decrypts the newest stored recovery key of a device: organization administrators only, with a
// fresh step-up and the device's hostname typed as confirmation (audited: disk.recovery_key_revealed with the
// generation, never the key).
func (d *Disk) RevealRecoveryKey(ctx context.Context, deviceID uuid.UUID, confirmHostname string) (int, string, error) {
	spec := SpecDiskRecoveryKeyReveal
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	var generation int
	var key string
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		s, err := d.confirmedEscrow(ctx, q, rec, deviceID, confirmHostname, escrow.KindLUKSRecoveryKey, uuid.NullUUID{}, false, 0)
		if err != nil {
			return err
		}
		plain, err := d.escrow.decrypt(ctx, deviceID, []uuid.UUID{s.ID}, PurposeDiskRecoveryKey)
		if err != nil {
			return err
		}
		generation, key = int(s.Generation), string(plain[s.ID])
		clear(plain[s.ID])
		return nil
	})
	if err != nil {
		return 0, "", err
	}
	return generation, key, nil
}

// Header is a decrypted LUKS header backup of a device; Volume is the LUKS UUID of its volume ("" for a root volume
// header escrowed before PDK-009 whose UUID the device has not reported yet).
type Header struct {
	Hostname   string
	Volume     string
	Generation int
	Data       []byte
}

// DownloadHeader decrypts a stored header generation (0: the newest) of a LUKS volume of a device (nil: the root
// volume) under the same guards as the recovery key (audited: disk.header_downloaded with the volume and the
// generation, PDK-009 decision 5). Headers escrowed before PDK-009 count as the root volume's.
func (d *Disk) DownloadHeader(ctx context.Context, deviceID uuid.UUID, confirmHostname string, volume *uuid.UUID, generation int) (Header, error) {
	spec := SpecDiskHeaderDownload
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	var out Header
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		want, legacy, err := headerVolume(ctx, q, deviceID, volume)
		if err != nil {
			return err
		}
		s, err := d.confirmedEscrow(ctx, q, rec, deviceID, confirmHostname, escrow.KindLUKSHeader, want, legacy, generation)
		if err != nil {
			return err
		}
		if s.Volume.Valid {
			out.Volume = s.Volume.UUID.String()
			rec.SetParam("volume", out.Volume)
		}
		out.Hostname, out.Generation = confirmHostname, int(s.Generation)
		out.Data, err = d.openHeader(ctx, s)
		return err
	})
	return out, err
}

// headerVolume is the volume a header download asks for and whether headers without a volume count: the root
// volume's (the requested volume is nil or the root volume the device reports) includes them.
func headerVolume(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID, volume *uuid.UUID) (uuid.NullUUID, bool, error) {
	root, known := uuid.UUID{}, false
	status, err := q.GetDeviceStatus(ctx, deviceID)
	switch {
	case err == nil:
		root, known = RootVolume(diskHealth(status.Health))
	case !db.IsNoRows(err):
		return uuid.NullUUID{}, false, err
	}
	switch {
	case volume == nil && known:
		return uuid.NullUUID{UUID: root, Valid: true}, true, nil
	case volume == nil:
		return uuid.NullUUID{}, true, nil
	}
	return uuid.NullUUID{UUID: *volume, Valid: true}, known && *volume == root, nil
}

// confirmedEscrow loads the device, records it as target, checks the typed hostname and returns the stored escrow
// of kind and volume (generation 0: the newest; legacy: headers without a volume count as well).
func (d *Disk) confirmedEscrow(ctx context.Context, q *pgstore.Queries, rec Recorder, deviceID uuid.UUID, confirmHostname, kind string,
	volume uuid.NullUUID, legacy bool, generation int) (pgstore.EscrowSecret, error) {
	dev, err := q.GetDevice(ctx, deviceID)
	if err != nil {
		return pgstore.EscrowSecret{}, notFound(err)
	}
	rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
	rec.SetParam("hostname", dev.Hostname)
	if confirmHostname != dev.Hostname {
		return pgstore.EscrowSecret{}, problem.InvalidRequest.WithDetail("confirm_hostname does not match the device's hostname")
	}
	if generation < 0 || generation > 1<<31-1 {
		return pgstore.EscrowSecret{}, problem.InvalidRequest.WithDetail("generation must be positive")
	}
	s, err := q.LatestStoredEscrow(ctx, pgstore.LatestStoredEscrowParams{DeviceID: deviceID, Kind: kind,
		Generation: int32(generation), Volume: volume, Legacy: legacy}) //nolint:gosec // bounded above
	if db.IsNoRows(err) {
		// After a Destroy the escrow is gone for good (plan M4c gate R2); before, it may still arrive.
		destroyed, err := q.DeviceEscrowDestroyed(ctx, deviceID)
		if err != nil {
			return s, err
		}
		if destroyed {
			return s, problem.NotFound.WithDetail("the device was destroyed; its escrow is deleted")
		}
		return s, problem.InvalidState.WithDetail("the device has no stored escrow of this kind and generation")
	}
	if err != nil {
		return s, err
	}
	rec.SetParam("generation", s.Generation)
	return s, nil
}

// openHeader reads the sealed object of a header generation, unwraps its key with escrow-wrap and decrypts it.
func (d *Disk) openHeader(ctx context.Context, s pgstore.EscrowSecret) ([]byte, error) {
	if s.ObjectKey == nil {
		return nil, fmt.Errorf("header %s without object", s.ID)
	}
	object, found, err := d.headers.GetIfExists(ctx, *s.ObjectKey)
	if err != nil || !found {
		slog.ErrorContext(ctx, "reading an escrowed header failed", "device_id", s.DeviceID, "generation", s.Generation, "found", found, "error", err)
		return nil, problem.UpstreamUnavailable.WithDetail("the escrow bucket does not answer with the header")
	}
	plain, err := d.escrow.decrypt(ctx, s.DeviceID, []uuid.UUID{s.ID}, PurposeDiskHeader)
	if err != nil {
		return nil, err
	}
	dek := plain[s.ID]
	defer clear(dek)
	header, err := escrow.OpenHeader(dek, s.Nonce, s.ID.String(), object)
	if err != nil {
		return nil, fmt.Errorf("open header %s: %w", s.ID, err)
	}
	return header, nil
}

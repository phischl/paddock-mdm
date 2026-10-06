package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the local administrator actions.
var (
	SpecLocalAdminRotate = ActionSpec{Code: audit.CodeLocalAdminRotationRequested, AllowedRoles: RolesWrite}
	SpecLocalAdminReveal = ActionSpec{Code: audit.CodeLocalAdminRevealed, AllowedRoles: RolesAdmin, RequiresStepUp: true}
)

// LocalAdmin holds the use cases of the managed local administrator account (plan M4a decision 17).
type LocalAdmin struct {
	runner *ActionRunner
	org    *db.OrgPool
	escrow *EscrowAccess
	now    func() time.Time
}

// NewLocalAdmin creates the use cases; escrow is used by Reveal only.
func NewLocalAdmin(runner *ActionRunner, org *db.OrgPool, escrow *EscrowAccess) *LocalAdmin {
	return &LocalAdmin{runner: runner, org: org, escrow: escrow, now: time.Now}
}

// RotationError is the last failed rotation of a device, newer than its last successful one.
type RotationError struct {
	Reason     string
	Generation int64
	At         time.Time
}

// LocalAdminState is the local administrator of a device as the server knows it.
type LocalAdminState struct {
	Username          string
	ActiveGeneration  *int
	PendingGeneration *int
	LastRotatedAt     *time.Time
	NextRotationAt    *time.Time // LastRotatedAt + the rotation interval
	LastRotationError *RotationError
}

// Get returns the local administrator state of a device; an unknown or foreign device is not_found.
func (l *LocalAdmin) Get(ctx context.Context, deviceID uuid.UUID) (LocalAdminState, error) {
	var out LocalAdminState
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := l.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDevice(ctx, deviceID); err != nil {
			return notFound(err)
		}
		settings, err := q.GetLoginSettings(ctx)
		if err != nil {
			return err
		}
		out.Username = settings.LocalAdminUsername
		secrets, err := q.ListLocalAdminSecrets(ctx, deviceID)
		if err != nil {
			return err
		}
		for _, s := range secrets {
			g := int(s.Generation)
			if s.Status == escrowActive {
				out.ActiveGeneration, out.LastRotatedAt = &g, s.ActivatedAt
				continue
			}
			out.PendingGeneration = &g
		}
		if out.LastRotatedAt != nil {
			next := out.LastRotatedAt.Add(time.Duration(settings.LocalAdminRotationDays) * 24 * time.Hour)
			out.NextRotationAt = &next
		}
		status, err := q.GetDeviceStatus(ctx, deviceID)
		if err != nil && !db.IsNoRows(err) {
			return err
		}
		out.LastRotationError = lastRotationError(status.LoginState)
		return nil
	})
	return out, err
}

const escrowActive = "active"

// lastRotationError reads the latest rotation outcome of device_status.login_state; nil unless it is a failure.
func lastRotationError(state json.RawMessage) *RotationError {
	var areas map[string]struct {
		Type       string         `json:"type"`
		OccurredAt time.Time      `json:"occurred_at"`
		Params     map[string]any `json:"params"`
	}
	if json.Unmarshal(state, &areas) != nil {
		return nil
	}
	last, ok := areas["local_admin"]
	if !ok || last.Type != protocol.EventLocalAdminRotationFailed {
		return nil
	}
	reason, _ := last.Params["reason"].(string)
	generation, _ := last.Params["generation"].(float64)
	return &RotationError{Reason: reason, Generation: int64(generation), At: last.OccurredAt}
}

// RevealedPassword is one password of a reveal.
type RevealedPassword struct {
	Generation int
	State      string // active or pending
	Password   string
}

// Reveal decrypts the active and the pending local administrator passwords of a device (plan M4a decision 17):
// organization administrators only, with a fresh step-up and the device's hostname typed as confirmation (audited:
// local_admin.revealed with the generations, never the passwords). If the organization rotates after a reveal,
// a rotate_admin_password command is scheduled that many hours later.
func (l *LocalAdmin) Reveal(ctx context.Context, deviceID uuid.UUID, confirmHostname string) ([]RevealedPassword, error) {
	spec := SpecLocalAdminReveal
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	var out []RevealedPassword
	err := l.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.GetDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		if confirmHostname != dev.Hostname {
			return problem.InvalidRequest.WithDetail("confirm_hostname does not match the device's hostname")
		}
		secrets, err := q.ListLocalAdminSecrets(ctx, deviceID)
		if err != nil {
			return err
		}
		if len(secrets) == 0 {
			return problem.InvalidState.WithDetail("the device has no escrowed local administrator password yet")
		}
		ids := make([]uuid.UUID, 0, len(secrets))
		for _, s := range secrets {
			ids = append(ids, s.ID)
		}
		plain, err := l.escrow.decrypt(ctx, deviceID, ids, PurposeLocalAdminReveal)
		if err != nil {
			return err
		}
		generations := make([]int, 0, len(secrets))
		for _, s := range secrets {
			state := "pending"
			if s.Status == escrowActive {
				state = "active"
			}
			out = append(out, RevealedPassword{Generation: int(s.Generation), State: state, Password: string(plain[s.ID])})
			clear(plain[s.ID])
			generations = append(generations, int(s.Generation))
		}
		rec.SetParam("generations", generations)
		settings, err := q.GetLoginSettings(ctx)
		if err != nil {
			return err
		}
		if h := settings.RotateAfterRevealHours; h != nil && dev.State == device.StateActive {
			at := l.now().Add(time.Duration(*h) * time.Hour)
			if _, err := issueCommand(ctx, q, rec, deviceID, command.TypeRotateAdminPassword, nil, l.now(), &at); err != nil {
				return err
			}
			rec.SetParam("rotation_scheduled_at", at.UTC().Format(time.RFC3339))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Rotate issues rotate_admin_password to an active device (audited: local_admin.rotation_requested).
func (l *LocalAdmin) Rotate(ctx context.Context, deviceID uuid.UUID) (pgstore.DeviceCommand, error) {
	spec := SpecLocalAdminRotate
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	var out pgstore.DeviceCommand
	err := l.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.GetDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		if dev.State != device.StateActive {
			return problem.InvalidState.WithDetail("commands are delivered to active devices only")
		}
		out, err = issueCommand(ctx, q, rec, deviceID, command.TypeRotateAdminPassword, nil, l.now(), nil)
		return err
	})
	return out, err
}

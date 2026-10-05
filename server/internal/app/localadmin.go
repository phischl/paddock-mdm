package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/command"
	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/domain/device"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// SpecLocalAdminRotate is the privileged action local_admin.rotation_requested.
var SpecLocalAdminRotate = ActionSpec{Code: audit.CodeLocalAdminRotationRequested, AllowedRoles: RolesWrite}

// LocalAdmin holds the use cases of the managed local administrator account (plan M4a decision 17).
type LocalAdmin struct {
	runner *ActionRunner
	org    *db.OrgPool
	now    func() time.Time
}

// NewLocalAdmin creates the use cases.
func NewLocalAdmin(runner *ActionRunner, org *db.OrgPool) *LocalAdmin {
	return &LocalAdmin{runner: runner, org: org, now: time.Now}
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

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicecommand"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// DeviceCommands are the use cases of device commands (plan M4a decisions 1–3): the command list of a device for
// the portal, and for the worker the open commands to deliver, their delivery, results and expiry. Commands are
// issued by the use cases of their type through issueCommand.
type DeviceCommands struct {
	org *db.OrgPool
}

// NewDeviceCommands creates the use cases.
func NewDeviceCommands(org *db.OrgPool) *DeviceCommands { return &DeviceCommands{org: org} }

// CommandQuery selects a page of the commands of a device.
type CommandQuery struct {
	Page     ListPage
	Statuses []string
	Types    []string
}

// List returns one page of the commands of a device; an unknown or foreign device is not_found.
func (d *DeviceCommands) List(ctx context.Context, deviceID uuid.UUID, query CommandQuery) (Listed[pgstore.DeviceCommand], error) {
	var out Listed[pgstore.DeviceCommand]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDevice(ctx, deviceID); err != nil {
			return notFound(err)
		}
		statuses, types := nilIfEmpty(query.Statuses), nilIfEmpty(query.Types)
		n, err := q.CountDeviceCommands(ctx, pgstore.CountDeviceCommandsParams{
			DeviceID: deviceID, QPattern: query.Page.QPattern, Statuses: statuses, Types: types, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count commands: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListDeviceCommands(ctx, pgstore.ListDeviceCommandsParams{
			DeviceID: deviceID, QPattern: query.Page.QPattern, Statuses: statuses, Types: types,
			Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list commands: %w", err)
		}
		return nil
	})
	return out, err
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// issueCommand inserts a pending command of a registered type for a device inside the action's transaction, queues
// its command.issued message and records its ID as audit param command_id; notBefore (optional) delays its delivery
// (plan M4a decision 17).
func issueCommand(ctx context.Context, q *pgstore.Queries, rec Recorder, deviceID uuid.UUID, typ string,
	params map[string]any, now time.Time, notBefore *time.Time) (pgstore.DeviceCommand, error) {
	c, err := queueCommand(ctx, q, rec, deviceID, typ, params, now, notBefore)
	if err == nil {
		rec.SetParam("command_id", c.ID.String())
	}
	return c, err
}

// queueCommand is issueCommand without the audit param, for actions that issue a command to many devices.
func queueCommand(ctx context.Context, q *pgstore.Queries, rec Recorder, deviceID uuid.UUID, typ string,
	params map[string]any, now time.Time, notBefore *time.Time) (pgstore.DeviceCommand, error) {
	lifetime, ok := command.Lifetime(typ)
	if !ok {
		return pgstore.DeviceCommand{}, fmt.Errorf("app: command type %q is not registered", typ)
	}
	org, err := orgOf(ctx)
	if err != nil {
		return pgstore.DeviceCommand{}, err
	}
	if params == nil {
		params = map[string]any{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return pgstore.DeviceCommand{}, err
	}
	var issuedBy uuid.NullUUID
	if p, ok := principal.From(ctx); ok && p.Kind == principal.KindAdmin && p.ID != uuid.Nil {
		issuedBy = uuid.NullUUID{UUID: p.ID, Valid: true}
	}
	issued := now.UTC().Truncate(time.Second)
	start := issued
	if notBefore != nil && notBefore.After(issued) {
		start = notBefore.UTC().Truncate(time.Second)
	}
	c, err := q.InsertDeviceCommand(ctx, pgstore.InsertDeviceCommandParams{
		ID: uuid.Must(uuid.NewV7()), OrganizationID: org, DeviceID: deviceID, Type: typ, Params: raw, IssuedBy: issuedBy,
		IssuedAt: issued, ExpiresAt: start.Add(lifetime), NotBefore: notBefore,
	})
	if err != nil {
		return c, fmt.Errorf("insert command: %w", err)
	}
	rec.CommandIssued(c.ID)
	return c, nil
}

// Payload is the signed payload of a command row.
func Payload(c pgstore.DeviceCommand) command.Command {
	return command.Command{
		CommandID: c.ID.String(), DeviceID: c.DeviceID.String(), OrganizationID: c.OrganizationID.String(), Type: c.Type,
		Params: c.Params, IssuedAt: c.IssuedAt.UTC(), ExpiresAt: c.ExpiresAt.UTC(),
	}
}

// Deliverable reports whether a command is open, due and unexpired at now.
func Deliverable(c pgstore.DeviceCommand, now time.Time) bool {
	open := c.Status == devicecommand.StatusPending || c.Status == devicecommand.StatusDelivered
	due := c.NotBefore == nil || !c.NotBefore.After(now)
	return open && due && now.Before(c.ExpiresAt)
}

// Get returns one command (worker).
func (d *DeviceCommands) Get(ctx context.Context, id uuid.UUID) (pgstore.DeviceCommand, error) {
	var out pgstore.DeviceCommand
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetDeviceCommand(ctx, id)
		return notFound(err)
	})
	return out, err
}

// Due returns the open commands of the context's organization that are due and unexpired at now (worker).
func (d *DeviceCommands) Due(ctx context.Context, now time.Time) ([]pgstore.DeviceCommand, error) {
	var out []pgstore.DeviceCommand
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.ListDueDeviceCommands(ctx, now)
		return err
	})
	return out, err
}

// Expire marks the open commands of the context's organization whose lifetime ended at now as expired and returns
// them (worker).
func (d *DeviceCommands) Expire(ctx context.Context, now time.Time) ([]pgstore.ExpireDeviceCommandsRow, error) {
	var out []pgstore.ExpireDeviceCommandsRow
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.ExpireDeviceCommands(ctx, now)
		return err
	})
	return out, err
}

// MarkDelivered records that a check-in response carried the commands and revocation tokens (worker).
func (d *DeviceCommands) MarkDelivered(ctx context.Context, hb ingest.Heartbeat) error {
	if len(hb.DeliveredCommands) == 0 {
		return nil
	}
	return d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.MarkDeviceCommandsDelivered(ctx, pgstore.MarkDeviceCommandsDeliveredParams{
			DeviceID: hb.DeviceID, Ids: hb.DeliveredCommands, DeliveredAt: hb.ReceivedAt,
		}); err != nil {
			return err
		}
		_, err := q.MarkRevocationsDelivered(ctx, pgstore.MarkRevocationsDeliveredParams{
			DeviceID: hb.DeviceID, Ids: hb.DeliveredCommands, DeliveredAt: hb.ReceivedAt,
		})
		return err
	})
}

// Finish records the result of a command; only the first result of an open command counts (worker).
func (d *DeviceCommands) Finish(ctx context.Context, r ingest.CommandResult) error {
	result := r.Result
	if len(result) == 0 {
		result = json.RawMessage(`{}`)
	}
	return d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.FinishDeviceCommand(ctx, pgstore.FinishDeviceCommandParams{
			ID: r.CommandID, DeviceID: r.DeviceID, Status: r.Status, Result: result, FinishedAt: r.ReceivedAt,
		})
		return err
	})
}

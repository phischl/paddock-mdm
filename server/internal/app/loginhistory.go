package app

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// StoreDeviceLoginEvent is the store name of the login history in retention.purged (plan M8d decision 19).
const StoreDeviceLoginEvent = "device_login_event"

// LoginHistory lists and purges the login history of an organization's devices (ADR 0037 decision 6).
type LoginHistory struct {
	runner *ActionRunner
	org    *db.OrgPool
	// day is the length of a day of login_history_days: 24 hours, a second in development (PADDOCK_RETENTION_UNIT).
	day time.Duration
	// budget bounds one purge pass (retentionPassBudget).
	budget time.Duration
}

// NewLoginHistory creates the use cases.
func NewLoginHistory(runner *ActionRunner, org *db.OrgPool, day time.Duration) *LoginHistory {
	return &LoginHistory{runner: runner, org: org, day: day, budget: retentionPassBudget}
}

// LoginEventQuery selects a page of a device's login history; Username filters one user (exact, lower case).
type LoginEventQuery struct {
	Page     ListPage
	Username *string
}

// List returns one page of the logins of a device; a missing or foreign device is not_found. While the history is
// off the list is empty: switching it off deleted the rows.
func (h *LoginHistory) List(ctx context.Context, deviceID uuid.UUID, query LoginEventQuery) (Listed[pgstore.DeviceLoginEvent], error) {
	var out Listed[pgstore.DeviceLoginEvent]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := h.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDevice(ctx, deviceID); err != nil {
			return notFound(err)
		}
		n, err := q.CountDeviceLoginEvents(ctx, pgstore.CountDeviceLoginEventsParams{
			DeviceID: deviceID, QPattern: query.Page.QPattern, Username: query.Username, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count logins: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListDeviceLoginEvents(ctx, pgstore.ListDeviceLoginEventsParams{
			DeviceID: deviceID, QPattern: query.Page.QPattern, Username: query.Username, Sort: query.Page.Sort,
			SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list logins: %w", err)
		}
		return nil
	})
	return out, err
}

// Purge deletes the logins of the context's organization older than login_history_days at now (system principal);
// without expired rows it records nothing. It returns the number of deleted rows (purgeBatches).
func (h *LoginHistory) Purge(ctx context.Context, now time.Time) (int64, error) {
	var cutoff time.Time
	var expired bool
	err := h.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		settings, err := q.GetLoginSettings(ctx)
		if err != nil {
			return err
		}
		cutoff = now.Add(-time.Duration(settings.LoginHistoryDays) * h.day)
		expired, err = q.HasDeviceLoginEventsBefore(ctx, cutoff)
		return err
	})
	if err != nil || !expired {
		return 0, err
	}
	return purgeBatches(ctx, h.runner, h.org, StoreDeviceLoginEvent, cutoff, h.budget, retentionLockTimeout, func(ctx context.Context, q *pgstore.Queries) (int64, error) {
		return q.PurgeDeviceLoginEvents(ctx, cutoff)
	})
}

package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// LoginHistoryInterval is the period of the login history purge (plan M8d decision 19).
const LoginHistoryInterval = 6 * time.Hour

// loginHistoryLockKey is the advisory lock of the round ("padd log").
const loginHistoryLockKey = 0x70616464206c6f67

// LoginHistory deletes the logins older than every organization's login_history_days.
type LoginHistory struct {
	history  *app.LoginHistory
	pool     *db.OrgPool
	platform *db.PlatformPool
	interval time.Duration
	now      func() time.Time
}

// NewLoginHistory creates the round; interval is LoginHistoryInterval, shorter in development installations that
// count the retention days in seconds.
func NewLoginHistory(history *app.LoginHistory, pool *db.OrgPool, platform *db.PlatformPool, interval time.Duration) *LoginHistory {
	return &LoginHistory{history: history, pool: pool, platform: platform, interval: interval, now: time.Now}
}

// Run runs the round at start and then every interval until ctx ends; only the replica holding the lock acts.
func (l *LoginHistory) Run(ctx context.Context) error {
	tick := time.NewTicker(l.interval)
	defer tick.Stop()
	for {
		if err := l.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "login history purge failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round purges the login history of every organization; a failing organization does not stop the others.
func (l *LoginHistory) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := l.platform.WithLeaderLock(sys, loginHistoryLockKey, func(ctx context.Context) error {
		orgs, err := l.pool.OrganizationIDs(ctx)
		if err != nil {
			return err
		}
		var errs []error
		for _, org := range orgs {
			if _, err := l.history.Purge(systemContext(ctx, org, "login-history-round"), l.now()); err != nil {
				errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
			}
		}
		return errors.Join(errs...)
	})
	return err
}

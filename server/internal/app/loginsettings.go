package app

import (
	"context"
	"slices"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/domain/loginsettings"
	"github.com/paddock-mdm/paddock/server/internal/domain/statechange"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// LoginSettings are the use cases of the organization's login settings (plan M3a decision 8).
type LoginSettings struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewLoginSettings creates the use cases.
func NewLoginSettings(runner *ActionRunner, org *db.OrgPool) *LoginSettings {
	return &LoginSettings{runner: runner, org: org}
}

// SpecLoginSettingsUpdate is the privileged action settings.login_changed.
var SpecLoginSettingsUpdate = ActionSpec{Code: audit.CodeSettingsLoginChanged, AllowedRoles: RolesAdmin}

// Get returns the login settings.
func (s *LoginSettings) Get(ctx context.Context) (pgstore.OrganizationLoginSetting, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.OrganizationLoginSetting{}, err
	}
	var out pgstore.OrganizationLoginSetting
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetLoginSettings(ctx)
		return err
	})
	return out, err
}

// Update replaces the login settings and recompiles every device (audited: settings.login_changed with the names
// of the changed settings).
func (s *LoginSettings) Update(ctx context.Context, in loginsettings.Settings) (pgstore.OrganizationLoginSetting, error) {
	var out pgstore.OrganizationLoginSetting
	in = loginsettings.Normalize(in)
	err := s.runner.RunTx(ctx, ScopeOrg, SpecLoginSettingsUpdate, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.GetLoginSettings(ctx)
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "organization", ID: cur.OrganizationID.String()})
		changed := []string{}
		for name, differs := range map[string]bool{
			"hello_enabled":            cur.HelloEnabled != in.HelloEnabled,
			"hello_pin_min_length":     int(cur.HelloPinMinLength) != in.HelloPinMinLength,
			"user_lock_session_action": cur.UserLockSessionAction != in.UserLockSessionAction,
			"break_glass_accounts":     !slices.Equal(cur.BreakGlassAccounts, in.BreakGlassAccounts),
			"sudoers_d_allowlist":      !slices.Equal(cur.SudoersDAllowlist, in.SudoersDAllowlist),
			"sudo_lecture_text":        cur.SudoLectureText != in.SudoLectureText,
		} {
			if differs {
				changed = append(changed, name)
			}
		}
		slices.Sort(changed)
		rec.SetParam("changed", changed)
		if err := loginsettings.Validate(in); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		out, err = q.UpdateLoginSettings(ctx, pgstore.UpdateLoginSettingsParams{
			HelloEnabled: in.HelloEnabled, HelloPinMinLength: int32(in.HelloPinMinLength), //nolint:gosec // validated 6–32
			UserLockSessionAction: in.UserLockSessionAction, BreakGlassAccounts: in.BreakGlassAccounts,
			SudoersDAllowlist: in.SudoersDAllowlist, SudoLectureText: in.SudoLectureText,
		})
		if err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeOrg, cur.OrganizationID)
		return nil
	})
	return out, err
}

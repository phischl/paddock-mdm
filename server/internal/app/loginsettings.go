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

func equalHours(cur *int32, in *int) bool {
	if cur == nil || in == nil {
		return cur == nil && in == nil
	}
	return int(*cur) == *in
}

func int32Ptr(v *int) *int32 {
	if v == nil {
		return nil
	}
	n := int32(*v) //nolint:gosec // validated 1–168
	return &n
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
			"hello_enabled":             cur.HelloEnabled != in.HelloEnabled,
			"hello_pin_min_length":      int(cur.HelloPinMinLength) != in.HelloPinMinLength,
			"user_lock_session_action":  cur.UserLockSessionAction != in.UserLockSessionAction,
			"break_glass_accounts":      !slices.Equal(cur.BreakGlassAccounts, in.BreakGlassAccounts),
			"sudoers_d_allowlist":       !slices.Equal(cur.SudoersDAllowlist, in.SudoersDAllowlist),
			"sudo_lecture_text":         cur.SudoLectureText != in.SudoLectureText,
			"local_admin_username":      cur.LocalAdminUsername != in.LocalAdminUsername,
			"local_admin_rotation_days": int(cur.LocalAdminRotationDays) != in.LocalAdminRotationDays,
			"rotate_after_reveal_hours": !equalHours(cur.RotateAfterRevealHours, in.RotateAfterRevealHours),
			"notice_text":               cur.NoticeText != in.NoticeText,
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
		if cur.LocalAdminUsername != in.LocalAdminUsername {
			locked, err := q.OrganizationHasActiveLocalAdmin(ctx)
			if err != nil {
				return err
			}
			if locked {
				return problem.SettingLocked.WithDetail("local_admin_username cannot change: devices have an active password for " + cur.LocalAdminUsername)
			}
		}
		out, err = q.UpdateLoginSettings(ctx, pgstore.UpdateLoginSettingsParams{
			HelloEnabled: in.HelloEnabled, HelloPinMinLength: int32(in.HelloPinMinLength), //nolint:gosec // validated 6–32
			UserLockSessionAction: in.UserLockSessionAction, BreakGlassAccounts: in.BreakGlassAccounts,
			SudoersDAllowlist: in.SudoersDAllowlist, SudoLectureText: in.SudoLectureText,
			LocalAdminUsername: in.LocalAdminUsername, LocalAdminRotationDays: int32(in.LocalAdminRotationDays), //nolint:gosec // validated 1–365
			RotateAfterRevealHours: int32Ptr(in.RotateAfterRevealHours), NoticeText: in.NoticeText,
		})
		if err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeOrg, cur.OrganizationID)
		return nil
	})
	return out, err
}

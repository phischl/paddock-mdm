package worker

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// markDirectory holds the portal role groups and the authenticators of users and records the changes of their
// enrolment marks.
type markDirectory struct {
	mu      sync.Mutex
	groups  []string
	devices map[string]ports.Authenticators
	changes map[string][]any // user pk → values set, nil for a removal
}

func (d *markDirectory) PortalRoleGroupNames(context.Context) ([]string, error) {
	return d.groups, nil
}

func (d *markDirectory) UserAuthenticators(_ context.Context, pks []string) (map[string]ports.Authenticators, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]ports.Authenticators{}
	for _, pk := range pks {
		out[pk] = d.devices[pk]
	}
	return out, nil
}

func (d *markDirectory) SetUserAttribute(_ context.Context, pk, _ string, value any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.changes[pk] = append(d.changes[pk], value)
	return nil
}

// TestAdminAccountsRoundSeedsAndClearsEnrolmentMarks (ADR 0053 decision 4): the admin-accounts round seeds the
// enrolment marks once before the organizations and removes, after them, the marks of listed administrators who have
// a passkey; the next round seeds nothing again.
func TestAdminAccountsRoundSeedsAndClearsEnrolmentMarks(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	if _, err := f.super.Exec(ctx, "DELETE FROM platform_mfa_enrolment"); err != nil {
		t.Fatal(err)
	}
	admins := organization.RoleGroup("w"+f.org.String()[24:], organization.GroupAdmins)
	joined := time.Now().Add(-time.Hour)
	dir := &roleDirectory{listings: map[string]int{}, members: map[string][]ports.IdentityUser{admins: {
		{PK: "81", Username: "newcomer", UID: "uid-81", Active: true, Joined: joined},
		{PK: "82", Username: "enrolled", UID: "uid-82", Active: true, MFAEnrolAtLogin: true, Joined: joined},
	}}}
	marks := &markDirectory{groups: []string{admins}, devices: map[string]ports.Authenticators{"82": {WebAuthn: true}},
		changes: map[string][]any{}}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	i := NewIdentity(nil, app.NewAdminAccounts(runner, f.pool, platform, dir, nil), app.NewRoleMembership(runner, f.pool, platform, dir),
		app.NewMFAEnrolment(runner, platform, dir, marks), nil, f.pool, platform, 0, 0)
	_ = i.adminAccountsRound(ctx)
	if got := marks.changes["81"]; len(got) != 1 || got[0] != true {
		t.Errorf("newcomer without a passkey: changes %v, want one mark", got)
	}
	if got := marks.changes["82"]; len(got) != 1 || got[0] != nil {
		t.Errorf("marked administrator with a passkey: changes %v, want one removal", got)
	}
	var seeded int
	if err := f.super.QueryRow(ctx, "SELECT count(*) FROM platform_mfa_enrolment").Scan(&seeded); err != nil || seeded != 1 {
		t.Fatalf("seed rows %d (%v), want 1", seeded, err)
	}
	dir.members[admins] = append(dir.members[admins], ports.IdentityUser{PK: "83", Username: "later", UID: "uid-83", Active: true,
		Joined: joined})
	_ = i.adminAccountsRound(ctx)
	if got := marks.changes["83"]; len(got) != 0 {
		t.Errorf("an administrator added after the seed was changed: %v", got)
	}
	if got := marks.changes["81"]; len(got) != 1 {
		t.Errorf("the seed ran again for the newcomer: %v", got)
	}
}

package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestIdentityRoundContinuesAfterAFailingOrganization: a round of admin-accounts runs every organization in its own
// system context under the leader lock; a failing organization is logged and does not stop the others.
func TestIdentityRoundContinuesAfterAFailingOrganization(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	other := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'W2', 'active')",
		other, "w"+other.String()[24:]); err != nil {
		t.Fatal(err)
	}
	i := NewIdentity(nil, nil, nil, nil, f.pool, platform, time.Minute, time.Minute)
	var mu sync.Mutex
	seen := map[uuid.UUID]bool{}
	err = i.Round(ctx, identityAdminAccountsLockKey, "admin-accounts", func(ctx context.Context) error {
		p, _ := principal.From(ctx)
		mu.Lock()
		seen[p.OrganizationID] = p.Kind == principal.KindSystem
		mu.Unlock()
		if p.OrganizationID == f.org {
			return errors.New("directory down")
		}
		return nil
	})
	if err != nil || !seen[f.org] || !seen[other] {
		t.Fatalf("round: %v, organizations %v", err, seen)
	}
}

// roleDirectory lists fixed role group members and counts the listings per group; nothing else is used.
type roleDirectory struct {
	ports.UserDirectory
	mu       sync.Mutex
	members  map[string][]ports.IdentityUser
	listings map[string]int
}

func (d *roleDirectory) RoleGroupUsers(_ context.Context, name string) ([]ports.IdentityUser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.listings[name]++
	return d.members[name], nil
}

// TestAdminAccountsRoundSharesTheListings (PDK-111): the round admin-accounts lists each role group of an organization
// once and both the account reconciliation and the role membership use that listing.
func TestAdminAccountsRoundSharesTheListings(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	slug := "w" + f.org.String()[24:]
	admins := organization.RoleGroup(slug, organization.GroupAdmins)
	dir := &roleDirectory{listings: map[string]int{},
		members: map[string][]ports.IdentityUser{admins: {{PK: "71", Username: "alice", UID: "uid-alice", Active: true}}}}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	i := NewIdentity(nil, app.NewAdminAccounts(runner, f.pool, platform, dir, nil), app.NewRoleMembership(runner, f.pool, platform, dir),
		nil, f.pool, platform, time.Minute, time.Minute)
	if err := i.adminAccounts(systemContext(ctx, f.org, "admin-accounts-test")); err != nil {
		t.Fatal(err)
	}
	for _, g := range []organization.GroupRole{organization.GroupAdmins, organization.GroupOperators, organization.GroupAuditors} {
		if n := dir.listings[organization.RoleGroup(slug, g)]; n != 1 {
			t.Errorf("%s listed %d times, want once", g, n)
		}
	}
	var n int
	if err := f.super.QueryRow(ctx, `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'admin.role_granted'
		AND params->>'username' = 'alice' AND (params->>'baseline')::boolean`, f.org).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d baseline grants of alice (%v), want 1", n, err)
	}
}

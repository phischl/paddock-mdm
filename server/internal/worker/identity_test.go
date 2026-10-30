package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

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
	// readable and usersVisible answer the directory probe (PDK-424); probes counts its reads.
	readable     bool
	usersVisible bool
	probes       int
}

func (d *roleDirectory) GroupReadable(context.Context, string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.probes++
	return d.readable, nil
}

func (d *roleDirectory) UsersVisible(context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.probes++
	return d.usersVisible, nil
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

// TestAdminAccountsRoundCountsRefusals (PDK-424): an organization round refused because the directory looks empty to
// the service token runs the probe once for both consumers, counts once in paddock_identity_directory_refusals_total
// (although both refuse) and extends the organization's streak of refusals; a successful round ends the streak.
func TestAdminAccountsRoundCountsRefusals(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	slug := "w" + f.org.String()[24:]
	admins := organization.RoleGroup(slug, organization.GroupAdmins)
	alice := ports.IdentityUser{PK: "72", Username: "alice", UID: "uid-alice-" + f.org.String(), Active: true}
	if _, err := f.super.Exec(ctx, `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
		VALUES ($1, $2, $3, 'alice', 'alice', 'org_admin')`, uuid.Must(uuid.NewV7()), f.org, alice.UID); err != nil {
		t.Fatal(err)
	}
	dir := &roleDirectory{listings: map[string]int{}, members: map[string][]ports.IdentityUser{admins: {alice}}, readable: true}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	i := NewIdentity(nil, app.NewAdminAccounts(runner, f.pool, platform, dir, nil), app.NewRoleMembership(runner, f.pool, platform, dir),
		nil, f.pool, platform, time.Minute, time.Minute)
	sys := systemContext(ctx, f.org, "admin-accounts-test")
	if err := i.adminAccounts(sys); err != nil {
		t.Fatal(err)
	}
	dir.members = map[string][]ports.IdentityUser{}
	before := testutil.ToFloat64(metricDirectoryRefusals)
	for round := 1; round <= refusedRepeatedly; round++ {
		dir.probes = 0
		if err := i.adminAccounts(sys); !errors.Is(err, app.ErrDirectoryEmpty) {
			t.Fatalf("round %d: %v, want ErrDirectoryEmpty", round, err)
		}
		if dir.probes != 4 {
			t.Fatalf("round %d: %d probe reads, want 4 (three groups and the user listing, once for both consumers)", round, dir.probes)
		}
		if got := testutil.ToFloat64(metricDirectoryRefusals) - before; got != float64(round) {
			t.Fatalf("round %d: %v refusals counted, want %d", round, got, round)
		}
		if i.refused[f.org] != round {
			t.Fatalf("round %d: streak %d", round, i.refused[f.org])
		}
	}
	dir.members = map[string][]ports.IdentityUser{admins: {alice}}
	if err := i.adminAccounts(sys); err != nil {
		t.Fatal(err)
	}
	if _, ok := i.refused[f.org]; ok || testutil.ToFloat64(metricDirectoryRefusals)-before != refusedRepeatedly {
		t.Fatalf("after a successful round: streak %v, %v refusals", i.refused, testutil.ToFloat64(metricDirectoryRefusals)-before)
	}
}

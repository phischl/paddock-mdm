package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/platform/db"
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
	i := NewIdentity(nil, nil, nil, f.pool, platform, time.Minute, time.Minute)
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

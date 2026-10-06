package app_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/enrollment"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// fakeTokenCache records the tokens the use cases publish.
type fakeTokenCache struct {
	puts []cachedToken
	err  error
}

type cachedToken struct {
	hash  []byte
	token devicecache.Token
}

func (c *fakeTokenCache) PutToken(_ context.Context, secretSHA256 []byte, t devicecache.Token, _ time.Time) error {
	c.puts = append(c.puts, cachedToken{secretSHA256, t})
	return c.err
}

// TestEnrollmentTokensPublishToTheDeviceCache: a created token is in the gateway's cache when Create returns, a
// revoked one is marked revoked when Revoke returns; a cache failure does not fail the action (the worker's cache
// sync repairs it).
func TestEnrollmentTokensPublishToTheDeviceCache(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	org := uuid.Must(uuid.NewV7())
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Test', 'active')",
		org, "c"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	admin := func() context.Context {
		return httpx.WithRequestID(principal.With(ctx, principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()),
			Display: "alice", Role: principal.RoleOrgAdmin, OrganizationID: org}), uuid.NewString())
	}
	keys := func(context.Context) ([]protocol.BundleKey, error) { return []protocol.BundleKey{{KeyID: "k1"}}, nil }
	cache := &fakeTokenCache{}
	tokens := app.NewEnrollmentTokens(app.NewActionRunner(pool, nil, httpx.RequestID), pool, keys, cache, "https://device.test")
	in := app.TokenInput{Name: "laptops", MaxUses: 5, ExpiresAt: time.Now().Add(time.Hour)}

	created, err := tokens.Create(admin(), in)
	if err != nil {
		t.Fatal(err)
	}
	hash := enrollment.HashSecret(created.Secret)
	if len(cache.puts) != 1 || !bytes.Equal(cache.puts[0].hash, hash) || cache.puts[0].token.OrganizationID != org ||
		cache.puts[0].token.Revoked || !cache.puts[0].token.ExpiresAt.Equal(created.Token.ExpiresAt) {
		t.Fatalf("published after create: %+v", cache.puts)
	}
	if _, err := tokens.Revoke(admin(), created.Token.ID); err != nil {
		t.Fatal(err)
	}
	if len(cache.puts) != 2 || !bytes.Equal(cache.puts[1].hash, hash) || !cache.puts[1].token.Revoked {
		t.Fatalf("published after revoke: %+v", cache.puts)
	}

	cache.err = errors.New("valkey down")
	if _, err := tokens.Create(admin(), in); err != nil {
		t.Fatalf("create with the cache down: %v", err)
	}
	// A refused action publishes nothing.
	in.MaxUses = 0
	if _, err := tokens.Create(admin(), in); err == nil || len(cache.puts) != 3 {
		t.Fatalf("invalid token: %v, %d publishes", err, len(cache.puts))
	}
}

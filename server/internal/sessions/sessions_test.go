package sessions_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	srv := valkeytest.Start(t)
	c := srv.Client(t)
	s := sessions.NewStore(c)
	account, org := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	rec := sessions.Record{AccountID: account, Kind: "admin", Role: "org_admin", Org: org, CreatedAt: time.Now().Unix()}

	if id := sessions.NewID(); len(id) != 43 || id == sessions.NewID() {
		t.Fatalf("NewID %q", id)
	}
	first := sessions.NewID()
	created, err := s.Create(ctx, first, rec, time.Hour)
	if err != nil || created.Gen != 0 {
		t.Fatalf("create: %+v %v", created, err)
	}
	got, gen, found, err := s.Get(ctx, first)
	if err != nil || !found || gen != 0 || got != rec {
		t.Fatalf("get: %+v gen %d found %v %v", got, gen, found, err)
	}
	if err := s.Touch(ctx, first, account, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if ttl, err := c.Do(ctx, c.B().Pttl().Key("sess:"+first).Build()).AsInt64(); err != nil || ttl <= time.Hour.Milliseconds() {
		t.Fatalf("ttl after touch: %d %v", ttl, err)
	}
	if err := s.Delete(ctx, first, account); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := s.Get(ctx, first); err != nil || found {
		t.Fatalf("after delete: found %v %v", found, err)
	}

	for range 2 {
		if _, err := s.Create(ctx, sessions.NewID(), rec, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	other := sessions.Record{AccountID: uuid.Must(uuid.NewV7()), Kind: "platform_admin", Role: "platform_admin"}
	otherID := sessions.NewID()
	if _, err := s.Create(ctx, otherID, other, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CountAccount(ctx, account); err != nil || n != 2 {
		t.Fatalf("count: %d %v", n, err)
	}
	if n, err := s.RevokeAccount(ctx, account); err != nil || n != 2 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if n, err := s.RevokeAccount(ctx, account); err != nil || n != 0 {
		t.Fatalf("second revoke: %d %v", n, err)
	}
	if n, err := s.CountAccount(ctx, account); err != nil || n != 0 {
		t.Fatalf("count after revoke: %d %v", n, err)
	}
	if _, _, found, err := s.Get(ctx, otherID); err != nil || !found {
		t.Fatalf("another account's session: found %v %v", found, err)
	}

	gen, err = s.EndAll(ctx)
	if err != nil || gen != 1 {
		t.Fatalf("end all: %d %v", gen, err)
	}
	if got, gen, found, err := s.Get(ctx, otherID); err != nil || !found || gen != 1 || got.Gen >= gen {
		t.Fatalf("older session after end all: %+v gen %d found %v %v", got, gen, found, err)
	}
	if created, err := s.Create(ctx, sessions.NewID(), rec, time.Hour); err != nil || created.Gen != 1 {
		t.Fatalf("session after end all: %+v %v", created, err)
	}

	closed, err := valkey.New(srv.Config)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	down := sessions.NewStore(closed)
	if _, _, _, err := down.Get(ctx, otherID); !errors.Is(err, sessions.ErrUnavailable) {
		t.Fatalf("get on a closed client: %v", err)
	}
	if _, err := down.Create(ctx, sessions.NewID(), rec, time.Hour); !errors.Is(err, sessions.ErrUnavailable) {
		t.Fatalf("create on a closed client: %v", err)
	}
	if _, err := down.EndAll(ctx); !errors.Is(err, sessions.ErrUnavailable) {
		t.Fatalf("end all on a closed client: %v", err)
	}
}

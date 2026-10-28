package sessions_test

import (
	"context"
	"errors"
	"strings"
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

// TestStoreMCPRecord covers the MCP session record (plan M14 §3.2 item 7): its channel, display and subject round-trip,
// a portal record stays without them, and revoking the account ends MCP and portal sessions alike.
func TestStoreMCPRecord(t *testing.T) {
	ctx := context.Background()
	srv := valkeytest.Start(t)
	c := srv.Client(t)
	s := sessions.NewStore(c)
	account, org := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	portal := sessions.Record{AccountID: account, Kind: "admin", Role: "org_admin", Org: org, CreatedAt: time.Now().Unix()}
	mcp := portal
	mcp.Channel, mcp.Display, mcp.Subject = "mcp", "alice", "ak-sub-alice"

	mcpID, portalID := "mcp:"+strings.Repeat("ab", 32), sessions.NewID()
	if _, err := s.Create(ctx, mcpID, mcp, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, portalID, portal, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, _, found, err := s.Get(ctx, mcpID); err != nil || !found || got != mcp {
		t.Fatalf("mcp record: %+v found %v %v", got, found, err)
	}
	if got, _, found, err := s.Get(ctx, portalID); err != nil || !found || got != portal {
		t.Fatalf("portal record: %+v found %v %v", got, found, err)
	}
	raw, err := c.Do(ctx, c.B().Get().Key("sess:"+portalID).Build()).ToString()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"channel"`, `"display"`, `"sub"`} {
		if strings.Contains(raw, key) {
			t.Fatalf("portal record carries %s: %s", key, raw)
		}
	}
	raw, err = c.Do(ctx, c.B().Get().Key("sess:"+mcpID).Build()).ToString()
	if err != nil || !strings.Contains(raw, `"channel":"mcp"`) || !strings.Contains(raw, `"sub":"ak-sub-alice"`) {
		t.Fatalf("mcp record JSON: %s %v", raw, err)
	}

	if n, err := s.RevokeAccount(ctx, account); err != nil || n != 2 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	for _, sid := range []string{mcpID, portalID} {
		if _, _, found, err := s.Get(ctx, sid); err != nil || found {
			t.Fatalf("%s after revoke: found %v %v", sid, found, err)
		}
	}
}

// TestStoreMCPBinding covers the login binding of MCP renewals (ADR 0044 amendment 2026-10-28): it is found only for
// its own subject and auth_time, carries the generation it was written in, expires with its lifetime, and logout
// (Unbind) and RevokeAccount remove it without counting it as a session.
func TestStoreMCPBinding(t *testing.T) {
	ctx := context.Background()
	srv := valkeytest.Start(t)
	c := srv.Client(t)
	s := sessions.NewStore(c)
	account := uuid.Must(uuid.NewV7())
	b := sessions.Binding{AccountID: account, Kind: "admin", Role: "org_admin", Org: uuid.Must(uuid.NewV7()), Client: "Claude Code"}

	if _, err := s.Bind(ctx, "sub-a", 100, b, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, gen, found, err := s.Binding(ctx, "sub-a", 100)
	if err != nil || !found || gen != 0 || got != b {
		t.Fatalf("binding: %+v gen %d found %v %v", got, gen, found, err)
	}
	for name, key := range map[string]struct {
		sub  string
		auth int64
	}{"another auth_time": {"sub-a", 101}, "another subject": {"sub-b", 100}} {
		if _, _, found, err := s.Binding(ctx, key.sub, key.auth); err != nil || found {
			t.Errorf("%s: found %v %v", name, found, err)
		}
	}
	if _, err := s.Bind(ctx, "sub-a", 1, b, 0); err == nil {
		t.Fatal("a binding without lifetime was written")
	}

	if _, err := s.EndAll(ctx); err != nil {
		t.Fatal(err)
	}
	if got, gen, _, err := s.Binding(ctx, "sub-a", 100); err != nil || got.Gen >= gen {
		t.Fatalf("binding after end all: gen %d, current %d %v", got.Gen, gen, err)
	}

	if err := s.Unbind(ctx, "sub-a", 100, account); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := s.Binding(ctx, "sub-a", 100); err != nil || found {
		t.Fatalf("after unbind: found %v %v", found, err)
	}

	if _, err := s.Bind(ctx, "sub-a", 200, b, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, _, found, err := s.Binding(ctx, "sub-a", 200); err != nil || found {
		t.Fatalf("expired binding: found %v %v", found, err)
	}

	if _, err := s.Bind(ctx, "sub-a", 300, b, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "mcp:"+strings.Repeat("cd", 32), sessions.Record{AccountID: account, Kind: "admin", Role: "org_admin",
		Channel: "mcp"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RevokeAccount(ctx, account); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if _, _, found, err := s.Binding(ctx, "sub-a", 300); err != nil || found {
		t.Fatalf("binding after revoke: found %v %v", found, err)
	}
}

// TestStoreUseLoginToken: a login token is accepted once while its marker lives (at least a second), and again only
// after it expired.
func TestStoreUseLoginToken(t *testing.T) {
	ctx := context.Background()
	srv := valkeytest.Start(t)
	s := sessions.NewStore(srv.Client(t))
	for i, want := range []bool{true, false} {
		if first, err := s.UseLoginToken(ctx, "id-token-a", time.Hour); err != nil || first != want {
			t.Fatalf("use %d: %v %v, want %v", i, first, err, want)
		}
	}
	if first, err := s.UseLoginToken(ctx, "id-token-b", 0); err != nil || !first {
		t.Fatalf("another token: %v %v", first, err)
	}
	if first, err := s.UseLoginToken(ctx, "id-token-b", time.Hour); err != nil || first {
		t.Fatalf("a token without lifetime is still marked for the minimum second: %v %v", first, err)
	}
	if _, err := s.UseLoginToken(ctx, "id-token-c", time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if first, err := s.UseLoginToken(ctx, "id-token-c", time.Hour); err != nil || !first {
		t.Fatalf("after expiry: %v %v", first, err)
	}
}

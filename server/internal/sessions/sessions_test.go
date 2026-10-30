package sessions_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
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
	b := sessions.Binding{AccountID: account, Kind: "admin", Role: "org_admin", Org: uuid.Must(uuid.NewV7()), Client: "Claude Code",
		PasskeyVerified: true}
	rec := sessions.Record{AccountID: account, Kind: "admin", Role: "org_admin", Channel: "mcp"}
	login := func(sid, sub string, authTime int64) string {
		t.Helper()
		if _, err := s.CreateMCP(ctx, sid, rec, time.Hour, sessions.Chain{Sub: sub, AuthTime: authTime, TTL: time.Hour}); err != nil {
			t.Fatal(err)
		}
		return sid
	}

	if _, err := s.Bind(ctx, login("mcp:"+strings.Repeat("a1", 32), "sub-a", 100), "sub-a", 100, b, time.Hour); err != nil {
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
	if _, err := s.Bind(ctx, "mcp:"+strings.Repeat("a1", 32), "sub-a", 1, b, 0); err == nil {
		t.Fatal("a binding without lifetime was written")
	}

	// A binding written before PDK-531 has no passkey_verified and reads as unmarked.
	legacy := `{"account_id":"` + account.String() + `","kind":"admin","role":"org_admin","org":"` + uuid.Nil.String() + `","gen":0}`
	if err := c.Do(ctx, c.B().Set().Key(bindingKeyOf("sub-l", 100)).Value(legacy).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if got, _, found, err := s.Binding(ctx, "sub-l", 100); err != nil || !found || got.PasskeyVerified || got.AccountID != account {
		t.Fatalf("legacy binding: %+v found %v %v", got, found, err)
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

	if _, err := s.Bind(ctx, login("mcp:"+strings.Repeat("a2", 32), "sub-a", 200), "sub-a", 200, b, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, _, found, err := s.Binding(ctx, "sub-a", 200); err != nil || found {
		t.Fatalf("expired binding: found %v %v", found, err)
	}

	if err := s.Delete(ctx, "mcp:"+strings.Repeat("a2", 32), account); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(ctx, login("mcp:"+strings.Repeat("cd", 32), "sub-a", 300), "sub-a", 300, b, time.Hour); err != nil {
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

// bindingKeyOf is the key of a login binding, as the store names it.
func bindingKeyOf(sub string, authTime int64) string {
	return "mcp-bind:" + strings.TrimPrefix(chainKeyOf(sub, authTime), "mcp-chain:")
}

// chainKeyOf is the key of the set of a binding's MCP session records, as the store names it.
func chainKeyOf(sub string, authTime int64) string {
	sum := sha256.Sum256([]byte(sub))
	return "mcp-chain:" + hex.EncodeToString(sum[:]) + ":" + strconv.FormatInt(authTime, 10)
}

// TestStoreMCPChain covers the set of a binding's MCP session records (PDK-468): every record joins it, its lifetime
// covers the binding and only grows, a renewal without a binding writes nothing, and Unbind and RevokeAccount end
// every record of the chain while other sessions of the account stay.
func TestStoreMCPChain(t *testing.T) {
	ctx := context.Background()
	srv := valkeytest.Start(t)
	c := srv.Client(t)
	s := sessions.NewStore(c)
	account := uuid.Must(uuid.NewV7())
	b := sessions.Binding{AccountID: account, Kind: "admin", Role: "org_admin", Org: uuid.Must(uuid.NewV7())}
	rec := sessions.Record{AccountID: account, Kind: "admin", Role: "org_admin", Org: b.Org, Channel: "mcp", Subject: "sub-a"}
	sid := func(i int) string { return "mcp:" + strings.Repeat(strconv.Itoa(i), 64) }
	chainTTL := func(sub string, authTime int64) time.Duration {
		t.Helper()
		ms, err := c.Do(ctx, c.B().Pttl().Key(chainKeyOf(sub, authTime)).Build()).AsInt64()
		if err != nil {
			t.Fatal(err)
		}
		return time.Duration(ms) * time.Millisecond
	}
	exists := func(id string) bool {
		t.Helper()
		_, _, found, err := s.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}

	if _, err := s.CreateMCP(ctx, sid(1), rec, 30*time.Minute, sessions.Chain{Sub: "sub-a", AuthTime: 100, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if ttl := chainTTL("sub-a", 100); ttl <= 59*time.Minute || ttl > time.Hour {
		t.Fatalf("chain lifetime after the login record: %s", ttl)
	}
	if _, err := s.Bind(ctx, sid(1), "sub-a", 100, b, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMCP(ctx, sid(2), rec, 30*time.Minute,
		sessions.Chain{Sub: "sub-a", AuthTime: 100, TTL: 2 * time.Hour, Renewal: true}); err != nil {
		t.Fatal(err)
	}
	if ttl := chainTTL("sub-a", 100); ttl <= 119*time.Minute || ttl > 2*time.Hour {
		t.Fatalf("chain lifetime not refreshed by a renewal: %s", ttl)
	}
	if _, err := s.CreateMCP(ctx, sid(3), rec, 20*time.Minute,
		sessions.Chain{Sub: "sub-a", AuthTime: 100, TTL: 10 * time.Minute, Renewal: true}); err != nil {
		t.Fatal(err)
	}
	if ttl := chainTTL("sub-a", 100); ttl <= 119*time.Minute {
		t.Fatalf("a shorter renewal shortened the chain lifetime: %s", ttl)
	}

	if _, err := s.CreateMCP(ctx, sid(4), rec, 30*time.Minute,
		sessions.Chain{Sub: "sub-b", AuthTime: 100, TTL: time.Hour, Renewal: true}); !errors.Is(err, sessions.ErrNoBinding) {
		t.Fatalf("renewal without a binding: %v", err)
	}
	if exists(sid(4)) || chainTTL("sub-b", 100) != -2*time.Millisecond {
		t.Fatal("a renewal without a binding wrote its record or chain")
	}

	portal := sessions.NewID()
	if _, err := s.Create(ctx, portal, sessions.Record{AccountID: account, Kind: "admin", Role: "org_admin", Org: b.Org},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Unbind(ctx, "sub-a", 100, account); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if exists(sid(i)) {
			t.Fatalf("record %d of the chain survived the end of its binding", i)
		}
	}
	if chainTTL("sub-a", 100) != -2*time.Millisecond {
		t.Fatal("the chain's set survived the end of its binding")
	}
	if n, err := s.CountAccount(ctx, account); err != nil || n != 1 || !exists(portal) {
		t.Fatalf("sessions of the account after unbind: %d %v", n, err)
	}

	if _, err := s.CreateMCP(ctx, sid(6), rec, 30*time.Minute, sessions.Chain{Sub: "sub-a", AuthTime: 300, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(ctx, sid(6), "sub-a", 300, b, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMCP(ctx, sid(5), rec, 30*time.Minute,
		sessions.Chain{Sub: "sub-a", AuthTime: 300, TTL: time.Hour, Renewal: true}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RevokeAccount(ctx, account); err != nil || n != 3 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if exists(sid(5)) || exists(sid(6)) || chainTTL("sub-a", 300) != -2*time.Millisecond {
		t.Fatal("RevokeAccount left a record or the chain's set")
	}
}

// TestStoreMCPChainRacingUnbind: a renewal racing the end of its binding never leaves a record behind, whichever runs
// first.
func TestStoreMCPChainRacingUnbind(t *testing.T) {
	ctx := context.Background()
	srv := valkeytest.Start(t)
	s := sessions.NewStore(srv.Client(t))
	account := uuid.Must(uuid.NewV7())
	b := sessions.Binding{AccountID: account, Kind: "admin", Role: "org_admin", Org: uuid.Must(uuid.NewV7())}
	rec := sessions.Record{AccountID: account, Kind: "admin", Role: "org_admin", Org: b.Org, Channel: "mcp", Subject: "sub-r"}
	refused := 0
	for i := range 100 {
		authTime := int64(1000 + i)
		login := "mcp:login-" + strconv.Itoa(i)
		if _, err := s.CreateMCP(ctx, login, rec, 30*time.Minute,
			sessions.Chain{Sub: "sub-r", AuthTime: authTime, TTL: time.Hour}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Bind(ctx, login, "sub-r", authTime, b, time.Hour); err != nil {
			t.Fatal(err)
		}
		id := "mcp:" + strconv.Itoa(i)
		var wg sync.WaitGroup
		var createErr, unbindErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, createErr = s.CreateMCP(ctx, id, rec, 30*time.Minute,
				sessions.Chain{Sub: "sub-r", AuthTime: authTime, TTL: time.Hour, Renewal: true})
		}()
		go func() {
			defer wg.Done()
			unbindErr = s.Unbind(ctx, "sub-r", authTime, account)
		}()
		wg.Wait()
		if unbindErr != nil || (createErr != nil && !errors.Is(createErr, sessions.ErrNoBinding)) {
			t.Fatalf("round %d: create %v, unbind %v", i, createErr, unbindErr)
		}
		if createErr != nil {
			refused++
		}
		if _, _, found, err := s.Get(ctx, id); err != nil || found {
			t.Fatalf("round %d: the renewal's record survived the end of its binding (found %v %v)", i, found, err)
		}
	}
	t.Logf("renewals refused because the binding ended first: %d of 100", refused)
}

// TestStoreMCPBindAfterChainEnd: a first login's binding is written only while its record exists and is in the chain's
// set (PDK-546); after a logout (Unbind), a revocation or a deleted record, and for a record of another chain, Bind
// writes nothing and fails with ErrNoBinding.
func TestStoreMCPBindAfterChainEnd(t *testing.T) {
	ctx := context.Background()
	srv := valkeytest.Start(t)
	c := srv.Client(t)
	s := sessions.NewStore(c)
	account := uuid.Must(uuid.NewV7())
	b := sessions.Binding{AccountID: account, Kind: "admin", Role: "org_admin", Org: uuid.Must(uuid.NewV7())}
	rec := sessions.Record{AccountID: account, Kind: "admin", Role: "org_admin", Org: b.Org, Channel: "mcp", Subject: "sub-e"}
	for i, tc := range []struct {
		name string
		end  func(sid string, authTime int64) error
		// bindAt is the auth_time Bind names; 0 is the login's own.
		bindAt int64
	}{
		{name: "logout", end: func(_ string, authTime int64) error { return s.Unbind(ctx, "sub-e", authTime, account) }},
		{name: "revocation", end: func(string, int64) error { _, err := s.RevokeAccount(ctx, account); return err }},
		{name: "deleted record", end: func(sid string, _ int64) error { return s.Delete(ctx, sid, account) }},
		{name: "record of another chain", end: func(string, int64) error { return nil }, bindAt: 1},
	} {
		authTime := int64(100 + i)
		sid := "mcp:" + strings.Repeat(strconv.Itoa(i), 64)
		if _, err := s.CreateMCP(ctx, sid, rec, 30*time.Minute, sessions.Chain{Sub: "sub-e", AuthTime: authTime, TTL: time.Hour}); err != nil {
			t.Fatal(err)
		}
		if err := tc.end(sid, authTime); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		bindAt := authTime
		if tc.bindAt != 0 {
			bindAt = tc.bindAt
		}
		if _, err := s.Bind(ctx, sid, "sub-e", bindAt, b, time.Hour); !errors.Is(err, sessions.ErrNoBinding) {
			t.Fatalf("%s: bind %v, want ErrNoBinding", tc.name, err)
		}
		if _, _, found, err := s.Binding(ctx, "sub-e", bindAt); err != nil || found {
			t.Fatalf("%s: binding written (found %v %v)", tc.name, found, err)
		}
		if n, err := c.Do(ctx, c.B().Exists().Key("acct-mcp-bind:"+account.String()).Build()).AsInt64(); err != nil || n != 0 {
			t.Fatalf("%s: the account's set of bindings names a binding (%d %v)", tc.name, n, err)
		}
	}
}

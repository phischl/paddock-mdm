package devicecache_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

func TestRoundTrips(t *testing.T) {
	srv := valkeytest.Start(t)
	client := srv.Client(t)
	cache := devicecache.New(client)
	ctx := context.Background()
	now := time.Now()
	org := uuid.New()

	hash := bytes.Repeat([]byte{7}, 32)
	if _, ok, err := cache.Token(ctx, hash); ok || err != nil {
		t.Fatalf("missing token: %v %v", ok, err)
	}
	tok := devicecache.Token{OrganizationID: org, ExpiresAt: now.Add(time.Hour).Truncate(time.Second)}
	if err := cache.PutToken(ctx, hash, tok, now); err != nil {
		t.Fatal(err)
	}
	got, ok, err := cache.Token(ctx, hash)
	if err != nil || !ok || got.OrganizationID != org || !got.ExpiresAt.Equal(tok.ExpiresAt) || !got.Usable(now) {
		t.Fatalf("token %+v %v %v", got, ok, err)
	}
	ttl, err := client.Do(ctx, client.B().Ttl().Key("et:0707070707070707070707070707070707070707070707070707070707070707").Build()).AsInt64()
	if err != nil || ttl <= 3500 || ttl > 3600 {
		t.Fatalf("token ttl %d %v", ttl, err)
	}
	tok.Revoked = true
	if err := cache.PutToken(ctx, hash, tok, now); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := cache.Token(ctx, hash); !got.Revoked || got.Usable(now) {
		t.Fatalf("revoked token %+v", got)
	}
	tok.ExpiresAt = now.Add(-time.Second)
	if err := cache.PutToken(ctx, hash, tok, now); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := cache.Token(ctx, hash); ok {
		t.Fatal("expired token still cached")
	}

	key := devicecache.DeviceKey{DeviceID: uuid.New(), OrganizationID: org, Status: devicecache.KeyActive, PublicKey: []byte{1, 2, 3}}
	if err := cache.PutDeviceKey(ctx, "abc", key); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := cache.DeviceKey(ctx, "abc"); err != nil || !ok || got.DeviceID != key.DeviceID || !bytes.Equal(got.PublicKey, key.PublicKey) || got.Status != "active" {
		t.Fatalf("device key %+v %v %v", got, ok, err)
	}

	id := uuid.New()
	enr := devicecache.Enrollment{KeyID: "abc", PublicKey: []byte{4}, OrganizationID: org, Status: "processing"}
	if err := cache.PutEnrollment(ctx, id, enr, now); err != nil {
		t.Fatal(err)
	}
	if got, ok, _ := cache.Enrollment(ctx, id); !ok || got.Status != "processing" || got.DeviceID != uuid.Nil {
		t.Fatalf("enrollment %+v", got)
	}
	enr.Status, enr.DeviceID = "active", id
	if err := cache.PutEnrollment(ctx, id, enr, now); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := cache.Enrollment(ctx, id); got.Status != "active" || got.DeviceID != id {
		t.Fatalf("enrollment update %+v", got)
	}
}

func TestKeyStatus(t *testing.T) {
	if devicecache.KeyStatus("active", "quarantined") != devicecache.KeyQuarantined || devicecache.KeyStatus("revoked", "active") != devicecache.KeyRevoked {
		t.Fatal("key status mapping")
	}
}

func TestGatewayKeys(t *testing.T) {
	srv := valkeytest.Start(t)
	cache := devicecache.New(srv.Client(t))
	ctx := context.Background()
	dev := uuid.New()

	if fresh, err := cache.UseNonce(ctx, dev.String(), "n1"); err != nil || !fresh {
		t.Fatalf("first nonce: %v %v", fresh, err)
	}
	if fresh, err := cache.UseNonce(ctx, dev.String(), "n1"); err != nil || fresh {
		t.Fatalf("replayed nonce accepted: %v %v", fresh, err)
	}

	if err := cache.RestoreSeq(ctx, dev, 41); err != nil {
		t.Fatal(err)
	}
	if err := cache.RestoreSeq(ctx, dev, 3); err != nil {
		t.Fatal(err)
	}
	if n, err := cache.NextSeq(ctx, dev); err != nil || n != 42 {
		t.Fatalf("seq %d %v", n, err)
	}

	if _, ok, _ := cache.BundlePointer(ctx, dev); ok {
		t.Fatal("pointer before any bundle")
	}
	for _, v := range []int64{2, 1} {
		if err := cache.PutBundlePointer(ctx, dev, devicecache.BundlePointer{Version: v, SHA256: "s", ObjectKey: "k"}); err != nil {
			t.Fatal(err)
		}
	}
	if p, _, _ := cache.BundlePointer(ctx, dev); p.Version != 2 {
		t.Fatalf("pointer moved back to %d", p.Version)
	}

	now := time.Date(2026, 10, 4, 12, 0, 30, 0, time.UTC)
	for i := range 3 {
		if ok, _, err := cache.Allow(ctx, "key:x", 3, now); err != nil || !ok {
			t.Fatalf("request %d limited: %v", i, err)
		}
	}
	ok, wait, err := cache.Allow(ctx, "key:x", 3, now)
	if err != nil || ok || wait != 30*time.Second {
		t.Fatalf("fourth request: %v %s %v", ok, wait, err)
	}
	if ok, _, _ := cache.Allow(ctx, "key:other", 3, now); !ok {
		t.Fatal("limits are not per scope")
	}
	// 45 s into the next minute only a quarter of the previous minute still counts.
	if ok, _, _ := cache.Allow(ctx, "key:x", 3, now.Add(75*time.Second)); !ok {
		t.Fatal("window does not slide")
	}
}

// TestErrorsDoNotCarryKeys: cache errors are logged by the gateway, so they must not contain the key ID from the
// Paddock-Key-Id header or the hash of an enrollment token.
func TestErrorsDoNotCarryKeys(t *testing.T) {
	cache := devicecache.New(valkeytest.Start(t).Client(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tokenHash := bytes.Repeat([]byte{0xab}, 32)
	tokenHex := strings.Repeat("ab", 32)
	keyID := strings.Repeat("cd", 32)
	now := time.Now()

	_, _, readToken := cache.Token(ctx, tokenHash)
	writeToken := cache.PutToken(ctx, tokenHash, devicecache.Token{ExpiresAt: now.Add(time.Hour)}, now)
	_, _, readKey := cache.DeviceKey(ctx, keyID)
	writeKey := cache.PutDeviceKey(ctx, keyID, devicecache.DeviceKey{})
	for name, err := range map[string]error{"Token": readToken, "PutToken": writeToken, "DeviceKey": readKey, "PutDeviceKey": writeKey} {
		if err == nil {
			t.Fatalf("%s with a cancelled context succeeded", name)
		}
		if msg := err.Error(); strings.Contains(msg, tokenHex) || strings.Contains(msg, keyID) {
			t.Fatalf("%s error carries the key: %s", name, msg)
		}
	}
}

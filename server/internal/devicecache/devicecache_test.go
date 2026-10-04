package devicecache_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/valkeytest"
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

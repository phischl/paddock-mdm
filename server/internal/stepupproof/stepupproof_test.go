package stepupproof_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// issuer is an OIDC issuer with discovery and a JWKS of one key.
type issuer struct {
	*httptest.Server
	key *rsa.PrivateKey
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": is.URL, "authorization_endpoint": is.URL + "/authorize", "token_endpoint": is.URL + "/token",
			"jwks_uri": is.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	is.Server = httptest.NewServer(mux)
	t.Cleanup(is.Close)
	return is
}

// token signs claims over the defaults of a valid step-up token with key.
func (is *issuer) token(t *testing.T, key *rsa.PrivateKey, override map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{"iss": is.URL, "aud": "paddock-portal-stepup", "sub": "alice-sub", "jti": "jti-1",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Add(-10 * time.Second).Unix(),
		"amr": []string{"pwd", "mfa"}}
	for k, v := range override {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	b64 := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	payload, _ := json.Marshal(claims)
	signed := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64(sig)
}

func TestVerify(t *testing.T) {
	is := newIssuer(t)
	v := stepupproof.NewVerifier(is.URL, "paddock-portal-stepup", 300*time.Second, time.Now)
	ctx := context.Background()
	if _, err := v.Verify(ctx, is.token(t, is.key, nil)); err == nil || errors.Is(err, stepupproof.ErrInvalid) {
		t.Fatalf("before discovery: %v", err)
	}
	discoverCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	v.Discover(discoverCtx)
	if !v.Ready() {
		t.Fatal("not ready after discovery")
	}
	c, err := v.Verify(ctx, is.token(t, is.key, nil))
	if err != nil || c.Subject != "alice-sub" || c.JTI != "jti-1" || c.Expiry.Before(time.Now()) {
		t.Fatalf("valid token: %+v, %v", c, err)
	}

	forger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for name, tok := range map[string]string{
		"forged signature": is.token(t, forger, nil),
		"other audience":   is.token(t, is.key, map[string]any{"aud": "paddock-portal"}),
		"other issuer":     is.token(t, is.key, map[string]any{"iss": "https://evil.example"}),
		"expired":          is.token(t, is.key, map[string]any{"exp": now.Add(-time.Minute).Unix()}),
		"stale auth_time":  is.token(t, is.key, map[string]any{"auth_time": now.Add(-301 * time.Second).Unix()}),
		"future auth_time": is.token(t, is.key, map[string]any{"auth_time": now.Add(2 * time.Minute).Unix()}),
		"no auth_time":     is.token(t, is.key, map[string]any{"auth_time": nil}),
		"no MFA":           is.token(t, is.key, map[string]any{"amr": []string{"pwd"}}),
		"no jti":           is.token(t, is.key, map[string]any{"jti": nil}),
		"garbage":          "a.b.c",
	} {
		if _, err := v.Verify(ctx, tok); !errors.Is(err, stepupproof.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestStore(t *testing.T) {
	srv := valkeytest.Start(t)
	c, err := valkey.New(srv.Config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	s := stepupproof.NewStore(c)
	ctx := context.Background()
	if _, ok, err := s.Get(ctx, "unknown"); ok || err != nil {
		t.Fatalf("unknown token: %v %v", ok, err)
	}
	if err := s.Put(ctx, "j1", "raw-token", time.Second); err != nil {
		t.Fatal(err)
	}
	if raw, ok, err := s.Get(ctx, "j1"); !ok || err != nil || raw != "raw-token" {
		t.Fatalf("get: %q %v %v", raw, ok, err)
	}
	for want := int64(1); want <= stepupproof.MaxUses+1; want++ {
		if n, err := s.Use(ctx, "j1", time.Now().Add(time.Minute)); err != nil || n != want {
			t.Fatalf("use %d: %d %v", want, n, err)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	if _, ok, _ := s.Get(ctx, "j1"); ok {
		t.Fatal("the token outlived its TTL")
	}
}

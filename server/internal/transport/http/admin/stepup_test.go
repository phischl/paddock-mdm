package admin_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

// fakeStepUpIdP is an OIDC provider that issues one ID token per code with the claims the test sets.
type fakeStepUpIdP struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu     sync.Mutex
	claims map[string]any // claims of the next token; nonce is filled from the authorization request
	nonce  string
}

func newFakeStepUpIdP(t *testing.T) *fakeStepUpIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeStepUpIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.URL, "authorization_endpoint": f.URL + "/authorize", "token_endpoint": f.URL + "/token",
			"jwks_uri": f.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		claims := map[string]any{"iss": f.URL, "aud": "paddock-portal-stepup", "exp": time.Now().Add(time.Minute).Unix(),
			"iat": time.Now().Unix(), "nonce": f.nonce}
		for k, v := range f.claims {
			claims[k] = v
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 60,
			"id_token": f.sign(t, claims)})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeStepUpIdP) sign(t *testing.T, claims map[string]any) string {
	b64 := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	payload, _ := json.Marshal(claims)
	signed := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Error(err)
	}
	return signed + "." + b64(sig)
}

type stepUpWorld struct {
	t       *testing.T
	idp     *fakeStepUpIdP
	keys    *admin.Keyring
	handler http.Handler
	session admin.Session
}

func newStepUpWorld(t *testing.T) *stepUpWorld {
	t.Helper()
	idp := newFakeStepUpIdP(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	keys := &admin.Keyring{}
	if err := keys.SetKeys(base64.StdEncoding.EncodeToString(key), ""); err != nil {
		t.Fatal(err)
	}
	stepUp := admin.NewOIDC(admin.OIDCConfig{Issuer: idp.URL, ClientID: "paddock-portal-stepup", ClientSecret: "s",
		PublicURL: "https://admin.test", RedirectPath: "/api/auth/stepup/callback"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stepUp.Discover(ctx)
	if !stepUp.Ready() {
		t.Fatal("discovery failed")
	}
	static, err := admin.NewStaticHandler(fstest.MapFS{"index.html": {Data: []byte(testIndex)}})
	if err != nil {
		t.Fatal(err)
	}
	p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Subject: "sub-alice",
		Display: "alice@acme.test", Role: principal.RoleOrgAdmin, OrganizationID: uuid.Must(uuid.NewV7())}
	return &stepUpWorld{t: t, idp: idp, keys: keys, session: admin.NewSession(p, "en", time.Now()),
		handler: admin.NewHandler(admin.Deps{Static: static, Keys: keys, OIDC: admin.NewOIDC(admin.OIDCConfig{}), StepUp: stepUp,
			PublicURL: "https://admin.test"})}
}

func (w *stepUpWorld) serve(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://admin.test"+path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, req)
	return rec
}

func cookieOf(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// stepUp runs a step-up with the claims the provider puts into the ID token and returns the callback response.
func (w *stepUpWorld) stepUp(claims map[string]any) *httptest.ResponseRecorder {
	w.t.Helper()
	value, err := w.keys.Seal(admin.SessionCookie, w.session)
	if err != nil {
		w.t.Fatal(err)
	}
	start := w.serve("/api/auth/stepup?return_to=%2Fdevices%2Fx", &http.Cookie{Name: admin.SessionCookie, Value: value})
	if start.Code != http.StatusFound {
		w.t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	loc, _ := url.Parse(start.Header().Get("Location"))
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), w.idp.URL+"/authorize") || q.Get("prompt") != "login" || q.Get("max_age") != "60" ||
		q.Get("login_hint") != "alice@acme.test" || q.Get("client_id") != "paddock-portal-stepup" ||
		q.Get("redirect_uri") != "https://admin.test/api/auth/stepup/callback" || q.Get("code_challenge_method") != "S256" {
		w.t.Fatalf("authorization request %s", loc)
	}
	state := cookieOf(start, admin.StepUpCookie)
	if state == nil || state.SameSite != http.SameSiteLaxMode || !state.HttpOnly || !state.Secure {
		w.t.Fatalf("step-up cookie %+v", state)
	}
	w.idp.mu.Lock()
	w.idp.claims, w.idp.nonce = claims, q.Get("nonce")
	w.idp.mu.Unlock()
	// Authentik redirects back cross-site: the SameSite=Strict session cookie is not sent.
	return w.serve("/api/auth/stepup/callback?code=c&state="+url.QueryEscape(q.Get("state")), state)
}

func TestStepUp(t *testing.T) {
	now := time.Now().Unix()
	good := map[string]any{"sub": "sub-alice", "auth_time": now - 5, "amr": []string{"pwd", "mfa"}, "jti": "jti-1"}
	with := func(k string, v any) map[string]any {
		c := map[string]any{}
		for key, val := range good {
			c[key] = val
		}
		c[k] = v
		return c
	}
	t.Run("fresh step-up of the session's user", func(t *testing.T) {
		w := newStepUpWorld(t)
		res := w.stepUp(good)
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/devices/x" {
			t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
		}
		c := cookieOf(res, admin.SessionCookie)
		if c == nil || c.SameSite != http.SameSiteStrictMode {
			t.Fatalf("session cookie %+v", c)
		}
		var sess admin.Session
		if err := w.keys.Open(admin.SessionCookie, c.Value, &sess); err != nil {
			t.Fatal(err)
		}
		if sess.PID != w.session.PID || sess.StepUpJTI != "jti-1" || time.Since(time.Unix(sess.StepUpAt, 0)) > 5*time.Second ||
			sess.Principal("").StepUpAt.IsZero() {
			t.Fatalf("session %+v", sess)
		}
	})
	for name, claims := range map[string]map[string]any{
		"another user":       with("sub", "sub-carol"),
		"old authentication": with("auth_time", now-61),
		"no auth_time":       with("auth_time", 0),
		"without MFA":        with("amr", []string{"pwd"}),
	} {
		t.Run(name, func(t *testing.T) {
			w := newStepUpWorld(t)
			res := w.stepUp(claims)
			if res.Code != http.StatusFound || res.Header().Get("Location") != "/devices/x?stepup=failed" {
				t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
			}
			if c := cookieOf(res, admin.SessionCookie); c != nil {
				t.Fatalf("session issued: %+v", c)
			}
		})
	}
	t.Run("without session", func(t *testing.T) {
		w := newStepUpWorld(t)
		if res := w.serve("/api/auth/stepup?return_to=%2F"); res.Code != http.StatusUnauthorized {
			t.Fatalf("start without session: %d", res.Code)
		}
	})
	t.Run("forged state", func(t *testing.T) {
		w := newStepUpWorld(t)
		res := w.serve("/api/auth/stepup/callback?code=c&state=forged")
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/?stepup=failed" {
			t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
		}
	})
}

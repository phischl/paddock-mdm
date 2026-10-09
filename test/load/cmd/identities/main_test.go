package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// fakeGateway answers the enrollment API like the gateway: it verifies every signature with the key of the
// enrollment request, answers "processing" once and then the configured final status.
type fakeGateway struct {
	mu        sync.Mutex
	final     string
	keys      map[string]*ecdsa.PublicKey // enrollment ID → key
	polled    map[string]int
	forwarded []string
	tokens    []string
}

func newFakeGateway(final string) *fakeGateway {
	return &fakeGateway{final: final, keys: map[string]*ecdsa.PublicKey{}, polled: map[string]int{}}
}

func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	h, err := protocol.ParseHeaders(r.Header)
	if err != nil || h.Device != protocol.EnrollDevice {
		http.Error(w, "headers", http.StatusUnauthorized)
		return
	}
	g.forwarded = append(g.forwarded, r.Header.Get("X-Forwarded-For"))
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/enroll":
		var req protocol.EnrollRequest
		_ = json.Unmarshal(body, &req)
		spki, _ := base64.StdEncoding.DecodeString(req.PublicKey)
		pub, err := protocol.ParsePublicKey(spki)
		if err != nil || protocol.KeyID(spki) != h.KeyID || protocol.Verify(pub, r.Method, r.URL.RequestURI(), h, body) != nil {
			http.Error(w, "signature", http.StatusUnauthorized)
			return
		}
		id := fmt.Sprintf("e-%d", len(g.keys))
		g.keys[id] = pub
		g.tokens = append(g.tokens, req.Token)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(protocol.EnrollAccepted{EnrollmentID: id})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/enroll/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/enroll/")
		pub := g.keys[id]
		if pub == nil || protocol.Verify(pub, r.Method, r.URL.RequestURI(), h, body) != nil {
			http.Error(w, "signature", http.StatusUnauthorized)
			return
		}
		g.polled[id]++
		s := protocol.EnrollStatus{Status: protocol.EnrollProcessing}
		if g.polled[id] > 1 {
			s.Status = g.final
			if g.final == protocol.EnrollActive {
				s.DeviceID = "00000000-0000-4000-8000-" + fmt.Sprintf("%012d", len(id))
			}
		}
		_ = json.NewEncoder(w).Encode(s)
	default:
		http.NotFound(w, r)
	}
}

func writeConfig(t *testing.T, dir, name, token string) string {
	t.Helper()
	b, _ := json.Marshal(protocol.EnrollmentConfig{ServerURL: "https://unused.invalid", Token: token})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnrollsDevicesWithUsableKeys(t *testing.T) {
	g := newFakeGateway(protocol.EnrollActive)
	srv := httptest.NewServer(g)
	defer srv.Close()
	dir := t.TempDir()
	out := filepath.Join(dir, "ids.json")
	err := run(context.Background(), []string{
		"--config", writeConfig(t, dir, "a.json", "tok-a"), "--config", writeConfig(t, dir, "b.json", "tok-b"),
		"--count", "5", "--per-config", "3", "--server", srv.URL, "--forwarded-for", "--concurrency", "2", "--out", out,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var ids []Identity
	if err := json.Unmarshal(b, &ids); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 5 {
		t.Fatalf("got %d identities, want 5", len(ids))
	}
	seenIP := map[string]bool{}
	for i, id := range ids {
		if id.DeviceID == "" || id.IP != syntheticIP(i) || seenIP[id.IP] {
			t.Fatalf("identity %d: %+v", i, id)
		}
		seenIP[id.IP] = true
		der, err := base64.StdEncoding.DecodeString(id.KeyPKCS8)
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatalf("identity %d: PKCS#8: %v", i, err)
		}
		spki, _ := protocol.MarshalPublicKey(&key.(*ecdsa.PrivateKey).PublicKey)
		if protocol.KeyID(spki) != id.KeyID {
			t.Fatalf("identity %d: key ID does not match the key", i)
		}
	}
	tokens := map[string]int{}
	for _, tok := range g.tokens {
		tokens[tok]++
	}
	if tokens["tok-a"] != 3 || tokens["tok-b"] != 2 {
		t.Fatalf("tokens used %v, want 3 × tok-a and 2 × tok-b", tokens)
	}
	for _, f := range g.forwarded {
		if f == "" {
			t.Fatal("a request without X-Forwarded-For")
		}
	}
}

func TestFailsOnEnrollmentThatIsNotApproved(t *testing.T) {
	srv := httptest.NewServer(newFakeGateway(protocol.EnrollPending))
	defer srv.Close()
	dir := t.TempDir()
	err := run(context.Background(), []string{
		"--config", writeConfig(t, dir, "a.json", "tok"), "--count", "1", "--server", srv.URL, "--out", filepath.Join(dir, "ids.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "auto-approving") {
		t.Fatalf("err = %v, want a hint at the auto-approving token", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "ids.json")); statErr == nil {
		t.Fatal("output written despite the failure")
	}
}

func TestRefusesTooFewConfigurations(t *testing.T) {
	dir := t.TempDir()
	err := run(context.Background(), []string{"--config", writeConfig(t, dir, "a.json", "tok"), "--count", "1001",
		"--server", "http://paddock-gateway:8081"})
	if err == nil || !strings.Contains(err.Error(), "need 2 configurations") {
		t.Fatalf("err = %v", err)
	}
}

// TestRequiresServer (PDK-006 review 1): without --server the tool refuses instead of enrolling into the
// configuration's server_url, which may be a production installation.
func TestRequiresServer(t *testing.T) {
	dir := t.TempDir()
	err := run(context.Background(), []string{"--config", writeConfig(t, dir, "a.json", "tok"), "--count", "1"})
	if err == nil || !strings.Contains(err.Error(), "--server URL") {
		t.Fatalf("err = %v", err)
	}
}

func TestSyntheticIPsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := range 70000 {
		ip := syntheticIP(i)
		if seen[ip] {
			t.Fatalf("duplicate %s at %d", ip, i)
		}
		seen[ip] = true
	}
}

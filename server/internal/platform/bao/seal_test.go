package bao_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
)

// fakeSeal is an OpenBao stand-in for sys/seal-status and sys/unseal: three of the given shares unseal it, a share
// it does not know is refused with 400, reset=true discards the progress.
type fakeSeal struct {
	mu       sync.Mutex
	valid    map[string]bool
	progress int
	sealed   bool
	resets   int
	tokens   []string
}

func (f *fakeSeal) status(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "shamir", "initialized": true, "sealed": f.sealed, "t": 3, "n": 5, "progress": f.progress,
	})
}

func (f *fakeSeal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens = append(f.tokens, r.Header.Get("X-Vault-Token"))
	switch r.URL.Path {
	case "/v1/sys/seal-status":
		f.status(w)
	case "/v1/sys/unseal":
		var body struct {
			Key   string `json:"key"`
			Reset bool   `json:"reset"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case body.Reset:
			f.resets++
			f.progress = 0
		case !f.valid[body.Key]:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"invalid key: " + body.Key}})
			return
		default:
			f.progress++
			if f.progress >= 3 {
				f.sealed, f.progress = false, 0
			}
		}
		f.status(w)
	default:
		http.NotFound(w, r)
	}
}

// TestSealCalls: seal status, unseal with progress, a refused share and the reset need no token; the error of a
// refused share does not carry the share, even when OpenBao's answer quotes it.
func TestSealCalls(t *testing.T) {
	f := &fakeSeal{sealed: true, valid: map[string]bool{"s1": true, "s2": true, "s3": true}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c, err := bao.New(srv.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	st, err := c.SealStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st != (bao.SealStatus{Reachable: true, Initialized: true, Sealed: true, Type: "shamir", Threshold: 3, Shares: 5}) {
		t.Fatalf("SealStatus = %+v", st)
	}

	if st, err = c.Unseal(ctx, "s1"); err != nil || st.Progress != 1 || !st.Sealed {
		t.Fatalf("Unseal(s1) = %+v, %v", st, err)
	}
	_, err = c.Unseal(ctx, "secret-share-xyz")
	if !errors.Is(err, bao.ErrShareRefused) {
		t.Fatalf("Unseal(unknown) error = %v, want ErrShareRefused", err)
	}
	if strings.Contains(err.Error(), "secret-share-xyz") {
		t.Fatalf("the error carries the share: %v", err)
	}
	if err := c.ResetUnseal(ctx); err != nil {
		t.Fatal(err)
	}
	if f.resets != 1 || f.progress != 0 {
		t.Fatalf("resets %d progress %d after ResetUnseal", f.resets, f.progress)
	}
	for _, s := range []string{"s1", "s2", "s3"} {
		if st, err = c.Unseal(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if st.Sealed {
		t.Fatalf("still sealed after three shares: %+v", st)
	}
	for _, tok := range f.tokens {
		if tok != "" {
			t.Fatalf("a seal call sent a token: %q", tok)
		}
	}
}

// TestSealCallsUnreachable: an OpenBao that does not answer is an error and SealStatus{Reachable: false}.
func TestSealCallsUnreachable(t *testing.T) {
	c, err := bao.New("http://127.0.0.1:1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if st, err := c.SealStatus(ctx); err == nil || st.Reachable {
		t.Fatalf("SealStatus = %+v, %v; want unreachable", st, err)
	}
	if _, err := c.Unseal(ctx, "secret-share-xyz"); err == nil || errors.Is(err, bao.ErrShareRefused) ||
		strings.Contains(err.Error(), "secret-share-xyz") {
		t.Fatalf("Unseal on an unreachable OpenBao: %v", err)
	}
}

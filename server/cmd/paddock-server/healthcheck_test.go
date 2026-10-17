package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/config"
)

// TestHealthcheckNamesTheReason: a 503 of /readyz fails the healthcheck with the reason from the response body, so
// that `docker inspect` and ./paddock up name a sealed OpenBao (plan M8x decision 29); a 200 passes.
func TestHealthcheckNamesTheReason(t *testing.T) {
	const reason = "not ready: session keys not loaded: OpenBao is sealed or unreachable (docs/operations/openbao.md section 2)"
	ready := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !ready {
			http.Error(w, reason+strings.Repeat("x", 300), http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	common := config.Common{OpsAddr: strings.TrimPrefix(srv.URL, "http://")}

	err := runHealthcheck(context.Background(), common)
	if err == nil || !strings.HasPrefix(err.Error(), "readyz: 503 Service Unavailable: "+reason) {
		t.Fatalf("sealed: %v", err)
	}
	if len(err.Error()) > len("readyz: 503 Service Unavailable: ")+200 {
		t.Fatalf("the error carries more than 200 bytes of the body: %d", len(err.Error()))
	}
	ready = true
	if err := runHealthcheck(context.Background(), common); err != nil {
		t.Fatalf("ready: %v", err)
	}
}

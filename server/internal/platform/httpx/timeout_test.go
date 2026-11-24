package httpx_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestWriteProblemTransactionTimeout: a request whose database transaction PostgreSQL ended for exceeding
// transaction_timeout is answered 503 transaction_timeout with Retry-After: 5, also when the error wraps the timeout
// (plan M17 amendment r point 5); other 503s carry no Retry-After from here.
func TestWriteProblemTransactionTimeout(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		status     int
		code       string
		retryAfter string
	}{
		{"timeout", fmt.Errorf("list devices: %w: %w", problem.TransactionTimeout, errors.New("FATAL 25P04")), 503, "transaction_timeout", "5"},
		{"other 503", problem.SessionStoreUnavailable, 503, "session_store_unavailable", ""},
		{"internal", errors.New("boom"), 500, "internal", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			httpx.WriteProblem(rec, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil), c.err)
			var body httpx.Problem
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != c.status || body.Code != c.code {
				t.Errorf("status %d code %q, want %d %q", rec.Code, body.Code, c.status, c.code)
			}
			if got := rec.Header().Get("Retry-After"); got != c.retryAfter {
				t.Errorf("Retry-After = %q, want %q", got, c.retryAfter)
			}
		})
	}
}

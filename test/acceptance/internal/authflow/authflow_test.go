package authflow

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 5 * time.Second}
}

func TestWaitReady(t *testing.T) {
	tests := []struct {
		name     string
		notReady int32  // number of 404 answers before the flow answers
		stage    string // component of the first stage once the flow answers
		wantErr  bool
	}{
		{name: "ready at once", notReady: 0, stage: "ak-stage-identification"},
		{name: "ready after blueprints applied", notReady: 3, stage: "ak-stage-identification"},
		{name: "never ready", notReady: 1 << 30, stage: "ak-stage-identification", wantErr: true},
		{name: "unexpected first stage", notReady: 0, stage: "ak-stage-access-denied", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v3/flows/executor/paddock-admin-login/" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				if calls.Add(1) <= tt.notReady {
					http.Error(w, `{"detail":"Not found."}`, http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"component":"` + tt.stage + `"}`))
			}))
			defer srv.Close()

			err := WaitReady(context.Background(), newTestClient(t), srv.URL, "paddock-admin-login",
				300*time.Millisecond, 10*time.Millisecond)
			if (err != nil) != tt.wantErr {
				t.Fatalf("WaitReady() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDoRepeatsAuthentikStarting: a request Authentik answers with 503 "authentik starting" is sent again, with its
// body; any other 503 is returned at once.
func TestDoRepeatsAuthentikStarting(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 16)
		n, _ := r.Body.Read(body)
		if string(body[:n]) != "answer" {
			http.Error(w, "body "+string(body[:n]), http.StatusBadRequest)
			return
		}
		switch calls.Add(1) {
		case 1:
			http.Error(w, "authentik starting", http.StatusServiceUnavailable)
		case 2:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "maintenance", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	send := func() *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader("answer"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := Do(newTestClient(t), req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	if resp := send(); resp.StatusCode != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("status %d after %d calls, want 200 after 2", resp.StatusCode, calls.Load())
	}
	if resp := send(); resp.StatusCode != http.StatusServiceUnavailable || calls.Load() != 3 {
		t.Fatalf("status %d after %d calls, want 503 after 3", resp.StatusCode, calls.Load())
	}
}

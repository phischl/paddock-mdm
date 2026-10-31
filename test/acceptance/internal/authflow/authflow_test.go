package authflow

import (
	"context"
	"errors"
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
	send := func() int {
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
		return resp.StatusCode
	}
	if status := send(); status != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("status %d after %d calls, want 200 after 2", status, calls.Load())
	}
	if status := send(); status != http.StatusServiceUnavailable || calls.Load() != 3 {
		t.Fatalf("status %d after %d calls, want 503 after 3", status, calls.Load())
	}
}

// fakeClock is a TOTP clock that only moves when the test says so; its timers never fire on their own.
type fakeClock struct{ at time.Time }

func (c *fakeClock) Now() time.Time { return c.at }

func (c *fakeClock) After(time.Duration) <-chan time.Time { return nil }

func newFakeTOTP() (*TOTP, *fakeClock) {
	clock := &fakeClock{at: time.Unix(1_700_000_000, 0)}
	return &TOTP{Secret: "JBSWY3DPEHPK3PXP", now: clock.Now, after: clock.After}, clock
}

func TestTOTPCodeEndsWithContext(t *testing.T) {
	totp, _ := newFakeTOTP()
	first, err := totp.Code(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first == "" {
		t.Fatal("first caller got no code")
	}
	lastStep := totp.last

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = totp.Code(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "TOTP") {
		t.Fatalf("second caller error = %v, want the TOTP step-wait error wrapping the deadline", err)
	}
	if totp.last != lastStep {
		t.Fatal("the cancelled caller consumed a step")
	}

	cancelled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err = totp.Code(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller error = %v", err)
	}
}

func TestTOTPQueueWaitEndsWithContextAndKeepsSlot(t *testing.T) {
	totp, clock := newFakeTOTP()
	if _, err := totp.Code(context.Background()); err != nil {
		t.Fatal(err)
	}
	lastStep := totp.last

	totp.sem <- struct{}{} // another caller holds the queue of this user
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := totp.Code(ctx)
		result <- err
	}()
	cancel()
	err := <-result
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "queue") {
		t.Fatalf("queued caller error = %v, want the TOTP queue error wrapping the cancellation", err)
	}
	if totp.last != lastStep {
		t.Fatal("the queued caller consumed a step")
	}
	if len(totp.sem) != 1 {
		t.Fatal("the queued caller changed the queue slot of the holder")
	}

	<-totp.sem // the holder leaves
	clock.at = clock.at.Add(30 * time.Second)
	code, err := totp.Code(context.Background())
	if err != nil || code == "" {
		t.Fatalf("later caller got code %q, err %v; the queue slot leaked", code, err)
	}
	if totp.last != lastStep+1 {
		t.Fatalf("later caller step = %d, want %d", totp.last, lastStep+1)
	}
}

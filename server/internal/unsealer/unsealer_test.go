package unsealer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
)

var testShares = []string{"share-one-AAAA", "share-two-BBBB", "share-three-CCCC"}

// fakeBao is an OpenBao stand-in for sys/seal-status and sys/unseal.
type fakeBao struct {
	mu           sync.Mutex
	initialized  bool
	sealed       bool
	valid        map[string]bool
	threshold    int // shares needed; more than three keeps it sealed after three
	progress     int
	unsealCalls  int
	resets       int
	statusCalls  int
	submittedKey []string
}

func newFakeBao(sealed bool) *fakeBao {
	v := map[string]bool{}
	for _, s := range testShares {
		v[s] = true
	}
	return &fakeBao{initialized: true, sealed: sealed, valid: v, threshold: 3}
}

func (f *fakeBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status := func() {
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "shamir", "initialized": f.initialized,
			"sealed": f.sealed, "t": 3, "n": 5, "progress": f.progress})
	}
	switch r.URL.Path {
	case "/v1/sys/seal-status":
		f.statusCalls++
		status()
	case "/v1/sys/unseal":
		var body struct {
			Key   string `json:"key"`
			Reset bool   `json:"reset"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Reset {
			f.resets++
			f.progress = 0
			status()
			return
		}
		f.unsealCalls++
		f.submittedKey = append(f.submittedKey, body.Key)
		if !f.valid[body.Key] {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"invalid key " + body.Key}})
			return
		}
		f.progress++
		if f.progress >= f.threshold {
			f.sealed, f.progress = false, 0
		}
		status()
	case "/v1/sys/health":
		status()
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeBao) counts() (unseals, resets, statuses int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unsealCalls, f.resets, f.statusCalls
}

// fakeStore records the unsealer's report.
type fakeStore struct {
	state      autounseal.State
	stateErr   error
	reports    []bool
	unseals    int
	failures   []string
	stateCalls int
}

func (s *fakeStore) State(context.Context) (autounseal.State, error) {
	s.stateCalls++
	return s.state, s.stateErr
}
func (s *fakeStore) Report(_ context.Context, present bool) error {
	s.reports = append(s.reports, present)
	return nil
}
func (s *fakeStore) RecordUnseal(context.Context) error { s.unseals++; return nil }
func (s *fakeStore) RecordFailure(_ context.Context, reason string) error {
	s.failures = append(s.failures, reason)
	return nil
}

func writeShares(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "auto-unseal-shares")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// captureLogs routes slog to a buffer for the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func assertNoShare(t *testing.T, where, text string) {
	t.Helper()
	for _, s := range testShares {
		if strings.Contains(text, s) {
			t.Fatalf("%s contains a share: %s", where, text)
		}
	}
}

type harness struct {
	bao   *fakeBao
	store *fakeStore
	u     *Unsealer
	logs  *bytes.Buffer
	now   time.Time
}

func newHarness(t *testing.T, sealed bool, state autounseal.State, sharesFile string) *harness {
	t.Helper()
	h := &harness{bao: newFakeBao(sealed), store: &fakeStore{state: state}, logs: captureLogs(t),
		now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	srv := httptest.NewServer(h.bao)
	t.Cleanup(srv.Close)
	c, err := bao.New(srv.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	h.u = New(c, h.store, sharesFile)
	h.u.now = func() time.Time { return h.now }
	return h
}

func threeShares() string { return strings.Join(testShares, "\n") + "\n" }

func TestReadShares(t *testing.T) {
	long := strings.Repeat("x", MaxShareBytes+1)
	for _, tc := range []struct {
		name, content string
		want          string // substring of the error, "" for present
	}{
		{"three lines", threeShares(), ""},
		{"surrounding whitespace", "  share-one-AAAA \n\tshare-two-BBBB\nshare-three-CCCC\n\n", ""},
		{"crlf", "share-one-AAAA\r\nshare-two-BBBB\r\nshare-three-CCCC\r\n", ""},
		{"empty", "", "holds 0 lines"},
		{"two lines", "share-one-AAAA\nshare-two-BBBB\n", "holds 2 lines"},
		{"four lines", threeShares() + "share-four-DDDD\n", "holds 4 lines"},
		{"empty line", "share-one-AAAA\n\nshare-three-CCCC\n", "line 2 of the shares file is empty"},
		{"long line", "share-one-AAAA\n" + long + "\nshare-three-CCCC\n", "line 2 of the shares file is longer than 128 bytes"},
		{"huge file", strings.Repeat("share-one-AAAA\n", 200), "longer than"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shares, present, err := ReadShares(writeShares(t, tc.content))
			if tc.want == "" {
				if err != nil || !present || len(shares) != 3 || shares[0] != testShares[0] || shares[2] != testShares[2] {
					t.Fatalf("ReadShares = %q, %v, %v", shares, present, err)
				}
				return
			}
			if err == nil || present || shares != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadShares = %q, %v, %v; want error containing %q", shares, present, err, tc.want)
			}
			assertNoShare(t, "the error", err.Error())
			if strings.Contains(err.Error(), long) {
				t.Fatal("the error carries the long line")
			}
		})
	}
	if _, present, err := ReadShares(filepath.Join(t.TempDir(), "missing")); present || err == nil {
		t.Fatalf("missing file: present=%v err=%v", present, err)
	}
	if _, present, err := ReadShares("/dev/null"); present || err == nil || !strings.Contains(err.Error(), "holds 0 lines") {
		t.Fatalf("/dev/null: present=%v err=%v", present, err)
	}
}

func TestTickDisabledDoesNotUnseal(t *testing.T) {
	h := newHarness(t, true, autounseal.StateDisabled, writeShares(t, threeShares()))
	h.u.Tick(context.Background())
	if unseals, _, _ := h.bao.counts(); unseals != 0 {
		t.Fatalf("%d unseal calls with the setting disabled", unseals)
	}
	if len(h.store.reports) != 1 || !h.store.reports[0] {
		t.Fatalf("reports = %v, want [true]", h.store.reports)
	}
	if got := testutil.ToFloat64(metricSettingEnabled); got != 0 {
		t.Fatalf("paddock_unsealer_setting_enabled = %v, want 0", got)
	}
	if got := testutil.ToFloat64(metricSharesPresent); got != 1 {
		t.Fatalf("paddock_unsealer_shares_present = %v, want 1", got)
	}
}

func TestTickUnseals(t *testing.T) {
	h := newHarness(t, true, autounseal.StateEnabled, writeShares(t, threeShares()))
	before := testutil.ToFloat64(metricUnseals.WithLabelValues("success"))
	h.u.Tick(context.Background())
	if unseals, resets, _ := h.bao.counts(); unseals != 3 || resets != 0 {
		t.Fatalf("unseal calls %d resets %d, want 3 and 0", unseals, resets)
	}
	if h.bao.sealed {
		t.Fatal("the stand-in is still sealed")
	}
	if h.store.unseals != 1 || len(h.store.failures) != 0 || len(h.store.reports) != 1 || !h.store.reports[0] {
		t.Fatalf("store = %+v", h.store)
	}
	if got := testutil.ToFloat64(metricUnseals.WithLabelValues("success")) - before; got != 1 {
		t.Fatalf("paddock_unsealer_unseals_total{result=success} grew by %v, want 1", got)
	}
	if got := testutil.ToFloat64(metricSettingEnabled); got != 1 {
		t.Fatalf("paddock_unsealer_setting_enabled = %v, want 1", got)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "OpenBao unsealed automatically") || !strings.Contains(logs, "shares_submitted=3") {
		t.Fatalf("logs lack the unseal line:\n%s", logs)
	}
	assertNoShare(t, "the log", logs)

	h.u.Tick(context.Background())
	if unseals, _, _ := h.bao.counts(); unseals != 3 {
		t.Fatalf("an unsealed OpenBao got %d more unseal calls", unseals-3)
	}
	if len(h.store.reports) != 2 {
		t.Fatalf("reports = %v after the second tick", h.store.reports)
	}
}

func TestTickInvalidShareBacksOff(t *testing.T) {
	h := newHarness(t, true, autounseal.StateEnabled, writeShares(t, threeShares()))
	delete(h.bao.valid, testShares[1])
	before := testutil.ToFloat64(metricUnseals.WithLabelValues("failure"))
	h.u.Tick(context.Background())
	unseals, resets, _ := h.bao.counts()
	if unseals != 2 || resets != 1 {
		t.Fatalf("unseal calls %d resets %d, want 2 and 1", unseals, resets)
	}
	if len(h.store.failures) != 1 || h.store.failures[0] != autounseal.FailureReasonInvalidShare || h.store.unseals != 0 {
		t.Fatalf("store = %+v", h.store)
	}
	if got := testutil.ToFloat64(metricUnseals.WithLabelValues("failure")) - before; got != 1 {
		t.Fatalf("paddock_unsealer_unseals_total{result=failure} grew by %v, want 1", got)
	}
	assertNoShare(t, "the log", h.logs.String())

	h.now = h.now.Add(FailureBackoff - time.Second)
	h.u.Tick(context.Background())
	if u, _, _ := h.bao.counts(); u != 2 {
		t.Fatalf("an unseal call within the backoff (%d calls)", u)
	}
	if len(h.store.reports) != 2 {
		t.Fatalf("the backoff tick did not report: %v", h.store.reports)
	}

	h.now = h.now.Add(time.Second)
	h.u.Tick(context.Background())
	if u, _, _ := h.bao.counts(); u != 4 {
		t.Fatalf("after the backoff: %d unseal calls, want 4", u)
	}
}

func TestTickStillSealed(t *testing.T) {
	h := newHarness(t, true, autounseal.StateEnabled, writeShares(t, threeShares()))
	h.bao.threshold = 4
	h.u.Tick(context.Background())
	if unseals, resets, _ := h.bao.counts(); unseals != 3 || resets != 1 {
		t.Fatalf("unseal calls %d resets %d, want 3 and 1", unseals, resets)
	}
	if len(h.store.failures) != 1 || h.store.failures[0] != autounseal.FailureReasonStillSealed {
		t.Fatalf("failures = %v", h.store.failures)
	}
}

// unsealDown is a Seal whose unseal call fails without an answer (connection refused after the status read).
type unsealDown struct{ Seal }

func (unsealDown) Unseal(context.Context, string) (bao.SealStatus, error) {
	return bao.SealStatus{}, errors.New("bao: unseal: connection refused")
}

func TestTickUnreachableDuringUnseal(t *testing.T) {
	h := newHarness(t, true, autounseal.StateEnabled, writeShares(t, threeShares()))
	h.u.seal = unsealDown{h.u.seal}
	h.u.Tick(context.Background())
	if len(h.store.failures) != 1 || h.store.failures[0] != autounseal.FailureReasonUnreachable {
		t.Fatalf("failures = %v", h.store.failures)
	}
	if _, resets, _ := h.bao.counts(); resets != 1 {
		t.Fatalf("resets = %d, want 1", resets)
	}
}

func TestTickOpenBaoUnreachable(t *testing.T) {
	h := newHarness(t, true, autounseal.StateEnabled, writeShares(t, threeShares()))
	down, err := bao.New("http://127.0.0.1:1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	h.u.seal = down
	h.u.Tick(context.Background())
	if len(h.store.failures) != 0 || h.store.unseals != 0 || len(h.store.reports) != 1 {
		t.Fatalf("store = %+v; an unreachable seal status is no attempt, but a report", h.store)
	}
}

func TestTickStateUnreadable(t *testing.T) {
	h := newHarness(t, true, autounseal.StateEnabled, writeShares(t, threeShares()))
	h.store.stateErr = errors.New("connection refused")
	h.u.Tick(context.Background())
	h.now = h.now.Add(30 * time.Second)
	h.u.Tick(context.Background())
	if unseals, _, statuses := h.bao.counts(); unseals != 0 || statuses != 0 {
		t.Fatalf("OpenBao calls with an unreadable setting: %d unseal, %d status", unseals, statuses)
	}
	if n := strings.Count(h.logs.String(), "the setting cannot be read"); n != 1 {
		t.Fatalf("%d warnings within a minute, want 1:\n%s", n, h.logs.String())
	}
	if !strings.Contains(h.logs.String(), "level=WARN") {
		t.Fatalf("the warning is not at warn level:\n%s", h.logs.String())
	}
	h.now = h.now.Add(30 * time.Second)
	h.u.Tick(context.Background())
	if n := strings.Count(h.logs.String(), "the setting cannot be read"); n != 2 {
		t.Fatalf("%d warnings after a minute, want 2", n)
	}
	if len(h.store.reports) != 0 {
		t.Fatalf("reports = %v; an unreadable setting returns before the report", h.store.reports)
	}
}

func TestTickNoUnsealWhenNotNeeded(t *testing.T) {
	for _, tc := range []struct {
		name        string
		initialized bool
		sealed      bool
		shares      string
	}{
		{"uninitialized", false, true, threeShares()},
		{"already unsealed", true, false, threeShares()},
		{"no shares", true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.sealed, autounseal.StateEnabled, writeShares(t, tc.shares))
			h.bao.initialized = tc.initialized
			h.u.Tick(context.Background())
			if unseals, _, _ := h.bao.counts(); unseals != 0 {
				t.Fatalf("%d unseal calls", unseals)
			}
			want := tc.shares != ""
			if len(h.store.reports) != 1 || h.store.reports[0] != want {
				t.Fatalf("reports = %v, want [%v]", h.store.reports, want)
			}
			if got := testutil.ToFloat64(metricSharesPresent); got != boolGauge(want) {
				t.Fatalf("paddock_unsealer_shares_present = %v", got)
			}
		})
	}
}

// TestDeletedSharesTakeEffect: the file is re-read on every tick, so deleting it stops the unseal at the next tick.
func TestDeletedSharesTakeEffect(t *testing.T) {
	path := writeShares(t, threeShares())
	h := newHarness(t, false, autounseal.StateEnabled, path)
	h.u.Tick(context.Background())
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	h.bao.sealed = true
	h.u.Tick(context.Background())
	if unseals, _, _ := h.bao.counts(); unseals != 0 {
		t.Fatalf("%d unseal calls after the file was deleted", unseals)
	}
	if len(h.store.reports) != 2 || !h.store.reports[0] || h.store.reports[1] {
		t.Fatalf("reports = %v, want [true false]", h.store.reports)
	}
}

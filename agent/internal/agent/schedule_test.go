package agent

import (
	"testing"
	"time"
)

func TestAfterFailure(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, w := range want {
		if got := afterFailure(i+1, 0.5, 0); got != w {
			t.Errorf("failure %d: %v, want %v", i+1, got, w)
		}
	}
	if lo, hi := afterFailure(1, 0, 0), afterFailure(1, 0.999999, 0); lo != 24*time.Second || hi < 35*time.Second || hi > 36*time.Second {
		t.Errorf("jitter bounds: %v .. %v", lo, hi)
	}
	if got := afterFailure(1, 0.5, 2*time.Minute); got != 2*time.Minute {
		t.Errorf("Retry-After ignored: %v", got)
	}
}

func TestAfterSuccess(t *testing.T) {
	if got := afterSuccess(287, 0.1); got != 287*time.Second {
		t.Errorf("server interval: %v", got)
	}
	if got := afterSuccess(0, 0.5); got != DefaultCheckin {
		t.Errorf("fallback: %v", got)
	}
	if got := afterSuccess(0, 0); got != 240*time.Second {
		t.Errorf("fallback jitter: %v", got)
	}
}

func TestTriggered(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	if got := triggered(now, now.Add(-time.Hour), 0.5); got != now.Add(7500*time.Millisecond) {
		t.Errorf("random delay: %v", got.Sub(now))
	}
	if got := triggered(now, now.Add(-10*time.Second), 0); got != now.Add(50*time.Second) {
		t.Errorf("at most one per minute: %v", got.Sub(now))
	}
}

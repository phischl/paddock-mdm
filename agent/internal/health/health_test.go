package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "agent.sock")
	s := NewState("1.2.3")
	s.Update(func(r *Report) { r.Status, r.LastBundleVersion, r.LastError = StatusDegraded, 7, "check-in: timeout" })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, s) }()
	var r Report
	var err error
	for range 100 {
		if r, err = Get(ctx, path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || r.Status != StatusDegraded || r.Version != "1.2.3" || r.LastBundleVersion != 7 || r.LastError == "" {
		t.Fatalf("report %+v, %v", r, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

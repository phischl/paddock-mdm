package worker

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestRolloutsRunCancelledIsQuiet: a round that fails only because shutdown cancelled the context ends Run with nil
// and logs no warning (PDK-1035).
func TestRolloutsRunCancelledIsQuiet(t *testing.T) {
	platform, err := db.NewPlatformPool(context.Background(), pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	r := NewRollouts(nil, platform, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not end")
	}
	if strings.Contains(logs.String(), "rollout round failed") {
		t.Fatalf("warning logged on shutdown: %s", logs.String())
	}
}

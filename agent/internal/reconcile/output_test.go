package reconcile_test

import (
	"context"
	"errors"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
)

// TestOSOutput: stdout of a tool, a non-zero exit as *ExitError with the output, the output cut at MaxOutput with
// ErrOutputLimit, and no tool below a test root.
func TestOSOutput(t *testing.T) {
	ctx := context.Background()
	host := reconcile.OS{Root: "/"}
	out, err := host.Output(ctx, "sh", "-c", "echo out; echo err >&2")
	if err != nil || string(out) != "out\n" {
		t.Fatalf("%q %v", out, err)
	}
	out, err = host.Output(ctx, "sh", "-c", "echo partial; exit 3")
	var exit *reconcile.ExitError
	if !errors.As(err, &exit) || exit.Code != 3 || string(out) != "partial\n" {
		t.Fatalf("%q %v", out, err)
	}
	out, err = host.Output(ctx, "sh", "-c", "while :; do printf '%01024d' 0; done")
	if !errors.Is(err, reconcile.ErrOutputLimit) || len(out) != reconcile.MaxOutput {
		t.Fatalf("%d bytes, %v", len(out), err)
	}
	if _, err := host.Output(ctx, "/nonexistent/tool"); err == nil {
		t.Fatal("a missing tool ran")
	}
	if _, err := (reconcile.OS{Root: t.TempDir()}).Output(ctx, "sh", "-c", "echo x"); err == nil {
		t.Fatal("a tool ran below a test root")
	}
}

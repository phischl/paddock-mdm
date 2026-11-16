package op_test

import (
	"context"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/platform/op"
)

// TestOpNames: a context without a name is Unknown, and an inner name replaces an outer one (a round's audited action
// is labelled with its code).
func TestOpNames(t *testing.T) {
	ctx := context.Background()
	if got := op.From(ctx); got != op.Unknown {
		t.Fatalf("From(background) = %q, want %q", got, op.Unknown)
	}
	round := op.With(ctx, "cache-sync")
	if got := op.From(round); got != "cache-sync" {
		t.Fatalf("From = %q, want cache-sync", got)
	}
	if got := op.From(op.With(round, "device.enrolled")); got != "device.enrolled" {
		t.Fatalf("inner name = %q, want device.enrolled", got)
	}
	if got := op.From(op.With(ctx, "")); got != op.Unknown {
		t.Fatalf("empty name = %q, want %q", got, op.Unknown)
	}
}

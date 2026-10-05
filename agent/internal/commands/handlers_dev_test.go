//go:build paddock_dev

package commands_test

import (
	"context"
	"testing"

	"github.com/paddock-mdm/paddock/agent/internal/commands"
	"github.com/paddock-mdm/paddock/pkg/command"
)

// TestNoopInDevelopmentBuilds: development builds (TAGS=paddock_dev) know the noop command; release builds do not.
func TestNoopInDevelopmentBuilds(t *testing.T) {
	h, ok := commands.Handlers(nil)[commands.TypeNoop]
	if !ok {
		t.Fatal("noop missing")
	}
	if status, _ := h(context.Background(), &command.Command{Type: commands.TypeNoop}); status != "succeeded" {
		t.Fatalf("status %s", status)
	}
}

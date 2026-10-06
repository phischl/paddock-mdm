//go:build !paddock_dev

package commands_test

import (
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/commands"
)

// TestReleaseBuildsHaveNoNoop: the noop command exists only in development builds.
func TestReleaseBuildsHaveNoNoop(t *testing.T) {
	if _, ok := commands.Handlers(nil)["noop"]; ok {
		t.Fatal("noop in a release build")
	}
}

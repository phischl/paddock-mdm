package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestRolloutRefusedNamesProblemCode: a refused host rollout command names the problem code the API answers with.
func TestRolloutRefusedNamesProblemCode(t *testing.T) {
	cmd := adminCommand{name: "agent-rollout", version: "1.2.0"}
	for _, c := range []struct {
		err  error
		want string
	}{
		{problem.InvalidState.WithDetail("only published releases can be rolled out"),
			"agent-rollout 1.2.0: refused: problem invalid_state: only published releases can be rolled out\n"},
		{problem.AlreadyExists.WithDetail("this release already has a rollout; resume it instead"),
			"agent-rollout 1.2.0: refused: problem already_exists: this release already has a rollout; resume it instead\n"},
		{errors.New("connection refused"), "agent-rollout 1.2.0: connection refused\n"},
	} {
		var out strings.Builder
		if err := rolloutRefused(&out, cmd, c.err); !errors.Is(err, c.err) {
			t.Errorf("rolloutRefused returned %v, want %v", err, c.err)
		}
		if out.String() != c.want {
			t.Errorf("rolloutRefused printed %q, want %q", out.String(), c.want)
		}
	}
}

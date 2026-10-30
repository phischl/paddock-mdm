package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// TestUninstallUnreadablePlanDiscards (PDK-341): a helper that gives up on the agent's unreadable plan removes the plan,
// its binary copy and the then empty directory below /root, which no reboot clears; a manual run with a plan of its
// own leaves the agent's preparation alone.
func TestUninstallUnreadablePlanDiscards(t *testing.T) {
	for name, own := range map[string]bool{"agent's plan": true, "other plan": false} {
		t.Run(name, func(t *testing.T) {
			layout := paths.Layout{Root: t.TempDir()}
			dir := filepath.Dir(layout.UninstallPlan())
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, f := range []string{layout.UninstallPlan(), layout.UninstallBinary()} {
				if err := os.WriteFile(f, []byte("not a plan"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			plan := layout.UninstallPlan()
			if !own {
				plan = filepath.Join(t.TempDir(), "plan.json")
				if err := os.WriteFile(plan, []byte("not a plan"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if code := runUninstall(context.Background(), layout, []string{"--plan", plan}); code != 1 {
				t.Fatalf("exit %d", code)
			}
			_, err := os.Stat(dir)
			if own && !os.IsNotExist(err) {
				t.Fatalf("preparation kept: %v", err)
			}
			if !own {
				for _, f := range []string{layout.UninstallPlan(), layout.UninstallBinary()} {
					if _, err := os.Stat(f); err != nil {
						t.Fatalf("agent's preparation removed: %v", err)
					}
				}
			}
		})
	}
}

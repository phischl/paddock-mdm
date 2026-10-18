package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
)

// componentPackages are the components read from dpkg (plan M8d decision 52).
var componentPackages = map[string]string{
	"paddock_revoke": "paddock-revoke",
	"himmelblau":     "himmelblau",
	"fleetd":         reconcile.FleetdPackage,
}

// refreshComponents puts the installed component versions into the health report, once per check-in. A component that
// is not installed is "" (the key is present); a lookup that fails keeps the last value.
func (a *Agent) refreshComponents(ctx context.Context) {
	prev := a.d.Health.Report().Components
	next := map[string]string{"paddockd": buildinfo.Version}
	if v, err := a.d.SupervisorVersion(ctx); err == nil {
		next["paddock_supervisor"] = v
	} else {
		slog.DebugContext(ctx, "supervisor version unknown; keeping the last one", "error", err)
		next["paddock_supervisor"] = prev["paddock_supervisor"]
	}
	for key, pkg := range componentPackages {
		if a.d.Sys == nil {
			next[key] = prev[key]
			continue
		}
		next[key] = a.d.Sys.PackageVersion(pkg)
	}
	a.d.Health.Update(func(r *health.Report) { r.Components = next })
}

// supervisorVersion runs `paddock-supervisor version`; "" when the supervisor is not installed.
func supervisorVersion(ctx context.Context, l paths.Layout) (string, error) {
	bin := l.Join(supervisorpkg.Binary)
	if _, err := os.Stat(bin); errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output() //nolint:gosec // the supervisor binary of the layout
	if err != nil {
		return "", fmt.Errorf("%s version: %w", bin, err)
	}
	return strings.TrimSpace(string(out)), nil
}

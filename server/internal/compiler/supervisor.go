package compiler

import (
	"context"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
)

// supervisorRelease are the paddock-supervisor packages of the current rollout by arch and the percentage of devices
// its waves reached. Both are part of the reconcile digest, so an advancing wave recompiles every device.
type supervisorRelease struct {
	Packages map[string]bundle.PackageRef `json:"packages"`
	Percent  int                          `json:"percent"`
}

// supervisorPackages returns the paddock-supervisor packages of the current rollout (plan M8d decision 30, ADR 0037
// amendment 2026-10-18): while it runs or after it completed, with the percentage of devices its waves reached;
// nothing while no rollout exists or the current one is halted.
func supervisorPackages(ctx context.Context, q *pgstore.Queries) (*supervisorRelease, error) {
	rows, err := q.SupervisorPackages(ctx)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	out := &supervisorRelease{Packages: make(map[string]bundle.PackageRef, len(rows))}
	for _, r := range rows {
		out.Packages[r.Arch] = bundle.PackageRef{Version: r.PackageVersion, URLPath: r.ObjectKey, SHA256: r.Sha256}
		if int(r.CurrentWaveIndex) < len(r.Waves) {
			out.Percent = agentrelease.Percent(r.Status, int32s(r.Waves), int(r.CurrentWaveIndex))
		}
	}
	return out, nil
}

// supervisorFor returns the supervisor packages a device's bundle carries (design contract 6): only once the
// rollout's waves reached the device's bucket — the gate of the agent offer — and none for an agent that reports no
// semantic version, as there is no release for it to follow.
func supervisorFor(rel *supervisorRelease, device uuid.UUID, agentVersion string) map[string]bundle.PackageRef {
	if rel == nil || len(rel.Packages) == 0 || agentrelease.ValidateVersion(agentVersion) != nil ||
		!agentrelease.Eligible(device, rel.Percent) {
		return nil
	}
	return rel.Packages
}

func int32s(v []int32) []int {
	out := make([]int, len(v))
	for i, x := range v {
		out[i] = int(x)
	}
	return out
}

// himmelblauTarget records the Himmelblau version the compiler renders as the component target (plan M8d decision
// 53); an unchanged target is not rewritten.
func (c *Compiler) himmelblauTarget(ctx context.Context, q *pgstore.Queries) error {
	if c.cfg.HimmelblauVersion == "" {
		return nil
	}
	return q.SetHimmelblauTarget(ctx, pgstore.SetHimmelblauTargetParams{Version: c.cfg.HimmelblauVersion, Source: "PADDOCK_HIMMELBLAU_VERSION"})
}

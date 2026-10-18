package compiler

import (
	"context"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
)

// supervisorPackages returns the paddock-supervisor packages of the current release by arch (plan M8d decision 30):
// the release of the most recently completed rollout, nothing while none completed or the latest rollout is
// halted or running.
func supervisorPackages(ctx context.Context, q *pgstore.Queries) (map[string]bundle.PackageRef, error) {
	rows, err := q.SupervisorPackages(ctx)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	out := make(map[string]bundle.PackageRef, len(rows))
	for _, r := range rows {
		out[r.Arch] = bundle.PackageRef{Version: r.PackageVersion, URLPath: r.ObjectKey, SHA256: r.Sha256}
	}
	return out, nil
}

// supervisorFor returns the supervisor packages a device's bundle carries: none for an agent that reports no
// semantic version, as there is no release for it to follow.
func supervisorFor(packages map[string]bundle.PackageRef, agentVersion string) map[string]bundle.PackageRef {
	if len(packages) == 0 || agentrelease.ValidateVersion(agentVersion) != nil {
		return nil
	}
	return packages
}

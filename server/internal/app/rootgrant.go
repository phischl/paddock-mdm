package app

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// requireRootGrant is the rule for every change that grants root in effect (plan M8s decision 7g): an organization
// administrator with a fresh step-up. An API token is refused with the step-up detail first, whatever its role: it can
// never complete the step-up (ADR 0034 decision 3). Any other role is problem.Forbidden; system principals pass.
func requireRootGrant(ctx context.Context, rec Recorder) error {
	p, ok := principal.From(ctx)
	if !ok {
		return problem.Unauthenticated
	}
	if p.APITokenID != uuid.Nil {
		return rec.RequireStepUp()
	}
	if p.Kind != principal.KindSystem && p.Role != principal.RoleOrgAdmin {
		return problem.Forbidden.WithDetail("granting root needs an organization administrator")
	}
	return rec.RequireStepUp()
}

// rootGrantGuard compares the organization's grants before and after a change in the same transaction (plan M8s
// decisions 7g–7j). begin takes the organization's privilege lock first, so a concurrent change that could complete a
// combination waits and is compared against this one.
type rootGrantGuard struct {
	before *Identity
}

func beginRootGrantGuard(ctx context.Context, q *pgstore.Queries) (rootGrantGuard, error) {
	if err := q.LockOrganizationPrivileges(ctx); err != nil {
		return rootGrantGuard{}, fmt.Errorf("lock privileges: %w", err)
	}
	before, err := LoadIdentity(ctx, q)
	return rootGrantGuard{before: before}, err
}

// grows reads the grants after the change and reports whether any user gained root on any device or device scope.
func (g rootGrantGuard) grows(ctx context.Context, q *pgstore.Queries) (bool, error) {
	after, err := LoadIdentity(ctx, q)
	if err != nil {
		return false, err
	}
	return rootGrantGrows(g.before, after), nil
}

// check applies requireRootGrant when the change grew a root grant. For the codes that carry effective_class
// (profiles and assignments) the param records the effect of the change: full.
func (g rootGrantGuard) check(ctx context.Context, q *pgstore.Queries, rec Recorder, effectiveClassParam bool) error {
	grows, err := g.grows(ctx, q)
	if err != nil || !grows {
		return err
	}
	if effectiveClassParam {
		rec.SetParam("effective_class", string(privilege.ClassFull))
	}
	return requireRootGrant(ctx, rec)
}

// rootGrantGrows reports whether a user's effective profile grants root after the change where it did not before.
// The device contexts are every active device (with its device groups before and after the change), a device in no
// group, and a device in each single device group an assignment names, so a grant through a group without devices is
// judged as well. Users with the same groups and no assignment of their own share one evaluation.
func rootGrantGrows(before, after *Identity) bool {
	type pair struct{ before, after []uuid.UUID }
	contexts := map[string]pair{}
	add := func(b, a []uuid.UUID) {
		contexts[idsKey(b)+"→"+idsKey(a)] = pair{b, a}
	}
	add(nil, nil)
	for _, id := range []*Identity{before, after} {
		for _, a := range id.Assignments {
			if a.DeviceGroupID != uuid.Nil {
				add([]uuid.UUID{a.DeviceGroupID}, []uuid.UUID{a.DeviceGroupID})
			}
		}
	}
	for device, groups := range after.deviceGroups {
		was, ok := before.deviceGroups[device]
		if !ok {
			was = groups
		}
		add(was, groups)
	}

	direct := map[uuid.UUID]bool{}
	for _, id := range []*Identity{before, after} {
		for _, a := range id.Assignments {
			if a.SubjectType == privilege.SubjectUser {
				direct[a.SubjectID] = true
			}
		}
	}
	seen := map[string]bool{}
	for _, id := range []*Identity{before, after} {
		for user := range id.Users {
			key := idsKey(before.userGroups[user]) + "→" + idsKey(after.userGroups[user])
			if direct[user] {
				key = user.String()
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			for _, c := range contexts {
				if privilege.RootGrantGrows(before.Effective(user, c.before), after.Effective(user, c.after)) {
					return true
				}
			}
		}
	}
	return false
}

func idsKey(ids []uuid.UUID) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = id.String()
	}
	slices.Sort(s)
	return strings.Join(s, ",")
}

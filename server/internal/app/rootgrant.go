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

// grows reads the grants after the change and reports whether any user gained root on any device or device scope;
// fresh are devices that become active with the change (approve, quarantine release).
func (g rootGrantGuard) grows(ctx context.Context, q *pgstore.Queries, fresh ...uuid.UUID) (bool, error) {
	after, err := LoadIdentity(ctx, q)
	if err != nil {
		return false, err
	}
	return rootGrantGrows(g.before, after, fresh...), nil
}

// check applies requireRootGrant when the change grew a root grant. For the codes that carry effective_class
// (profiles and assignments) the param records the effect of the change: full.
func (g rootGrantGuard) check(ctx context.Context, q *pgstore.Queries, rec Recorder, effectiveClassParam bool, fresh ...uuid.UUID) error {
	grows, err := g.grows(ctx, q, fresh...)
	if err != nil || !grows {
		return err
	}
	if effectiveClassParam {
		rec.SetParam("effective_class", string(privilege.ClassFull))
	}
	return requireRootGrant(ctx, rec)
}

// rootGrantGrows reports whether a user's effective profile grants root after the change where it did not before
// (plan M8s decisions 7g and 7g-bis). The device contexts are every device in any state (its device groups before and
// after the change; a device that is new, or listed in fresh because it becomes active, starts without groups), a
// device in no group, and a device in each single device group an assignment names, so a grant through a group without
// devices is judged as well. The subjects are every user, plus synthetic members: one of each group an assignment
// names, one of all of them together and one of no group, so a combination aimed at an empty group or at everyone is
// judged before a sync fills it. Users with the same groups and no assignment of their own share one evaluation.
func rootGrantGrows(before, after *Identity, fresh ...uuid.UUID) bool {
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
	for _, id := range []*Identity{before, after} {
		for device := range id.memberGroups {
			was := before.memberGroups[device]
			if slices.Contains(fresh, device) {
				was = nil
			}
			add(was, after.memberGroups[device])
		}
	}
	for _, device := range fresh {
		add(nil, after.memberGroups[device])
	}

	type subject struct {
		user          uuid.UUID
		before, after []uuid.UUID
	}
	subjects := map[string]subject{}
	direct := map[uuid.UUID]bool{}
	var groups []uuid.UUID
	for _, id := range []*Identity{before, after} {
		for _, a := range id.Assignments {
			switch a.SubjectType {
			case privilege.SubjectUser:
				direct[a.SubjectID] = true
			case privilege.SubjectGroup:
				if !slices.Contains(groups, a.SubjectID) {
					groups = append(groups, a.SubjectID)
				}
			}
		}
	}
	for _, id := range []*Identity{before, after} {
		for user := range id.Users {
			s := subject{user, before.userGroups[user], after.userGroups[user]}
			key := idsKey(s.before) + "→" + idsKey(s.after)
			if direct[user] {
				key = user.String()
			}
			subjects[key] = s
		}
	}
	synthetic := uuid.New()
	for _, g := range groups {
		subjects["synthetic:"+g.String()] = subject{synthetic, []uuid.UUID{g}, []uuid.UUID{g}}
	}
	subjects["synthetic:all"] = subject{synthetic, groups, groups}
	subjects["synthetic:none"] = subject{synthetic, nil, nil}

	for _, s := range subjects {
		for _, c := range contexts {
			if privilege.RootGrantGrows(effectiveWith(before, s.user, s.before, c.before), effectiveWith(after, s.user, s.after, c.after)) {
				return true
			}
		}
	}
	return false
}

// effectiveWith is the effective profile of user as a member of userGroups on a device in deviceGroups.
func effectiveWith(id *Identity, user uuid.UUID, userGroups, deviceGroups []uuid.UUID) privilege.EffectiveProfile {
	return privilege.Effective(privilege.Input{
		UserID: user, UserGroups: userGroups, DeviceGroups: deviceGroups, Assignments: id.Assignments, Profiles: id.Profiles,
	})
}

func idsKey(ids []uuid.UUID) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = id.String()
	}
	slices.Sort(s)
	return strings.Join(s, ",")
}

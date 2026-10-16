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

// grantGuard is the check of a change to a profile, an assignment or a declarative document (plan M8s decision
// 7g-quater): the root witnesses of the union of the commands of every assigned profile, before and after the change.
// It over-approximates on purpose: it does not depend on who is in which group or which device is in which state, so
// no shape of subject or device can hide a combination. begin takes the organization's privilege lock first.
type grantGuard struct {
	before []string
}

func beginGrantGuard(ctx context.Context, q *pgstore.Queries) (grantGuard, error) {
	if err := q.LockOrganizationPrivileges(ctx); err != nil {
		return grantGuard{}, fmt.Errorf("lock privileges: %w", err)
	}
	before, err := assignedWitnesses(ctx, q, nil)
	return grantGuard{before: before}, err
}

// grows reports whether the assigned profiles have a root witness after the change that they did not have before.
func (g grantGuard) grows(ctx context.Context, q *pgstore.Queries) (bool, error) {
	after, err := assignedWitnesses(ctx, q, nil)
	return len(privilege.NewWitnesses(g.before, after)) > 0, err
}

// check applies requireRootGrant when the change added a witness and records the effect as effective_class full.
func (g grantGuard) check(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
	grows, err := g.grows(ctx, q)
	if err != nil || !grows {
		return err
	}
	rec.SetParam("effective_class", string(privilege.ClassFull))
	return requireRootGrant(ctx, rec)
}

// assignedWitnesses are the root witnesses of the union of the commands of every profile with an assignment that
// include accepts (nil: every assignment); the profiles are read once into a map.
func assignedWitnesses(ctx context.Context, q *pgstore.Queries, include func(privilege.Assignment) bool) ([]string, error) {
	profiles, err := loadProfiles(ctx, q)
	if err != nil {
		return nil, err
	}
	assignments, err := loadAssignments(ctx, q)
	if err != nil {
		return nil, err
	}
	byID := make(map[uuid.UUID]privilege.Profile, len(profiles))
	for _, p := range profiles {
		byID[p.ID] = p
	}
	class := privilege.ClassNone
	var commands []string
	seen := map[uuid.UUID]bool{}
	for _, a := range assignments {
		p, ok := byID[a.ProfileID]
		if !ok || seen[p.ID] || (include != nil && !include(a)) {
			continue
		}
		seen[p.ID] = true
		class = privilege.MaxReportedClass(class, p.Class)
		commands = append(commands, p.Commands...)
	}
	return privilege.RootWitnesses(class, commands), nil
}

// subjectGuard is the exact check of a change to Paddock group membership, device groups, approval or quarantine
// release (plan M8s decision 7g-quater): every real user on every device, compared by root witnesses, so a user who
// is Full already still needs the step-up for a new way to root. begin takes the organization's privilege lock first.
type subjectGuard struct {
	before *Identity
}

func beginSubjectGuard(ctx context.Context, q *pgstore.Queries) (subjectGuard, error) {
	if err := q.LockOrganizationPrivileges(ctx); err != nil {
		return subjectGuard{}, fmt.Errorf("lock privileges: %w", err)
	}
	before, err := LoadIdentity(ctx, q)
	return subjectGuard{before: before}, err
}

// check applies requireRootGrant when a real user gained a root witness on a device; fresh are devices that become
// active with the change (approve, quarantine release).
func (g subjectGuard) check(ctx context.Context, q *pgstore.Queries, rec Recorder, fresh ...uuid.UUID) error {
	after, err := LoadIdentity(ctx, q)
	if err != nil {
		return err
	}
	if !subjectsGain(g.before, after, fresh...) {
		return nil
	}
	return requireRootGrant(ctx, rec)
}

// requireTokenGroups is the gate of an enrollment token at creation (plan M8s decisions 7g-ter and 7g-quater): the
// witnesses of the profiles assigned to everyone or to one of the token's device groups, against those assigned to
// everyone. A device that enrolls into the groups gains nothing new, or the token needs requireRootGrant. For a token
// that approves automatically this is the binding gate; approval keeps its own guard.
func requireTokenGroups(ctx context.Context, q *pgstore.Queries, rec Recorder, groups []uuid.UUID) error {
	if len(groups) == 0 {
		return nil
	}
	if err := q.LockOrganizationPrivileges(ctx); err != nil {
		return fmt.Errorf("lock privileges: %w", err)
	}
	everywhere, err := assignedWitnesses(ctx, q, func(a privilege.Assignment) bool { return a.DeviceGroupID == uuid.Nil })
	if err != nil {
		return err
	}
	inGroups, err := assignedWitnesses(ctx, q, func(a privilege.Assignment) bool {
		return a.DeviceGroupID == uuid.Nil || slices.Contains(groups, a.DeviceGroupID)
	})
	if err != nil {
		return err
	}
	if len(privilege.NewWitnesses(everywhere, inGroups)) > 0 {
		return requireRootGrant(ctx, rec)
	}
	return nil
}

// subjectsGain reports whether a real user gains a root witness on a device: every device in any state with its
// device groups before and after the change (a new device, or one in fresh because it becomes active, starts without
// groups), and a device in no group. Users with the same groups and no assignment of their own share one evaluation.
func subjectsGain(before, after *Identity, fresh ...uuid.UUID) bool {
	type pair struct{ before, after []uuid.UUID }
	contexts := map[string]pair{}
	add := func(b, a []uuid.UUID) {
		contexts[idsKey(b)+"→"+idsKey(a)] = pair{b, a}
	}
	add(nil, nil)
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
			b, a := before.userGroups[user], after.userGroups[user]
			key := idsKey(b) + "→" + idsKey(a)
			if direct[user] {
				key = user.String()
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			for _, c := range contexts {
				if privilege.RootGrantGrows(effectiveWith(before, user, b, c.before), effectiveWith(after, user, a, c.after)) {
					return true
				}
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

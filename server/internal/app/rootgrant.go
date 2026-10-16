package app

import (
	"context"
	"fmt"
	"maps"
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

// grantGuard is the check of a change to a profile, an assignment or a declarative document (plan M8s decisions
// 7g-quater and 7g-quinquies). It runs two checks and the change grows when either does: (a) the root witnesses of the
// union of the commands of every assigned profile, which covers future and empty subjects, and (b) the exact witness
// gain of every real user on every device in any state, which covers spreading an existing combination to more users.
// begin takes the organization's privilege lock first.
type grantGuard struct {
	union    []string
	subjects *Identity
}

func beginGrantGuard(ctx context.Context, q *pgstore.Queries) (grantGuard, error) {
	if err := q.LockOrganizationPrivileges(ctx); err != nil {
		return grantGuard{}, fmt.Errorf("lock privileges: %w", err)
	}
	union, err := assignedWitnesses(ctx, q, nil)
	if err != nil {
		return grantGuard{}, err
	}
	subjects, err := loadGuardIdentity(ctx, q)
	return grantGuard{union: union, subjects: subjects}, err
}

// grows reports whether the change added a witness to the union of the assigned profiles or to a real user.
func (g grantGuard) grows(ctx context.Context, q *pgstore.Queries) (bool, error) {
	union, err := assignedWitnesses(ctx, q, nil)
	if err != nil {
		return false, err
	}
	if len(privilege.NewWitnesses(g.union, union)) > 0 {
		return true, nil
	}
	after, err := loadGuardIdentity(ctx, q)
	if err != nil {
		return false, err
	}
	return subjectsGain(g.subjects, after), nil
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
	before, err := loadGuardIdentity(ctx, q)
	return subjectGuard{before: before}, err
}

// check applies requireRootGrant when a real user gained a root witness on a device; fresh are devices that become
// active with the change (approve, quarantine release).
func (g subjectGuard) check(ctx context.Context, q *pgstore.Queries, rec Recorder, fresh ...uuid.UUID) error {
	after, err := loadGuardIdentity(ctx, q)
	if err != nil {
		return err
	}
	if !subjectsGain(g.before, after, fresh...) {
		return nil
	}
	return requireRootGrant(ctx, rec)
}

// requireTokenGroups is the gate of an enrollment token at creation (plan M8s decisions 7g-ter, 7g-quater and
// 7g-quinquies): (a) the witnesses of the profiles assigned to everyone or to one of the token's device groups, against
// those assigned to everyone, and (b) the exact gain of every real user on a new device in the token's groups. When
// either grows the token needs requireRootGrant. For a token that approves automatically this is the binding gate;
// approval keeps its own guard.
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
	before, err := loadGuardIdentity(ctx, q)
	if err != nil {
		return err
	}
	if newDeviceGains(before, groups) {
		return requireRootGrant(ctx, rec)
	}
	return nil
}

// loadGuardIdentity is LoadIdentity plus the device groups of the usable auto-approve enrollment tokens, the future
// devices that the guards judge (plan M8s decision 7g-sexies).
func loadGuardIdentity(ctx context.Context, q *pgstore.Queries) (*Identity, error) {
	id, err := LoadIdentity(ctx, q)
	if err != nil {
		return nil, err
	}
	if id.tokenGroups, err = q.ListAutoApproveTokenGroups(ctx); err != nil {
		return nil, fmt.Errorf("load auto-approve token groups: %w", err)
	}
	return id, nil
}

// newDeviceGains reports whether a device that joins groups as a new device gives a real or future user a root
// witness (plan M8s decisions 7g-quinquies and 7g-sexies).
func newDeviceGains(before *Identity, groups []uuid.UUID) bool {
	after := *before
	after.memberGroups = maps.Clone(before.memberGroups)
	after.memberGroups[uuid.New()] = groups
	return subjectsGain(before, &after)
}

// subjectsGain reports whether a real or future user gains a root witness on a device (future users and devices are
// the stand-ins of plan M8s decision 7g-sexies): every device in any state with its
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
	// Future devices: a device in each device group that a usable auto-approve token enrolls into or an assignment
	// names (plan M8s decision 7g-sexies).
	var subjectGroups []uuid.UUID
	for _, id := range []*Identity{before, after} {
		for _, g := range id.tokenGroups {
			add([]uuid.UUID{g}, []uuid.UUID{g})
		}
		for _, a := range id.Assignments {
			if a.DeviceGroupID != uuid.Nil {
				add([]uuid.UUID{a.DeviceGroupID}, []uuid.UUID{a.DeviceGroupID})
			}
			if a.SubjectType == privilege.SubjectGroup && !slices.Contains(subjectGroups, a.SubjectID) {
				subjectGroups = append(subjectGroups, a.SubjectID)
			}
		}
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
			// A user created by the change is judged from nothing, so it never shares an evaluation with an existing one.
			_, existed := before.Users[user]
			key := idsKey(b) + "→" + idsKey(a)
			if !existed {
				key = "new:" + key
			}
			if direct[user] {
				key = user.String()
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			for _, c := range contexts {
				was := effectiveWith(before, user, b, c.before)
				if !existed {
					// A user created by the change had nothing before.
					was = privilege.EffectiveProfile{}
				}
				if privilege.RootGrantGrows(was, effectiveWith(after, user, a, c.after)) {
					return true
				}
			}
		}
	}
	// Future users: one with no groups and no assignment of its own, and one member of each group an assignment names.
	future := uuid.New()
	memberships := [][]uuid.UUID{nil}
	for _, g := range subjectGroups {
		memberships = append(memberships, []uuid.UUID{g})
	}
	for _, groups := range memberships {
		for _, c := range contexts {
			if privilege.RootGrantGrows(effectiveWith(before, future, groups, c.before), effectiveWith(after, future, groups, c.after)) {
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

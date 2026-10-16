package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// The two halves of a root-equivalent pair: each is restricted in effect on its own (plan M8s decision 7h).
var (
	writerCommands = []string{"/usr/bin/tee /opt/x/run.sh"}
	runnerCommands = []string{"/opt/x/run.sh"}
)

type combinationWorld struct {
	privilegesHarness
	devices   *app.Devices
	admin     principal.Principal
	steppedUp principal.Principal
	operator  principal.Principal
	token     principal.Principal
	user      uuid.UUID
	writer    uuid.UUID
	runner    uuid.UUID
}

func newCombinationWorld(t *testing.T) combinationWorld {
	t.Helper()
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	w := combinationWorld{privilegesHarness: h, devices: app.NewDevices(h.runner, pool), user: uuid.Must(uuid.NewV7())}
	w.admin = h.account(t, principal.RoleOrgAdmin, false)
	w.steppedUp = h.account(t, principal.RoleOrgAdmin, true)
	w.operator = h.account(t, principal.RoleOrgOperator, true)
	token := h.create(t, w.steppedUp, "ci", principal.RoleOrgAdmin)
	if w.token, _, err = h.tokens.Authenticate(context.Background(), token.Secret, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(context.Background(), `INSERT INTO app_user (id, organization_id, authentik_pk, username, source)
		VALUES ($1, $2, $3, $4, 'local')`, w.user, h.org, "c"+w.user.String()[24:], "combo-"+w.user.String()[24:]+"@x.test"); err != nil {
		t.Fatal(err)
	}
	w.writer = w.profile(t, "writer", writerCommands)
	w.runner = w.profile(t, "runner", runnerCommands)
	return w
}

func (w combinationWorld) ctx(p principal.Principal) context.Context {
	return principal.With(context.Background(), p)
}

// profile creates a profile as the operator: neither half needs a step-up on its own.
func (w combinationWorld) profile(t *testing.T, name string, commands []string) uuid.UUID {
	t.Helper()
	p, err := w.privileges.CreateProfile(w.ctx(w.operator), privilege.Profile{Name: name, Class: privilege.ClassRestricted,
		Commands: commands, Lecture: privilege.LectureOnce})
	if err != nil {
		t.Fatalf("operator creating %s = %v", name, err)
	}
	return p.ID
}

func (w combinationWorld) assign(p principal.Principal, profile uuid.UUID, group *uuid.UUID) error {
	_, err := w.privileges.CreateAssignment(w.ctx(p), app.NewAssignment{ProfileID: profile, SubjectType: privilege.SubjectUser,
		SubjectID: &w.user, DeviceGroupID: group})
	return err
}

// TestCombinedRootGrant: an assignment that completes a writer/exec pair across two profiles needs an organization
// administrator with a step-up; an operator is forbidden and a token gets the token detail (plan M8s decisions 7g and
// 7k). The audit params record the effect as effective_class full.
func TestCombinedRootGrant(t *testing.T) {
	w := newCombinationWorld(t)
	if err := w.assign(w.operator, w.writer, nil); err != nil {
		t.Fatalf("the first half = %v", err)
	}
	got := w.during(t, func() {
		if err := w.assign(w.operator, w.runner, nil); !errors.Is(err, problem.Forbidden) {
			t.Errorf("operator completing the pair = %v", err)
		}
		if err := w.assign(w.token, w.runner, nil); !errors.Is(err, problem.StepUpRequired) ||
			!strings.Contains(problem.From(err).Detail, "API tokens") {
			t.Errorf("token completing the pair = %v", err)
		}
		if err := w.assign(w.admin, w.runner, nil); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("admin without step-up completing the pair = %v", err)
		}
	})
	if strings.Join(got, ",") != "profile_assignment.created:denied:forbidden,profile_assignment.created:denied:step_up_required,"+
		"profile_assignment.created:denied:step_up_required" {
		t.Fatalf("actions %v", got)
	}
	var stored int
	if err := w.super.QueryRow(context.Background(), "SELECT count(*) FROM profile_assignment WHERE profile_id = $1", w.runner).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("refused assignments stored: %d (%v)", stored, err)
	}
	if err := w.assign(w.steppedUp, w.runner, nil); err != nil {
		t.Fatalf("stepped-up admin completing the pair = %v", err)
	}
	if ev := w.lastEvent(t); ev.Params["effective_class"] != "full" || !ev.Actor.StepUp {
		t.Fatalf("assignment event %+v", ev)
	}
}

// TestCombinedRootGrantByProfileChange: changing the commands of an assigned harmless profile so that it completes
// a pair with another profile of the same user is gated like an assignment.
func TestCombinedRootGrantByProfileChange(t *testing.T) {
	w := newCombinationWorld(t)
	harmless := w.profile(t, "harmless", []string{"/usr/bin/systemctl restart nginx.service"})
	for _, p := range []uuid.UUID{w.writer, harmless} {
		if err := w.assign(w.operator, p, nil); err != nil {
			t.Fatal(err)
		}
	}
	commands := runnerCommands
	if _, err := w.privileges.UpdateProfile(w.ctx(w.operator), harmless, app.ProfilePatch{Commands: &commands}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator completing the pair by a profile change = %v", err)
	}
	if _, err := w.privileges.UpdateProfile(w.ctx(w.steppedUp), harmless, app.ProfilePatch{Commands: &commands}); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
	// Once granted, a rename of either half grants nothing new.
	name := "harmless-renamed"
	if _, err := w.privileges.UpdateProfile(w.ctx(w.operator), harmless, app.ProfilePatch{Name: &name}); err != nil {
		t.Fatalf("rename after the grant = %v", err)
	}
}

// TestCombinedRootGrantByDeviceGroup: a device joining the device group of the second half extends the root grant to
// that device and is gated; a device group without the grant is not.
func TestCombinedRootGrantByDeviceGroup(t *testing.T) {
	w := newCombinationWorld(t)
	ctx := context.Background()
	scoped, other, device := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(ctx, "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $3, 'scoped'), ($2, $3, 'other')",
		scoped, other, w.org); err != nil {
		t.Fatal(err)
	}
	if _, err := w.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", device, w.org); err != nil {
		t.Fatal(err)
	}
	if err := w.assign(w.operator, w.writer, nil); err != nil {
		t.Fatal(err)
	}
	// Within a device group, the second half grants root only to its devices; the assignment itself is gated too.
	if err := w.assign(w.steppedUp, w.runner, &scoped); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.SetGroups(w.ctx(w.operator), device, []uuid.UUID{other}); err != nil {
		t.Fatalf("operator moving the device to a group without the grant = %v", err)
	}
	if _, err := w.devices.SetGroups(w.ctx(w.operator), device, []uuid.UUID{other, scoped}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator moving the device into the grant = %v", err)
	}
	if _, err := w.devices.SetGroups(w.ctx(w.steppedUp), device, []uuid.UUID{other, scoped}); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
}

// TestCombinedRootGrantDeclarative: a document that completes the pair needs an organization administrator with a
// step-up, although no single profile in it is effectively Full.
func TestCombinedRootGrantDeclarative(t *testing.T) {
	h := newConfigHarness(t)
	operator := h.account(t, principal.RoleOrgOperator, true)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	// A global grant reaches every user of the organization; without users it grants nothing.
	user := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), `INSERT INTO app_user (id, organization_id, authentik_pk, username, source)
		VALUES ($1, $2, $3, $4, 'local')`, user, h.org, "d"+user.String()[24:], "doc-"+user.String()[24:]+"@x.test"); err != nil {
		t.Fatal(err)
	}
	doc := h.export(t, steppedUp)
	*doc.PermissionProfiles = append(*doc.PermissionProfiles,
		declarative.PermissionProfile{Name: "writer", Class: "restricted", Commands: writerCommands, Lecture: "once"},
		declarative.PermissionProfile{Name: "runner", Class: "restricted", Commands: runnerCommands, Lecture: "once"})
	*doc.ProfileAssignments = append(*doc.ProfileAssignments,
		declarative.ProfileAssignment{Profile: "writer", Subject: declarative.Subject{Type: "global"}},
		declarative.ProfileAssignment{Profile: "runner", Subject: declarative.Subject{Type: "global"}})
	if _, _, err := h.config.Apply(principal.With(context.Background(), operator), raw(t, doc), ""); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator applying a combined root grant = %v", err)
	}
	if n := h.count(t, "SELECT count(*) FROM permission_profile WHERE organization_id = $1", h.org); n != 0 {
		t.Fatal("the refused document was applied")
	}
	if _, _, err := h.config.Apply(principal.With(context.Background(), steppedUp), raw(t, doc), ""); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
}

// TestCombinedRootGrantOnInactiveDevices: a pending device is judged like an active one when it joins the device
// group of a grant, and approving a pending device that already sits in such a group is gated, because it activates
// the grant (plan M8s decision 7g-bis).
func TestCombinedRootGrantOnInactiveDevices(t *testing.T) {
	w := newCombinationWorld(t)
	ctx := context.Background()
	scoped, pending, waiting := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(ctx, "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'scoped')", scoped, w.org); err != nil {
		t.Fatal(err)
	}
	if _, err := w.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $3, 'p', 'pending'), ($2, $3, 'w', 'pending')",
		pending, waiting, w.org); err != nil {
		t.Fatal(err)
	}
	if err := w.assign(w.operator, w.writer, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.assign(w.steppedUp, w.runner, &scoped); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.SetGroups(w.ctx(w.operator), pending, []uuid.UUID{scoped}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator moving a pending device into the grant = %v", err)
	}
	// A device that an enrollment token put into the group: its approval activates the grant.
	if _, err := w.super.Exec(ctx, "INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)",
		w.org, scoped, waiting); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.Approve(w.ctx(w.operator), waiting); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator approving a device into the grant = %v", err)
	}
	if _, err := w.devices.Approve(w.ctx(w.admin), waiting); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("admin without step-up approving a device into the grant = %v", err)
	}
	if _, err := w.devices.Approve(w.ctx(w.steppedUp), waiting); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
	// A device outside every grant is approved as before.
	if _, err := w.devices.Approve(w.ctx(w.operator), pending); err != nil {
		t.Fatalf("operator approving a device without a grant = %v", err)
	}
}

// TestCombinedRootGrantOnEmptyGroup: a combination aimed at a group without members, or at everyone in an organization
// without users, is judged through a synthetic member, so a later sync cannot complete it ungated.
func TestCombinedRootGrantOnEmptyGroup(t *testing.T) {
	w := newCombinationWorld(t)
	group := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), `INSERT INTO user_group (id, organization_id, slug, name, source)
		VALUES ($1, $2, 'empty', 'Empty', 'local')`, group, w.org); err != nil {
		t.Fatal(err)
	}
	global := func(p principal.Principal, profile uuid.UUID) error {
		_, err := w.privileges.CreateAssignment(w.ctx(p), app.NewAssignment{ProfileID: profile, SubjectType: privilege.SubjectGlobal})
		return err
	}
	toGroup := func(p principal.Principal, profile uuid.UUID) error {
		_, err := w.privileges.CreateAssignment(w.ctx(p), app.NewAssignment{ProfileID: profile, SubjectType: privilege.SubjectGroup, SubjectID: &group})
		return err
	}
	if err := toGroup(w.operator, w.writer); err != nil {
		t.Fatalf("the first half to the empty group = %v", err)
	}
	if err := toGroup(w.operator, w.runner); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator completing the pair in an empty group = %v", err)
	}
	if err := global(w.operator, w.runner); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator completing the pair for everyone = %v", err)
	}
	if err := toGroup(w.steppedUp, w.runner); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
}

// TestEnrollmentTokenIntoRootGrant: a token whose device group would give a device root grants needs an organization
// administrator with a step-up when it is created; an API token gets the token detail (plan M8s decision 7g-ter).
func TestEnrollmentTokenIntoRootGrant(t *testing.T) {
	w := newCombinationWorld(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	keys := func(context.Context) ([]protocol.BundleKey, error) { return []protocol.BundleKey{{KeyID: "k1"}}, nil }
	tokens := app.NewEnrollmentTokens(w.privilegesHarness.runner, pool, keys, keys, &fakeTokenCache{}, "https://device.test")
	scoped, plain := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $3, 'scoped'), ($2, $3, 'plain')",
		scoped, plain, w.org); err != nil {
		t.Fatal(err)
	}
	if err := w.assign(w.operator, w.writer, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.assign(w.steppedUp, w.runner, &scoped); err != nil {
		t.Fatal(err)
	}
	in := func(group uuid.UUID) app.TokenInput {
		return app.TokenInput{Name: "t-" + group.String()[24:], MaxUses: 5, ExpiresAt: time.Now().Add(time.Hour), AutoApprove: true, DeviceGroupID: &group}
	}
	if _, err := tokens.Create(w.ctx(w.admin), in(scoped)); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("admin without step-up = %v", err)
	}
	if _, err := tokens.Create(w.ctx(w.token), in(scoped)); !errors.Is(err, problem.StepUpRequired) ||
		!strings.Contains(problem.From(err).Detail, "API tokens") {
		t.Fatalf("API token = %v", err)
	}
	if _, err := tokens.Create(w.ctx(w.steppedUp), in(scoped)); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
	if _, err := tokens.Create(w.ctx(w.admin), in(plain)); err != nil {
		t.Fatalf("a token into a group without a grant = %v", err)
	}
}

// TestWitnessUnion covers the cases of plan M8s decision 7g-quater: a pair completed by an assignment to a group the
// user is not in yet, a new pair next to an unscoped Full grant, and a membership that gives a user who is Full
// already a new way to root.
func TestWitnessUnion(t *testing.T) {
	t.Run("direct grant plus a group the user is not in", func(t *testing.T) {
		w := newCombinationWorld(t)
		group := uuid.Must(uuid.NewV7())
		if _, err := w.super.Exec(context.Background(), `INSERT INTO user_group (id, organization_id, slug, name, source)
			VALUES ($1, $2, 'later', 'Later', 'local')`, group, w.org); err != nil {
			t.Fatal(err)
		}
		if err := w.assign(w.operator, w.writer, nil); err != nil {
			t.Fatal(err)
		}
		in := app.NewAssignment{ProfileID: w.runner, SubjectType: privilege.SubjectGroup, SubjectID: &group}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.operator), in); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator = %v", err)
		}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.admin), in); !errors.Is(err, problem.StepUpRequired) {
			t.Fatalf("admin without step-up = %v", err)
		}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.steppedUp), in); err != nil {
			t.Fatalf("stepped-up admin = %v", err)
		}
	})

	t.Run("new pair next to an unscoped Full grant", func(t *testing.T) {
		w := newCombinationWorld(t)
		full, err := w.privileges.CreateProfile(w.ctx(w.steppedUp), privilege.Profile{Name: "full", Class: privilege.ClassFull, Lecture: privilege.LectureOnce})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.steppedUp), app.NewAssignment{ProfileID: full.ID, SubjectType: privilege.SubjectGlobal}); err != nil {
			t.Fatal(err)
		}
		if err := w.assign(w.operator, w.writer, nil); err != nil {
			t.Fatalf("the first half = %v", err)
		}
		if err := w.assign(w.operator, w.runner, nil); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator completing a pair next to a Full grant = %v", err)
		}
	})

	t.Run("membership adds a witness to a Full user", func(t *testing.T) {
		w := newCombinationWorld(t)
		pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		groups := app.NewUserGroups(w.privilegesHarness.runner, pool, newDirectory())
		group := uuid.Must(uuid.NewV7())
		if _, err := w.super.Exec(context.Background(), `INSERT INTO user_group (id, organization_id, slug, name, source, authentik_pk)
			VALUES ($1, $2, 'pair', 'Pair', 'local', 'gpk')`, group, w.org); err != nil {
			t.Fatal(err)
		}
		full, err := w.privileges.CreateProfile(w.ctx(w.steppedUp), privilege.Profile{Name: "full", Class: privilege.ClassFull, Lecture: privilege.LectureOnce})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.assign(w.steppedUp, full.ID, nil); err != nil {
			t.Fatal(err)
		}
		for _, p := range []uuid.UUID{w.writer, w.runner} {
			if _, err := w.privileges.CreateAssignment(w.ctx(w.steppedUp), app.NewAssignment{ProfileID: p, SubjectType: privilege.SubjectGroup, SubjectID: &group}); err != nil {
				t.Fatal(err)
			}
		}
		if err := groups.AddMember(w.ctx(w.admin), group, w.user); !errors.Is(err, problem.StepUpRequired) {
			t.Fatalf("admin without step-up adding a Full user to the pair = %v", err)
		}
		if err := groups.AddMember(w.ctx(w.steppedUp), group, w.user); err != nil {
			t.Fatalf("stepped-up admin = %v", err)
		}
	})
}

// spreadWorld: user one holds the writer/exec pair (approved by an administrator with a step-up); user two is a member
// of group A and holds the writer only (plan M8s decision 7g-quinquies).
type spreadWorld struct {
	combinationWorld
	two    uuid.UUID
	groupA uuid.UUID
}

func newSpreadWorld(t *testing.T) spreadWorld {
	t.Helper()
	w := spreadWorld{combinationWorld: newCombinationWorld(t), two: uuid.Must(uuid.NewV7()), groupA: uuid.Must(uuid.NewV7())}
	ctx := context.Background()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO app_user (id, organization_id, authentik_pk, username, source) VALUES ($1, $2, $3, $4, 'local')`,
			[]any{w.two, w.org, "u" + w.two.String()[24:], "two-" + w.two.String()[24:] + "@x.test"}},
		{`INSERT INTO user_group (id, organization_id, slug, name, source, authentik_pk) VALUES ($1, $2, 'group-a', 'A', 'local', 'apk')`,
			[]any{w.groupA, w.org}},
		{`INSERT INTO user_group_member (organization_id, group_id, user_id) VALUES ($1, $2, $3)`, []any{w.org, w.groupA, w.two}},
	} {
		if _, err := w.super.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
	for _, p := range []uuid.UUID{w.writer, w.runner} {
		if err := w.assign(w.steppedUp, p, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.privileges.CreateAssignment(w.ctx(w.operator), app.NewAssignment{ProfileID: w.writer, SubjectType: privilege.SubjectUser, SubjectID: &w.two}); err != nil {
		t.Fatalf("the writer alone for user two = %v", err)
	}
	return w
}

// TestSpreadingAnApprovedCombination: once a pair exists, giving it to another real user needs the step-up again,
// through a new assignment, a re-scope, a profile change, a declarative document or an enrollment token
// (plan M8s decision 7g-quinquies).
func TestSpreadingAnApprovedCombination(t *testing.T) {
	t.Run("assignment to the group", func(t *testing.T) {
		w := newSpreadWorld(t)
		in := app.NewAssignment{ProfileID: w.runner, SubjectType: privilege.SubjectGroup, SubjectID: &w.groupA}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.operator), in); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator = %v", err)
		}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.token), in); !errors.Is(err, problem.StepUpRequired) {
			t.Fatalf("token = %v", err)
		}
		global := app.NewAssignment{ProfileID: w.runner, SubjectType: privilege.SubjectGlobal}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.operator), global); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator, global = %v", err)
		}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.steppedUp), in); err != nil {
			t.Fatalf("stepped-up admin = %v", err)
		}
	})

	t.Run("re-scope to every device", func(t *testing.T) {
		w := newSpreadWorld(t)
		scoped := uuid.Must(uuid.NewV7())
		if _, err := w.super.Exec(context.Background(), "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'empty')", scoped, w.org); err != nil {
			t.Fatal(err)
		}
		in := app.NewAssignment{ProfileID: w.runner, SubjectType: privilege.SubjectUser, SubjectID: &w.two, DeviceGroupID: &scoped}
		// A stand-in device in the device group judges it although it has no devices (plan M8s decision 7g-sexies).
		if _, err := w.privileges.CreateAssignment(w.ctx(w.operator), in); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator, the pair for user two in a device group without devices = %v", err)
		}
		a, err := w.privileges.CreateAssignment(w.ctx(w.steppedUp), in)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.privileges.UpdateAssignmentScope(w.ctx(w.operator), a.ID, nil); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator re-scoping to every device = %v", err)
		}
	})

	t.Run("profile text", func(t *testing.T) {
		w := newSpreadWorld(t)
		other := w.profile(t, "other", []string{"/usr/bin/systemctl restart nginx.service"})
		if _, err := w.privileges.CreateAssignment(w.ctx(w.operator), app.NewAssignment{ProfileID: other, SubjectType: privilege.SubjectGroup, SubjectID: &w.groupA}); err != nil {
			t.Fatal(err)
		}
		commands := runnerCommands
		if _, err := w.privileges.UpdateProfile(w.ctx(w.operator), other, app.ProfilePatch{Commands: &commands}); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator adding the exec text to a profile of group A = %v", err)
		}
	})

	t.Run("enrollment token into a device-scoped spread", func(t *testing.T) {
		w := newSpreadWorld(t)
		d := uuid.Must(uuid.NewV7())
		if _, err := w.super.Exec(context.Background(), "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'd')", d, w.org); err != nil {
			t.Fatal(err)
		}
		// Spreading into a device group without devices is judged through its stand-in device (7g-sexies) ...
		spread := app.NewAssignment{ProfileID: w.runner, SubjectType: privilege.SubjectGroup, SubjectID: &w.groupA, DeviceGroupID: &d}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.operator), spread); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator spreading into an empty device group = %v", err)
		}
		if _, err := w.privileges.CreateAssignment(w.ctx(w.steppedUp), spread); err != nil {
			t.Fatal(err)
		}
		// ... and so is a token that enrolls devices into it.
		pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		keys := func(context.Context) ([]protocol.BundleKey, error) { return []protocol.BundleKey{{KeyID: "k1"}}, nil }
		tokens := app.NewEnrollmentTokens(w.privilegesHarness.runner, pool, keys, keys, &fakeTokenCache{}, "https://device.test")
		in := app.TokenInput{Name: "d", MaxUses: 5, ExpiresAt: time.Now().Add(time.Hour), AutoApprove: true, DeviceGroupID: &d}
		if _, err := tokens.Create(w.ctx(w.admin), in); !errors.Is(err, problem.StepUpRequired) {
			t.Fatalf("token into the spread = %v", err)
		}
		if _, err := tokens.Create(w.ctx(w.steppedUp), in); err != nil {
			t.Fatalf("stepped-up admin = %v", err)
		}
	})
}

// TestSpreadingToAnEmptyGroup: giving the second half to a group without members passes; adding a member who holds
// the first half afterwards needs the step-up.
func TestSpreadingToAnEmptyGroup(t *testing.T) {
	w := newSpreadWorld(t)
	empty := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), `INSERT INTO user_group (id, organization_id, slug, name, source, authentik_pk)
		VALUES ($1, $2, 'empty', 'Empty', 'local', 'epk')`, empty, w.org); err != nil {
		t.Fatal(err)
	}
	if _, err := w.privileges.CreateAssignment(w.ctx(w.operator), app.NewAssignment{ProfileID: w.runner, SubjectType: privilege.SubjectGroup, SubjectID: &empty}); err != nil {
		t.Fatalf("operator spreading to an empty group = %v", err)
	}
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	groups := app.NewUserGroups(w.privilegesHarness.runner, pool, newDirectory())
	if err := groups.AddMember(w.ctx(w.operator), empty, w.two); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator adding the member = %v", err)
	}
	if err := groups.AddMember(w.ctx(w.admin), empty, w.two); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("admin without step-up adding the member = %v", err)
	}
	if err := groups.AddMember(w.ctx(w.steppedUp), empty, w.two); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
}

// TestSpreadingDeclarative: a document that gives the pair to another user needs the step-up although the union of
// the assigned profiles does not change.
func TestSpreadingDeclarative(t *testing.T) {
	h := newConfigHarness(t)
	operator := h.account(t, principal.RoleOrgOperator, true)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	ctx := context.Background()
	names := []string{"one-" + uuid.NewString()[:8] + "@x.test", "two-" + uuid.NewString()[:8] + "@x.test"}
	for _, n := range names {
		id := uuid.Must(uuid.NewV7())
		if _, err := h.super.Exec(ctx, `INSERT INTO app_user (id, organization_id, authentik_pk, username, source) VALUES ($1, $2, $3, $4, 'local')`,
			id, h.org, "p"+id.String()[24:], n); err != nil {
			t.Fatal(err)
		}
	}
	doc := h.export(t, steppedUp)
	*doc.PermissionProfiles = append(*doc.PermissionProfiles,
		declarative.PermissionProfile{Name: "writer", Class: "restricted", Commands: writerCommands, Lecture: "once"},
		declarative.PermissionProfile{Name: "runner", Class: "restricted", Commands: runnerCommands, Lecture: "once"})
	for _, p := range []string{"writer", "runner"} {
		*doc.ProfileAssignments = append(*doc.ProfileAssignments,
			declarative.ProfileAssignment{Profile: p, Subject: declarative.Subject{Type: "user", Username: names[0]}})
	}
	*doc.ProfileAssignments = append(*doc.ProfileAssignments,
		declarative.ProfileAssignment{Profile: "writer", Subject: declarative.Subject{Type: "user", Username: names[1]}})
	if _, _, err := h.config.Apply(principal.With(ctx, steppedUp), raw(t, doc), ""); err != nil {
		t.Fatalf("the approved pair = %v", err)
	}
	*doc.ProfileAssignments = append(*doc.ProfileAssignments,
		declarative.ProfileAssignment{Profile: "runner", Subject: declarative.Subject{Type: "user", Username: names[1]}})
	if _, _, err := h.config.Apply(principal.With(ctx, operator), raw(t, doc), ""); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator spreading the pair = %v", err)
	}
	if _, _, err := h.config.Apply(principal.With(ctx, steppedUp), raw(t, doc), ""); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
}

// TestFutureSubjects covers plan M8s decision 7g-sexies: a usable auto-approve token's device group is judged as a
// future device, a user without groups as a future user, and a new user is judged from nothing.
func TestFutureSubjects(t *testing.T) {
	t.Run("auto-approve token into an empty device group", func(t *testing.T) {
		w := newCombinationWorld(t)
		pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		keys := func(context.Context) ([]protocol.BundleKey, error) { return []protocol.BundleKey{{KeyID: "k1"}}, nil }
		tokens := app.NewEnrollmentTokens(w.privilegesHarness.runner, pool, keys, keys, &fakeTokenCache{}, "https://device.test")
		d2 := uuid.Must(uuid.NewV7())
		if _, err := w.super.Exec(context.Background(), "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'd2')", d2, w.org); err != nil {
			t.Fatal(err)
		}
		if _, err := tokens.Create(w.ctx(w.admin), app.TokenInput{Name: "d2", MaxUses: 5, ExpiresAt: time.Now().Add(time.Hour),
			AutoApprove: true, DeviceGroupID: &d2}); err != nil {
			t.Fatalf("a token into an empty, unassigned group = %v", err)
		}
		if err := w.assign(w.operator, w.writer, &d2); err != nil {
			t.Fatalf("the first half into d2 = %v", err)
		}
		if err := w.assign(w.operator, w.runner, &d2); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator completing the pair where the token enrolls = %v", err)
		}
	})

	t.Run("future user and new users", func(t *testing.T) {
		w := newCombinationWorld(t)
		global := func(p principal.Principal, profile uuid.UUID) error {
			_, err := w.privileges.CreateAssignment(w.ctx(p), app.NewAssignment{ProfileID: profile, SubjectType: privilege.SubjectGlobal})
			return err
		}
		if err := global(w.operator, w.writer); err != nil {
			t.Fatal(err)
		}
		if err := w.assign(w.steppedUp, w.runner, nil); err != nil {
			t.Fatal(err)
		}
		if err := global(w.operator, w.runner); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator giving the second half to everyone = %v", err)
		}
		if err := global(w.steppedUp, w.runner); err != nil {
			t.Fatal(err)
		}
		pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if _, err := w.super.Exec(context.Background(), "UPDATE organization SET domains = '{x.test}' WHERE id = $1", w.org); err != nil {
			t.Fatal(err)
		}
		users := app.NewUsers(w.privilegesHarness.runner, pool, creatingDirectory{newDirectory()})
		in := app.NewUser{Username: "u2-" + uuid.NewString()[:6] + "@x.test", DisplayName: "U2"}
		if _, err := users.Create(w.ctx(w.operator), in); !errors.Is(err, problem.Forbidden) {
			t.Fatalf("operator creating a user who becomes root = %v", err)
		}
		if _, err := users.Create(w.ctx(w.steppedUp), in); err != nil {
			t.Fatalf("stepped-up admin = %v", err)
		}
	})
}

// creatingDirectory is the in-memory directory that also creates users.
type creatingDirectory struct{ *directory }

func (creatingDirectory) CreateUser(context.Context, string, ports.NewIdentityUser) (string, error) {
	return "pk-" + uuid.NewString(), nil
}

// TestNewUserNextToAPlainUser: an organization that already has a user without groups and without assignments of its
// own still judges a new user from nothing (regression: both shared one evaluation, and the new user was skipped).
func TestNewUserNextToAPlainUser(t *testing.T) {
	w := newCombinationWorld(t)
	ctx := context.Background()
	plain := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(ctx, `INSERT INTO app_user (id, organization_id, authentik_pk, username, source) VALUES ($1, $2, $3, $4, 'local')`,
		plain, w.org, "q"+plain.String()[24:], "plain-"+plain.String()[24:]+"@x.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.super.Exec(ctx, "UPDATE organization SET domains = '{x.test}' WHERE id = $1", w.org); err != nil {
		t.Fatal(err)
	}
	for _, p := range []uuid.UUID{w.writer, w.runner} {
		if _, err := w.privileges.CreateAssignment(w.ctx(w.steppedUp), app.NewAssignment{ProfileID: p, SubjectType: privilege.SubjectGlobal}); err != nil {
			t.Fatal(err)
		}
	}
	pool, err := db.NewOrgPool(ctx, pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	users := app.NewUsers(w.privilegesHarness.runner, pool, creatingDirectory{newDirectory()})
	if _, err := users.Create(w.ctx(w.operator), app.NewUser{Username: "new-" + uuid.NewString()[:6] + "@x.test", DisplayName: "New"}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator creating a user who becomes root next to a plain user = %v", err)
	}
}

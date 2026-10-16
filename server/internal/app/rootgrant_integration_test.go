package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
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

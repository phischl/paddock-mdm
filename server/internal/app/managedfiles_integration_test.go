package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestManagedFileTierRules: ordinary paths stay with the operator role; sensitive paths need an organization
// administrator with a step-up; denied paths are refused; an API token never manages a sensitive path (ADR 0034
// decision 2).
func TestManagedFileTierRules(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	files := app.NewManagedConfig(h.runner, pool)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	in := func(path, mode, content string) app.FileInput {
		return app.FileInput{Path: &path, Mode: &mode, Content: &content}
	}

	got := h.during(t, func() {
		if _, err := files.CreateFile(ctx(operator), in("/etc/cron.d/x", "0644", "x")); !errors.Is(err, problem.Forbidden) ||
			problem.From(err).Detail != "files on sensitive paths need an organization administrator" {
			t.Errorf("operator on a sensitive path = %v", err)
		}
		if _, err := files.CreateFile(ctx(admin), in("/etc/cron.d/x", "0644", "x")); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("admin without step-up = %v", err)
		}
	})
	if strings.Join(got, ",") != "managed_file.created:denied:forbidden,managed_file.created:denied:step_up_required" {
		t.Fatalf("actions %v", got)
	}
	cron, err := files.CreateFile(ctx(steppedUp), in("/etc/cron.d/x", "0644", "x"))
	if err != nil {
		t.Fatalf("stepped-up admin on a sensitive path = %v", err)
	}
	if ev := h.lastEvent(t); ev.Params["tier"] != "sensitive" || !ev.Actor.StepUp {
		t.Fatalf("sensitive event %+v", ev)
	}
	for _, denied := range []string{"/etc/ld.so.preload", "/etc/tmpfiles.d/x.conf"} {
		if _, err := files.CreateFile(ctx(steppedUp), in(denied, "0644", "x")); !errors.Is(err, problem.PathNotAllowed) {
			t.Fatalf("%s = %v", denied, err)
		}
	}
	app1, err := files.CreateFile(ctx(operator), in("/etc/myapp/app.conf", "0644", "a"))
	if err != nil {
		t.Fatalf("operator on an ordinary path = %v", err)
	}
	if ev := h.lastEvent(t); ev.Params["tier"] != "ordinary" {
		t.Fatalf("ordinary event %+v", ev)
	}
	if _, err := files.CreateFile(ctx(operator), in("/etc/myapp/hook.sh", "0755", "#!/bin/sh")); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator creating an executable = %v", err)
	}

	content := "b"
	if _, err := files.UpdateFile(ctx(admin), app1.ID, app.FileInput{Content: &content}); err != nil {
		t.Fatalf("admin changing an ordinary file = %v", err)
	}
	if _, err := files.UpdateFile(ctx(admin), cron.ID, app.FileInput{Content: &content}); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("admin changing a sensitive file without step-up = %v", err)
	}
	// Moving a sensitive file to an ordinary path changes a tier-S definition: the rule still applies.
	moved := "/etc/myapp/cron"
	if _, err := files.UpdateFile(ctx(operator), cron.ID, app.FileInput{Path: &moved}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator moving a sensitive file = %v", err)
	}
	mode := "0700"
	if _, err := files.UpdateFile(ctx(operator), app1.ID, app.FileInput{Mode: &mode}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator making a file executable = %v", err)
	}
	if err := files.DeleteFile(ctx(operator), cron.ID); err != nil {
		t.Fatalf("operator deleting a sensitive file = %v", err)
	}

	token := h.create(t, steppedUp, "ci", principal.RoleOrgAdmin)
	tp, _, err := h.tokens.Authenticate(context.Background(), token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := files.CreateFile(ctx(tp), in("/etc/profile.d/x.sh", "0644", "x")); !errors.Is(err, problem.StepUpRequired) ||
		!strings.Contains(problem.From(err).Detail, "API tokens") {
		t.Fatalf("token on a sensitive path = %v", err)
	}
	if _, err := files.CreateFile(ctx(tp), in("/opt/myapp/conf/a.ini", "0644", "x")); err != nil {
		t.Fatalf("token on an ordinary path = %v", err)
	}
}

// TestDeniedFileIsNotEffective: a stored definition on a denied path is not part of a device's effective
// configuration, an ordinary file of the same scope is.
func TestDeniedFileIsNotEffective(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	devices := app.NewDevices(h.runner, pool)
	device := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')",
		device, h.org); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(context.Background(), `INSERT INTO managed_file (id, organization_id, path, mode, content) VALUES
		(gen_random_uuid(), $1, '/etc/ld.so.preload', '0644', 'x'), (gen_random_uuid(), $1, '/etc/acme/app.conf', '0644', 'y')`,
		h.org); err != nil {
		t.Fatal(err)
	}
	auditor := h.account(t, principal.RoleOrgAuditor, false)
	cfg, err := devices.EffectiveConfig(principal.With(context.Background(), auditor), device)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Files) != 1 || cfg.Files[0].Path != "/etc/acme/app.conf" {
		t.Fatalf("effective files %+v", cfg.Files)
	}
}

// TestDeclarativeSensitiveFile: the declarative path applies the same tier rule as the per-resource use cases.
func TestDeclarativeSensitiveFile(t *testing.T) {
	h := newConfigHarness(t)
	operator := h.account(t, principal.RoleOrgOperator, true)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	doc := h.export(t, steppedUp)
	*doc.ManagedFiles = append(*doc.ManagedFiles, declarative.ManagedFile{Path: "/etc/profile.d/x.sh", Mode: "0644",
		Owner: "root", Group: "root", Content: "export X=1"})
	_, _, err := h.config.Apply(principal.With(context.Background(), operator), raw(t, doc), "")
	if !errors.Is(err, problem.Forbidden) || !strings.HasPrefix(problem.From(err).Detail, "/managed_files/0: ") {
		t.Fatalf("operator applying a sensitive file = %v", err)
	}
	if _, _, err := h.config.Apply(principal.With(context.Background(), steppedUp), raw(t, doc), ""); err != nil {
		t.Fatalf("stepped-up admin applying a sensitive file = %v", err)
	}
}

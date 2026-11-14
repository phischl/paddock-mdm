package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestCompileWarningsIsolation (PDK-918): each organization lists only its own compile warnings; a filter on another
// organization's device or assignment matches nothing; the read needs an organization role.
func TestCompileWarningsIsolation(t *testing.T) {
	w := newSoftwareTargetsWorld(t)
	h := w.h
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	uc := app.NewCompileWarnings(pool)

	foreignDevice, assignment, foreignAssignment := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'foreign-laptop', 'active')", []any{foreignDevice, w.foreignOrg}},
		{`INSERT INTO compile_warning (organization_id, device_id, assignment_id, catalog_entry_id, code, params)
			VALUES ($1, $2, $3, $4, 'audience_truncated', '{"users": 201, "kept": 200}')`, []any{h.org, w.device, assignment, w.entry}},
		{`INSERT INTO compile_warning (organization_id, device_id, assignment_id, code, params)
			VALUES ($1, $2, $3, 'flatpak_forbidden', '{"flatpak_ref": "org.gimp.GIMP"}')`, []any{w.foreignOrg, foreignDevice, foreignAssignment}},
	} {
		if _, err := h.super.Exec(context.Background(), stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}
	page := app.ListPage{Sort: "-created_at", Limit: 25}

	own, err := uc.List(w.ctx(w.auditor), app.CompileWarningQuery{Page: page})
	if err != nil {
		t.Fatal(err)
	}
	if own.Count != 1 || len(own.Items) != 1 || own.Items[0].DeviceID != w.device || own.Items[0].Hostname != "laptop" ||
		own.Items[0].AssignmentID.UUID != assignment || own.Items[0].CatalogEntryID.UUID != w.entry ||
		own.Items[0].Code != "audience_truncated" || own.Items[0].Params["users"] != float64(201) {
		t.Fatalf("own warnings %+v", own)
	}
	byAssignment, err := uc.List(w.ctx(w.operator), app.CompileWarningQuery{Page: page, AssignmentID: &assignment})
	if err != nil || byAssignment.Count != 1 {
		t.Fatalf("by assignment %+v, %v", byAssignment, err)
	}
	for name, q := range map[string]app.CompileWarningQuery{
		"foreign device":     {Page: page, DeviceID: &foreignDevice},
		"foreign assignment": {Page: page, AssignmentID: &foreignAssignment},
	} {
		got, err := uc.List(w.ctx(w.auditor), q)
		if err != nil || got.Count != 0 || len(got.Items) != 0 {
			t.Fatalf("%s: %+v, %v", name, got, err)
		}
	}

	foreign, err := uc.List(w.ctx(w.foreignAdmin), app.CompileWarningQuery{Page: page})
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Count != 1 || len(foreign.Items) != 1 || foreign.Items[0].DeviceID != foreignDevice {
		t.Fatalf("foreign warnings %+v", foreign)
	}
	if got, err := uc.List(w.ctx(w.foreignAdmin), app.CompileWarningQuery{Page: page, DeviceID: &w.device}); err != nil || got.Count != 0 {
		t.Fatalf("foreign admin filtering on our device: %+v, %v", got, err)
	}

	if _, err := uc.List(context.Background(), app.CompileWarningQuery{Page: page}); !errors.Is(err, problem.Unauthenticated) {
		t.Fatalf("a read without a principal: %v", err)
	}
}

// TestCompileWarningGrants (PDK-918): the compiler writes the warnings and the API only reads them; no other role
// reaches the table.
func TestCompileWarningGrants(t *testing.T) {
	conn := newSoftwareTargetsWorld(t).h.super
	for _, c := range []struct {
		role, privilege string
		want            bool
	}{
		{"paddock_api", "SELECT", true}, {"paddock_api", "INSERT", false}, {"paddock_api", "UPDATE", false},
		{"paddock_api", "DELETE", false},
		{"paddock_compiler", "SELECT", true}, {"paddock_compiler", "INSERT", true}, {"paddock_compiler", "DELETE", true},
		{"paddock_compiler", "UPDATE", false},
		{"paddock_worker", "SELECT", false}, {"paddock_worker", "INSERT", false},
	} {
		var got bool
		if err := conn.QueryRow(context.Background(), "SELECT has_table_privilege($1, 'compile_warning', $2)", c.role, c.privilege).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s %s on compile_warning: %v, want %v", c.role, c.privilege, got, c.want)
		}
	}
}

package app

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestDeclarativeGroupDeletionRace (review 3 of PDK-008): a managed file of a device group, committed by another
// transaction after the apply read the configuration and before it deletes the group, is not cascaded away outside
// the plan: the apply is refused with in_use, deletes nothing and records one failure.
func TestDeclarativeGroupDeletionRace(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	org, group, admin := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, sql := range []struct {
		q    string
		args []any
	}{
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Race', 'active')", []any{org, "r" + org.String()[24:]}},
		{"INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'lab')", []any{group, org}},
		{`INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
			VALUES ($1, $2, $3, 'a', 'a', 'org_admin')`, []any{admin, org, uuid.NewString()}},
	} {
		if _, err := super.Exec(ctx, sql.q, sql.args...); err != nil {
			t.Fatal(err)
		}
	}
	corr := "corr-" + t.Name()
	d := NewDeclarative(NewActionRunner(pool, nil, func(context.Context) string { return corr }), pool)
	d.afterRead = func(context.Context) error {
		_, err := super.Exec(ctx, `INSERT INTO managed_file (id, organization_id, device_group_id, path, mode, content)
			VALUES ($1, $2, $3, '/etc/late.conf', '0644', 'late')`, uuid.Must(uuid.NewV7()), org, group)
		return err
	}
	doc, _ := json.Marshal(map[string]any{"api_version": "paddock/v1", "kind": "OrganizationConfig",
		"device_groups": []any{}, "managed_files": []any{}, "managed_units": []any{}, "package_holds": []any{}, "profile_assignments": []any{}})
	p := principal.Principal{Kind: principal.KindAdmin, ID: admin, Display: "a", Role: principal.RoleOrgAdmin, OrganizationID: org}
	_, _, err = d.Apply(principal.With(ctx, p), doc, "")
	if !errors.Is(err, problem.InUse) {
		t.Fatalf("Apply = %v, want in_use", err)
	}
	var groups, files, failures int
	if err := super.QueryRow(ctx, "SELECT count(*) FROM device_group WHERE organization_id = $1", org).Scan(&groups); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, "SELECT count(*) FROM managed_file WHERE organization_id = $1", org).Scan(&files); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'config.applied'
		AND outcome = 'failure' AND error_code = 'in_use'`, corr).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if groups != 1 || files != 1 || failures != 1 {
		t.Fatalf("groups %d, files %d, failure events %d; want 1, 1, 1", groups, files, failures)
	}
}

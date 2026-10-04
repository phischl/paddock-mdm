package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestRLSLint enforces plan M0 §6.1: every table in schema public except the allow list has organization_id, and
// every table with organization_id has ENABLE + FORCE ROW LEVEL SECURITY and at least one policy.
func TestRLSLint(t *testing.T) {
	env := sharedPaddock(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	allow := map[string]bool{
		"goose_db_version": true, "organization": true, "platform_admin": true,
		// Platform data of agent releases (plan M2b decision 19), role paddock_platform only.
		"agent_release": true, "agent_artifact": true, "agent_rollout": true,
	}
	rows, err := conn.Query(ctx, `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
		       EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'organization_id'
		               AND NOT a.attisdropped) AS has_org,
		       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policies
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
		ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
	}
	var offending []string
	seen := 0
	for rows.Next() {
		var name string
		var rls, force, hasOrg bool
		var policies int64
		if err := rows.Scan(&name, &rls, &force, &hasOrg, &policies); err != nil {
			t.Fatal(err)
		}
		seen++
		if !hasOrg && !allow[name] {
			offending = append(offending, name+": no organization_id column")
			continue
		}
		if hasOrg && (!rls || !force || policies == 0) {
			offending = append(offending, name+": missing ENABLE/FORCE ROW LEVEL SECURITY or policy")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen < 6 {
		t.Fatalf("expected at least 6 tables, saw %d", seen)
	}
	if len(offending) > 0 {
		t.Fatalf("RLS lint failed:\n  %s", strings.Join(offending, "\n  "))
	}
}

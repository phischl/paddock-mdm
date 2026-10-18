package unsealer

import (
	"context"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// unsealerRoleSQL creates the role with the grants of deploy/compose/scripts/postgres-unsealer-role.sh (plan M8u
// decision 17).
const unsealerRoleSQL = `
CREATE ROLE paddock_unsealer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD 'unsealer-pw';
GRANT CONNECT ON DATABASE paddock TO paddock_unsealer;
GRANT USAGE ON SCHEMA public TO paddock_unsealer;
GRANT SELECT ON openbao_auto_unseal TO paddock_unsealer;
GRANT UPDATE (unsealer_seen_at, unsealer_shares_present, unseal_count, last_unseal_at, failure_count, last_failure_at, last_failure_reason, updated_at) ON openbao_auto_unseal TO paddock_unsealer;
`

// TestPGStore: the role paddock_unsealer reads the state and writes its report through the column grants, and may
// do nothing else (plan M8u decisions 2 and 10; stop condition S2).
func TestPGStore(t *testing.T) {
	env := pgtest.StartPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	if _, err := super.Exec(ctx, unsealerRoleSQL); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(env.Super)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("paddock_unsealer", "unsealer-pw")
	pool, err := db.NewUnsealerPool(ctx, u.String(), db.Options{ApplicationName: "test", MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	s := NewPGStore(pool)

	if st, err := s.State(ctx); err != nil || st != autounseal.StateDisabled {
		t.Fatalf("State = %q, %v", st, err)
	}
	if err := s.Report(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordUnseal(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFailure(ctx, autounseal.FailureReasonInvalidShare); err != nil {
		t.Fatal(err)
	}
	var present bool
	var unseals, failures int64
	var reason string
	if err := super.QueryRow(ctx, `SELECT unsealer_shares_present, unseal_count, failure_count, last_failure_reason
		FROM openbao_auto_unseal WHERE unsealer_seen_at IS NOT NULL AND last_unseal_at IS NOT NULL`).
		Scan(&present, &unseals, &failures, &reason); err != nil {
		t.Fatal(err)
	}
	if !present || unseals != 1 || failures != 1 || reason != autounseal.FailureReasonInvalidShare {
		t.Fatalf("row: present=%v unseals=%d failures=%d reason=%q", present, unseals, failures, reason)
	}

	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	for _, stmt := range []string{
		"UPDATE openbao_auto_unseal SET state = 'disabled' WHERE id = 1",
		"UPDATE openbao_auto_unseal SET audited_unseal_count = 0 WHERE id = 1",
		"INSERT INTO openbao_auto_unseal (id, state) VALUES (1, 'disabled')",
		"SELECT count(*) FROM organization",
		"SELECT count(*) FROM ip_allowlist_entry",
	} {
		if _, err := conn.Exec(ctx, stmt); err == nil {
			t.Errorf("paddock_unsealer may run %q", stmt)
		}
	}
}

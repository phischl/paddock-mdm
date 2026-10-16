package app_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// TestEndAllSessionsCLI: paddock-server admin end-sessions increments the session generation and records
// platform.sessions_ended with the system actor and the new generation (plan M8s decision 16).
func TestEndAllSessionsCLI(t *testing.T) {
	admin, super, _ := adminHarness(t)
	store := sessions.NewStore(valkeytest.Start(t).Client(t))
	s := app.NewSessions(admin.Runner(), store)
	for want := int64(1); want <= 2; want++ {
		gen, err := s.EndAllCLI(context.Background())
		if err != nil || gen != want {
			t.Fatalf("end sessions: %d %v, want %d", gen, err, want)
		}
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.sessions_ended'
		AND outcome = 'success' AND organization_id = $2 AND actor->>'type' = 'system' AND (params->>'generation')::int = 2`,
		"corr-"+t.Name(), uuid.Nil); n != 1 {
		t.Fatalf("%d platform.sessions_ended events of generation 2", n)
	}
}

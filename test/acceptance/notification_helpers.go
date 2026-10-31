package acceptance

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// notificationURL is a webhook URL on a public IP literal: the api validates it without a name lookup, and the path
// and query stand for the credential a real webhook URL carries.
const notificationURL = "https://93.184.215.14/services/T000/B000/XXXX?token=n-secret"

// destinationName is a unique destination name (letters, digits, spaces, '.', '_' and '-').
func destinationName(prefix string) string { return prefix + "-" + uuid.NewString()[:8] }

func webhookBody(name, url string) map[string]any {
	return map[string]any{"type": "webhook", "name": name, "enabled": true, "filter_mode": "security", "url": url}
}

// deleteDestinationOnCleanup deletes a notification destination when the test ends. The deletion needs a step-up:
// renew steps p up again when the window has run out meanwhile.
func deleteDestinationOnCleanup(t *testing.T, p *env.Portal, renew func(t *testing.T), path string) {
	t.Helper()
	t.Cleanup(func() {
		res := call(t, p, http.MethodDelete, path, nil)
		if res.Status == http.StatusForbidden && res.ProblemCode() == "step_up_required" {
			renew(t)
			res = call(t, p, http.MethodDelete, path, nil)
		}
		if res.Status != http.StatusNoContent && res.Status != http.StatusNotFound {
			t.Errorf("cleanup: DELETE %s: HTTP %d %s", path, res.Status, res.Body)
		}
	})
}

// deleteLookupOnCleanup removes a pseudonym lookup when the test ends. Without a notifier on the stack it stays
// unresolved, and an unresolved lookup refuses the organization's next one for 10 minutes (409 invalid_state).
func deleteLookupOnCleanup(t *testing.T, lookupID string) {
	t.Helper()
	t.Cleanup(func() {
		dsn, err := stack.PaddockOwnerDSN()
		if err != nil {
			t.Error(err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close(context.Background()) }()
		if _, err := conn.Exec(ctx, "DELETE FROM notification_pseudonym_lookup WHERE id = $1", lookupID); err != nil {
			t.Errorf("cleanup: delete pseudonym lookup %s: %v", lookupID, err)
		}
	})
}

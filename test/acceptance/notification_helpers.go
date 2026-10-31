package acceptance

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
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

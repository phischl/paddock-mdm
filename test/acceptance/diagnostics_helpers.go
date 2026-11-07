package acceptance

import (
	"net/http"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// requestDiagnostics asks for a diagnostics bundle of the device as p.
func requestDiagnostics(t *testing.T, p *env.Portal, deviceID, reason string) env.Response {
	t.Helper()
	return call(t, p, http.MethodPost, "/api/v1/devices/"+deviceID+"/diagnostics", map[string]string{"reason": reason})
}

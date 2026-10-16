package acceptance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestBodyLimits is gate S15 of plan M8s (decision 32): an admin API body above 256 KiB is refused with 400
// invalid_request and recorded once as a failure; an agent release artifact of 1 MiB is not cut by that limit.
func TestBodyLimits(t *testing.T) {
	alice, root := login(t, env.Alice), login(t, env.PlatformAdmin)

	body, err := json.Marshal(map[string]string{"name": uniqueName("body-limit"), "description": strings.Repeat("a", 300<<10)})
	if err != nil {
		t.Fatal(err)
	}
	res := call(t, alice, http.MethodPost, "/api/v1/device-groups", body)
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	expectOneEvent(t, alice, res.RequestID, "device_group.created", "failure")

	v := gateRelease(t, root, false, false)
	bin := append([]byte("gate binary "+v), bytes.Repeat([]byte{0}, 1<<20)...)
	expectStatus(t, uploadArtifact(t, root, v, bin, signBinary(t, bin, v)), http.StatusOK, "")
}

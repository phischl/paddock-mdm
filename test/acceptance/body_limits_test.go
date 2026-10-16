package acceptance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestBodyLimits is gate S15 of plan M8s (decisions 31 and 32): an admin API body above 256 KiB is refused with 400
// invalid_request and recorded once as a failure, a body of exactly 256 KiB is created; an agent release artifact of
// 1 MiB is not cut by that limit; the edge refuses an admin body above 2 MiB with 413.
func TestBodyLimits(t *testing.T) {
	alice, root := login(t, env.Alice), login(t, env.PlatformAdmin)

	res := call(t, alice, http.MethodPost, "/api/v1/device-groups", paddedGroup(t, 300<<10))
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	expectOneEvent(t, alice, res.RequestID, "device_group.created", "failure")
	res = call(t, alice, http.MethodPost, "/api/v1/device-groups", paddedGroup(t, 256<<10))
	expectStatus(t, res, http.StatusCreated, "")
	expectOneEvent(t, alice, res.RequestID, "device_group.created", "success")
	createdID(t, alice, "/api/v1/device-groups", res)

	v := gateRelease(t, root, false, false)
	bin := append([]byte("gate binary "+v), bytes.Repeat([]byte{0}, 1<<20)...)
	expectStatus(t, uploadArtifact(t, root, v, bin, signBinary(t, bin, v)), http.StatusOK, "")

	if code := edgeSend(t, http.MethodPost, stack.AdminURL()+"/api/v1/device-groups", 3<<20); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("3 MiB to the admin API: HTTP %d, want 413 from the edge", code)
	}
}

// paddedGroup is a valid device group document preceded by whitespace to exactly size bytes, so that only the body
// limit can refuse it and the decoder reads the whole body.
func paddedGroup(t *testing.T, size int) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]string{"name": uniqueName("body-limit")})
	if err != nil {
		t.Fatal(err)
	}
	return append(bytes.Repeat([]byte(" "), size-len(doc)), doc...)
}

package system

import (
	"slices"
	"testing"
)

// TestTokenDevices: of the devices with the throwaway VM's hostname only the active ones that enrolled with the run's
// token count, never an earlier run's device or one without a token.
func TestTokenDevices(t *testing.T) {
	page := []byte(`{"items": [
		{"id": "earlier-run", "state": "active", "enrollment_token_id": "token-earlier"},
		{"id": "no-token", "state": "active", "enrollment_token_id": null},
		{"id": "retired", "state": "retired", "enrollment_token_id": "token-run"},
		{"id": "this-run", "state": "active", "enrollment_token_id": "token-run"}
	], "page": 1, "page_size": 100, "total": 4, "total_capped": false, "sort": "hostname"}`)
	ids, err := tokenDevices(page, "token-run")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, []string{"this-run"}) {
		t.Fatalf("devices %v, want [this-run]", ids)
	}
	if ids, err := tokenDevices(page, "token-unknown"); err != nil || ids != nil {
		t.Fatalf("an unknown token matches %v (%v)", ids, err)
	}
	if _, err := tokenDevices([]byte("not json"), "token-run"); err == nil {
		t.Fatal("no error for a page that is not JSON")
	}
}

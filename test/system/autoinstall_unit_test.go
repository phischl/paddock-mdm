package system

import (
	"slices"
	"testing"
)

// TestTokenDevices: of the devices with the throwaway VM's hostname only those in the asked state that enrolled with
// the run's token count, never an earlier run's device or one without a token.
func TestTokenDevices(t *testing.T) {
	page := []byte(`{"items": [
		{"id": "earlier-run", "state": "active", "enrollment_token_id": "token-earlier"},
		{"id": "no-token", "state": "active", "enrollment_token_id": null},
		{"id": "retired", "state": "retired", "enrollment_token_id": "token-run"},
		{"id": "quarantined", "state": "quarantined", "enrollment_token_id": "token-run"},
		{"id": "pending", "state": "pending", "enrollment_token_id": "token-run"},
		{"id": "this-run", "state": "active", "enrollment_token_id": "token-run"}
	], "page": 1, "page_size": 100, "total": 6, "total_capped": false, "sort": "hostname"}`)
	for state, want := range map[string][]string{"active": {"this-run"}, "quarantined": {"quarantined"}, "pending": {"pending"}} {
		if ids, err := tokenDevices(page, "token-run", state); err != nil || !slices.Equal(ids, want) {
			t.Errorf("%s devices %v (%v), want %v", state, ids, err, want)
		}
	}
	if ids, err := tokenDevices(page, "token-unknown", "active"); err != nil || ids != nil {
		t.Fatalf("an unknown token matches %v (%v)", ids, err)
	}
	if _, err := tokenDevices([]byte("not json"), "token-run", "active"); err == nil {
		t.Fatal("no error for a page that is not JSON")
	}
}

// TestEndVerbs: the cleanup takes the run's device out of use in every state but rejected and retired, each with the
// action the product allows in that state.
func TestEndVerbs(t *testing.T) {
	got := map[string]string{}
	for _, e := range endVerbs() {
		got[e.state] = e.verb
	}
	want := map[string]string{"pending": "reject", "active": "retire", "quarantined": "retire"}
	if len(got) != len(want) {
		t.Fatalf("end verbs %v, want %v", got, want)
	}
	for state, verb := range want {
		if got[state] != verb {
			t.Errorf("%s: %q, want %q", state, got[state], verb)
		}
	}
}

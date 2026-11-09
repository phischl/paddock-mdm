package software

import (
	"errors"
	"strings"
	"testing"
)

// TestValidateDecisionReason (plan M13c decision 9): a denial needs a reason, an approval may go without one; a reason
// is at most 500 characters without control or invisible characters, line breaks allowed.
func TestValidateDecisionReason(t *testing.T) {
	cases := []struct {
		reason   string
		required bool
		ok       bool
	}{
		{"", false, true},
		{"", true, false},
		{"no licence left", true, true},
		{"line one\nline two", true, true},
		{strings.Repeat("ä", MaxReasonLength), true, true},
		{strings.Repeat("a", MaxReasonLength+1), true, false},
		{"bell\a", false, false},
		{"rtl\u202e", true, false},
		{"\xff", true, false},
	}
	for _, c := range cases {
		err := ValidateDecisionReason(c.reason, c.required)
		if (err == nil) != c.ok || err != nil && !errors.Is(err, ErrRequest) {
			t.Errorf("%q required %v: %v", c.reason, c.required, err)
		}
	}
	if got := NormalizeDecisionReason("  ok \n"); got != "ok" {
		t.Errorf("normalized %q", got)
	}
}

// TestValidRequestUsername: a request names a user the way an audience does: lower case, no white space or control
// characters, 1 to 256 characters.
func TestValidRequestUsername(t *testing.T) {
	for u, ok := range map[string]bool{
		"alice@acme.test": true, "": false, "Alice@acme.test": false, "a b": false, "tab\there": false, "nul\x00": false,
		strings.Repeat("a", MaxRequestUsername): true, strings.Repeat("a", MaxRequestUsername+1): false, "\xff": false,
	} {
		if ValidRequestUsername(u) != ok {
			t.Errorf("%q: want %v", u, ok)
		}
	}
	if !ValidApproval(ApprovalNone) || !ValidApproval(ApprovalRequired) || ValidApproval("") || ValidApproval("Required") {
		t.Error("ValidApproval")
	}
}

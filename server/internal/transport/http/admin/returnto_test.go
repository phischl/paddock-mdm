package admin

import "testing"

func TestValidReturnTo(t *testing.T) {
	valid := []string{"/", "/device-groups", "/audit?code=admin.login", "/platform/organizations#x"}
	invalid := []string{"", "//evil", "//evil.example/x", "https://evil.example", "http:/x", "/\\evil", "\\evil",
		"evil", "/x\r\nLocation: y", "javascript:alert(1)", "///evil"}
	for _, s := range valid {
		if !ValidReturnTo(s) {
			t.Errorf("ValidReturnTo(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if ValidReturnTo(s) {
			t.Errorf("ValidReturnTo(%q) = true, want false", s)
		}
	}
}

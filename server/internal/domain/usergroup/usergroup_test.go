package usergroup

import "testing"

func TestValidateSlug(t *testing.T) {
	for _, ok := range []string{"ab", "engineering", "linux-admins-2"} {
		if ValidateSlug(ok) != nil {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"", "a", "-ab", "ab-", "Ab", "a.b", "a:b", "a b", string(make([]byte, 43))} {
		if ValidateSlug(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

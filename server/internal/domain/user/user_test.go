package user

import (
	"errors"
	"testing"
)

func TestValidateLocalUsername(t *testing.T) {
	domains := []string{"acme.test", "acme.example.org"}
	for _, ok := range []string{"dave@acme.test", "d.ave+x_1-2@acme.example.org"} {
		if err := ValidateLocalUsername(ok, domains); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"dave", "dave@globex.test", "@acme.test", ".dave@acme.test", "dave.@acme.test", "da..ve@acme.test",
		"Dave@acme.test", "da ve@acme.test", "da:ve@acme.test", "dave@acme.test@acme.test", "dävé@acme.test",
		"-x@acme.test", "-@acme.test",
	} {
		if err := ValidateLocalUsername(bad, domains); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if err := ValidateLocalUsername("dave@acme.test", nil); !errors.Is(err, ErrNoDomains) {
		t.Errorf("without domains: %v", err)
	}
	if NormalizeUsername("  Dave@ACME.test ") != "dave@acme.test" {
		t.Error("NormalizeUsername")
	}
}

func TestValidateEmailAndName(t *testing.T) {
	if ValidateEmail("") != nil || ValidateEmail("dave@acme.test") != nil {
		t.Error("valid email refused")
	}
	for _, bad := range []string{"dave", "Dave <dave@acme.test>", "dave@acme.test\n"} {
		if ValidateEmail(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if ValidateDisplayName("") == nil || ValidateDisplayName("Dave") != nil {
		t.Error("ValidateDisplayName")
	}
}

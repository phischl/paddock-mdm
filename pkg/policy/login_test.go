package policy

import (
	"errors"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

func validLoginSpec() bundle.LoginSpec {
	return bundle.LoginSpec{
		Provider: bundle.ProviderHimmelblau,
		Himmelblau: bundle.HimmelblauSpec{
			OIDCIssuerURL: "https://auth.example.org/application/o/paddock-device-acme/",
			AppID:         "paddock-device-acme", Domain: "acme.example.org",
			PamAllowGroups: []string{"paddock.acme", "paddock.acme.g.dev-team", "paddock.acme.s.entra-staff",
				"paddock.acme.d.0f8fad5b-d9cb-469f-a165-70867728950e"},
		},
		LockedUsers:        []string{"alice@acme.example.org", "Bob.Smith+x@acme.example.org"},
		BreakGlassAccounts: []string{"paddock-admin", "rescue"},
		LocalAdmin:         &bundle.LocalAdminSpec{Username: "paddock-admin", RotationDays: 30},
	}
}

func TestValidateLoginSpec(t *testing.T) {
	if err := ValidateLoginSpec(validLoginSpec()); err != nil {
		t.Fatalf("valid spec: %v", err)
	}
	for name, mutate := range map[string]func(*bundle.LoginSpec){
		"empty domain":          func(s *bundle.LoginSpec) { s.Himmelblau.Domain = "" },
		"uppercase domain":      func(s *bundle.LoginSpec) { s.Himmelblau.Domain = "ACME.example.org" },
		"single-label domain":   func(s *bundle.LoginSpec) { s.Himmelblau.Domain = "acme" },
		"domain with newline":   func(s *bundle.LoginSpec) { s.Himmelblau.Domain = "acme.org\nfoo = bar" },
		"domain over 253":       func(s *bundle.LoginSpec) { s.Himmelblau.Domain = longDomain() + "x" },
		"foreign app":           func(s *bundle.LoginSpec) { s.Himmelblau.AppID = "other-app" },
		"app with bad slug":     func(s *bundle.LoginSpec) { s.Himmelblau.AppID = "paddock-device-a" },
		"issuer of another app": func(s *bundle.LoginSpec) { s.Himmelblau.OIDCIssuerURL = "https://auth.example.org/application/o/x/" },
		"issuer without scheme": func(s *bundle.LoginSpec) {
			s.Himmelblau.OIDCIssuerURL = "auth.example.org/application/o/paddock-device-acme/"
		},
		"issuer file scheme": func(s *bundle.LoginSpec) { s.Himmelblau.OIDCIssuerURL = "file:///application/o/paddock-device-acme/" },
		"issuer with user": func(s *bundle.LoginSpec) {
			s.Himmelblau.OIDCIssuerURL = "https://u:p@auth.example.org/application/o/paddock-device-acme/"
		},
		"issuer with query": func(s *bundle.LoginSpec) {
			s.Himmelblau.OIDCIssuerURL = "https://auth.example.org/application/o/paddock-device-acme/?a=b"
		},
		"issuer with space": func(s *bundle.LoginSpec) {
			s.Himmelblau.OIDCIssuerURL = "https://auth.example.org/application/o/paddock-device-acme/ x"
		},
		"group of another org":   func(s *bundle.LoginSpec) { s.Himmelblau.PamAllowGroups = []string{"paddock.other"} },
		"group outside paddock":  func(s *bundle.LoginSpec) { s.Himmelblau.PamAllowGroups = []string{"domain users"} },
		"group with bad kind":    func(s *bundle.LoginSpec) { s.Himmelblau.PamAllowGroups = []string{"paddock.acme.x.dev"} },
		"group with bad device":  func(s *bundle.LoginSpec) { s.Himmelblau.PamAllowGroups = []string{"paddock.acme.d.not-a-uuid"} },
		"group with comma":       func(s *bundle.LoginSpec) { s.Himmelblau.PamAllowGroups = []string{"paddock.acme,paddock.other"} },
		"empty locked user":      func(s *bundle.LoginSpec) { s.LockedUsers = []string{""} },
		"locked user with space": func(s *bundle.LoginSpec) { s.LockedUsers = []string{"a b@acme.example.org"} },
		"locked user with #":     func(s *bundle.LoginSpec) { s.LockedUsers = []string{"a#b"} },
		"locked user with ctl":   func(s *bundle.LoginSpec) { s.LockedUsers = []string{"a\x7f"} },
		"bad break-glass":        func(s *bundle.LoginSpec) { s.BreakGlassAccounts = []string{"-root"} },
		"bad local admin":        func(s *bundle.LoginSpec) { s.LocalAdmin.Username = "Admin" },
	} {
		s := validLoginSpec()
		mutate(&s)
		if err := ValidateLoginSpec(s); !errors.Is(err, ErrInvalidLoginSpec) {
			t.Errorf("%s: %v, want ErrInvalidLoginSpec", name, err)
		}
	}
	s := validLoginSpec()
	s.Himmelblau.Domain = longDomain()
	if err := ValidateLoginSpec(s); err != nil || len(s.Himmelblau.Domain) != MaxDomainLength {
		t.Fatalf("domain of %d characters: %v", len(s.Himmelblau.Domain), err)
	}
	s = validLoginSpec()
	s.Himmelblau.PamAllowGroups, s.LockedUsers, s.LocalAdmin = []string{}, nil, nil
	s.Himmelblau.OIDCIssuerURL = "http://authentik:9000/sub/application/o/paddock-device-acme/"
	if err := ValidateLoginSpec(s); err != nil {
		t.Fatalf("suspended spec behind a path prefix: %v", err)
	}
}

// longDomain is a valid domain of exactly MaxDomainLength characters.
func longDomain() string {
	d := ""
	for len(d)+10 <= MaxDomainLength-4 {
		d += "abcdefghi."
	}
	for len(d) < MaxDomainLength-4 {
		d += "a"
	}
	return d + ".org"
}

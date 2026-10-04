package organization

import (
	"testing"

	"github.com/google/uuid"
)

func TestGroupNames(t *testing.T) {
	cases := []struct{ got, want string }{
		{RootGroup("acme"), "paddock.acme"},
		{RoleGroup("acme", GroupAdmins), "paddock.acme.admins"},
		{RoleGroup("acme", GroupOperators), "paddock.acme.operators"},
		{RoleGroup("acme", GroupAuditors), "paddock.acme.auditors"},
		{PlatformAdminsGroup(), "paddock.platform.admins"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("group name = %q, want %q", c.got, c.want)
		}
	}
}

func TestParseRoleGroup(t *testing.T) {
	cases := []struct {
		name     string
		wantSlug string
		wantRole GroupRole
		wantOK   bool
	}{
		{"paddock.acme.admins", "acme", GroupAdmins, true},
		{"paddock.my-org-1.operators", "my-org-1", GroupOperators, true},
		{"paddock.acme.auditors", "acme", GroupAuditors, true},
		{"paddock.acme", "", "", false},
		{"paddock.platform.admins", "", "", false},
		{"paddock.platform.auditors", "", "", false},
		{"paddock.ab.admins", "", "", false},
		{"paddock.-acme.admins", "", "", false},
		{"paddock.acme-.admins", "", "", false},
		{"paddock.Acme.admins", "", "", false},
		{"paddock.acme.owners", "", "", false},
		{"paddock.acme.admins.x", "", "", false},
		{"paddock.a.b.admins", "", "", false},
		{"xpaddock.acme.admins", "", "", false},
		{"paddock:acme:admins", "", "", false},
		{"paddockXacmeXadmins", "", "", false},
	}
	for _, c := range cases {
		slug, role, ok := ParseRoleGroup(c.name)
		if slug != c.wantSlug || role != c.wantRole || ok != c.wantOK {
			t.Errorf("ParseRoleGroup(%q) = %q, %q, %v; want %q, %q, %v", c.name, slug, role, ok, c.wantSlug, c.wantRole, c.wantOK)
		}
	}
}

func TestIdentityGroupNames(t *testing.T) {
	dev := uuid.MustParse("0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11")
	cases := []struct{ got, want string }{
		{LockedGroup("acme"), "paddock.acme.locked"},
		{LocalUserGroup("acme", "engineering"), "paddock.acme.g.engineering"},
		{SyncedUserGroup("acme", "sales"), "paddock.acme.s.sales"},
		{DeviceLoginGroup("acme", dev), "paddock.acme.d.0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11"},
		{DeviceLoginApp("acme"), "paddock-device-acme"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("name = %q, want %q", c.got, c.want)
		}
	}
	if !IsPaddockGroup("paddock.acme.g.x") || IsPaddockGroup("Engineering: Linux") {
		t.Error("IsPaddockGroup")
	}
}

func TestValidateDomains(t *testing.T) {
	for _, ok := range [][]string{nil, {"acme.test"}, {"acme.test", "mail.acme-corp.example.org"}} {
		if err := ValidateDomains(ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][]string{
		{"Acme.test"}, {"acme"}, {"acme.test", "acme.test"}, {"-acme.test"}, {"acme..test"}, {"acme.test."},
		{"a b.test"}, {"*.acme.test"}, {"acme.1"}, make([]string, MaxDomains+1),
	} {
		if err := ValidateDomains(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if PrimaryDomain(nil) != "" || PrimaryDomain([]string{"b.test", "a.test"}) != "b.test" {
		t.Error("PrimaryDomain")
	}
}

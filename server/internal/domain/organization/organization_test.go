package organization

import "testing"

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

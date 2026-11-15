package organization

import (
	"slices"
	"strings"
	"testing"
	"time"

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

func TestValidateGraceDays(t *testing.T) {
	cases := []struct {
		days        int
		development bool
		ok          bool
	}{
		{6, false, false}, {7, false, true}, {30, false, true}, {90, false, true}, {91, false, false}, {0, false, false},
		{-1, true, false}, {0, true, true}, {6, true, true}, {90, true, true}, {91, true, false},
	}
	for _, c := range cases {
		if err := ValidateGraceDays(c.days, c.development); (err == nil) != c.ok {
			t.Errorf("ValidateGraceDays(%d, %v) = %v, want ok %v", c.days, c.development, err, c.ok)
		}
	}
}

func TestValidateDeletionReason(t *testing.T) {
	for reason, ok := range map[string]bool{
		"x": false, "ok": true, strings.Repeat("ä", 500): true, strings.Repeat("a", 501): false, "": false,
	} {
		if err := ValidateDeletionReason(reason); (err == nil) != ok {
			t.Errorf("ValidateDeletionReason(%d characters) = %v, want ok %v", len([]rune(reason)), err, ok)
		}
	}
}

func TestDeletionStates(t *testing.T) {
	at := time.Now()
	for _, c := range []struct {
		status    string
		after     *time.Time
		deletable bool
		pending   bool
	}{
		{StatusActive, nil, true, false},
		{StatusActive, &at, true, true},
		{StatusProvisioningFailed, &at, true, true},
		{StatusProvisioning, nil, false, false},
		{StatusSuspended, nil, false, false},
		{StatusDeleting, &at, false, false},
		{StatusDeleted, &at, false, false},
	} {
		if got := Deletable(c.status); got != c.deletable {
			t.Errorf("Deletable(%s) = %v", c.status, got)
		}
		if got := DeletionPending(c.status, c.after); got != c.pending {
			t.Errorf("DeletionPending(%s, %v) = %v", c.status, c.after, got)
		}
	}
	if got := ListedByDefault(); slices.Contains(got, StatusDeleted) || !slices.Contains(got, StatusDeleting) || len(got) != 5 {
		t.Errorf("ListedByDefault() = %v", got)
	}
}

// IsAdministratorGroup is the predicate of the sign-in policy paddock-admin-login-webauthn-administrator (ADR 0053):
// three dot-separated parts, paddock first, a role suffix last, whatever the middle part names.
func TestIsAdministratorGroup(t *testing.T) {
	for name, want := range map[string]bool{
		"paddock.platform.admins":   true,
		"paddock.acme.admins":       true,
		"paddock.acme.operators":    true,
		"paddock.acme.auditors":     true,
		"paddock.platform.auditors": true,
		"paddock.gone-org.admins":   true,
		"paddock.acme":              false,
		"paddock.acme.locked":       false,
		"paddock.acme.g.admins":     false,
		"other.acme.admins":         false,
		"Paddock.acme.admins":       false,
		"paddock.acme.admins.x":     false,
	} {
		if got := IsAdministratorGroup(name); got != want {
			t.Errorf("IsAdministratorGroup(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestOffboarding(t *testing.T) {
	for status, want := range map[string]bool{
		StatusProvisioning: false, StatusActive: false, StatusProvisioningFailed: false, StatusSuspended: false,
		StatusDeleting: true, StatusDeleted: true,
	} {
		if got := Offboarding(status); got != want {
			t.Errorf("Offboarding(%q) = %v, want %v", status, got, want)
		}
	}
}

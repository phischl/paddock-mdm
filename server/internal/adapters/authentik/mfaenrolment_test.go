package authentik_test

import (
	"context"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// SetUserAttribute changes one attribute and keeps the others: Authentik replaces the whole attributes object on a
// PATCH (ADR 0053 decision 4). A nil value removes the attribute; removing a missing one writes nothing.
func TestSetUserAttributeKeepsTheOtherAttributes(t *testing.T) {
	f, srv := newFake(t)
	f.users[7] = &fakeUser{pk: 7, username: "alice", attributes: map[string]any{"paddock_managed": true, "paddock_org": "acme"}}
	c := client(srv)
	ctx := context.Background()
	if err := c.SetUserAttribute(ctx, "7", ports.AttrMFAEnrolAtLogin, true); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"paddock_managed": true, "paddock_org": "acme", ports.AttrMFAEnrolAtLogin: true}
	if got := f.users[7].attributes; !reflect.DeepEqual(got, want) {
		t.Fatalf("attributes after set: %v, want %v", got, want)
	}
	if err := c.SetUserAttribute(ctx, "7", ports.AttrMFAEnrolAtLogin, nil); err != nil {
		t.Fatal(err)
	}
	want = map[string]any{"paddock_managed": true, "paddock_org": "acme"}
	if got := f.users[7].attributes; !reflect.DeepEqual(got, want) {
		t.Fatalf("attributes after removal: %v, want %v", got, want)
	}
	patches := f.count("PATCH")
	if err := c.SetUserAttribute(ctx, "7", ports.AttrMFAEnrolAtLogin, nil); err != nil {
		t.Fatal(err)
	}
	if f.count("PATCH") != patches {
		t.Error("removing a missing attribute patched the user")
	}
	if err := c.SetUserAttribute(ctx, "8", ports.AttrMFAEnrolAtLogin, true); err == nil {
		t.Error("setting an attribute of a missing user succeeded")
	}
}

// UserAuthenticators reads each requested user's devices from Authentik's device listing filtered by user, one
// request per user and none for other users; WebAuthn and TOTP are told apart by the device's model label; a user
// Authentik no longer knows is absent, and a user without devices is present with both false.
func TestUserAuthenticators(t *testing.T) {
	f, srv := newFake(t)
	for _, pk := range []int{1, 2, 3, 4, 9} {
		f.users[pk] = &fakeUser{pk: pk, username: "u" + strconv.Itoa(pk)}
	}
	f.devices = map[string][]int{
		"authentik_stages_authenticator_webauthn.WebAuthnDevice": {1, 1, 3, 9},
		"authentik_stages_authenticator_totp.TOTPDevice":         {2, 3, 9},
		"authentik_stages_authenticator_static.StaticDevice":     {4},
	}
	got, err := client(srv).UserAuthenticators(context.Background(), []string{"1", "2", "3", "4", "5"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]ports.Authenticators{
		"1": {WebAuthn: true}, "2": {TOTP: true}, "3": {WebAuthn: true, TOTP: true}, "4": {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("authenticators %v, want %v (user 5 does not exist)", got, want)
	}
	if n := f.count("GET /api/v3/authenticators/admin/all/"); n != 5 {
		t.Errorf("%d device requests, want one per requested user", n)
	}
	if n := f.count("GET /api/v3/authenticators/admin/webauthn/") + f.count("GET /api/v3/authenticators/admin/totp/"); n != 0 {
		t.Errorf("%d listings of every device", n)
	}
	if _, err := client(srv).UserAuthenticators(context.Background(), []string{"x"}); err == nil {
		t.Error("a non-integer pk was accepted")
	}
	none, err := client(srv).UserAuthenticators(context.Background(), nil)
	if err != nil || len(none) != 0 {
		t.Errorf("no users: %v, %v", none, err)
	}
	f.failNext, f.failStatus = 10, http.StatusServiceUnavailable
	if _, err := client(srv).UserAuthenticators(context.Background(), []string{"1"}); err == nil {
		t.Error("a failing device read was not reported")
	}
}

// PortalRoleGroupNames lists every group the sign-in policy treats as a portal role group, whether or not an
// organization of its slug exists, and no other group.
func TestPortalRoleGroupNames(t *testing.T) {
	f, srv := newFake(t)
	for i, name := range []string{"paddock.platform.admins", "paddock.acme.admins", "paddock.acme.operators", "paddock.acme",
		"paddock.acme.locked", "paddock.acme.g.admins", "paddock.gone.auditors", "staff", "other.acme.admins"} {
		g := &fakeGroup{pk: "g" + strconv.Itoa(i), name: name, parents: []string{}}
		f.groups[g.pk] = g
	}
	got, err := client(srv).PortalRoleGroupNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"paddock.acme.admins", "paddock.acme.operators", "paddock.gone.auditors", "paddock.platform.admins"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("groups %v, want %v", got, want)
	}
}

// A listed user's attribute paddock_mfa_enrol_at_login becomes IdentityUser.MFAEnrolAtLogin.
func TestRoleGroupsMembersCarryTheEnrolmentMark(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	if _, err := c.EnsureOrganization(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	admins := organization.RoleGroup("acme", organization.GroupAdmins)
	g := f.groupByName(admins).pk
	f.users[1] = &fakeUser{pk: 1, username: "marked", groups: []string{g}, attributes: map[string]any{ports.AttrMFAEnrolAtLogin: true}}
	// The fixture's date_joined becomes IdentityUser.Joined.
	f.users[2] = &fakeUser{pk: 2, username: "plain", groups: []string{g}, attributes: map[string]any{}}
	members, err := c.RoleGroupsMembers(ctx, []string{admins})
	if err != nil {
		t.Fatal(err)
	}
	marks := map[string]bool{}
	for _, u := range members[admins] {
		marks[u.Username] = u.MFAEnrolAtLogin
		if u.Joined.IsZero() {
			t.Errorf("%s without date_joined", u.Username)
		}
	}
	if !reflect.DeepEqual(marks, map[string]bool{"marked": true, "plain": false}) {
		t.Fatalf("marks %v", marks)
	}
}

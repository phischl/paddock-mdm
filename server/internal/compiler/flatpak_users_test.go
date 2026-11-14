package compiler_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/compiler"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
)

// userFlatpakEntry inserts a catalog entry of the Flatpak source src with application ref in the user scope.
func (w *world) userFlatpakEntry(name string, src uuid.UUID, ref string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages) VALUES ($1, $2, $3, $4,
		jsonb_build_array(jsonb_build_object('distribution', 'ubuntu', 'release', '*', 'architecture', '*', 'flatpak_ref', $5::text,
		'scope', 'user')))`, id, w.org, name, src, ref)
	return id
}

// usersString renders the users of a package for comparison: the user names joined by ",", or "-" for none.
func usersString(u *[]string) string {
	if u == nil {
		return "-"
	}
	return strings.Join(*u, ",")
}

// TestSoftwareFlatpakUsers (architect decision A10-11): on a device shared by alice and bob, a user-scope Flatpak
// application required for alice carries alice only; one forbidden for a user group carries the group's owners; an
// organization-wide or device-group assignment carries no users and so applies in system scope; a system-scope
// application assigned to a user carries none either; an available one keeps its audience and no users. A device
// that only bob owns does not get alice's application. A recompile without a change publishes nothing new.
func TestSoftwareFlatpakUsers(t *testing.T) {
	w := newWorld(t)
	flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	alice, bob, carol := w.user("alice", false), w.user("bob", false), w.user("carol", false)
	gimp := w.userFlatpakEntry("GIMP", flathub, "org.gimp.GIMP")
	w.assignTo(gimp, "user_id", alice, "required")
	steam := w.userFlatpakEntry("Steam", flathub, "com.valvesoftware.Steam")
	gamers := w.userGroup("gamers", bob, carol)
	w.assignTo(steam, "user_group_id", gamers, "forbid")
	w.assign(w.userFlatpakEntry("Inkscape", flathub, "org.inkscape.Inkscape"), nil, "required", "latest", nil)
	w.assign(w.userFlatpakEntry("Krita", flathub, "org.kde.krita"), w.g1, "uninstall", "latest", nil)
	w.assignTo(w.flatpakEntry("Blender", flathub, "org.blender.Blender"), "user_id", alice, "required")
	w.assignTo(w.userFlatpakEntry("Darktable", flathub, "org.darktable.Darktable"), "user_id", alice, "available")
	shared, bobs := w.v2Device("{1,2}", w.g1), w.v2Device("{1,2}", w.g1)
	w.ubuntu(shared, "amd64")
	w.ubuntu(bobs, "amd64")
	w.own(shared, alice, bob)
	w.own(bobs, bob)
	w.mustCompile(statechange.ScopeOrg, w.org)

	s := w.fetch(shared).Software
	for ref, want := range map[string]string{
		"org.gimp.GIMP":           "required user " + w.username(alice),
		"com.valvesoftware.Steam": "forbid user " + w.username(bob),
		"org.inkscape.Inkscape":   "required user -",
		"org.kde.krita":           "uninstall user -",
		"org.blender.Blender":     "required system -",
		"org.darktable.Darktable": "available user -",
	} {
		p := pkgOf(s, ref)
		if p == nil {
			t.Errorf("%s is missing", ref)
			continue
		}
		users := usersString(p.Users)
		if got := p.Intent + " " + p.Scope + " " + users; got != want {
			t.Errorf("%s: %q, want %q", ref, got, want)
		}
	}
	if p := pkgOf(s, "org.darktable.Darktable"); p == nil || audienceString(p.Audience) != w.username(alice) {
		t.Errorf("darktable audience %+v", p)
	}
	if err := bundle.ValidateSoftware(*s); err != nil {
		t.Fatal(err)
	}
	if p := pkgOf(w.fetch(bobs).Software, "org.gimp.GIMP"); p != nil {
		t.Errorf("a device alice does not own gets her application: %+v", p)
	}
	if p := pkgOf(w.fetch(bobs).Software, "com.valvesoftware.Steam"); p == nil || usersString(p.Users) != w.username(bob) {
		t.Errorf("bob's device: steam %+v", p)
	}

	before := w.version(shared)
	w.mustCompile(statechange.ScopeDevice, shared)
	if w.version(shared) != before {
		t.Fatal("a recompile without a change published a new bundle")
	}
	// alice joining the forbidding group widens the list; a whole-device forbid next to it leaves no list (system).
	w.exec("INSERT INTO user_group_member (organization_id, group_id, user_id) VALUES ($1, $2, $3)", w.org, gamers, alice)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if p := pkgOf(w.fetch(shared).Software, "com.valvesoftware.Steam"); p == nil ||
		usersString(p.Users) != w.username(alice)+","+w.username(bob) {
		t.Fatalf("steam after alice joined %+v", p)
	}
	w.assign(steam, nil, "forbid", "latest", nil)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if p := pkgOf(w.fetch(shared).Software, "com.valvesoftware.Steam"); p == nil || p.Users != nil || p.Intent != bundle.SoftwareForbid {
		t.Fatalf("steam with a whole-device forbid %+v", p)
	}
}

// TestSoftwareFlatpakUsersUncarriedName (A10-11, PDK-799 review 1): a user-scope application targeted only at an owner
// whose stored name a bundle cannot carry is left out rather than widened to system scope; the bundle is published.
func TestSoftwareFlatpakUsersUncarriedName(t *testing.T) {
	w := newWorld(t)
	flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	spaced := w.namedUser("flatpak user@c.test")
	w.assignTo(w.userFlatpakEntry("GIMP", flathub, "org.gimp.GIMP"), "user_id", spaced, "required")
	w.assign(w.entry("Tree", nil, [4]string{"ubuntu", "*", "*", "tree"}), nil, "required", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.own(d, spaced)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d) == 0 {
		t.Fatal("no bundle was published")
	}
	if p := pkgOf(w.fetch(d).Software, "org.gimp.GIMP"); p != nil {
		t.Fatalf("an application targeted at nobody the bundle can name is rendered: %+v", p)
	}
}

// TestCompileWarningFlatpakUsersTruncated (A10-11, A10-10): a user-scope application required for 201 owners keeps
// the first 200 by user name, the bundle is published and a flatpak_users_truncated warning is persisted for its
// assignment; with 200 owners the list is complete and the warning is gone.
func TestCompileWarningFlatpakUsersTruncated(t *testing.T) {
	w := newWorld(t)
	flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	users := make([]uuid.UUID, bundle.MaxSoftwareAudience+1)
	for i := range users {
		users[i] = w.user(fmt.Sprintf("u%03d", i), false)
	}
	w.own(d, users...)
	group := w.userGroup("all", users...)
	gimp := w.userFlatpakEntry("GIMP", flathub, "org.gimp.GIMP")
	w.assignTo(gimp, "user_group_id", group, "required")
	assignment := w.assignmentOf(gimp)
	w.mustCompile(statechange.ScopeOrg, w.org)

	p := pkgOf(w.fetch(d).Software, "org.gimp.GIMP")
	if p == nil || p.Users == nil || len(*p.Users) != bundle.MaxSoftwareAudience || (*p.Users)[0] != w.username(users[0]) ||
		slices.Contains(*p.Users, w.username(users[bundle.MaxSoftwareAudience])) {
		t.Fatalf("package %+v", p)
	}
	got := w.warnings(d)
	if len(got) != 1 || got[0].code != compiler.WarningFlatpakUsersTruncated || got[0].assignment.UUID != assignment ||
		got[0].entry.UUID != gimp || got[0].params["users"] != float64(bundle.MaxSoftwareAudience+1) ||
		got[0].params["kept"] != float64(bundle.MaxSoftwareAudience) || got[0].params["flatpak_ref"] != "org.gimp.GIMP" {
		t.Fatalf("warnings %+v", got)
	}

	w.exec("DELETE FROM user_group_member WHERE group_id = $1 AND user_id = $2", group, users[0])
	w.mustCompile(statechange.ScopeOrg, w.org)
	if p := pkgOf(w.fetch(d).Software, "org.gimp.GIMP"); p == nil || p.Users == nil || len(*p.Users) != bundle.MaxSoftwareAudience ||
		(*p.Users)[0] != w.username(users[1]) {
		t.Fatalf("package %+v", p)
	}
	if got := w.warnings(d); len(got) != 0 {
		t.Fatalf("after 200 users: %+v", got)
	}
}

// TestCompileWarningFlatpakUsersTruncatedWinningIntentOnly (A10-10): a forbid for 201 owners wins over a required of the
// same application for one user; only the forbid assignment is warned about, the losing required never put its user
// into the list.
func TestCompileWarningFlatpakUsersTruncatedWinningIntentOnly(t *testing.T) {
	w := newWorld(t)
	flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	users := make([]uuid.UUID, bundle.MaxSoftwareAudience+1)
	for i := range users {
		users[i] = w.user(fmt.Sprintf("u%03d", i), false)
	}
	w.own(d, users...)
	group := w.userGroup("all", users...)
	forbidden := w.userFlatpakEntry("GIMP forbid", flathub, "org.gimp.GIMP")
	w.assignTo(forbidden, "user_group_id", group, "forbid")
	required := w.userFlatpakEntry("GIMP required", flathub, "org.gimp.GIMP")
	w.assignTo(required, "user_id", users[0], "required")
	forbidAssignment := w.assignmentOf(forbidden)
	w.mustCompile(statechange.ScopeOrg, w.org)

	got := w.warnings(d)
	if len(got) != 1 || got[0].code != compiler.WarningFlatpakUsersTruncated || got[0].assignment.UUID != forbidAssignment {
		t.Fatalf("warnings %+v", got)
	}
}

// TestSoftwareFlatpakUsersGated (A10-11 with A10-6): an alpha.9 agent on a shared device gets no Flatpak application,
// so no users field, in a section the frozen alpha.9 rules accept; the first alpha.10 agent gets the users.
func TestSoftwareFlatpakUsersGated(t *testing.T) {
	w := newWorld(t)
	flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	alice, bob := w.user("alice", false), w.user("bob", false)
	w.assignTo(w.userFlatpakEntry("GIMP", flathub, "org.gimp.GIMP"), "user_id", alice, "required")
	w.assignTo(w.userFlatpakEntry("Steam", flathub, "com.valvesoftware.Steam"), "user_id", bob, "forbid")
	w.assign(w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"}), nil, "required", "latest", nil)
	devices := map[string]uuid.UUID{}
	for _, v := range []string{"0.1.0-alpha.9", "0.1.0-alpha.10"} {
		d := w.v2Device("{1,2}", w.g1)
		w.ubuntu(d, "amd64")
		w.agentAt(d, v)
		w.own(d, alice, bob)
		devices[v] = d
	}
	w.mustCompile(statechange.ScopeOrg, w.org)

	raw, err := json.Marshal(w.fetch(devices["0.1.0-alpha.9"]).Software)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"users"`) || strings.Contains(string(raw), "org.gimp.GIMP") {
		t.Errorf("alpha.9 section carries a Flatpak application or users: %s", raw)
	}
	if err := alpha9Accepts(raw); err != nil {
		t.Errorf("the alpha.9 agent refuses the section: %v", err)
	}
	s := w.fetch(devices["0.1.0-alpha.10"]).Software
	if p := pkgOf(s, "org.gimp.GIMP"); p == nil || usersString(p.Users) != w.username(alice) {
		t.Errorf("alpha.10 gimp %+v", p)
	}
	if p := pkgOf(s, "com.valvesoftware.Steam"); p == nil || usersString(p.Users) != w.username(bob) {
		t.Errorf("alpha.10 steam %+v", p)
	}
}

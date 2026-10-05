package compiler_test

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/sudoers"
	"github.com/paddock-mdm/paddock/server/internal/compiler"
	"github.com/paddock-mdm/paddock/server/internal/domain/statechange"
)

// v2Device is an active device whose agent reports schema_versions.
func (w *world) v2Device(versions string, groups ...uuid.UUID) uuid.UUID {
	w.t.Helper()
	d := w.device("active", groups...)
	w.exec("INSERT INTO device_status (device_id, organization_id, schema_versions) VALUES ($1, $2, $3::int[])", d, w.org, versions)
	return d
}

func (w *world) user(name string, locked bool) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO app_user (id, organization_id, authentik_pk, username, source, locked) VALUES ($1, $2, $3, $4, 'local', $5)",
		id, w.org, "pk-"+id.String(), name+"-"+id.String()[24:]+"@c.test", locked)
	return id
}

func (w *world) username(id uuid.UUID) string {
	w.t.Helper()
	var s string
	if err := w.super.QueryRow(context.Background(), "SELECT username FROM app_user WHERE id = $1", id).Scan(&s); err != nil {
		w.t.Fatal(err)
	}
	return s
}

func spec[T any](t *testing.T, b *bundle.Bundle, id string) T {
	t.Helper()
	var out T
	for _, r := range b.Resources {
		if r.ID == id {
			if err := json.Unmarshal(r.Spec, &out); err != nil {
				t.Fatal(err)
			}
			return out
		}
	}
	t.Fatalf("resource %s missing: %s", id, resourceIDs(b))
	return out
}

func TestSchemaNegotiation(t *testing.T) {
	w := newWorld(t)
	w.exec("UPDATE organization SET domains = '{c.test}' WHERE id = $1", w.org)
	v1, v2 := w.v2Device("{1}"), w.v2Device("{1,2}")
	old := w.device("active") // never checked in
	w.mustCompile(statechange.ScopeOrg, w.org)
	for _, d := range []uuid.UUID{v1, old} {
		if b := w.fetch(d); b.SchemaVersion != bundle.SchemaVersion || resourceIDs(b) != "time" {
			t.Fatalf("v1 device got schema %d with %s", b.SchemaVersion, resourceIDs(b))
		}
	}
	b := w.fetch(v2)
	if b.SchemaVersion != bundle.SchemaVersion2 || resourceIDs(b) != "login,sudo,time" {
		t.Fatalf("v2 device got schema %d with %s", b.SchemaVersion, resourceIDs(b))
	}
	login := spec[bundle.LoginSpec](t, b, "login")
	slug := "c" + w.org.String()[24:]
	if login.Provider != "himmelblau" || login.Himmelblau.AppID != "paddock-device-"+slug || login.Himmelblau.Domain != "c.test" ||
		login.Himmelblau.OIDCIssuerURL != "https://auth.test/application/o/paddock-device-"+slug+"/" ||
		!slices.Equal(login.Himmelblau.PamAllowGroups, []string{"paddock." + slug}) || !login.Himmelblau.EnableHello ||
		login.Himmelblau.HelloPinMinLength != 6 || login.Himmelblau.PackageVersion != "4.0.4" || login.Suspended || login.SessionAction != "lock_screen" {
		t.Fatalf("login %+v", login)
	}
	sudo := spec[bundle.SudoSpec](t, b, "sudo")
	if !slices.Equal(sudo.PrivilegedGroups, []string{"sudo", "admin", "wheel"}) || !slices.Equal(sudo.SudoersDAllowlist, []string{"README"}) ||
		sudo.LectureText == "" || len(sudo.Entries) != 0 {
		t.Fatalf("sudo %+v", sudo)
	}
	// An organization without a primary domain gets no login resource.
	w.exec("UPDATE organization SET domains = '{}' WHERE id = $1", w.org)
	w.mustCompile(statechange.ScopeDevice, v2)
	if ids := resourceIDs(w.fetch(v2)); ids != "sudo,time" {
		t.Fatalf("without domain: %s", ids)
	}
}

func TestLockSuspensionAndSudoEntries(t *testing.T) {
	w := newWorld(t)
	w.exec("UPDATE organization SET domains = '{c.test}' WHERE id = $1", w.org)
	dev := w.v2Device("{1,2}", w.g1)
	elsewhere := w.v2Device("{1,2}")
	dave, erin := w.user("dave", false), w.user("erin", false)
	profile := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO permission_profile (id, organization_id, name, class, commands, require_password, timestamp_timeout_min, lecture)
		VALUES ($1, $2, 'nginx', 'restricted', '{"/usr/bin/systemctl restart nginx.service"}', true, 5, 'always')`, profile, w.org)
	w.exec("INSERT INTO profile_assignment (id, organization_id, profile_id, subject_type, subject_id, device_group_id) VALUES ($1, $2, $3, 'user', $4, $5)",
		uuid.Must(uuid.NewV7()), w.org, profile, dave, w.g1)
	// dave may log in on dev directly; erin logged in on elsewhere earlier (cached credentials).
	w.exec("INSERT INTO device_login_assignment (organization_id, device_id, subject_type, subject_id) VALUES ($1, $2, 'user', $3)", w.org, dev, dave)
	w.exec("INSERT INTO device_user_seen (organization_id, device_id, username, last_seen_at) VALUES ($1, $2, $3, now())", w.org, elsewhere, w.username(erin))
	w.mustCompile(statechange.ScopeOrg, w.org)

	b := w.fetch(dev)
	slug := "c" + w.org.String()[24:]
	if got := spec[bundle.LoginSpec](t, b, "login").Himmelblau.PamAllowGroups; !slices.Equal(got, []string{"paddock." + slug + ".d." + dev.String()}) {
		t.Fatalf("allow list with a direct user: %v", got)
	}
	entries := spec[bundle.SudoSpec](t, b, "sudo").Entries
	if len(entries) != 1 || entries[0].Username != w.username(dave) || entries[0].Class != sudoers.ClassRestricted ||
		entries[0].Lecture != "always" || len(entries[0].ProfileDigest) != 64 {
		t.Fatalf("sudo entries %+v", entries)
	}
	if w.validator.checked.Load() == 0 {
		t.Fatal("the sudo entry was not validated")
	}
	// The device-group-scoped assignment does not apply elsewhere (every user may log in there).
	if e := spec[bundle.SudoSpec](t, w.fetch(elsewhere), "sudo").Entries; len(e) != 0 {
		t.Fatalf("entries elsewhere %+v", e)
	}

	// Locking erin (scope user) recompiles exactly the devices where erin is affected: elsewhere (seen there and
	// allowed by the empty assignment), not dev (only dave may log in there).
	devBefore, elseBefore := w.version(dev), w.version(elsewhere)
	w.exec("UPDATE app_user SET locked = true WHERE id = $1", erin)
	w.mustCompile(statechange.ScopeUser, erin)
	if w.version(dev) != devBefore || w.version(elsewhere) != elseBefore+1 {
		t.Fatalf("versions after the lock: dev %d→%d, elsewhere %d→%d", devBefore, w.version(dev), elseBefore, w.version(elsewhere))
	}
	if got := spec[bundle.LoginSpec](t, w.fetch(elsewhere), "login").LockedUsers; !slices.Equal(got, []string{w.username(erin)}) {
		t.Fatalf("locked users %v", got)
	}

	// Suspension: the allow list is present and empty.
	w.exec("UPDATE device SET logins_suspended = true WHERE id = $1", dev)
	w.mustCompile(statechange.ScopeDevice, dev)
	login := spec[bundle.LoginSpec](t, w.fetch(dev), "login")
	if !login.Suspended || login.Himmelblau.PamAllowGroups == nil || len(login.Himmelblau.PamAllowGroups) != 0 {
		t.Fatalf("suspended login %+v", login)
	}
}

func TestRenderFailureBlocksTheBundle(t *testing.T) {
	w := newWorld(t)
	dev := w.v2Device("{1,2}")
	dave := w.user("dave", false)
	profile := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO permission_profile (id, organization_id, name, class) VALUES ($1, $2, 'root', 'full')", profile, w.org)
	w.mustCompile(statechange.ScopeDevice, dev)
	before := w.version(dev)

	w.validator.reject = "NOPASSWD"
	w.exec("UPDATE permission_profile SET require_password = false WHERE id = $1", profile)
	w.exec("INSERT INTO profile_assignment (id, organization_id, profile_id, subject_type, subject_id) VALUES ($1, $2, $3, 'user', $4)",
		uuid.Must(uuid.NewV7()), w.org, profile, dave)
	w.mustCompile(statechange.ScopeDevice, dev)
	if w.version(dev) != before {
		t.Fatal("a bundle with an invalid sudo entry was published")
	}
	var events int
	_ = w.super.QueryRow(context.Background(), `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'device.bundle_render_failed'
		AND outcome = 'failure' AND error_code = 'render_failed' AND target->>'id' = $2 AND params->>'username' = $3`,
		w.org, dev.String(), w.username(dave)).Scan(&events)
	if events != 1 {
		t.Fatalf("%d render failure events, want 1", events)
	}
	w.validator.reject = ""
	w.mustCompile(statechange.ScopeDevice, dev)
	if w.version(dev) != before+1 {
		t.Fatal("bundle not published after the entry became valid")
	}
}

// TestReconcileRecompilesOutdatedSchemas: an agent that starts reporting schema 2 gets a v2 bundle from the reconcile
// loop, without any other change.
func TestReconcileRecompilesOutdatedSchemas(t *testing.T) {
	w := newWorld(t)
	dev := w.v2Device("{1}")
	w.mustCompile(statechange.ScopeDevice, dev)
	if b := w.fetch(dev); b.SchemaVersion != 1 {
		t.Fatalf("schema %d", b.SchemaVersion)
	}
	w.exec("UPDATE device_status SET schema_versions = '{1,2}' WHERE device_id = $1", dev)
	if err := w.comp.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b := w.fetch(dev); b.SchemaVersion != bundle.SchemaVersion2 {
		t.Fatalf("after the reconcile: schema %d", b.SchemaVersion)
	}
}

// TestVisudo checks the real validator with the host's visudo (the compiler image has it, gate P1).
func TestVisudo(t *testing.T) {
	path := "/usr/sbin/visudo"
	if _, err := os.Stat(path); err != nil {
		t.Skip("visudo not installed on this host")
	}
	v := compiler.Visudo{Path: path}
	good, err := sudoers.Render(sudoers.Entry{Username: "dave@c.test", Class: sudoers.ClassFull, Lecture: sudoers.LectureOnce}, sudoers.PlaceholderUID, sudoers.Classic)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(context.Background(), good); err != nil {
		t.Fatalf("valid file refused: %v", err)
	}
	if err := v.Validate(context.Background(), []byte("#4294967294 ALL=(root) /usr/bin/a, b\n")); err == nil {
		t.Fatal("invalid file accepted")
	}
}

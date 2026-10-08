package compiler_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/sudoers"
	"github.com/phischl/paddock-mdm/pkg/timeticket"
	"github.com/phischl/paddock-mdm/server/internal/compiler"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
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
		if b := w.fetch(d); b.SchemaVersion != bundle.SchemaVersion || resourceIDs(b) != "time" || b.Keys != nil || b.Revocation != nil {
			t.Fatalf("v1 device got schema %d with %s, keys %+v, revocation %+v", b.SchemaVersion, resourceIDs(b), b.Keys, b.Revocation)
		}
	}
	b := w.fetch(v2)
	if b.SchemaVersion != bundle.SchemaVersion2 || resourceIDs(b) != "login,sudo,time" {
		t.Fatalf("v2 device got schema %d with %s", b.SchemaVersion, resourceIDs(b))
	}
	// Plan M4a decision 5: v2 bundles carry every version of command-signing.
	if b.Keys == nil || len(b.Keys.CommandSigning) != 1 || b.Keys.CommandSigning[0].KeyID != "command-signing:v1" ||
		len(b.Keys.CommandSigning[0].PublicKey) != 44 || b.Keys.EscrowWrap == nil || b.Keys.EscrowWrap.KeyID != "escrow-wrap:v1" {
		t.Fatalf("keys %+v", b.Keys)
	}
	if _, err := escrow.ParsePublicKey(b.Keys.EscrowWrap.PublicKeyPEM); err != nil {
		t.Fatalf("escrow-wrap key: %v", err)
	}
	// Plan M4c decisions 14 and 15: the time-ticket keys, and the dead man's switch, off with the defaults.
	if len(b.Keys.TimeTicket) != 1 || b.Keys.TimeTicket[0].KeyID != "time-ticket:v1" || b.DMS == nil || b.DMS.Enabled ||
		b.DMS.PeriodDays != 30 || !slices.Equal(b.DMS.WarnDays, []int{3, 1}) {
		t.Fatalf("time-ticket keys %+v, dms %+v", b.Keys.TimeTicket, b.DMS)
	}
	// Plan M4c decisions 1 and 3: the revocation section carries the flag (off by default) and revocation-signing.
	if r := b.Revocation; r == nil || r.Enabled || len(r.Keys) != 1 || r.Keys[0].KeyID != "revocation-signing:v1" || len(r.Keys[0].PublicKey) != 44 {
		t.Fatalf("revocation %+v", b.Revocation)
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
	// Plan M4a decision 14: the managed local administrator, a break-glass account in both resources.
	if login.LocalAdmin == nil || *login.LocalAdmin != (bundle.LocalAdminSpec{Username: "paddock-admin", RotationDays: 30}) ||
		!slices.Equal(login.BreakGlassAccounts, []string{"paddock-admin"}) || !slices.Equal(sudo.BreakGlassAccounts, []string{"paddock-admin"}) ||
		!strings.HasPrefix(login.Notice, "This device is managed by your organization.") {
		t.Fatalf("local admin %+v, break-glass %v / %v", login.LocalAdmin, login.BreakGlassAccounts, sudo.BreakGlassAccounts)
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

// TestInvalidCommandOmitsTheEntry: a profile stored before the command check was tightened (plan M3.1 decision 1)
// does not block the bundle; the entries it contributes to are omitted, recorded once per bundle version.
func TestInvalidCommandOmitsTheEntry(t *testing.T) {
	w := newWorld(t)
	dev := w.v2Device("{1,2}")
	dave, erin := w.user("dave", false), w.user("erin", false)
	legacy, nginx := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO permission_profile (id, organization_id, name, class, commands)
		VALUES ($1, $2, 'legacy', 'restricted', '{"/usr/bin/systemctl ^.*$"}')`, legacy, w.org)
	w.exec(`INSERT INTO permission_profile (id, organization_id, name, class, commands)
		VALUES ($1, $2, 'nginx', 'restricted', '{"/usr/bin/systemctl restart nginx.service"}')`, nginx, w.org)
	for _, a := range []struct{ profile, user uuid.UUID }{{legacy, dave}, {nginx, dave}, {nginx, erin}} {
		w.exec("INSERT INTO profile_assignment (id, organization_id, profile_id, subject_type, subject_id) VALUES ($1, $2, $3, 'user', $4)",
			uuid.Must(uuid.NewV7()), w.org, a.profile, a.user)
	}
	events := func() (n int, reason string) {
		t.Helper()
		err := w.super.QueryRow(context.Background(), `SELECT count(*), coalesce(max(params->>'reason'), '') FROM action
			WHERE organization_id = $1 AND code = 'device.bundle_entry_omitted' AND outcome = 'success'
			AND target->>'id' = $2 AND params->>'username' = $3`, w.org, dev.String(), w.username(dave)).Scan(&n, &reason)
		if err != nil {
			t.Fatal(err)
		}
		return n, reason
	}

	w.mustCompile(statechange.ScopeDevice, dev)
	entries := spec[bundle.SudoSpec](t, w.fetch(dev), "sudo").Entries
	if len(entries) != 1 || entries[0].Username != w.username(erin) {
		t.Fatalf("sudo entries %+v, want only erin's", entries)
	}
	n, reason := events()
	if n != 1 || !strings.Contains(reason, `"/usr/bin/systemctl ^.*$" of profile legacy`) || !strings.Contains(reason, "'^'") {
		t.Fatalf("%d omission events, reason %q", n, reason)
	}
	// An unchanged bundle records nothing again; the next bundle version records the omission once more.
	w.mustCompile(statechange.ScopeDevice, dev)
	if n, _ := events(); n != 1 {
		t.Fatalf("%d omission events after an unchanged compile", n)
	}
	before := w.version(dev)
	w.exec("UPDATE permission_profile SET timestamp_timeout_min = 1 WHERE id = $1", nginx)
	w.mustCompile(statechange.ScopeDevice, dev)
	if n, _ := events(); w.version(dev) != before+1 || n != 2 {
		t.Fatalf("version %d→%d, %d omission events", before, w.version(dev), n)
	}
	// Fixing the profile restores dave's entry.
	w.exec(`UPDATE permission_profile SET commands = '{"/usr/bin/systemctl status nginx.service"}' WHERE id = $1`, legacy)
	w.mustCompile(statechange.ScopeDevice, dev)
	if entries := spec[bundle.SudoSpec](t, w.fetch(dev), "sudo").Entries; len(entries) != 2 {
		t.Fatalf("sudo entries after the fix %+v", entries)
	}
	if n, _ := events(); n != 2 {
		t.Fatalf("%d omission events after the fix", n)
	}
}

// TestOptionLikeUsernameOmitsTheEntry: a synced user whose name starts with '-' (plan M4a step 0a) gets no sudo entry
// and does not block the bundle.
func TestOptionLikeUsernameOmitsTheEntry(t *testing.T) {
	w := newWorld(t)
	dev := w.v2Device("{1,2}")
	dave := w.user("dave", false)
	bad := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO app_user (id, organization_id, authentik_pk, username, source) VALUES ($1, $2, $3, '-x@acme.test', 'synced')",
		bad, w.org, "pk-"+bad.String())
	profile := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO permission_profile (id, organization_id, name, class) VALUES ($1, $2, 'root', 'full')", profile, w.org)
	w.exec("INSERT INTO profile_assignment (id, organization_id, profile_id, subject_type, subject_id) VALUES ($1, $2, $3, 'global', NULL)",
		uuid.Must(uuid.NewV7()), w.org, profile)
	w.mustCompile(statechange.ScopeDevice, dev)
	entries := spec[bundle.SudoSpec](t, w.fetch(dev), "sudo").Entries
	if len(entries) != 1 || entries[0].Username != w.username(dave) {
		t.Fatalf("sudo entries %+v, want only dave's", entries)
	}
	var n int
	_ = w.super.QueryRow(context.Background(), `SELECT count(*) FROM action WHERE organization_id = $1
		AND code = 'device.bundle_entry_omitted' AND params->>'username' = '-x@acme.test'`, w.org).Scan(&n)
	if n != 1 {
		t.Fatalf("%d omission events, want 1", n)
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

// TestReconcileDeliversRotatedKeys (plan M4a decision 5): after command-signing is rotated, the reconcile loop
// recompiles the organization and v2 bundles list both versions; without a change a reconcile keeps the version.
func TestReconcileDeliversRotatedKeys(t *testing.T) {
	w := newWorld(t)
	dev := w.v2Device("{1,2}")
	w.mustCompile(statechange.ScopeDevice, dev)
	ctx := context.Background()
	for range 2 { // the first round after start recompiles content-equal bundles: no new version
		if err := w.comp.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	before := w.version(dev)
	if _, err := w.bao.Root.Logical().Write("transit/keys/command-signing/rotate", nil); err != nil {
		t.Fatal(err)
	}
	if err := w.comp.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	b := w.fetch(dev)
	if b.BundleVersion != before+1 || len(b.Keys.CommandSigning) != 2 || b.Keys.CommandSigning[1].KeyID != "command-signing:v2" {
		t.Fatalf("version %d→%d, keys %+v", before, b.BundleVersion, b.Keys)
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

// TestRevocationFlag: PADDOCK_REVOCATION_ENABLED reaches v2 bundles as revocation.enabled (plan M4c decision 1).
func TestRevocationFlag(t *testing.T) {
	w := newWorldConfig(t, func(c *compiler.Config) { c.RevocationEnabled = true })
	d := w.v2Device("{1,2}")
	w.mustCompile(statechange.ScopeOrg, w.org)
	if r := w.fetch(d).Revocation; r == nil || !r.Enabled || len(r.Keys) != 1 {
		t.Fatalf("revocation %+v", r)
	}
}

// TestDMSSection: the organization's dead man's switch reaches v2 bundles (plan M4c decision 15).
func TestDMSSection(t *testing.T) {
	w := newWorld(t)
	d := w.v2Device("{1,2}")
	w.exec("INSERT INTO organization_dms_settings (organization_id, enabled, period_days, warn_days) VALUES ($1, true, 14, '{5,2}')", w.org)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if dms := w.fetch(d).DMS; dms == nil || !dms.Enabled || dms.PeriodDays != 14 || !slices.Equal(dms.WarnDays, []int{5, 2}) {
		t.Fatalf("dms %+v", dms)
	}
}

// TestTimeTickets (plan M4c decision 14): one ticket per organization, signed with time-ticket, in tt:<org>.
func TestTimeTickets(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if err := w.comp.IssueTimeTickets(ctx); err != nil {
		t.Fatal(err)
	}
	env, err := w.cache.TimeTicket(ctx, w.org)
	if err != nil || env == nil {
		t.Fatalf("tt: %v", err)
	}
	reader, err := bao.NewWithToken(w.bao.Addr, "root")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := reader.PublicKeys(ctx, "time-ticket")
	if err != nil {
		t.Fatal(err)
	}
	tk, err := timeticket.Verify(env, map[string]ed25519.PublicKey{"time-ticket:v1": pub[1]}, w.org.String())
	if err != nil || time.Since(tk.IssuedAt) > time.Minute {
		t.Fatalf("ticket %+v %v", tk, err)
	}
}

// TestInventorySection (plan M5a decisions 3 and 4): v2 bundles carry Fleet's URL, the enroll secret and the fleetd
// package of the newest published release that has one; a new package reaches every device with the next reconcile,
// v1 bundles never get the section.
func TestInventorySection(t *testing.T) {
	w := newWorldConfig(t, func(c *compiler.Config) {
		c.FleetURL, c.FleetEnrollSecret = "https://fleet.test", "enroll-secret"
	})
	release := func(version, fleetd string, sum byte) {
		w.exec("INSERT INTO agent_release (version, status, created_by, published_at) VALUES ($1, 'published', 'test', now())", version)
		w.exec(`INSERT INTO agent_package (version, name, arch, sha256, size, minisig, object_key, package_version)
			VALUES ($1, 'fleet-osquery', 'amd64', $2, 1, 'sig', $3, $4)`,
			version, strings.Repeat(string("0123456789abcdef"[sum]), 64), "packages/"+version+"/fleet-osquery_"+fleetd+"_amd64.deb", fleetd)
	}
	v2, v1 := w.v2Device("{1,2}"), w.v2Device("{1}")
	w.mustCompile(statechange.ScopeOrg, w.org)
	if inv := w.fetch(v2).Inventory; inv != nil {
		t.Fatalf("inventory without a fleetd package: %+v", inv)
	}
	release("90.0.1", "1.48.0", 1)
	ctx := context.Background()
	if err := w.comp.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	inv := w.fetch(v2).Inventory
	if inv == nil || inv.FleetURL != "https://fleet.test" || inv.EnrollSecret != "enroll-secret" ||
		inv.Package != (bundle.InventoryPackage{Version: "1.48.0", URLPath: "packages/90.0.1/fleet-osquery_1.48.0_amd64.deb", SHA256: strings.Repeat("1", 64)}) {
		t.Fatalf("inventory %+v", inv)
	}
	if b := w.fetch(v1); b.Inventory != nil {
		t.Fatalf("v1 bundle with inventory %+v", b.Inventory)
	}
	before := w.version(v2)
	release("90.0.2", "1.49.0", 2)
	if err := w.comp.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if b := w.fetch(v2); b.BundleVersion != before+1 || b.Inventory.Package.Version != "1.49.0" {
		t.Fatalf("after a new fleetd package: version %d→%d, inventory %+v", before, b.BundleVersion, b.Inventory)
	}
}

// TestUpdatesSection (plan M5b decision 4): v2 bundles carry the organization's update schedule and the holds of the
// organization and the device's groups, one per package (the smallest version wins); v1 bundles never get it.
func TestUpdatesSection(t *testing.T) {
	w := newWorld(t)
	g1, g2 := w.g1, w.g2
	in, out, v1 := w.v2Device("{1,2}", g1, g2), w.v2Device("{1,2}"), w.v2Device("{1}", g1)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if u := w.fetch(out).Updates; u == nil || u.SecurityDailyAt != "03:00" || u.RegularSchedule != "Sat 04:00" || !u.RegularUpdatesEnabled ||
		u.MaxRandomDelayMin != 60 || u.Holds == nil || len(u.Holds) != 0 {
		t.Fatalf("defaults %+v", u)
	}
	w.exec(`INSERT INTO organization_update_settings (organization_id, security_daily_at, regular_schedule, regular_updates_enabled,
		max_random_delay_min) VALUES ($1, '02:30', 'Mon,Thu 12:30', false, 0)`, w.org)
	hold := func(group any, pkg string, version any) {
		w.exec("INSERT INTO package_hold (id, organization_id, device_group_id, package, version) VALUES ($1, $2, $3, $4, $5)",
			uuid.Must(uuid.NewV7()), w.org, group, pkg, version)
	}
	hold(nil, "linux-generic", nil)
	hold(g1, "openssl", "3.0.13-0ubuntu3.4")
	hold(g2, "openssl", "3.0.13-0ubuntu3.1")
	w.mustCompile(statechange.ScopeOrg, w.org)
	u := w.fetch(in).Updates
	if u == nil || u.SecurityDailyAt != "02:30" || u.RegularSchedule != "Mon,Thu 12:30" || u.RegularUpdatesEnabled || u.MaxRandomDelayMin != 0 ||
		len(u.Holds) != 2 || u.Holds[0].Package != "linux-generic" || u.Holds[0].Version != nil ||
		u.Holds[1].Package != "openssl" || *u.Holds[1].Version != "3.0.13-0ubuntu3.1" {
		t.Fatalf("updates of the member %+v", u)
	}
	if u := w.fetch(out).Updates; len(u.Holds) != 1 || u.Holds[0].Package != "linux-generic" {
		t.Fatalf("updates of the non-member %+v", u)
	}
	if b := w.fetch(v1); b.Updates != nil {
		t.Fatalf("v1 bundle with updates %+v", b.Updates)
	}
}

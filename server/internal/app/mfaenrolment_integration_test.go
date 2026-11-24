package app_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// mfaIdP is an in-memory MFADirectory: the portal role groups, the devices and the marks of identity provider users.
type mfaIdP struct {
	mu      sync.Mutex
	groups  []string
	devices map[string]ports.Authenticators // user pk → devices
	marked  map[string]bool                 // user pk → paddock_mfa_enrol_at_login
	sets    int
	reads   int // users whose devices were read
	// groupsFail, readFail and setFail make the group listing, the device reads or the marks of a pk fail.
	groupsFail error
	readFail   error
	setFail    map[string]error
}

func (a *mfaIdP) PortalRoleGroupNames(context.Context) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.groups), a.groupsFail
}

func (a *mfaIdP) UserAuthenticators(_ context.Context, pks []string) (map[string]ports.Authenticators, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.readFail != nil {
		return nil, a.readFail
	}
	a.reads += len(pks)
	out := map[string]ports.Authenticators{}
	for _, pk := range pks {
		out[pk] = a.devices[pk]
	}
	return out, nil
}

func (a *mfaIdP) SetUserAttribute(_ context.Context, pk, key string, value any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if key != ports.AttrMFAEnrolAtLogin {
		return errors.New("unexpected attribute " + key)
	}
	if err := a.setFail[pk]; err != nil {
		return err
	}
	a.sets++
	if value == nil {
		delete(a.marked, pk)
	} else {
		a.marked[pk] = value.(bool)
	}
	return nil
}

func (a *mfaIdP) markedPKs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for pk, v := range a.marked {
		if v {
			out = append(out, pk)
		}
	}
	slices.Sort(out)
	return out
}

type mfaWorld struct {
	super *pgx.Conn
	dir   *directory
	idp   *mfaIdP
	mfa   *app.MFAEnrolment
	ctx   context.Context
	// corr is the correlation ID of this world's events.
	corr string
}

// newMFAWorld starts without a seed row; its directory lists only the groups it is given.
func newMFAWorld(t *testing.T) *mfaWorld {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	if _, err := super.Exec(ctx, "DELETE FROM platform_mfa_enrolment"); err != nil {
		t.Fatal(err)
	}
	dir := newDirectory()
	dir.roleGroups = map[string][]ports.IdentityUser{}
	dir.readable = map[string]bool{}
	idp := &mfaIdP{devices: map[string]ports.Authenticators{}, marked: map[string]bool{}}
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	corr := "corr-mfa-" + uuid.NewString()
	runner := app.NewActionRunner(worker, platform, func(context.Context) string { return corr })
	return &mfaWorld{super: super, dir: dir, idp: idp, mfa: app.NewMFAEnrolment(runner, platform, dir, idp), ctx: sys, corr: corr}
}

func (w *mfaWorld) seeded(t *testing.T) bool {
	t.Helper()
	var n int
	if err := w.super.QueryRow(context.Background(), "SELECT count(*) FROM platform_mfa_enrolment WHERE seeded_at IS NOT NULL").
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// member adds the account pk to group, created at joined (zero: one hour ago), with devices.
func (w *mfaWorld) member(group, pk string, devices ports.Authenticators, joined time.Time) {
	if joined.IsZero() {
		joined = time.Now().Add(-time.Hour)
	}
	if !slices.Contains(w.idp.groups, group) {
		w.idp.groups = append(w.idp.groups, group)
	}
	w.dir.roleGroups[group] = append(w.dir.roleGroups[group], ports.IdentityUser{PK: pk, Username: "u" + pk, UID: "uid-" + pk,
		Active: true, MFAEnrolAtLogin: w.idp.marked[pk], Joined: joined})
	w.idp.devices[pk] = devices
}

// relist renews the listing's marks from the identity provider, as the next round's listing would.
func (w *mfaWorld) relist() {
	for g, members := range w.dir.roleGroups {
		for i := range members {
			members[i].MFAEnrolAtLogin = w.idp.marked[members[i].PK]
		}
		w.dir.roleGroups[g] = members
	}
}

// events lists the MFA mark events of this world (its correlation ID) as "code outcome marked totp_only organizations cleared error_code".
func (w *mfaWorld) events(t *testing.T) []string {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT code || ' ' || outcome || ' ' || coalesce(params->>'marked', '-') ||
		' ' || coalesce(params->>'totp_only', '-') || ' ' || coalesce(params->>'organizations', '-') || ' ' ||
		coalesce(params->>'cleared', '-') || ' ' || coalesce(error_code, '-') || ' ' || (actor->>'type') || ' ' || organization_id::text
		FROM action WHERE code IN ('platform.mfa_enrol_marks_seeded', 'platform.mfa_enrol_marks_cleared') AND correlation_id = $1
		ORDER BY started_at, id`, w.corr)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const platformOrg = "00000000-0000-0000-0000-000000000000"

// TestMFAEnrolmentSeedMarksAdministratorsWithoutPasskeyOnce (ADR 0053 decision 4 and amendments c and d, gate MF4):
// the first seed marks every member of a portal role group without a passkey, TOTP-only accounts included, also in a
// role group without an organization, records one audit event with the counts, and never runs again: an administrator
// added afterwards stays unmarked and the second round records nothing.
func TestMFAEnrolmentSeedMarksAdministratorsWithoutPasskeyOnce(t *testing.T) {
	w := newMFAWorld(t)
	w.member(organization.PlatformAdminsGroup(), "1", ports.Authenticators{}, time.Time{})
	w.member(organization.RoleGroup("acme", organization.GroupAdmins), "2", ports.Authenticators{TOTP: true}, time.Time{})
	w.member(organization.RoleGroup("acme", organization.GroupOperators), "3", ports.Authenticators{WebAuthn: true}, time.Time{})
	w.member(organization.RoleGroup("acme", organization.GroupAuditors), "4", ports.Authenticators{WebAuthn: true, TOTP: true}, time.Time{})
	w.member(organization.RoleGroup("globex", organization.GroupAuditors), "5", ports.Authenticators{}, time.Time{})
	// A role group whose organization no longer exists still grants the role in the sign-in policy.
	w.member(organization.RoleGroup("gone", organization.GroupAdmins), "6", ports.Authenticators{}, time.Time{})
	if err := w.mfa.Seed(w.ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.idp.markedPKs(); !slices.Equal(got, []string{"1", "2", "5", "6"}) {
		t.Fatalf("marked %v, want the administrators without a passkey [1 2 5 6]", got)
	}
	if !w.seeded(t) {
		t.Fatal("the seed was not recorded")
	}
	want := []string{"platform.mfa_enrol_marks_seeded success 4 1 3 - - system " + platformOrg}
	if got := w.events(t); !slices.Equal(got, want) {
		t.Fatalf("events %q, want %q", got, want)
	}
	w.relist()
	w.member(organization.RoleGroup("acme", organization.GroupAdmins), "7", ports.Authenticators{}, time.Now())
	sets := w.idp.sets
	if err := w.mfa.Seed(w.ctx); err != nil {
		t.Fatal(err)
	}
	if w.idp.sets != sets || w.idp.marked["7"] || len(w.events(t)) != 1 {
		t.Fatalf("a second seed changed accounts (%d marks, account 7 marked %v) or recorded events %q", w.idp.sets-sets,
			w.idp.marked["7"], w.events(t))
	}
}

// A seed whose listing or device read fails records nothing and is repeated next round; the repeat marks only accounts
// created before the first attempt, never an administrator added in between.
func TestMFAEnrolmentSeedRetryNeverMarksLaterAdministrators(t *testing.T) {
	w := newMFAWorld(t)
	w.member(organization.RoleGroup("acme", organization.GroupAdmins), "1", ports.Authenticators{}, time.Time{})
	w.idp.readFail = errors.New("authentik down")
	if err := w.mfa.Seed(w.ctx); err == nil || w.seeded(t) || len(w.idp.markedPKs()) != 0 {
		t.Fatalf("a seed whose device read failed: %v, seeded %v, marked %v", err, w.seeded(t), w.idp.markedPKs())
	}
	w.idp.readFail = nil
	w.idp.groupsFail = errors.New("authentik down")
	if err := w.mfa.Seed(w.ctx); err == nil || w.seeded(t) {
		t.Fatalf("a seed whose group listing failed: %v, seeded %v", err, w.seeded(t))
	}
	w.idp.groupsFail = nil
	w.member(organization.RoleGroup("acme", organization.GroupAdmins), "2", ports.Authenticators{}, time.Now().Add(time.Second))
	if err := w.mfa.Seed(w.ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.idp.markedPKs(); !slices.Equal(got, []string{"1"}) || !w.seeded(t) {
		t.Fatalf("after the repeat: marked %v, seeded %v; want only the administrator of before the first attempt", got, w.seeded(t))
	}
	if w.idp.reads != 1 {
		t.Errorf("devices of %d users read, want 1 (the failed read is not counted; the later administrator is not read)", w.idp.reads)
	}
}

// A mark that fails after another was written is not repeated: the seed is recorded, the event is a failure with the
// count written, and the unmarked administrator fails closed (a sign-in setup link helps). A seed whose every mark
// fails records no event.
func TestMFAEnrolmentSeedPartialFailure(t *testing.T) {
	w := newMFAWorld(t)
	w.member(organization.RoleGroup("acme", organization.GroupAdmins), "1", ports.Authenticators{}, time.Time{})
	w.member(organization.RoleGroup("acme", organization.GroupAdmins), "2", ports.Authenticators{}, time.Time{})
	w.idp.setFail = map[string]error{"2": errors.New("authentik down")}
	if err := w.mfa.Seed(w.ctx); err == nil {
		t.Fatal("a seed with a failed mark reported success")
	}
	if got := w.idp.markedPKs(); !slices.Equal(got, []string{"1"}) || !w.seeded(t) {
		t.Fatalf("marked %v, seeded %v", got, w.seeded(t))
	}
	if got := w.events(t); len(got) != 1 || got[0][:len("platform.mfa_enrol_marks_seeded failure 1 0 1")] !=
		"platform.mfa_enrol_marks_seeded failure 1 0 1" {
		t.Fatalf("events %q, want one failure with marked 1", got)
	}
	w.idp.setFail = nil
	w.relist()
	if err := w.mfa.Seed(w.ctx); err != nil || w.idp.marked["2"] {
		t.Fatalf("the seed ran again: %v, account 2 marked %v", err, w.idp.marked["2"])
	}

	nothing := newMFAWorld(t)
	nothing.member(organization.RoleGroup("acme", organization.GroupAdmins), "3", ports.Authenticators{}, time.Time{})
	nothing.idp.setFail = map[string]error{"3": errors.New("authentik down")}
	if err := nothing.mfa.Seed(nothing.ctx); err == nil || len(nothing.events(t)) != 0 {
		t.Fatalf("a seed that wrote nothing: %v, events %q", err, nothing.events(t))
	}
}

// Listings that are all empty to a service token that sees no users (PDK-424) never record a seed.
func TestMFAEnrolmentSeedRefusesABlindDirectory(t *testing.T) {
	w := newMFAWorld(t)
	w.idp.groups = []string{organization.PlatformAdminsGroup()}
	w.dir.usersVisible = false
	if err := w.mfa.Seed(w.ctx); !errors.Is(err, app.ErrDirectoryEmpty) || w.seeded(t) {
		t.Fatalf("empty listings of a blind token: %v, seeded %v", err, w.seeded(t))
	}
	w.dir.roleGroupFail = map[string]error{organization.PlatformAdminsGroup(): errors.New("listing failed")}
	if err := w.mfa.Seed(w.ctx); err == nil || w.seeded(t) {
		t.Fatalf("a failed listing: %v, seeded %v", err, w.seeded(t))
	}
}

// Clear removes the mark from marked accounts with a passkey only, records the count, and reads no devices for a round
// without marked accounts; a round that removes nothing records nothing.
func TestMFAEnrolmentClear(t *testing.T) {
	w := newMFAWorld(t)
	w.idp.marked = map[string]bool{"1": true, "2": true}
	w.idp.devices = map[string]ports.Authenticators{"1": {WebAuthn: true}, "2": {TOTP: true}, "3": {WebAuthn: true}}
	members := []ports.IdentityUser{
		{PK: "1", Username: "enrolled", MFAEnrolAtLogin: true},
		{PK: "1", Username: "enrolled", MFAEnrolAtLogin: true},
		{PK: "2", Username: "totp-only", MFAEnrolAtLogin: true},
		{PK: "3", Username: "never-marked"},
	}
	if err := w.mfa.Clear(w.ctx, members); err != nil {
		t.Fatal(err)
	}
	if got := w.idp.markedPKs(); !slices.Equal(got, []string{"2"}) || w.idp.sets != 1 || w.idp.reads != 2 {
		t.Fatalf("after clear: marked %v, %d changes, %d reads; want [2], 1 change, 2 reads", got, w.idp.sets, w.idp.reads)
	}
	want := []string{"platform.mfa_enrol_marks_cleared success - - - 1 - system " + platformOrg}
	if got := w.events(t); !slices.Equal(got, want) {
		t.Fatalf("events %q, want %q", got, want)
	}
	if err := w.mfa.Clear(w.ctx, []ports.IdentityUser{{PK: "2", MFAEnrolAtLogin: true}}); err != nil || len(w.events(t)) != 1 {
		t.Fatalf("a round that removed nothing: %v, events %q", err, w.events(t))
	}
	w.idp.readFail = errors.New("must not read devices")
	if err := w.mfa.Clear(w.ctx, []ports.IdentityUser{{PK: "3"}}); err != nil {
		t.Fatalf("a round without marked accounts read devices: %v", err)
	}
}

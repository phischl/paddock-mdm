package app_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// fixedPortalUsers lists n portal users with the pks 1..n.
type fixedPortalUsers struct{ n int }

func (f fixedPortalUsers) PortalUsers(context.Context) ([]ports.IdentityUser, error) {
	out := make([]ports.IdentityUser, f.n)
	for i := range out {
		out[i] = ports.IdentityUser{PK: strconv.Itoa(i + 1), Username: fmt.Sprintf("u%d", i+1)}
	}
	return out, nil
}

// identitySessions records every bulk delete; each user has two sessions. failAt fails the call with that index
// (1-based); retried makes every bulk delete report 0, like one repeated after a timeout (PDK-342); countFail fails
// the count, countHangs blocks it until its context ends. deadlines are the bulk deletes' deadlines.
type identitySessions struct {
	mu         sync.Mutex
	calls      [][]string
	deadlines  []time.Time
	failAt     int
	retried    bool
	countFail  bool
	countHangs bool
}

func (f *identitySessions) CountUserSessions(ctx context.Context, pks []string) (int, error) {
	if f.countHangs {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if f.countFail {
		return 0, fmt.Errorf("%w: authentik: HTTP 503", problem.UpstreamUnavailable)
	}
	return 2 * len(pks), nil
}

func (f *identitySessions) EndUserSessions(ctx context.Context, pks []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, slices.Clone(pks))
	deadline, _ := ctx.Deadline()
	f.deadlines = append(f.deadlines, deadline)
	if len(f.calls) == f.failAt {
		return 0, fmt.Errorf("%w: authentik: HTTP 403", problem.UpstreamUnavailable)
	}
	if f.retried {
		return 0, nil
	}
	return 2 * len(pks), nil
}

// TestEndAllSessionsCLI: paddock-server admin end-sessions increments the session generation and records
// platform.sessions_ended with the system actor and the new generation (plan M8s decision 16).
func TestEndAllSessionsCLI(t *testing.T) {
	admin, super, _ := adminHarness(t)
	store := sessions.NewStore(valkeytest.Start(t).Client(t))
	s := app.NewSessions(admin.Runner(), store, fixedPortalUsers{}, &identitySessions{})
	for want := int64(1); want <= 2; want++ {
		gen, err := s.EndAllCLI(context.Background())
		if err != nil || gen != want {
			t.Fatalf("end sessions: %d %v, want %d", gen, err, want)
		}
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.sessions_ended'
		AND outcome = 'success' AND organization_id = $2 AND actor->>'type' = 'system' AND (params->>'generation')::int = 2`,
		"corr-"+t.Name(), uuid.Nil); n != 1 {
		t.Fatalf("%d platform.sessions_ended events of generation 2", n)
	}
}

// TestEndAllSessionsEndsIdentitySessions (plan M8f decisions 16 and 20): ending all sessions also ends the identity
// provider's sessions of every portal user, 50 users per call, and records how many users and sessions; a failing call
// fails the action with upstream_unavailable after the Paddock sessions are ended.
func TestEndAllSessionsEndsIdentitySessions(t *testing.T) {
	admin, super, _ := adminHarness(t)
	store := sessions.NewStore(valkeytest.Start(t).Client(t))
	ender := &identitySessions{}
	s := app.NewSessions(admin.Runner(), store, fixedPortalUsers{n: 120}, ender)
	if _, err := s.EndAllCLI(context.Background()); err != nil {
		t.Fatal(err)
	}
	var seen []string
	for i, c := range ender.calls {
		if want := []int{50, 50, 20}; i >= len(want) || len(c) != want[i] {
			t.Fatalf("calls %v, want 50, 50 and 20 users", ender.calls)
		}
		seen = append(seen, c...)
	}
	slices.Sort(seen)
	if len(slices.Compact(seen)) != 120 {
		t.Fatalf("%d distinct users ended, want 120", len(seen))
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.sessions_ended'
		AND outcome = 'success' AND (params->>'identity_users')::int = 120 AND (params->>'identity_sessions_ended')::int = 240`,
		"corr-"+t.Name()); n != 1 {
		t.Fatalf("%d success events with identity_users 120 and identity_sessions_ended 240", n)
	}

	failing := &identitySessions{failAt: 2}
	gen, err := app.NewSessions(admin.Runner(), store, fixedPortalUsers{n: 120}, failing).EndAllCLI(context.Background())
	if !errors.Is(err, problem.UpstreamUnavailable) ||
		problem.From(err).Detail != "the identity provider's sessions could not be ended; end all sessions again" {
		t.Fatalf("failing identity provider: %v", err)
	}
	if len(failing.calls) != 2 {
		t.Fatalf("%d calls after a failing chunk, want 2", len(failing.calls))
	}
	if gen != 2 {
		t.Fatalf("generation %d after the failure, want 2: the Paddock sessions are ended first", gen)
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.sessions_ended'
		AND outcome = 'failure'`, "corr-"+t.Name()); n != 1 {
		t.Fatalf("%d failure events", n)
	}
}

// TestEndAllSessionsCountsIdentitySessions (PDK-342): the sessions ended are the users' sessions counted before the
// bulk deletes when a repeated bulk delete reports fewer; a failing count still ends every chunk and records the
// deletes' count.
func TestEndAllSessionsCountsIdentitySessions(t *testing.T) {
	store := sessions.NewStore(valkeytest.Start(t).Client(t))
	for _, tc := range []struct {
		name  string
		ender *identitySessions
		want  int
	}{
		{"repeated bulk delete", &identitySessions{retried: true}, 240},
		{"failing count", &identitySessions{countFail: true}, 240},
		{"failing count and repeated bulk delete", &identitySessions{countFail: true, retried: true}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin, super, _ := adminHarness(t)
			if _, err := app.NewSessions(admin.Runner(), store, fixedPortalUsers{n: 120}, tc.ender).EndAllCLI(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(tc.ender.calls) != 3 {
				t.Fatalf("%d bulk deletes, want 3", len(tc.ender.calls))
			}
			if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.sessions_ended'
				AND outcome = 'success' AND (params->>'identity_sessions_ended')::int = $2`, "corr-"+t.Name(), tc.want); n != 1 {
				t.Fatalf("%d success events with identity_sessions_ended %d", n, tc.want)
			}
		})
	}
}

// TestEndAllSessionsSlowCountKeepsTheDeleteBudget (PDK-342): a count that does not answer is cut off after its own
// bound, every chunk's bulk delete is still sent, and the deletes' deadline moves by the time the count took, so they
// keep the whole identitySessionBudget (80 s).
func TestEndAllSessionsSlowCountKeepsTheDeleteBudget(t *testing.T) {
	admin, super, _ := adminHarness(t)
	store := sessions.NewStore(valkeytest.Start(t).Client(t))
	ender := &identitySessions{countHangs: true}
	s := app.NewSessions(admin.Runner(), store, fixedPortalUsers{n: 120}, ender)
	const countBudget = 300 * time.Millisecond
	s.SetCountBudget(countBudget)
	before := time.Now()
	if _, err := s.EndAllCLI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ender.calls) != 3 {
		t.Fatalf("%d bulk deletes, want 3", len(ender.calls))
	}
	for i, d := range ender.deadlines {
		if d.Before(before.Add(80*time.Second + countBudget)) {
			t.Fatalf("bulk delete %d has the deadline %v, want at least 80 s plus the count's %v after %v", i+1, d, countBudget, before)
		}
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.sessions_ended'
		AND outcome = 'success' AND (params->>'identity_sessions_ended')::int = 240`, "corr-"+t.Name()); n != 1 {
		t.Fatalf("%d success events with identity_sessions_ended 240", n)
	}
}

// observingSessions checks, during each bulk delete, that the action is already recorded as started and that the call
// carries a deadline; it ends no session and fails when told to.
type observingSessions struct {
	check    func()
	deadline time.Time
	fail     error
}

func (f *observingSessions) CountUserSessions(context.Context, []string) (int, error) { return 0, nil }

func (f *observingSessions) EndUserSessions(ctx context.Context, _ []string) (int, error) {
	f.check()
	f.deadline, _ = ctx.Deadline()
	return 0, f.fail
}

// TestEndAllSessionsCallsOutsideTheTransaction (plan M8f decision 16, amended 2026-10-18; PDK-322): the identity
// provider is called after the started action is committed, so a crash leaves an action the reaper records as unknown,
// and within a deadline below the HTTP write timeout; a call that runs into the deadline records a failure.
func TestEndAllSessionsCallsOutsideTheTransaction(t *testing.T) {
	admin, super, _ := adminHarness(t)
	store := sessions.NewStore(valkeytest.Start(t).Client(t))
	started := func() int {
		return countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.sessions_ended'
			AND status = 'started'`, "corr-"+t.Name())
	}
	var seen []int
	ender := &observingSessions{check: func() { seen = append(seen, started()) }}
	before := time.Now()
	if _, err := app.NewSessions(admin.Runner(), store, fixedPortalUsers{n: 3}, ender).EndAllCLI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(seen) != "[1]" {
		t.Fatalf("started actions seen during the identity-provider call %v, want [1]", seen)
	}
	if ender.deadline.IsZero() || ender.deadline.After(before.Add(90*time.Second)) {
		t.Fatalf("identity-provider call deadline %v, want one within 90 s of %v", ender.deadline, before)
	}
	if n := started(); n != 0 {
		t.Fatalf("%d actions still started after the call", n)
	}

	ender.fail = context.DeadlineExceeded
	_, err := app.NewSessions(admin.Runner(), store, fixedPortalUsers{n: 3}, ender).EndAllCLI(context.Background())
	if !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("identity provider past the deadline: %v, want upstream_unavailable", err)
	}
	if n := countRows(t, super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'platform.sessions_ended'
		AND status = 'finished' AND outcome = 'failure' AND (params->>'identity_users')::int = 3`, "corr-"+t.Name()); n != 1 {
		t.Fatalf("%d failure events with identity_users 3", n)
	}
}

// roleDirectory answers RoleGroupUsers from groups; a group it does not know does not exist.
type roleDirectory struct {
	ports.UserDirectory
	groups map[string][]ports.IdentityUser
}

func (d roleDirectory) RoleGroupUsers(_ context.Context, name string) ([]ports.IdentityUser, error) {
	if users, ok := d.groups[name]; ok {
		return users, nil
	}
	return nil, ports.ErrGroupNotFound
}

// TestPortalUsers (plan M8f decision 16): the portal users are the platform administrators and the members of the
// three role groups of every organization, each once; a group that does not exist yet is skipped, any other error
// fails the listing.
func TestPortalUsers(t *testing.T) {
	_, super, org := adminHarness(t)
	var slug string
	if err := super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", org).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	platform, err := db.NewPlatformPool(context.Background(), pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	root, alice, bob := ports.IdentityUser{PK: "1"}, ports.IdentityUser{PK: "2"}, ports.IdentityUser{PK: "3"}
	dir := roleDirectory{groups: map[string][]ports.IdentityUser{
		organization.PlatformAdminsGroup():                        {root},
		organization.RoleGroup(slug, organization.GroupAdmins):    {alice},
		organization.RoleGroup(slug, organization.GroupOperators): {alice, bob},
	}}
	ctx := principal.With(context.Background(), principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Role: principal.RolePlatform})
	users, err := app.NewPortalUsers(platform, dir).PortalUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(users) != fmt.Sprint([]ports.IdentityUser{root, alice, bob}) {
		t.Fatalf("portal users %v, want root, alice and bob once", users)
	}
	failing := failingDirectory{roleDirectory: dir}
	if _, err := app.NewPortalUsers(platform, failing).PortalUsers(ctx); err == nil {
		t.Fatal("a failing role group listing was ignored")
	}
}

// failingDirectory fails every listing.
type failingDirectory struct{ roleDirectory }

func (failingDirectory) RoleGroupUsers(context.Context, string) ([]ports.IdentityUser, error) {
	return nil, problem.UpstreamUnavailable
}

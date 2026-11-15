package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// fakeOffboardIdentity is Authentik for the deletion: the objects of each organization slug, deleted once.
type fakeOffboardIdentity struct {
	mu      sync.Mutex
	objects map[string]int
	calls   []string
	err     error
}

func (f *fakeOffboardIdentity) DeleteOrganization(_ context.Context, slug string) (ports.OrgIdentityDeletion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, slug)
	if f.err != nil {
		return ports.OrgIdentityDeletion{}, f.err
	}
	n := f.objects[slug]
	delete(f.objects, slug)
	return ports.OrgIdentityDeletion{Groups: n}, nil
}

// fakeOffboardFleet is Fleet's host deletion.
type fakeOffboardFleet struct {
	mu      sync.Mutex
	hosts   map[string]bool
	deleted []string
}

func (f *fakeOffboardFleet) DeleteHost(_ context.Context, ref ports.HostRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hosts, string(ref))
	f.deleted = append(f.deleted, string(ref))
	return nil
}

// fakeOffboardCache is the device keys in Valkey, by organization; it records the devices of every deletion and the
// devices handed over by the step devices.
type fakeOffboardCache struct {
	mu         sync.Mutex
	keys       map[uuid.UUID]int
	err        error
	devices    []devicecache.OffboardDevice
	offboarded map[uuid.UUID]devicecache.OffboardedDevice
	dropped    []uuid.UUID
}

func (f *fakeOffboardCache) DeleteCommand(_ context.Context, _, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.dropped = append(f.dropped, id)
	return nil
}

func (f *fakeOffboardCache) PutOffboardedDevice(_ context.Context, d devicecache.OffboardedDevice, _ int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if f.offboarded == nil {
		f.offboarded = map[uuid.UUID]devicecache.OffboardedDevice{}
	}
	f.offboarded[d.ID] = d
	return nil
}

// fakeCommandSigner signs with command-signing:v1 and a constant signature; err fails every call.
type fakeCommandSigner struct{ err error }

func (f fakeCommandSigner) SignBatch(_ context.Context, _ string, messages [][]byte) ([]bao.RawSignature, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]bao.RawSignature, len(messages))
	for i := range out {
		out[i] = bao.RawSignature{KeyVersion: 1, Value: []byte{1}}
	}
	return out, nil
}

func (f *fakeOffboardCache) DeleteOrganization(_ context.Context, org uuid.UUID, devices []devicecache.OffboardDevice) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.devices = devices
	n := f.keys[org]
	delete(f.keys, org)
	return int64(n), nil
}

// fakeOffboardSessions is the session store: sessions per administrator account.
type fakeOffboardSessions struct {
	mu       sync.Mutex
	sessions map[uuid.UUID]int
}

func (f *fakeOffboardSessions) RevokeAccount(_ context.Context, account uuid.UUID) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.sessions[account]
	delete(f.sessions, account)
	return n, nil
}

// fakeBucket is one bucket of the object store with the purge of the deletion's credentials; it records every call
// with its bucket, so a test sees which buckets the step used.
type fakeBucket struct {
	name    string
	mu      *sync.Mutex
	calls   *[]string
	objects map[string]bool
	retain  map[string]bool
	err     error
}

func (b *fakeBucket) purge(prefix string) (objectstore.Purge, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	*b.calls = append(*b.calls, b.name+":"+prefix)
	if b.err != nil {
		return objectstore.Purge{}, b.err
	}
	var p objectstore.Purge
	for k := range b.objects {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if b.retain[k] {
			p.Retained = append(p.Retained, k)
			continue
		}
		delete(b.objects, k)
		p.Deleted++
	}
	if len(p.Retained) > 0 {
		return p, fmt.Errorf("%w: %d below %s", objectstore.ErrRetained, len(p.Retained), prefix)
	}
	return p, nil
}

func (b *fakeBucket) PurgeObjects(_ context.Context, prefix string) (objectstore.Purge, error) {
	return b.purge(prefix)
}

func (b *fakeBucket) PurgeVersions(_ context.Context, prefix string) (objectstore.Purge, error) {
	return b.purge(prefix)
}

// offboardWorld is an organization whose deletion is due, another organization that must survive it, and the fakes
// of every store the deletion touches (plan M17 §8.3).
type offboardWorld struct {
	deletionWorld
	worker                *db.OrgPool
	other                 uuid.UUID
	otherDevice           uuid.UUID
	account               uuid.UUID
	idp                   *fakeOffboardIdentity
	fleet                 *fakeOffboardFleet
	cache                 *fakeOffboardCache
	sessions              *fakeOffboardSessions
	signer                fakeCommandSigner
	bundles, escrow, logs *fakeBucket
	bucketCalls           []string
	clock                 time.Time
	clockMu               sync.Mutex
}

func newOffboardWorld(t *testing.T) *offboardWorld {
	t.Helper()
	d := newDeletionWorld(t)
	env := pgtest.SharedPaddock(t)
	worker, err := db.NewOrgPool(context.Background(), env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	w := &offboardWorld{deletionWorld: d, worker: worker, clock: time.Now()}
	w.other = d.otherOrg(t)
	w.otherDevice, _ = d.newDevice(t, w.other, "active")
	w.account = uuid.Must(uuid.NewV7())
	otherAccount := uuid.Must(uuid.NewV7())
	for _, a := range []struct {
		id, org uuid.UUID
	}{{w.account, d.org}, {otherAccount, w.other}} {
		d.exec(t, `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
			VALUES ($1, $2, $3, 'admin', 'Admin', 'org_admin')`, a.id, a.org, "sub-"+a.id.String())
	}
	d.exec(t, `INSERT INTO api_token (id, organization_id, name, role, secret_sha256, prefix, created_by, expires_at)
		VALUES ($1, $2, 'ci', 'org_admin', $3, 'pdk_abcdefgh', $4, now() + interval '1 day')`,
		uuid.Must(uuid.NewV7()), d.org, []byte(uuid.NewString()), w.account)
	d.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)",
		d.device, d.org, "host-"+d.device.String())
	d.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)",
		w.otherDevice, w.other, "host-"+w.otherDevice.String())
	var otherSlug string
	if err := d.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", w.other).Scan(&otherSlug); err != nil {
		t.Fatal(err)
	}

	w.idp = &fakeOffboardIdentity{objects: map[string]int{d.slug: 7, otherSlug: 5}}
	w.fleet = &fakeOffboardFleet{hosts: map[string]bool{"host-" + d.device.String(): true, "host-" + w.otherDevice.String(): true}}
	w.cache = &fakeOffboardCache{keys: map[uuid.UUID]int{d.org: 6, w.other: 6}}
	w.sessions = &fakeOffboardSessions{sessions: map[uuid.UUID]int{w.account: 2, otherAccount: 3}}
	mu := &sync.Mutex{}
	bucket := func(name string, keys ...string) *fakeBucket {
		b := &fakeBucket{name: name, mu: mu, calls: &w.bucketCalls, objects: map[string]bool{}, retain: map[string]bool{}}
		for _, k := range keys {
			b.objects[k] = true
		}
		return b
	}
	org, other := d.org.String(), w.other.String()
	w.bundles = bucket("paddock-bundles", "org/"+org+"/a", "org/"+org+"/b", "apt/"+org+"/dists/x", "org/"+other+"/a", "apt/"+other+"/x")
	w.escrow = bucket("paddock-escrow", "org/"+org+"/devices/d/luks-header/1", "org/"+other+"/devices/d/luks-header/1")
	w.logs = bucket("paddock-audit", "org/"+org+"/2026/11/15.jsonl")
	return w
}

// job is the deletion as the worker wires it, with the stubbed step of PDK-1017.
func (w *offboardWorld) job() *app.Offboarding {
	return app.NewOffboarding(app.OffboardingObjects{Bundles: w.bundles, Escrow: w.escrow}).
		WithDeps(app.OffboardingDeps{Runner: w.runner, Worker: w.worker, Platform: w.platform, Identity: w.idp,
			Inventory: w.fleet, Cache: w.cache, Sessions: w.sessions, Signer: w.signer}).
		WithStubbedSteps(offboarding.StepAuditFinal).
		WithClock(func() time.Time {
			w.clockMu.Lock()
			defer w.clockMu.Unlock()
			return w.clock
		})
}

// requestDue requests the deletion with grace 0, publishes the organization's outbox (no relay runs here), starts the
// deletion, and lets every device report its removal, as the devices do during the grace period.
func (w *offboardWorld) requestDue(t *testing.T, job *app.Offboarding) {
	t.Helper()
	w.requestDueWithDevices(t, job)
	w.exec(t, "UPDATE device SET uninstalled_at = now() WHERE organization_id = $1", w.org)
}

// requestDueWithDevices is requestDue with the devices still unreported.
func (w *offboardWorld) requestDueWithDevices(t *testing.T, job *app.Offboarding) {
	t.Helper()
	if _, err := w.devOrgs.RequestDeletion(w.root(true), w.org, w.input(0)); err != nil {
		t.Fatal(err)
	}
	w.publishOutbox(t)
	started, err := job.StartDue(context.Background())
	if err != nil || !slices.Contains(started, w.org) {
		t.Fatalf("StartDue = %v, %v; want %s", started, err, w.org)
	}
	if slices.Contains(started, w.other) {
		t.Fatal("the other organization was started")
	}
}

func (w *offboardWorld) publishOutbox(t *testing.T) {
	t.Helper()
	w.exec(t, "UPDATE outbox SET published_at = now() WHERE organization_id = $1 AND published_at IS NULL", w.org)
}

// state is the organization's status, step and error code.
func (w *offboardWorld) state(t *testing.T) (status, step, code string) {
	t.Helper()
	var st, ec *string
	if err := w.super.QueryRow(context.Background(), "SELECT status, offboarding_step, offboarding_error_code FROM organization WHERE id = $1",
		w.org).Scan(&status, &st, &ec); err != nil {
		t.Fatal(err)
	}
	if st != nil {
		step = *st
	}
	if ec != nil {
		code = *ec
	}
	return status, step, code
}

// stepEvents are the platform events of code for the organization, oldest first.
func (w *offboardWorld) stepEvents(t *testing.T, code audit.Code) []audit.Event {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT payload FROM outbox
		WHERE organization_id = $1 AND payload ->> 'code' = $2 AND payload -> 'target' ->> 'id' = $3 ORDER BY id`,
		audit.PlatformOrganizationID, string(code), w.org.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []audit.Event
	for rows.Next() {
		var raw []byte
		var ev audit.Event
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// passCutoff moves the stored cutoff base of quiesce 7 s back, so the test need not wait the gate's 6 s margin.
func (w *offboardWorld) passCutoff(t *testing.T) {
	t.Helper()
	w.exec(t, `UPDATE organization SET deleting_committed_at = coalesce(deleting_committed_at, now()) - interval '7 seconds'
		WHERE id = $1 AND offboarding_wait_vxids IS NULL`, w.org)
}

// advanceTo advances until the organization is at step (or done when step is ""), failing on a step error.
func (w *offboardWorld) advanceTo(t *testing.T, job *app.Offboarding, step string) {
	t.Helper()
	for range 60 {
		if _, cur, _ := w.state(t); cur == step {
			return
		}
		done, err := job.Advance(context.Background(), w.org)
		switch {
		case errors.Is(err, app.ErrOffboardingWaiting):
			w.passCutoff(t)
			time.Sleep(50 * time.Millisecond)
		case err != nil:
			t.Fatalf("Advance: %v", err)
		case done && step == "":
			return
		}
	}
	t.Fatalf("the deletion never reached step %q", step)
}

func (w *offboardWorld) rows(t *testing.T, org uuid.UUID) int {
	t.Helper()
	return w.count(t, `SELECT (SELECT count(*) FROM device WHERE organization_id = $1) + (SELECT count(*) FROM admin_account WHERE organization_id = $1)
		+ (SELECT count(*) FROM device_inventory_ref WHERE organization_id = $1)`, org)
}

// TestOffboardingDeletesOrganization (plan M17 §8.3, OFB-4): a due organization goes through every step in the order
// of decision 6 and ends deleted, with one organization.deletion_step_completed per step and organization.deleted with
// the counts per store; the other organization's rows, objects, Valkey keys, sessions, Fleet host and Authentik
// objects survive, and the audit bucket is never called.
func TestOffboardingDeletesOrganization(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	otherRows := w.rows(t, w.other)
	w.requestDue(t, job)
	if status, step, _ := w.state(t); status != organization.StatusDeleting || step != offboarding.StepSessions {
		t.Fatalf("after StartDue: %s at %s", status, step)
	}
	w.advanceTo(t, job, "")

	if status, step, code := w.state(t); status != organization.StatusDeleted || step != "" || code != "" {
		t.Fatalf("after the deletion: %s at %q with %q", status, step, code)
	}
	completed := w.stepEvents(t, audit.CodeOrganizationDeletionStepCompleted)
	var steps []string
	for _, ev := range completed {
		steps = append(steps, ev.Params["step"].(string))
		if ev.Outcome != audit.OutcomeSuccess || ev.Params["slug"] != w.slug || ev.Actor.Type != "system" {
			t.Fatalf("step event %+v", ev)
		}
	}
	if !slices.Equal(steps, offboarding.Steps()) {
		t.Fatalf("completed steps %v, want %v", steps, offboarding.Steps())
	}
	byStep := map[string]float64{}
	for _, ev := range completed {
		byStep[ev.Params["step"].(string)] = ev.Params["count"].(float64)
	}
	if byStep[offboarding.StepSessions] != 3 || byStep[offboarding.StepAuthentik] != 7 || byStep[offboarding.StepFleet] != 1 ||
		byStep[offboarding.StepObjects] != 4 || byStep[offboarding.StepValkey] != 6 || byStep[offboarding.StepDatabase] < 3 {
		t.Fatalf("step counts %v", byStep)
	}
	deleted := w.stepEvents(t, audit.CodeOrganizationDeleted)
	if len(deleted) != 1 {
		t.Fatalf("organization.deleted recorded %d times", len(deleted))
	}
	p := deleted[0].Params
	if p["slug"] != w.slug || p["authentik_objects_deleted"] != float64(7) || p["fleet_hosts_deleted"] != float64(1) ||
		p["objects_deleted"] != float64(4) || p["devices_offboarded"] != float64(0) || p["rows_deleted"] != byStep[offboarding.StepDatabase] {
		t.Fatalf("organization.deleted params %v", p)
	}
	if n := len(w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)); n != 0 {
		t.Fatalf("%d failure events on a clean run", n)
	}

	if w.rows(t, w.org) != 0 {
		t.Fatal("rows of the organization remain")
	}
	if got := w.rows(t, w.other); got != otherRows {
		t.Fatalf("the other organization has %d rows, had %d", got, otherRows)
	}
	other := w.other.String()
	for _, k := range []string{"org/" + other + "/a", "apt/" + other + "/x"} {
		if !w.bundles.objects[k] {
			t.Fatalf("bundles object %s of the other organization was deleted", k)
		}
	}
	if len(w.bundles.objects) != 2 || len(w.escrow.objects) != 1 || len(w.logs.objects) != 1 {
		t.Fatalf("objects left: bundles %v, escrow %v, audit %v", w.bundles.objects, w.escrow.objects, w.logs.objects)
	}
	for _, c := range w.bucketCalls {
		if strings.HasPrefix(c, "paddock-audit:") || !strings.Contains(c, w.org.String()) {
			t.Fatalf("object store call %s", c)
		}
	}
	if w.cache.keys[w.other] != 6 || w.sessions.sessions[w.account] != 0 || len(w.sessions.sessions) != 1 ||
		!w.fleet.hosts["host-"+w.otherDevice.String()] || len(w.idp.objects) != 1 {
		t.Fatalf("other organization: keys %v, sessions %v, hosts %v, identity %v", w.cache.keys, w.sessions.sessions,
			w.fleet.hosts, w.idp.objects)
	}

	if done, err := job.Advance(context.Background(), w.org); !done || err != nil {
		t.Fatalf("Advance after the deletion: %v, %v", done, err)
	}
	if n := len(w.stepEvents(t, audit.CodeOrganizationDeleted)); n != 1 {
		t.Fatalf("organization.deleted recorded %d times after another round", n)
	}
}

// TestOffboardingResumesAfterCrash (plan M17 §8.3): a worker that stops between two steps leaves the stored step; a
// new worker resumes there and does not repeat the completed step. A step repeated because its checkpoint was lost
// ends in the same state and removes nothing twice.
func TestOffboardingResumesAfterCrash(t *testing.T) {
	w := newOffboardWorld(t)
	first := w.job()
	w.requestDue(t, first)
	w.advanceTo(t, first, offboarding.StepFleet)
	if len(w.idp.calls) != 1 {
		t.Fatalf("identity calls %v", w.idp.calls)
	}

	second := w.job()
	if _, err := second.Advance(context.Background(), w.org); err != nil {
		t.Fatal(err)
	}
	if _, step, _ := w.state(t); step != offboarding.StepObjects {
		t.Fatalf("the new worker is at %s, want objects", step)
	}
	if len(w.idp.calls) != 1 || len(w.fleet.deleted) != 1 {
		t.Fatalf("a completed step ran again: identity %v, fleet %v", w.idp.calls, w.fleet.deleted)
	}

	// The checkpoint of authentik lost: the step runs again, finds nothing and leaves the same state.
	w.exec(t, "UPDATE organization SET offboarding_step = 'authentik' WHERE id = $1", w.org)
	w.advanceTo(t, second, offboarding.StepFleet)
	if len(w.idp.calls) != 2 || len(w.idp.objects) != 1 {
		t.Fatalf("repeated authentik: calls %v, objects %v", w.idp.calls, w.idp.objects)
	}
	w.advanceTo(t, second, "")
	ev := w.stepEvents(t, audit.CodeOrganizationDeleted)
	if len(ev) != 1 || ev[0].Params["authentik_objects_deleted"] != float64(7) {
		t.Fatalf("organization.deleted %+v", ev)
	}
}

// TestOffboardingWaitsForOutbox (plan M17 decision 9): the step outbox does not complete while an unpublished outbox
// row of the organization exists, and deletes none; once it is published the deletion continues.
func TestOffboardingWaitsForOutbox(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepOutbox)
	w.exec(t, `INSERT INTO outbox (organization_id, subject, msg_id, payload) VALUES ($1, 'audit.event', $2, '{}')`,
		w.org, uuid.NewString())
	for range 3 {
		_, err := job.Advance(context.Background(), w.org)
		var oe *app.OffboardingError
		if !errors.As(err, &oe) || oe.Code != offboarding.ErrorOutboxPending {
			t.Fatalf("Advance with an unpublished row: %v", err)
		}
	}
	if _, step, code := w.state(t); step != offboarding.StepOutbox || code != offboarding.ErrorOutboxPending {
		t.Fatalf("at %s with %s", step, code)
	}
	if n := w.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1 AND published_at IS NULL", w.org); n != 1 {
		t.Fatalf("%d unpublished rows, want the one kept", n)
	}
	if n := len(w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)); n != 1 {
		t.Fatalf("%d failure events, want 1", n)
	}
	w.publishOutbox(t)
	w.advanceTo(t, job, offboarding.StepAuthentik)
	if _, _, code := w.state(t); code != "" {
		t.Fatalf("the error code %s stays after the step completed", code)
	}
}

// TestOffboardingAuthentikOutage (plan M17 §8.3, OFB-6): an unreachable Authentik stores authentik_unavailable and
// records organization.deletion_step_failed once; repeated identical failures record nothing more; once Authentik is
// back the deletion continues.
func TestOffboardingAuthentikOutage(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepAuthentik)
	w.idp.err = fmt.Errorf("%w: connection refused", problem.UpstreamUnavailable)
	for range 4 {
		if _, err := job.Advance(context.Background(), w.org); err == nil {
			t.Fatal("Advance succeeded with Authentik down")
		}
	}
	if _, step, code := w.state(t); step != offboarding.StepAuthentik || code != offboarding.ErrorAuthentikUnavailable {
		t.Fatalf("at %s with %q", step, code)
	}
	failed := w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)
	if len(failed) != 1 || failed[0].Outcome != audit.OutcomeFailure || failed[0].ErrorCode != offboarding.ErrorAuthentikUnavailable ||
		failed[0].Params["error_code"] != offboarding.ErrorAuthentikUnavailable || failed[0].Params["step"] != offboarding.StepAuthentik ||
		failed[0].OrganizationID != audit.PlatformOrganizationID {
		t.Fatalf("failure events %+v, want one authentik_unavailable", failed)
	}
	w.idp.err = nil
	w.advanceTo(t, job, "")
	if status, _, _ := w.state(t); status != organization.StatusDeleted {
		t.Fatalf("status %s after recovery", status)
	}
	if n := len(w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)); n != 1 {
		t.Fatalf("%d failure events after recovery", n)
	}
}

// TestOffboardingObjectRetained (main's amendment of 2026-11-15, k addendum point 3): objects kept by Object Lock fail
// the step with object_retained; repeated rounds record one failure event; a change of code records a new one; once
// the retention is gone the step completes with everything it deleted over its attempts.
func TestOffboardingObjectRetained(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepObjects)
	header := "org/" + w.org.String() + "/devices/d/luks-header/1"
	w.escrow.retain[header] = true
	for range 3 {
		_, err := job.Advance(context.Background(), w.org)
		var oe *app.OffboardingError
		if !errors.As(err, &oe) || oe.Code != offboarding.ErrorObjectRetained {
			t.Fatalf("Advance with a retained version: %v", err)
		}
	}
	if n := len(w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)); n != 1 {
		t.Fatalf("%d failure events after 3 retained rounds, want 1", n)
	}
	w.escrow.err = errors.New("connection refused")
	if _, err := job.Advance(context.Background(), w.org); err == nil {
		t.Fatal("Advance succeeded with the store down")
	}
	failed := w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)
	if len(failed) != 2 || failed[1].Params["error_code"] != offboarding.ErrorObjectStoreUnavailable {
		t.Fatalf("failure events %+v, want a second one with object_store_unavailable", failed)
	}
	w.escrow.err = nil
	delete(w.escrow.retain, header)
	w.advanceTo(t, job, offboarding.StepValkey)
	completed := w.stepEvents(t, audit.CodeOrganizationDeletionStepCompleted)
	last := completed[len(completed)-1]
	if last.Params["step"] != offboarding.StepObjects || last.Params["count"] != float64(4) {
		t.Fatalf("objects completed with %v, want count 4 over all attempts", last.Params)
	}
}

// TestOffboardingTombstone (plan M17 amendment j addendum points 4 and 5): while an organization transaction that was
// open when the wait set was taken still runs, the tombstone waits and, after more than an hour, records
// finalize_waiting once; a row a straggler wrote after the delete loop sends the deletion back to the database step
// (40001); then the tombstone is written and organization.deleted recorded once.
func TestOffboardingTombstone(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepTombstone)
	// The step devices took the wait set already (PDK-1016); the straggler below starts after it and bypasses the gate,
	// so the test starts the tombstone's wait afresh to exercise it alone.
	w.exec(t, `UPDATE organization SET deleting_committed_at = NULL, offboarding_wait_vxids = NULL, offboarding_wait_taken_at = NULL
		WHERE id = $1`, w.org)

	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	straggler, err := pgx.Connect(ctx, env.API)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = straggler.Close(ctx) })
	tx, err := straggler.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", w.org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := job.Advance(ctx, w.org); !errors.Is(err, app.ErrOffboardingWaiting) {
		t.Fatalf("first tombstone round: %v, want waiting", err)
	}
	w.passCutoff(t)
	for range 3 {
		if _, err := job.Advance(ctx, w.org); !errors.Is(err, app.ErrOffboardingWaiting) {
			t.Fatalf("tombstone with an open transaction: %v, want waiting", err)
		}
	}
	if n := len(w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)); n != 0 {
		t.Fatalf("%d failure events within the hour", n)
	}
	var taken time.Time
	if err := w.super.QueryRow(ctx, "SELECT offboarding_wait_taken_at FROM organization WHERE id = $1", w.org).Scan(&taken); err != nil {
		t.Fatal(err)
	}
	w.clockMu.Lock()
	w.clock = taken.Add(app.FinalizeWaitAlert + time.Minute)
	w.clockMu.Unlock()
	for range 3 {
		if _, err := job.Advance(ctx, w.org); !errors.Is(err, app.ErrOffboardingWaiting) {
			t.Fatalf("tombstone after an hour: %v, want waiting", err)
		}
	}
	failed := w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)
	if len(failed) != 1 || failed[0].Params["error_code"] != offboarding.ErrorFinalizeWaiting || failed[0].Params["step"] != offboarding.StepTombstone {
		t.Fatalf("failure events %+v, want one finalize_waiting", failed)
	}

	// The straggler writes a row of the organization after the delete loop and ends.
	if _, err := tx.Exec(ctx, "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'late')",
		uuid.Must(uuid.NewV7()), w.org); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if done, err := job.Advance(ctx, w.org); done || err != nil {
		t.Fatalf("finalize with a late row: %v, %v", done, err)
	}
	if _, step, code := w.state(t); step != offboarding.StepDatabase || code != "" {
		t.Fatalf("after 40001: at %s with %q, want database", step, code)
	}
	w.advanceTo(t, job, "")
	if status, _, _ := w.state(t); status != organization.StatusDeleted {
		t.Fatalf("status %s", status)
	}
	if n := w.count(t, "SELECT count(*) FROM device_group WHERE organization_id = $1", w.org); n != 0 {
		t.Fatalf("%d late rows survive the tombstone", n)
	}
	if n := len(w.stepEvents(t, audit.CodeOrganizationDeleted)); n != 1 {
		t.Fatalf("organization.deleted recorded %d times", n)
	}
}

// TestOffboardingDefinerFunctions (amendment c point 2, decision 14): the outbox check and the token revocation refuse an
// organization that is not deleting, and count or revoke only the context organization's rows.
func TestOffboardingDefinerFunctions(t *testing.T) {
	w := newOffboardWorld(t)
	call := func(org uuid.UUID) (pending, revoked int64, err error) {
		err = w.worker.InOrgOffboarding(offboardingTestContext(org), func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			if pending, err = q.OffboardOutboxPending(ctx); err != nil {
				return err
			}
			revoked, err = q.OffboardRevokeAPITokens(ctx)
			return err
		})
		return pending, revoked, err
	}
	if _, _, err := call(w.org); err == nil || !strings.Contains(err.Error(), "42501") {
		t.Fatalf("an active organization: %v, want insufficient_privilege", err)
	}
	for range 2 {
		w.exec(t, `INSERT INTO outbox (organization_id, subject, msg_id, payload) VALUES ($1, 'audit.event', $2, '{}')`,
			w.other, uuid.NewString())
	}
	w.exec(t, `INSERT INTO api_token (id, organization_id, name, role, secret_sha256, prefix, created_by, expires_at)
		VALUES ($1, $2, 'other', 'org_admin', $3, 'pdk_ijklmnop', (SELECT id FROM admin_account WHERE organization_id = $2 LIMIT 1),
		now() + interval '1 day')`, uuid.Must(uuid.NewV7()), w.other, []byte(uuid.NewString()))
	w.publishOutbox(t)
	for _, org := range []uuid.UUID{w.org, w.other} {
		w.exec(t, "UPDATE organization SET status = 'deleting' WHERE id = $1", org)
		t.Cleanup(func() { w.exec(t, "UPDATE organization SET status = 'active' WHERE id = $1", org) })
	}
	pending, revoked, err := call(w.org)
	if err != nil || pending != 0 || revoked != 1 {
		t.Fatalf("own organization: pending %d, revoked %d, %v; want 0 and 1", pending, revoked, err)
	}
	if n := w.count(t, "SELECT count(*) FROM api_token WHERE organization_id = $1 AND revoked_at IS NULL", w.other); n != 1 {
		t.Fatalf("the other organization has %d live tokens, want 1", n)
	}
	want := int64(w.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1 AND published_at IS NULL", w.other))
	if pending, _, err := call(w.other); err != nil || pending != want || want < 2 {
		t.Fatalf("other organization: pending %d (want %d), %v", pending, want, err)
	}
}

// offboardingTestContext is the system principal of org for InOrgOffboarding.
func offboardingTestContext(org uuid.UUID) context.Context {
	return principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, Display: "test", OrganizationID: org})
}

// TestOffboardingKeepsOffboardedDeviceKeys (amendment l point 3): the valkey step hands every device to the cache
// deletion, marking the devices with an offboarded_device record, whose identity, command and sequence keys stay.
func TestOffboardingKeepsOffboardedDeviceKeys(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	leaving, _ := w.newDevice(t, w.org, "retired")
	w.exec(t, `INSERT INTO device_identity_key (key_id, organization_id, device_id, public_key, key_protection, status)
		VALUES ($1, $2, $3, '\x00', 'file', 'active'), ($4, $2, $5, '\x00', 'file', 'active')`,
		"k-"+leaving.String(), w.org, leaving, "k-"+w.device.String(), w.device)
	w.exec(t, `INSERT INTO offboarded_device (device_id, organization_id, keys, command_envelopes)
		VALUES ($1, $2, '[]', '[]')`, leaving, w.org)
	t.Cleanup(func() { w.exec(t, "DELETE FROM offboarded_device WHERE device_id = $1", leaving) })
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepAuditFinal)
	got := map[uuid.UUID]devicecache.OffboardDevice{}
	for _, d := range w.cache.devices {
		got[d.ID] = d
	}
	if len(got) != 2 || !got[leaving].Offboarded || got[w.device].Offboarded ||
		!slices.Equal(got[leaving].KeyIDs, []string{"k-" + leaving.String()}) ||
		!slices.Equal(got[w.device].KeyIDs, []string{"k-" + w.device.String()}) {
		t.Fatalf("devices handed to the cache: %+v", w.cache.devices)
	}
}

// TestOffboardingFleetHostSharedWithinOrganization (PDK-1058, plan M17 amendment l point 1): two devices of the deleted
// organization on one Fleet host do not keep each other's host alive, whereas a device of another organization on a
// second shared host keeps that host.
func TestOffboardingFleetHostSharedWithinOrganization(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	reenrolled, _ := w.newDevice(t, w.org, "active")
	sharedOwn := "host-" + w.device.String()
	w.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)",
		reenrolled, w.org, sharedOwn)
	second, _ := w.newDevice(t, w.org, "active")
	foreign, _ := w.newDevice(t, w.other, "active")
	const sharedForeign = "shared-with-other-org"
	for _, r := range []struct{ device, org uuid.UUID }{{second, w.org}, {foreign, w.other}} {
		w.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)",
			r.device, r.org, sharedForeign)
	}
	w.fleet.hosts[sharedForeign] = true
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepObjects)

	if !slices.Equal(w.fleet.deleted, []string{sharedOwn}) || w.fleet.hosts[sharedOwn] {
		t.Fatalf("deleted hosts %v, want only %s", w.fleet.deleted, sharedOwn)
	}
	if !w.fleet.hosts[sharedForeign] || !w.fleet.hosts["host-"+w.otherDevice.String()] {
		t.Fatalf("a host another organization uses was deleted: %v", w.fleet.hosts)
	}
}

// TestFleetHostInUseOutsideHardware (PDK-1058 review 1): the hardware answer ignores the deleting organization's own
// devices without a reference, counts another organization's, and does not count one that already has a reference.
func TestFleetHostInUseOutsideHardware(t *testing.T) {
	w := newOffboardWorld(t)
	const host, hw = "hw-host", "0A1B2C3D-0000-4000-8000-000000000001"
	holder, _ := w.newDevice(t, w.org, "active")
	w.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)",
		holder, w.org, host)
	w.exec(t, "UPDATE device SET hardware_uuid = $2 WHERE id = $1", holder, hw)
	check := func(want string) {
		t.Helper()
		sys := principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem})
		if got, err := w.platform.FleetHostInUseOutside(sys, w.org, host); err != nil || got != want {
			t.Fatalf("FleetHostInUseOutside = %q, %v; want %q", got, err, want)
		}
	}
	withHardware := func(org uuid.UUID) uuid.UUID {
		id, _ := w.newDevice(t, org, "active")
		w.exec(t, "UPDATE device SET hardware_uuid = lower($2) WHERE id = $1", id, hw)
		return id
	}

	withHardware(w.org)
	check(db.FleetHostUnused)

	foreign := withHardware(w.other)
	check(db.FleetHostUsedByHardware)

	w.exec(t, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, 'foreign-host')",
		foreign, w.other)
	check(db.FleetHostUnused)
}

// TestOffboardingCountsEveryBatch (review 1 minor 2): the database step stores its count after every batch, so a
// worker that stops in the middle of the step (here: its context ends while a later batch waits) keeps the count of
// the rows already gone, and the completion event reports all of them.
func TestOffboardingCountsEveryBatch(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepDatabase)
	w.exec(t, `INSERT INTO api_token (id, organization_id, name, role, secret_sha256, prefix, created_by, expires_at)
		SELECT gen_random_uuid(), $1::uuid, 'bulk-' || i, 'org_admin', sha256(convert_to($1::text || i, 'UTF8')), 'pdk_' || lpad(i::text, 8, '0'), $2,
		  now() + interval '1 day'
		FROM generate_series(1, 1500) i`, w.org, w.account)
	slow, _ := w.newDevice(t, w.org, "retired")
	w.exec(t, "UPDATE device SET hostname = $2 WHERE id = $1", slow, "slow-"+slow.String())
	w.exec(t, `CREATE OR REPLACE FUNCTION offboarding_test_slow() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN PERFORM pg_sleep(3); RETURN OLD; END $$`)
	trigger := "offboarding_slow_" + strings.ReplaceAll(slow.String()[:8], "-", "")
	w.exec(t, fmt.Sprintf(`CREATE TRIGGER %s BEFORE DELETE ON device FOR EACH ROW WHEN (OLD.hostname = 'slow-%s')
		EXECUTE FUNCTION offboarding_test_slow()`, trigger, slow))
	t.Cleanup(func() { w.exec(t, "DROP TRIGGER IF EXISTS "+trigger+" ON device") })

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() {
		_, err := job.Advance(ctx, w.org)
		stopped <- err
	}()
	stored := func() int {
		return w.count(t, "SELECT coalesce((offboarding_counts ->> 'database')::int, 0) FROM organization WHERE id = $1", w.org)
	}
	deadline := time.Now().Add(30 * time.Second)
	for stored() < 1500 {
		if time.Now().After(deadline) {
			t.Fatalf("the step stored %d deleted rows while running, want at least 1500", stored())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-stopped; err == nil {
		t.Fatal("the stopped step reported success")
	}
	before := stored()
	if n := len(w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)); n != 0 {
		t.Fatalf("%d failure events for a stopped worker", n)
	}
	w.exec(t, "DROP TRIGGER "+trigger+" ON device")
	w.advanceTo(t, job, offboarding.StepTombstone)
	completed := w.stepEvents(t, audit.CodeOrganizationDeletionStepCompleted)
	last := completed[len(completed)-1]
	if last.Params["step"] != offboarding.StepDatabase || last.Params["count"].(float64) <= float64(before) || before < 1500 {
		t.Fatalf("database completed with %v after %d stored before the stop", last.Params, before)
	}
}

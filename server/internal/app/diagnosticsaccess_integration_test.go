package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// fakeEscrowReader unwraps the data keys it was given, records every request and refuses when told to.
type fakeEscrowReader struct {
	mu       sync.Mutex
	deks     map[uuid.UUID][]byte
	requests []app.EscrowDecryptRequest
	refuse   bool
	// during runs once inside the next decryption, outside the lock: a step that races the download.
	during func()
}

func (f *fakeEscrowReader) Decrypt(_ context.Context, req app.EscrowDecryptRequest) (map[uuid.UUID][]byte, error) {
	f.mu.Lock()
	during := f.during
	f.during = nil
	f.mu.Unlock()
	if during != nil {
		during()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	if f.refuse {
		return nil, app.ErrEscrowRefused
	}
	out := map[uuid.UUID][]byte{}
	for _, id := range req.EscrowIDs {
		out[id] = bytes.Clone(f.deks[id])
	}
	return out, nil
}

func (f *fakeEscrowReader) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

type diagnosticsAccessWorld struct {
	diagnosticsWorld
	access *app.Diagnostics // api with download and purge
	reader *fakeEscrowReader
}

func newDiagnosticsAccessWorld(t *testing.T) diagnosticsAccessWorld {
	t.Helper()
	w := diagnosticsAccessWorld{diagnosticsWorld: newDiagnosticsWorld(t), reader: &fakeEscrowReader{deks: map[uuid.UUID][]byte{}}}
	w.access = app.NewDiagnostics(w.runner, w.api, nil, time.Second).
		WithDownload(app.NewEscrowAccess(w.reader, stepUpTokens{}), w.bundles)
	return w
}

// steppedUp is a caller of role with a fresh step-up whose ID token the api keeps for the escrow-reader.
func (w diagnosticsAccessWorld) steppedUp(org uuid.UUID, role principal.Role) context.Context {
	p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice", Role: role,
		OrganizationID: org, IP: "192.0.2.1", StepUpAt: time.Now(), StepUpJTI: uuid.NewString(), Subject: uuid.NewString()}
	return httpx.WithRequestID(principal.With(context.Background(), p), uuid.NewString())
}

// stored requests a bundle of the world's device, seals archive into it as the agent does, and lets the worker verify
// it; it returns the bundle's ID and its object key.
func (w diagnosticsAccessWorld) stored(t *testing.T, archive []byte, keyVersion int) (uuid.UUID, string) {
	t.Helper()
	row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{7}, 32)
	sealed, nonce, err := escrow.SealObject(dek, row.ID.String(), bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	w.reader.mu.Lock()
	w.reader.deks[row.ID] = dek
	w.reader.mu.Unlock()
	sum := sha256.Sum256(sealed)
	key := escrow.DiagnosticsObjectKey(w.org.String(), w.device.String(), row.ID.String())
	if counted, err := w.worker.Announce(systemCtx(w.org), ingest.DiagnosticsAnnounced{DiagnosticsID: row.ID, DeviceID: w.device,
		OrganizationID: w.org, ObjectKey: key, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(sealed)), Nonce: nonce,
		WrappedDEK: []byte{1, 2, 3}, KeyVersion: keyVersion, ReceivedAt: time.Now()}); err != nil || !counted {
		t.Fatalf("announce: %v %v", counted, err)
	}
	w.bundles.mu.Lock()
	w.bundles.objects[key] = sealed
	w.bundles.mu.Unlock()
	w.result(t, row.ID, "succeeded", uploaded)
	w.backdate(t, row.ID, time.Minute)
	if err := w.worker.Verify(systemCtx(w.org)); err != nil {
		t.Fatal(err)
	}
	if state, _ := w.state(t, row.ID); state != app.DiagnosticsStored {
		t.Fatalf("bundle %s", state)
	}
	return row.ID, key
}

// bundleEvent returns the params and outcome of the newest event of code for the bundle id.
func (w diagnosticsAccessWorld) bundleEvent(t *testing.T, code string, id uuid.UUID) (map[string]any, string) {
	t.Helper()
	var raw []byte
	var outcome string
	if err := w.super.QueryRow(context.Background(), `SELECT payload -> 'params', payload ->> 'outcome' FROM outbox
		WHERE payload ->> 'code' = $1 AND payload -> 'params' ->> 'request_id' = $2 ORDER BY id DESC LIMIT 1`, code, id.String()).
		Scan(&raw, &outcome); err != nil {
		t.Fatalf("%s: %v", code, err)
	}
	var params map[string]any
	_ = json.Unmarshal(raw, &params)
	return params, outcome
}

func (w diagnosticsAccessWorld) downloads(t *testing.T, id uuid.UUID) int {
	return w.count(t, "SELECT download_count FROM device_diagnostics WHERE id = $1", id)
}

// TestDiagnosticsKeyVersion (PDK-779): the escrow-wrap version the device announced is stored with the bundle; an
// agent that does not report it (before PDK-749) leaves it empty.
func TestDiagnosticsKeyVersion(t *testing.T) {
	w := newDiagnosticsAccessWorld(t)
	reported, _ := w.stored(t, []byte("archive"), 3)
	older, _ := w.stored(t, []byte("archive"), 0)
	var v3, none *int
	if err := w.super.QueryRow(context.Background(), "SELECT (SELECT key_version FROM device_diagnostics WHERE id = $1), "+
		"(SELECT key_version FROM device_diagnostics WHERE id = $2)", reported, older).Scan(&v3, &none); err != nil {
		t.Fatal(err)
	}
	if v3 == nil || *v3 != 3 || none != nil {
		t.Fatalf("key versions %v %v", v3, none)
	}
}

// TestDiagnosticsDownload (plan M12 decision 4, ADR 0048 decision 4): an operator or administrator with a fresh step-up
// gets the decrypted archive, unwrapped by the escrow-reader for purpose diagnostics; the download is recorded with
// the hash, size and file count and counted. An auditor is denied, a caller without step-up (as an API token always
// is) gets step_up_required, a bundle of another organization is not found, one that is not stored is invalid_state.
func TestDiagnosticsDownload(t *testing.T) {
	w := newDiagnosticsAccessWorld(t)
	archive := []byte("\x1f\x8b fixture tar.gz")
	id, _ := w.stored(t, archive, 3)

	if _, err := w.access.Download(w.steppedUp(w.org, principal.RoleOrgAuditor), id); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor: %v", err)
	}
	if _, outcome := w.bundleEvent(t, "device.diagnostics_downloaded", id); outcome != "denied" {
		t.Fatalf("auditor's attempt recorded as %s", outcome)
	}
	if _, err := w.access.Download(w.operator(), id); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("without step-up: %v", err)
	}
	token := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "ci", Role: principal.RoleOrgAdmin,
		OrganizationID: w.org, APITokenID: uuid.Must(uuid.NewV7()), APITokenName: "ci"}
	if _, err := w.access.Download(httpx.WithRequestID(principal.With(context.Background(), token), uuid.NewString()), id); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("API token: %v", err)
	}
	if w.reader.calls() != 0 || w.downloads(t, id) != 0 {
		t.Fatal("a refused caller reached the escrow-reader or was counted")
	}

	for i, role := range []principal.Role{principal.RoleOrgOperator, principal.RoleOrgAdmin} {
		b, err := w.access.Download(w.steppedUp(w.org, role), id)
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		got, _ := io.ReadAll(b.Reader)
		if !bytes.Equal(got, archive) || b.Size != int64(len(archive)) ||
			b.Name != "paddock-diagnostics-"+w.hostname+"-"+id.String()+".tar.gz" {
			t.Fatalf("%s: %q %d %s", role, got, b.Size, b.Name)
		}
		if n := w.downloads(t, id); n != i+1 {
			t.Fatalf("download_count %d after %d downloads", n, i+1)
		}
	}
	req := w.reader.requests[0]
	if req.Purpose != app.PurposeDiagnostics || req.DeviceID != w.device || req.OrganizationID != w.org ||
		len(req.EscrowIDs) != 1 || req.EscrowIDs[0] != id || req.StepUpIDToken != "id-token" {
		t.Fatalf("escrow-reader request %+v", req)
	}
	var sum string
	var size int64
	if err := w.super.QueryRow(context.Background(), "SELECT sha256, size FROM device_diagnostics WHERE id = $1", id).Scan(&sum, &size); err != nil {
		t.Fatal(err)
	}
	ev, outcome := w.bundleEvent(t, "device.diagnostics_downloaded", id)
	if outcome != "success" || ev["sha256"] != sum || ev["bytes"] != float64(size) || ev["files"] != float64(41) || ev["hostname"] != w.hostname {
		t.Fatalf("event %s %v", outcome, ev)
	}
	if strings.Contains(string(mustJSON(t, ev)), "fixture") {
		t.Fatal("the archive's content reached the audit event")
	}

	w.reader.mu.Lock()
	w.reader.refuse = true
	w.reader.mu.Unlock()
	if _, err := w.access.Download(w.steppedUp(w.org, principal.RoleOrgOperator), id); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("escrow-reader refused: %v", err)
	}
	if n := w.downloads(t, id); n != 2 {
		t.Fatalf("a refused download was counted: %d", n)
	}

	otherOrg := newHarness(t).org
	if _, err := w.access.Download(w.steppedUp(otherOrg, principal.RoleOrgAdmin), id); !errors.Is(err, problem.NotFound) {
		t.Fatalf("administrator of another organization: %v", err)
	}
	pending, err := w.diagnostics.Request(w.operator(), w.device, "second look")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.access.Download(w.steppedUp(w.org, principal.RoleOrgAdmin), pending.ID); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("requested bundle: %v", err)
	}
	if _, outcome := w.bundleEvent(t, "device.diagnostics_downloaded", pending.ID); outcome != "failure" {
		t.Fatalf("download of a requested bundle recorded as %s", outcome)
	}
}

// TestDiagnosticsDownloadReverifies (PDK-747 review finding 5): the device can overwrite its object with a blob of the
// same size while its presigned PUT is valid after the worker stored the bundle; the download reads the whole object
// first and refuses one whose SHA-256 (or size, or presence) does not match — nothing is decrypted or served, the
// download is recorded as a failure and not counted.
func TestDiagnosticsDownloadReverifies(t *testing.T) {
	w := newDiagnosticsAccessWorld(t)
	for name, replace := range map[string]func(objects map[string][]byte, key string){
		"same size, other content": func(objects map[string][]byte, key string) {
			objects[key] = bytes.Repeat([]byte{0x42}, len(objects[key]))
		},
		"other size": func(objects map[string][]byte, key string) { objects[key] = append(objects[key], 0) },
		"gone":       func(objects map[string][]byte, key string) { delete(objects, key) },
	} {
		t.Run(name, func(t *testing.T) {
			id, key := w.stored(t, []byte("fixture archive"), 1)
			w.bundles.mu.Lock()
			replace(w.bundles.objects, key)
			w.bundles.mu.Unlock()
			calls := w.reader.calls()
			b, err := w.access.Download(w.steppedUp(w.org, principal.RoleOrgAdmin), id)
			if !errors.Is(err, problem.InvalidState) || b.Reader != nil {
				t.Fatalf("download of a replaced object: %v", err)
			}
			if w.reader.calls() != calls {
				t.Fatal("the key of a replaced object was unwrapped")
			}
			if _, outcome := w.bundleEvent(t, "device.diagnostics_downloaded", id); outcome != "failure" {
				t.Fatalf("recorded as %s", outcome)
			}
			if n := w.downloads(t, id); n != 0 {
				t.Fatalf("download_count %d", n)
			}
			// The purge clears the bundle, so the next subtest's request is not refused as pending.
			if _, err := w.access.Purge(w.as(w.org, principal.RoleOrgAdmin, false), id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestDiagnosticsDownloadHoldsBundle (PDK-749 review): a download holds its bundle while the escrow-reader unwraps the
// key, so a purge or the retention round that would end the bundle meanwhile waits for it instead of turning the
// download into a refusal; the download is served and the bundle can be purged afterwards.
func TestDiagnosticsDownloadHoldsBundle(t *testing.T) {
	w := newDiagnosticsAccessWorld(t)
	id, _ := w.stored(t, []byte("fixture archive"), 1)
	var raced error
	w.reader.mu.Lock()
	w.reader.during = func() {
		ctx := context.Background()
		tx, err := w.super.Begin(ctx)
		if err != nil {
			raced = err
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '200ms'"); err != nil {
			raced = err
			return
		}
		_, raced = tx.Exec(ctx, "UPDATE device_diagnostics SET state = 'expired', wrapped_dek = NULL WHERE id = $1", id)
	}
	w.reader.mu.Unlock()

	b, err := w.access.Download(w.steppedUp(w.org, principal.RoleOrgAdmin), id)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if got, _ := io.ReadAll(b.Reader); string(got) != "fixture archive" {
		t.Fatalf("served %q", got)
	}
	var pgErr *pgconn.PgError
	if !errors.As(raced, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("ending the bundle during the download: %v, want lock_not_available", raced)
	}
	if _, err := w.access.Purge(w.as(w.org, principal.RoleOrgAdmin, false), id); err != nil {
		t.Fatalf("purge after the download: %v", err)
	}
}

// TestDiagnosticsPurge (ADR 0048 decision 5): an organization administrator deletes every version of the object by its
// derived key and the key material at once, the metadata stays and the bundle is purged; downloads and a second purge
// are then invalid_state. An operator is denied; a failed deletion leaves the bundle stored, and a deletion that broke
// off after removing the object is completed by purging again.
func TestDiagnosticsPurge(t *testing.T) {
	w := newDiagnosticsAccessWorld(t)
	id, key := w.stored(t, []byte("fixture archive"), 1)
	admin := w.as(w.org, principal.RoleOrgAdmin, false)

	if _, err := w.access.Purge(w.operator(), id); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator: %v", err)
	}
	if _, outcome := w.bundleEvent(t, "device.diagnostics_purged", id); outcome != "denied" {
		t.Fatalf("operator's attempt recorded as %s", outcome)
	}
	if _, err := w.access.Purge(w.as(newHarness(t).org, principal.RoleOrgAdmin, false), id); !errors.Is(err, problem.NotFound) {
		t.Fatalf("administrator of another organization: %v", err)
	}

	w.bundles.mu.Lock()
	w.bundles.fail = errors.New("bucket down")
	w.bundles.mu.Unlock()
	if _, err := w.access.Purge(admin, id); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("failed deletion: %v", err)
	}
	if held, _ := w.keyMaterial(t, id); !held {
		t.Fatal("a failed purge cleared the key material")
	}
	if state, _ := w.state(t, id); state != app.DiagnosticsStored {
		t.Fatalf("a failed purge left %s", state)
	}
	w.bundles.mu.Lock()
	w.bundles.fail = nil
	w.bundles.failAfterDelete = errors.New("bucket gone mid-purge")
	w.bundles.mu.Unlock()
	if _, err := w.access.Purge(admin, id); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("partial deletion: %v", err)
	}
	if state, _ := w.state(t, id); state != app.DiagnosticsStored {
		t.Fatalf("a partial purge left %s", state)
	}
	if _, err := w.access.Download(w.steppedUp(w.org, principal.RoleOrgAdmin), id); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("download after a partial purge: %v", err)
	}

	row, err := w.access.Purge(admin, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != app.DiagnosticsPurged || row.PurgedAt == nil || row.Sha256 == nil || row.Hostname != w.hostname ||
		row.ExpiresAt == nil || !row.ExpiresAt.Equal(row.PurgedAt.Add(app.DiagnosticsUploadWindow)) {
		t.Fatalf("purged row %+v", row)
	}
	if held, _ := w.keyMaterial(t, id); held {
		t.Fatal("the key material survived the purge")
	}
	w.bundles.mu.Lock()
	_, present := w.bundles.objects[key]
	deleted := w.bundles.deleted[len(w.bundles.deleted)-1]
	w.bundles.mu.Unlock()
	if present || deleted != key {
		t.Fatalf("object present %v, deleted %s", present, deleted)
	}
	ev, outcome := w.bundleEvent(t, "device.diagnostics_purged", id)
	if outcome != "success" || ev["hostname"] != w.hostname {
		t.Fatalf("event %s %v", outcome, ev)
	}
	if _, err := w.access.Download(w.steppedUp(w.org, principal.RoleOrgAdmin), id); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("download after the purge: %v", err)
	}
	if _, err := w.access.Purge(admin, id); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("second purge: %v", err)
	}

	// Review 2 L4: a PUT with a presigned URL issued before the purge lands after it; the retention round deletes it
	// once the upload window has ended and the purged bundle is no longer due.
	w.put(id, []byte("late upload"))
	if _, err := w.retention.PurgeDiagnostics(systemCtx(w.org), *row.PurgedAt); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.bundles.objects[key]; !ok {
		t.Fatal("late upload deleted within the upload window")
	}
	after := row.PurgedAt.Add(app.DiagnosticsUploadWindow + time.Minute)
	if n, err := w.retention.PurgeDiagnostics(systemCtx(w.org), after); err != nil || n != 1 {
		t.Fatalf("retention round after the purge: %d %v", n, err)
	}
	if _, ok := w.bundles.objects[key]; ok {
		t.Fatal("late upload after the purge kept")
	}
	if state, _ := w.state(t, id); state != app.DiagnosticsPurged {
		t.Fatalf("retention round left %s", state)
	}
	if _, expires := w.keyMaterial(t, id); expires != nil {
		t.Fatalf("expires_at %v after the deletion", expires)
	}
	if n, err := w.retention.PurgeDiagnostics(systemCtx(w.org), after); err != nil || n != 0 {
		t.Fatalf("second retention round: %d %v", n, err)
	}
}

// TestDiagnosticsLists (plan M12 decision 13): operators and administrators list the bundles of a device and of the
// organization, filtered by state and searched by hostname or requester, and read one; the auditor role is refused
// everywhere, another organization's device and bundle are not found and its bundles never listed.
func TestDiagnosticsLists(t *testing.T) {
	w := newDiagnosticsAccessWorld(t)
	stored, _ := w.stored(t, []byte("fixture archive"), 1)
	// requested_at has whole seconds; the stored bundle is the older one.
	w.exec(t, "UPDATE device_diagnostics SET requested_at = requested_at - interval '1 minute' WHERE id = $1", stored)
	pending, err := w.diagnostics.Request(w.operator(), w.device, "second look")
	if err != nil {
		t.Fatal(err)
	}
	page := app.ListPage{Sort: "-requested_at", Limit: 25}
	auditor := w.as(w.org, principal.RoleOrgAuditor, true)
	if _, err := w.access.List(auditor, w.device, app.DiagnosticsQuery{Page: page}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor list: %v", err)
	}
	if _, err := w.access.ListAll(auditor, app.DiagnosticsQuery{Page: page}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor list all: %v", err)
	}
	if _, err := w.access.Get(auditor, stored); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor get: %v", err)
	}

	res, err := w.access.List(w.operator(), w.device, app.DiagnosticsQuery{Page: page})
	if err != nil || res.Count != 2 || len(res.Items) != 2 || res.Items[0].ID != pending.ID || res.Items[1].ID != stored ||
		res.Items[1].Hostname != w.hostname {
		t.Fatalf("device list %+v %v", res, err)
	}
	res, err = w.access.List(w.operator(), w.device, app.DiagnosticsQuery{Page: page, States: []string{app.DiagnosticsStored}})
	if err != nil || res.Count != 1 || res.Items[0].ID != stored {
		t.Fatalf("stored filter %+v %v", res, err)
	}
	host := w.hostname[3:]
	res, err = w.access.ListAll(w.as(w.org, principal.RoleOrgAdmin, false), app.DiagnosticsQuery{
		Page: app.ListPage{Sort: "hostname", Limit: 25, QPattern: &[]string{"%" + host + "%"}[0]}})
	if err != nil || res.Count != 2 {
		t.Fatalf("search by hostname %+v %v", res, err)
	}
	nobody := "%nobody-matches%"
	if res, err := w.access.ListAll(w.operator(), app.DiagnosticsQuery{Page: app.ListPage{Sort: "state", Limit: 25, QPattern: &nobody}}); err != nil || res.Count != 0 {
		t.Fatalf("search without match %+v %v", res, err)
	}
	if b, err := w.access.Get(w.operator(), stored); err != nil || b.ID != stored || b.State != app.DiagnosticsStored {
		t.Fatalf("get %+v %v", b, err)
	}

	other := w.as(newHarness(t).org, principal.RoleOrgAdmin, false)
	if _, err := w.access.Get(other, stored); !errors.Is(err, problem.NotFound) {
		t.Fatalf("get from another organization: %v", err)
	}
	if _, err := w.access.List(other, w.device, app.DiagnosticsQuery{Page: page}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("list another organization's device: %v", err)
	}
	if res, err := w.access.ListAll(other, app.DiagnosticsQuery{Page: page}); err != nil || res.Count != 0 {
		t.Fatalf("another organization lists %+v %v", res, err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

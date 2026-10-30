package auditwriter_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// edSigner signs like OpenBao Transit with an ed25519 key of one version.
type edSigner struct {
	priv    ed25519.PrivateKey
	version int
}

func (s edSigner) Sign(_ context.Context, _ string, message []byte) (bao.Signature, error) {
	return bao.Signature{
		Value:      fmt.Sprintf("vault:v%d:%s", s.version, base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, message))),
		KeyVersion: s.version,
	}, nil
}

type exportEnv struct {
	pool     *db.AuditWriterPool
	super    *pgx.Conn
	store    *memStore
	writer   *auditwriter.Writer
	sealer   *auditwriter.Sealer
	exporter *auditwriter.Exporter
	keys     map[int][]byte
}

func newExportEnv(t *testing.T) exportEnv {
	t.Helper()
	ctx := context.Background()
	env := pgtest.SharedAudit(t)
	pool, err := db.NewAuditWriterPool(ctx, env.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super := superConn(t)
	t.Cleanup(func() { _ = super.Close(ctx) })
	// The audit database is shared and every test draws fresh keys for versions 1 and 2, so a key published by an
	// earlier test would read as a mismatch.
	if _, err := super.Exec(ctx, "DELETE FROM audit_signing_key WHERE key_version IN (1, 2)"); err != nil {
		t.Fatal(err)
	}
	store := &memStore{objects: map[string][]byte{}}
	writer, err := auditwriter.NewWriter(pool, store, 400)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[int][]byte{1: old, 2: pub}
	signer := edSigner{priv: priv, version: 2}
	keyFn := func(context.Context) (map[int][]byte, error) { return keys, nil }
	verifier := auditwriter.NewVerifier(pool, store, keyFn)
	return exportEnv{
		pool: pool, super: super, store: store, writer: writer, keys: keys,
		sealer:   auditwriter.NewSealer(pool, writer, signer, auditwriter.NewKeyPublisher(keyFn)),
		exporter: auditwriter.NewExporter(pool, writer, store, signer, keyFn, verifier, "test-1.2.3", time.Second),
	}
}

// object stores one WORM object of org recorded at recorded with n events and indexes it (as the writer would).
func (e exportEnv) object(t *testing.T, org uuid.UUID, recorded time.Time, n int) string {
	t.Helper()
	events := make([]audit.Event, n)
	for i := range events {
		events[i] = event(org, recorded.Add(time.Duration(i)*time.Second), audit.CodeDeviceGroupCreated)
		events[i].RecordedAt = audit.Timestamp(recorded)
	}
	body, err := auditwriter.EncodeObject(events)
	if err != nil {
		t.Fatal(err)
	}
	key := auditwriter.ObjectKey(org, recorded.Truncate(time.Hour), events[0].EventID)
	if err := e.store.PutLocked(context.Background(), key, "application/zstd", body, time.Time{}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if _, err := e.super.Exec(context.Background(), "INSERT INTO audit_object (object_key, organization_id, day, event_count, sha256) VALUES ($1, $2, $3, $4, $5)",
		key, org, recorded.UTC().Truncate(24*time.Hour), n, sum[:]); err != nil {
		t.Fatal(err)
	}
	return key
}

func (e exportEnv) seal(t *testing.T, org uuid.UUID, through time.Time) {
	t.Helper()
	if _, err := e.sealer.SealOrganizationThrough(context.Background(), org, through); err != nil {
		t.Fatal(err)
	}
}

// running inserts an export of org in status running and returns it as the builder sees it after its claim.
func (e exportEnv) running(t *testing.T, org uuid.UUID, from, to time.Time, purpose string) auditstore.AuditExport {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(context.Background(), `INSERT INTO audit_export (id, organization_id, status, from_day, to_day,
		purpose, requested_by, correlation_id, started_at) VALUES ($1, $2, 'running', $3, $4, $5, $6, $7, now())`,
		id, org, from, to, purpose, `{"type":"admin","id":"a1","display":"bob@acme.test","step_up":true}`, "req-"+id.String()); err != nil {
		t.Fatal(err)
	}
	return e.export(t, id)
}

func (e exportEnv) export(t *testing.T, id uuid.UUID) auditstore.AuditExport {
	t.Helper()
	var x auditstore.AuditExport
	err := e.super.QueryRow(context.Background(), `SELECT id, organization_id, status, from_day, to_day, purpose,
		requested_by, requested_at, started_at, ready_at, expires_at, event_count, object_count, size, package_sha256,
		verify_ok, verify_problems, signature, key_version, error, correlation_id FROM audit_export WHERE id = $1`, id).Scan(
		&x.ID, &x.OrganizationID, &x.Status, &x.FromDay, &x.ToDay, &x.Purpose, &x.RequestedBy, &x.RequestedAt,
		&x.StartedAt, &x.ReadyAt, &x.ExpiresAt, &x.EventCount, &x.ObjectCount, &x.Size, &x.PackageSha256, &x.VerifyOk,
		&x.VerifyProblems, &x.Signature, &x.KeyVersion, &x.Error, &x.CorrelationID)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func (e exportEnv) chunks(t *testing.T, id uuid.UUID) []byte {
	t.Helper()
	rows, err := e.super.Query(context.Background(), "SELECT seq, data FROM audit_export_chunk WHERE export_id = $1 ORDER BY seq", id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []byte
	next := int32(0)
	for rows.Next() {
		var seq int32
		var data []byte
		if err := rows.Scan(&seq, &data); err != nil {
			t.Fatal(err)
		}
		if seq != next {
			t.Fatalf("chunk seq %d, want %d", seq, next)
		}
		next++
		out = append(out, data...)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

type exportEvent struct {
	outcome, errorCode string
	target             json.RawMessage
	params             map[string]any
}

// events returns the events of code in org whose params name the export.
func (e exportEnv) events(t *testing.T, org uuid.UUID, code audit.Code, exportID uuid.UUID) []exportEvent {
	t.Helper()
	rows, err := e.super.Query(context.Background(), `SELECT outcome, target, params, correlation_id FROM audit_event
		WHERE organization_id = $1 AND code = $2 AND params->>'export_id' = $3`, org, string(code), exportID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []exportEvent
	for rows.Next() {
		var ev exportEvent
		var params []byte
		var correlation string
		if err := rows.Scan(&ev.outcome, &ev.target, &params, &correlation); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(params, &ev.params); err != nil {
			t.Fatal(err)
		}
		ev.errorCode, _ = ev.params["error_code"].(string)
		ev.params["correlation_id"] = correlation
		out = append(out, ev)
	}
	return out
}

type member struct {
	name string
	body []byte
}

func untar(t *testing.T, pkg []byte) []member {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(pkg))
	var out []member
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, member{h.Name, body})
	}
}

func decompress(t *testing.T, body []byte) []byte {
	t.Helper()
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	plain, err := dec.DecodeAll(body, nil)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func pastDay(daysAgo int) time.Time {
	return time.Now().UTC().AddDate(0, 0, -daysAgo).Truncate(24 * time.Hour)
}

// TestExportBuildsPackage: a range of three sealed days (the middle one without objects) becomes a ready package
// whose members, bytes, counts and signature match plan M10 §6.5; another organization's objects stay out.
func TestExportBuildsPackage(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org, other := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	day1, day3 := pastDay(10), pastDay(8)
	k1 := e.object(t, org, day1.Add(8*time.Hour), 3)
	k2 := e.object(t, org, day1.Add(9*time.Hour), 2)
	k3 := e.object(t, org, day3.Add(23*time.Hour), 4)
	foreign := e.object(t, other, day1.Add(8*time.Hour), 5)
	e.seal(t, org, day3)
	e.seal(t, other, day3)
	run := uuid.Must(uuid.NewV7())
	for _, r := range []struct {
		id       uuid.UUID
		org      uuid.UUID
		from, to time.Time
	}{
		{run, org, day3, day3.AddDate(0, 0, 1)},
		{uuid.Must(uuid.NewV7()), org, day1.AddDate(0, 0, -5), day1.AddDate(0, 0, -1)},
		{uuid.Must(uuid.NewV7()), other, day1, day3},
	} {
		if _, err := e.super.Exec(ctx, `INSERT INTO audit_verification_run (id, organization_id, trigger, from_day, to_day,
			started_at, finished_at, days, objects, ok, problems, event_id) VALUES ($1, $2, 'nightly', $3, $4, now(), now(),
			2, 1, false, '["x: broken"]', $5)`, r.id, r.org, r.from, r.to, uuid.Must(uuid.NewV7())); err != nil {
			t.Fatal(err)
		}
	}
	purpose := "ISO 27001 audit\n# injected heading\twith tab"
	x := e.running(t, org, day1, day3, purpose)
	before := time.Now()
	if err := e.exporter.Build(ctx, x); err != nil {
		t.Fatal(err)
	}

	got := e.export(t, x.ID)
	if got.Status != "ready" || got.EventCount == nil || *got.EventCount != 9 || *got.ObjectCount != 3 ||
		got.VerifyOk == nil || !*got.VerifyOk || got.Signature == nil || *got.KeyVersion != 2 || got.Error != nil {
		t.Fatalf("export = %+v", got)
	}
	if got.ExpiresAt.Sub(*got.ReadyAt) != auditwriter.ExportTTL || got.ReadyAt.Before(before.Add(-time.Second)) {
		t.Fatalf("ready_at %v, expires_at %v", got.ReadyAt, got.ExpiresAt)
	}
	if string(got.VerifyProblems) != "[]" {
		t.Fatalf("verify_problems = %s", got.VerifyProblems)
	}
	pkg := e.chunks(t, x.ID)
	sum := sha256.Sum256(pkg)
	if int64(len(pkg)) != *got.Size || !bytes.Equal(sum[:], got.PackageSha256) {
		t.Fatalf("package of %d bytes, sha %x; row says %d, %x", len(pkg), sum, *got.Size, got.PackageSha256)
	}

	members := untar(t, pkg)
	var names []string
	for _, m := range members {
		names = append(names, m.name)
	}
	path := func(key string) string { p, _ := auditevidence.ObjectPath(org.String(), key); return p }
	first, second := k1, k2
	if second < first {
		first, second = second, first
	}
	want := []string{"README.md",
		"manifests/" + day1.Format(time.DateOnly) + ".json", "manifests/" + day1.AddDate(0, 0, 1).Format(time.DateOnly) + ".json",
		"manifests/" + day3.Format(time.DateOnly) + ".json",
		path(first), path(second), path(k3), "events.jsonl", "export.json", "export.sig"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("members\n%q\nwant\n%q", names, want)
	}
	byName := map[string][]byte{}
	for _, m := range members {
		byName[m.name] = m.body
	}
	var events []byte
	for _, key := range []string{first, second, k3} {
		stored, _ := e.store.Get(ctx, key)
		if !bytes.Equal(byName[path(key)], stored) {
			t.Fatalf("object %s differs from the store", key)
		}
		events = append(events, decompress(t, stored)...)
	}
	for d := day1; !d.After(day3); d = d.AddDate(0, 0, 1) {
		stored, _ := e.store.Get(ctx, auditwriter.ManifestKey(org, d))
		if !bytes.Equal(byName["manifests/"+d.Format(time.DateOnly)+".json"], stored) {
			t.Fatalf("manifest of %s differs from the store", d.Format(time.DateOnly))
		}
	}
	if !bytes.Equal(byName["events.jsonl"], events) {
		t.Fatal("events.jsonl is not the concatenation of the decoded objects")
	}
	if bytes.Contains(pkg, []byte(foreign)) || bytes.Contains(byName["events.jsonl"], []byte(other.String())) {
		t.Fatal("the package holds data of another organization")
	}

	raw := byName["export.json"]
	if canonical, err := canonicaljson.Transform(raw); err != nil || !bytes.Equal(canonical, raw) {
		t.Fatalf("export.json is not canonical: %v", err)
	}
	var sig auditevidence.Signature
	if err := json.Unmarshal(byName["export.sig"], &sig); err != nil {
		t.Fatal(err)
	}
	var doc auditevidence.Export
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	embedded := map[int][]byte{}
	for _, k := range doc.Keys {
		embedded[k.KeyVersion] = k.PublicKey
		if k.Fingerprint != auditevidence.Fingerprint(k.PublicKey) {
			t.Fatalf("key v%d fingerprint %s", k.KeyVersion, k.Fingerprint)
		}
	}
	digest := auditevidence.ExportDigest(raw)
	if len(embedded) != 2 || sig.KeyVersion != 2 || sig.Signature != *got.Signature ||
		!auditevidence.VerifySignature(embedded, sig.KeyVersion, sig.Signature, digest[:]) {
		t.Fatalf("export.sig %+v does not verify with the embedded keys", sig)
	}
	eventsSum := sha256.Sum256(events)
	if doc.Schema != auditwriter.ExportSchema || doc.ExportID != x.ID.String() || doc.OrganizationID != org.String() ||
		doc.FromDay != day1.Format(time.DateOnly) || doc.ToDay != day3.Format(time.DateOnly) || doc.Purpose != purpose ||
		doc.RequestedBy != (auditevidence.Actor{Type: "admin", ID: "a1", Display: "bob@acme.test"}) ||
		doc.Generator != "paddock-server test-1.2.3" || doc.EventCount != 9 || len(doc.Days) != 3 || len(doc.Objects) != 3 ||
		doc.EventsSHA256 != hex.EncodeToString(eventsSum[:]) || doc.ChainAnchor != nil || !doc.Verification.OK {
		t.Fatalf("export.json = %+v", doc)
	}
	readmeSum := sha256.Sum256(byName["README.md"])
	if doc.ReadmeSHA256 != hex.EncodeToString(readmeSum[:]) {
		t.Fatalf("readme_sha256 %s, README.md hashes to %x", doc.ReadmeSHA256, readmeSum)
	}
	if bytes.Contains(raw, []byte("organization_slug")) {
		t.Fatal("export.json carries an organization slug (plan M10 amendment 2026-10-30)")
	}
	if d := doc.Days[1]; d.ObjectCount != 0 || d.EventCount != 0 || doc.Days[0].EventCount != 5 || doc.Days[2].EventCount != 4 {
		t.Fatalf("days = %+v", doc.Days)
	}
	if len(doc.Verification.Runs) != 1 || doc.Verification.Runs[0].RunID != run.String() || doc.Verification.Runs[0].OK ||
		!reflect.DeepEqual(doc.Verification.Runs[0].Problems, []string{"x: broken"}) {
		t.Fatalf("runs = %+v", doc.Verification.Runs)
	}

	readme := string(byName["README.md"])
	for _, s := range []string{"Organization " + org.String() + ", recording days", "ISO 27001 audit # injected heading with tab",
		"version 2, SHA-256 fingerprint " + auditevidence.Fingerprint(e.keys[2]), "no problems.", "1 runs, 1 with problems",
		"chain anchor none"} {
		if !strings.Contains(readme, s) {
			t.Fatalf("README lacks %q:\n%s", s, readme)
		}
	}
	if strings.Contains(readme, "\n# injected") {
		t.Fatal("the purpose starts a Markdown block in the README")
	}

	evs := e.events(t, org, audit.CodeAuditExportCompleted, x.ID)
	if len(evs) != 1 || evs[0].outcome != "success" || evs[0].params["events"] != float64(9) ||
		evs[0].params["objects"] != float64(3) || evs[0].params["days"] != float64(3) || evs[0].params["verify_ok"] != true ||
		evs[0].params["package_sha256"] != hex.EncodeToString(sum[:]) || evs[0].params["size"] != float64(len(pkg)) ||
		evs[0].params["key_version"] != float64(2) || evs[0].params["correlation_id"] != x.CorrelationID ||
		!strings.Contains(string(evs[0].target), `"audit_export"`) {
		t.Fatalf("audit.export_completed = %+v", evs)
	}
	if n := len(e.events(t, other, audit.CodeAuditExportCompleted, x.ID)); n != 0 {
		t.Fatalf("%d events in the other organization", n)
	}

	// A range of one day without objects is a valid package; its anchor links to the day before.
	empty := e.running(t, org, day1.AddDate(0, 0, 1), day1.AddDate(0, 0, 1), "empty day")
	if err := e.exporter.Build(ctx, empty); err != nil {
		t.Fatal(err)
	}
	if got := e.export(t, empty.ID); got.Status != "ready" || *got.EventCount != 0 || *got.ObjectCount != 0 || !*got.VerifyOk {
		t.Fatalf("empty export = %+v", got)
	}
	members = untar(t, e.chunks(t, empty.ID))
	if len(members) != 5 || members[2].name != "events.jsonl" || len(members[2].body) != 0 {
		t.Fatalf("empty package members = %v", members)
	}
	var emptyDoc auditevidence.Export
	if err := json.Unmarshal(members[3].body, &emptyDoc); err != nil {
		t.Fatal(err)
	}
	if emptyDoc.ChainAnchor == nil || *emptyDoc.ChainAnchor != doc.Days[0].ManifestSHA256 {
		t.Fatalf("chain anchor %v, want %s", emptyDoc.ChainAnchor, doc.Days[0].ManifestSHA256)
	}
}

// TestExportModifiedObjectIsDelivered: an object changed in the store after the seal is still packed, verify_ok is
// false and the problem names it; the export is ready, not failed.
func TestExportModifiedObjectIsDelivered(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(6)
	key := e.object(t, org, d.Add(10*time.Hour), 2)
	e.seal(t, org, d)
	e.store.mu.Lock()
	tampered := append([]byte(nil), e.store.objects[key]...)
	tampered[len(tampered)-1] ^= 0xff
	e.store.objects[key] = tampered
	e.store.mu.Unlock()

	x := e.running(t, org, d, d, "tamper check")
	if err := e.exporter.Build(ctx, x); err != nil {
		t.Fatal(err)
	}
	got := e.export(t, x.ID)
	if got.Status != "ready" || got.VerifyOk == nil || *got.VerifyOk {
		t.Fatalf("export = %+v", got)
	}
	want := fmt.Sprintf("%s: object %s was modified (SHA-256 mismatch)", d.Format(time.DateOnly), key)
	var problems []string
	if err := json.Unmarshal(got.VerifyProblems, &problems); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(problems, "\n"), want); n != 1 {
		t.Fatalf("problems %q contain %q %d times, want once", problems, want, n)
	}
	members := untar(t, e.chunks(t, x.ID))
	path, _ := auditevidence.ObjectPath(org.String(), key)
	var doc auditevidence.Export
	for _, m := range members {
		switch m.name {
		case path:
			if !bytes.Equal(m.body, tampered) {
				t.Fatal("the package does not hold the stored (modified) bytes")
			}
		case "export.json":
			if err := json.Unmarshal(m.body, &doc); err != nil {
				t.Fatal(err)
			}
		case "README.md":
			if !strings.Contains(string(m.body), "- "+want) {
				t.Fatalf("README lacks the problem:\n%s", m.body)
			}
		}
	}
	if doc.Verification.OK || !reflect.DeepEqual(doc.Verification.Problems, problems) {
		t.Fatalf("verification = %+v", doc.Verification)
	}
	evs := e.events(t, org, audit.CodeAuditExportCompleted, x.ID)
	if len(evs) != 1 || evs[0].outcome != "success" || evs[0].params["verify_ok"] != false {
		t.Fatalf("audit.export_completed = %+v", evs)
	}
}

// TestExportMissingManifestFails: a day of the range without a manifest fails the build with the day named, leaves
// no chunks and records the failure.
func TestExportMissingManifestFails(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(4)
	e.object(t, org, d.Add(time.Hour), 1)
	e.seal(t, org, d)
	x := e.running(t, org, d, d.AddDate(0, 0, 1), "missing day")
	if err := e.exporter.Build(ctx, x); err == nil {
		t.Fatal("build succeeded")
	}
	got := e.export(t, x.ID)
	wantErr := fmt.Sprintf("day %s: no manifest", d.AddDate(0, 0, 1).Format(time.DateOnly))
	if got.Status != "failed" || got.Error == nil || *got.Error != wantErr || got.ReadyAt != nil {
		t.Fatalf("export = %+v", got)
	}
	if pkg := e.chunks(t, x.ID); len(pkg) != 0 {
		t.Fatalf("%d bytes of chunks left", len(pkg))
	}
	evs := e.events(t, org, audit.CodeAuditExportCompleted, x.ID)
	if len(evs) != 1 || evs[0].outcome != "failure" || evs[0].errorCode != "export_failed" || evs[0].params["error"] != wantErr {
		t.Fatalf("audit.export_completed = %+v", evs)
	}
}

// TestExportExpireAndStuck: a ready export past its expiry loses its chunks and becomes expired with
// retention.purged; a running export older than ExportStuckAfter becomes failed ("exporter restarted").
func TestExportExpireAndStuck(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(20)
	now := time.Now().UTC()
	insert := func(status string, started, expires *time.Time) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := e.super.Exec(ctx, `INSERT INTO audit_export (id, organization_id, status, from_day, to_day, purpose,
			requested_by, correlation_id, started_at, expires_at) VALUES ($1, $2, $3, $4, $4, 'x', '{"type":"admin"}', $5, $6, $7)`,
			id, org, status, d, "req-"+id.String(), started, expires); err != nil {
			t.Fatal(err)
		}
		if _, err := e.super.Exec(ctx, "INSERT INTO audit_export_chunk (export_id, organization_id, seq, data) VALUES ($1, $2, 0, 'abc')", id, org); err != nil {
			t.Fatal(err)
		}
		return id
	}
	past, recent := now.Add(-time.Minute), now.Add(time.Hour)
	stuckStart, freshStart := now.Add(-auditwriter.ExportStuckAfter-time.Minute), now.Add(-time.Hour)
	expired := insert("ready", &stuckStart, &past)
	kept := insert("ready", &freshStart, &recent)
	stuck := insert("running", &stuckStart, nil)
	busy := insert("running", &freshStart, nil)

	n, err := e.exporter.Expire(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expired %d", n)
	}
	for id, want := range map[uuid.UUID]string{expired: "expired", kept: "ready", stuck: "failed", busy: "running"} {
		got := e.export(t, id)
		if got.Status != want {
			t.Fatalf("export %s status %s, want %s", id, got.Status, want)
		}
		left := len(e.chunks(t, id))
		if (want == "expired" || want == "failed") != (left == 0) {
			t.Fatalf("export %s (%s) has %d chunk bytes", id, want, left)
		}
	}
	if got := e.export(t, stuck); got.Error == nil || *got.Error != "exporter restarted" {
		t.Fatalf("stuck export error %v", got.Error)
	}
	purged := e.events(t, org, audit.CodeRetentionPurged, expired)
	if len(purged) != 1 || purged[0].outcome != "success" || purged[0].params["store"] != "audit_exports" ||
		purged[0].params["deleted"] != float64(1) || purged[0].params["cutoff"] == nil {
		t.Fatalf("retention.purged = %+v", purged)
	}
	failed := e.events(t, org, audit.CodeAuditExportCompleted, stuck)
	if len(failed) != 1 || failed[0].outcome != "failure" || failed[0].params["error"] != "exporter restarted" {
		t.Fatalf("audit.export_completed of the stuck export = %+v", failed)
	}
	if n := len(e.events(t, org, audit.CodeRetentionPurged, kept)); n != 0 {
		t.Fatalf("%d retention.purged events for a valid export", n)
	}

	// A second round finds nothing new to expire.
	if _, err := e.exporter.Expire(ctx, now); err != nil {
		t.Fatal(err)
	}
	if n := len(e.events(t, org, audit.CodeRetentionPurged, expired)); n != 1 {
		t.Fatalf("%d retention.purged events after a second round", n)
	}
}

// TestExportExpireDeletesLeftoverChunks: chunks a dead builder left with a failed or expired export are deleted by
// the next expiry pass without another event; ready and running exports keep theirs.
func TestExportExpireDeletesLeftoverChunks(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(21)
	now := time.Now().UTC()
	later := now.Add(time.Hour)
	ids := map[string]uuid.UUID{}
	for _, status := range []string{"failed", "expired", "ready", "running"} {
		id := uuid.Must(uuid.NewV7())
		var expires *time.Time
		if status == "ready" {
			expires = &later
		}
		if _, err := e.super.Exec(ctx, `INSERT INTO audit_export (id, organization_id, status, from_day, to_day, purpose,
			requested_by, correlation_id, started_at, expires_at) VALUES ($1, $2, $3, $4, $4, 'x', '{"type":"admin"}', $5, $6, $7)`,
			id, org, status, d, "req-"+id.String(), now, expires); err != nil {
			t.Fatal(err)
		}
		if _, err := e.super.Exec(ctx, "INSERT INTO audit_export_chunk (export_id, organization_id, seq, data) VALUES ($1, $2, 0, 'abc')", id, org); err != nil {
			t.Fatal(err)
		}
		ids[status] = id
	}
	for range 2 {
		if _, err := e.exporter.Expire(ctx, now); err != nil {
			t.Fatal(err)
		}
	}
	for status, id := range ids {
		left := len(e.chunks(t, id))
		if (status == "failed" || status == "expired") != (left == 0) {
			t.Fatalf("%s export has %d chunk bytes", status, left)
		}
		if got := e.export(t, id); got.Status != status {
			t.Fatalf("%s export became %s", status, got.Status)
		}
		for _, code := range []audit.Code{audit.CodeAuditExportCompleted, audit.CodeRetentionPurged} {
			if n := len(e.events(t, org, code, id)); n != 0 {
				t.Fatalf("%d %s events for the %s export", n, code, status)
			}
		}
	}
}

// TestExportReadyDespiteLostCommit: when the transaction marking an export ready commits but the client gets an
// error (lost acknowledgement, shutdown), the build keeps the package and records its success once.
func TestExportReadyDespiteLostCommit(t *testing.T) {
	e := newExportEnv(t)
	for _, c := range []struct {
		name   string
		cancel bool
	}{{"lost acknowledgement", false}, {"shutdown during commit", true}} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			org := uuid.Must(uuid.NewV7())
			d := pastDay(6)
			e.object(t, org, d.Add(time.Hour), 2)
			e.seal(t, org, d)
			x := e.running(t, org, d, d, c.name)
			auditwriter.SetReadyCommitted(e.exporter, func(_ context.Context, _ uuid.UUID, err error) error {
				if err != nil {
					return err
				}
				if c.cancel {
					cancel()
				}
				return errors.New("connection reset")
			})
			defer auditwriter.SetReadyCommitted(e.exporter, nil)
			if err := e.exporter.Build(ctx, x); err != nil {
				t.Fatalf("build: %v", err)
			}
			got := e.export(t, x.ID)
			if got.Status != "ready" || got.Size == nil || *got.Size == 0 {
				t.Fatalf("export = %+v", got)
			}
			if n := int64(len(e.chunks(t, x.ID))); n != *got.Size {
				t.Fatalf("%d chunk bytes, size %d", n, *got.Size)
			}
			evs := e.events(t, org, audit.CodeAuditExportCompleted, x.ID)
			if len(evs) != 1 || evs[0].outcome != "success" {
				t.Fatalf("audit.export_completed = %+v", evs)
			}
		})
	}
}

// TestExportBuildOfAbandonedExportRecordsNothing: when the stuck check failed an export while it was being built,
// the builder does not mark it ready and leaves no chunks; the stuck check's failure stays the only outcome.
func TestExportBuildOfAbandonedExportRecordsNothing(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(3)
	e.object(t, org, d.Add(time.Hour), 1)
	e.seal(t, org, d)
	x := e.running(t, org, d, d, "abandoned")
	if _, err := e.super.Exec(ctx, "UPDATE audit_export SET status = 'failed', error = 'exporter restarted' WHERE id = $1", x.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.exporter.Build(ctx, x); err == nil {
		t.Fatal("build of a failed export succeeded")
	}
	if got := e.export(t, x.ID); got.Status != "failed" || *got.Error != "exporter restarted" {
		t.Fatalf("export = %+v", got)
	}
	if len(e.chunks(t, x.ID)) != 0 {
		t.Fatal("chunks left")
	}
	if n := len(e.events(t, org, audit.CodeAuditExportCompleted, x.ID)); n != 0 {
		t.Fatalf("%d audit.export_completed events", n)
	}
}

// TestExportBuildFailingAfterStuckCheckRecordsOnce: when the stuck check failed an export while its build was still
// running and the build then fails as well, the stuck check's failure stays the only completed event and the chunks
// the build wrote are gone.
func TestExportBuildFailingAfterStuckCheckRecordsOnce(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	for _, c := range []struct {
		name string
		// lastDay prepares the failure and returns the last day of the export's range.
		lastDay func(t *testing.T, d time.Time, key string) time.Time
	}{
		{"missing manifest", func(_ *testing.T, d time.Time, _ string) time.Time { return d.AddDate(0, 0, 1) }},
		{"unreadable object", func(_ *testing.T, d time.Time, key string) time.Time {
			e.store.mu.Lock()
			delete(e.store.objects, key)
			e.store.mu.Unlock()
			return d
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			org := uuid.Must(uuid.NewV7())
			d := pastDay(5)
			key := e.object(t, org, d.Add(time.Hour), 1)
			e.seal(t, org, d)
			x := e.running(t, org, d, c.lastDay(t, d, key), c.name)
			if _, err := e.exporter.Expire(ctx, time.Now().Add(auditwriter.ExportStuckAfter+time.Hour)); err != nil {
				t.Fatal(err)
			}
			if _, err := e.super.Exec(ctx, "INSERT INTO audit_export_chunk (export_id, organization_id, seq, data) VALUES ($1, $2, 0, 'abc')", x.ID, org); err != nil {
				t.Fatal(err)
			}
			if err := e.exporter.Build(ctx, x); err == nil {
				t.Fatal("build succeeded")
			}
			if got := e.export(t, x.ID); got.Status != "failed" || got.Error == nil || *got.Error != "exporter restarted" {
				t.Fatalf("export = %+v", got)
			}
			if n := len(e.chunks(t, x.ID)); n != 0 {
				t.Fatalf("%d bytes of chunks left", n)
			}
			evs := e.events(t, org, audit.CodeAuditExportCompleted, x.ID)
			if len(evs) != 1 || evs[0].outcome != "failure" || evs[0].params["error"] != "exporter restarted" {
				t.Fatalf("audit.export_completed = %+v", evs)
			}
		})
	}
}

// TestExportDoesNotDecodeUnsafeObjects: an object whose hash does not match its manifest is packed but not
// decompressed, and an object that decompresses beyond the size limit is reported as undecodable; both packages
// are delivered with verify_ok=false and without the object's events.
func TestExportDoesNotDecodeUnsafeObjects(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	for _, c := range []struct {
		name    string
		prepare func(t *testing.T, org uuid.UUID, d time.Time, key string)
		problem string
	}{
		{"replaced object", func(t *testing.T, org uuid.UUID, d time.Time, key string) {
			body, err := auditwriter.EncodeObject([]audit.Event{event(org, d.Add(time.Hour), audit.CodeDeviceGroupCreated)})
			if err != nil {
				t.Fatal(err)
			}
			e.store.mu.Lock()
			e.store.objects[key] = body
			e.store.mu.Unlock()
		}, "%s: object %s was modified (SHA-256 mismatch)"},
		{"oversized object", func(*testing.T, uuid.UUID, time.Time, string) {
			auditwriter.SetExportMaxDecoded(e.exporter, 1<<10)
		}, "%s: object %s cannot be decoded"},
	} {
		t.Run(c.name, func(t *testing.T) {
			org := uuid.Must(uuid.NewV7())
			d := pastDay(7)
			key := e.object(t, org, d.Add(time.Hour), 20)
			e.seal(t, org, d)
			c.prepare(t, org, d, key)
			stored, err := e.store.Get(ctx, key)
			if err != nil {
				t.Fatal(err)
			}

			x := e.running(t, org, d, d, c.name)
			if err := e.exporter.Build(ctx, x); err != nil {
				t.Fatal(err)
			}
			got := e.export(t, x.ID)
			if got.Status != "ready" || got.VerifyOk == nil || *got.VerifyOk || got.EventCount == nil || *got.EventCount != 0 {
				t.Fatalf("export = %+v", got)
			}
			var problems []string
			if err := json.Unmarshal(got.VerifyProblems, &problems); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf(c.problem, d.Format(time.DateOnly), key)
			if !slices.Contains(problems, want) {
				t.Fatalf("problems %q lack %q", problems, want)
			}
			path, _ := auditevidence.ObjectPath(org.String(), key)
			for _, m := range untar(t, e.chunks(t, x.ID)) {
				switch m.name {
				case path:
					if !bytes.Equal(m.body, stored) {
						t.Fatal("the package does not hold the stored bytes")
					}
				case "events.jsonl":
					if len(m.body) != 0 {
						t.Fatalf("events.jsonl holds %d bytes", len(m.body))
					}
				}
			}
		})
	}
}

// hangingStore blocks every Get until ctx ends and closes reached on the first one.
type hangingStore struct {
	auditwriter.ObjectStore
	once    sync.Once
	reached chan struct{}
}

func (s *hangingStore) Get(ctx context.Context, _ string) ([]byte, error) {
	s.once.Do(func() { close(s.reached) })
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestExportPendingAgeDuringHungBuild: while a build hangs, the pending-age gauge still follows an export that
// became pending after the build started, so PaddockAuditExportStuck can fire.
func TestExportPendingAgeDuringHungBuild(t *testing.T) {
	e := newExportEnv(t)
	org := uuid.Must(uuid.NewV7())
	d := pastDay(9)
	e.object(t, org, d.Add(time.Hour), 1)
	e.seal(t, org, d)
	t.Cleanup(func() {
		if _, err := e.super.Exec(context.Background(), `UPDATE audit_export SET status = 'failed', error = 'test cleanup'
			WHERE organization_id = $1 AND status IN ('pending', 'running')`, org); err != nil {
			t.Error(err)
		}
	})
	pending := func(age time.Duration) {
		id := uuid.Must(uuid.NewV7())
		if _, err := e.super.Exec(context.Background(), `INSERT INTO audit_export (id, organization_id, status, from_day,
			to_day, purpose, requested_by, correlation_id, requested_at) VALUES ($1, $2, 'pending', $3, $3, 'x',
			'{"type":"admin"}', $4, now() - make_interval(secs => $5))`, id, org, d, "req-"+id.String(), age.Seconds()); err != nil {
			t.Fatal(err)
		}
	}
	pending(0)
	store := &hangingStore{ObjectStore: e.store, reached: make(chan struct{})}
	keyFn := func(context.Context) (map[int][]byte, error) { return e.keys, nil }
	exporter := auditwriter.NewExporter(e.pool, e.writer, store, edSigner{}, keyFn, auditwriter.NewVerifier(e.pool, store, keyFn),
		"test", 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = exporter.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-store.reached:
	case <-time.After(30 * time.Second):
		t.Fatal("no build started")
	}

	pending(2 * time.Hour)
	deadline := time.Now().Add(10 * time.Second)
	for gaugeValue(t, "paddock_audit_export_pending_age_seconds") < 7000 {
		if time.Now().After(deadline) {
			t.Fatalf("pending age %v during the hung build", gaugeValue(t, "paddock_audit_export_pending_age_seconds"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestExportClaimSkipsLockedExports: an exporter claims the oldest pending export another exporter has locked
// without waiting for it, and two concurrent exporters claim different exports.
func TestExportClaimSkipsLockedExports(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	if _, err := e.super.Exec(ctx, "UPDATE audit_export SET status = 'failed', error = 'test cleanup' WHERE status = 'pending'"); err != nil {
		t.Fatal(err)
	}
	org := uuid.Must(uuid.NewV7())
	pending := func() uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := e.super.Exec(ctx, `INSERT INTO audit_export (id, organization_id, status, from_day, to_day, purpose,
			requested_by, correlation_id) VALUES ($1, $2, 'pending', $3, $3, 'x', '{"type":"admin"}', 'c')`, id, org, pastDay(2)); err != nil {
			t.Fatal(err)
		}
		return id
	}
	oldest, next := pending(), pending()

	holder := superConn(t)
	defer func() { _ = holder.Close(ctx) }()
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT id FROM audit_export WHERE id = $1 FOR UPDATE", oldest); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	claimed, ok, err := e.exporter.Claim(waitCtx)
	cancel()
	if err != nil || !ok || claimed.ID != next || claimed.Status != "running" || claimed.StartedAt == nil {
		t.Fatalf("claim with the oldest locked = %v %v %+v; want %s", ok, err, claimed, next)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	a, b := pending(), pending()
	other := auditwriter.NewExporter(e.pool, e.writer, e.store, nil, nil, nil, "x", time.Second)
	var wg sync.WaitGroup
	ids := make([]uuid.UUID, 3)
	for i, ex := range []*auditwriter.Exporter{e.exporter, other, e.exporter} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x, ok, err := ex.Claim(ctx)
			if err != nil {
				t.Error(err)
			}
			if ok {
				ids[i] = x.ID
			}
		}()
	}
	wg.Wait()
	seen := map[uuid.UUID]int{}
	for _, id := range ids {
		seen[id]++
	}
	if seen[oldest] != 1 || seen[a] != 1 || seen[b] != 1 {
		t.Fatalf("concurrent claims = %v; want %s, %s, %s once each", ids, oldest, a, b)
	}
	if _, ok, err := e.exporter.Claim(ctx); err != nil || ok {
		t.Fatalf("claim with nothing pending = %v, %v", ok, err)
	}
}

// TestExportChunkBoundary: a stream of exactly ExportChunkSize bytes is one row; one byte more starts a second row.
func TestExportChunkBoundary(t *testing.T) {
	for _, c := range []struct {
		size  int
		parts []int
		want  []int
	}{
		{auditwriter.ExportChunkSize, []int{auditwriter.ExportChunkSize}, []int{auditwriter.ExportChunkSize}},
		{auditwriter.ExportChunkSize, []int{auditwriter.ExportChunkSize - 1, 1}, []int{auditwriter.ExportChunkSize}},
		{auditwriter.ExportChunkSize, []int{auditwriter.ExportChunkSize, 1}, []int{auditwriter.ExportChunkSize, 1}},
		{auditwriter.ExportChunkSize, []int{3, 2*auditwriter.ExportChunkSize + 5}, []int{auditwriter.ExportChunkSize, auditwriter.ExportChunkSize, 8}},
		{auditwriter.ExportChunkSize, nil, nil},
	} {
		var rows []int
		var seqs []int32
		var all []byte
		cw := auditwriter.NewChunkWriter(c.size, func(seq int32, data []byte) error {
			rows, seqs = append(rows, len(data)), append(seqs, seq)
			all = append(all, data...)
			return nil
		})
		var in []byte
		for i, n := range c.parts {
			part := bytes.Repeat([]byte{byte('a' + i)}, n)
			in = append(in, part...)
			if w, err := cw.Write(part); err != nil || w != n {
				t.Fatalf("Write = %d, %v", w, err)
			}
		}
		if err := cw.Close(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rows, c.want) || !bytes.Equal(all, in) {
			t.Fatalf("parts %v: rows %v, want %v", c.parts, rows, c.want)
		}
		for i, s := range seqs {
			if int(s) != i {
				t.Fatalf("seqs %v", seqs)
			}
		}
	}
}

// TestManifestTypesAgree: the manifest types of pkg/auditevidence, which the offline verifier uses, have the JSON
// shape the sealer writes.
func TestManifestTypesAgree(t *testing.T) {
	for _, pair := range [][2]any{
		{auditwriter.Manifest{}, auditevidence.Manifest{}},
		{auditwriter.ManifestObject{}, auditevidence.ManifestObject{}},
		{auditwriter.ManifestFile{}, auditevidence.ManifestFile{}},
	} {
		a, b := reflect.TypeOf(pair[0]), reflect.TypeOf(pair[1])
		if a.NumField() != b.NumField() {
			t.Fatalf("%s has %d fields, %s %d", a, a.NumField(), b, b.NumField())
		}
		for i := 0; i < a.NumField(); i++ {
			fa, fb := a.Field(i), b.Field(i)
			if fa.Name != fb.Name || fa.Tag != fb.Tag || fa.Type.Kind() != fb.Type.Kind() {
				t.Fatalf("%s.%s %s %q differs from %s.%s %s %q", a, fa.Name, fa.Type, fa.Tag, b, fb.Name, fb.Type, fb.Tag)
			}
		}
	}
	if auditwriter.ManifestSchema != auditevidence.ManifestSchema || audit.Schema != auditevidence.EventSchema {
		t.Fatal("schema names differ")
	}
	org := uuid.Must(uuid.NewV7())
	prev := sha256.Sum256([]byte("prev"))
	canonical, sum, err := auditwriter.CanonicalManifest(org, pastDay(1), []auditwriter.ManifestObject{
		{Key: "org/" + org.String() + "/b", SHA256: "bb", EventCount: 2}, {Key: "org/" + org.String() + "/a", SHA256: "aa", EventCount: 1},
	}, prev[:])
	if err != nil {
		t.Fatal(err)
	}
	gotCanonical, gotSum, err := auditevidence.ManifestDigest(auditevidence.ManifestFile{Manifest: canonical})
	if err != nil || !bytes.Equal(gotCanonical, canonical) || gotSum != sum {
		t.Fatalf("ManifestDigest differs from CanonicalManifest: %v", err)
	}
}

// TestExportReadmeKeepsFreeTextOnOneLine: control and bidi characters in the purpose, the requester's name and
// problem texts are rendered as spaces, so they cannot start Markdown blocks or reorder the text.
func TestExportReadmeKeepsFreeTextOnOneLine(t *testing.T) {
	doc := auditevidence.Export{
		OrganizationID: "o", FromDay: "2026-01-01", ToDay: "2026-01-02", Purpose: "a\r\nb\tc\u202ed",
		RequestedBy:  auditevidence.Actor{Type: "admin", Display: "eve\n# x"},
		Verification: auditevidence.Verification{Problems: []string{"p1\n## y", "p2"}},
	}
	readme := string(auditwriter.ExportReadme(doc, 3, "fp"))
	for _, s := range []string{"for: a  b c d.", "requested by eve # x on", "- p1 ## y\n- p2\n", "version 3, SHA-256 fingerprint fp"} {
		if !strings.Contains(readme, s) {
			t.Fatalf("README lacks %q:\n%s", s, readme)
		}
	}
	if strings.Contains(readme, "\u202e") || strings.Contains(readme, "\n# x") || strings.Contains(readme, "\n## y") {
		t.Fatalf("README carries raw control text:\n%s", readme)
	}
}

// switchingSigner signs with the versions of its keys in turn, so the exporter sees the signing key change on every
// call.
type switchingSigner struct {
	keys     map[int]ed25519.PrivateKey
	versions []int
	calls    *int
}

func (s switchingSigner) Sign(ctx context.Context, name string, message []byte) (bao.Signature, error) {
	v := s.versions[*s.calls%len(s.versions)]
	*s.calls++
	return edSigner{priv: s.keys[v], version: v}.Sign(ctx, name, message)
}

// withKeyPair publishes keys 1 and 2 with private halves known to the test; the sealer signs with version 2 while the
// exporter signs with exporterSigner(privs).
func (e exportEnv) withKeyPair(t *testing.T, exporterSigner func(privs map[int]ed25519.PrivateKey) auditwriter.Signer) (
	exportEnv, map[int][]byte) {
	t.Helper()
	pubs, privs := map[int][]byte{}, map[int]ed25519.PrivateKey{}
	for _, v := range []int{1, 2} {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		pubs[v], privs[v] = pub, priv
	}
	keyFn := func(context.Context) (map[int][]byte, error) { return pubs, nil }
	e.sealer = auditwriter.NewSealer(e.pool, e.writer, edSigner{priv: privs[2], version: 2}, auditwriter.NewKeyPublisher(keyFn))
	e.exporter = auditwriter.NewExporter(e.pool, e.writer, e.store, exporterSigner(privs), keyFn,
		auditwriter.NewVerifier(e.pool, e.store, keyFn), "test-1.2.3", time.Second)
	return e, pubs
}

// TestExportReadmeNamesTheKeyThatSigned: the README is rendered for the newest published key before signing; when the
// signer used an older published key, the README is rendered again so that it names the key of export.sig and
// readme_sha256 still covers the final README.
func TestExportReadmeNamesTheKeyThatSigned(t *testing.T) {
	ctx := context.Background()
	e, pubs := newExportEnv(t).withKeyPair(t, func(privs map[int]ed25519.PrivateKey) auditwriter.Signer {
		return edSigner{priv: privs[1], version: 1}
	})
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	e.object(t, org, d.Add(time.Hour), 2)
	e.seal(t, org, d)
	x := e.running(t, org, d, d, "older key")
	if err := e.exporter.Build(ctx, x); err != nil {
		t.Fatal(err)
	}
	got := e.export(t, x.ID)
	if got.Status != "ready" || got.KeyVersion == nil || *got.KeyVersion != 1 {
		t.Fatalf("export = %+v", got)
	}
	byName := map[string][]byte{}
	for _, m := range untar(t, e.chunks(t, x.ID)) {
		byName[m.name] = m.body
	}
	readme := string(byName["README.md"])
	want := "version 1, SHA-256 fingerprint " + auditevidence.Fingerprint(pubs[1])
	if !strings.Contains(readme, want) || strings.Contains(readme, "version 2, SHA-256") ||
		strings.Contains(readme, auditevidence.Fingerprint(pubs[2])) {
		t.Fatalf("README does not name only key 1 (%q):\n%s", want, readme)
	}
	var doc auditevidence.Export
	if err := json.Unmarshal(byName["export.json"], &doc); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(byName["README.md"])
	if doc.ReadmeSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("readme_sha256 %s, README.md hashes to %x", doc.ReadmeSHA256, sum)
	}
	var sig auditevidence.Signature
	if err := json.Unmarshal(byName["export.sig"], &sig); err != nil {
		t.Fatal(err)
	}
	digest := auditevidence.ExportDigest(byName["export.json"])
	if sig.KeyVersion != 1 || !auditevidence.VerifySignature(pubs, 1, sig.Signature, digest[:]) {
		t.Fatalf("export.sig %+v does not verify with key 1", sig)
	}
}

// TestExportFailsWhenTheSignerKeepsSwitchingKeys: a signer that changes its key version on every call never settles on
// the key the README names, so the build fails instead of delivering a README that disagrees with export.sig.
func TestExportFailsWhenTheSignerKeepsSwitchingKeys(t *testing.T) {
	ctx := context.Background()
	calls := 0
	e, _ := newExportEnv(t).withKeyPair(t, func(privs map[int]ed25519.PrivateKey) auditwriter.Signer {
		return switchingSigner{keys: privs, versions: []int{1, 2}, calls: &calls}
	})
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	e.object(t, org, d.Add(time.Hour), 2)
	e.seal(t, org, d)
	x := e.running(t, org, d, d, "switching signer")
	err := e.exporter.Build(ctx, x)
	if err == nil || !strings.Contains(err.Error(), "the signer switched from audit-chain v1 to v2 twice") {
		t.Fatalf("build error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("signer called %d times, want 2", calls)
	}
	if got := e.export(t, x.ID); got.Status != "failed" || got.ReadyAt != nil {
		t.Fatalf("export = %+v", got)
	}
	if pkg := e.chunks(t, x.ID); len(pkg) != 0 {
		t.Fatalf("%d bytes of chunks left", len(pkg))
	}
}

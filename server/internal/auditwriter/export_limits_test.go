package auditwriter_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// tempDir points os.TempDir at a fresh directory, so a test can see the exporter's temp files.
func tempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

// assertFailedOnce checks that the export failed with an error starting with wantErr, kept no chunks and recorded
// exactly one failure event whose reason is reason ("" for none), and that no temp file is left in dir.
func (e exportEnv) assertFailedOnce(t *testing.T, org, id uuid.UUID, wantErr, reason, dir string) {
	t.Helper()
	got := e.export(t, id)
	if got.Status != "failed" || got.Error == nil || !strings.HasPrefix(*got.Error, wantErr) || got.ReadyAt != nil {
		t.Fatalf("export = %+v, want failed with %q", got, wantErr)
	}
	if pkg := e.chunks(t, id); len(pkg) != 0 {
		t.Fatalf("%d bytes of chunks left", len(pkg))
	}
	evs := e.events(t, org, audit.CodeAuditExportCompleted, id)
	if len(evs) != 1 || evs[0].outcome != "failure" || evs[0].errorCode != "export_failed" || evs[0].params["error"] != *got.Error {
		t.Fatalf("audit.export_completed = %+v", evs)
	}
	if r, _ := evs[0].params["reason"].(string); r != reason {
		t.Fatalf("reason = %q, want %q", r, reason)
	}
	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

// TestExportEventsTooLargeFails: an events.jsonl larger than PADDOCK_AUDIT_EXPORT_MAX_BYTES fails the build with
// reason export_too_large, one failure event and no temp file left.
func TestExportEventsTooLargeFails(t *testing.T) {
	e := newExportEnv(t)
	dir := tempDir(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	e.object(t, org, d.Add(time.Hour), 20)
	e.seal(t, org, d)
	auditwriter.SetExportMaxBytes(e.exporter, 100)
	x := e.running(t, org, d, d, "too many events")
	if err := e.exporter.Build(ctx, x); err == nil {
		t.Fatal("build succeeded")
	}
	e.assertFailedOnce(t, org, x.ID, "export_too_large: events.jsonl exceeds PADDOCK_AUDIT_EXPORT_MAX_BYTES (100 bytes)",
		auditwriter.ReasonExportTooLarge, dir)
}

// TestExportPackageSizeExact: the package size the build computes before its first chunk is the size of the package
// it then stores, over several days and objects.
func TestExportPackageSizeExact(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	from := pastDay(6)
	to := from.AddDate(0, 0, 1)
	e.object(t, org, from.Add(time.Hour), 20)
	e.object(t, org, from.Add(2*time.Hour), 3)
	e.object(t, org, to.Add(time.Hour), 7)
	e.seal(t, org, to)
	var computed int64
	auditwriter.SetPackageSized(e.exporter, func(size int64) { computed = size })
	x := e.running(t, org, from, to, "exact size")
	if err := e.exporter.Build(ctx, x); err != nil {
		t.Fatal(err)
	}
	if pkg := e.chunks(t, x.ID); computed == 0 || computed != int64(len(pkg)) {
		t.Fatalf("computed %d bytes, the package has %d", computed, len(pkg))
	}
}

// TestExportPackageTooLargeFails: events.jsonl fits the limit exactly, the package around it does not; the build
// fails with reason export_too_large before it inserts a single chunk.
func TestExportPackageTooLargeFails(t *testing.T) {
	e := newExportEnv(t)
	dir := tempDir(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	e.object(t, org, d.Add(time.Hour), 20)
	e.seal(t, org, d)
	first := e.running(t, org, d, d, "unlimited")
	if err := e.exporter.Build(ctx, first); err != nil {
		t.Fatal(err)
	}
	var eventsSize int64
	for _, m := range untar(t, e.chunks(t, first.ID)) {
		if m.name == "events.jsonl" {
			eventsSize = int64(len(m.body))
		}
	}
	if eventsSize == 0 {
		t.Fatal("the first package has no events")
	}

	auditwriter.SetExportMaxBytes(e.exporter, eventsSize)
	auditwriter.SetExportChunkSize(e.exporter, 512)
	var computed int64
	auditwriter.SetPackageSized(e.exporter, func(size int64) { computed = size })
	inserted := 0
	auditwriter.SetChunkInserted(e.exporter, func(int32) { inserted++ })
	x := e.running(t, org, d, d, "too large a package")
	if err := e.exporter.Build(ctx, x); err == nil {
		t.Fatal("build succeeded")
	}
	if inserted != 0 {
		t.Fatalf("%d chunks inserted before the build failed", inserted)
	}
	e.assertFailedOnce(t, org, x.ID, fmt.Sprintf("export_too_large: the package (%d bytes) exceeds PADDOCK_AUDIT_EXPORT_MAX_BYTES (%d bytes)",
		computed, eventsSize), auditwriter.ReasonExportTooLarge, dir)
}

// TestExportManifestOverReadLimitFails: a manifest larger than the per-object read limit is refused like an object;
// the build fails without reason export_too_large.
func TestExportManifestOverReadLimitFails(t *testing.T) {
	e := newExportEnv(t)
	dir := tempDir(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	key := e.object(t, org, d.Add(time.Hour), 1)
	e.seal(t, org, d)
	limit := manifestLimit(t, e, org, d, key)
	auditwriter.SetExportMaxObject(e.exporter, limit)
	x := e.running(t, org, d, d, "large manifest")
	if err := e.exporter.Build(ctx, x); err == nil {
		t.Fatal("build succeeded")
	}
	e.assertFailedOnce(t, org, x.ID, fmt.Sprintf("day %s: manifest %s unreadable: larger than the per-object read limit (%d bytes)",
		d.Format(time.DateOnly), auditwriter.ManifestKey(org, d), limit), "", dir)
}

// TestVerifierManifestOverReadLimit: the verifier reports a manifest larger than its read limit as unreadable.
func TestVerifierManifestOverReadLimit(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	key := e.object(t, org, d.Add(time.Hour), 1)
	e.seal(t, org, d)
	keyFn := func(context.Context) (map[int][]byte, error) { return e.keys, nil }
	v := auditwriter.NewVerifier(e.pool, e.store, keyFn)
	limit := manifestLimit(t, e, org, d, key)
	auditwriter.SetVerifierMaxObject(v, limit)
	report, err := v.Verify(ctx, org, d, d)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%s: manifest object %s unreadable: larger than the per-object read limit (%d bytes)",
		d.Format(time.DateOnly), auditwriter.ManifestKey(org, d), limit)
	if !slices.Contains(report.Problems, want) {
		t.Fatalf("problems = %q, want %q", report.Problems, want)
	}
}

// rawObject stores body as the WORM object key of org with n events and indexes it.
func (e exportEnv) rawObject(t *testing.T, org uuid.UUID, recorded time.Time, key string, body []byte, n int) {
	t.Helper()
	if err := e.store.PutLocked(context.Background(), key, "application/zstd", body, time.Time{}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if _, err := e.super.Exec(context.Background(), "INSERT INTO audit_object (object_key, organization_id, day, event_count, sha256) VALUES ($1, $2, $3, $4, $5)",
		key, org, recorded.UTC().Truncate(24*time.Hour), n, sum[:]); err != nil {
		t.Fatal(err)
	}
}

// manifestLimit is a read limit one byte below the manifest of day d that the object key still fits.
func manifestLimit(t *testing.T, e exportEnv, org uuid.UUID, d time.Time, key string) int64 {
	t.Helper()
	ctx := context.Background()
	object, err := e.store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := e.store.Get(ctx, auditwriter.ManifestKey(org, d))
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(len(manifest)) - 1
	if int64(len(object)) > limit {
		t.Fatalf("the object (%d bytes) does not fit the limit %d", len(object), limit)
	}
	return limit
}

// TestExportDecodedOverLimitUndecodable: an object whose frames each pass the decoder's header checks but together
// decode to more than the limit is reported as undecodable, and none of its events reach events.jsonl.
func TestExportDecodedOverLimitUndecodable(t *testing.T) {
	e := newExportEnv(t)
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	recorded := d.Add(time.Hour)
	var body []byte
	var frame int
	for i := range 20 {
		ev := event(org, recorded.Add(time.Duration(i)*time.Second), audit.CodeDeviceGroupCreated)
		ev.RecordedAt = audit.Timestamp(recorded)
		part, err := auditwriter.EncodeObject([]audit.Event{ev})
		if err != nil {
			t.Fatal(err)
		}
		plain, err := auditwriter.DecodeObject(part)
		if err != nil || len(plain) != 1 {
			t.Fatal(err)
		}
		raw, err := json.Marshal(plain[0])
		if err != nil {
			t.Fatal(err)
		}
		frame = max(frame, len(raw)+1)
		body = append(body, part...)
	}
	key := auditwriter.ObjectKey(org, recorded.Truncate(time.Hour), uuid.Must(uuid.NewV7()))
	e.rawObject(t, org, recorded, key, body, 20)
	e.seal(t, org, d)
	auditwriter.SetExportMaxDecoded(e.exporter, uint64(5*frame))
	e.assertUndecodable(t, org, d, key)
}

// TestExportDecoderWindowOverLimitUndecodable: an object whose frame asks for a larger decoder window than the
// encoder of audit objects uses is reported as undecodable.
func TestExportDecoderWindowOverLimitUndecodable(t *testing.T) {
	e := newExportEnv(t)
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	recorded := d.Add(time.Hour)
	ev := event(org, recorded, audit.CodeDeviceGroupCreated)
	ev.RecordedAt = audit.Timestamp(recorded)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	zw, err := zstd.NewWriter(&body, zstd.WithWindowSize(16<<20))
	if err != nil {
		t.Fatal(err)
	}
	// More than one block, so the encoder cannot size the window from the content and declares its own.
	n := (256<<10)/(len(raw)+1) + 1
	for range n {
		if _, err := zw.Write(append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var header zstd.Header
	if err := header.Decode(body.Bytes()); err != nil || header.WindowSize <= 8<<20 {
		t.Fatalf("frame window %d, err %v; want more than 8 MiB", header.WindowSize, err)
	}
	if events, err := auditwriter.DecodeObject(body.Bytes()); err != nil || len(events) != n {
		t.Fatalf("the object does not decode without a window limit: %v", err)
	}
	key := auditwriter.ObjectKey(org, recorded.Truncate(time.Hour), uuid.Must(uuid.NewV7()))
	e.rawObject(t, org, recorded, key, body.Bytes(), n)
	e.seal(t, org, d)
	e.assertUndecodable(t, org, d, key)
}

// assertUndecodable builds an export of day d and checks that it is ready with object key reported as undecodable
// and no events.
func (e exportEnv) assertUndecodable(t *testing.T, org uuid.UUID, d time.Time, key string) {
	t.Helper()
	x := e.running(t, org, d, d, "undecodable")
	if err := e.exporter.Build(context.Background(), x); err != nil {
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
	if want := fmt.Sprintf("%s: object %s cannot be decoded", d.Format(time.DateOnly), key); !slices.Contains(problems, want) {
		t.Fatalf("problems %q lack %q", problems, want)
	}
	for _, m := range untar(t, e.chunks(t, x.ID)) {
		if m.name == "events.jsonl" && len(m.body) != 0 {
			t.Fatalf("events.jsonl holds %d bytes of the undecodable object", len(m.body))
		}
	}
}

// TestExportObjectOverReadLimitFails: an object larger than the per-object read limit is refused instead of read
// into memory; the build fails without reason export_too_large.
func TestExportObjectOverReadLimitFails(t *testing.T) {
	e := newExportEnv(t)
	dir := tempDir(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	key := e.object(t, org, d.Add(time.Hour), 200)
	e.seal(t, org, d)
	object, err := e.store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := e.store.Get(ctx, auditwriter.ManifestKey(org, d))
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(len(object)) - 1
	if int64(len(manifest)) > limit {
		t.Fatalf("the manifest (%d bytes) does not fit the limit %d", len(manifest), limit)
	}
	auditwriter.SetExportMaxObject(e.exporter, limit)
	x := e.running(t, org, d, d, "large object")
	if err := e.exporter.Build(ctx, x); err == nil {
		t.Fatal("build succeeded")
	}
	e.assertFailedOnce(t, org, x.ID, fmt.Sprintf("day %s: object %s unreadable: larger than the per-object read limit (%d bytes)",
		d.Format(time.DateOnly), key, limit), "", dir)
}

// TestVerifierObjectOverReadLimit: the verifier reports an object larger than its read limit as unreadable.
func TestVerifierObjectOverReadLimit(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	key := e.object(t, org, d.Add(time.Hour), 200)
	e.seal(t, org, d)
	object, err := e.store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	keyFn := func(context.Context) (map[int][]byte, error) { return e.keys, nil }
	v := auditwriter.NewVerifier(e.pool, e.store, keyFn)
	limit := int64(len(object)) - 1
	auditwriter.SetVerifierMaxObject(v, limit)
	report, err := v.Verify(ctx, org, d, d)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%s: object %s unreadable: larger than the per-object read limit (%d bytes)", d.Format(time.DateOnly), key, limit)
	if len(report.Problems) != 1 || report.Problems[0] != want {
		t.Fatalf("problems = %q, want [%q]", report.Problems, want)
	}

	auditwriter.SetVerifierMaxObject(v, int64(len(object)))
	if report, err := v.Verify(ctx, org, d, d); err != nil || !report.OK() {
		t.Fatalf("at the limit: report %+v, err %v", report, err)
	}
}

// swappingStore serves other bytes for key from the second read on, as if the object changed between the two passes.
type swappingStore struct {
	auditwriter.ObjectStore
	key   string
	other []byte
	mu    sync.Mutex
	reads int
}

func (s *swappingStore) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if key == s.key {
		s.mu.Lock()
		s.reads++
		second := s.reads > 1
		s.mu.Unlock()
		if second {
			return io.NopCloser(bytes.NewReader(s.other)), nil
		}
	}
	return s.ObjectStore.Open(ctx, key)
}

// TestExportObjectChangedBetweenPasses: an object streamed into the package that no longer hashes or sizes as in the
// first pass fails the build, and the chunks already stored are deleted.
func TestExportObjectChangedBetweenPasses(t *testing.T) {
	e := newExportEnv(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	key := e.object(t, org, d.Add(time.Hour), 200)
	e.seal(t, org, d)
	object, err := e.store.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	flipped := append([]byte(nil), object...)
	flipped[len(flipped)/2] ^= 0xff
	for name, other := range map[string][]byte{
		"same size": flipped, "longer": append(append([]byte(nil), object...), 0), "shorter": object[:len(object)-1],
	} {
		t.Run(name, func(t *testing.T) {
			dir := tempDir(t)
			store := &swappingStore{ObjectStore: e.store, key: key, other: other}
			exporter := e.newExporter(store)
			auditwriter.SetExportChunkSize(exporter, 512)
			x := e.running(t, org, d, d, name)
			if err := exporter.Build(ctx, x); err == nil {
				t.Fatal("build succeeded")
			}
			e.assertFailedOnce(t, org, x.ID, fmt.Sprintf("day %s: object %s changed during the build", d.Format(time.DateOnly), key), "", dir)
		})
	}
}

// openHookStore runs onOpen before every object read.
type openHookStore struct {
	auditwriter.ObjectStore
	onOpen func()
}

func (s *openHookStore) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	s.onOpen()
	return s.ObjectStore.Open(ctx, key)
}

// TestExportTempFileNeverVisible: while the build reads objects, the temp file of events.jsonl is already unlinked, so
// a writer killed in the middle of a build leaves nothing on the TMPDIR volume.
func TestExportTempFileNeverVisible(t *testing.T) {
	e := newExportEnv(t)
	dir := tempDir(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	d := pastDay(5)
	e.object(t, org, d.Add(time.Hour), 20)
	e.seal(t, org, d)
	var seen []string
	store := &openHookStore{ObjectStore: e.store, onOpen: func() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Error(err)
		}
		for _, entry := range entries {
			seen = append(seen, entry.Name())
		}
	}}
	x := e.running(t, org, d, d, "temp file")
	if err := e.newExporter(store).Build(ctx, x); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 0 {
		t.Fatalf("temp files visible during the build: %v", seen)
	}
	e.assertReady(t, org, x.ID)
}

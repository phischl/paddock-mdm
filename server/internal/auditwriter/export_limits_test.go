package auditwriter_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

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

// TestExportPackageTooLargeFails: events.jsonl fits the limit exactly, the package around it does not; the build
// fails with reason export_too_large and the chunks it had already stored are deleted.
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
	x := e.running(t, org, d, d, "too large a package")
	if err := e.exporter.Build(ctx, x); err == nil {
		t.Fatal("build succeeded")
	}
	e.assertFailedOnce(t, org, x.ID, fmt.Sprintf("export_too_large: the package exceeds PADDOCK_AUDIT_EXPORT_MAX_BYTES (%d bytes)", eventsSize),
		auditwriter.ReasonExportTooLarge, dir)
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

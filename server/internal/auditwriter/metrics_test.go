package auditwriter_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// failingStore rejects every WORM put.
type failingStore struct{ auditwriter.ObjectStore }

func (failingStore) PutLocked(context.Context, string, string, []byte, time.Time) error {
	return errors.New("rustfs unavailable")
}

// histogramCount is the number of observations of the histogram series name{labels} in the default registry.
func histogramCount(t *testing.T, name string, labels map[string]string) uint64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	series:
		for _, m := range f.GetMetric() {
			if len(m.GetLabel()) != len(labels) {
				continue
			}
			for _, l := range m.GetLabel() {
				if labels[l.GetName()] != l.GetValue() {
					continue series
				}
			}
			return m.GetHistogram().GetSampleCount()
		}
	}
	return 0
}

type histogramSeries struct {
	name   string
	labels map[string]string
}

var (
	txCommitted  = histogramSeries{"paddock_audit_writer_transaction_seconds", map[string]string{"result": "committed"}}
	txRolledBack = histogramSeries{"paddock_audit_writer_transaction_seconds", map[string]string{"result": "rolled_back"}}
	putEventsOK  = histogramSeries{"paddock_audit_worm_put_seconds", map[string]string{"object": "events", "result": "ok"}}
	putEventsErr = histogramSeries{"paddock_audit_worm_put_seconds", map[string]string{"object": "events", "result": "error"}}
	putManifest  = histogramSeries{"paddock_audit_worm_put_seconds", map[string]string{"object": "manifest", "result": "ok"}}
)

// observe runs fn and returns how many observations each series gained.
func observe(t *testing.T, series []histogramSeries, fn func()) []uint64 {
	t.Helper()
	before := make([]uint64, len(series))
	for i, s := range series {
		before[i] = histogramCount(t, s.name, s.labels)
	}
	fn()
	delta := make([]uint64, len(series))
	for i, s := range series {
		delta[i] = histogramCount(t, s.name, s.labels) - before[i]
	}
	return delta
}

// TestWriterLatencyMetrics: every writer transaction and every WORM put is observed, by result, so a slow transaction
// can be attributed to the WORM store or to the database (PDK-067).
func TestWriterLatencyMetrics(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	all := []histogramSeries{txCommitted, txRolledBack, putEventsOK, putEventsErr, putManifest}
	want := func(t *testing.T, got []uint64, exp ...uint64) {
		t.Helper()
		for i := range exp {
			if got[i] != exp[i] {
				t.Fatalf("%s%v gained %d observations, want %d", all[i].name, all[i].labels, got[i], exp[i])
			}
		}
	}

	t.Run("committed batch", func(t *testing.T) {
		got := observe(t, all, func() {
			if n, err := s.writer.WriteBatch(ctx, []audit.Event{event(org, time.Now(), audit.CodeDeviceGroupCreated)}); err != nil || n != 1 {
				t.Fatalf("WriteBatch = %d, %v", n, err)
			}
		})
		want(t, got, 1, 0, 1, 0, 0)
	})

	t.Run("duplicate batch commits without a put", func(t *testing.T) {
		ev := event(org, time.Now(), audit.CodeDeviceGroupUpdated)
		if _, err := s.writer.WriteBatch(ctx, []audit.Event{ev}); err != nil {
			t.Fatal(err)
		}
		got := observe(t, all, func() {
			if n, err := s.writer.WriteBatch(ctx, []audit.Event{ev}); err != nil || n != 0 {
				t.Fatalf("WriteBatch = %d, %v; want 0", n, err)
			}
		})
		want(t, got, 1, 0, 0, 0, 0)
	})

	t.Run("failed put rolls back", func(t *testing.T) {
		writer, err := auditwriter.NewWriter(s.pool, failingStore{s.store}, 400)
		if err != nil {
			t.Fatal(err)
		}
		got := observe(t, all, func() {
			if _, err := writer.WriteBatch(ctx, []audit.Event{event(org, time.Now(), audit.CodeDeviceGroupDeleted)}); err == nil {
				t.Fatal("WriteBatch succeeded with a failing WORM store")
			}
		})
		want(t, got, 0, 1, 0, 1, 0)
	})

	t.Run("sealed manifest", func(t *testing.T) {
		sealOrg := uuid.Must(uuid.NewV7())
		day := time.Now().UTC().AddDate(0, 0, -3).Truncate(24 * time.Hour)
		s.historicObject(t, sealOrg, day.Add(9*time.Hour), event(sealOrg, day.Add(9*time.Hour), audit.CodeDeviceGroupCreated))
		var sealed int
		got := observe(t, all, func() {
			var err error
			if sealed, err = s.sealer.SealThrough(ctx, day); err != nil || sealed < 1 {
				t.Fatalf("SealThrough = %d, %v", sealed, err)
			}
		})
		if got[4] != uint64(sealed) { //nolint:gosec // sealed ≥ 1
			t.Fatalf("%d manifest puts observed, want %d (one per sealed manifest)", got[4], sealed)
		}
	})
}

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// hashedObjects is the escrow bucket with the hash the diagnostics verification reads.
type hashedObjects struct{ *fakeObjects }

func (h hashedObjects) SHA256(ctx context.Context, key string) (string, bool, error) {
	data, ok, err := h.GetIfExists(ctx, key)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), ok, err
}

// TestDiagnosticsAnnouncementAndRound (plan M12 decision 5): a diagnostics announcement on the escrow ingest queue is
// handed to the diagnostics handler and recorded, a malformed one is poison, an escrow consumer without the handler
// refuses it as poison; the round stores the uploaded bundle whose object matches.
func TestDiagnosticsAnnouncementAndRound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	device, id := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lt-diag', 'active')", device, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(ctx, `INSERT INTO device_diagnostics (id, organization_id, device_id, requested_by, reason, state)
		VALUES ($1, $2, $3, 'alice', 'slow logins', 'requested')`, id, f.org, device); err != nil {
		t.Fatal(err)
	}
	// The retention rounds of this package run without an escrow bucket and would fail on this bundle once it expires.
	t.Cleanup(func() { _, _ = f.super.Exec(context.Background(), "DELETE FROM device_diagnostics WHERE id = $1", id) })
	objects := hashedObjects{&fakeObjects{objects: map[string][]byte{}}}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	d := NewDiagnostics(app.NewDiagnostics(runner, f.pool, objects, time.Second), f.pool, platform)
	e := NewEscrow(app.NewEscrow(runner, f.pool, nil), f.cache, f.pool, platform).WithDiagnostics(d)

	plain := []byte("sealed bundle")
	sum := sha256.Sum256(plain)
	key := escrow.DiagnosticsObjectKey(f.org.String(), device.String(), id.String())
	body, _ := json.Marshal(ingest.DiagnosticsAnnounced{DiagnosticsID: id, DeviceID: device, OrganizationID: f.org, ObjectKey: key,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(plain)), Nonce: make([]byte, 12), WrappedDEK: []byte{1}, ReceivedAt: time.Now()})
	if o := NewEscrow(app.NewEscrow(runner, f.pool, nil), f.cache, f.pool, platform).process(ctx, "diagnostics:"+id.String(), body); o != poison {
		t.Fatalf("without the handler: %v", o)
	}
	if o := e.process(ctx, "diagnostics:"+id.String(), body); o != ack {
		t.Fatalf("announcement: %v", o)
	}
	if o := e.process(ctx, "x", []byte(`{"diagnostics_id":"`+id.String()+`","extra":1}`)); o != poison {
		t.Fatalf("malformed announcement: %v", o)
	}
	var announced string
	if err := f.super.QueryRow(ctx, "SELECT object_key FROM device_diagnostics WHERE id = $1", id).Scan(&announced); err != nil || announced != key {
		t.Fatalf("object key %q %v", announced, err)
	}

	objects.put(key, plain)
	if _, err := f.super.Exec(ctx, `UPDATE device_diagnostics SET state = 'uploaded', uploaded_at = now() - interval '1 minute'
		WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := d.Round(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := f.super.QueryRow(ctx, "SELECT state FROM device_diagnostics WHERE id = $1", id).Scan(&state); err != nil || state != "stored" {
		t.Fatalf("state %q %v", state, err)
	}
}

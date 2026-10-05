package worker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/ingest"
)

// TestEscrowStore (plan M4a decisions 11 and 12): an upload is stored and reported stored, a repeated message keeps
// it, a second upload of the same generation and a generation not above the active one fail.
func TestEscrowStore(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	device := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lt-esc', 'active')", device, f.org); err != nil {
		t.Fatal(err)
	}
	e := NewEscrow(app.NewEscrow(f.pool), f.cache)
	upload := func(id uuid.UUID, generation int64) (outcome, string) {
		t.Helper()
		body, _ := json.Marshal(ingest.Escrow{DeviceID: device, OrganizationID: f.org, EscrowID: id, Kind: "admin_password",
			Generation: generation, KeyVersion: 1, Ciphertext: []byte{1, 2, 3}, ReceivedAt: time.Now()})
		o := e.process(ctx, id.String(), body)
		_, status, ok, err := f.cache.EscrowStatus(ctx, id)
		if err != nil || !ok {
			t.Fatalf("escrow status of %s: %v %v", id, ok, err)
		}
		return o, status
	}
	first := uuid.Must(uuid.NewV7())
	for range 2 {
		if o, status := upload(first, 1); o != ack || status != "stored" {
			t.Fatalf("upload: %v %s", o, status)
		}
	}
	if o, status := upload(uuid.Must(uuid.NewV7()), 1); o != ack || status != "failed" {
		t.Fatalf("second upload of generation 1: %v %s", o, status)
	}
	if _, err := f.super.Exec(ctx, "UPDATE escrow_secret SET status = 'active' WHERE id = $1", first); err != nil {
		t.Fatal(err)
	}
	if o, status := upload(uuid.Must(uuid.NewV7()), 1); o != ack || status != "failed" {
		t.Fatalf("generation not above the active one: %v %s", o, status)
	}
	if o, status := upload(uuid.Must(uuid.NewV7()), 2); o != ack || status != "stored" {
		t.Fatalf("next generation: %v %s", o, status)
	}
	var n int
	if err := f.super.QueryRow(ctx, "SELECT count(*) FROM escrow_secret WHERE device_id = $1", device).Scan(&n); err != nil || n != 2 {
		t.Fatalf("%d rows, want 2 (%v)", n, err)
	}
	if o := e.process(ctx, "x", []byte(`{"escrow":1}`)); o != poison {
		t.Fatalf("malformed message: %v", o)
	}
}

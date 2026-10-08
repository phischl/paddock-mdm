package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
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

// TestEscrowStore (plan M4a decisions 11 and 12): an upload is stored and reported stored, a repeated message keeps
// it, a second upload of the same generation and a generation not above the active one fail.
func TestEscrowStore(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	device := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lt-esc', 'active')", device, f.org); err != nil {
		t.Fatal(err)
	}
	e := NewEscrow(app.NewEscrow(app.NewActionRunner(f.pool, nil, httpx.RequestID), f.pool, nil), f.cache, f.pool, nil)
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

// fakeObjects is the escrow bucket.
type fakeObjects struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (f *fakeObjects) GetIfExists(_ context.Context, key string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[key]
	return data, ok, nil
}

func (f *fakeObjects) put(key string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = data
}

// TestEscrowLUKS (plan M4b decisions 10 and 13): a recovery key is stored like a secret, but every new generation
// must exceed the last one that did not fail; a header stays pending until the round finds its object with the
// announced size and SHA-256, fails on a mismatch or when it does not arrive in time.
func TestEscrowLUKS(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	device := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lt-luks', 'active')", device, f.org); err != nil {
		t.Fatal(err)
	}
	objects := &fakeObjects{objects: map[string][]byte{}}
	e := NewEscrow(app.NewEscrow(app.NewActionRunner(f.pool, nil, httpx.RequestID), f.pool, objects), f.cache, f.pool, platform)
	status := func(id uuid.UUID) string {
		t.Helper()
		_, s, ok, err := f.cache.EscrowStatus(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return escrow.StatusPending
		}
		return s
	}
	send := func(m ingest.Escrow) uuid.UUID {
		t.Helper()
		m.DeviceID, m.OrganizationID, m.EscrowID = device, f.org, uuid.Must(uuid.NewV7())
		if m.ReceivedAt.IsZero() {
			m.ReceivedAt = time.Now()
		}
		body, _ := json.Marshal(m)
		if o := e.process(ctx, m.EscrowID.String(), body); o != ack {
			t.Fatalf("process %s: %v", m.Kind, o)
		}
		return m.EscrowID
	}
	recovery := func(g int64) ingest.Escrow {
		return ingest.Escrow{Kind: escrow.KindLUKSRecoveryKey, Generation: g, KeyVersion: 1, Ciphertext: []byte{9}}
	}
	if id := send(recovery(1)); status(id) != escrow.StatusStored {
		t.Fatalf("recovery key 1: %s", status(id))
	}
	if id := send(recovery(1)); status(id) != escrow.StatusFailed {
		t.Fatalf("recovery key 1 again: %s", status(id))
	}
	if id := send(recovery(2)); status(id) != escrow.StatusStored {
		t.Fatalf("recovery key 2: %s", status(id))
	}

	object := []byte("sealed header")
	sum := sha256.Sum256(object)
	header := func(g int64, size int64, receivedAt time.Time) ingest.Escrow {
		key := escrow.HeaderObjectKey(f.org.String(), device.String(), "", g)
		return ingest.Escrow{Kind: escrow.KindLUKSHeader, Generation: g, KeyVersion: 1, ObjectKey: key, WrappedDEK: []byte{1},
			Nonce: make([]byte, 12), SHA256: hex.EncodeToString(sum[:]), Size: size, ReceivedAt: receivedAt}
	}
	ok := send(header(1, int64(len(object)), time.Time{}))
	mismatch := send(header(2, int64(len(object))+1, time.Time{}))
	late := send(header(3, int64(len(object)), time.Now().Add(-app.HeaderUploadWindow-time.Minute)))
	waiting := send(header(4, int64(len(object)), time.Time{}))
	for _, id := range []uuid.UUID{ok, mismatch, late, waiting} {
		if status(id) != escrow.StatusPending {
			t.Fatalf("header %s before the round: %s", id, status(id))
		}
	}
	objects.put(escrow.HeaderObjectKey(f.org.String(), device.String(), "", 1), object)
	objects.put(escrow.HeaderObjectKey(f.org.String(), device.String(), "", 2), object)
	if err := e.Round(ctx); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[uuid.UUID]string{ok: escrow.StatusStored, mismatch: escrow.StatusFailed, late: escrow.StatusFailed, waiting: escrow.StatusPending} {
		if got := status(id); got != want {
			t.Errorf("header %s: %s, want %s", id, got, want)
		}
	}
	objects.put(escrow.HeaderObjectKey(f.org.String(), device.String(), "", 4), object)
	if err := e.Round(ctx); err != nil || status(waiting) != escrow.StatusStored {
		t.Fatalf("late upload within the window: %v %s", err, status(waiting))
	}
	// A repeated message reports the recorded status; a generation at or below a header that did not fail fails.
	body, _ := json.Marshal(ingest.Escrow{DeviceID: device, OrganizationID: f.org, EscrowID: ok, Kind: escrow.KindLUKSHeader, Generation: 1,
		KeyVersion: 1, ObjectKey: "x", WrappedDEK: []byte{1}, Nonce: make([]byte, 12), SHA256: hex.EncodeToString(sum[:]), Size: 1, ReceivedAt: time.Now()})
	if o := e.process(ctx, ok.String(), body); o != ack || status(ok) != escrow.StatusStored {
		t.Fatalf("repeated header message: %v %s", o, status(ok))
	}
	if id := send(header(4, int64(len(object)), time.Time{})); status(id) != escrow.StatusFailed {
		t.Fatalf("header generation 4 again: %s", status(id))
	}

	// PDK-009: a header of another volume is recorded with it, its generation above every volume's.
	volume := uuid.MustParse("0d8f4c62-0000-4000-8000-0000000000bb")
	data := header(5, int64(len(object)), time.Time{})
	data.Volume, data.ObjectKey = &volume, escrow.HeaderObjectKey(f.org.String(), device.String(), volume.String(), 5)
	vid := send(data)
	objects.put(data.ObjectKey, object)
	if err := e.Round(ctx); err != nil || status(vid) != escrow.StatusStored {
		t.Fatalf("volume header: %v %s", err, status(vid))
	}
	var got uuid.NullUUID
	if err := f.super.QueryRow(ctx, "SELECT volume FROM escrow_secret WHERE id = $1", vid).Scan(&got); err != nil || got.UUID != volume {
		t.Fatalf("recorded volume %v: %v", got, err)
	}
	other := header(5, int64(len(object)), time.Time{})
	other.Volume = &volume
	if id := send(other); status(id) != escrow.StatusFailed {
		t.Fatalf("generation 5 of another volume: %s", status(id))
	}

	// Review round 1, decision 1: at most 32 distinct volumes per device. With 32 escrowed (the data volume and 31
	// more, written directly), a header of a 33rd volume fails and is audited; a known volume is still accepted.
	for i := 0; i < 31; i++ {
		if _, err := f.super.Exec(ctx, `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, key_version,
			object_key, wrapped_dek, nonce, sha256, size, volume) VALUES (gen_random_uuid(), $1, $2, 'luks_header', $3, 'stored', 1, 'k',
			'\x01', '\x000000000000000000000000', $4, 1, $5)`, f.org, device, 100+i, hex.EncodeToString(sum[:]),
			fmt.Sprintf("0d8f4c62-0000-4000-8000-%012d", i)); err != nil {
			t.Fatal(err)
		}
	}
	extra := uuid.MustParse("0d8f4c62-0000-4000-8000-0000000000ff")
	refused := header(200, int64(len(object)), time.Time{})
	refused.Volume = &extra
	refusedID := send(refused)
	if status(refusedID) != escrow.StatusRefused {
		t.Fatalf("33rd volume: %s", status(refusedID))
	}
	// Review round 3: a redelivered refusal reports refused again and is audited once.
	refused.DeviceID, refused.OrganizationID, refused.EscrowID, refused.ReceivedAt = device, f.org, refusedID, time.Now()
	again, _ := json.Marshal(refused)
	if o := e.process(ctx, refusedID.String(), again); o != ack || status(refusedID) != escrow.StatusRefused {
		t.Fatalf("redelivered refusal: %v %s", o, status(refusedID))
	}
	var outcome, code, param string
	if err := f.super.QueryRow(ctx, `SELECT outcome, coalesce(error_code, ''), params ->> 'volume' FROM action
		WHERE organization_id = $1 AND code = 'device.header_escrow_refused'`, f.org).Scan(&outcome, &code, &param); err != nil ||
		outcome != "failure" || code != "too_many_volumes" || param != extra.String() {
		t.Fatalf("audit %s %s %s: %v", outcome, code, param, err)
	}
	var audits int
	if err := f.super.QueryRow(ctx, `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'device.header_escrow_refused'`,
		f.org).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("%d refusal audits: %v", audits, err)
	}
	known := header(201, int64(len(object)), time.Time{})
	known.Volume = &volume
	if id := send(known); status(id) != escrow.StatusPending {
		t.Fatalf("a known volume beyond 32: %s", status(id))
	}
}

// TestEscrowVolumeCapConcurrent (PDK-009 review round 3, decision E5): two workers storing headers of two new volumes
// of a device that escrows 31 at the same time let exactly one through; the cap check holds a lock per device.
func TestEscrowVolumeCapConcurrent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	device := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lt-cap', 'active')", device, f.org); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	for i := 0; i < app.MaxHeaderVolumes-1; i++ {
		if _, err := f.super.Exec(ctx, `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, key_version,
			object_key, wrapped_dek, nonce, sha256, size, volume) VALUES (gen_random_uuid(), $1, $2, 'luks_header', $3, 'stored', 1, 'k',
			'\x01', '\x000000000000000000000000', $4, 1, $5)`, f.org, device, i+1, hex.EncodeToString(sum[:]),
			fmt.Sprintf("0d8f4c62-0000-4000-8000-%012d", i)); err != nil {
			t.Fatal(err)
		}
	}
	e := NewEscrow(app.NewEscrow(app.NewActionRunner(f.pool, nil, httpx.RequestID), f.pool, nil), f.cache, f.pool, nil)
	var wg sync.WaitGroup
	ids := make([]uuid.UUID, 2)
	for i := range ids {
		volume := uuid.MustParse(fmt.Sprintf("0d8f4c62-0000-4000-8000-0000000001%02d", i))
		ids[i] = uuid.Must(uuid.NewV7())
		m := ingest.Escrow{DeviceID: device, OrganizationID: f.org, EscrowID: ids[i], Kind: escrow.KindLUKSHeader, Generation: int64(100 + i),
			KeyVersion: 1, Volume: &volume, ObjectKey: "k", WrappedDEK: []byte{1}, Nonce: make([]byte, 12), SHA256: hex.EncodeToString(sum[:]),
			Size: 1, ReceivedAt: time.Now()}
		body, _ := json.Marshal(m)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if o := e.process(ctx, m.EscrowID.String(), body); o != ack {
				t.Errorf("process: %v", o)
			}
		}()
	}
	wg.Wait()
	var volumes int
	if err := f.super.QueryRow(ctx, `SELECT count(DISTINCT volume) FROM escrow_secret WHERE device_id = $1 AND kind = 'luks_header'
		AND status <> 'failed'`, device).Scan(&volumes); err != nil || volumes != app.MaxHeaderVolumes {
		t.Fatalf("%d volumes escrowed (%v), want %d", volumes, err, app.MaxHeaderVolumes)
	}
}

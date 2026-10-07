package worker

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
)

// TestDMSMarkSilent (plan M4c decision 17): with the switch on, a device silent for longer than the period is marked
// presumed self-locked and audited once; its next contact or a switch turned off clears the mark.
func TestDMSMarkSilent(t *testing.T) {
	f := newFixture(t)
	ctx := systemContext(context.Background(), f.org, "dms-test")
	dms := app.NewDMS(app.NewActionRunner(f.pool, nil, httpx.RequestID), f.pool, f.cache, false, false)
	silent, fresh := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, d := range []struct {
		id      uuid.UUID
		contact time.Duration
	}{{silent, 8 * 24 * time.Hour}, {fresh, time.Hour}} {
		if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lt-dms', 'active')", d.id, f.org); err != nil {
			t.Fatal(err)
		}
		if _, err := f.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)",
			d.id, f.org, time.Now().Add(-d.contact)); err != nil {
			t.Fatal(err)
		}
	}
	marked := func() []uuid.UUID {
		rows, _ := f.super.Query(ctx, "SELECT device_id FROM device_status WHERE organization_id = $1 AND presumed_self_locked_at IS NOT NULL", f.org)
		defer rows.Close()
		var out []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			_ = rows.Scan(&id)
			out = append(out, id)
		}
		return out
	}
	events := func() int {
		var n int
		_ = f.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE code = 'device.presumed_self_locked' AND target ->> 'id' = $1", silent.String()).Scan(&n)
		return n
	}
	if err := dms.MarkSilent(ctx, time.Now()); err != nil || len(marked()) != 0 {
		t.Fatalf("switch off: %v %v", marked(), err)
	}
	if _, err := f.super.Exec(ctx, "INSERT INTO organization_dms_settings (organization_id, enabled, period_days) VALUES ($1, true, 7)", f.org); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := dms.MarkSilent(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if m := marked(); len(m) != 1 || m[0] != silent || events() != 1 {
		t.Fatalf("marked %v, %d events", m, events())
	}
	if _, err := f.super.Exec(ctx, "UPDATE device_status SET last_contact_at = now() WHERE device_id = $1", silent); err != nil {
		t.Fatal(err)
	}
	if err := dms.MarkSilent(ctx, time.Now()); err != nil || len(marked()) != 0 {
		t.Fatalf("after contact: %v %v", marked(), err)
	}
}

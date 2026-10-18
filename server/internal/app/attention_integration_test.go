package app_test

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestAttentionConfigBehind (PDK-293, plan M8f decisions 23–24, migration 00061): an active device that keeps checking
// in but applies an older bundle than its newest one for more than an hour is the attention kind config_behind, with
// the detail "<applied> < <newest>" and the compile time of the newest bundle as since, for its own organization only.
// A device on its newest bundle, a bundle younger than an hour, a device without a check-in after that hour and a
// device that is not active are not listed. Everything runs in one transaction that is rolled back; the reads run as
// paddock_api.
func TestAttentionConfigBehind(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	tx, err := super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	org := func() uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", id, "o"+id.String()[24:])
		return id
	}
	// device has bundles 1..newest, the newest compiled compiledAgo before now, applies applied and last checked in
	// contactAfter after the newest bundle was compiled.
	device := func(org uuid.UUID, hostname, state string, newest, applied int, compiledAgo, contactAfter string) uuid.UUID {
		t.Helper()
		id := uuid.Must(uuid.NewV7())
		exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, $4)", id, org, hostname, state)
		for v := 1; v <= newest; v++ {
			exec(`INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key, created_at)
				VALUES ($1, $2, $3, '\x00', '\x00', 'k', now() - $4::interval - $5::int * interval '1 minute')`,
				id, v, org, compiledAgo, newest-v)
		}
		exec(`INSERT INTO device_status (device_id, organization_id, last_contact_at, applied_bundle_version)
			VALUES ($1, $2, now() - $3::interval + $4::interval, $5)`, id, org, compiledAgo, contactAfter, applied)
		return id
	}
	type row struct{ hostname, detail string }
	listed := func(asking uuid.UUID) []row {
		t.Helper()
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sp.Rollback(ctx) }()
		if _, err := sp.Exec(ctx, "SET LOCAL ROLE paddock_api"); err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", asking.String()); err != nil {
			t.Fatal(err)
		}
		rows, err := pgstore.New(sp).ListAttention(ctx, pgstore.ListAttentionParams{Kinds: []string{"config_behind"}, Sort: "hostname", MaxRows: 100})
		if err != nil {
			t.Fatal(err)
		}
		var out []row
		for _, r := range rows {
			if r.ID != "config_behind:"+r.DeviceID.String() || r.Kind != "config_behind" {
				t.Errorf("row %+v", r)
			}
			out = append(out, row{r.Hostname, r.Detail})
		}
		return out
	}

	acme, globex := org(), org()
	behind := device(acme, "behind", "active", 4, 3, "2 hours", "90 minutes")
	device(acme, "current", "active", 4, 4, "2 hours", "90 minutes")
	device(acme, "fresh-bundle", "active", 4, 3, "30 minutes", "29 minutes")
	device(acme, "silent", "active", 4, 3, "2 hours", "30 minutes")
	device(acme, "retired", "retired", 4, 3, "2 hours", "90 minutes")
	device(acme, "never-applied", "active", 1, 0, "3 hours", "2 hours")
	device(globex, "other", "active", 2, 1, "2 hours", "90 minutes")

	want := []row{{"behind", "3 < 4"}, {"never-applied", "0 < 1"}}
	if got := listed(acme); !slices.Equal(got, want) {
		t.Fatalf("acme config_behind %v, want %v", got, want)
	}
	if got := listed(globex); !slices.Equal(got, []row{{"other", "1 < 2"}}) {
		t.Fatalf("globex config_behind %v, want [other 1 < 2]", got)
	}

	// since is the compile time of the newest bundle.
	var since, compiled any
	if err := tx.QueryRow(ctx, `SELECT a.since, b.created_at FROM attention_condition a JOIN bundle b ON b.device_id = a.device_id AND b.version = 4
		WHERE a.kind = 'config_behind' AND a.device_id = $1`, behind).Scan(&since, &compiled); err != nil || since != compiled {
		t.Fatalf("since %v, newest bundle compiled %v: %v", since, compiled, err)
	}

	// Applying the newest bundle clears the condition.
	exec("UPDATE device_status SET applied_bundle_version = 4 WHERE device_id = $1", behind)
	if got := listed(acme); !slices.Equal(got, []row{{"never-applied", "0 < 1"}}) {
		t.Fatalf("acme config_behind %v after the device applied its newest bundle", got)
	}
}

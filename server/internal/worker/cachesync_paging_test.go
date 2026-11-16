package worker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

func (f fixture) key(t *testing.T, device uuid.UUID, keyID string) {
	t.Helper()
	if _, err := f.super.Exec(context.Background(), `INSERT INTO device_identity_key
		(key_id, organization_id, device_id, public_key, key_protection, status) VALUES ($1, $2, $3, '\x01', 'file', 'active')`,
		keyID, f.org, device); err != nil {
		t.Fatal(err)
	}
}

// TestCacheSyncReconcilePages: the reconcile reads the keys in pages keyset-paged by device ID (plan M17 amendment r
// point 6) and still caches every key of a non-pending device exactly as before, also when a page boundary falls
// between two keys of one device, a device has no key, or a page ends on a pending device; keys of pending devices
// stay uncached.
func TestCacheSyncReconcilePages(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	twoKeys, pending := f.device(t, "active"), f.device(t, "pending")
	f.device(t, "active") // no key
	last := f.device(t, "quarantined")
	f.key(t, twoKeys, "a-"+twoKeys.String())
	f.key(t, twoKeys, "b-"+twoKeys.String())
	f.key(t, pending, "p-"+pending.String())
	f.key(t, last, "l-"+last.String())
	if _, err := f.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_seq) VALUES ($1, $2, 9)", last, f.org); err != nil {
		t.Fatal(err)
	}
	vk := valkeytest.Start(t)
	for _, size := range []int{1, 2, 3, ReconcilePageSize} {
		t.Run(fmt.Sprintf("page size %d", size), func(t *testing.T) {
			client := vk.Client(t)
			if err := client.Do(ctx, client.B().Flushall().Build()).Error(); err != nil {
				t.Fatal(err)
			}
			cache := devicecache.New(client)
			s := NewCacheSync(f.pool, cache)
			s.pageSize = size
			if err := s.Reconcile(ctx, f.org); err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]struct {
				device uuid.UUID
				status string
			}{"a-" + twoKeys.String(): {twoKeys, "active"}, "b-" + twoKeys.String(): {twoKeys, "active"},
				"l-" + last.String(): {last, "quarantined"}} {
				k, ok, err := cache.DeviceKey(ctx, key)
				if err != nil || !ok || k.DeviceID != want.device || k.Status != want.status || k.OrganizationID != f.org {
					t.Errorf("key %s: %+v %v %v, want device %s %s", key, k, ok, err, want.device, want.status)
				}
			}
			if _, ok, _ := cache.DeviceKey(ctx, "p-"+pending.String()); ok {
				t.Error("the key of a pending device was cached")
			}
			if n, err := cache.NextSeq(ctx, last); err != nil || n != 10 {
				t.Errorf("the sequence of the last device was not restored from last_seq: %d %v", n, err)
			}
		})
	}
}

// TestCacheSyncReconcileShortTransactionsAtScale: reconciling an organization of 70 000 devices keeps every
// transaction of the cache sync within the 10 s target and far below the 45 s cap (plan M17 amendment r points 1, 6
// and 9), measured from pg_stat_activity like the devstack sampling; every key is cached.
func TestCacheSyncReconcileShortTransactionsAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 70 000 devices")
	}
	const devices = 70000
	const app = "paddock-test-cache-scale"
	f := newFixture(t)
	ctx := context.Background()
	// The package's tests share one database; 70 000 devices left behind would slow every later test.
	t.Cleanup(func() {
		for _, table := range []string{"device_status", "device_identity_key", "device"} {
			if _, err := f.super.Exec(ctx, "DELETE FROM "+table+" WHERE organization_id = $1", f.org); err != nil {
				t.Errorf("remove the seeded %s rows: %v", table, err)
			}
		}
	})
	if _, err := f.super.Exec(ctx, `
		WITH d AS (
			INSERT INTO device (id, organization_id, hostname, state)
			SELECT gen_random_uuid(), $1, 'scale-' || i, CASE WHEN i % 100 = 0 THEN 'pending' ELSE 'active' END
			FROM generate_series(1, $2::int) i RETURNING id, hostname)
		INSERT INTO device_identity_key (key_id, organization_id, device_id, public_key, key_protection, status)
		SELECT 'k-' || hostname, $1, id, '\x01', 'file', 'active' FROM d`, f.org, devices); err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(ctx, `INSERT INTO device_status (device_id, organization_id, last_seq)
		SELECT id, organization_id, 3 FROM device WHERE organization_id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(ctx, "ANALYZE device; ANALYZE device_identity_key; ANALYZE device_status"); err != nil {
		t.Fatal(err)
	}
	pool, err := db.NewOrgPool(ctx, pgtest.SharedPaddock(t).Worker,
		db.Options{ApplicationName: app, MaxConns: 2, TransactionTimeout: db.OrgTransactionTimeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var longest time.Duration
	var mu sync.Mutex
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			var age float64
			if err := f.super.QueryRow(ctx, `SELECT coalesce(max(extract(epoch FROM now() - xact_start)), 0)
				FROM pg_stat_activity WHERE application_name = $1 AND xact_start IS NOT NULL`, app).Scan(&age); err != nil {
				continue
			}
			mu.Lock()
			longest = max(longest, time.Duration(age*float64(time.Second)))
			mu.Unlock()
		}
	}()
	start := time.Now()
	err = NewCacheSync(pool, f.cache).Reconcile(ctx, f.org)
	close(stop)
	<-sampled
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("reconciled %d devices in %s; longest transaction %s", devices, time.Since(start).Round(time.Millisecond), longest)
	if longest > 10*time.Second {
		t.Fatalf("longest cache sync transaction %s, want at most 10 s", longest)
	}
	for _, i := range []int{1, devices/2 + 1, devices - 1} {
		k, ok, err := f.cache.DeviceKey(ctx, fmt.Sprintf("k-scale-%d", i))
		if err != nil || !ok || k.Status != "active" {
			t.Errorf("key of device %d: %+v %v %v", i, k, ok, err)
		}
	}
	if _, ok, _ := f.cache.DeviceKey(ctx, "k-scale-100"); ok {
		t.Error("the key of a pending device was cached")
	}
}

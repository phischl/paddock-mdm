package worker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// failingSettings fails its first calls, then succeeds.
type failingSettings struct {
	failures int32
	calls    atomic.Int32
}

func (s *failingSettings) EnsureSettings(context.Context) ([]string, error) {
	if s.calls.Add(1) <= s.failures {
		return nil, errors.New("fleet: HTTP 502")
	}
	return []string{"features"}, nil
}

// TestInventorySettingsRetryUntilChecked: an unreachable Fleet is retried soon; once the settings are checked, the
// next round waits for the round interval (plan M5a decision 2).
func TestInventorySettingsRetryUntilChecked(t *testing.T) {
	s := &failingSettings{failures: 2}
	i := &Inventory{settings: s, every: time.Hour, retry: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- i.RunSettings(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for s.calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("%d calls after 5 s, want 3", s.calls.Load())
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := s.calls.Load(); n != 3 {
		t.Fatalf("%d calls, want 3 (no retry after success)", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// fakeSource is an inventory system with fixed hosts; it records the since of every listing and the hosts read.
type fakeSource struct {
	hosts    []ports.InventoryHost
	since    []time.Time
	read     []ports.HostRef
	policies int
}

func (s *fakeSource) ListHostsChangedSince(_ context.Context, since time.Time, cursor string) (ports.HostPage, error) {
	s.since = append(s.since, since)
	if cursor == "" { // two pages of one host each
		return ports.HostPage{Hosts: s.hosts[:1], Next: "1"}, nil
	}
	return ports.HostPage{Hosts: s.hosts[1:]}, nil
}

func (s *fakeSource) HostInventory(_ context.Context, ref ports.HostRef) (ports.HostInventory, error) {
	s.read = append(s.read, ref)
	return ports.HostInventory{OSVersion: "Ubuntu 26.04.1 LTS", Software: []ports.SoftwarePackage{{Name: "bash", Version: "5.2", Source: "deb_packages"}}}, nil
}

func (s *fakeSource) ApplyPolicies(_ context.Context, p []ports.PolicyDefinition) error {
	s.policies = len(p)
	return nil
}

// TestInventoryRound (plan M5a decision 6): a round pushes the policies, reads every page, stores the hosts that map
// to a device and skips the others; after the first (full) round only changes since the previous round are listed,
// and every inventoryFullEvery rounds all hosts again.
func TestInventoryRound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	hw := uuid.NewString()
	dev := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, 'lt-inv', 'active', $3)",
		dev, f.org, hw); err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{hosts: []ports.InventoryHost{{Ref: "1", HardwareUUID: strings.ToUpper(hw)}, {Ref: "2", HardwareUUID: uuid.NewString()}}}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	i := NewInventory(nil, src, app.NewInventorySync(runner, f.pool, platform), f.pool, platform, time.Minute)
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	for range inventoryFullEvery + 1 {
		if err := i.Round(sys); err != nil {
			t.Fatal(err)
		}
	}
	if src.policies != 2 || !slices.Equal(src.read[:2], []ports.HostRef{"1", "1"}) {
		t.Fatalf("policies %d, read %v", src.policies, src.read)
	}
	var n int
	if err := f.super.QueryRow(ctx, "SELECT count(*) FROM installed_software WHERE device_id = $1", dev).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d packages, %v", n, err)
	}
	full := 0
	for k, s := range src.since {
		if s.IsZero() {
			full++
		} else if k > 0 && !s.After(src.since[k-2]) {
			t.Fatalf("listing %d since %v, not after the previous round", k, s)
		}
	}
	if full != 4 { // two pages each in rounds 1 and 13
		t.Fatalf("%d full listings in %v", full, src.since)
	}
}

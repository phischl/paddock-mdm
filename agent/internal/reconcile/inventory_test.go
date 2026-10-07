package reconcile_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const fleetdDeb = "fleetd package 1.61.0"

// inventoryFixture is a device without fleetd and a package store that serves fleetdDeb.
func inventoryFixture(t *testing.T) (*fakesys.System, *reconcile.Inventory, *[]event, *[]string) {
	t.Helper()
	sys := fakesys.New()
	var events []event
	var downloads []string
	inv := &reconcile.Inventory{
		Sys: sys, BundlesURL: "https://bundles.example.org:8443",
		Events: &reconcile.Events{Emit: func(typ string, data any) {
			b, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, event{typ, string(b)})
		}},
		Download: func(_ context.Context, url string, limit int64) ([]byte, error) {
			downloads = append(downloads, url)
			if limit < int64(len(fleetdDeb)) {
				return nil, errors.New("too large")
			}
			return []byte(fleetdDeb), nil
		},
	}
	return sys, inv, &events, &downloads
}

func inventoryResource(t *testing.T, secret string, change func(*bundle.Inventory)) bundle.Resource {
	t.Helper()
	sum := sha256.Sum256([]byte(fleetdDeb))
	inv := &bundle.Inventory{FleetURL: "https://fleet.example.org:8443", EnrollSecret: secret, Package: bundle.InventoryPackage{
		Version: "1.61.0", URLPath: "packages/1.2.0/fleet-osquery_1.61.0_amd64.deb", SHA256: hex.EncodeToString(sum[:]),
	}}
	if change != nil {
		change(inv)
	}
	r, err := reconcile.InventoryResource(inv)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestInventoryInstallsAndEnrollsFleetd (plan M5a decision 5): the files come first (the package's postinst starts
// fleetd), then the package from Paddock's package store, checked against its SHA-256; a second apply changes nothing.
func TestInventoryInstallsAndEnrollsFleetd(t *testing.T) {
	ctx := context.Background()
	sys, inv, events, downloads := inventoryFixture(t)
	r := inventoryResource(t, "enroll-secret", nil)
	if changes, err := inv.Plan(ctx, r); err != nil || !slices.Equal(changes, []string{"file " + reconcile.FleetdEnrollFile,
		"file " + reconcile.FleetdEnv, "file " + reconcile.FleetdDropIn, "package 1.61.0"}) {
		t.Fatalf("plan %v, %v", changes, err)
	}
	if res := inv.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if !slices.Equal(*downloads, []string{"https://bundles.example.org:8443/packages/1.2.0/fleet-osquery_1.61.0_amd64.deb"}) {
		t.Fatalf("downloads %v", *downloads)
	}
	if f := sys.Files[reconcile.FleetdEnrollFile]; f == nil || string(f.Data) != "enroll-secret" || f.Mode != 0o600 {
		t.Fatalf("secret %+v", f)
	}
	env := string(sys.Files[reconcile.FleetdEnv].Data)
	for _, line := range []string{"ORBIT_FLEET_URL=https://fleet.example.org:8443", "ORBIT_ENROLL_SECRET_PATH=/opt/orbit/secret.txt",
		"ORBIT_DISABLE_UPDATES=true", "ORBIT_ENABLE_SCRIPTS=false", "ORBIT_FLEET_DESKTOP=false"} {
		if !strings.Contains(env, line+"\n") {
			t.Errorf("orbit.env lacks %s:\n%s", line, env)
		}
	}
	if strings.Contains(env, "enroll-secret") {
		t.Error("the enroll secret is in orbit.env")
	}
	if !strings.Contains(string(sys.Files[reconcile.FleetdDropIn].Data), "EnvironmentFile=/etc/paddock/orbit.env\n") {
		t.Errorf("drop-in %s", sys.Files[reconcile.FleetdDropIn].Data)
	}
	calls := sys.TakeCalls()
	if i := slices.Index(calls, "dpkg -i /var/lib/paddock/packages/fleet-osquery_1.61.0_amd64.deb"); i < 0 ||
		i < slices.Index(calls, "write "+reconcile.FleetdEnrollFile) || slices.Contains(calls, "systemctl restart orbit.service") {
		t.Fatalf("calls %v (files before the package, no extra restart)", calls)
	}
	if sys.Files["/var/lib/paddock/packages/fleet-osquery_1.61.0_amd64.deb"] != nil {
		t.Error("downloaded package left behind")
	}
	if res := inv.Apply(ctx, r); res.Status != reconcile.OK || len(sys.TakeCalls()) != 0 || len(*events) != 0 {
		t.Fatalf("second apply %+v, events %v", res, *events)
	}
}

// TestInventoryWatchesFleetd: a stopped orbit.service is reported once as tamper.service_stopped and started again;
// a changed fleetd file is reported, restored and fleetd restarted (mutual watch, plan M5a decision 5). A new enroll
// secret from the server is no tamper.
func TestInventoryWatchesFleetd(t *testing.T) {
	ctx := context.Background()
	sys, inv, events, _ := inventoryFixture(t)
	r := inventoryResource(t, "enroll-secret", nil)
	inv.Apply(ctx, r)
	sys.TakeCalls()

	sys.Units["orbit.service"].Active = false
	if changes, _ := inv.Plan(ctx, r); !slices.Equal(changes, []string{"systemctl start orbit.service"}) {
		t.Fatalf("plan %v", changes)
	}
	if res := inv.Apply(ctx, r); res.Status != reconcile.Changed || !sys.Units["orbit.service"].Active {
		t.Fatalf("apply %+v", res)
	}
	if got := takeEvents(events); !slices.Equal(got, []event{{protocol.EventTamperServiceStopped, `{"unit":"orbit.service"}`}}) {
		t.Fatalf("events %v", got)
	}

	sys.Files[reconcile.FleetdEnv].Data = []byte("ORBIT_ENABLE_SCRIPTS=true\n")
	if res := inv.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if got := takeEvents(events); !slices.Equal(got, []event{{protocol.EventTamperProtectedFileChanged, `{"file":"/etc/paddock/orbit.env"}`}}) {
		t.Fatalf("events %v", got)
	}
	if calls := sys.TakeCalls(); !slices.Contains(calls, "systemctl daemon-reload") || !slices.Contains(calls, "systemctl restart orbit.service") {
		t.Fatalf("calls %v", calls)
	}

	rotated := inventoryResource(t, "new-secret", nil)
	if res := inv.Apply(ctx, rotated); res.Status != reconcile.Changed || string(sys.Files[reconcile.FleetdEnrollFile].Data) != "new-secret" {
		t.Fatalf("apply %+v", res)
	}
	if got := takeEvents(events); len(got) != 0 {
		t.Fatalf("a new enroll secret reported as tamper: %v", got)
	}
}

// TestInventoryRefusesBadPackages: a package whose SHA-256 differs is never installed; an invalid spec is refused;
// a dpkg run killed at its timeout backs off before the next download.
func TestInventoryRefusesBadPackages(t *testing.T) {
	ctx := context.Background()
	sys, inv, _, downloads := inventoryFixture(t)
	bad := inventoryResource(t, "s", func(i *bundle.Inventory) { i.Package.SHA256 = strings.Repeat("0", 64) })
	if res := inv.Apply(ctx, bad); res.Status != reconcile.Error || !strings.Contains(res.Message, "SHA-256") {
		t.Fatalf("apply %+v", res)
	}
	for _, c := range sys.TakeCalls() {
		if strings.HasPrefix(c, "dpkg") {
			t.Fatalf("dpkg ran: %s", c)
		}
	}
	for _, change := range []func(*bundle.Inventory){
		func(i *bundle.Inventory) { i.Package.URLPath = "packages/../../etc/fleet-osquery_1.61.0_amd64.deb" },
		func(i *bundle.Inventory) { i.Package.URLPath = "packages/1.2.0/paddock-agent_1.61.0_amd64.deb" },
		func(i *bundle.Inventory) { i.FleetURL = "http://fleet.example.org" },
		func(i *bundle.Inventory) { i.EnrollSecret = "a\nORBIT_ENABLE_SCRIPTS=true" },
		func(i *bundle.Inventory) { i.Package.Version = "1.61" },
	} {
		if res := inv.Apply(ctx, inventoryResource(t, "s", change)); res.Status != reconcile.Error {
			t.Fatalf("invalid spec applied: %+v", res)
		}
	}

	now := time.Now()
	inv.Now = func() time.Time { return now }
	sys.DpkgTimeout = true
	*downloads = nil
	r := inventoryResource(t, "s", nil)
	if res := inv.Apply(ctx, r); res.Status != reconcile.Error || !strings.Contains(res.Message, "killed after") {
		t.Fatalf("apply %+v", res)
	}
	sys.DpkgTimeout = false
	if res := inv.Apply(ctx, r); res.Status != reconcile.Error || len(*downloads) != 1 {
		t.Fatalf("retried within the back-off: %+v, downloads %v", res, *downloads)
	}
	now = now.Add(reconcile.PackageTimeout)
	if res := inv.Apply(ctx, r); res.Status != reconcile.Changed || sys.PackageVersion("fleet-osquery") != "1.61.0" {
		t.Fatalf("after the back-off: %+v", res)
	}
}

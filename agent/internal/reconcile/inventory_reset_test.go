package reconcile_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
)

const orbitEnvBefore = "# Managed by Paddock. Do not edit: local changes are reverted.\n" +
	"ORBIT_FLEET_URL=https://fleet.example.org:8443\nORBIT_ENROLL_SECRET_PATH=/opt/orbit/secret.txt\n" +
	"ORBIT_FLEET_CERTIFICATE=/etc/ssl/certs/ca-certificates.crt\nORBIT_DISABLE_UPDATES=true\nORBIT_ENABLE_SCRIPTS=false\n" +
	"ORBIT_FLEET_DESKTOP=false\n"

var enrollmentFiles = []string{"/opt/orbit/secret-orbit-node-key.txt", reconcile.FleetdDeviceTokenFile, "/opt/orbit/osquery.db"}

// TestInventoryOrbitEnvHostIdentifier (ADR 0057, H2): fleetd enrolls under its instance identifier.
func TestInventoryOrbitEnvHostIdentifier(t *testing.T) {
	sys, inv, _, _ := inventoryFixture(t)
	if res := inv.Apply(context.Background(), inventoryResource(t, "enroll-secret", nil)); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	want := orbitEnvBefore + "ORBIT_HOST_IDENTIFIER=instance\n"
	if got := string(sys.Files[reconcile.FleetdEnv].Data); got != want {
		t.Fatalf("orbit.env:\n%s\nwant:\n%s", got, want)
	}
}

// enrolledFleetd is a device whose fleetd was enrolled with the previous orbit.env.
func enrolledFleetd(t *testing.T) (*fakesys.System, *reconcile.Inventory, *[]string) {
	t.Helper()
	sys, inv, _, _ := inventoryFixture(t)
	sys.Packages[reconcile.FleetdPackage] = true
	sys.Versions[reconcile.FleetdPackage] = "1.61.0"
	sys.Units[reconcile.FleetdUnit] = &fakesys.Unit{State: "enabled", Active: true}
	sys.Files[reconcile.FleetdEnv] = &fakesys.File{Data: []byte(orbitEnvBefore), Mode: 0o600}
	sys.Files["/opt/orbit/secret-orbit-node-key.txt"] = &fakesys.File{Data: []byte("key")}
	sys.Files[reconcile.FleetdDeviceTokenFile] = &fakesys.File{Data: []byte("0b6e8a0c-1d2f-4a3b-9c4d-5e6f7a8b9c0d")}
	sys.Files["/opt/orbit/osquery.db/000001.log"] = &fakesys.File{Data: []byte("db")}
	var order []string
	inv.AnnounceReset = func(time.Time) error {
		order = append(order, "announce")
		order = append(order, sys.TakeCalls()...)
		return nil
	}
	return sys, inv, &order
}

// TestInventoryEnrollmentReset (ADR 0057, H2 and H14): an enrolled fleetd whose orbit.env lacks the host identifier
// line is reset once: the reset is announced before anything changes, orbit.service stops, its node key, device token
// and osquery database go, and the new files are written before fleetd restarts. Nothing is reset on a second apply,
// without orbit.env or without the package.
func TestInventoryEnrollmentReset(t *testing.T) {
	ctx := context.Background()
	r := inventoryResource(t, "enroll-secret", nil)

	sys, inv, order := enrolledFleetd(t)
	if res := inv.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	calls := append(*order, sys.TakeCalls()...)
	stop, write, restart := slices.Index(calls, "systemctl stop orbit.service"), slices.Index(calls, "write "+reconcile.FleetdEnv),
		slices.Index(calls, "systemctl restart orbit.service")
	if calls[0] != "announce" || stop < 0 || write < stop || restart < write {
		t.Fatalf("calls %v", calls)
	}
	for _, p := range enrollmentFiles {
		if i := slices.Index(calls, "removeall "+p); i < stop || i > write {
			t.Errorf("%s not removed between stop and write: %v", p, calls)
		}
	}
	for p := range sys.Files {
		if p == "/opt/orbit/secret-orbit-node-key.txt" || p == reconcile.FleetdDeviceTokenFile || p == "/opt/orbit/osquery.db/000001.log" {
			t.Errorf("%s left behind", p)
		}
	}
	*order = nil
	if res := inv.Apply(ctx, r); res.Status != reconcile.OK || len(*order) != 0 || slices.Contains(sys.TakeCalls(), "systemctl stop orbit.service") {
		t.Fatalf("second apply %+v, announced %v", res, *order)
	}

	sys, inv, order = enrolledFleetd(t)
	delete(sys.Files, reconcile.FleetdEnv)
	inv.Apply(ctx, r)
	if len(*order) != 0 || slices.Contains(sys.TakeCalls(), "systemctl stop orbit.service") {
		t.Fatal("reset without orbit.env")
	}

	sys, inv, order = enrolledFleetd(t)
	delete(sys.Packages, reconcile.FleetdPackage)
	inv.Apply(ctx, r)
	if len(*order) != 0 || slices.Contains(sys.TakeCalls(), "systemctl stop orbit.service") {
		t.Fatal("reset without the package")
	}

	sys, inv, _ = enrolledFleetd(t)
	for _, p := range []string{"/opt/orbit/secret-orbit-node-key.txt", reconcile.FleetdDeviceTokenFile, "/opt/orbit/osquery.db/000001.log"} {
		delete(sys.Files, p)
	}
	if res := inv.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("missing paths: %+v", res)
	}
}

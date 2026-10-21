package app_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestInventoryHardware: the hardware facts of the inventory are stored with the inventory reference, shown on the
// device and in the list (NULL without an inventory row), and the device search finds the serial number (plan M8d
// decisions 7 and 8).
func TestInventoryHardware(t *testing.T) {
	h := newInventoryHarness(t)
	org, dev := h.device(t, uuid.Nil, uuid.NewString(), "active")
	_, bare := h.device(t, org, uuid.NewString(), "active")
	api, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	devices := app.NewDevices(nil, api, nil)
	reader := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()),
		Role: principal.RoleOrgAuditor, OrganizationID: org})

	hw := ports.HostHardware{Vendor: "LENOVO", Model: "21HD003LGE", Serial: "PF4XK2QZ", CPUBrand: "i7-1365U", CPUCores: 10,
		MemoryBytes: 33328349184, DiskTotalBytes: 510440000000}
	if err := h.sync.StoreHost(systemCtx(org), dev, "17", ports.HostInventory{OSVersion: "Ubuntu 24.04", Hardware: hw}); err != nil {
		t.Fatal(err)
	}
	got, err := devices.Get(reader, dev)
	if err != nil || got.Hardware == nil {
		t.Fatalf("detail = %+v, %v", got.Hardware, err)
	}
	if got.Hardware.HardwareSerial != "PF4XK2QZ" || got.Hardware.CpuCores != 10 || got.Hardware.DiskTotalBytes != 510440000000 ||
		got.Hardware.MemoryBytes != 33328349184 || got.Hardware.HardwareVendor != "LENOVO" {
		t.Fatalf("hardware %+v", got.Hardware)
	}
	other, err := devices.Get(reader, bare)
	if err != nil || other.Hardware != nil {
		t.Fatalf("device without inventory: %+v, %v", other.Hardware, err)
	}

	pattern := "%pf4xk2%"
	listed, err := devices.List(reader, app.DeviceQuery{Page: app.ListPage{Sort: "hostname", Limit: 10, QPattern: &pattern}})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].Device.ID != dev || listed.Items[0].HardwareSerial == nil ||
		*listed.Items[0].HardwareSerial != "PF4XK2QZ" {
		t.Fatalf("search by serial = %+v, %v", listed.Items, err)
	}

	// A later sync without hardware facts stores empty values, not the old ones.
	if err := h.sync.StoreHost(systemCtx(org), dev, "17", ports.HostInventory{OSVersion: "Ubuntu 24.04"}); err != nil {
		t.Fatal(err)
	}
	if got, err = devices.Get(reader, dev); err != nil || got.Hardware == nil || got.Hardware.HardwareSerial != "" || got.Hardware.CpuCores != 0 {
		t.Fatalf("after an empty sync: %+v, %v", got.Hardware, err)
	}
}

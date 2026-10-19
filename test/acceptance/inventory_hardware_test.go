package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type deviceHardware struct {
	Hardware *struct {
		Vendor         string `json:"vendor"`
		Model          string `json:"model"`
		Serial         string `json:"serial"`
		CPUBrand       string `json:"cpu_brand"`
		CPUCores       int    `json:"cpu_cores"`
		MemoryBytes    int64  `json:"memory_bytes"`
		DiskTotalBytes int64  `json:"disk_total_bytes"`
	} `json:"hardware"`
}

func hardwareOf(t *testing.T, p *env.Portal, deviceID string) deviceHardware {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+deviceID, nil)
	expectStatus(t, res, http.StatusOK, "")
	var out deviceHardware
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestInventoryHardware is gate A2 of plan M8d (AC2): a Fleet host that reports vendor, model, serial number, CPU,
// memory and disk size shows them on its device after a sync round, the serial number is searchable, a host without
// them shows empty values, and a device without an inventory row shows null.
func TestInventoryHardware(t *testing.T) {
	alice := login(t, env.Alice)
	suffix := uniqueSuffix()
	withHW := activeDevice(t, alice, "", "inv-hw-"+suffix)
	without := activeDevice(t, alice, "", "inv-hw-bare-"+suffix)
	unmapped := activeDevice(t, alice, "", "inv-hw-none-"+suffix)
	serial := "PDK221" + suffix
	hosts := []*devicesim.FleetHost{
		enrollFleetHostWithHardware(t, withHW.HardwareUUID(), "inv-hw-"+suffix, devicesim.FleetHardware{
			Vendor: "LENOVO", Model: "21HD003LGE", Serial: serial, CPUBrand: "13th Gen Intel(R) Core(TM) i7-1365U", CPUCores: 10,
			MemoryBytes: 33328349184, DiskTotalGB: 510.44,
		}),
		enrollFleetHost(t, without.HardwareUUID(), "inv-hw-bare-"+suffix, nil),
	}
	for _, h := range hosts {
		if err := h.WaitAnswered(testContext(t, 2*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	var got deviceHardware
	for deadline := time.Now().Add(10 * time.Minute); ; time.Sleep(10 * time.Second) {
		got = hardwareOf(t, alice, withHW.DeviceID)
		if got.Hardware != nil && got.Hardware.Serial != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no hardware facts within 10 minutes: %+v", got.Hardware)
		}
		for _, h := range hosts {
			if _, err := h.Answer(testContext(t, time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
	}
	hw := *got.Hardware
	if hw.Vendor != "LENOVO" || hw.Model != "21HD003LGE" || hw.Serial != serial || hw.CPUBrand != "13th Gen Intel(R) Core(TM) i7-1365U" ||
		hw.CPUCores != 10 || hw.MemoryBytes != 33328349184 || hw.DiskTotalBytes != 510440000000 {
		t.Fatalf("hardware %+v", hw)
	}

	items := devicePage(t, alice, "/api/v1/devices?q="+url.QueryEscape(strings.ToLower(serial[:8])))
	if len(items) != 1 || items[0].ID != withHW.DeviceID {
		t.Fatalf("search by serial prefix lists %+v", items)
	}

	waitDeviceInventoried(t, alice, without.DeviceID)
	bare := hardwareOf(t, alice, without.DeviceID)
	if bare.Hardware == nil || bare.Hardware.Vendor != "" || bare.Hardware.Serial != "" || bare.Hardware.CPUCores < 0 {
		t.Fatalf("host without hardware facts: %+v", bare.Hardware)
	}
	if none := hardwareOf(t, alice, unmapped.DeviceID); none.Hardware != nil {
		t.Fatalf("device without an inventory row: %+v", none.Hardware)
	}
}

// waitDeviceInventoried waits until the sync round stored an inventory row for the device (its hardware is not null).
func waitDeviceInventoried(t *testing.T, p *env.Portal, deviceID string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Minute); hardwareOf(t, p, deviceID).Hardware == nil; time.Sleep(10 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("device %s has no inventory row within 10 minutes", deviceID)
		}
	}
}

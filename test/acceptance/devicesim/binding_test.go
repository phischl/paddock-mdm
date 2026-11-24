package devicesim

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// fakeFleet records the requests of the enrollment endpoints and hands out numbered node keys.
type fakeFleet struct {
	mu    sync.Mutex
	calls []string
	enrol []map[string]any
	keys  int
}

func (f *fakeFleet) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.URL.Path)
		f.keys++
		switch r.URL.Path {
		case "/api/fleet/orbit/enroll":
			f.enrol = append(f.enrol, body)
			_, _ = w.Write([]byte(`{"orbit_node_key": "orbit-key"}`))
		case "/api/fleet/orbit/device_token":
			f.enrol = append(f.enrol, body)
			_, _ = w.Write([]byte(`{}`))
		case "/api/v1/osquery/enroll":
			f.enrol = append(f.enrol, body)
			_, _ = w.Write([]byte(`{"node_key": "key-` + strings.Repeat("x", f.keys) + `"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestEnrollFleetBound (ADR 0057): orbit enrolls, registers the device token and osquery enrolls, in that order and
// under one instance identifier; EnrollFleetAs enrolls under the given identifier; EnrollAgain replaces the node key.
func TestEnrollFleetBound(t *testing.T) {
	f := &fakeFleet{}
	srv := f.server(t)
	ctx := context.Background()
	h, err := EnrollFleetBound(ctx, srv.Client(), srv.URL, "secret", "hw-1", "sim", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.calls, " ") != "/api/fleet/orbit/enroll /api/fleet/orbit/device_token /api/v1/osquery/enroll" {
		t.Fatalf("calls %v", f.calls)
	}
	if f.enrol[0]["osquery_identifier"] != h.Identifier || f.enrol[0]["hardware_uuid"] != "hw-1" ||
		f.enrol[1]["device_auth_token"] != h.Token || f.enrol[1]["orbit_node_key"] != "orbit-key" ||
		f.enrol[2]["host_identifier"] != h.Identifier || h.Identifier == "" || !protocol.ValidFleetDeviceToken(h.Token) {
		t.Fatalf("requests %v, host %+v", f.enrol, h)
	}
	before := h.key()
	if err := h.EnrollAgain(ctx); err != nil || h.key() == before {
		t.Fatalf("enroll again: %v, key %q", err, h.key())
	}
	other, err := EnrollFleetAs(ctx, srv.Client(), srv.URL, "secret", "my-identifier", "hw-1", "sim", nil)
	if err != nil || f.enrol[len(f.enrol)-1]["host_identifier"] != "my-identifier" || other.UUID != "hw-1" {
		t.Fatalf("enroll as: %v, %v", err, f.enrol[len(f.enrol)-1])
	}
}

// TestCheckinFleetDeviceToken (ADR 0057): the check-in carries fleet_device_token only when set, and the hardware UUID
// override replaces the device's UUID.
func TestCheckinFleetDeviceToken(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		_, _ = w.Write([]byte(`{"seq": 1}`))
	}))
	t.Cleanup(srv.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := &Device{Config: protocol.EnrollmentConfig{ServerURL: srv.URL}, Key: key, KeyID: "0123456789abcdef0123456789abcdef", HTTP: srv.Client()}
	ctx := context.Background()
	if _, _, err := d.Checkin(ctx); err != nil {
		t.Fatal(err)
	}
	d.FleetDeviceToken = "0b6e8a0c-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	if _, _, err := d.Checkin(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bodies[0], "fleet_device_token") || !strings.Contains(bodies[1], `"fleet_device_token":"`+d.FleetDeviceToken+`"`) {
		t.Fatalf("bodies %v", bodies)
	}
	if d.HardwareUUID() != "sim-0123456789ab" {
		t.Fatalf("uuid %q", d.HardwareUUID())
	}
	d.HardwareUUIDOverride = "shared"
	if d.HardwareUUID() != "shared" {
		t.Fatalf("override %q", d.HardwareUUID())
	}
}

package acceptance

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/test/acceptance/devicesim"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// createdToken is the answer of POST /api/v1/enrollment-tokens.
type createdToken struct {
	Token struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"token"`
	Secret           string                    `json:"secret"`
	EnrollmentConfig protocol.EnrollmentConfig `json:"enrollment_config"`
}

type tokenOptions struct {
	name        string // default: a unique "gate token …"
	autoApprove bool
	maxUses     int
	groupID     string
	validFor    time.Duration
}

func createToken(t *testing.T, p *env.Portal, o tokenOptions) createdToken {
	t.Helper()
	if o.maxUses == 0 {
		o.maxUses = 10
	}
	if o.validFor == 0 {
		o.validFor = time.Hour
	}
	if o.name == "" {
		o.name = uniqueName("gate token")
	}
	body := map[string]any{"name": o.name, "expires_at": time.Now().Add(o.validFor).UTC().Format(time.RFC3339),
		"max_uses": o.maxUses, "auto_approve": o.autoApprove}
	if o.groupID != "" {
		body["device_group_id"] = o.groupID
	}
	res := call(t, p, http.MethodPost, "/api/v1/enrollment-tokens", body)
	expectStatus(t, res, http.StatusCreated, "")
	var tok createdToken
	if err := res.JSON(&tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

// namedGroup creates a device group with a unique name starting with prefix and returns its ID.
func namedGroup(t *testing.T, p *env.Portal, prefix string) string {
	t.Helper()
	res := call(t, p, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName(prefix)})
	expectStatus(t, res, http.StatusCreated, "")
	return responseID(t, res).String()
}

func newSim(t *testing.T, cfg protocol.EnrollmentConfig) *devicesim.Device {
	t.Helper()
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	d, err := devicesim.New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// enroll enrolls a new simulated device and waits until the enrollment is decided (not processing).
func enroll(t *testing.T, cfg protocol.EnrollmentConfig, hostname string) (*devicesim.Device, protocol.EnrollStatus) {
	t.Helper()
	d := newSim(t, cfg)
	ctx := testContext(t, time.Minute)
	res, err := d.Enroll(ctx, hostname)
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("enroll: %v HTTP %d %s", err, res.Status, res.Body)
	}
	s, err := d.WaitEnrollment(testContext(t, 30*time.Second), func(s protocol.EnrollStatus) bool { return s.Status != protocol.EnrollProcessing })
	if err != nil {
		t.Fatal(err)
	}
	return d, s
}

// activeDevice enrolls a device with an auto-approve token of p and waits until it is active.
func activeDevice(t *testing.T, p *env.Portal, groupID, hostname string) *devicesim.Device {
	t.Helper()
	tok := createToken(t, p, tokenOptions{autoApprove: true, groupID: groupID})
	d, s := enroll(t, tok.EnrollmentConfig, hostname)
	if s.Status != protocol.EnrollActive {
		t.Fatalf("enrollment %+v, want active", s)
	}
	return d
}

// checkinUntil checks in every 2.5 s (within the per-key rate limit) until cond holds for the response.
func checkinUntil(t *testing.T, d *devicesim.Device, timeout time.Duration, cond func(protocol.CheckinResponse) bool) protocol.CheckinResponse {
	t.Helper()
	ctx := testContext(t, timeout+time.Minute)
	deadline := time.Now().Add(timeout)
	for {
		out, res, err := d.Checkin(ctx)
		if err != nil || res.Status != http.StatusOK {
			t.Fatalf("checkin: %v HTTP %d %s", err, res.Status, res.Body)
		}
		if cond(out) {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s; last response %+v", timeout, out)
		}
		time.Sleep(2500 * time.Millisecond)
	}
}

// deviceState is the part of the admin API's device the gates read.
type deviceState struct {
	ID                   string  `json:"id"`
	Hostname             string  `json:"hostname"`
	State                string  `json:"state"`
	BundleVersion        int64   `json:"bundle_version"`
	LastContactAt        *string `json:"last_contact_at"`
	AppliedBundleVersion *int64  `json:"applied_bundle_version"`
}

func getDevice(t *testing.T, p *env.Portal, id string) deviceState {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var d deviceState
	if err := res.JSON(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

// waitDevice polls the admin API until cond holds for the device.
func waitDevice(t *testing.T, p *env.Portal, id string, timeout time.Duration, cond func(deviceState) bool) deviceState {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		d := getDevice(t, p, id)
		if cond(d) {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("device %s: condition not met within %s: %+v", id, timeout, d)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// eventCount counts the audit events of code whose target is the device (portal audit log of viewer).
func eventCount(t *testing.T, viewer *env.Portal, code, deviceID string) int {
	t.Helper()
	events, err := viewer.AuditEvents(testContext(t, time.Minute), code)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Target != nil && e.Target.ID == deviceID {
			n++
		}
	}
	return n
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

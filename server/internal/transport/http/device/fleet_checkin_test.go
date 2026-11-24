package device_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
)

// fleetCheckin sends one check-in with the given fleet fields and returns the published heartbeat; the check-in must
// succeed whatever the fields hold (ADR 0057).
func fleetCheckin(t *testing.T) func(token string, resetAt *time.Time) ingest.Heartbeat {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, "active")
	seq := int64(0)
	return func(token string, resetAt *time.Time) ingest.Heartbeat {
		t.Helper()
		body := checkinBody(0)
		body.FleetDeviceToken, body.FleetEnrollmentResetAt = token, resetAt
		// Values outside the contract are sent on purpose: the gateway must drop them, not fail.
		r := e.send(c, request{method: "POST", path: "/v1/checkin", device: id.String(), body: body, seq: seq,
			skipReqCheck: token != "" && !protocol.ValidFleetDeviceToken(token)})
		if r.status != http.StatusOK {
			t.Fatalf("checkin: %d %s", r.status, r.body)
		}
		var out protocol.CheckinResponse
		_ = json.Unmarshal(r.body, &out)
		seq = out.Seq
		var hb ingest.Heartbeat
		_ = json.Unmarshal(e.pub.last(t).Body, &hb)
		return hb
	}
}

// TestCheckinFleetDeviceToken: a token of the documented format reaches the heartbeat; anything else is dropped and
// the check-in still succeeds.
func TestCheckinFleetDeviceToken(t *testing.T) {
	checkin := fleetCheckin(t)
	const valid = "0b6e8a0c-1d2f-4a3b-9c4d-5e6f7a8b9c0d"
	if got := checkin(valid, nil).FleetDeviceToken; got != valid {
		t.Fatalf("valid token: %q", got)
	}
	for name, token := range map[string]string{
		"absent": "", "upper case": "0B6E8A0C-1D2F-4A3B-9C4D-5E6F7A8B9C0D", "37 characters": valid + "0",
		"path characters": "../../api/latest/fleet/hosts/1/a-9c4d-5e", "trailing newline": valid + "\n",
	} {
		if got := checkin(token, nil).FleetDeviceToken; got != "" {
			t.Errorf("%s: %q passed on", name, got)
		}
	}
}

// TestCheckinFleetEnrollmentResetAt: an announced reset within [receive time - 24 h, receive time + 5 min] reaches
// the heartbeat; outside it is dropped and the check-in still succeeds.
func TestCheckinFleetEnrollmentResetAt(t *testing.T) {
	checkin := fleetCheckin(t)
	at := func(d time.Duration) *time.Time { v := time.Now().Add(d); return &v }
	for name, in := range map[string]*time.Time{"now": at(0), "23 h ago": at(-23 * time.Hour), "4 min ahead": at(4 * time.Minute)} {
		if got := checkin("", in).FleetEnrollmentResetAt; got == nil || !got.Equal(*in) {
			t.Errorf("%s: %v, want %v", name, got, in)
		}
	}
	for name, in := range map[string]*time.Time{"absent": nil, "25 h ago": at(-25 * time.Hour), "6 min ahead": at(6 * time.Minute)} {
		if got := checkin("", in).FleetEnrollmentResetAt; got != nil {
			t.Errorf("%s: %v passed on", name, got)
		}
	}
}

// TestFleetDeviceTokenNeverLogged (ADR 0057, H13): the gateway's check-in logs no device token, valid or not.
func TestFleetDeviceTokenNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	checkin := fleetCheckin(t)
	const valid, invalid = "0b6e8a0c-1d2f-4a3b-9c4d-5e6f7a8b9c0d", "0B6E8A0C-1D2F-4A3B-9C4D-5E6F7A8B9C0D"
	checkin(valid, nil)
	checkin(invalid, nil)
	if strings.Contains(buf.String(), valid) || strings.Contains(strings.ToLower(buf.String()), strings.ToLower(invalid)) {
		t.Fatalf("a device token in the gateway's logs:\n%s", buf.String())
	}
}

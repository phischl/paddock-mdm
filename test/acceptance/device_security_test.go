package acceptance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/test/acceptance/devicesim"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
)

// TestDeviceSecurity is gate D2 (plan M2a §8, AC3): forged, altered, stale, future and replayed requests are
// rejected with the right code; unusable tokens do not enroll; a retired device is locked out; presigned bundle
// URLs cannot be bent to another object and objects cannot be fetched without a signature.
func TestDeviceSecurity(t *testing.T) {
	alice := login(t, env.Alice)
	dev := activeDevice(t, alice, "", "d2-"+uniqueSuffix())
	ctx := testContext(t, 5*time.Minute)
	checkin := devicesim.Request{Method: http.MethodPost, Path: "/v1/checkin", Body: protocol.CheckinRequest{SchemaVersions: []int{1}}}
	with := func(f func(*devicesim.Request)) devicesim.Request {
		r := checkin
		f(&r)
		return r
	}
	stranger := newSim(t, dev.Config)
	cases := map[string]struct {
		d    *devicesim.Device
		req  devicesim.Request
		code string
	}{
		"wrong signature": {dev, with(func(r *devicesim.Request) {
			r.Tamper = func(h *http.Request, _ *[]byte) {
				other, _ := http.NewRequest(http.MethodPost, h.URL.String(), nil)
				_ = protocol.Sign(other, nil, stranger.Key, dev.DeviceID, dev.KeyID, dev.Seq, time.Now())
				h.Header.Set(protocol.HeaderSignature, other.Header.Get(protocol.HeaderSignature))
			}
		}), protocol.CodeInvalidSignature},
		"altered body": {dev, with(func(r *devicesim.Request) {
			r.Tamper = func(_ *http.Request, b *[]byte) {
				*b = bytes.Replace(*b, []byte(`"event_seq_high":0`), []byte(`"event_seq_high":7`), 1)
			}
		}), protocol.CodeInvalidSignature},
		"altered path": {dev, with(func(r *devicesim.Request) {
			r.Tamper = func(h *http.Request, _ *[]byte) { h.URL.RawQuery = "altered=1" }
		}), protocol.CodeInvalidSignature},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := c.d.Do(ctx, c.req)
			expectDeviceProblem(t, res, err, http.StatusUnauthorized, c.code)
		})
	}
	for _, skew := range []time.Duration{-301 * time.Second, 301 * time.Second} {
		t.Run("timestamp "+skew.String(), func(t *testing.T) {
			skewed := dev.Clone()
			skewed.ClockOffset = skew
			res, err := skewed.Do(ctx, checkin)
			expectDeviceProblem(t, res, err, http.StatusUnauthorized, protocol.CodeClockSkew)
			if res.Problem().ServerTime == nil {
				t.Fatal("clock_skew without server_time")
			}
		})
	}
	t.Run("replayed nonce", func(t *testing.T) {
		var sent http.Header
		var body []byte
		res, err := dev.Do(ctx, with(func(r *devicesim.Request) {
			r.Tamper = func(h *http.Request, b *[]byte) { sent, body = h.Header.Clone(), *b }
		}))
		if err != nil || res.Status != http.StatusOK {
			t.Fatalf("original: %v %d %s", err, res.Status, res.Body)
		}
		res, err = dev.Do(ctx, with(func(r *devicesim.Request) {
			r.Tamper = func(h *http.Request, b *[]byte) { h.Header, *b = sent, body }
		}))
		expectDeviceProblem(t, res, err, http.StatusUnauthorized, protocol.CodeReplay)
	})

	t.Run("unusable tokens", func(t *testing.T) { unusableTokens(t, alice) })
	t.Run("presigned urls", func(t *testing.T) { presignedURLs(t, alice, dev) })

	t.Run("retired device", func(t *testing.T) {
		expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/devices/"+dev.DeviceID+"/retire", nil), http.StatusOK, "")
		deadline := time.Now().Add(15 * time.Second)
		for {
			res, err := dev.Do(ctx, checkin)
			if err == nil && res.Problem().Code == protocol.CodeIdentityRevoked {
				expectDeviceProblem(t, res, err, http.StatusUnauthorized, protocol.CodeIdentityRevoked)
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("retired device still answered: %v HTTP %d %s", err, res.Status, res.Body)
			}
			time.Sleep(time.Second)
		}
	})
}

func expectDeviceProblem(t *testing.T, res devicesim.Response, err error, status int, code string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != status || res.Problem().Code != code {
		t.Fatalf("HTTP %d %s, want %d %s: %s", res.Status, res.Problem().Code, status, code, res.Body)
	}
	if status == http.StatusUnauthorized && res.Problem().ServerTime == nil {
		t.Fatal("401 without server_time")
	}
}

// unusableTokens: revoked and expired tokens answer 401 invalid_token; an exhausted token rejects the enrollment.
func unusableTokens(t *testing.T, alice *env.Portal) {
	revoked := createToken(t, alice, tokenOptions{autoApprove: true})
	expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/enrollment-tokens/"+revoked.Token.ID+"/revoke", nil), http.StatusOK, "")
	expired := createToken(t, alice, tokenOptions{autoApprove: true, validFor: 3 * time.Second})
	time.Sleep(4 * time.Second)
	for name, tok := range map[string]createdToken{"revoked": revoked, "expired": expired} {
		d := newSim(t, tok.EnrollmentConfig)
		deadline := time.Now().Add(15 * time.Second) // the revocation reaches Valkey asynchronously
		for {
			res, err := d.Enroll(testContext(t, time.Minute), "d2-"+name)
			if err == nil && res.Status == http.StatusUnauthorized {
				expectDeviceProblem(t, res, err, http.StatusUnauthorized, protocol.CodeInvalidToken)
				break
			}
			if err == nil && res.Status == http.StatusAccepted {
				// Accepted before the cache saw the change: the worker must reject it.
				s, werr := d.WaitEnrollment(testContext(t, 30*time.Second), func(s protocol.EnrollStatus) bool { return s.Status != protocol.EnrollProcessing })
				if werr != nil || s.Status != protocol.EnrollRejected {
					t.Fatalf("%s token enrolled: %+v %v", name, s, werr)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s token: %v HTTP %d %s", name, err, res.Status, res.Body)
			}
			time.Sleep(time.Second)
		}
	}
	single := createToken(t, alice, tokenOptions{autoApprove: true, maxUses: 1})
	if _, s := enroll(t, single.EnrollmentConfig, "d2-first"); s.Status != protocol.EnrollActive {
		t.Fatalf("first use: %+v", s)
	}
	if _, s := enroll(t, single.EnrollmentConfig, "d2-second"); s.Status != protocol.EnrollRejected || s.Reason != "token_exhausted" {
		t.Fatalf("second use of a single-use token: %+v", s)
	}
}

// presignedURLs: the bundle URL of device A, bent to device B's object, and an unsigned object URL are refused.
func presignedURLs(t *testing.T, alice *env.Portal, a *devicesim.Device) {
	b := activeDevice(t, alice, "", "d2-b-"+uniqueSuffix())
	refA := checkinUntil(t, a, 30*time.Second, func(r protocol.CheckinResponse) bool { return r.Bundle != nil }).Bundle
	checkinUntil(t, b, 30*time.Second, func(r protocol.CheckinResponse) bool { return r.Bundle != nil })
	ctx := testContext(t, time.Minute)
	if _, status, err := a.Download(ctx, refA.URL); err != nil || status != http.StatusOK {
		t.Fatalf("own URL: %v HTTP %d", err, status)
	}
	bent := strings.Replace(refA.URL, "/devices/"+a.DeviceID+"/", "/devices/"+b.DeviceID+"/", 1)
	if bent == refA.URL {
		t.Fatalf("URL %s does not contain the device path", refA.URL)
	}
	if _, status, err := a.Download(ctx, bent); err != nil || status != http.StatusForbidden {
		t.Fatalf("bent URL: %v HTTP %d, want 403", err, status)
	}
	unsigned := strings.SplitN(refA.URL, "?", 2)[0]
	if _, status, err := a.Download(ctx, unsigned); err != nil || status != http.StatusForbidden {
		t.Fatalf("unsigned URL: %v HTTP %d, want 403", err, status)
	}
}

// TestCloneDetection is gate D3 (plan M2a §8, AC4): two devices with the same identity and diverging sequence
// numbers quarantine the device within one check-in with exactly one device.clone_suspected event; the quarantined
// device keeps checking in but gets no bundle URL.
func TestCloneDetection(t *testing.T) {
	alice := login(t, env.Alice)
	original := activeDevice(t, alice, "", "d3-"+uniqueSuffix())
	clone := original.Clone()
	ctx := testContext(t, 2*time.Minute)
	for range 2 {
		if _, res, err := original.Checkin(ctx); err != nil || res.Status != http.StatusOK {
			t.Fatalf("original: %v %d", err, res.Status)
		}
	}
	if _, res, err := clone.Checkin(ctx); err != nil || res.Status != http.StatusOK {
		t.Fatalf("clone: %v %d", err, res.Status)
	}
	waitDevice(t, alice, original.DeviceID, 15*time.Second, func(d deviceState) bool { return d.State == "quarantined" })

	// Both keep checking in (fail safe) without bundle URLs, and the clone is reported once.
	for _, d := range []*devicesim.Device{original, clone, original} {
		out, res, err := d.Checkin(ctx)
		if err != nil || res.Status != http.StatusOK || out.Bundle != nil {
			t.Fatalf("quarantined check-in: %v HTTP %d bundle %+v", err, res.Status, out.Bundle)
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	for eventCount(t, alice, "device.clone_suspected", original.DeviceID) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no device.clone_suspected audit event")
		}
		time.Sleep(time.Second)
	}
	time.Sleep(auditSettleDelay)
	if n := eventCount(t, alice, "device.clone_suspected", original.DeviceID); n != 1 {
		t.Fatalf("%d device.clone_suspected events, want exactly 1", n)
	}
}

// TestNoSynchronousDatabasePath is gate D4 (plan M2a §8, AC5): the gateway has no database credential, and with
// PostgreSQL stopped check-ins still succeed; the heartbeat is processed once PostgreSQL is back.
func TestNoSynchronousDatabasePath(t *testing.T) {
	ctx := testContext(t, 10*time.Minute)
	out, err := stack.Compose(ctx, nil, "--profile", "paddock", "config", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Services map[string]json.RawMessage `json:"services"`
	}
	// docker compose may print warnings before the JSON document.
	start := strings.Index(out, "{")
	if start < 0 {
		t.Fatalf("no JSON in docker compose config output: %s", out)
	}
	if err := json.Unmarshal([]byte(out[start:]), &cfg); err != nil {
		t.Fatal(err)
	}
	gw, ok := cfg.Services["paddock-gateway"]
	if !ok {
		t.Fatal("no paddock-gateway service")
	}
	for _, needle := range []string{"db_", "_DB_", "postgres", "DSN"} {
		if strings.Contains(string(gw), needle) {
			t.Fatalf("paddock-gateway configuration mentions %q: %s", needle, gw)
		}
	}

	alice := login(t, env.Alice)
	// Active means the worker cached the key, so the gateway can serve the device without the database. The device
	// has not checked in yet, so its first heartbeat is not coalesced away.
	dev := activeDevice(t, alice, "", "d4-"+uniqueSuffix())
	if d := getDevice(t, alice, dev.DeviceID); d.LastContactAt != nil {
		t.Fatalf("device has a last contact before its first check-in: %+v", d)
	}

	if _, err := stack.Compose(ctx, nil, "stop", "postgres"); err != nil {
		t.Fatal(err)
	}
	restarted := false
	t.Cleanup(func() {
		if !restarted {
			_, _ = stack.Compose(ctx, nil, "start", "postgres")
		}
	})
	outage := time.Now()
	for range 2 {
		if _, res, err := dev.Checkin(ctx); err != nil || res.Status != http.StatusOK {
			t.Fatalf("check-in during the database outage: %v HTTP %d %s", err, res.Status, res.Body)
		}
		time.Sleep(3 * time.Second)
	}
	if _, err := stack.Compose(ctx, nil, "start", "postgres"); err != nil {
		t.Fatal(err)
	}
	restarted = true
	if err := stack.WaitHealthy(ctx); err != nil {
		t.Fatal(err)
	}
	alice = login(t, env.Alice)
	after := waitDevice(t, alice, dev.DeviceID, 2*time.Minute, func(d deviceState) bool {
		if d.LastContactAt == nil {
			return false
		}
		at, err := time.Parse(time.RFC3339Nano, *d.LastContactAt)
		return err == nil && !at.Before(outage.Add(-time.Second))
	})
	t.Logf("last contact %s recorded after the outage", *after.LastContactAt)
}

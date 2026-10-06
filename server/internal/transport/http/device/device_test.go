package device_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/domain/enrollment"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/device"
)

// fakePublisher records published messages; nack makes the broker refuse them.
type fakePublisher struct {
	mu   sync.Mutex
	msgs map[string][]mq.Message // by exchange
	nack bool
}

func (f *fakePublisher) PublishBatch(_ context.Context, exchange string, msgs []mq.Message) ([]error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	res := make([]error, len(msgs))
	for i, m := range msgs {
		if f.nack {
			res[i] = mq.ErrNacked
			continue
		}
		if f.msgs == nil {
			f.msgs = map[string][]mq.Message{}
		}
		f.msgs[exchange] = append(f.msgs[exchange], m)
	}
	return res, nil
}

func (f *fakePublisher) last(t *testing.T) mq.Message {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	ms := f.msgs[mq.ExchangeIngest]
	if len(ms) == 0 {
		t.Fatal("nothing published")
	}
	return ms[len(ms)-1]
}

type fakePresigner struct{}

func (fakePresigner) PresignGet(_ context.Context, key string, ttl time.Duration) (string, error) {
	return "https://bundles.test/paddock-bundles/" + key + "?X-Amz-Expires=" + strconv.Itoa(int(ttl.Seconds())), nil
}

func (fakePresigner) PresignPut(_ context.Context, key string, ttl time.Duration) (string, error) {
	return "https://bundles.test/paddock-escrow/" + key + "?X-Amz-Expires=" + strconv.Itoa(int(ttl.Seconds())), nil
}

type env struct {
	t       *testing.T
	handler http.Handler
	cache   *devicecache.Cache
	pub     *fakePublisher
	router  routers.Router
	now     time.Time
	org     uuid.UUID
}

func newEnv(t *testing.T, perKey, perIP int) *env {
	t.Helper()
	e := &env{t: t, cache: devicecache.New(valkeytest.Start(t).Client(t)), pub: &fakePublisher{},
		now: time.Now().Truncate(time.Second), org: uuid.New()}
	e.handler = device.NewHandler(device.Deps{
		Cache: e.cache, Publisher: e.pub, Presigner: fakePresigner{}, Artifacts: fakePresigner{}, Escrow: fakePresigner{},
		PerKeyLimit: perKey, PerIPLimit: perIP,
		Now: func() time.Time { return e.now }, CheckinDelay: func() int { return 300 },
	})
	_, file, _, _ := runtime.Caller(0)
	doc, err := openapi3.NewLoader().LoadFromFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "api", "openapi", "device.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc.Servers = openapi3.Servers{{URL: "https://device.test"}}
	if e.router, err = legacy.NewRouter(doc); err != nil {
		t.Fatal(err)
	}
	return e
}

// client is a device key.
type client struct {
	key   *ecdsa.PrivateKey
	spki  []byte
	keyID string
}

func newClient(t *testing.T) client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := protocol.MarshalPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return client{key: key, spki: spki, keyID: protocol.KeyID(spki)}
}

// request is one signed device request; mutate changes it after signing.
type request struct {
	method, path, signedPath string
	body                     any
	device                   string
	seq                      int64
	signedAt                 time.Time
	mutate                   func(r *http.Request, body *[]byte)
	skipReqCheck             bool
}

type result struct {
	status int
	header http.Header
	body   []byte
}

func (r result) problem(t *testing.T) protocol.Problem {
	t.Helper()
	var p protocol.Problem
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatalf("not a problem: %s", r.body)
	}
	return p
}

func (e *env) send(c client, rq request) result {
	e.t.Helper()
	var body []byte
	if rq.body != nil {
		body, _ = json.Marshal(rq.body)
	}
	signedPath := rq.signedPath
	if signedPath == "" {
		signedPath = rq.path
	}
	at := rq.signedAt
	if at.IsZero() {
		at = e.now
	}
	signReq := httptest.NewRequest(rq.method, "https://device.test"+signedPath, nil)
	if err := protocol.Sign(signReq, body, c.key, rq.device, c.keyID, rq.seq, at); err != nil {
		e.t.Fatal(err)
	}
	req := httptest.NewRequest(rq.method, "https://device.test"+rq.path, nil)
	req.Header = signReq.Header.Clone()
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if rq.mutate != nil {
		rq.mutate(req, &body)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	route, params, err := e.router.FindRoute(req)
	if err != nil {
		e.t.Fatalf("%s %s is not in the device contract: %v", rq.method, rq.path, err)
	}
	in := &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route,
		Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc}}
	if !rq.skipReqCheck {
		if err := openapi3filter.ValidateRequest(context.Background(), in); err != nil {
			e.t.Fatalf("request violates the contract: %v", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	res := result{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
	out := &openapi3filter.ResponseValidationInput{RequestValidationInput: in, Status: res.status, Header: res.header,
		Options: &openapi3filter.Options{IncludeResponseStatus: true}}
	out.SetBodyBytes(res.body)
	if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
		e.t.Fatalf("%s %s: response %d violates the contract: %v\n%s", rq.method, rq.path, res.status, err, res.body)
	}
	return res
}

func (e *env) expectProblem(r result, status int, code string) {
	e.t.Helper()
	if r.status != status {
		e.t.Fatalf("status %d, want %d: %s", r.status, status, r.body)
	}
	p := r.problem(e.t)
	if p.Code != code {
		e.t.Fatalf("code %s, want %s", p.Code, code)
	}
	if status == http.StatusUnauthorized && p.ServerTime == nil {
		e.t.Fatal("401 without server_time")
	}
}

// token caches an enrollment token and returns its secret.
func (e *env) token(revoked bool, expires time.Time) string {
	e.t.Helper()
	secret, hash, _ := enrollment.NewSecret()
	if err := e.cache.PutToken(context.Background(), hash, devicecache.Token{OrganizationID: e.org, Revoked: revoked, ExpiresAt: expires}, e.now); err != nil {
		e.t.Fatal(err)
	}
	return secret
}

func (e *env) enrollBody(c client, secret string) protocol.EnrollRequest {
	return protocol.EnrollRequest{Token: secret, PublicKey: base64.StdEncoding.EncodeToString(c.spki), KeyProtection: "file",
		Hostname: "lt-test", AgentVersion: "0.1.0", OSRelease: map[string]string{"id": "ubuntu"}}
}

// enrolled caches an identity key as the worker does and returns the device ID.
func (e *env) enrolled(c client, status string) uuid.UUID {
	e.t.Helper()
	id := uuid.New()
	if err := e.cache.PutDeviceKey(context.Background(), c.keyID, devicecache.DeviceKey{
		DeviceID: id, OrganizationID: e.org, Status: status, PublicKey: c.spki,
	}); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func checkinBody(applied int64) protocol.CheckinRequest {
	return protocol.CheckinRequest{AppliedBundleVersion: applied, AgentVersion: "0.1.0", SchemaVersions: []int{1},
		Health: json.RawMessage(`{"reconcile":"ok"}`)}
}

func TestEnrollFlow(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	secret := e.token(false, e.now.Add(time.Hour))
	res := e.send(c, request{method: "POST", path: "/v1/enroll", device: "enroll", body: e.enrollBody(c, secret)})
	if res.status != http.StatusAccepted {
		t.Fatalf("enroll: %d %s", res.status, res.body)
	}
	var acc protocol.EnrollAccepted
	_ = json.Unmarshal(res.body, &acc)
	msg := e.pub.last(t)
	var in ingest.Enroll
	if err := json.Unmarshal(msg.Body, &in); err != nil {
		t.Fatal(err)
	}
	if msg.MessageID != acc.EnrollmentID || msg.RoutingKey != "ingest.enroll."+e.org.String() || in.KeyID != c.keyID ||
		in.OrganizationID != e.org || !bytes.Equal(in.TokenSHA256, enrollment.HashSecret(secret)) || in.Hostname != "lt-test" {
		t.Fatalf("published %s %s %+v", msg.MessageID, msg.RoutingKey, in)
	}

	status := func() protocol.EnrollStatus {
		t.Helper()
		r := e.send(c, request{method: "GET", path: "/v1/enroll/" + acc.EnrollmentID, device: "enroll"})
		if r.status != http.StatusOK {
			t.Fatalf("status: %d %s", r.status, r.body)
		}
		var s protocol.EnrollStatus
		_ = json.Unmarshal(r.body, &s)
		return s
	}
	if s := status(); s.Status != "processing" {
		t.Fatalf("status %+v", s)
	}
	id := uuid.MustParse(acc.EnrollmentID)
	if err := e.cache.PutEnrollment(context.Background(), id, devicecache.Enrollment{KeyID: c.keyID, PublicKey: c.spki,
		OrganizationID: e.org, Status: "pending", DeviceID: id}, e.now); err != nil {
		t.Fatal(err)
	}
	if s := status(); s.Status != "pending" || s.DeviceID != acc.EnrollmentID {
		t.Fatalf("status %+v", s)
	}
	// An administrator approves: the worker caches the key, which makes the enrollment active.
	if err := e.cache.PutDeviceKey(context.Background(), c.keyID, devicecache.DeviceKey{DeviceID: id, OrganizationID: e.org,
		Status: "active", PublicKey: c.spki}); err != nil {
		t.Fatal(err)
	}
	if s := status(); s.Status != "active" {
		t.Fatalf("status %+v", s)
	}

	other := newClient(t)
	e.expectProblem(e.send(other, request{method: "GET", path: "/v1/enroll/" + acc.EnrollmentID, device: "enroll"}),
		http.StatusUnauthorized, "invalid_signature")
	e.expectProblem(e.send(c, request{method: "GET", path: "/v1/enroll/" + uuid.NewString(), device: "enroll"}),
		http.StatusNotFound, "not_found")
}

func TestEnrollRejections(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	valid := e.token(false, e.now.Add(time.Hour))
	cases := map[string]struct {
		secret string
		mutate func(r *http.Request, body *[]byte)
		device string
		status int
		code   string
	}{
		"unknown token":  {secret: "guessed", status: 401, code: "invalid_token"},
		"revoked token":  {secret: e.token(true, e.now.Add(time.Hour)), status: 401, code: "invalid_token"},
		"expired token":  {secret: e.token(false, e.now.Add(time.Second)), status: 401, code: "invalid_token"},
		"device header":  {secret: valid, device: uuid.NewString(), status: 401, code: "invalid_signature"},
		"key of another": {secret: valid, status: 401, code: "invalid_signature", mutate: func(r *http.Request, _ *[]byte) { r.Header.Set(protocol.HeaderKeyID, newClient(t).keyID) }},
		"tampered body":  {secret: valid, status: 401, code: "invalid_signature", mutate: func(_ *http.Request, b *[]byte) { *b = bytes.Replace(*b, []byte("lt-test"), []byte("lt-evil"), 1) }},
		"invalid json":   {secret: valid, status: 400, code: "invalid_request", mutate: func(r *http.Request, b *[]byte) { *b = []byte("{"); resign(t, r, c, *b) }},
		"bad hostname": {secret: valid, status: 400, code: "invalid_request", mutate: func(r *http.Request, b *[]byte) {
			*b = bytes.Replace(*b, []byte(`"lt-test"`), []byte(`"a\nb"`), 1)
			resign(t, r, c, *b)
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dev := tc.device
			if dev == "" {
				dev = "enroll"
			}
			if name == "expired token" {
				defer func(now time.Time) { e.now = now }(e.now)
				e.now = e.now.Add(2 * time.Second)
			}
			res := e.send(c, request{method: "POST", path: "/v1/enroll", device: dev, body: e.enrollBody(c, tc.secret), mutate: tc.mutate, skipReqCheck: true})
			e.expectProblem(res, tc.status, tc.code)
		})
	}
}

// resign signs the request again for a changed body, so the test reaches the check after the signature.
func resign(t *testing.T, r *http.Request, c client, body []byte) {
	t.Helper()
	h, _ := protocol.ParseHeaders(r.Header)
	signReq := httptest.NewRequest(r.Method, r.URL.String(), nil)
	if err := protocol.Sign(signReq, body, c.key, h.Device, h.KeyID, h.Seq, time.Unix(h.Timestamp, 0)); err != nil {
		t.Fatal(err)
	}
	r.Header = signReq.Header.Clone()
}

func TestCheckinAuthFailures(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, "active")
	stranger := newClient(t)
	ok := request{method: "POST", path: "/v1/checkin", device: id.String(), body: checkinBody(0)}
	if r := e.send(c, ok); r.status != http.StatusOK {
		t.Fatalf("baseline: %d %s", r.status, r.body)
	}
	with := func(f func(*request)) request {
		r := ok
		f(&r)
		return r
	}
	cases := map[string]struct {
		c    client
		req  request
		code string
	}{
		"missing header": {c, with(func(r *request) {
			r.mutate = func(h *http.Request, _ *[]byte) { h.Header.Del(protocol.HeaderNonce) }
			r.skipReqCheck = true
		}), "invalid_signature"},
		"malformed header": {c, with(func(r *request) {
			r.mutate = func(h *http.Request, _ *[]byte) { h.Header.Set(protocol.HeaderSeq, "-1") }
			r.skipReqCheck = true
		}), "invalid_signature"},
		"unknown key":     {stranger, ok, "invalid_signature"},
		"other device id": {c, with(func(r *request) { r.device = uuid.NewString() }), "invalid_signature"},
		"wrong signature": {c, with(func(r *request) {
			r.mutate = func(h *http.Request, _ *[]byte) {
				other := httptest.NewRequest("POST", "https://device.test/v1/checkin", nil)
				_ = protocol.Sign(other, nil, stranger.key, id.String(), c.keyID, 0, e.now)
				h.Header.Set(protocol.HeaderSignature, other.Header.Get(protocol.HeaderSignature))
			}
		}), "invalid_signature"},
		"altered body": {c, with(func(r *request) {
			r.mutate = func(_ *http.Request, b *[]byte) {
				*b = bytes.Replace(*b, []byte(`"applied_bundle_version":0`), []byte(`"applied_bundle_version":9`), 1)
			}
		}), "invalid_signature"},
		"altered path":     {c, with(func(r *request) { r.signedPath = "/v1/events" }), "invalid_signature"},
		"altered query":    {c, with(func(r *request) { r.path, r.signedPath = "/v1/checkin?a=2", "/v1/checkin?a=1" }), "invalid_signature"},
		"old timestamp":    {c, with(func(r *request) { r.signedAt = e.now.Add(-301 * time.Second) }), "clock_skew"},
		"future timestamp": {c, with(func(r *request) { r.signedAt = e.now.Add(301 * time.Second) }), "clock_skew"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e.expectProblem(e.send(tc.c, tc.req), http.StatusUnauthorized, tc.code)
		})
	}
	for _, offset := range []time.Duration{-300 * time.Second, 300 * time.Second} {
		if r := e.send(c, with(func(r *request) { r.signedAt = e.now.Add(offset) })); r.status != http.StatusOK {
			t.Errorf("timestamp %s at the boundary rejected: %s", offset, r.body)
		}
	}

	t.Run("replayed nonce", func(t *testing.T) {
		var captured http.Header
		first := with(func(r *request) {
			r.mutate = func(h *http.Request, _ *[]byte) { captured = h.Header.Clone() }
		})
		if r := e.send(c, first); r.status != http.StatusOK {
			t.Fatalf("first: %s", r.body)
		}
		replay := with(func(r *request) {
			r.mutate = func(h *http.Request, _ *[]byte) { h.Header = captured }
		})
		e.expectProblem(e.send(c, replay), http.StatusUnauthorized, "replay")
	})

	for _, status := range []string{"retired", "rejected", "revoked"} {
		t.Run(status, func(t *testing.T) {
			d := newClient(t)
			dev := e.enrolled(d, status)
			e.expectProblem(e.send(d, request{method: "POST", path: "/v1/checkin", device: dev.String(), body: checkinBody(0)}),
				http.StatusUnauthorized, "identity_revoked")
		})
	}
}

func TestCheckinSeqBundleAndClone(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, "active")
	checkin := func(applied, seq int64) protocol.CheckinResponse {
		t.Helper()
		r := e.send(c, request{method: "POST", path: "/v1/checkin", device: id.String(), body: checkinBody(applied), seq: seq})
		if r.status != http.StatusOK {
			t.Fatalf("checkin: %d %s", r.status, r.body)
		}
		var out protocol.CheckinResponse
		_ = json.Unmarshal(r.body, &out)
		return out
	}
	first := checkin(0, 0)
	if first.Seq != 1 || first.Bundle != nil || first.NextCheckinS != 300 {
		t.Fatalf("first checkin %+v", first)
	}
	var hb ingest.Heartbeat
	msg := e.pub.last(t)
	_ = json.Unmarshal(msg.Body, &hb)
	if msg.RoutingKey != "ingest.heartbeat."+e.org.String() || hb.DeviceID != id || hb.Seq != 1 || hb.CloneSuspected ||
		string(hb.Health) != `{"reconcile":"ok"}` || !slices.Equal(hb.SchemaVersions, []int{1}) {
		t.Fatalf("heartbeat %s %+v", msg.RoutingKey, hb)
	}
	// Schema versions are passed on bounded: plausible, distinct, at most 16 (plan M3a decision 14a).
	noisy := checkinBody(0)
	noisy.SchemaVersions = []int{2, 1, 2, 0, -5, 1001}
	if r := e.send(c, request{method: "POST", path: "/v1/checkin", device: id.String(), body: noisy, seq: 1}); r.status != http.StatusOK {
		t.Fatalf("checkin: %d", r.status)
	}
	hb = ingest.Heartbeat{}
	_ = json.Unmarshal(e.pub.last(t).Body, &hb)
	if !slices.Equal(hb.SchemaVersions, []int{2, 1}) {
		t.Fatalf("schema versions %v", hb.SchemaVersions)
	}

	if err := e.cache.PutBundlePointer(context.Background(), id, devicecache.BundlePointer{Version: 3, SHA256: "abc", ObjectKey: "org/o/devices/d/bundles/3.dsse"}); err != nil {
		t.Fatal(err)
	}
	if out := checkin(0, 2); out.Bundle == nil || out.Bundle.Version != 3 || out.Bundle.SHA256 != "abc" ||
		!strings.Contains(out.Bundle.URL, "bundles/3.dsse") || !strings.Contains(out.Bundle.URL, "X-Amz-Expires=120") {
		t.Fatalf("bundle %+v", out.Bundle)
	}
	if out := checkin(3, 3); out.Bundle != nil {
		t.Fatalf("current device got a bundle %+v", out.Bundle)
	}

	// A lost response is tolerated; a clone that is two behind is reported.
	_ = checkin(3, 3)
	hb = ingest.Heartbeat{}
	_ = json.Unmarshal(e.pub.last(t).Body, &hb)
	if hb.CloneSuspected {
		t.Fatal("tolerance of one lost response violated")
	}
	_ = checkin(3, 2)
	_ = json.Unmarshal(e.pub.last(t).Body, &hb)
	if !hb.CloneSuspected || hb.ReportedSeq != 2 || hb.Seq != 6 {
		t.Fatalf("clone not suspected: %+v", hb)
	}

	q := newClient(t)
	qid := e.enrolled(q, "quarantined")
	if err := e.cache.PutBundlePointer(context.Background(), qid, devicecache.BundlePointer{Version: 1, SHA256: "x", ObjectKey: "k"}); err != nil {
		t.Fatal(err)
	}
	r := e.send(q, request{method: "POST", path: "/v1/checkin", device: qid.String(), body: checkinBody(0)})
	var out protocol.CheckinResponse
	_ = json.Unmarshal(r.body, &out)
	if r.status != http.StatusOK || out.Bundle != nil {
		t.Fatalf("quarantined device: %d %+v", r.status, out)
	}
}

// envelope is a stand-in for a signed command envelope; the gateway passes envelopes through unchanged.
func envelope(id uuid.UUID) json.RawMessage {
	return json.RawMessage(`{"payloadType":"application/vnd.paddock.command.v1+json","payload":"` +
		base64.StdEncoding.EncodeToString([]byte(id.String())) + `","signatures":[{"keyid":"command-signing:v1","sig":"AA=="}]}`)
}

// TestCheckinCommands: the check-in carries the unexpired commands of an active device oldest first and reports
// them as delivered in the heartbeat; a quarantined device gets none (plan M4a decision 3).
func TestCheckinCommands(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, "active")
	ctx := context.Background()
	first, second, expired := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for cmd, expires := range map[uuid.UUID]time.Time{first: e.now.Add(time.Hour), second: e.now.Add(time.Hour), expired: e.now} {
		if err := e.cache.PutCommand(ctx, id, cmd, devicecache.Command{ExpiresAt: expires, Envelope: envelope(cmd)}); err != nil {
			t.Fatal(err)
		}
	}
	r := e.send(c, request{method: "POST", path: "/v1/checkin", device: id.String(), body: checkinBody(0)})
	var out protocol.CheckinResponse
	if err := json.Unmarshal(r.body, &out); err != nil || r.status != http.StatusOK {
		t.Fatalf("checkin: %d %s", r.status, r.body)
	}
	if len(out.Commands) != 2 || string(out.Commands[0]) != string(envelope(first)) || string(out.Commands[1]) != string(envelope(second)) {
		t.Fatalf("commands %s", out.Commands)
	}
	var hb ingest.Heartbeat
	_ = json.Unmarshal(e.pub.last(t).Body, &hb)
	if !slices.Equal(hb.DeliveredCommands, []uuid.UUID{first, second}) {
		t.Fatalf("delivered %v", hb.DeliveredCommands)
	}

	q := newClient(t)
	qid := e.enrolled(q, "quarantined")
	if err := e.cache.PutCommand(ctx, qid, first, devicecache.Command{ExpiresAt: e.now.Add(time.Hour), Envelope: envelope(first)}); err != nil {
		t.Fatal(err)
	}
	r = e.send(q, request{method: "POST", path: "/v1/checkin", device: qid.String(), body: checkinBody(0)})
	out = protocol.CheckinResponse{}
	if err := json.Unmarshal(r.body, &out); err != nil || r.status != http.StatusOK || out.Commands == nil || len(out.Commands) != 0 {
		t.Fatalf("quarantined device: %d %s", r.status, r.body)
	}
}

// TestCommandResult: a result is accepted for a pending command of the signing device, published once per status,
// repeated idempotently and refused with another status or for any other command (plan M4a decision 3).
func TestCommandResult(t *testing.T) {
	e := newEnv(t, 0, 0)
	c, other := newClient(t), newClient(t)
	id, otherID := e.enrolled(c, "active"), e.enrolled(other, "active")
	ctx := context.Background()
	cmd := uuid.Must(uuid.NewV7())
	if err := e.cache.PutCommand(ctx, id, cmd, devicecache.Command{ExpiresAt: e.now.Add(time.Hour), Envelope: envelope(cmd)}); err != nil {
		t.Fatal(err)
	}
	post := func(c client, dev uuid.UUID, cmd uuid.UUID, body any) result {
		t.Helper()
		return e.send(c, request{method: "POST", path: "/v1/commands/" + cmd.String() + "/result", device: dev.String(), body: body})
	}
	ok := protocol.CommandResult{Status: "succeeded", Result: json.RawMessage(`{"generation":2}`)}

	e.expectProblem(post(other, otherID, cmd, ok), http.StatusNotFound, "not_found")
	e.expectProblem(post(c, id, uuid.Must(uuid.NewV7()), ok), http.StatusNotFound, "not_found")
	if r := post(c, id, cmd, ok); r.status != http.StatusAccepted {
		t.Fatalf("result: %d %s", r.status, r.body)
	}
	msg := e.pub.last(t)
	var in ingest.CommandResult
	if err := json.Unmarshal(msg.Body, &in); err != nil || msg.RoutingKey != "ingest.command_result."+e.org.String() ||
		msg.MessageID != cmd.String()+":succeeded" || in.CommandID != cmd || in.DeviceID != id || in.Status != "succeeded" ||
		string(in.Result) != `{"generation":2}` {
		t.Fatalf("published %s %s %s", msg.RoutingKey, msg.MessageID, msg.Body)
	}
	// The worker removes the command once it recorded the result; the gateway still answers repeated posts.
	if err := e.cache.DeleteCommand(ctx, id, cmd); err != nil {
		t.Fatal(err)
	}
	published := len(e.pub.msgs[mq.ExchangeIngest])
	if r := post(c, id, cmd, ok); r.status != http.StatusAccepted || len(e.pub.msgs[mq.ExchangeIngest]) != published {
		t.Fatalf("repeated result: %d %s, %d messages", r.status, r.body, len(e.pub.msgs[mq.ExchangeIngest])-published)
	}
	e.expectProblem(post(c, id, cmd, protocol.CommandResult{Status: "failed"}), http.StatusConflict, "conflict")
	e.expectProblem(post(other, otherID, cmd, ok), http.StatusNotFound, "not_found")

	invalid := uuid.Must(uuid.NewV7())
	if err := e.cache.PutCommand(ctx, id, invalid, devicecache.Command{ExpiresAt: e.now.Add(time.Hour), Envelope: envelope(invalid)}); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown status": `{"status":"done"}`, "result not an object": `{"status":"failed","result":[1]}`,
		"result too large": `{"status":"failed","result":{"x":"` + strings.Repeat("a", protocol.MaxCommandResult) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := e.send(c, request{method: "POST", path: "/v1/commands/" + invalid.String() + "/result", device: id.String(),
				body: json.RawMessage(body), skipReqCheck: true})
			e.expectProblem(r, http.StatusBadRequest, "invalid_request")
		})
	}
}

// TestEscrow: an upload is validated and published to ingest.escrow; the status is pending until the worker sets
// it, and another device's status is not found (plan M4a decision 12).
func TestEscrow(t *testing.T) {
	e := newEnv(t, 0, 0)
	c, other := newClient(t), newClient(t)
	id, otherID := e.enrolled(c, "active"), e.enrolled(other, "active")
	escrowID := uuid.Must(uuid.NewV7())
	ct := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 512))
	body := map[string]any{"escrow_id": escrowID.String(), "kind": "admin_password", "generation": 2, "key_version": 1, "ciphertext": ct}
	r := e.send(c, request{method: "POST", path: "/v1/escrow", device: id.String(), body: body})
	if r.status != http.StatusAccepted || !strings.Contains(string(r.body), escrowID.String()) {
		t.Fatalf("upload: %d %s", r.status, r.body)
	}
	msg := e.pub.last(t)
	var in ingest.Escrow
	if err := json.Unmarshal(msg.Body, &in); err != nil || msg.RoutingKey != "ingest.escrow."+e.org.String() || msg.MessageID != escrowID.String() ||
		in.DeviceID != id || in.Generation != 2 || in.KeyVersion != 1 || len(in.Ciphertext) != 512 {
		t.Fatalf("published %s %s %+v", msg.RoutingKey, msg.MessageID, in)
	}
	status := func(c client, dev uuid.UUID) result {
		t.Helper()
		return e.send(c, request{method: "GET", path: "/v1/escrow/" + escrowID.String(), device: dev.String()})
	}
	if r := status(c, id); r.status != http.StatusOK || !strings.Contains(string(r.body), `"pending"`) {
		t.Fatalf("status before the worker: %d %s", r.status, r.body)
	}
	if err := e.cache.PutEscrowStatus(context.Background(), escrowID, id, "stored"); err != nil {
		t.Fatal(err)
	}
	if r := status(c, id); r.status != http.StatusOK || !strings.Contains(string(r.body), `"stored"`) {
		t.Fatalf("status after the worker: %d %s", r.status, r.body)
	}
	e.expectProblem(status(other, otherID), http.StatusNotFound, "not_found")

	for name, mutate := range map[string]func(map[string]any){
		"kind":       func(b map[string]any) { b["kind"] = "luks_keyfile" },
		"header":     func(b map[string]any) { b["kind"] = "luks_header" },
		"extra":      func(b map[string]any) { b["sha256"] = strings.Repeat("a", 64) },
		"generation": func(b map[string]any) { b["generation"] = 0 },
		"escrow_id":  func(b map[string]any) { b["escrow_id"] = "x" },
		"ciphertext": func(b map[string]any) { b["ciphertext"] = base64.StdEncoding.EncodeToString(make([]byte, 4097)) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := map[string]any{}
			for k, v := range body {
				bad[k] = v
			}
			mutate(bad)
			r := e.send(c, request{method: "POST", path: "/v1/escrow", device: id.String(), body: bad, skipReqCheck: true})
			e.expectProblem(r, http.StatusBadRequest, "invalid_request")
		})
	}
}

func TestCheckinAgentUpdate(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, "active")
	seq := int64(0)
	checkin := func(arch, version string) *protocol.AgentUpdate {
		t.Helper()
		body := checkinBody(0)
		body.Arch, body.AgentVersion = arch, version
		r := e.send(c, request{method: "POST", path: "/v1/checkin", device: id.String(), body: body, seq: seq})
		if r.status != http.StatusOK {
			t.Fatalf("checkin: %d %s", r.status, r.body)
		}
		var out protocol.CheckinResponse
		_ = json.Unmarshal(r.body, &out)
		seq = out.Seq
		return out.AgentUpdate
	}
	if u := checkin("amd64", "1.0.0"); u != nil {
		t.Fatalf("offer without a rollout: %+v", u)
	}
	offer := agentrelease.Offer{Version: "1.1.0", Status: agentrelease.RolloutRunning, Waves: []int{100},
		Artifacts: map[string]agentrelease.Artifact{"amd64": {SHA256: "ab12", Size: 42, Minisig: "c2ln", ObjectKey: "releases/1.1.0/amd64/paddockd"}}}
	if err := e.cache.PutOffer(context.Background(), &offer); err != nil {
		t.Fatal(err)
	}
	u := checkin("amd64", "1.0.0")
	if u == nil || u.Version != "1.1.0" || u.SHA256 != "ab12" || u.Size != 42 || u.Minisig != "c2ln" ||
		!strings.Contains(u.URL, "releases/1.1.0/amd64/paddockd") || !strings.Contains(u.URL, "X-Amz-Expires=300") {
		t.Fatalf("offer %+v", u)
	}
	for _, tc := range []struct{ arch, version string }{{"amd64", "1.1.0"}, {"arm64", "1.0.0"}, {"", "1.0.0"}} {
		if u := checkin(tc.arch, tc.version); u != nil {
			t.Fatalf("arch %q version %q offered %+v", tc.arch, tc.version, u)
		}
	}
	offer.Status = agentrelease.RolloutHalted
	_ = e.cache.PutOffer(context.Background(), &offer)
	if u := checkin("amd64", "1.0.0"); u != nil {
		t.Fatalf("halted rollout offered %+v", u)
	}
	offer.Status, offer.Waves = agentrelease.RolloutRunning, []int{agentrelease.Bucket(id), 100}
	_ = e.cache.PutOffer(context.Background(), &offer)
	if u := checkin("amd64", "1.0.0"); u != nil {
		t.Fatal("offered to a device outside the current wave")
	}
	_ = e.cache.PutOffer(context.Background(), nil)
	if u := checkin("amd64", "1.0.0"); u != nil {
		t.Fatal("offered after the offer was deleted")
	}
}

func TestEvents(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, "active")
	ev := func(typ string) protocol.Event {
		return protocol.Event{EventSeq: 1, Type: typ, OccurredAt: e.now, Data: json.RawMessage(`{"bundle_version":3}`)}
	}
	post := func(events []protocol.Event, skip bool) result {
		return e.send(c, request{method: "POST", path: "/v1/events", device: id.String(), body: protocol.EventsRequest{Events: events}, skipReqCheck: skip})
	}
	if r := post([]protocol.Event{ev("bundle.applied"), ev("config.drift_corrected")}, false); r.status != http.StatusAccepted {
		t.Fatalf("events: %d %s", r.status, r.body)
	}
	var batch ingest.Events
	msg := e.pub.last(t)
	_ = json.Unmarshal(msg.Body, &batch)
	if msg.RoutingKey != "ingest.event."+e.org.String() || len(batch.Events) != 2 || batch.DeviceID != id {
		t.Fatalf("published %s %+v", msg.RoutingKey, batch)
	}
	e.expectProblem(post([]protocol.Event{ev("bundle.applied"), ev("rm -rf")}, true), http.StatusBadRequest, "unknown_event_type")
	many := make([]protocol.Event, 501)
	for i := range many {
		many[i] = ev("bundle.applied")
	}
	e.expectProblem(post(many, true), http.StatusBadRequest, "invalid_request")
	big := []protocol.Event{{EventSeq: 1, Type: "bundle.applied", OccurredAt: e.now, Data: json.RawMessage(`{"x":"` + strings.Repeat("a", 1<<20) + `"}`)}}
	e.expectProblem(post(big, true), http.StatusRequestEntityTooLarge, "payload_too_large")
}

func TestBackpressureAndRateLimits(t *testing.T) {
	e := newEnv(t, 2, 5)
	c := newClient(t)
	id := e.enrolled(c, "active")
	checkin := func(cl client, dev uuid.UUID) result {
		return e.send(cl, request{method: "POST", path: "/v1/checkin", device: dev.String(), body: checkinBody(0)})
	}
	e.pub.nack = true
	r := checkin(c, id)
	e.expectProblem(r, http.StatusServiceUnavailable, "backpressure")
	if r.header.Get("Retry-After") == "" {
		t.Fatal("503 without Retry-After")
	}
	e.pub.nack = false
	if r := checkin(c, id); r.status != http.StatusOK {
		t.Fatalf("second: %d", r.status)
	}
	r = checkin(c, id)
	e.expectProblem(r, http.StatusTooManyRequests, "rate_limited")
	if r.header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	// The address limit (5) counts every request, including the rate-limited one above.
	d := newClient(t)
	did := e.enrolled(d, "active")
	if r := checkin(d, did); r.status != http.StatusOK {
		t.Fatalf("other key, same address: %d %s", r.status, r.body)
	}
	if r := checkin(d, did); r.status != http.StatusOK {
		t.Fatalf("other key, same address: %d %s", r.status, r.body)
	}
	e.expectProblem(checkin(d, did), http.StatusTooManyRequests, "rate_limited")
}

// TestEscrowHeader: a header escrow is answered with a presigned PUT of the key the gateway chose for the device's
// organization and generation, and published with the facts of the sealed object (plan M4b decision 10).
func TestEscrowHeader(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, "active")
	escrowID := uuid.Must(uuid.NewV7())
	body := map[string]any{"escrow_id": escrowID.String(), "kind": "luks_header", "generation": 3, "key_version": 2,
		"wrapped_dek": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 512)),
		"nonce":       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 12)),
		"sha256":      strings.Repeat("ab", 32), "size": 1234567}
	r := e.send(c, request{method: "POST", path: "/v1/escrow", device: id.String(), body: body})
	key := "org/" + e.org.String() + "/devices/" + id.String() + "/luks-header/3.bin"
	var accepted struct {
		EscrowID  string `json:"escrow_id"`
		UploadURL string `json:"upload_url"`
	}
	if err := json.Unmarshal(r.body, &accepted); err != nil || r.status != http.StatusAccepted || accepted.EscrowID != escrowID.String() ||
		accepted.UploadURL != "https://bundles.test/paddock-escrow/"+key+"?X-Amz-Expires=600" {
		t.Fatalf("header: %d %s", r.status, r.body)
	}
	var in ingest.Escrow
	if err := json.Unmarshal(e.pub.last(t).Body, &in); err != nil || in.ObjectKey != key || in.Kind != "luks_header" || len(in.WrappedDEK) != 512 ||
		len(in.Nonce) != 12 || in.SHA256 != strings.Repeat("ab", 32) || in.Size != 1234567 || in.Ciphertext != nil || in.Generation != 3 {
		t.Fatalf("published %+v", in)
	}
	for name, mutate := range map[string]func(map[string]any){
		"ciphertext":  func(b map[string]any) { b["ciphertext"] = base64.StdEncoding.EncodeToString([]byte("x")) },
		"nonce":       func(b map[string]any) { b["nonce"] = base64.StdEncoding.EncodeToString(make([]byte, 16)) },
		"sha256":      func(b map[string]any) { b["sha256"] = strings.Repeat("AB", 32) },
		"size":        func(b map[string]any) { b["size"] = 32<<20 + 1 },
		"no size":     func(b map[string]any) { delete(b, "size") },
		"wrapped_dek": func(b map[string]any) { b["wrapped_dek"] = "%%%" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := map[string]any{}
			for k, v := range body {
				bad[k] = v
			}
			mutate(bad)
			r := e.send(c, request{method: "POST", path: "/v1/escrow", device: id.String(), body: bad, skipReqCheck: true})
			e.expectProblem(r, http.StatusBadRequest, "invalid_request")
		})
	}
}

// Package devicesim is the reference device client of the acceptance gates (plan M2a step 6): it enrolls with an
// enrollment configuration, checks in, and fetches and verifies bundles exactly as an agent must, using only the
// shared packages pkg/protocol and pkg/bundle. It keeps its state in memory.
package devicesim

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Device is one simulated device identity.
type Device struct {
	Config       protocol.EnrollmentConfig
	Trust        bundle.Trust
	Key          *ecdsa.PrivateKey
	KeyID        string
	SPKI         []byte
	EnrollmentID string
	DeviceID     string // set once the enrollment is active or pending
	Seq          int64  // last sequence number received
	Applied      int64  // last applied bundle version
	HTTP         *http.Client
	// ClockOffset shifts the signing time (clock skew tests).
	ClockOffset time.Duration
	// Arch is reported in check-ins; empty (the default) keeps the device out of agent rollouts.
	Arch string
	// SchemaVersions are the bundle schemas the device reports and accepts; nil means [bundle.SchemaVersion], the
	// schema of today's agent.
	SchemaVersions []int
}

func (d *Device) schemaVersions() []int {
	if d.SchemaVersions == nil {
		return []int{bundle.SchemaVersion}
	}
	return d.SchemaVersions
}

// New creates a device with a new ECDSA P-256 key for an enrollment configuration.
func New(cfg protocol.EnrollmentConfig, client *http.Client) (*Device, error) {
	trust, err := bundle.TrustFromKeys(cfg.BundleKeys)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	spki, err := protocol.MarshalPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Device{Config: cfg, Trust: trust, Key: key, KeyID: protocol.KeyID(spki), SPKI: spki, HTTP: client}, nil
}

// Clone returns a second device with the same identity and state, like a copied disk image.
func (d *Device) Clone() *Device {
	c := *d
	return &c
}

// Response is a device API response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Problem decodes a problem response.
func (r Response) Problem() protocol.Problem {
	var p protocol.Problem
	_ = json.Unmarshal(r.Body, &p)
	return p
}

// Request is a signed request; Tamper may change it after signing (security gates).
type Request struct {
	Method string
	Path   string // path and query
	Body   any
	Device string // Paddock-Device; default: the device ID
	Tamper func(r *http.Request, body *[]byte)
}

// Do signs and sends a request.
func (d *Device) Do(ctx context.Context, rq Request) (Response, error) {
	var body []byte
	if rq.Body != nil {
		var err error
		if body, err = json.Marshal(rq.Body); err != nil {
			return Response{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, rq.Method, strings.TrimRight(d.Config.ServerURL, "/")+rq.Path, nil)
	if err != nil {
		return Response{}, err
	}
	device := rq.Device
	if device == "" {
		device = d.DeviceID
	}
	if err := protocol.Sign(req, body, d.Key, device, d.KeyID, d.Seq, time.Now().Add(d.ClockOffset)); err != nil {
		return Response{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if rq.Tamper != nil {
		rq.Tamper(req, &body)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	res, err := d.HTTP.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = res.Body.Close() }()
	out, err := io.ReadAll(res.Body)
	return Response{Status: res.StatusCode, Header: res.Header, Body: out}, err
}

// Enroll sends the enrollment request and remembers the enrollment ID.
func (d *Device) Enroll(ctx context.Context, hostname string) (Response, error) {
	res, err := d.Do(ctx, Request{Method: http.MethodPost, Path: "/v1/enroll", Device: protocol.EnrollDevice, Body: protocol.EnrollRequest{
		Token: d.Config.Token, PublicKey: base64.StdEncoding.EncodeToString(d.SPKI), KeyProtection: protocol.KeyProtectionFile,
		Hostname: hostname, HardwareUUID: "sim-" + d.KeyID[:12], MachineID: d.KeyID[:32],
		OSRelease: map[string]string{"id": "ubuntu", "version_id": "26.04"}, AgentVersion: "0.0.0-devicesim",
	}})
	if err != nil || res.Status != http.StatusAccepted {
		return res, err
	}
	var acc protocol.EnrollAccepted
	if err := json.Unmarshal(res.Body, &acc); err != nil {
		return res, err
	}
	d.EnrollmentID = acc.EnrollmentID
	return res, nil
}

// EnrollmentStatus polls GET /v1/enroll/{id} once and adopts the device ID.
func (d *Device) EnrollmentStatus(ctx context.Context) (protocol.EnrollStatus, error) {
	res, err := d.Do(ctx, Request{Method: http.MethodGet, Path: "/v1/enroll/" + d.EnrollmentID, Device: protocol.EnrollDevice})
	if err != nil {
		return protocol.EnrollStatus{}, err
	}
	if res.Status != http.StatusOK {
		return protocol.EnrollStatus{}, fmt.Errorf("enrollment status: HTTP %d %s", res.Status, res.Body)
	}
	var s protocol.EnrollStatus
	if err := json.Unmarshal(res.Body, &s); err != nil {
		return s, err
	}
	if s.DeviceID != "" {
		d.DeviceID = s.DeviceID
	}
	return s, nil
}

// WaitEnrollment polls until the enrollment leaves "processing" and returns its status.
func (d *Device) WaitEnrollment(ctx context.Context, until func(protocol.EnrollStatus) bool) (protocol.EnrollStatus, error) {
	for {
		s, err := d.EnrollmentStatus(ctx)
		if err == nil && until(s) {
			return s, nil
		}
		select {
		case <-ctx.Done():
			return s, fmt.Errorf("enrollment %s stays %q: %w", d.EnrollmentID, s.Status, errors.Join(err, ctx.Err()))
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Checkin sends a check-in and adopts the returned sequence number.
func (d *Device) Checkin(ctx context.Context) (protocol.CheckinResponse, Response, error) {
	res, err := d.Do(ctx, Request{Method: http.MethodPost, Path: "/v1/checkin", Body: protocol.CheckinRequest{
		AppliedBundleVersion: d.Applied, AgentVersion: "0.0.0-devicesim", SchemaVersions: d.schemaVersions(),
		Health: json.RawMessage(`{"reconcile":"ok"}`), Arch: d.Arch,
	}})
	if err != nil || res.Status != http.StatusOK {
		return protocol.CheckinResponse{}, res, err
	}
	var out protocol.CheckinResponse
	if err := json.Unmarshal(res.Body, &out); err != nil {
		return out, res, err
	}
	d.Seq = out.Seq
	return out, res, nil
}

// Fetch downloads a bundle, checks the SHA-256 from the check-in response and verifies it in the order of
// architecture §7.2. On success the bundle counts as applied.
func (d *Device) Fetch(ctx context.Context, ref *protocol.BundleRef) (*bundle.Bundle, error) {
	env, status, err := d.Download(ctx, ref.URL)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("bundle download: HTTP %d", status)
	}
	b, err := bundle.VerifyVersions(env, d.Trust, d.DeviceID, d.Config.OrganizationID, d.Applied, d.schemaVersions())
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(env)
	if hex.EncodeToString(sum[:]) != ref.SHA256 {
		return nil, errors.New("bundle sha256 differs from the check-in response")
	}
	d.Applied = b.BundleVersion
	return b, nil
}

// Download fetches a URL without credentials (presigned bundle URLs).
func (d *Device) Download(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	res, err := d.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	return body, res.StatusCode, err
}

// Upload PUTs body to a presigned URL (an escrowed LUKS header) and returns the HTTP status.
func (d *Device) Upload(ctx context.Context, url string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := d.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	_ = res.Body.Close()
	return res.StatusCode, nil
}

// SendEvents posts a batch of events.
func (d *Device) SendEvents(ctx context.Context, events []protocol.Event) (Response, error) {
	return d.Do(ctx, Request{Method: http.MethodPost, Path: "/v1/events", Body: protocol.EventsRequest{Events: events}})
}

// CommandResult posts the result of a command.
func (d *Device) CommandResult(ctx context.Context, commandID, status string, result json.RawMessage) (Response, error) {
	return d.Do(ctx, Request{Method: http.MethodPost, Path: "/v1/commands/" + commandID + "/result",
		Body: protocol.CommandResult{Status: status, Result: result}})
}

// Escrow uploads an escrowed secret.
func (d *Device) Escrow(ctx context.Context, req escrow.Request) (Response, error) {
	return d.Do(ctx, Request{Method: http.MethodPost, Path: "/v1/escrow", Body: req})
}

// EscrowStatus polls the storage status of an escrow upload.
func (d *Device) EscrowStatus(ctx context.Context, escrowID string) (string, Response, error) {
	res, err := d.Do(ctx, Request{Method: http.MethodGet, Path: "/v1/escrow/" + escrowID})
	if err != nil || res.Status != http.StatusOK {
		return "", res, err
	}
	var s escrow.Status
	err = json.Unmarshal(res.Body, &s)
	return s.Status, res, err
}

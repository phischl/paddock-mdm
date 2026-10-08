package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Identity is one enrolled device as the k6 scripts read it.
type Identity struct {
	DeviceID string `json:"device_id"`
	KeyID    string `json:"key_id"`
	// KeyPKCS8 is the standard base64 PKCS#8 DER of the device's ECDSA P-256 key (WebCrypto importKey "pkcs8").
	KeyPKCS8 string `json:"key_pkcs8"`
	// IP is the X-Forwarded-For address the device uses when the scripts talk to the gateway directly; empty otherwise.
	IP string `json:"ip,omitempty"`
}

func readConfigs(files []string, server string) ([]protocol.EnrollmentConfig, error) {
	cfgs := make([]protocol.EnrollmentConfig, 0, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // file named by the operator on the command line
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		var cfg protocol.EnrollmentConfig
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if cfg.Token == "" {
			return nil, fmt.Errorf("%s: no token", f)
		}
		if server != "" {
			cfg.ServerURL = server
		}
		cfgs = append(cfgs, cfg)
	}
	return cfgs, nil
}

type enroller struct {
	client       *http.Client
	forwardedFor bool
	poll         time.Duration
}

// syntheticIP is a distinct address per device index in 10.0.0.0/8, so that the gateway's per-IP rate limit sees a
// fleet instead of one load generator.
func syntheticIP(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
}

func (e enroller) enrollAll(ctx context.Context, cfgs []protocol.EnrollmentConfig, count, perConfig, concurrency int, prefix string) ([]Identity, error) {
	ids := make([]Identity, count)
	work := make(chan int)
	var (
		wg    sync.WaitGroup
		once  sync.Once
		first error
	)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for range concurrency {
		wg.Go(func() {
			for i := range work {
				id, err := e.enroll(ctx, cfgs[i/perConfig], fmt.Sprintf("%s-%05d", prefix, i), i)
				if err != nil {
					once.Do(func() { first = fmt.Errorf("device %d: %w", i, err); cancel() })
					continue
				}
				ids[i] = id
			}
		})
	}
	for i := range count {
		select {
		case work <- i:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()
	return ids, first
}

// enroll creates a key, enrolls it and waits until the enrollment is active (the token must approve automatically).
func (e enroller) enroll(ctx context.Context, cfg protocol.EnrollmentConfig, hostname string, i int) (Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	spki, err := protocol.MarshalPublicKey(&key.PublicKey)
	if err != nil {
		return Identity{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Identity{}, err
	}
	id := Identity{KeyID: protocol.KeyID(spki), KeyPKCS8: base64.StdEncoding.EncodeToString(pkcs8)}
	if e.forwardedFor {
		id.IP = syntheticIP(i)
	}
	var acc protocol.EnrollAccepted
	if err := e.do(ctx, cfg, key, id, http.MethodPost, "/v1/enroll", protocol.EnrollRequest{
		Token: cfg.Token, PublicKey: base64.StdEncoding.EncodeToString(spki), KeyProtection: protocol.KeyProtectionFile,
		Hostname: hostname, HardwareUUID: "load-" + id.KeyID[:12], MachineID: id.KeyID[:32],
		OSRelease: map[string]string{"id": "ubuntu", "version_id": "26.04"}, AgentVersion: "0.0.0-load",
	}, http.StatusAccepted, &acc); err != nil {
		return Identity{}, fmt.Errorf("enroll: %w", err)
	}
	for {
		var s protocol.EnrollStatus
		if err := e.do(ctx, cfg, key, id, http.MethodGet, "/v1/enroll/"+acc.EnrollmentID, nil, http.StatusOK, &s); err != nil {
			return Identity{}, fmt.Errorf("enrollment status: %w", err)
		}
		switch s.Status {
		case protocol.EnrollActive:
			id.DeviceID = s.DeviceID
			return id, nil
		case protocol.EnrollProcessing:
		default:
			return Identity{}, fmt.Errorf("enrollment %s is %s (%s); use an auto-approving token with uses left", acc.EnrollmentID, s.Status, s.Reason)
		}
		select {
		case <-ctx.Done():
			return Identity{}, ctx.Err()
		case <-time.After(e.poll):
		}
	}
}

// do sends one signed enrollment request (Paddock-Device "enroll") and decodes the answer into out.
func (e enroller) do(ctx context.Context, cfg protocol.EnrollmentConfig, key *ecdsa.PrivateKey, id Identity, method, path string, body any, want int, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(cfg.ServerURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if err := protocol.Sign(req, raw, key, protocol.EnrollDevice, id.KeyID, 0, time.Now()); err != nil {
		return err
	}
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if id.IP != "" {
		req.Header.Set("X-Forwarded-For", id.IP)
	}
	res, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != want {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, res.StatusCode, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return errors.Join(fmt.Errorf("%s %s: decode answer", method, path), err)
	}
	return nil
}

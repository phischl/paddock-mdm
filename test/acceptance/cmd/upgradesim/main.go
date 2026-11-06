// Command upgradesim is a simulated device that outlives an upgrade (plan M16 decision 10, deploy/bundle/ci/upgrade.sh):
// unlike devicesim it keeps its identity in a state file, so the same device enrolls on the old release and checks in
// again after the upgrade, the restore and the rollback.
//
//	upgradesim enroll --state <file> --hostname <name> < enrollment-config.json
//	upgradesim checkin --state <file> --want <text> [--timeout <duration>]
//
// enroll needs an auto-approving token: it enrolls, escrows generation 1 of a random local administrator password like
// an agent (encrypted to the escrow key of its bundle, confirmed with local_admin.rotated), writes the state (0600,
// with the password, which is never printed) and prints {"device_id"}. checkin checks in until it receives a bundle
// newer than the last one it applied, verifies it, requires <text> in it (the managed file's path or content), reports
// bundle.applied (202) and prints {"device_id", "bundle_version"}.
//
// The upgrade job builds this command twice from the same source: in a checkout of the previous release's tag, so the
// device speaks with that release's devicesim package and protocol types (decisions-alpha9 item 53), and in the tree
// of the candidate. It therefore uses only the parts of those packages that both releases have.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

const usage = "usage: upgradesim enroll --state <file> --hostname <name> < enrollment-config.json\n" +
	"       upgradesim checkin --state <file> --want <text> [--timeout <duration>]"

// state is the device's identity and protocol state between two runs.
type state struct {
	Config         protocol.EnrollmentConfig `json:"config"`
	Key            []byte                    `json:"key"` // PKCS#8
	Hostname       string                    `json:"hostname"`
	EnrollmentID   string                    `json:"enrollment_id"`
	DeviceID       string                    `json:"device_id"`
	Seq            int64                     `json:"seq"`
	Applied        int64                     `json:"applied"`
	EventSeqHigh   int64                     `json:"event_seq_high"`
	SchemaVersions []int                     `json:"schema_versions"`
	Password       string                    `json:"password"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "upgradesim:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || (args[0] != "enroll" && args[0] != "checkin") {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	statePath := fs.String("state", "", "state file of the device")
	hostname := fs.String("hostname", "", "hostname to report (enroll)")
	want := fs.String("want", "", "text the new bundle must contain (checkin)")
	timeout := fs.Duration("timeout", 3*time.Minute, "how long to wait")
	if err := fs.Parse(args[1:]); err != nil || *statePath == "" ||
		(args[0] == "enroll" && *hostname == "") || (args[0] == "checkin" && *want == "") {
		return errors.New(usage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, err := env.NewHTTPClient()
	if err != nil {
		return err
	}
	if args[0] == "enroll" {
		var cfg protocol.EnrollmentConfig
		if err := json.NewDecoder(os.Stdin).Decode(&cfg); err != nil {
			return fmt.Errorf("read enrollment configuration: %w", err)
		}
		return enroll(ctx, client, cfg, *statePath, *hostname)
	}
	return checkin(ctx, client, *statePath, *want)
}

func enroll(ctx context.Context, client *http.Client, cfg protocol.EnrollmentConfig, path, hostname string) error {
	dev, err := devicesim.New(cfg, client)
	if err != nil {
		return err
	}
	res, err := dev.Enroll(ctx, hostname)
	if err != nil {
		return err
	}
	if res.Status != http.StatusAccepted {
		return fmt.Errorf("enroll: HTTP %d %s", res.Status, res.Body)
	}
	s, err := dev.WaitEnrollment(ctx, func(s protocol.EnrollStatus) bool { return s.Status != protocol.EnrollProcessing })
	if err != nil {
		return err
	}
	if s.Status != protocol.EnrollActive {
		return fmt.Errorf("enrollment %s, want active (auto-approving token)", s.Status)
	}
	password, err := escrowLocalAdmin(ctx, dev)
	if err != nil {
		return err
	}
	if err := save(path, dev, hostname, password); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"device_id": dev.DeviceID})
}

func checkin(ctx context.Context, client *http.Client, path, want string) error {
	st, dev, err := load(path, client)
	if err != nil {
		return err
	}
	for {
		out, res, err := dev.Checkin(ctx)
		if err != nil || res.Status != http.StatusOK {
			return fmt.Errorf("checkin: %v HTTP %d %s", err, res.Status, res.Body)
		}
		if out.Bundle != nil {
			b, err := dev.Fetch(ctx, out.Bundle)
			if err != nil {
				return fmt.Errorf("bundle %d does not verify: %w", out.Bundle.Version, err)
			}
			data, err := json.Marshal(b)
			if err != nil {
				return err
			}
			if !strings.Contains(string(data), want) {
				return fmt.Errorf("bundle %d does not contain %q", b.BundleVersion, want)
			}
			if err := reportApplied(ctx, dev, b.BundleVersion); err != nil {
				return err
			}
			if err := save(path, dev, st.Hostname, st.Password); err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"device_id": dev.DeviceID, "bundle_version": b.BundleVersion})
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no bundle newer than version %d", dev.Applied)
		case <-time.After(2500 * time.Millisecond):
		}
	}
}

// reportApplied sends bundle.applied for version as the next event of the device; the server must accept it (202).
func reportApplied(ctx context.Context, dev *devicesim.Device, version int64) error {
	data, err := json.Marshal(map[string]any{
		"version": version, "changed": 0, "mode": "enforce", "errors": []any{}, "resources": []any{},
	})
	if err != nil {
		return err
	}
	res, err := dev.SendEvents(ctx, []protocol.Event{{EventSeq: dev.EventSeqHigh + 1, Type: protocol.EventBundleApplied,
		OccurredAt: time.Now(), Data: data}})
	if err != nil || res.Status != http.StatusAccepted {
		return fmt.Errorf("bundle.applied event: %v HTTP %d %s", err, res.Status, res.Body)
	}
	return nil
}

func save(path string, dev *devicesim.Device, hostname, password string) error {
	key, err := x509.MarshalPKCS8PrivateKey(dev.Key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(state{
		Config: dev.Config, Key: key, Hostname: hostname, EnrollmentID: dev.EnrollmentID, DeviceID: dev.DeviceID,
		Seq: dev.Seq, Applied: dev.Applied, EventSeqHigh: dev.EventSeqHigh, SchemaVersions: dev.SchemaVersions,
		Password: password,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func load(path string, client *http.Client) (state, *devicesim.Device, error) {
	var st state
	data, err := os.ReadFile(path) //nolint:gosec // the job's own state file
	if err != nil {
		return st, nil, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, nil, fmt.Errorf("%s: %w", path, err)
	}
	dev, err := devicesim.New(st.Config, client)
	if err != nil {
		return st, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(st.Key)
	if err != nil {
		return st, nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return st, nil, errors.New("the device key is no ECDSA key")
	}
	spki, err := protocol.MarshalPublicKey(&key.PublicKey)
	if err != nil {
		return st, nil, err
	}
	dev.Key, dev.SPKI, dev.KeyID = key, spki, protocol.KeyID(spki)
	dev.EnrollmentID, dev.DeviceID = st.EnrollmentID, st.DeviceID
	dev.Seq, dev.Applied, dev.EventSeqHigh, dev.SchemaVersions = st.Seq, st.Applied, st.EventSeqHigh, st.SchemaVersions
	return st, dev, nil
}

// escrowLocalAdmin checks in as a schema 2 agent until the bundle carries the escrow key, escrows generation 1 of a
// random password and confirms it (the same steps as devicesim local-admin).
func escrowLocalAdmin(ctx context.Context, dev *devicesim.Device) (string, error) {
	dev.SchemaVersions = []int{1, 2}
	var keys *bundle.Keys
	for keys == nil {
		out, res, err := dev.Checkin(ctx)
		if err != nil || res.Status != http.StatusOK {
			return "", fmt.Errorf("checkin: %v HTTP %d", err, res.Status)
		}
		if out.Bundle != nil {
			b, err := dev.Fetch(ctx, out.Bundle)
			if err != nil {
				return "", err
			}
			if b.Keys != nil && b.Keys.EscrowWrap != nil {
				keys = b.Keys
				break
			}
		}
		select {
		case <-ctx.Done():
			return "", errors.New("no bundle with the escrow key")
		case <-time.After(2500 * time.Millisecond):
		}
	}
	pub, err := escrow.ParsePublicKey(keys.EscrowWrap.PublicKeyPEM)
	if err != nil {
		return "", err
	}
	version, err := escrow.KeyVersion(keys.EscrowWrap.KeyID)
	if err != nil {
		return "", err
	}
	password := "Up-" + uuid.NewString()[:18]
	ct, err := escrow.Encrypt(pub, []byte(password))
	if err != nil {
		return "", err
	}
	id := uuid.NewString()
	if res, err := dev.Escrow(ctx, escrow.Request{EscrowID: id, Kind: escrow.KindAdminPassword, Generation: 1, KeyVersion: version,
		Ciphertext: ct}); err != nil || res.Status != http.StatusAccepted {
		return "", fmt.Errorf("escrow: %v HTTP %d", err, res.Status)
	}
	for {
		status, _, err := dev.EscrowStatus(ctx, id)
		if err != nil {
			return "", err
		}
		if status == escrow.StatusStored {
			break
		}
		if status == escrow.StatusFailed {
			return "", errors.New("escrow failed")
		}
		select {
		case <-ctx.Done():
			return "", errors.New("the escrow was not stored in time")
		case <-time.After(time.Second):
		}
	}
	data, err := json.Marshal(protocol.LocalAdminRotated{Generation: 1})
	if err != nil {
		return "", err
	}
	if res, err := dev.SendEvents(ctx, []protocol.Event{{EventSeq: dev.EventSeqHigh + 1, Type: protocol.EventLocalAdminRotated,
		OccurredAt: time.Now(), Data: data}}); err != nil || res.Status != http.StatusAccepted {
		return "", fmt.Errorf("rotated event: %v HTTP %d", err, res.Status)
	}
	return password, nil
}

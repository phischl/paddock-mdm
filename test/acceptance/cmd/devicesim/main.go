// Command devicesim enrolls a simulated device for the portal end-to-end tests (plan M2a E2, plan M4a):
//
//	devicesim enroll --hostname <name> < enrollment-config.json
//	devicesim local-admin --hostname <name> < enrollment-config.json
//
// enroll prints {"enrollment_id", "device_id", "status"} once the enrollment left "processing". local-admin needs an
// auto-approving token: it enrolls, escrows a first local administrator password like an agent (encrypted to the
// escrow key of its bundle, confirmed with local_admin.rotated) and prints {"device_id", "password"}.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/escrow"
	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/test/acceptance/devicesim"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "devicesim:", err)
		os.Exit(1)
	}
}

const usage = "usage: devicesim enroll|local-admin --hostname <name> < enrollment-config.json"

func run(args []string) error {
	if len(args) == 0 || (args[0] != "enroll" && args[0] != "local-admin") {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	hostname := fs.String("hostname", "", "hostname to report")
	if err := fs.Parse(args[1:]); err != nil || *hostname == "" {
		return errors.New(usage)
	}
	var cfg protocol.EnrollmentConfig
	if err := json.NewDecoder(os.Stdin).Decode(&cfg); err != nil {
		return fmt.Errorf("read enrollment configuration: %w", err)
	}
	client, err := env.NewHTTPClient()
	if err != nil {
		return err
	}
	dev, err := devicesim.New(cfg, client)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := dev.Enroll(ctx, *hostname)
	if err != nil {
		return err
	}
	if res.Status != 202 {
		return fmt.Errorf("enroll: HTTP %d %s", res.Status, res.Body)
	}
	s, err := dev.WaitEnrollment(ctx, func(s protocol.EnrollStatus) bool { return s.Status != protocol.EnrollProcessing })
	if err != nil {
		return err
	}
	if args[0] == "enroll" {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{
			"enrollment_id": dev.EnrollmentID, "device_id": s.DeviceID, "status": s.Status,
		})
	}
	if s.Status != protocol.EnrollActive {
		return fmt.Errorf("enrollment %s, want active (auto-approving token)", s.Status)
	}
	password, err := escrowLocalAdmin(ctx, dev)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"device_id": s.DeviceID, "password": password})
}

// escrowLocalAdmin checks in as a schema 2 agent until the bundle carries the escrow key, escrows generation 1 of
// a random password and confirms it.
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
	password := "E2e-" + uuid.NewString()[:18]
	ct, err := escrow.Encrypt(pub, []byte(password))
	if err != nil {
		return "", err
	}
	id := uuid.NewString()
	if res, err := dev.Escrow(ctx, escrow.Request{EscrowID: id, Kind: escrow.KindAdminPassword, Generation: 1, KeyVersion: version, Ciphertext: ct}); err != nil || res.Status != http.StatusAccepted {
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
		time.Sleep(time.Second)
	}
	data, _ := json.Marshal(protocol.LocalAdminRotated{Generation: 1})
	if res, err := dev.SendEvents(ctx, []protocol.Event{{EventSeq: 1, Type: protocol.EventLocalAdminRotated, OccurredAt: time.Now(), Data: data}}); err != nil || res.Status != http.StatusAccepted {
		return "", fmt.Errorf("rotated event: %v HTTP %d", err, res.Status)
	}
	return password, nil
}

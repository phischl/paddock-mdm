// Command devicesim enrolls a simulated device for the portal end-to-end tests (plan M2a E2, plan M4a):
//
//	devicesim enroll --hostname <name> [--enrollment-method autoinstall|adopted] < enrollment-config.json
//	devicesim local-admin --hostname <name> < enrollment-config.json
//	devicesim inventory --hostname <name> --package <name>=<version> ... < enrollment-config.json
//	devicesim disk --hostname <name> --health <json> < enrollment-config.json
//	devicesim config-report --hostname <name> --resource <id>=<status>[:<message>] ... < enrollment-config.json
//	devicesim diagnostics --hostname <name> < enrollment-config.json
//	devicesim software-request --hostname <name> --entry <id> --user <name> --justification <text> < enrollment-config.json
//
// enroll prints {"enrollment_id", "device_id", "status"} once the enrollment left "processing". local-admin needs an
// auto-approving token: it enrolls, escrows a first local administrator password like an agent (encrypted to the
// escrow key of its bundle, confirmed with local_admin.rotated) and prints {"device_id", "password"}. inventory needs
// an auto-approving token, too: it enrolls, enrolls an osquery host with the device's hardware UUID in Fleet (plan
// M5a), reports the packages and prints {"device_id"}. disk needs an auto-approving token, too: it enrolls, checks in
// once with the given health (e.g. an unencrypted disk that can be encrypted in place, plan M8e) and prints
// {"device_id"}. config-report needs an auto-approving token, too: it enrolls, waits for its first bundle and reports
// bundle.applied with the given resource outcomes (plan M11) and prints {"device_id"}. diagnostics needs an
// auto-approving token, too: it enrolls, prints {"device_id"} at once, checks in until a collect_status command arrives
// (requested by the test meanwhile), seals a small fixed archive like an agent (ADR 0048 decision 3, with the
// escrow-wrap version of its bundle), announces and uploads it, reports the result and prints {"archive_sha256"} of the
// plain archive. software-request needs an auto-approving token, too: it enrolls, prints {"device_id"} at once, checks in
// as a schema 2 agent until its bundle offers the catalog entry (the test adds the device to a group meanwhile), sends the
// user's software.request with the justification like the self-service app does and prints {"requested": entry}.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "devicesim:", err)
		os.Exit(1)
	}
}

const usage = "usage: devicesim enroll|local-admin|inventory|disk|config-report|diagnostics|software-request --hostname <name> " +
	"[--enrollment-method autoinstall|adopted] [--package <name>=<version> ...] [--health <json>] [--resource <id>=<status>[:<message>] ...] " +
	"[--entry <id> --user <name> --justification <text>] < enrollment-config.json"

func run(args []string) error {
	if len(args) == 0 || (args[0] != "enroll" && args[0] != "local-admin" && args[0] != "inventory" && args[0] != "disk" && args[0] != "config-report" &&
		args[0] != "diagnostics" && args[0] != "software-request") {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	hostname := fs.String("hostname", "", "hostname to report")
	health := fs.String("health", "", "check-in health to report (disk)")
	method := fs.String("enrollment-method", "", "enrollment method to send: autoinstall or adopted (none by default)")
	entry := fs.String("entry", "", "catalog entry ID to request (software-request)")
	user := fs.String("user", "", "user who requests the entry (software-request)")
	justification := fs.String("justification", "", "the user's justification (software-request)")
	var packages [][2]string
	fs.Func("package", "deb package <name>=<version> to report to Fleet (inventory)", func(v string) error {
		name, version, ok := strings.Cut(v, "=")
		if !ok || name == "" || version == "" {
			return errors.New("want <name>=<version>")
		}
		packages = append(packages, [2]string{name, version})
		return nil
	})
	var resources []map[string]string
	fs.Func("resource", "resource outcome <id>=<status>[:<message>] (config-report)", func(v string) error {
		id, outcome, ok := strings.Cut(v, "=")
		status, message, _ := strings.Cut(outcome, ":")
		if !ok || id == "" || status == "" {
			return errors.New("want <id>=<status>[:<message>]")
		}
		resources = append(resources, map[string]string{"id": id, "status": status, "message": message})
		return nil
	})
	if err := fs.Parse(args[1:]); err != nil || *hostname == "" || (args[0] == "disk" && !json.Valid([]byte(*health))) ||
		(args[0] == "software-request" && (*entry == "" || *user == "")) {
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
	dev.EnrollmentMethod = *method
	timeout := 2 * time.Minute
	if args[0] == "diagnostics" || args[0] == "software-request" {
		timeout = 5 * time.Minute // the test requests the collection or offers the entry after the enrollment
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
	if args[0] == "disk" {
		dev.Health = json.RawMessage(*health)
		_, res, err := dev.Checkin(ctx)
		if err != nil {
			return fmt.Errorf("check in: %w", err)
		}
		if res.Status != http.StatusOK {
			return fmt.Errorf("check in: HTTP %d %s", res.Status, res.Body)
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"device_id": s.DeviceID})
	}
	if args[0] == "diagnostics" {
		if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"device_id": s.DeviceID}); err != nil {
			return err
		}
		sum, err := uploadDiagnostics(ctx, dev)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"archive_sha256": sum})
	}
	if args[0] == "software-request" {
		if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"device_id": s.DeviceID}); err != nil {
			return err
		}
		if err := requestSoftware(ctx, dev, *entry, *user, *justification); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"requested": *entry})
	}
	if args[0] == "config-report" {
		if err := reportConfig(ctx, dev, resources); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"device_id": s.DeviceID})
	}
	if args[0] == "inventory" {
		if err := reportInventory(ctx, client, dev, *hostname, packages); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"device_id": s.DeviceID})
	}
	password, err := escrowLocalAdmin(ctx, dev)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"device_id": s.DeviceID, "password": password})
}

// reportConfig checks in until the device has a bundle and reports it applied with the given resource outcomes.
func reportConfig(ctx context.Context, dev *devicesim.Device, resources []map[string]string) error {
	for {
		out, res, err := dev.Checkin(ctx)
		if err != nil || res.Status != http.StatusOK {
			return fmt.Errorf("checkin: %v HTTP %d", err, res.Status)
		}
		if out.Bundle != nil {
			failed := 0
			errs := []map[string]string{}
			for _, r := range resources {
				if r["status"] == "failed" {
					failed++
					errs = append(errs, map[string]string{"id": r["id"], "message": r["message"]})
				}
			}
			data, err := json.Marshal(map[string]any{
				"version": out.Bundle.Version, "changed": len(resources) - failed, "mode": "enforce", "errors": errs, "resources": resources,
			})
			if err != nil {
				return err
			}
			res, err := dev.SendEvents(ctx, []protocol.Event{{EventSeq: 1, Type: protocol.EventBundleApplied, OccurredAt: time.Now(), Data: data}})
			if err != nil || res.Status != http.StatusAccepted {
				return fmt.Errorf("bundle.applied event: %v HTTP %d %s", err, res.Status, res.Body)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("the device got no bundle")
		case <-time.After(2500 * time.Millisecond):
		}
	}
}

// requestSoftware checks in as a schema 2 agent until a bundle offers the entry and sends user's software.request for it.
// The server opens a request only for an entry the device is offered, so the event waits for that bundle.
func requestSoftware(ctx context.Context, dev *devicesim.Device, entry, user, justification string) error {
	dev.SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}
	for {
		out, res, err := dev.Checkin(ctx)
		if err != nil || res.Status != http.StatusOK {
			return fmt.Errorf("checkin: %v HTTP %d", err, res.Status)
		}
		if out.Bundle != nil {
			b, err := dev.Fetch(ctx, out.Bundle)
			if err != nil {
				return err
			}
			if b.Software != nil && slices.ContainsFunc(b.Software.Packages, func(p bundle.SoftwarePackage) bool { return p.CatalogEntryID == entry }) {
				break
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no bundle offers catalog entry %s", entry)
		case <-time.After(2500 * time.Millisecond):
		}
	}
	data, err := json.Marshal(protocol.SoftwareRequest{User: user, EntryID: entry, Justification: justification})
	if err != nil {
		return err
	}
	res, err := dev.SendEvents(ctx, []protocol.Event{{EventSeq: 1, Type: protocol.EventSoftwareRequest, OccurredAt: time.Now(), Data: data}})
	if err != nil || res.Status != http.StatusAccepted {
		return fmt.Errorf("software.request event: %v HTTP %d %s", err, res.Status, res.Body)
	}
	return nil
}

// reportInventory enrolls the device's osquery host in Fleet and answers Fleet's queries until it has the packages.
func reportInventory(ctx context.Context, client *http.Client, dev *devicesim.Device, hostname string, packages [][2]string) error {
	secret, err := stack.Secret("fleet_enroll_secret")
	if err != nil {
		return err
	}
	host, err := devicesim.EnrollFleet(ctx, client, stack.FleetURL(), strings.TrimSpace(secret), dev.HardwareUUID(), hostname, packages)
	if err != nil {
		return err
	}
	return host.WaitAnswered(ctx)
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

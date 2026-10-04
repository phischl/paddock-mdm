// Command devicesim enrolls a simulated device for the portal end-to-end test (plan M2a E2):
//
//	devicesim enroll --hostname <name> < enrollment-config.json
//
// It prints {"enrollment_id", "device_id", "status"} once the enrollment left "processing".
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

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

func run(args []string) error {
	if len(args) == 0 || args[0] != "enroll" {
		return fmt.Errorf("usage: devicesim enroll --hostname <name> < enrollment-config.json")
	}
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	hostname := fs.String("hostname", "", "hostname to report")
	if err := fs.Parse(args[1:]); err != nil || *hostname == "" {
		return fmt.Errorf("usage: devicesim enroll --hostname <name> < enrollment-config.json")
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
	return json.NewEncoder(os.Stdout).Encode(map[string]string{
		"enrollment_id": dev.EnrollmentID, "device_id": s.DeviceID, "status": s.Status,
	})
}

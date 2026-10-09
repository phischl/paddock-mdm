// Command identities pre-generates device identities for the load test (plan M6b decision 1): it enrolls devices
// through the real enrollment API with the enrollment configurations of auto-approving tokens and writes each
// device's ID, key ID and private key (PKCS#8) to a JSON file the k6 scripts read. The keys are throw-away test keys.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "identities:", err)
		os.Exit(1)
	}
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("identities", flag.ContinueOnError)
	var configs stringList
	fs.Var(&configs, "config", "enrollment configuration (JSON file) of an auto-approving token; repeat for more tokens")
	count := fs.Int("count", 10000, "number of devices to enroll")
	perConfig := fs.Int("per-config", 1000, "devices per enrollment configuration (at most the token's maximum uses)")
	server := fs.String("server", "", "device API base URL of the test stack, required (never the configurations' server_url), e.g. http://paddock-gateway:8081")
	caFile := fs.String("ca-file", "", "PEM file with the CA that signed the device API's certificate (https only)")
	forwardedFor := fs.Bool("forwarded-for", false, "send a distinct X-Forwarded-For address per device (only when talking to the gateway directly)")
	concurrency := fs.Int("concurrency", 32, "parallel enrollments")
	prefix := fs.String("hostname-prefix", "load", "hostname prefix of the devices")
	out := fs.String("out", "identities.json", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// No fallback to the configurations' server_url, which names the installation that issued the token: the load test
	// must never enroll thousands of devices into a production installation by accident.
	if len(configs) == 0 || *server == "" || *count < 1 || *perConfig < 1 || *concurrency < 1 {
		return errors.New("usage: identities --config <enrollment-config.json> [--config …] --server URL [--count N] [--out FILE]")
	}
	if *count > len(configs)**perConfig {
		return fmt.Errorf("%d devices need %d configurations of %d uses, got %d", *count, (*count+*perConfig-1) / *perConfig, *perConfig, len(configs))
	}
	cfgs, err := readConfigs(configs, *server)
	if err != nil {
		return err
	}
	client, err := httpClient(*caFile)
	if err != nil {
		return err
	}
	e := enroller{client: client, forwardedFor: *forwardedFor, poll: 500 * time.Millisecond}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	ids, err := e.enrollAll(ctx, cfgs, *count, *perConfig, *concurrency, *prefix)
	if err != nil {
		return err
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	fmt.Printf("enrolled %d devices into %s\n", len(ids), *out)
	return nil
}

func httpClient(caFile string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 256
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // file named by the operator on the command line
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificate", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

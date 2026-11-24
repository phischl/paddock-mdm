// Command orgseed creates N organizations on a development stack through the platform admin API, for the identity
// round measurement (docs/operations/capacity.md, "Identity rounds"). It authenticates with the platform admin's
// session cookie, which the operator passes in a file: the platform API accepts no API token. The make target
// `load-orgs` runs it behind the same guard as `load-identities`, so it never runs against production.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	createPath = "/api/platform/v1/organizations"
	// createTimeout covers the synchronous Authentik provisioning of one organization (app.ProvisioningBudget, 60 s).
	createTimeout = 90 * time.Second
	maxRetries    = 5
)

// slugPattern is the API's organization slug pattern.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "orgseed:", err)
		os.Exit(1)
	}
}

type options struct {
	server      string
	cookie      string
	count       int
	prefix      string
	concurrency int
}

func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("orgseed", flag.ContinueOnError)
	server := fs.String("server", "", "admin API base URL of the test stack, required, e.g. http://paddock-api:8080")
	cookieFile := fs.String("cookie-file", "", "file with the platform admin's session cookie value (paddock_session), required")
	count := fs.Int("count", 250, "number of organizations to create")
	prefix := fs.String("slug-prefix", "load", "slug prefix; organizations are named <prefix>-001, <prefix>-002, ...")
	concurrency := fs.Int("concurrency", 4, "parallel creations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *cookieFile == "" || *count < 1 || *concurrency < 1 {
		return errors.New("usage: orgseed --server URL --cookie-file FILE [--count N] [--slug-prefix load] [--concurrency N]")
	}
	u, err := url.Parse(*server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("--server %q is not an http(s) URL", *server)
	}
	raw, err := os.ReadFile(*cookieFile) //nolint:gosec // file named by the operator on the command line
	if err != nil {
		return fmt.Errorf("read cookie file: %w", err)
	}
	cookie := strings.TrimSpace(string(raw))
	if cookie == "" {
		return fmt.Errorf("%s is empty", *cookieFile)
	}
	opts := options{server: strings.TrimRight(*server, "/"), cookie: cookie, count: *count, prefix: *prefix, concurrency: *concurrency}
	if _, err := slugOf(opts.prefix, 1); err != nil {
		return err
	}
	return seed(ctx, &http.Client{Timeout: createTimeout}, opts, out)
}

// slugOf returns the slug of organization n (1-based), zero-padded to at least three digits, and checks it against
// the API's slug pattern.
func slugOf(prefix string, n int) (string, error) {
	slug := fmt.Sprintf("%s-%03d", prefix, n)
	if !slugPattern.MatchString(slug) {
		return "", fmt.Errorf("slug %q does not match %s", slug, slugPattern)
	}
	return slug, nil
}

type result struct {
	created, existing int
}

// seed creates organizations 1..count. An organization that already exists (409) counts as existing, so an
// interrupted run is repeated with the same arguments.
func seed(ctx context.Context, client *http.Client, o options, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu    sync.Mutex
		res   result
		first error
		wg    sync.WaitGroup
	)
	work := make(chan int)
	for range o.concurrency {
		wg.Go(func() {
			for n := range work {
				existed, err := createOne(ctx, client, o, n)
				mu.Lock()
				switch {
				case err != nil:
					if first == nil {
						first = fmt.Errorf("organization %d: %w", n, err)
						cancel()
					}
				case existed:
					res.existing++
				default:
					res.created++
				}
				mu.Unlock()
			}
		})
	}
	for n := 1; n <= o.count; n++ {
		select {
		case work <- n:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()
	if first != nil {
		return first
	}
	fmt.Fprintf(out, "%d organizations ready (%d created, %d existed): %s-001 .. %s-%03d\n",
		res.created+res.existing, res.created, res.existing, o.prefix, o.prefix, o.count)
	return nil
}

// createOne posts organization n and reports whether it already existed. A 429 is retried after the server's
// Retry-After, because the write limit of one session (120 per minute) is below the pace of a fast seeding run.
func createOne(ctx context.Context, client *http.Client, o options, n int) (bool, error) {
	slug, err := slugOf(o.prefix, n)
	if err != nil {
		return false, err
	}
	body, err := json.Marshal(map[string]string{"slug": slug, "name": "Load " + slug})
	if err != nil {
		return false, err
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.server+createPath, bytes.NewReader(body))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Paddock-CSRF", "1")
		req.Header.Set("Cookie", "paddock_session="+o.cookie)
		resp, err := client.Do(req)
		if err != nil {
			return false, fmt.Errorf("POST %s: %w", createPath, err)
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusCreated, resp.StatusCode == http.StatusOK:
			return false, nil
		case resp.StatusCode == http.StatusConflict:
			return true, nil
		case resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries:
			wait := time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return false, ctx.Err()
			}
		default:
			return false, fmt.Errorf("POST %s: HTTP %d: %s", createPath, resp.StatusCode, strings.TrimSpace(string(msg)))
		}
	}
}

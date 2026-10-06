// Command agentrelease signs agent binaries with the development release key and uploads them as an agent release
// through the platform API, signed in as the development platform administrator (plan M2b decision 24; used by
// `make agent-release`, the portal end-to-end test and the system tests):
//
//	agentrelease --version 1.2.0 --artifact amd64=bin/paddockd [--deb bin/deb/paddock-agent_1.2.0_amd64.deb …]
//	    [--publish] [--rollout [--waves 100] [--min-wave-minutes 1] [--failure-threshold-min 1]
//	    [--failure-threshold-percent 2]] [--halt-running]
//
// Debian packages (plan M4b decision 1) are named <name>_<version>_<arch>.deb, as `make deb` builds them; they are
// stored under the release version.
//
// It prints the release detail as JSON.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

type artifacts map[string]string

func (a artifacts) String() string { return fmt.Sprint(map[string]string(a)) }

// debs are the paths of Debian packages to upload.
type debs []string

func (d *debs) String() string { return strings.Join(*d, ",") }

func (d *debs) Set(v string) error {
	*d = append(*d, v)
	return nil
}

func (a artifacts) Set(v string) error {
	arch, path, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("want <arch>=<path>, got %q", v)
	}
	a[arch] = path
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agentrelease:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("agentrelease", flag.ContinueOnError)
	version := fs.String("version", "", "release version (semantic version)")
	arts := artifacts{}
	fs.Var(arts, "artifact", "<arch>=<path of paddockd>, repeatable")
	var packages debs
	fs.Var(&packages, "deb", "path of a Debian package <name>_<version>_<arch>.deb, repeatable")
	key := fs.String("key", "", "minisign secret key (default: the development key in deploy/compose/.secrets/release)")
	publish := fs.Bool("publish", false, "publish the release")
	rollout := fs.Bool("rollout", false, "start the rollout (implies --publish)")
	waves := fs.String("waves", "", "comma-separated wave percentages, e.g. 100")
	minWave := fs.Int("min-wave-minutes", 0, "minimum wave duration (development allows < 60)")
	failMin := fs.Int("failure-threshold-min", -1, "failed devices that halt the rollout at least")
	failPct := fs.Int("failure-threshold-percent", -1, "failed devices in percent that halt the rollout")
	haltRunning := fs.Bool("halt-running", false, "halt every running rollout first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" || (len(arts) == 0 && !*haltRunning) {
		return fmt.Errorf("--version and at least one --artifact are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	p, err := env.Login(ctx, env.PlatformAdmin, "")
	if err != nil {
		return fmt.Errorf("sign in as %s: %w", env.PlatformAdmin, err)
	}
	if *haltRunning {
		if err := haltAll(ctx, p); err != nil {
			return err
		}
	}
	if len(arts) == 0 {
		return nil
	}
	priv, err := stack.ReleaseKey(*key)
	if err != nil {
		return err
	}
	base := "/api/platform/v1/agent-releases/" + *version
	res, err := p.Do(ctx, http.MethodPost, "/api/platform/v1/agent-releases", map[string]string{"version": *version})
	if err != nil || (res.Status != http.StatusCreated && res.ProblemCode() != "already_exists") {
		return fail("create", res, err)
	}
	for arch, path := range arts {
		bin, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sig := minisign.SignWithComments(priv, bin, fmt.Sprintf("paddockd %s %s", *version, arch), "paddock agent release")
		if res, err := upload(ctx, p, base+"/artifacts/"+arch, bin, sig); err != nil || res.Status != http.StatusOK {
			return fail("upload "+arch, res, err)
		}
	}
	for _, path := range packages {
		name, arch, err := debName(filepath.Base(path), *version)
		if err != nil {
			return err
		}
		deb, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sig := minisign.SignWithComments(priv, deb, fmt.Sprintf("%s %s %s", name, *version, arch), "paddock agent package")
		if res, err := upload(ctx, p, base+"/packages/"+name+"/"+arch, deb, sig); err != nil || res.Status != http.StatusOK {
			return fail("upload "+name+" "+arch, res, err)
		}
	}
	if *publish || *rollout {
		if res, err := p.Do(ctx, http.MethodPost, base+"/publish", nil); err != nil || (res.Status != http.StatusOK && res.ProblemCode() != "invalid_state") {
			return fail("publish", res, err)
		}
	}
	if *rollout {
		body := map[string]any{}
		if *waves != "" {
			var ws []int
			for _, w := range strings.Split(*waves, ",") {
				n, err := strconv.Atoi(strings.TrimSpace(w))
				if err != nil {
					return fmt.Errorf("--waves: %w", err)
				}
				ws = append(ws, n)
			}
			body["waves"] = ws
		}
		for name, v := range map[string]int{"min_wave_minutes": *minWave, "failure_threshold_min": *failMin, "failure_threshold_percent": *failPct} {
			if v > 0 || (v == 0 && name != "min_wave_minutes") {
				body[name] = v
			}
		}
		if res, err := p.Do(ctx, http.MethodPost, base+"/rollout", body); err != nil || res.Status != http.StatusCreated {
			return fail("start rollout", res, err)
		}
	}
	res, err = p.Do(ctx, http.MethodGet, base, nil)
	if err != nil || res.Status != http.StatusOK {
		return fail("get", res, err)
	}
	_, err = os.Stdout.Write(append(res.Body, '\n'))
	return err
}

// debName splits <name>_<version>_<arch>.deb and checks the version; nfpm writes a pre-release version such as
// 1.2.0-rc.1 as 1.2.0~rc.1 (Debian ordering).
func debName(file, version string) (name, arch string, err error) {
	parts := strings.Split(strings.TrimSuffix(file, ".deb"), "_")
	if len(parts) != 3 || !strings.HasSuffix(file, ".deb") || (parts[1] != version && parts[1] != strings.Replace(version, "-", "~", 1)) {
		return "", "", fmt.Errorf("--deb %s: want <name>_%s_<arch>.deb", file, version)
	}
	return parts[0], parts[2], nil
}

func upload(ctx context.Context, p *env.Portal, path string, bin, sig []byte) (env.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, stack.AdminURL()+path, strings.NewReader(string(bin)))
	if err != nil {
		return env.Response{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Paddock-CSRF", "1")
	req.Header.Set("X-Paddock-Minisig", base64.StdEncoding.EncodeToString(sig))
	resp, err := p.Client.Do(req)
	if err != nil {
		return env.Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	return env.Response{Status: resp.StatusCode, Header: resp.Header, Body: data}, err
}

// haltAll halts every running rollout, so that a new one can start.
func haltAll(ctx context.Context, p *env.Portal) error {
	res, err := p.Do(ctx, http.MethodGet, "/api/platform/v1/agent-releases?page_size=100&sort=-created_at", nil)
	if err != nil || res.Status != http.StatusOK {
		return fail("list", res, err)
	}
	var page struct {
		Items []struct {
			Version       string `json:"version"`
			RolloutStatus string `json:"rollout_status"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		return err
	}
	for _, r := range page.Items {
		if r.RolloutStatus == "running" {
			if res, err := p.Do(ctx, http.MethodPost, "/api/platform/v1/agent-releases/"+r.Version+"/rollout/halt", nil); err != nil || res.Status != http.StatusOK {
				return fail("halt "+r.Version, res, err)
			}
		}
	}
	return nil
}

func fail(step string, res env.Response, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", step, err)
	}
	return fmt.Errorf("%s: HTTP %d %s", step, res.Status, res.Body)
}

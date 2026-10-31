// Package preflight is `paddockd preflight` (plan M11 decision 11): the checks an operator runs on an installed device
// before adopting it. It only reads; it never changes the device.
package preflight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Check results.
const (
	OK   = "ok"
	Warn = "warn"
	Fail = "fail"
	Info = "info"
)

// serverTimeout bounds the GET of the server's /healthz.
const serverTimeout = 10 * time.Second

// Check is one pre-flight check.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Options are the inputs of Run. Root prefixes the sysfs path of the TPM (tests use a temporary directory); a
// ConfigPath enables the server check.
type Options struct {
	Sys        reconcile.System
	LUKS       luks.Tools
	Root       string
	EUID       int
	ConfigPath string
	Proxy      string
	HTTP       *http.Client
}

// Run executes every check in the order of the plan. Checks that cannot run report fail or warn; Run never errors.
func Run(ctx context.Context, o Options) []Check {
	return []Check{
		osCheck(o.Sys),
		systemdCheck(o.Sys),
		rootCheck(o.EUID),
		sudoCheck(ctx, o.Sys),
		tpm2Check(o.Root),
		luksCheck(ctx, o.LUKS),
		sssdCheck(o.Sys),
		himmelblauCheck(o.Sys),
		sudoersDCheck(o.Sys),
		privilegedGroupsCheck(ctx, o.Sys),
		serverCheck(ctx, o),
		clockCheck(ctx, o.Sys),
	}
}

// Failed reports whether a check failed.
func Failed(checks []Check) bool {
	for _, c := range checks {
		if c.Status == Fail {
			return true
		}
	}
	return false
}

// WriteTable prints one line per check.
func WriteTable(w io.Writer, checks []Check) {
	for _, c := range checks {
		_, _ = fmt.Fprintf(w, "%-18s %-5s %s\n", c.Name, c.Status, c.Detail)
	}
}

// WriteJSON prints the checks as a JSON array.
func WriteJSON(w io.Writer, checks []Check) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(checks)
}

func osCheck(sys reconcile.System) Check {
	c := Check{Name: "os"}
	data, _, err := sys.ReadFile("/etc/os-release")
	if err != nil || data == nil {
		c.Status, c.Detail = Fail, "/etc/os-release is not readable"
		return c
	}
	fields := osRelease(string(data))
	name := fields["PRETTY_NAME"]
	if name == "" {
		name = fields["ID"] + " " + fields["VERSION_ID"]
	}
	if fields["ID"] != "ubuntu" || (fields["VERSION_ID"] != "24.04" && fields["VERSION_ID"] != "26.04") {
		c.Status, c.Detail = Fail, name+": Paddock supports Ubuntu 24.04 and 26.04"
		return c
	}
	c.Status, c.Detail = OK, name
	return c
}

func osRelease(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			out[k] = strings.Trim(v, `"'`)
		}
	}
	return out
}

func systemdCheck(sys reconcile.System) Check {
	c := Check{Name: "systemd"}
	if _, info, err := sys.ReadFile("/run/systemd/system"); err != nil || info == nil {
		c.Status, c.Detail = Fail, "systemd is not the running init system (/run/systemd/system is missing)"
		return c
	}
	c.Status, c.Detail = OK, "systemd is running"
	return c
}

func rootCheck(euid int) Check {
	if euid != 0 {
		return Check{Name: "root", Status: Fail, Detail: fmt.Sprintf("running as uid %d; run with sudo", euid)}
	}
	return Check{Name: "root", Status: OK, Detail: "running as root"}
}

func sudoCheck(ctx context.Context, sys reconcile.System) Check {
	flavor, _, err := reconcile.SudoFlavor(ctx, sys)
	if err != nil {
		return Check{Name: "sudo", Status: Fail, Detail: err.Error()}
	}
	return Check{Name: "sudo", Status: OK, Detail: string(flavor)}
}

func tpm2Check(root string) Check {
	if !luks.TPM2Present(root) {
		return Check{Name: "tpm2", Status: Warn, Detail: "no TPM 2.0; disk unlock will rely on a passphrase"}
	}
	return Check{Name: "tpm2", Status: OK, Detail: "TPM 2.0 present"}
}

func luksCheck(ctx context.Context, t luks.Tools) Check {
	c := Check{Name: "luks"}
	_, err := luks.Root(ctx, t)
	switch {
	case err == nil:
		c.Status, c.Detail = OK, "root file system is on LUKS; the agent reports "+protocol.DiskUnmanaged
	case errors.Is(err, luks.ErrNotEncrypted):
		c.Status, c.Detail = Warn, "root file system is not encrypted; the agent reports "+protocol.DiskNotEncrypted
	default:
		c.Status, c.Detail = Warn, "cannot tell whether the root file system is encrypted: "+err.Error()
	}
	return c
}

func sssdCheck(sys reconcile.System) Check {
	if sys.PackageInstalled("sssd") {
		return Check{Name: "sssd", Status: Warn, Detail: "package sssd is installed and conflicts with Himmelblau's NSS and PAM configuration"}
	}
	return Check{Name: "sssd", Status: OK, Detail: "package sssd is not installed"}
}

func himmelblauCheck(sys reconcile.System) Check {
	if v := sys.PackageVersion("himmelblau"); v != "" {
		return Check{Name: "himmelblau", Status: Info, Detail: "installed " + v}
	}
	return Check{Name: "himmelblau", Status: Info, Detail: "not installed; the agent installs it"}
}

// sudoersDCheck names what the sudo reconciler quarantines at the first enforced apply: every entry except its own
// paddock-u-* files and the default allow list (README); an organization's allow list is unknown before enrollment.
func sudoersDCheck(sys reconcile.System) Check {
	c := Check{Name: "sudoers_d"}
	names, err := sys.ReadDir("/etc/sudoers.d")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		c.Status, c.Detail = Warn, "cannot read /etc/sudoers.d: "+err.Error()
		return c
	}
	var foreign []string
	for _, n := range names {
		if strings.HasPrefix(n, "paddock-u-") || n == "README" {
			continue
		}
		foreign = append(foreign, n)
	}
	if len(foreign) == 0 {
		c.Status, c.Detail = OK, "no foreign file in /etc/sudoers.d"
		return c
	}
	c.Status, c.Detail = Warn, "the first enforced apply quarantines, unless the organization allows it: "+strings.Join(foreign, ", ")
	return c
}

// privilegedGroupsCheck lists every member: the organization's break-glass accounts are unknown before enrollment.
func privilegedGroupsCheck(ctx context.Context, sys reconcile.System) Check {
	c := Check{Name: "privileged_groups"}
	var parts []string
	for _, g := range []string{"sudo", "admin"} {
		out, exit, err := sys.Getent(ctx, "group", g)
		if err != nil || exit != 0 {
			continue
		}
		fields := strings.Split(strings.TrimSpace(out), ":")
		if len(fields) < 4 || fields[3] == "" {
			continue
		}
		parts = append(parts, g+": "+fields[3])
	}
	if len(parts) == 0 {
		c.Status, c.Detail = OK, "the groups sudo and admin have no members"
		return c
	}
	c.Status, c.Detail = Warn, strings.Join(parts, "; ")+" (members not named as break-glass accounts lose these groups when enforced)"
	return c
}

func serverCheck(ctx context.Context, o Options) Check {
	c := Check{Name: "server"}
	if o.ConfigPath == "" {
		c.Status, c.Detail = Info, "skipped; pass --config to test the server"
		return c
	}
	raw, err := os.ReadFile(o.ConfigPath)
	if err != nil {
		c.Status, c.Detail = Fail, err.Error()
		return c
	}
	cfg, err := config.ParseEnrollment(raw)
	if err != nil {
		c.Status, c.Detail = Fail, err.Error()
		return c
	}
	// The device gateway has no health route (/healthz is on the internal ops listener). A plain unauthenticated GET
	// of an unrouted /v1 path (the gateway's problem+json catch-all) has no body, token or side effect and causes no
	// audit noise beyond any unauthenticated request; only a Paddock problem answer proves that TLS works and that the
	// gateway, not a captive portal or a proxy error page, answers.
	target := strings.TrimRight(cfg.ServerURL, "/") + "/v1/preflight"
	ctx, cancel := context.WithTimeout(ctx, serverTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		c.Status, c.Detail = Fail, err.Error()
		return c
	}
	client, err := httpClient(o)
	if err != nil {
		c.Status, c.Detail = Fail, err.Error()
		return c
	}
	resp, err := client.Do(req)
	if err != nil {
		c.Status, c.Detail = Fail, "GET "+target+": "+err.Error()
		return c
	}
	defer func() { _ = resp.Body.Close() }()
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json") {
		c.Status, c.Detail = Fail, fmt.Sprintf("GET %s: status %d, but not a Paddock gateway answer (a proxy or captive portal?)", target, resp.StatusCode)
		return c
	}
	c.Status, c.Detail = OK, "the Paddock gateway at "+cfg.ServerURL+" answers"
	return c
}

// httpClient is the injected client or one that uses only the proxy of the options, like paddockd enroll: the
// environment of sudo is not configuration.
func httpClient(o Options) (*http.Client, error) {
	if o.HTTP != nil {
		return o.HTTP, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	if o.Proxy != "" {
		u, err := url.Parse(o.Proxy)
		if err != nil {
			return nil, fmt.Errorf("proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: tr}, nil
}

func clockCheck(ctx context.Context, sys reconcile.System) Check {
	out, _, err := sys.Timedatectl(ctx, "show", "--property=NTP", "--value")
	if err != nil {
		return Check{Name: "clock", Status: Warn, Detail: "cannot read the time synchronization state: " + err.Error()}
	}
	if strings.TrimSpace(out) == "no" {
		return Check{Name: "clock", Status: Warn, Detail: "time synchronization is off; enrollment fails with clock_skew when the clock is wrong"}
	}
	return Check{Name: "clock", Status: OK, Detail: "time synchronization is on"}
}

// Package prodcheck checks the effective Compose configuration of a production host before Paddock starts on it
// (plan M6a decision 2): no development overrides or variables, secret files present and private, production release
// keys, public certificates, no published port beyond 80/443 except on the interconnect address, TLS on every link
// between the two hosts and, online, the audit bucket's Object Lock. A lab host (ADR 0029) runs both halves behind an
// external TLS proxy: its host-shape items are replaced, every other item applies unchanged.
package prodcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// Hosts of the two-host topology (architecture §4.1) and the single lab host (ADR 0029).
const (
	HostControlPlane = "controlplane"
	HostAudit        = "audit"
	HostLab          = "lab"
)

// Config is the part of `docker compose config --format json` the checks read.
type Config struct {
	Services map[string]Service `json:"services"`
	Secrets  map[string]Secret  `json:"secrets"`
	Prod     Prod               `json:"x-paddock-prod"`
}

// Prod is the extension x-paddock-prod of the production overlays: values of .env that the checks need.
type Prod struct {
	InterconnectAddr   string `json:"interconnect_addr"`
	RevocationAccepted string `json:"revocation_accepted"`
	// LabProxyAddr is the TLS proxy's address as the lab host reaches it (compose.lab.yaml).
	LabProxyAddr string `json:"lab_proxy_addr"`
	// AutoUnseal is PADDOCK_AUTO_UNSEAL (compose.prod.yaml), set by ./paddock auto-unseal (ADR 0035).
	AutoUnseal string `json:"auto_unseal"`
}

// Service is one Compose service.
type Service struct {
	Environment map[string]*string `json:"environment"`
	Ports       []Port             `json:"ports"`
	Secrets     []ServiceSecret    `json:"secrets"`
	Volumes     []Volume           `json:"volumes"`
	Command     []string           `json:"command"`
	// ExtraHosts are rendered as "<host>=<ip>" entries.
	ExtraHosts  []string                  `json:"extra_hosts"`
	Networks    map[string]ServiceNetwork `json:"networks"`
	NetworkMode string                    `json:"network_mode"`
	CapAdd      []string                  `json:"cap_add"`
	CapDrop     []string                  `json:"cap_drop"`
	SecurityOpt []string                  `json:"security_opt"`
	PidsLimit   int64                     `json:"pids_limit"`
}

// ServiceNetwork is a service's attachment to one network.
type ServiceNetwork struct {
	Aliases []string `json:"aliases"`
}

// Port is a published port.
type Port struct {
	HostIP    string `json:"host_ip"`
	Target    int    `json:"target"`
	Published string `json:"published"`
}

// ServiceSecret mounts a top-level secret into a service.
type ServiceSecret struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// Secret is a top-level secret.
type Secret struct {
	File string `json:"file"`
}

// Volume is a mount of a service.
type Volume struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	Target string `json:"target"`
}

// Parse reads the JSON output of `docker compose config --format json`.
func Parse(r io.Reader) (Config, error) {
	var c Config
	if err := json.NewDecoder(r).Decode(&c); err != nil {
		return Config{}, fmt.Errorf("parse compose config: %w", err)
	}
	return c, nil
}

// ObjectLockReader reads the audit bucket's Object Lock configuration (the online check).
type ObjectLockReader interface {
	DefaultRetention(ctx context.Context) (enabled bool, mode string, days int32, err error)
}

// Options are the inputs beside the Compose configuration.
type Options struct {
	Host string
	// ComposeFiles are the files the configuration was built from.
	ComposeFiles []string
	// DevReleaseKeys are public keys `make dev-release-key` writes; a configured key equal to one of them fails.
	DevReleaseKeys []string
	// ObjectLock reads the audit bucket online; nil means offline.
	ObjectLock ObjectLockReader
}

// Result is one line of the checklist.
type Result struct {
	Item string
	OK   bool
	// Detail holds the findings, one per line.
	Detail string
	// Warn marks a passed item that still needs the operator's attention (printed WARN, plan M8u decision 20); a
	// warning never fails the check.
	Warn bool
}

// devOnly are the variables honoured only with PADDOCK_ENV=development; any of them in production is a finding even
// where the role would refuse or ignore it, because it shows that development overrides leaked into the host.
var devOnly = []string{
	"PADDOCK_STEPUP_WINDOW", "PADDOCK_STEPUP_MAX_AUTH_AGE", "PADDOCK_STALENESS_UNIT", "PADDOCK_REAPER_THRESHOLD",
	"PADDOCK_OSV_SYNC_INTERVAL", "PADDOCK_LOGIN_MFA_OPTIONAL",
}

// releaseKeyVars name the minisign public keys of agent and revocation releases.
var releaseKeyVars = []string{"PADDOCK_RELEASE_PUBLIC_KEY_FILE", "PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE"}

// MinObjectLockDays is the platform minimum of the audit bucket's default retention (docs/operations/audit-bucket.md).
const MinObjectLockDays = 400

// Run executes every check that applies to the host.
func Run(ctx context.Context, c Config, o Options) []Result {
	results := []Result{
		checkDevOverlay(c, o),
		checkEnv(c),
		checkDevVariables(c),
		checkRevocation(c),
		checkSecretFiles(c),
		checkSecretFilesReadableByServices(c),
		checkMountedReferences(c),
		checkAutoUnseal(c, o),
	}
	lab := o.Host == HostLab
	if lab {
		results = append(results, checkLabPorts(c), checkTLSLinks(c), checkContainerHardening(c), checkLabCaddy(c), checkEdgeClientAddress(c, true),
			checkLabAdminAllowlist(c), checkLabAliases(c), checkLabProxyResolution(c))
	} else {
		results = append(results, checkPorts(c), checkTLSLinks(c), checkContainerHardening(c))
		if _, ok := c.Services["caddy"]; ok {
			results = append(results, checkCaddy(c), checkEdgeClientAddress(c, false))
		}
	}
	if usesAny(c, []string{"PADDOCK_TRUSTED_PROXY_CIDRS"}) {
		results = append(results, checkRoleTrustedProxies(c))
	}
	if _, ok := c.Services["paddock-api"]; ok {
		results = append(results, checkAllowlistBypass(c))
	}
	if usesAny(c, releaseKeyVars) {
		results = append(results, checkReleaseKeys(c, o))
	}
	// The lab's offline check has to pass on its own (plan M8a step PDK-100): there the item exists only with --online.
	if o.Host == HostAudit || (lab && o.ObjectLock != nil) {
		results = append(results, checkObjectLock(ctx, o))
	}
	return results
}

// Write prints the checklist and reports whether every item passed.
func Write(w io.Writer, results []Result) bool {
	ok := true
	for _, r := range results {
		status := "PASS"
		switch {
		case !r.OK:
			status, ok = "FAIL", false
		case r.Warn:
			status = "WARN"
		}
		_, _ = fmt.Fprintln(w, status+"  "+r.Item)
		if r.Detail != "" {
			for _, d := range strings.Split(r.Detail, "\n") {
				_, _ = fmt.Fprintln(w, "      - "+d)
			}
		}
	}
	return ok
}

func result(item string, findings []string) Result {
	slices.Sort(findings)
	return Result{Item: item, OK: len(findings) == 0, Detail: strings.Join(slices.Compact(findings), "\n")}
}

func env(s Service, name string) string {
	if v, ok := s.Environment[name]; ok && v != nil {
		return strings.TrimSpace(*v)
	}
	return ""
}

func sortedServices(c Config) []string {
	names := make([]string, 0, len(c.Services))
	for n := range c.Services {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func usesAny(c Config, vars []string) bool {
	for _, s := range c.Services {
		for _, v := range vars {
			if env(s, v) != "" {
				return true
			}
		}
	}
	return false
}

func checkDevOverlay(c Config, o Options) Result {
	var f []string
	for _, file := range o.ComposeFiles {
		if filepath.Base(file) == "compose.dev.yaml" {
			f = append(f, "compose.dev.yaml is part of the configuration")
		}
	}
	for name := range c.Secrets {
		if strings.HasPrefix(name, "dev_") {
			f = append(f, "development secret "+name)
		}
	}
	for _, name := range sortedServices(c) {
		for _, v := range c.Services[name].Volumes {
			if strings.Contains(v.Target, "paddock-dev") || strings.HasSuffix(v.Source, "/openbao/dev.hcl") {
				f = append(f, fmt.Sprintf("%s: development mount %s", name, v.Target))
			}
		}
	}
	return result("compose.dev.yaml is not in the effective configuration", f)
}

func checkEnv(c Config) Result {
	var f []string
	for _, name := range sortedServices(c) {
		if v := env(c.Services[name], "PADDOCK_ENV"); v != "" && v != "production" {
			f = append(f, fmt.Sprintf("%s: PADDOCK_ENV=%s", name, v))
		}
	}
	return result("PADDOCK_ENV=production in every service", f)
}

func checkDevVariables(c Config) Result {
	var f []string
	for _, name := range sortedServices(c) {
		for k, v := range c.Services[name].Environment {
			if v == nil || strings.TrimSpace(*v) == "" {
				continue
			}
			if slices.Contains(devOnly, k) || strings.HasPrefix(k, "PADDOCK_TEST_") {
				f = append(f, fmt.Sprintf("%s: %s", name, k))
			}
		}
	}
	return result("no development-only variables", f)
}

func checkRevocation(c Config) Result {
	var f []string
	if c.Prod.RevocationAccepted != "yes" {
		for _, name := range sortedServices(c) {
			if env(c.Services[name], "PADDOCK_REVOCATION_ENABLED") == "true" {
				f = append(f, name+": PADDOCK_REVOCATION_ENABLED=true without PADDOCK_REVOCATION_ACCEPTED=yes")
			}
		}
	}
	return result("revocation path enabled only after its acceptance", f)
}

// Automatic unseal of OpenBao (ADR 0035, plan M8u decision 20).
const (
	autoUnsealItem    = "openbao auto-unseal"
	autoUnsealService = "paddock-unsealer"
	autoUnsealShares  = "openbao_auto_unseal_shares"
	autoUnsealRisk    = "automatic unseal is on: whoever controls this host or a copy of its disk, snapshots or .secrets/ can unseal OpenBao and use every key; the custodian threshold of ADR 0006 does not gate the unseal (residual risk RR-43)"
)

// autoUnsealForbiddenEnv are the variables of credentials the unsealer must not hold.
var autoUnsealForbiddenEnv = []string{"PADDOCK_OPENBAO_ROLE_ID_FILE", "PADDOCK_OPENBAO_SECRET_ID_FILE", "PADDOCK_VALKEY_ADDR",
	"PADDOCK_AMQP_URL"}

// checkAutoUnseal: the unsealer and the switch PADDOCK_AUTO_UNSEAL go together, never on the audit host; only the
// unsealer mounts the shares, and it holds no AppRole and no database URL but its own. A production control plane with
// automatic unseal passes with a warning on every run (residual risk RR-43); a lab host passes.
func checkAutoUnseal(c Config, o Options) Result {
	u, has := c.Services[autoUnsealService]
	on := c.Prod.AutoUnseal == "yes"
	var f []string
	if has && !on {
		f = append(f, autoUnsealService+" is configured but PADDOCK_AUTO_UNSEAL is not yes")
	}
	if on && !has {
		f = append(f, "PADDOCK_AUTO_UNSEAL=yes but "+autoUnsealService+" is not in the configuration")
	}
	if (on || has) && o.Host == HostAudit {
		f = append(f, "PADDOCK_AUTO_UNSEAL=yes on the audit host: there is no OpenBao here")
	}
	for _, name := range sortedServices(c) {
		if name == autoUnsealService {
			continue
		}
		for _, sec := range c.Services[name].Secrets {
			if sec.Source == autoUnsealShares {
				f = append(f, name+": mounts "+autoUnsealShares)
			}
		}
	}
	if has {
		for _, sec := range u.Secrets {
			own := sec.Source == "db_paddock_unsealer_url"
			dbURL := strings.HasPrefix(sec.Source, "db_paddock_") && strings.HasSuffix(sec.Source, "_url")
			if strings.HasPrefix(sec.Source, "approle_") || (dbURL && !own) {
				f = append(f, autoUnsealService+": mounts "+sec.Source)
			}
		}
		for _, v := range autoUnsealForbiddenEnv {
			if env(u, v) != "" {
				f = append(f, autoUnsealService+": "+v+" is set")
			}
		}
	}
	switch {
	case len(f) > 0:
		return result(autoUnsealItem, f)
	case has && on:
		return Result{Item: autoUnsealItem, OK: true, Warn: o.Host == HostControlPlane, Detail: autoUnsealRisk}
	default:
		return Result{Item: autoUnsealItem, OK: true, Detail: "automatic unseal is off"}
	}
}

// usedSecrets returns the top-level secrets mounted by at least one service.
func usedSecrets(c Config) []string {
	var names []string
	for _, s := range c.Services {
		for _, sec := range s.Secrets {
			names = append(names, sec.Source)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func checkSecretFiles(c Config) Result {
	var f []string
	for _, name := range usedSecrets(c) {
		sec, ok := c.Secrets[name]
		if !ok || sec.File == "" {
			continue
		}
		fi, err := os.Stat(sec.File)
		switch {
		case err != nil:
			f = append(f, fmt.Sprintf("%s: missing (%s)", name, sec.File))
		case fi.IsDir() || fi.Size() == 0:
			f = append(f, fmt.Sprintf("%s: empty (%s)", name, sec.File))
		default:
			if readable, err := worldReadable(sec.File); err != nil {
				f = append(f, fmt.Sprintf("%s: cannot check who can read it (%s): %v", name, sec.File, err))
			} else if readable {
				f = append(f, fmt.Sprintf("%s: readable by every user of the host (%s)", name, sec.File))
			}
		}
	}
	return result("secret files present, not empty and not world-readable", f)
}

// serviceUID is the user of the Paddock images (USER nonroot in deploy/compose/Dockerfile).
const serviceUID = 65532

// checkSecretFilesReadableByServices: Compose bind-mounts every secret file by path with its own mode and owner, so a
// secret of a Paddock service must be readable by others or owned by the image's user; a 0600 file of the operator
// makes the role fail with "permission denied" (plan M8x decision 49). Third-party images run as other users and are
// not checked.
func checkSecretFilesReadableByServices(c Config) Result {
	var f []string
	for _, name := range sortedServices(c) {
		if !strings.HasPrefix(name, "paddock-") {
			continue
		}
		for _, ref := range c.Services[name].Secrets {
			sec, ok := c.Secrets[ref.Source]
			if !ok || sec.File == "" {
				continue
			}
			fi, err := os.Stat(sec.File)
			if err != nil {
				f = append(f, fmt.Sprintf("%s: %s: cannot check (%s): %v", name, ref.Source, sec.File, err))
				continue
			}
			mode := fi.Mode().Perm()
			uid := -1
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				uid = int(st.Uid)
			}
			if mode&0o004 != 0 || (uid == serviceUID && mode&0o400 != 0) {
				continue
			}
			f = append(f, fmt.Sprintf("%s: %s is not readable by the service user (uid %d): %s has mode %04o, owner uid %d; run chmod 644 %s",
				name, ref.Source, serviceUID, sec.File, mode, uid, sec.File))
		}
	}
	return result("secret files readable by the Paddock services", f)
}

// worldReadable reports whether any local user can read the file: it is readable by others and every directory above
// it lets others pass. A file of mode 0644 in a 0700 directory is private (the secrets directory's layout). Symbolic
// links are resolved first, so that the walk checks the directories that really hold the file; an error is returned,
// never taken as private.
func worldReadable(path string) (bool, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, err
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return false, err
	}
	if fi.Mode().Perm()&0o004 == 0 {
		return false, nil
	}
	dir := filepath.Dir(resolved)
	for {
		di, err := os.Lstat(dir)
		if err != nil {
			return false, err
		}
		if di.Mode().Perm()&0o001 == 0 {
			return false, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return true, nil
		}
		dir = parent
	}
}

// checkMountedReferences fails every path below /run/secrets/ that a service names, in a variable or as the
// sslrootcert of a DSN file, without mounting that secret: such a role cannot start.
func checkMountedReferences(c Config) Result {
	var f []string
	for _, name := range sortedServices(c) {
		s := c.Services[name]
		for k, v := range s.Environment {
			if v == nil {
				continue
			}
			path := strings.TrimSpace(*v)
			if strings.HasPrefix(path, "/run/secrets/") && secretFile(c, s, path) == "" {
				f = append(f, fmt.Sprintf("%s: %s names %s, which is not mounted", name, k, path))
				continue
			}
			if !isDSNVar(k) {
				continue
			}
			if root := dsnRootCert(c, s, path); strings.HasPrefix(root, "/run/secrets/") && secretFile(c, s, root) == "" {
				f = append(f, fmt.Sprintf("%s: the DSN of %s names sslrootcert %s, which is not mounted", name, k, root))
			}
		}
	}
	return result("secrets the services reference are mounted", f)
}

// isDSNVar reports whether the variable names a database DSN file.
func isDSNVar(k string) bool {
	return strings.HasPrefix(k, "PADDOCK_") && strings.Contains(k, "DB") && strings.HasSuffix(k, "_URL_FILE")
}

// dsnRootCert returns the sslrootcert of the DSN file a service sees at containerPath ("" if none or unreadable;
// checkTLSLinks reports an unreadable DSN file).
func dsnRootCert(c Config, s Service, containerPath string) string {
	file := secretFile(c, s, containerPath)
	if file == "" {
		return ""
	}
	b, err := os.ReadFile(file) //nolint:gosec // the path comes from the operator's Compose configuration
	if err != nil {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(string(b)))
	if err != nil {
		return ""
	}
	return u.Query().Get("sslrootcert")
}

func checkPorts(c Config) Result {
	var f []string
	addr := strings.TrimSpace(c.Prod.InterconnectAddr)
	if ip := net.ParseIP(addr); addr != "" && (ip == nil || ip.IsUnspecified()) {
		f = append(f, fmt.Sprintf("PADDOCK_INTERCONNECT_ADDR %q is not a specific IP address", addr))
		addr = ""
	}
	f = append(f, networkModeFindings(c)...)
	for _, name := range sortedServices(c) {
		for _, p := range c.Services[name].Ports {
			// 80 and 443 are public, and only Caddy may hold them.
			if name == "caddy" && (p.Published == "80" || p.Published == "443") {
				continue
			}
			if addr == "" || p.HostIP != addr {
				f = append(f, fmt.Sprintf("%s: port %s published on %q, not on the interconnect address", name, p.Published, hostIP(p)))
			}
		}
	}
	return result("only 80/443 published, other ports on the interconnect address only", f)
}

// checkLabPorts replaces checkPorts on a lab host: Caddy's plain-HTTP port on the bind address is the only published
// port (plan M8a decision 12).
func checkLabPorts(c Config) Result {
	var f []string
	addr := strings.TrimSpace(c.Prod.InterconnectAddr)
	if !specificIP(addr) {
		f = append(f, fmt.Sprintf("PADDOCK_INTERCONNECT_ADDR %q is not a specific IP address", addr))
	}
	f = append(f, networkModeFindings(c)...)
	for _, name := range sortedServices(c) {
		ports := c.Services[name].Ports
		if name != "caddy" {
			for _, p := range ports {
				f = append(f, fmt.Sprintf("%s: port %s published; the lab publishes nothing but Caddy", name, p.Published))
			}
			continue
		}
		for _, p := range ports {
			if p.HostIP != addr {
				f = append(f, fmt.Sprintf("caddy: port %s published on %q, not on the bind address", p.Published, hostIP(p)))
			}
			if p.Target != 80 {
				f = append(f, fmt.Sprintf("caddy: port %s forwards to %d, not to Caddy's plain-HTTP port 80", p.Published, p.Target))
			}
		}
	}
	if n := len(c.Services["caddy"].Ports); n != 1 {
		f = append(f, fmt.Sprintf("caddy: publishes %d ports, want exactly one", n))
	}
	return result("only Caddy's HTTP port published, on the bind address", f)
}

// networkModeFindings reports network namespaces the port items cannot see: the host's own (every port the service
// listens on is reachable) and another container's. Sharing the namespace of a service of this configuration is
// accepted, because that service's ports are checked (PDK-104).
func networkModeFindings(c Config) []string {
	var f []string
	for _, name := range sortedServices(c) {
		mode := strings.TrimSpace(c.Services[name].NetworkMode)
		if target, ok := strings.CutPrefix(mode, "service:"); ok {
			if _, checked := c.Services[target]; checked {
				continue
			}
		}
		switch {
		case mode == "host":
			f = append(f, name+": network_mode host exposes every port of the service on the host")
		case strings.HasPrefix(mode, "service:"), strings.HasPrefix(mode, "container:"):
			f = append(f, fmt.Sprintf("%s: network_mode %s shares a network namespace this check does not see", name, mode))
		}
	}
	return f
}

func specificIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsUnspecified()
}

func hostIP(p Port) string {
	if p.HostIP == "" {
		return "0.0.0.0"
	}
	return p.HostIP
}

// checkTLSLinks requires TLS on every connection that leaves the host: a URL whose host is not a Compose service of
// this host crosses the interconnect (plan M6a amendment 2026-10-08: amqps, Postgres sslmode=verify-full, OpenBao
// over TLS). OpenBao is TLS-only even inside the host (decision 1).
func checkTLSLinks(c Config) Result {
	var f []string
	local := func(host string) bool { _, ok := c.Services[host]; return ok }
	for _, name := range sortedServices(c) {
		s := c.Services[name]
		if v := env(s, "PADDOCK_OPENBAO_ADDR"); v != "" && !strings.HasPrefix(v, "https://") {
			f = append(f, name+": PADDOCK_OPENBAO_ADDR is not https")
		}
		if v := env(s, "PADDOCK_AMQP_URL"); v != "" {
			if u, err := url.Parse(v); err != nil || (!local(u.Hostname()) && u.Scheme != "amqps") {
				f = append(f, name+": PADDOCK_AMQP_URL crosses hosts without amqps")
			}
		}
		for k, v := range s.Environment {
			if v == nil || !isDSNVar(k) {
				continue
			}
			if problem := dsnProblem(c, s, *v, local); problem != "" {
				f = append(f, fmt.Sprintf("%s: %s %s", name, k, problem))
			}
		}
		if name == "rabbitmq" {
			for _, p := range s.Ports {
				if p.Target == 5672 {
					f = append(f, "rabbitmq: plaintext AMQP (5672) published")
				}
			}
		}
	}
	return result("links between the hosts use TLS", f)
}

// checkContainerHardening requires that the Paddock roles and Caddy run without capabilities beyond Caddy's bind to
// 80 and 443 and without privilege gain, and that every service bounds its number of processes (plan M8s decision 36).
func checkContainerHardening(c Config) Result {
	var f []string
	for _, name := range sortedServices(c) {
		s := c.Services[name]
		paddock := strings.HasPrefix(name, "paddock-")
		if paddock || name == "caddy" || name == "caddy-ca-export" {
			if !slices.Equal(s.CapDrop, []string{"ALL"}) {
				f = append(f, name+": cap_drop is not [ALL]")
			}
			if !slices.Contains(s.SecurityOpt, "no-new-privileges:true") {
				f = append(f, name+": security_opt lacks no-new-privileges:true")
			}
		}
		if paddock && len(s.CapAdd) > 0 {
			f = append(f, fmt.Sprintf("%s: cap_add %v", name, s.CapAdd))
		}
		if name == "caddy" && !slices.Equal(s.CapAdd, []string{"NET_BIND_SERVICE"}) {
			f = append(f, fmt.Sprintf("caddy: cap_add %v, want [NET_BIND_SERVICE]", s.CapAdd))
		}
		if s.PidsLimit <= 0 {
			f = append(f, name+": no pids_limit")
		}
	}
	return result("container hardening", f)
}

// dsnProblem reads the DSN file a *_URL_FILE variable names (inside the container: /run/secrets/<target>) and
// reports a cross-host DSN without sslmode=verify-full. The DSN itself never reaches the output.
func dsnProblem(c Config, s Service, containerPath string, local func(string) bool) string {
	file := secretFile(c, s, containerPath)
	if file == "" {
		// checkMountedReferences reports the missing mount.
		return ""
	}
	b, err := os.ReadFile(file) //nolint:gosec // the path comes from the operator's Compose configuration
	if err != nil {
		return "cannot be read"
	}
	u, err := url.Parse(strings.TrimSpace(string(b)))
	if err != nil {
		return "is not a URL"
	}
	if local(u.Hostname()) || u.Query().Get("sslmode") == "verify-full" {
		return ""
	}
	return "crosses hosts without sslmode=verify-full"
}

// secretFile returns the host file of the secret a service sees at containerPath ("" if none).
func secretFile(c Config, s Service, containerPath string) string {
	for _, sec := range s.Secrets {
		target := sec.Target
		if target == "" {
			target = sec.Source
		}
		if !strings.HasPrefix(target, "/") {
			target = "/run/secrets/" + target
		}
		if target == containerPath {
			return c.Secrets[sec.Source].File
		}
	}
	return ""
}

func checkCaddy(c Config) Result {
	var f []string
	s := c.Services["caddy"]
	if env(s, "PADDOCK_ACME_EMAIL") == "" {
		f = append(f, "PADDOCK_ACME_EMAIL is not set")
	}
	mountFindings, _ := caddyMounts(s)
	f = append(f, mountFindings...)
	return result("Caddy: public ACME certificates, edge guards and entrypoint mounted", f)
}

// checkLabCaddy replaces checkCaddy on a lab host: the proxy terminates TLS, so Caddy serves http:// sites with
// auto_https off and needs no ACME e-mail (plan M8a decision 12). The site-address scan is a heuristic over the
// Caddyfile's tokens, not Caddy's own parser (an address with its brace on the next line, a quoted brace or a site in
// an imported snippet can slip past it); the guarantee that nothing but plain HTTP is reachable comes from the ports
// item, which allows exactly one published port with target 80.
func checkLabCaddy(c Config) Result {
	f, content := caddyMounts(c.Services["caddy"])
	autoHTTPSOff := false
	for _, line := range strings.Split(content, "\n") {
		if fields := caddyTokens(line); len(fields) == 2 && fields[0] == "auto_https" && fields[1] == "off" {
			autoHTTPSOff = true
		}
	}
	for _, addr := range caddySiteAddresses(content) {
		if !strings.HasPrefix(addr, "http://") {
			f = append(f, fmt.Sprintf("Caddyfile site %q is not an http:// site", addr))
		}
	}
	if content != "" && !autoHTTPSOff {
		f = append(f, "Caddyfile does not set auto_https off")
	}
	return result("Caddy: plain HTTP behind the TLS proxy", f)
}

// caddyTokens splits a Caddyfile line into tokens and drops a comment: a token that starts with #.
func caddyTokens(line string) []string {
	fields := strings.Fields(line)
	for i, t := range fields {
		if strings.HasPrefix(t, "#") {
			return fields[:i]
		}
	}
	return fields
}

// caddySiteAddresses returns the addresses of every top-level block of a Caddyfile that is neither the global options
// block nor a snippet: the tokens before a "{" at nesting depth 0, including the lines of a comma-continued address
// list, regardless of indentation. Lines at depth 0 that open no block (import) are not addresses.
func caddySiteAddresses(content string) []string {
	var addrs, pending []string
	depth := 0
	for _, line := range strings.Split(content, "\n") {
		tokens := caddyTokens(line)
		if len(tokens) == 0 {
			continue
		}
		if depth == 0 {
			opens := tokens[len(tokens)-1] == "{"
			words := tokens
			if opens {
				words = tokens[:len(tokens)-1]
			}
			var lineAddrs []string
			for _, w := range words {
				lineAddrs = append(lineAddrs, strings.FieldsFunc(w, func(r rune) bool { return r == ',' })...)
			}
			switch {
			case opens:
				block := slices.Concat(pending, lineAddrs)
				pending = nil
				if len(block) > 0 && !strings.HasPrefix(block[0], "(") && !strings.HasPrefix(block[0], "&(") {
					addrs = append(addrs, block...)
				}
			case strings.HasSuffix(words[len(words)-1], ","):
				pending = append(pending, lineAddrs...)
				continue
			default:
				pending = nil
			}
		}
		for _, t := range tokens {
			switch t {
			case "{":
				depth++
			case "}":
				depth--
			}
		}
	}
	return addrs
}

// caddyMounts checks the Caddyfile and the edge files mounted next to it and returns the Caddyfile's content ("" when
// it is missing or unreadable, which is a finding).
func caddyMounts(s Service) ([]string, string) {
	var f []string
	var content string
	mounts := map[string]string{}
	for _, v := range s.Volumes {
		mounts[v.Target] = v.Source
	}
	caddyfile, found := mounts["/etc/caddy/Caddyfile"]
	if !found {
		f = append(f, "no Caddyfile mounted")
	} else if b, err := os.ReadFile(caddyfile); err != nil { //nolint:gosec // operator configuration
		f = append(f, "Caddyfile unreadable: "+caddyfile)
	} else {
		content = string(b)
		f = append(f, caddyfileFindings(caddyfile, content)...)
	}
	// The edge guards and the entrypoint belong next to the Caddyfile (plan M7a decisions 2 and 6; an operator
	// bundle ships them in the same directory).
	for target, name := range map[string]string{"/etc/caddy/guards.caddy": "guards.caddy", "/paddock/entrypoint.sh": "entrypoint.sh"} {
		src, ok := mounts[target]
		switch {
		case !ok:
			f = append(f, fmt.Sprintf("%s is not mounted (expected %s next to the Caddyfile)", target, name))
		case found && src != filepath.Join(filepath.Dir(caddyfile), name):
			f = append(f, fmt.Sprintf("%s is mounted from %s, not from %s next to the Caddyfile", target, src, name))
		}
	}
	return f, content
}

// caddyfileFindings reports tls internal and the client address options the Caddyfile sets itself: trusted_proxies
// and client_ip_headers come from the entrypoint only (plan M7a decision 24).
func caddyfileFindings(path, content string) []string {
	var f []string
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case len(fields) >= 2 && fields[0] == "tls" && fields[1] == "internal":
			f = append(f, "Caddyfile uses tls internal: "+path)
		case fields[0] == "trusted_proxies" || fields[0] == "trusted_proxies_strict" || fields[0] == "client_ip_headers":
			f = append(f, fmt.Sprintf("Caddyfile declares %s itself (only caddy/entrypoint.sh may): %s", fields[0], path))
		}
	}
	return f
}

// edgeHeaders are the values of PADDOCK_EDGE_CLIENT_IP_HEADER allowed in production: exactly one.
var edgeHeaders = []string{"none", "X-Forwarded-For", "CF-Connecting-IP"}

// checkEdgeClientAddress checks the trusted proxies and the client address header of the edge (plan M7a decisions 1
// and 24): one known header, proxies exactly when a header is read, no /0, the servers block on every listener. Behind
// the lab proxy (plan M8a decision 12) the header is X-Forwarded-For and the proxy list is not empty and does not hold
// private_ranges.
func checkEdgeClientAddress(c Config, lab bool) Result {
	var f []string
	s := c.Services["caddy"]
	header := env(s, "PADDOCK_EDGE_CLIENT_IP_HEADER")
	if header == "" {
		header = "none"
	}
	proxies := strings.Fields(env(s, "PADDOCK_EDGE_TRUSTED_PROXIES"))
	if !slices.Contains(edgeHeaders, header) {
		f = append(f, fmt.Sprintf("PADDOCK_EDGE_CLIENT_IP_HEADER %q is not exactly one of none, X-Forwarded-For, CF-Connecting-IP", header))
	}
	switch {
	case header != "none" && len(proxies) == 0:
		f = append(f, fmt.Sprintf("PADDOCK_EDGE_CLIENT_IP_HEADER is %s but PADDOCK_EDGE_TRUSTED_PROXIES is empty: no trusted proxy may send it", header))
	case header == "none" && len(proxies) > 0:
		f = append(f, "PADDOCK_EDGE_TRUSTED_PROXIES is set but PADDOCK_EDGE_CLIENT_IP_HEADER is none")
	}
	for _, p := range proxies {
		if p == "private_ranges" {
			continue
		}
		if problem := rangeProblem(p, true); problem != "" {
			f = append(f, "PADDOCK_EDGE_TRUSTED_PROXIES: "+problem)
		}
	}
	if v := env(s, "PADDOCK_EDGE_SERVERS_LISTENER"); v != "" {
		f = append(f, fmt.Sprintf("PADDOCK_EDGE_SERVERS_LISTENER is %q: production applies the servers block to every listener", v))
	}
	if lab {
		if header != "X-Forwarded-For" {
			f = append(f, "PADDOCK_EDGE_CLIENT_IP_HEADER must be X-Forwarded-For behind the lab proxy")
		}
		if len(proxies) == 0 {
			f = append(f, "PADDOCK_EDGE_TRUSTED_PROXIES is empty: name the lab proxy's address")
		}
		if slices.Contains(proxies, "private_ranges") {
			f = append(f, "PADDOCK_EDGE_TRUSTED_PROXIES: private_ranges trusts every LAN peer; name the proxy's address")
		}
	}
	return result("edge client address", f)
}

// checkLabAdminAllowlist requires a real edge admin allow list on a lab host, where the compose.prod.yaml default of
// every address would open the administrative surfaces to everybody who reaches the proxy (plan M8a decision 12).
func checkLabAdminAllowlist(c Config) Result {
	var f []string
	ranges := strings.Fields(env(c.Services["caddy"], "PADDOCK_ADMIN_ALLOWED_CIDRS"))
	if len(ranges) == 0 {
		f = append(f, "PADDOCK_ADMIN_ALLOWED_CIDRS is empty: name the networks that may open the portal")
	}
	for _, p := range ranges {
		if p == "private_ranges" {
			continue
		}
		if problem := rangeProblem(p, true); problem != "" {
			f = append(f, "PADDOCK_ADMIN_ALLOWED_CIDRS: "+problem)
		}
	}
	return result("lab: edge admin allow list", f)
}

// checkLabAliases fails Caddy's network aliases on a lab host: a role resolving a public name to Caddy would bypass
// the TLS proxy and reach a plain-HTTP listener (ADR 0029).
func checkLabAliases(c Config) Result {
	var f []string
	nets := c.Services["caddy"].Networks
	names := make([]string, 0, len(nets))
	for n := range nets {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		for _, a := range nets[n].Aliases {
			f = append(f, fmt.Sprintf("caddy: alias %s on network %s would short-circuit the proxy", a, n))
		}
	}
	return result("lab: caddy has no hostname aliases", f)
}

// labRoles are the roles that call the public names (Authentik, the OIDC issuers, the certificate probe).
var labRoles = []string{"paddock-api", "paddock-escrow-reader", "paddock-revocation-issuer", "paddock-worker"}

// labNames are the public host names below the domain.
var labNames = []string{"admin", "auth", "device", "bundles", "fleet"}

// checkLabProxyResolution requires the roles to resolve every public name to the TLS proxy and the worker's
// certificate probe to dial it (plan M8a decisions 4 and 12).
func checkLabProxyResolution(c Config) Result {
	const item = "lab: roles resolve the public names to the proxy"
	proxy := strings.TrimSpace(c.Prod.LabProxyAddr)
	if !specificIP(proxy) {
		return result(item, []string{fmt.Sprintf("PADDOCK_LAB_PROXY_ADDR %q is not a specific IP address", proxy)})
	}
	adminURL := env(c.Services["paddock-api"], "PADDOCK_PUBLIC_ADMIN_URL")
	domain, hasPrefix := "", false
	if u, err := url.Parse(adminURL); err == nil && u.Scheme == "https" {
		domain, hasPrefix = strings.CutPrefix(u.Hostname(), "admin.")
	}
	if !hasPrefix || domain == "" {
		return result(item, []string{fmt.Sprintf("paddock-api: PADDOCK_PUBLIC_ADMIN_URL %q is not https://admin.<domain>", adminURL)})
	}
	var f []string
	for _, role := range labRoles {
		hosts := c.Services[role].ExtraHosts
		for _, n := range labNames {
			name := n + "." + domain
			found := false
			// Every entry for the name counts: Compose sorts extra_hosts, so a second entry from another overlay may be
			// the one the role resolves. Host names match like the resolver matches them: case-insensitively and
			// with or without the trailing dot.
			for _, h := range hosts {
				host, ip, ok := strings.Cut(h, "=")
				if !ok || !strings.EqualFold(strings.TrimSuffix(host, "."), name) {
					continue
				}
				found = true
				if ip != proxy {
					f = append(f, fmt.Sprintf("%s: extra_hosts maps %s to %s, not to the proxy %s", role, name, ip, proxy))
				}
			}
			if !found {
				f = append(f, fmt.Sprintf("%s: extra_hosts lacks %s=%s", role, name, proxy))
			}
		}
	}
	if v, want := env(c.Services["paddock-worker"], "PADDOCK_TLS_PROBE_ADDR"), proxy+":443"; v != want {
		f = append(f, fmt.Sprintf("paddock-worker: PADDOCK_TLS_PROBE_ADDR is %q, not %s", v, want))
	}
	return result(item, f)
}

// rangeProblem describes why s is not an acceptable trusted range: unparsable, or a /0 that trusts every address.
// Single addresses are accepted where the consumer accepts them (Caddy does, the roles do not).
func rangeProblem(s string, addrOK bool) string {
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" && addrOK {
		return ""
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return fmt.Sprintf("%s is not a CIDR", s)
	}
	if p.Bits() == 0 {
		return fmt.Sprintf("%s trusts every address", s)
	}
	return ""
}

// checkRoleTrustedProxies checks PADDOCK_TRUSTED_PROXY_CIDRS of every role (plan M7a decisions 4 and 24).
func checkRoleTrustedProxies(c Config) Result {
	var f []string
	for _, name := range sortedServices(c) {
		for _, p := range strings.Fields(env(c.Services[name], "PADDOCK_TRUSTED_PROXY_CIDRS")) {
			if problem := rangeProblem(p, false); problem != "" {
				f = append(f, fmt.Sprintf("%s: PADDOCK_TRUSTED_PROXY_CIDRS: %s", name, problem))
			}
		}
	}
	return result("role trusted proxies", f)
}

// checkAllowlistBypass fails while the api bypasses the application IP allow list (plan M7a decision 22).
func checkAllowlistBypass(c Config) Result {
	var f []string
	if v, err := strconv.ParseBool(env(c.Services["paddock-api"], "PADDOCK_IP_ALLOWLIST_BYPASS")); err == nil && v {
		f = append(f, "paddock-api: PADDOCK_IP_ALLOWLIST_BYPASS is true (break-glass; remove it once access is restored)")
	}
	return result("ip allow list bypass is off", f)
}

func checkReleaseKeys(c Config, o Options) Result {
	var f []string
	for _, name := range sortedServices(c) {
		s := c.Services[name]
		for _, v := range releaseKeyVars {
			path := env(s, v)
			if path == "" {
				continue
			}
			file := secretFile(c, s, path)
			if file == "" {
				continue
			}
			if _, err := os.Stat(strings.TrimSuffix(file, ".pub") + ".key"); err == nil {
				f = append(f, fmt.Sprintf("%s: the secret key of %s lies on this host (development key)", v, file))
			}
			if isDevKey(file, o.DevReleaseKeys) {
				f = append(f, fmt.Sprintf("%s: %s is the development release key", v, file))
			}
		}
	}
	return result("release public keys are production keys", f)
}

// isDevKey compares the key line of a minisign public key file with the development keys.
func isDevKey(file string, devKeys []string) bool {
	key := minisignKey(file)
	if key == "" {
		return false
	}
	for _, d := range devKeys {
		if minisignKey(d) == key {
			return true
		}
	}
	return false
}

func minisignKey(file string) string {
	b, err := os.ReadFile(file) //nolint:gosec // operator configuration
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "untrusted comment:") {
			return line
		}
	}
	return ""
}

func checkObjectLock(ctx context.Context, o Options) Result {
	const item = "audit bucket has Object Lock COMPLIANCE"
	if o.ObjectLock == nil {
		return Result{Item: item, Detail: "not checked (run with ONLINE=1)"}
	}
	enabled, mode, days, err := o.ObjectLock.DefaultRetention(ctx)
	switch {
	case err != nil:
		return Result{Item: item, Detail: "cannot read the Object Lock configuration: " + err.Error()}
	case !enabled:
		return Result{Item: item, Detail: "Object Lock is not enabled"}
	case mode != "COMPLIANCE":
		return Result{Item: item, Detail: fmt.Sprintf("default retention mode is %q, not COMPLIANCE", mode)}
	case days < MinObjectLockDays:
		return Result{Item: item, Detail: fmt.Sprintf("default retention is %d days, less than %d", days, MinObjectLockDays)}
	}
	return Result{Item: item, OK: true}
}

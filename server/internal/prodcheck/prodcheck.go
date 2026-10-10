// Package prodcheck checks the effective Compose configuration of a production host before Paddock starts on it
// (plan M6a decision 2): no development overrides or variables, secret files present and private, production release
// keys, public certificates, no published port beyond 80/443 except on the interconnect address, TLS on every link
// between the two hosts and, online, the audit bucket's Object Lock.
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
)

// Hosts of the two-host topology (architecture §4.1).
const (
	HostControlPlane = "controlplane"
	HostAudit        = "audit"
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
}

// Service is one Compose service.
type Service struct {
	Environment map[string]*string `json:"environment"`
	Ports       []Port             `json:"ports"`
	Secrets     []ServiceSecret    `json:"secrets"`
	Volumes     []Volume           `json:"volumes"`
	Command     []string           `json:"command"`
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
}

// devOnly are the variables honoured only with PADDOCK_ENV=development; any of them in production is a finding even
// where the role would refuse or ignore it, because it shows that development overrides leaked into the host.
var devOnly = []string{
	"PADDOCK_STEPUP_WINDOW", "PADDOCK_STEPUP_MAX_AUTH_AGE", "PADDOCK_STALENESS_UNIT", "PADDOCK_REAPER_THRESHOLD",
	"PADDOCK_OSV_SYNC_INTERVAL",
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
		checkMountedReferences(c),
		checkPorts(c),
		checkTLSLinks(c),
	}
	if _, ok := c.Services["caddy"]; ok {
		results = append(results, checkCaddy(c), checkEdgeClientAddress(c))
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
	if o.Host == HostAudit {
		results = append(results, checkObjectLock(ctx, o))
	}
	return results
}

// Write prints the checklist and reports whether every item passed.
func Write(w io.Writer, results []Result) bool {
	ok := true
	for _, r := range results {
		status := "PASS"
		if !r.OK {
			status, ok = "FAIL", false
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
		f = append(f, caddyfileFindings(caddyfile, string(b))...)
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
	return result("Caddy: public ACME certificates, edge guards and entrypoint mounted", f)
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
// and 24): one known header, proxies exactly when a header is read, no /0, the servers block on every listener.
func checkEdgeClientAddress(c Config) Result {
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
	return result("edge client address", f)
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

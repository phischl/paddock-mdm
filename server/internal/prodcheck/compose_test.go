package prodcheck_test

import (
	"bytes"
	"context"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

const mountedItem = "secrets the services reference are mounted"

// composeDir is deploy/compose of the repository.
func composeDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "deploy", "compose"))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// prodFiles reads the Compose files of a host from scripts/lib.sh (PROD_FILES_<host>), the single list the operator
// bundle and its ./paddock check use (plan M7b decision 18).
func prodFiles(t *testing.T, host string) []string {
	t.Helper()
	return libFiles(t, "PROD_FILES_"+host)
}

// libFiles reads one file list of scripts/lib.sh.
func libFiles(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(composeDir(t), "scripts", "lib.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^` + name + `="(.+)"$`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("no %s in scripts/lib.sh", name)
	}
	return strings.Fields(string(m[1]))
}

// renderConfig runs `docker compose config --format json` over files with the settings template prod.env.example.
func renderConfig(t *testing.T, files []string, envFiles ...string) prodcheck.Config {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	dir := composeDir(t)
	args := []string{"compose", "--project-directory", dir, "-p", "paddock", "--env-file", filepath.Join(dir, "versions.env")}
	for _, e := range envFiles {
		args = append(args, "--env-file", filepath.Join(dir, e))
	}
	for _, f := range files {
		args = append(args, "-f", filepath.Join(dir, f))
	}
	args = append(args, "--profile", "*", "config", "--format", "json")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // fixed arguments of the test
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3.example.org")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose config %v: %v: %s", files, err, stderr.String())
	}
	cfg, err := prodcheck.Parse(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	// The check is about the configuration, not about the secret files of this checkout.
	for name, s := range cfg.Secrets {
		s.File = "/nonexistent/" + name
		cfg.Secrets[name] = s
	}
	return cfg
}

func mountedResult(t *testing.T, cfg prodcheck.Config) prodcheck.Result {
	t.Helper()
	for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{}) {
		if r.Item == mountedItem {
			return r
		}
	}
	t.Fatalf("no item %q", mountedItem)
	return prodcheck.Result{}
}

// TestComposeConfigsMountEverySecretTheyName renders the real Compose configurations (both production hosts, the lab
// with and without backups and the development stack with and without backups) and requires that every /run/secrets/ path a service names is mounted
// (regression of review 1 finding 1: the worker's backup secrets dropped by `secrets: !override`).
func TestComposeConfigsMountEverySecretTheyName(t *testing.T) {
	cases := map[string]struct {
		files    []string
		envFiles []string
	}{
		"production control plane": {prodFiles(t, "controlplane"), []string{"prod.env.example"}},
		"production audit host":    {prodFiles(t, "audit"), []string{"prod.env.example"}},
		"lab":                      {prodFiles(t, "lab"), []string{"lab.env.example"}},
		"lab with backups":         {append(prodFiles(t, "lab"), libFiles(t, "LAB_BACKUP_FILES")...), []string{"lab.env.example"}},
		"development":              {libFiles(t, "DEV_FILES"), []string{".env.example"}},
		"development with backups": {append(libFiles(t, "DEV_FILES"), libFiles(t, "DEV_BACKUP_FILES")...), []string{".env.example"}},
		"control plane with automatic unseal": {append(prodFiles(t, "controlplane"), libFiles(t, "AUTO_UNSEAL_FILES")...),
			[]string{"prod.env.example"}},
		"lab with automatic unseal and backups": {append(append(prodFiles(t, "lab"), libFiles(t, "AUTO_UNSEAL_FILES")...),
			libFiles(t, "LAB_BACKUP_FILES")...), []string{"lab.env.example"}},
		"control plane upgraded with a legacy key file": {append(prodFiles(t, "controlplane"), libFiles(t, "BACKUP_LEGACY_KEY_FILES")...),
			[]string{"prod.env.example"}},
		"lab with backups upgraded with a legacy key file": {append(append(prodFiles(t, "lab"), libFiles(t, "LAB_BACKUP_FILES")...),
			libFiles(t, "BACKUP_LEGACY_KEY_FILES")...), []string{"lab.env.example"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := mountedResult(t, renderConfig(t, tc.files, tc.envFiles...))
			if !r.OK {
				t.Fatalf("%s:\n%s", r.Item, r.Detail)
			}
		})
	}
	// Plan M15 decisions 15 and 18: the backup secrets moved from the worker to the backup role.
	t.Run("backup secrets reach the backup role, not the worker", func(t *testing.T) {
		cfg := renderConfig(t, prodFiles(t, "controlplane"), "prod.env.example")
		mounted := func(service string) map[string]bool {
			m := map[string]bool{}
			for _, s := range cfg.Services[service].Secrets {
				m[s.Source] = true
			}
			return m
		}
		backup, worker := mounted("paddock-backup"), mounted("paddock-worker")
		for _, want := range []string{"db_paddock_backup_url", "db_paddock_platform_url", "approle_backup_role_id",
			"approle_backup_secret_id", "rustfs_escrow_backup_access_key", "rustfs_escrow_backup_secret_key",
			"internal_ca_bundle"} {
			if !backup[want] {
				t.Errorf("paddock-backup does not mount %s", want)
			}
		}
		for name := range worker {
			if strings.Contains(name, "backup") {
				t.Errorf("paddock-worker mounts %s", name)
			}
		}
		for _, name := range []string{"fleet-backup-upload", "backup-s3-tls"} {
			if _, ok := cfg.Services[name]; ok {
				t.Errorf("service %s is still configured", name)
			}
		}
		for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{}) {
			if strings.HasPrefix(r.Item, "backup:") && !r.OK {
				t.Errorf("%s:\n%s", r.Item, r.Detail)
			}
		}
		// decisions-alpha9 item 44: the restore's escrow step alone reaches the audit index with the reader credential.
		restore := mounted("backup-restore-escrow")
		for _, want := range []string{"db_paddock_audit_reader_url", "rustfs_escrow_backup_access_key",
			"rustfs_escrow_backup_secret_key", "rustfs_bundles_gateway_access_key", "rustfs_bundles_gateway_secret_key",
			"internal_ca_bundle"} {
			if !restore[want] {
				t.Errorf("backup-restore-escrow does not mount %s", want)
			}
		}
		if restore["approle_backup_secret_id"] || restore["db_paddock_backup_url"] || backup["db_paddock_audit_reader_url"] {
			t.Error("the AppRole or the backup database credential reaches the escrow step, or the audit reader the backup role")
		}
		networks := slices.Sorted(maps.Keys(cfg.Services["backup-restore-escrow"].Networks))
		if !slices.Equal(networks, []string{"audit-index", "data"}) {
			t.Errorf("backup-restore-escrow networks %v, want [audit-index data]", networks)
		}
		if _, ok := cfg.Services["paddock-backup"].Networks["audit-index"]; ok {
			t.Error("paddock-backup joins audit-index")
		}
	})
	// decisions-alpha9 item 63: a fresh control plane neither imports nor mounts a legacy key; the overlay ./paddock
	// adds while the host file exists mounts it into the api alone, and the backup items still pass.
	t.Run("legacy key import only with the overlay", func(t *testing.T) {
		fresh := renderConfig(t, prodFiles(t, "controlplane"), "prod.env.example")
		if _, ok := fresh.Secrets["backup_encryption_key"]; ok {
			t.Error("a fresh control plane defines the secret backup_encryption_key")
		}
		if v := fresh.Services["paddock-api"].Environment["PADDOCK_BACKUP_LEGACY_KEY_FILE"]; v != nil {
			t.Errorf("a fresh control plane sets PADDOCK_BACKUP_LEGACY_KEY_FILE=%s", *v)
		}
		upgraded := renderConfig(t, append(prodFiles(t, "controlplane"), libFiles(t, "BACKUP_LEGACY_KEY_FILES")...), "prod.env.example")
		for name, s := range upgraded.Services {
			if mounts := slices.ContainsFunc(s.Secrets, func(m prodcheck.ServiceSecret) bool { return m.Source == "backup_encryption_key" }); mounts != (name == "paddock-api") {
				t.Errorf("%s mounts backup_encryption_key: %v", name, mounts)
			}
		}
		if v := upgraded.Services["paddock-api"].Environment["PADDOCK_BACKUP_LEGACY_KEY_FILE"]; v == nil || *v != "/run/secrets/backup_encryption_key" {
			t.Errorf("the upgraded api's PADDOCK_BACKUP_LEGACY_KEY_FILE is %v", v)
		}
		for _, r := range prodcheck.Run(context.Background(), upgraded, prodcheck.Options{}) {
			if strings.HasPrefix(r.Item, "backup:") && !r.OK {
				t.Errorf("%s:\n%s", r.Item, r.Detail)
			}
		}
	})
}

// roleProxy matches a reverse_proxy to a Paddock role and the rest of its block up to the closing brace.
var roleProxy = regexp.MustCompile(`reverse_proxy (paddock-api:8080|paddock-gateway:8081)([^}]*}?)`)

// TestCaddyfilesEdge: the three Caddyfiles carry the rendered servers block and import the shared guards, and every proxy
// to a Paddock role replaces X-Paddock-Client-IP with the resolved client address (plan M7a decisions 2, 3, 6).
func TestCaddyfilesEdge(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(composeDir(t), "caddy", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, name := range []string{"Caddyfile", "Caddyfile.prod", "Caddyfile.lab"} {
		s := read(name)
		if !strings.Contains(s, "\t{$CADDY_SERVERS_BLOCK}\n}") {
			t.Errorf("%s: {$CADDY_SERVERS_BLOCK} is not the last line of the global options", name)
		}
		if !strings.Contains(s, "\nimport /etc/caddy/guards.caddy\n") {
			t.Errorf("%s does not import the guards", name)
		}
		for _, site := range []string{"admin.{$PADDOCK_DOMAIN} {", "auth.{$PADDOCK_DOMAIN} {"} {
			i := strings.Index(s, site)
			if i < 0 {
				t.Fatalf("%s: no site %s", name, site)
			}
			if body := s[i : i+strings.Index(s[i:], "\n}")]; !strings.Contains(body, "\timport admin_site") && !strings.Contains(body, "\timport authentik_site") {
				t.Errorf("%s: site %s does not import its guard", name, site)
			}
		}
	}
	proxies := 0
	for _, name := range []string{"Caddyfile", "Caddyfile.prod", "Caddyfile.lab", "guards.caddy"} {
		for _, m := range roleProxy.FindAllStringSubmatch(read(name), -1) {
			proxies++
			if !strings.HasPrefix(strings.TrimLeft(m[2], " "), "{") || !strings.Contains(m[2], "header_up X-Paddock-Client-IP {client_ip}") {
				t.Errorf("%s: reverse_proxy %s does not set X-Paddock-Client-IP", name, m[1])
			}
		}
	}
	// The bundles host proxies GET and HEAD of /apt/* to the api, which checks the repository credential and redirects
	// to a presigned GET (plan M13c decision 14, ADR 0050, PDK-812): one more role proxy in each Caddyfile.
	if proxies != 7 {
		t.Errorf("found %d proxies to Paddock roles, want 7 (admin_site, device. and bundles. /apt/* in the three Caddyfiles)", proxies)
	}
	// Plan M8s decision 31: every proxy to a role or an upstream is preceded by a request body limit in its block.
	limited := 0
	for _, name := range []string{"Caddyfile", "Caddyfile.prod", "Caddyfile.lab", "guards.caddy"} {
		lines := strings.Split(read(name), "\n")
		for i, line := range lines {
			m := upstreamProxy.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			limited++
			if !requestBodyBefore(lines, i) {
				t.Errorf("%s:%d: reverse_proxy %s has no request_body before it in its block", name, i+1, m[1])
			}
		}
	}
	// body_limit answers a declared Content-Length above the limit with 413 before the upstream sees the request, and
	// bounds the body with request_body (an upstream that answers without reading the body would hide the limit).
	if g := read("guards.caddy"); !strings.Contains(g, "(body_limit) {") || !strings.Contains(g, "max_size {args[0]}") ||
		!strings.Contains(g, "int({http.request.header.Content-Length}) > {args[1]}") {
		t.Error("guards.caddy has no body_limit snippet with a Content-Length check and request_body")
	}
	// The bundles host's /apt/* proxy to the api (PDK-812) is the sixth in each Caddyfile.
	if limited != 20 {
		t.Errorf("found %d proxies to roles and upstreams, want 20 (2 in the guards, 6 in each Caddyfile)", limited)
	}
	// Plan M12h decision 16: every site imports the hardening headers, and the snippet sets all four.
	g := read("guards.caddy")
	for _, want := range []string{"(hardening_headers) {", "\t\tdefer\n", "X-Content-Type-Options nosniff",
		`Strict-Transport-Security "max-age=31536000; includeSubDomains"`, "X-Frame-Options DENY",
		"header ?Referrer-Policy strict-origin-when-cross-origin"} {
		if !strings.Contains(g, want) {
			t.Errorf("guards.caddy: hardening_headers lacks %q", want)
		}
	}
	for _, name := range []string{"Caddyfile", "Caddyfile.prod", "Caddyfile.lab"} {
		lines := strings.Split(read(name), "\n")
		sites := 0
		for i, line := range lines {
			if !strings.HasSuffix(line, " {") || strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "{") {
				continue
			}
			sites++
			if i+1 >= len(lines) || lines[i+1] != "\timport hardening_headers" {
				t.Errorf("%s:%d: site %q does not import hardening_headers first", name, i+1, line)
			}
		}
		if sites < 5 {
			t.Errorf("%s: found %d sites, want at least 5", name, sites)
		}
	}
}

// upstreamProxy matches a reverse_proxy to a Paddock role or an upstream the edge publishes.
var upstreamProxy = regexp.MustCompile(`^\t*reverse_proxy (paddock-api|paddock-gateway|rustfs|fleet|authentik-server):`)

// requestBodyBefore reports whether a request_body directive precedes line i at its indentation in the same block.
func requestBodyBefore(lines []string, i int) bool {
	depth := len(lines[i]) - len(strings.TrimLeft(lines[i], "\t"))
	for j := i - 1; j >= 0; j-- {
		l := lines[j]
		if strings.TrimSpace(l) == "" {
			continue
		}
		d := len(l) - len(strings.TrimLeft(l, "\t"))
		if d < depth {
			return false
		}
		if d == depth && (strings.HasPrefix(strings.TrimSpace(l), "request_body") || strings.HasPrefix(strings.TrimSpace(l), "import body_limit ")) {
			return true
		}
	}
	return false
}

// TestProductionEdge renders the production control plane: Caddy publishes 80 and 443 only, runs the entrypoint with
// the guards next to the Caddyfile, and the edge items pass with the defaults of prod.env.example.
func TestProductionEdge(t *testing.T) {
	cfg := renderConfig(t, prodFiles(t, "controlplane"), "prod.env.example")
	var published []string
	for _, p := range cfg.Services["caddy"].Ports {
		published = append(published, p.Published)
	}
	slices.Sort(published)
	if !slices.Equal(published, []string{"443", "80"}) {
		t.Errorf("caddy publishes %v, want 80 and 443 only", published)
	}
	for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{}) {
		switch r.Item {
		case "edge client address", "role trusted proxies", "container hardening", "networks: caddy on edge only",
			"networks: no datastore on edge", "networks: fleet, caddy and authentik not on data",
			"trusted proxies: caddy's address only", "edge: internal ranges are not private_ranges",
			"rabbitmq: management bound to loopback", "rabbitmq: memory limit readable by the memory alarm":
			if !r.OK {
				t.Errorf("%s:\n%s", r.Item, r.Detail)
			}
		case "Caddy: public ACME certificates, edge guards and entrypoint mounted":
			if !r.OK {
				t.Errorf("%s:\n%s", r.Item, r.Detail)
			}
		}
	}
}

// TestLabEdge renders the lab (plan M8a decision 10): Caddy publishes one port, on the bind address, and has no
// hostname aliases, nothing else is published, and the edge and lab items pass with the values of lab.env.example.
func TestLabEdge(t *testing.T) {
	cfg := renderConfig(t, prodFiles(t, "lab"), "lab.env.example")
	caddy := cfg.Services["caddy"]
	if len(caddy.Ports) != 1 || caddy.Ports[0].HostIP != "192.0.2.10" || caddy.Ports[0].Target != 80 {
		t.Errorf("caddy publishes %+v, want exactly 192.0.2.10:<port>:80", caddy.Ports)
	}
	for _, name := range []string{"openbao", "rabbitmq", "audit-postgres"} {
		if p := cfg.Services[name].Ports; len(p) != 0 {
			t.Errorf("%s publishes %+v, want nothing", name, p)
		}
	}
	for network, n := range caddy.Networks {
		if len(n.Aliases) != 0 {
			t.Errorf("caddy has aliases %v on network %s", n.Aliases, network)
		}
	}
	want := map[string]bool{
		"edge client address":                                   false,
		"role trusted proxies":                                  false,
		"Caddy: plain HTTP behind the TLS proxy":                false,
		"lab: edge admin allow list":                            false,
		"lab: caddy has no hostname aliases":                    false,
		"lab: roles resolve the public names to the proxy":      false,
		"only Caddy's HTTP port published, on the bind address": false,
		"container hardening":                                   false,
		"networks: caddy on edge only":                          false,
		"networks: no datastore on edge":                        false,
		"networks: fleet, caddy and authentik not on data":      false,
		"trusted proxies: caddy's address only":                 false,
		"edge: internal ranges are not private_ranges":          false,
		"rabbitmq: management bound to loopback":                false,
		"rabbitmq: memory limit readable by the memory alarm":   false,
	}
	for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{Host: prodcheck.HostLab}) {
		if _, ok := want[r.Item]; !ok {
			continue
		}
		want[r.Item] = true
		if !r.OK {
			t.Errorf("%s:\n%s", r.Item, r.Detail)
		}
	}
	for item, seen := range want {
		if !seen {
			t.Errorf("no item %q", item)
		}
	}
}

// TestNetworkSegmentation renders every host file set that runs Caddy (ADR 0051 decision 1): Caddy is on edge alone
// at the fixed address, no datastore is on edge, Fleet, Caddy and Authentik are off data, Authentik's worker and
// database are on the internal network authentik only, and the roles trust Caddy's address alone. The development
// stack keeps the production topology.
func TestNetworkSegmentation(t *testing.T) {
	cases := map[string]struct {
		files    []string
		envFiles []string
	}{
		"production control plane": {prodFiles(t, "controlplane"), []string{"prod.env.example"}},
		"production control plane with automatic unseal": {append(prodFiles(t, "controlplane"), "compose.auto-unseal.yaml"),
			[]string{"prod.env.example"}},
		"lab":              {prodFiles(t, "lab"), []string{"lab.env.example"}},
		"lab with backups": {append(prodFiles(t, "lab"), libFiles(t, "LAB_BACKUP_FILES")...), []string{"lab.env.example"}},
		"development":      {libFiles(t, "DEV_FILES"), []string{".env.example"}},
		"development with backups": {append(libFiles(t, "DEV_FILES"), libFiles(t, "DEV_BACKUP_FILES")...),
			[]string{".env.example"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := renderConfig(t, tc.files, tc.envFiles...)
			caddy := cfg.Services["caddy"]
			if got := slices.Sorted(maps.Keys(caddy.Networks)); !slices.Equal(got, []string{"edge"}) ||
				caddy.Networks["edge"].IPv4Address != "172.28.0.10" {
				t.Errorf("caddy networks %v at %q, want [edge] at 172.28.0.10", got, caddy.Networks["edge"].IPv4Address)
			}
			if subnets := cfg.Networks["edge"].IPAM.Config; len(subnets) != 1 || subnets[0].Subnet != "172.28.0.0/24" ||
				subnets[0].IPRange != "172.28.0.128/25" {
				t.Errorf("edge subnets %+v, want 172.28.0.0/24 with the dynamic pool 172.28.0.128/25", subnets)
			}
			for role, alias := range map[string]string{"paddock-worker": "worker-ops",
				"paddock-escrow-reader": "escrow-reader-ops", "paddock-revocation-issuer": "revocation-issuer-ops"} {
				s := cfg.Services[role]
				if v := s.Environment["PADDOCK_OPS_ADDR"]; v == nil || *v != alias+":9090" {
					t.Errorf("%s: PADDOCK_OPS_ADDR %v, want %s:9090", role, v, alias)
				}
				if !slices.Contains(s.Networks["data"].Aliases, alias) || len(s.Networks["edge"].Aliases) != 0 {
					t.Errorf("%s: aliases on data %v, on edge %v, want %s on data only", role, s.Networks["data"].Aliases,
						s.Networks["edge"].Aliases, alias)
				}
			}
			if !cfg.Networks["authentik"].Internal {
				t.Error("network authentik is not internal")
			}
			if _, ok := cfg.Networks["cp"]; ok {
				t.Error("network cp still exists")
			}
			for svc, s := range cfg.Services {
				if _, ok := s.Networks["cp"]; ok {
					t.Errorf("%s is on network cp", svc)
				}
			}
			for _, svc := range []string{"postgres", "valkey", "rabbitmq", "openbao", "authentik-postgres", "fleet-mysql",
				"fleet-redis", "audit-postgres", "audit-rustfs"} {
				if _, ok := cfg.Services[svc].Networks["edge"]; ok {
					t.Errorf("%s is on network edge", svc)
				}
			}
			for _, svc := range []string{"caddy", "fleet", "authentik-server", "authentik-worker"} {
				if _, ok := cfg.Services[svc].Networks["data"]; ok {
					t.Errorf("%s is on network data", svc)
				}
			}
			for svc, want := range map[string][]string{"authentik-worker": {"authentik"}, "authentik-postgres": {"authentik"},
				"authentik-server": {"authentik", "edge"}, "fleet": {"edge", "fleet"}} {
				if got := slices.Sorted(maps.Keys(cfg.Services[svc].Networks)); !slices.Equal(got, want) {
					t.Errorf("%s networks %v, want %v", svc, got, want)
				}
			}
			for _, role := range []string{"paddock-api", "paddock-escrow-reader", "paddock-revocation-issuer", "paddock-worker",
				"paddock-compiler", "paddock-notifier", "paddock-outbox-relay"} {
				if v := cfg.Services[role].Environment["PADDOCK_TRUSTED_PROXY_CIDRS"]; v == nil || *v != "172.28.0.10/32" {
					t.Errorf("%s trusts %v, want Caddy's 172.28.0.10/32", role, v)
				}
			}
		})
	}
}

// hardeningResult runs the checks over cfg for host and returns the item container hardening.
func hardeningResult(t *testing.T, cfg prodcheck.Config, host string) prodcheck.Result {
	t.Helper()
	for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{Host: host}) {
		if r.Item == "container hardening" {
			return r
		}
	}
	t.Fatal("no item container hardening")
	return prodcheck.Result{}
}

// TestContainerHardening renders every Compose file set (plan M8s decisions 34–36): the Paddock roles and Caddy drop
// every capability and privilege gain, and every service bounds its processes. A control plane whose x-paddock anchor
// lost the settings fails the item naming each role and each missing setting.
func TestContainerHardening(t *testing.T) {
	cases := map[string]struct {
		host     string
		files    []string
		envFiles []string
	}{
		"production control plane": {prodcheck.HostControlPlane, prodFiles(t, "controlplane"), []string{"prod.env.example"}},
		"production audit host":    {prodcheck.HostAudit, prodFiles(t, "audit"), []string{"prod.env.example"}},
		"lab":                      {prodcheck.HostLab, prodFiles(t, "lab"), []string{"lab.env.example"}},
		"lab with backups": {prodcheck.HostLab, append(prodFiles(t, "lab"), libFiles(t, "LAB_BACKUP_FILES")...),
			[]string{"lab.env.example"}},
		"development": {prodcheck.HostControlPlane, libFiles(t, "DEV_FILES"), []string{".env.example"}},
		"development with backups": {prodcheck.HostControlPlane, append(libFiles(t, "DEV_FILES"), libFiles(t, "DEV_BACKUP_FILES")...),
			[]string{".env.example"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := renderConfig(t, tc.files, tc.envFiles...)
			if r := hardeningResult(t, cfg, tc.host); !r.OK {
				t.Fatalf("%s:\n%s", r.Item, r.Detail)
			}
			if c, ok := cfg.Services["caddy"]; ok && c.PidsLimit != 256 {
				t.Errorf("caddy pids_limit %d, want 256", c.PidsLimit)
			}
		})
	}

	t.Run("stripped anchor", func(t *testing.T) {
		cfg := renderConfig(t, prodFiles(t, "controlplane"), "prod.env.example")
		for name, s := range cfg.Services {
			if strings.HasPrefix(name, "paddock-") {
				s.CapDrop, s.SecurityOpt, s.PidsLimit = nil, nil, 0
				cfg.Services[name] = s
			}
		}
		r := hardeningResult(t, cfg, prodcheck.HostControlPlane)
		for _, want := range []string{"paddock-api: cap_drop is not [ALL]", "paddock-gateway: security_opt lacks no-new-privileges:true",
			"paddock-compiler: no pids_limit"} {
			if r.OK || !strings.Contains(r.Detail, want) {
				t.Errorf("no finding %q in\n%s", want, r.Detail)
			}
		}
	})
}

// TestComposeConfigsRotateContainerLogs renders every host's file set (plan M10 decision 40): every service logs with
// json-file at 50m x 10, and the item container logs are rotated passes; a service whose logging block is removed
// fails the item naming it.
func TestComposeConfigsRotateContainerLogs(t *testing.T) {
	cases := map[string]struct {
		host     string
		files    []string
		envFiles []string
	}{
		"production control plane": {prodcheck.HostControlPlane, prodFiles(t, "controlplane"), []string{"prod.env.example"}},
		"production audit host":    {prodcheck.HostAudit, prodFiles(t, "audit"), []string{"prod.env.example"}},
		"lab":                      {prodcheck.HostLab, prodFiles(t, "lab"), []string{"lab.env.example"}},
		"lab with backups": {prodcheck.HostLab, append(prodFiles(t, "lab"), libFiles(t, "LAB_BACKUP_FILES")...),
			[]string{"lab.env.example"}},
		"control plane with automatic unseal": {prodcheck.HostControlPlane,
			append(prodFiles(t, "controlplane"), libFiles(t, "AUTO_UNSEAL_FILES")...), []string{"prod.env.example"}},
		"lab with automatic unseal and backups": {prodcheck.HostLab, append(append(prodFiles(t, "lab"),
			libFiles(t, "AUTO_UNSEAL_FILES")...), libFiles(t, "LAB_BACKUP_FILES")...), []string{"lab.env.example"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := renderConfig(t, tc.files, tc.envFiles...)
			if len(cfg.Services) == 0 {
				t.Fatal("no services rendered")
			}
			for _, svc := range sortedNames(cfg) {
				l := cfg.Services[svc].Logging
				if l.Driver != "json-file" || l.Options["max-size"] != "50m" || l.Options["max-file"] != "10" {
					t.Errorf("%s: logging %+v, want json-file max-size=50m max-file=10", svc, l)
				}
			}
			if r := logRotationResult(t, cfg, tc.host); !r.OK {
				t.Fatalf("%s:\n%s", r.Item, r.Detail)
			}
		})
	}

	t.Run("removed logging block", func(t *testing.T) {
		cfg := renderConfig(t, prodFiles(t, "audit"), "prod.env.example")
		s := cfg.Services["paddock-audit-writer"]
		s.Logging = prodcheck.Logging{}
		cfg.Services["paddock-audit-writer"] = s
		r := logRotationResult(t, cfg, prodcheck.HostAudit)
		if r.OK || !strings.Contains(r.Detail, "paddock-audit-writer: logging driver") {
			t.Errorf("no finding for paddock-audit-writer in\n%s", r.Detail)
		}
	})
}

func sortedNames(cfg prodcheck.Config) []string {
	names := make([]string, 0, len(cfg.Services))
	for n := range cfg.Services {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func logRotationResult(t *testing.T, cfg prodcheck.Config, host string) prodcheck.Result {
	t.Helper()
	for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{Host: host}) {
		if r.Item == "container logs are rotated" {
			return r
		}
	}
	t.Fatal("no item container logs are rotated")
	return prodcheck.Result{}
}

// blueprintEntries returns every entry of a blueprint text (from "  - model:" to the next one) that contains all of
// markers, in file order.
func blueprintEntries(text string, markers ...string) []string {
	var out []string
	parts := strings.Split(text, "\n  - model:")
	for _, e := range parts[1:] {
		// The split takes the line break before the next entry; every line of an entry ends with one again.
		e += "\n"
		ok := true
		for _, m := range markers {
			ok = ok && strings.Contains(e, m)
		}
		if ok {
			out = append(out, e)
		}
	}
	return out
}

// policyBinding returns the one policy binding of policy (its blueprint id) to the stage binding target, failing the
// test when there is none or more than one.
func policyBinding(t *testing.T, text, policy, target string) string {
	t.Helper()
	e := blueprintEntries(text, "authentik_policies.policybinding", "policy: !KeyOf "+policy+"\n", "target: !KeyOf "+target+"\n")
	if len(e) != 1 {
		t.Errorf("%d policy bindings of %s to %s, want exactly one", len(e), policy, target)
		return ""
	}
	return e[0]
}

// expectDistinctOrders fails when two policy bindings of policy share an order: the bindings are identified by policy
// and order, so a shared order would make one re-apply overwrite the other's target.
func expectDistinctOrders(t *testing.T, text, file, policy string) {
	t.Helper()
	seen := map[string]bool{}
	order := regexp.MustCompile(`\n      order: (\d+)\n`)
	for _, e := range blueprintEntries(text, "authentik_policies.policybinding", "policy: !KeyOf "+policy+"\n") {
		m := order.FindStringSubmatch(e)
		if m == nil {
			t.Errorf("%s: a policy binding of %s has no order in its identifiers:\n%s", file, policy, e)
			continue
		}
		if seen[m[1]] {
			t.Errorf("%s: two policy bindings of %s share order %s", file, policy, m[1])
		}
		seen[m[1]] = true
	}
}

// TestPortalBlueprintBindsMFAOnTheDefaultFlow: the portal blueprint adds a second factor at order 31 of Authentik's
// default authentication flow and the development blueprint skips it (plan M8x decisions 5 and 7a). Since ADR 0053
// (plan M12h-2 decision 7, amendment c) the stage denies an administrator without a factor and without the enrolment
// mark, and a sibling at the same order enrols everyone else (policy paddock-mfa-enrol-at-login). Both are skipped
// only when order 30 has validated a WebAuthn or TOTP device in this sign-in, because a last_auth_threshold cannot skip
// a stage after another stage's validation (PDK-324). Owning such a device does not skip them, so a sign-in with a
// recovery code, e-mail, SMS or Duo is asked again (where Authentik also accepts a further recovery code), and an
// expression error keeps the stage.
func TestPortalBlueprintBindsMFAOnTheDefaultFlow(t *testing.T) {
	read := func(path string) string {
		b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", path))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	portal := read(filepath.Join("blueprints", "paddock-portal.yaml"))
	block := func(marker string) string {
		t.Helper()
		start := strings.Index(portal, marker)
		if start < 0 {
			t.Fatalf("paddock-portal.yaml has no entry %q", marker)
		}
		end := strings.Index(portal[start:], "\n  - model:")
		if end < 0 {
			end = len(portal) - start
		}
		return portal[start : start+end]
	}
	for _, c := range []struct{ marker, want string }{
		{"name: paddock-default-login-mfa\n", "\n      not_configured_action: deny\n"},
		{"name: paddock-default-login-mfa\n", "last_auth_threshold: seconds=0"},
		{"name: paddock-default-login-mfa-enrol\n", "\n      not_configured_action: configure\n"},
		{"name: paddock-default-login-mfa-enrol\n", "last_auth_threshold: seconds=0"},
		{"name: paddock-default-login-mfa-enrol\n", "\n      device_classes: [webauthn, totp]\n"},
		{"id: default-flow-mfa-binding\n", "stage: !KeyOf default-flow-mfa\n"},
		{"id: default-flow-mfa-enrol-binding\n", "stage: !KeyOf default-flow-mfa-enrol\n"},
		{"name: paddock-default-login-mfa-missing\n",
			`method_args = request.context.get("auth_method_args") or {}`},
		{"name: paddock-default-login-mfa-missing\n",
			`return not any(d.__class__.__name__ in ("TOTPDevice", "WebAuthnDevice") for d in method_args.get("mfa_devices") or [])`},
	} {
		if !strings.Contains(block(c.marker), c.want) {
			t.Errorf("the entry with %q lacks %q", strings.TrimSpace(c.marker), c.want)
		}
	}
	for _, binding := range []string{"default-flow-mfa-binding", "default-flow-mfa-enrol-binding"} {
		for _, want := range []string{"slug, default-authentication-flow", "order: 31", "evaluate_on_plan: false",
			"re_evaluate_policies: true", "policy_engine_mode: all"} {
			if !strings.Contains(block("id: "+binding+"\n"), want) {
				t.Errorf("the entry with %q lacks %q", "id: "+binding, want)
			}
		}
		// Both stages skip only after a validation at order 30 in this sign-in; an expression error keeps them.
		if pb := policyBinding(t, portal, "default-flow-mfa-missing", binding); !strings.Contains(pb, "failure_result: true") {
			t.Errorf("default-flow-mfa-missing on %s does not fail closed:\n%s", binding, pb)
		}
	}
	// The deny stage: an administrator (an error counts as one) without the enrolment mark (an error counts as
	// unmarked).
	for _, policy := range []string{"enrol-at-login-absent", "webauthn-administrator"} {
		if pb := policyBinding(t, portal, policy, "default-flow-mfa-binding"); !strings.Contains(pb, "failure_result: true") {
			t.Errorf("%s on the deny stage does not fail closed:\n%s", policy, pb)
		}
	}
	// The enrolment sibling: marked or not an administrator; an error never opens it.
	if pb := policyBinding(t, portal, "enrol-at-login", "default-flow-mfa-enrol-binding"); strings.Contains(pb, "failure_result: true") {
		t.Errorf("the enrolment policy opens the enrolment on an error:\n%s", pb)
	}
	if n := len(blueprintEntries(portal, "authentik_policies.policybinding", "target: !KeyOf default-flow-mfa-binding\n")); n != 3 {
		t.Errorf("the deny stage has %d policy bindings, want 3 (missing factor, administrator, mark absent)", n)
	}
	if n := len(blueprintEntries(portal, "authentik_policies.policybinding", "target: !KeyOf default-flow-mfa-enrol-binding\n")); n != 2 {
		t.Errorf("the enrolment stage has %d policy bindings, want 2 (missing factor, enrolment)", n)
	}
	if strings.Contains(block("name: paddock-default-login-mfa-missing\n"), "ak_user_has_authenticator") {
		t.Error("paddock-default-login-mfa-missing decides by the devices the user owns, not by the factor of this sign-in")
	}
	dev := read(filepath.Join("dev", "paddock-dev.yaml"))
	for _, stage := range []string{"paddock-default-login-mfa", "paddock-default-login-mfa-enrol"} {
		target := "[slug, default-authentication-flow]]], [stage, !Find [authentik_stages_authenticator_validate.authenticatorvalidatestage, [name, " + stage + "]]]]"
		if e := blueprintEntries(dev, "authentik_policies.policybinding", "policy: !KeyOf skip-mfa\n", target); len(e) != 1 {
			t.Errorf("paddock-dev.yaml skips %s of default-authentication-flow %d times, want once", stage, len(e))
		}
	}
}

// TestPortalBlueprintLoginWebAuthnOnly (plan M8f decision 13 as amended on 2026-10-18, ADR 0053 with plan M12h-2
// decision 7 and amendment c): stage A at order 30 validates any existing authenticator; stage B at order 31 asks a
// direct member of a portal role group for WebAuthn after a TOTP validation (Authentik counts a recovery code as TOTP)
// when the account has no WebAuthn device (ADR 0034 amendment 2026-10-29, PDK-498): the flow is also the default
// brand's, which the device-code page runs for every device user. Neither enrols an administrator without the
// enrolment mark (not_configured_action deny); each has a sibling at the same order that enrols WebAuthn only, for a
// marked administrator and (stage A) for everyone who is not an administrator. Every error keeps the denial and never
// opens an enrolment. The default flow's stage, which serves every Authentik user, keeps accepting TOTP.
func TestPortalBlueprintLoginWebAuthnOnly(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", "blueprints", "paddock-portal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	portal := string(b)
	block := func(marker string) string {
		t.Helper()
		start := strings.Index(portal, marker)
		if start < 0 {
			t.Fatalf("paddock-portal.yaml has no entry %q", marker)
		}
		end := strings.Index(portal[start:], "\n  - model:")
		if end < 0 {
			end = len(portal) - start
		}
		return portal[start : start+end]
	}
	stage := func(name, classes, action string) {
		t.Helper()
		s := block("name: " + name + "\n")
		for _, want := range []string{"\n      device_classes: " + classes + "\n", "\n      not_configured_action: " + action + "\n",
			"[name, default-authenticator-webauthn-setup]"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
		if n := strings.Count(s, "        - !Find"); n != 1 || strings.Contains(s, "totp-setup") {
			t.Errorf("%s has %d configuration stages or enrols TOTP:\n%s", name, n, s)
		}
	}
	stage("paddock-admin-login-mfa", "[webauthn, totp]", "deny")
	stage("paddock-admin-login-mfa-enrol", "[webauthn, totp]", "configure")
	stage("paddock-admin-login-webauthn", "[webauthn]", "deny")
	stage("paddock-admin-login-webauthn-enrol", "[webauthn]", "configure")
	for _, c := range []struct{ marker, want string }{
		{"stage: !KeyOf mfa\n", "order: 30"},
		{"stage: !KeyOf mfa-enrol\n", "order: 30"},
		{"stage: !KeyOf mfa-webauthn\n", "order: 31"},
		{"stage: !KeyOf mfa-webauthn-enrol\n", "order: 31"},
		{"name: paddock-admin-login-webauthn-missing\n", `return not ak_user_has_authenticator(request.user, "webauthn")`},
		{"name: paddock-admin-login-webauthn-administrator\n",
			`len(p) == 3 and p[0] == "paddock" and p[2] in ("admins", "operators", "auditors")`},
		{"name: paddock-admin-login-webauthn-administrator\n",
			`for p in (g.name.split(".") for g in request.user.groups.all())`},
		{"name: paddock-mfa-enrol-at-login-absent\n", `return not bool(request.user.attributes.get("paddock_mfa_enrol_at_login"))`},
		{"name: paddock-mfa-enrol-at-login\n", `if bool(request.user.attributes.get("paddock_mfa_enrol_at_login")):`},
		{"name: paddock-mfa-enrol-at-login\n", `administrator = ak_call_policy("paddock-admin-login-webauthn-administrator")`},
		{"name: paddock-mfa-enrol-at-login\n", "if administrator.messages:\n            return False\n"},
		{"name: paddock-mfa-enrol-at-login\n", "return not administrator.passing"},
	} {
		if !strings.Contains(block(c.marker), c.want) {
			t.Errorf("the entry with %q lacks %q", strings.TrimSpace(c.marker), c.want)
		}
	}
	// Every binding of the four stages is evaluated when its stage is reached (on the plan the user is still
	// anonymous) and in mode "all", so that the development blueprint's skip policy skips it.
	for _, id := range []string{"mfa-binding", "mfa-enrol-binding", "mfa-webauthn-binding", "mfa-webauthn-enrol-binding"} {
		binding := block("id: " + id + "\n")
		for _, want := range []string{"evaluate_on_plan: false", "re_evaluate_policies: true", "policy_engine_mode: all"} {
			if !strings.Contains(binding, want) {
				t.Errorf("the stage binding %s lacks %q", id, want)
			}
		}
	}
	// The policies of each binding, exactly; failClosed are those with failure_result true.
	for _, c := range []struct {
		binding    string
		policies   []string
		failClosed []string
	}{
		{"mfa-binding", []string{"enrol-at-login-absent", "webauthn-administrator"},
			[]string{"enrol-at-login-absent", "webauthn-administrator"}},
		{"mfa-enrol-binding", []string{"enrol-at-login"}, nil},
		{"mfa-webauthn-binding", []string{"webauthn-missing", "webauthn-administrator", "enrol-at-login-absent"},
			[]string{"webauthn-administrator", "enrol-at-login-absent"}},
		{"mfa-webauthn-enrol-binding", []string{"webauthn-missing", "webauthn-administrator", "enrol-at-login"}, nil},
	} {
		if n := len(blueprintEntries(portal, "authentik_policies.policybinding", "target: !KeyOf "+c.binding+"\n")); n != len(c.policies) {
			t.Errorf("%s has %d policy bindings, want %d (%v)", c.binding, n, len(c.policies), c.policies)
		}
		for _, policy := range c.policies {
			pb := policyBinding(t, portal, policy, c.binding)
			if got, want := strings.Contains(pb, "failure_result: true"), slices.Contains(c.failClosed, policy); got != want {
				t.Errorf("%s on %s: failure_result true %v, want %v", policy, c.binding, got, want)
			}
		}
	}
	for _, policy := range []string{"webauthn-missing", "webauthn-administrator", "enrol-at-login-absent", "enrol-at-login"} {
		expectDistinctOrders(t, portal, "paddock-portal.yaml", policy)
	}
	// The administrator policy never shares order 0 with the WebAuthn-missing policy.
	for _, e := range blueprintEntries(portal, "authentik_policies.policybinding", "policy: !KeyOf webauthn-administrator\n") {
		if strings.Contains(e, "\n      order: 0\n") {
			t.Errorf("the administrator policy shares order 0 with the WebAuthn-missing policy:\n%s", e)
		}
	}
	// Stage C (ADR 0034 amendment 2026-10-29): the passkey confirmation after an enrolment, for administrators only.
	confirm := block("name: paddock-admin-login-webauthn-confirm\n")
	if !strings.Contains(confirm, "\n      device_classes: [webauthn]\n") || !strings.Contains(confirm, "\n      not_configured_action: deny\n") ||
		strings.Contains(confirm, "configuration_stages") {
		t.Errorf("stage C does not validate WebAuthn only with deny:\n%s", confirm)
	}
	binding := block("id: mfa-webauthn-confirm-binding\n")
	for _, want := range []string{"stage: !KeyOf mfa-webauthn-confirm\n", "order: 32", "evaluate_on_plan: false",
		"re_evaluate_policies: true", "policy_engine_mode: all"} {
		if !strings.Contains(binding, want) {
			t.Errorf("the stage binding of stage C lacks %q", want)
		}
	}
	if !strings.Contains(block("name: paddock-admin-login-webauthn-unconfirmed\n"),
		`return not any(d.__class__.__name__ == "WebAuthnDevice" for d in method_args.get("mfa_devices") or [])`) {
		t.Error("paddock-admin-login-webauthn-unconfirmed does not check the WebAuthn devices validated in the flow")
	}
	for _, policy := range []string{"webauthn-administrator", "webauthn-unconfirmed"} {
		if pb := policyBinding(t, portal, policy, "mfa-webauthn-confirm-binding"); !strings.Contains(pb, "failure_result: true") {
			t.Errorf("stage C is not bound to %s with failure_result true", policy)
		}
	}
	if !strings.Contains(block("name: paddock-default-login-mfa\n"), "\n      device_classes: [webauthn, totp]\n") {
		t.Error("paddock-default-login-mfa no longer accepts WebAuthn and TOTP")
	}
}

// TestDevBlueprintSkipsPortalLoginMFA: the development users have TOTP only, so the development blueprint must skip
// every second-factor stage of the portal login: stages A and B and their enrolment siblings (ADR 0053) and stage C;
// a missing skip of an enrolment stage sends every development sign-in to the WebAuthn enrolment, one of a deny stage
// or stage C denies it. The skip passes only for an account with the test attribute paddock_dev_enforce_mfa, which the
// acceptance gates of ADR 0053 set on temporary users; for every other account it fails and skips the stage.
func TestDevBlueprintSkipsPortalLoginMFA(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", "dev", "paddock-dev.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dev := string(b)
	for _, stage := range []string{"paddock-admin-login-mfa", "paddock-admin-login-mfa-enrol", "paddock-admin-login-webauthn",
		"paddock-admin-login-webauthn-enrol", "paddock-admin-login-webauthn-confirm"} {
		target := "[slug, paddock-admin-login]]], [stage, !Find [authentik_stages_authenticator_validate.authenticatorvalidatestage, [name, " + stage + "]]]]"
		i := strings.Index(dev, target)
		if i < 0 {
			t.Errorf("the development blueprint binds no policy to paddock-admin-login's stage %s", stage)
			continue
		}
		entry := dev[strings.LastIndex(dev[:i], "  - model:"):i]
		if !strings.Contains(entry, "authentik_policies.policybinding") || !strings.Contains(entry, "policy: !KeyOf skip-mfa") {
			t.Errorf("paddock-admin-login's stage %s is not skipped by skip-mfa:\n%s", stage, entry)
		}
		if n := strings.Count(dev, target); n != 1 {
			t.Errorf("paddock-admin-login's stage %s is bound %d times, want once", stage, n)
		}
	}
	expectDistinctOrders(t, dev, "paddock-dev.yaml", "skip-mfa")
	skip := blueprintEntries(dev, "authentik_policies_expression.expressionpolicy", "name: paddock-dev-skip-mfa\n")
	if len(skip) != 1 {
		t.Fatalf("%d expression policies paddock-dev-skip-mfa, want one", len(skip))
	}
	if strings.Count(skip[0], "return ") != 1 ||
		!strings.Contains(skip[0], `return bool(request.user.attributes.get("paddock_dev_enforce_mfa"))`) {
		t.Errorf("paddock-dev-skip-mfa does not fail for every account without the test attribute:\n%s", skip[0])
	}
}

// TestStepUpBlueprintWebAuthnOnly (plan M8s decision 40): the shipped step-up flow validates with WebAuthn only; only
// the development blueprint adds a stage that accepts TOTP.
func TestStepUpBlueprintWebAuthnOnly(t *testing.T) {
	read := func(path string) string {
		b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", path))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	stepup := read(filepath.Join("blueprints", "paddock-stepup.yaml"))
	if !strings.Contains(stepup, "\n      device_classes: [webauthn]\n") {
		t.Error("paddock-stepup.yaml does not validate with device_classes: [webauthn]")
	}
	if strings.Contains(stepup, "totp") {
		t.Error("paddock-stepup.yaml mentions totp")
	}
	if !strings.Contains(read(filepath.Join("dev", "paddock-dev.yaml")), "paddock-dev-stepup-mfa") {
		t.Error("the development blueprint has no stage paddock-dev-stepup-mfa")
	}
}

// TestPortalBlueprintEmitsMFAClasses (ADR 0034 amendment 2026-10-29): the portal provider carries the mapping that
// names the validated authenticator classes under the scope the api requests, which every portal sign-in requires.
func TestPortalBlueprintEmitsMFAClasses(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", "blueprints", "paddock-portal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	portal := string(b)
	for _, want := range []string{"managed: io.paddock/scope-login-mfa", "scope_name: paddock_mfa\n",
		"return {\"paddock_mfa_classes\": classes}", "        - !KeyOf scope-mfa\n", "request.context.get(\"token\")", "get_login_event(grant.session)"} {
		if !strings.Contains(portal, want) {
			t.Errorf("paddock-portal.yaml lacks %q", want)
		}
	}
	if mapping, provider := strings.Index(portal, "id: scope-mfa\n"), strings.Index(portal, "\n    id: provider\n"); mapping < 0 || mapping > provider {
		t.Error("the mapping scope-mfa must precede the provider that references it")
	}
}

// TestStepUpBlueprintEmitsMFAClasses (plan M8f decision 11): the step-up provider carries the mapping that names the
// validated authenticator classes, which the api requires in every step-up token.
func TestStepUpBlueprintEmitsMFAClasses(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", "blueprints", "paddock-stepup.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	stepup := string(b)
	for _, want := range []string{"managed: io.paddock/scope-stepup-mfa", "scope_name: paddock_stepup",
		"paddock_mfa_classes", "        - !KeyOf scope-stepup-mfa\n", "request.context.get(\"token\")", "get_login_event(grant.session)"} {
		if !strings.Contains(stepup, want) {
			t.Errorf("paddock-stepup.yaml lacks %q", want)
		}
	}
	if mapping, provider := strings.Index(stepup, "id: scope-stepup-mfa"), strings.Index(stepup, "id: provider"); mapping < 0 || mapping > provider {
		t.Error("the mapping scope-stepup-mfa must precede the provider that references it")
	}
}

// TestDeviceBlueprintOneDevicePrompt (plan M8f amendment 2026-10-29, PDK-521): the device-code entry flow
// paddock-device-code binds no MFA stage, and the blueprint removes the binding an earlier version created, so a code
// typed at /device is not asked for the second factor twice; the provider's authorization flow
// paddock-device-authorization keeps the stage paddock-device-mfa as the one device prompt of every approval. The
// removal is conditional on the binding existing, because Authentik fails the whole import on an absent entry for a
// missing binding (review 1 of PDK-521).
func TestDeviceBlueprintOneDevicePrompt(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", "blueprints", "paddock-device.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	entries := strings.Split(string(b), "\n  - model: ")
	idLine := regexp.MustCompile(`(?m)^    id: (\S+)$`)
	var entryFlowID, authorizationFlowID, mfaID string
	for _, e := range entries {
		id := idLine.FindStringSubmatch(e)
		switch {
		case id == nil:
		case strings.Contains(e, "\n      slug: paddock-device-code\n"):
			entryFlowID = id[1]
		case strings.Contains(e, "\n      slug: paddock-device-authorization\n"):
			authorizationFlowID = id[1]
		case strings.Contains(e, "\n      name: paddock-device-mfa\n"):
			mfaID = id[1]
		}
	}
	if entryFlowID == "" || authorizationFlowID == "" || mfaID == "" {
		t.Fatalf("paddock-device.yaml lacks a flow or the MFA stage: entry %q, authorization %q, mfa %q",
			entryFlowID, authorizationFlowID, mfaID)
	}
	authorizationMFA := 0
	for _, e := range entries {
		if !strings.HasPrefix(e, "authentik_flows.flowstagebinding\n") {
			continue
		}
		absent := strings.Contains(e, "\n    state: absent\n")
		switch {
		case strings.Contains(e, "target: !KeyOf "+entryFlowID+"\n") && !absent:
			t.Errorf("the entry flow paddock-device-code binds a stage:\n%s", e)
		case strings.Contains(e, "target: !KeyOf "+entryFlowID+"\n") && !strings.Contains(e, "stage: !KeyOf "+mfaID+"\n"):
			t.Errorf("the removed binding of paddock-device-code does not name the stage paddock-device-mfa:\n%s", e)
		case strings.Contains(e, "target: !KeyOf "+authorizationFlowID+"\n") && strings.Contains(e, "stage: !KeyOf "+mfaID+"\n") && !absent:
			authorizationMFA++
		}
	}
	if authorizationMFA != 1 {
		t.Errorf("paddock-device-authorization binds paddock-device-mfa %d times, want once", authorizationMFA)
	}
	if !strings.Contains(string(b), "    state: absent\n    conditions:\n      - !Find [authentik_flows.flowstagebinding, [target, !KeyOf "+
		entryFlowID+"], [stage, !KeyOf "+mfaID+"], [order, 10]]\n    identifiers:\n      target: !KeyOf "+entryFlowID+
		"\n      stage: !KeyOf "+mfaID+"\n      order: 10\n") {
		t.Error("paddock-device.yaml does not remove the MFA binding at order 10 of paddock-device-code from earlier " +
			"installations, or removes it without the condition that the binding exists (an absent entry for a missing " +
			"binding fails the whole blueprint import)")
	}
}

// TestAuthentikWebWorkers: every installation runs authentik-server with PADDOCK_AUTHENTIK_WEB_WORKERS web workers,
// default 4 instead of Authentik's 2, under which simultaneous logins queued until clients timed out (PDK-545).
func TestAuthentikWebWorkers(t *testing.T) {
	cases := map[string]struct {
		files    []string
		envFiles []string
	}{
		"production control plane": {prodFiles(t, "controlplane"), []string{"prod.env.example"}},
		"lab":                      {prodFiles(t, "lab"), []string{"lab.env.example"}},
		"development":              {libFiles(t, "DEV_FILES"), []string{".env.example"}},
	}
	for name, tc := range cases {
		for _, c := range []struct{ value, want string }{{"", "4"}, {"8", "8"}} {
			t.Run(name+" PADDOCK_AUTHENTIK_WEB_WORKERS="+c.value, func(t *testing.T) {
				t.Setenv("PADDOCK_AUTHENTIK_WEB_WORKERS", c.value)
				cfg := renderConfig(t, tc.files, tc.envFiles...)
				got := cfg.Services["authentik-server"].Environment["AUTHENTIK_WEB__WORKERS"]
				if got == nil || *got != c.want {
					t.Fatalf("authentik-server AUTHENTIK_WEB__WORKERS = %v, want %s", got, c.want)
				}
				for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{}) {
					if r.Item == "authentik web workers" && !r.OK {
						t.Fatalf("item authentik web workers fails: %s", r.Detail)
					}
				}
			})
		}
	}
}

// TestNotifierCompose renders the control plane and the lab with their templates (plan M9 decision 41, amendment
// B13.1): paddock-notifier runs in production on networks cp and audit-index, talks TLS to OpenBao, holds exactly its
// secrets, gets no lab extra_hosts, and the notifier items pass.
func TestNotifierCompose(t *testing.T) {
	cases := map[string]struct {
		host    string
		envFile string
	}{
		"production control plane": {prodcheck.HostControlPlane, "prod.env.example"},
		"lab":                      {prodcheck.HostLab, "lab.env.example"},
	}
	wantSecrets := []string{"approle_notifier_role_id", "approle_notifier_secret_id", "db_paddock_audit_reader_url",
		"db_paddock_notifier_url", "db_paddock_platform_url", "internal_ca_bundle", "smtp_password"}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := renderConfig(t, prodFiles(t, tc.host), tc.envFile)
			n, ok := cfg.Services["paddock-notifier"]
			if !ok {
				t.Fatal("no paddock-notifier")
			}
			env := func(k string) string {
				if v := n.Environment[k]; v != nil {
					return *v
				}
				return ""
			}
			for k, want := range map[string]string{
				"PADDOCK_ENV": "production", "PADDOCK_OPENBAO_ADDR": "https://openbao:8200",
				"BAO_CACERT": "/run/secrets/internal_ca_bundle", "PADDOCK_SMTP_PASSWORD_FILE": "/run/secrets/smtp_password",
				"PADDOCK_PUBLIC_ADMIN_URL": "https://admin.paddock.example.org", "PADDOCK_SMTP_HOST": "",
			} {
				if got := env(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			var secrets []string
			for _, s := range n.Secrets {
				secrets = append(secrets, s.Source)
			}
			slices.Sort(secrets)
			if !slices.Equal(secrets, wantSecrets) {
				t.Errorf("secrets %v, want %v", secrets, wantSecrets)
			}
			var networks []string
			for nw := range n.Networks {
				networks = append(networks, nw)
			}
			slices.Sort(networks)
			if !slices.Equal(networks, []string{"audit-index", "data"}) {
				t.Errorf("networks %v, want [audit-index data]", networks)
			}
			if len(n.ExtraHosts) != 0 {
				t.Errorf("extra_hosts %v, want none", n.ExtraHosts)
			}
			want := map[string]bool{"notifications: SMTP presence flag matches the relay": false,
				"no development-only variables": false, "PADDOCK_ENV=production in every service": false,
				mountedItem: false}
			for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{Host: tc.host}) {
				if _, ok := want[r.Item]; !ok {
					continue
				}
				want[r.Item] = true
				if !r.OK {
					t.Errorf("%s:\n%s", r.Item, r.Detail)
				}
			}
			for item, seen := range want {
				if !seen {
					t.Errorf("no item %q", item)
				}
			}
		})
	}
}

// TestSuperuserPasswordOnlyWhereRolesAreProvisioned requires that the PostgreSQL superuser passwords reach only the
// database itself and its one-shot provisioning service, never a migration or a role (plan M16 decision 8: the owner
// stays NOCREATEROLE).
func TestSuperuserPasswordOnlyWhereRolesAreProvisioned(t *testing.T) {
	allowed := map[string]bool{
		"postgres": true, "db-provision": true, "audit-postgres": true, "audit-db-provision": true,
	}
	for name, files := range map[string][]string{
		"production control plane": prodFiles(t, "controlplane"),
		"production audit host":    prodFiles(t, "audit"),
	} {
		cfg := renderConfig(t, files, "prod.env.example")
		for svc, s := range cfg.Services {
			for _, ref := range s.Secrets {
				if (ref.Source == "postgres_superuser_password" || ref.Source == "audit_postgres_superuser_password") && !allowed[svc] {
					t.Errorf("%s: %s mounts %s", name, svc, ref.Source)
				}
			}
		}
		if _, ok := cfg.Services["db-provision"]; !ok && name == "production control plane" {
			t.Errorf("%s: no service db-provision", name)
		}
	}
}

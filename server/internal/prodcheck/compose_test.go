package prodcheck_test

import (
	"bytes"
	"context"
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
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := mountedResult(t, renderConfig(t, tc.files, tc.envFiles...))
			if !r.OK {
				t.Fatalf("%s:\n%s", r.Item, r.Detail)
			}
		})
	}
	t.Run("backup secrets reach the production worker", func(t *testing.T) {
		cfg := renderConfig(t, prodFiles(t, "controlplane"), "prod.env.example")
		mounted := map[string]bool{}
		for _, s := range cfg.Services["paddock-worker"].Secrets {
			mounted[s.Source] = true
		}
		for _, want := range []string{"backup_worker_access_key", "backup_worker_secret_key", "backup_encryption_key",
			"approle_backup_role_id", "approle_backup_secret_id", "internal_ca_bundle", "db_paddock_worker_url"} {
			if !mounted[want] {
				t.Errorf("paddock-worker does not mount %s", want)
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
	if proxies != 4 {
		t.Errorf("found %d proxies to Paddock roles, want 4 (admin_site, device. in the three Caddyfiles)", proxies)
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
	if limited != 17 {
		t.Errorf("found %d proxies to roles and upstreams, want 17 (2 in the guards, 5 in each Caddyfile)", limited)
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
		case "edge client address", "role trusted proxies", "container hardening":
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

// TestStepUpBlueprintWebAuthnOnly (plan M8s decision 40): the shipped step-up flow validates with WebAuthn only; only
// the development blueprint adds a stage that accepts TOTP.
// TestPortalBlueprintBindsMFAOnTheDefaultFlow: the portal blueprint adds a second factor at order 31 of Authentik's
// default authentication flow and the development blueprint skips it (plan M8x decisions 5 and 7a).
func TestPortalBlueprintBindsMFAOnTheDefaultFlow(t *testing.T) {
	read := func(path string) string {
		b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", path))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	portal := read(filepath.Join("blueprints", "paddock-portal.yaml"))
	for _, want := range []string{"name: paddock-default-login-mfa", "slug, default-authentication-flow", "order: 31",
		"not_configured_action: configure", "last_auth_threshold: minutes=5"} {
		if !strings.Contains(portal, want) {
			t.Errorf("paddock-portal.yaml does not contain %q", want)
		}
	}
	dev := read(filepath.Join("dev", "paddock-dev.yaml"))
	if !strings.Contains(dev, "[slug, default-authentication-flow]]], [order, 31]]") {
		t.Error("paddock-dev.yaml does not skip the stage at order 31 of default-authentication-flow")
	}
}

// TestPortalBlueprintLoginWebAuthnOnly (plan M8f decision 13 as amended on 2026-10-18): stage A at order 30 validates
// any existing authenticator and enrols WebAuthn only for an account without one; stage B at order 31 enrols WebAuthn
// after a TOTP validation and runs only for an account without a WebAuthn device. The default flow's stage, which
// serves every Authentik user, keeps accepting TOTP.
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
	stage := func(name, classes string) {
		t.Helper()
		s := block("name: " + name + "\n")
		for _, want := range []string{"\n      device_classes: " + classes + "\n", "\n      not_configured_action: configure\n",
			"[name, default-authenticator-webauthn-setup]"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
		if n := strings.Count(s, "        - !Find"); n != 1 || strings.Contains(s, "totp-setup") {
			t.Errorf("%s has %d configuration stages or enrols TOTP:\n%s", name, n, s)
		}
	}
	stage("paddock-admin-login-mfa", "[webauthn, totp]")
	stage("paddock-admin-login-webauthn", "[webauthn]")
	for _, c := range []struct{ marker, want string }{
		{"stage: !KeyOf mfa\n", "order: 30"},
		{"stage: !KeyOf mfa-webauthn\n", "order: 31"},
		{"stage: !KeyOf mfa-webauthn\n", "re_evaluate_policies: true"},
		{"stage: !KeyOf mfa-webauthn\n", "policy_engine_mode: all"},
		{"name: paddock-admin-login-webauthn-missing\n", `return not ak_user_has_authenticator(request.user, "webauthn")`},
		{"policy: !KeyOf webauthn-missing\n", "target: !KeyOf mfa-webauthn-binding"},
	} {
		if !strings.Contains(block(c.marker), c.want) {
			t.Errorf("the entry with %q lacks %q", strings.TrimSpace(c.marker), c.want)
		}
	}
	if !strings.Contains(block("name: paddock-default-login-mfa\n"), "\n      device_classes: [webauthn, totp]\n") {
		t.Error("paddock-default-login-mfa no longer accepts WebAuthn and TOTP")
	}
}

// TestDevBlueprintSkipsPortalLoginMFA: the development users have TOTP only, so the development blueprint must skip
// both portal login stages; a missing skip of stage B sends every development sign-in to the WebAuthn enrolment.
func TestDevBlueprintSkipsPortalLoginMFA(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", "dev", "paddock-dev.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dev := string(b)
	for _, order := range []string{"30", "31"} {
		target := "[slug, paddock-admin-login]]], [order, " + order + "]]"
		i := strings.Index(dev, target)
		if i < 0 {
			t.Errorf("the development blueprint binds no policy to paddock-admin-login's order %s", order)
			continue
		}
		entry := dev[strings.LastIndex(dev[:i], "  - model:"):i]
		if !strings.Contains(entry, "authentik_policies.policybinding") || !strings.Contains(entry, "policy: !KeyOf skip-mfa") {
			t.Errorf("paddock-admin-login's order %s is not skipped by skip-mfa:\n%s", order, entry)
		}
	}
}

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

// TestStepUpBlueprintEmitsMFAClasses (plan M8f decision 11): the step-up provider carries the mapping that names the
// validated authenticator classes, which the api requires in every step-up token.
func TestStepUpBlueprintEmitsMFAClasses(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(composeDir(t), "authentik", "blueprints", "paddock-stepup.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	stepup := string(b)
	for _, want := range []string{"managed: io.paddock/scope-stepup-mfa", "scope_name: paddock_stepup",
		"paddock_mfa_classes", "        - !KeyOf scope-stepup-mfa\n", "get_login_event(token.session)"} {
		if !strings.Contains(stepup, want) {
			t.Errorf("paddock-stepup.yaml lacks %q", want)
		}
	}
	if mapping, provider := strings.Index(stepup, "id: scope-stepup-mfa"), strings.Index(stepup, "id: provider"); mapping < 0 || mapping > provider {
		t.Error("the mapping scope-stepup-mfa must precede the provider that references it")
	}
}

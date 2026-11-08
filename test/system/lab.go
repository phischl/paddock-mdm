package system

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// The lab-profile installation of the backup gates (plan M15 §9 BS1–BS4): one bundle directory with the Compose project
// labProject, PADDOCK_HOST=lab with backups, behind the shipped Nginx reference configuration on the host, as
// deploy/bundle/ci/smoke-lab.sh installs it (docs/operations/lab-install.md section 5). Its names are the development
// stack's (paddock.localhost) on port 443 instead of 8443, so a VM reaches it through the same hosts entries.
const (
	labProject  = "paddock-systest-lab"
	labDomain   = "paddock.localhost"
	labNginx    = "paddock-systest-lab-nginx"
	labAdminURL = "https://admin." + labDomain
	labAuthURL  = "https://auth." + labDomain
	labRPID     = "auth." + labDomain
	// labLocalPath is the subpath of the local target below the lab's PADDOCK_BACKUP_LOCAL_ROOT.
	labLocalPath = "local"
)

// labUser is an Authentik account of the lab with its software WebAuthn authenticator: a production-profile
// installation accepts no other second factor for the sign-in and the step-up.
type labUser struct {
	name, password string
	key            *portal.WebAuthn
}

// Lab is the lab-profile installation of the backup gates. The gates drive it as an operator does: ./paddock in its
// bundle directory, ./paddock restore through sudo (the restore hands the staged set to uid 999), the portal API as the
// platform administrator and as the administrator of the organization the VM enrolls into.
type Lab struct {
	root      string // repository root
	work      string // working directory: the bundle directory lab/, tls/, logs/
	dir       string // the bundle directory
	run       string
	localRoot string   // PADDOCK_BACKUP_LOCAL_ROOT
	shares    []string // three OpenBao unseal shares, which the custodians type at a restore
	platform  *labUser
	orgAdmin  *labUser
	orgSlug   string
	images    map[string]string // deploy/compose/versions.env
	s3        *s3Store

	mu        sync.Mutex
	admin     *portal.Session // the platform administrator's session
	steppedUp time.Time       // the last step-up of admin
}

// newLab installs the lab from the local bundle (make bundle; PADDOCK_SYSTEM_BUNDLE overrides the tarball) and removes
// it, its volumes and its local backup root when the test ends; with PADDOCK_SYSTEM_KEEP set a failed test leaves it
// running. The host needs passwordless sudo, and 80, 443, 445, 2049 and 127.0.0.1:8080 free.
func newLab(t *testing.T, root string) *Lab {
	t.Helper()
	tarball := os.Getenv("PADDOCK_SYSTEM_BUNDLE")
	if tarball == "" {
		tarball = filepath.Join(root, "dist", "bundle", "paddock-deploy-0.0.0-local.tar.gz")
	}
	if _, err := os.Stat(tarball); err != nil {
		t.Fatalf("no bundle %s (make build web image image-compiler image-pgbackrest bundle): %v", tarball, err)
	}
	if out, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Fatalf("the backup gates need passwordless sudo on the host (local backup root, ./paddock restore): %v %s", err, out)
	}
	removeLeftovers(t)
	for _, port := range []string{"80", "443", "445", "2049", "8080"} {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second); err == nil {
			_ = c.Close()
			t.Fatalf("127.0.0.1:%s is in use; the lab's proxy, Caddy and the share relay need it", port)
		}
	}
	work, err := os.MkdirTemp("", "paddock-systest-lab-")
	if err != nil {
		t.Fatal(err)
	}
	l := &Lab{root: root, work: work, dir: filepath.Join(work, "lab"), run: unique(),
		images: readVersions(t, filepath.Join(root, "deploy", "compose", "versions.env"))}
	l.localRoot = "/srv/paddock-systest-" + l.run
	t.Logf("lab installation in %s (project %s)", l.dir, labProject)
	t.Cleanup(func() { l.teardown(t) })

	for _, dir := range []string{l.dir, filepath.Join(work, "logs")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(t, "", nil, "tar", "-xzf", tarball, "-C", l.dir, "--strip-components=1")
	l.paddock(t, "verify")
	writeLabTLS(t, filepath.Join(work, "tls"))
	l.s3 = startS3Store(t, l)
	l.writeEnv(t)
	// Plan M15 decision 36: the root owned by root and closed to group and others, the target writable by uid 999.
	mustRun(t, "", nil, "sudo", "-n", "install", "-d", "-o", "root", "-g", "root", "-m", "0755", l.localRoot)
	mustRun(t, "", nil, "sudo", "-n", "install", "-d", "-o", "999", "-g", "999", "-m", "0750", filepath.Join(l.localRoot, labLocalPath))

	l.paddock(t, "secrets")
	l.paddock(t, "up", "--infra")
	l.initOpenBao(t)
	for _, b := range []string{"buckets", "audit-bucket", "fleet"} {
		l.paddock(t, "bootstrap", b)
	}
	l.releaseKeys(t)
	l.startProxy(t)
	l.paddock(t, "check")
	l.paddock(t, "up")
	l.setupIdentities(t)
	return l
}

// removeLeftovers removes what a killed earlier run left behind, because its cleanups never ran: the lab's Compose
// project with its volumes, the proxy, the share relay and the S3 store. Only the gates' own fixed names are touched; the
// local roots and working directories of earlier runs carry a run ID and stay.
func removeLeftovers(t *testing.T) {
	t.Helper()
	t.Logf("removing leftovers of an earlier run, if any: Compose project %s with its volumes, containers %s and %s, "+
		"the S3 store", labProject, labNginx, shareRelay)
	// An empty directory, so Compose finds no project file and works from the project's labels alone.
	down := exec.Command("docker", "compose", "-p", labProject, "down", "--volumes", "--remove-orphans")
	down.Dir = t.TempDir()
	if out, err := down.CombinedOutput(); err != nil {
		t.Logf("docker compose -p %s down: %v %s", labProject, err, tail(out))
	}
	// Without a project file, Compose versions differ in whether down removes the named volumes; the label does not.
	if out, err := exec.Command("docker", "volume", "ls", "-q", "--filter",
		"label=com.docker.compose.project="+labProject).Output(); err == nil {
		for _, v := range strings.Fields(string(out)) {
			_ = exec.Command("docker", "volume", "rm", "-f", v).Run()
		}
	}
	_ = exec.Command("docker", "rm", "-f", labNginx, shareRelay).Run()
	(&s3Store{}).remove()
}

// readVersions reads the image references of versions.env.
func readVersions(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // repository file
	if err != nil {
		t.Fatal(err)
	}
	images := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(k, "#") {
			images[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return images
}

func (l *Lab) image(t *testing.T, name string) string {
	t.Helper()
	if l.images[name] == "" {
		t.Fatalf("%s is not set in deploy/compose/versions.env", name)
	}
	return l.images[name]
}

// caFile is the throwaway CA of the lab's proxy and of the S3 store.
func (l *Lab) caFile() string { return filepath.Join(l.work, "tls", "ca.crt") }

// env is the environment of every ./paddock call: smoke-lab.sh's CI overlay (pinned subnets, trust in the throwaway CA)
// and the gates' overlay that attaches the backup role to the S3 store's network. The project is pinned as smoke-lab.sh
// pins it, so no call can reach the development stack's.
func (l *Lab) env() []string {
	extra := filepath.Join(l.root, "deploy", "bundle", "ci", "compose.ci-lab.yaml")
	if l.s3 != nil {
		extra += " " + l.s3.overlay
	}
	return append(os.Environ(), "PADDOCK_PROJECT="+labProject, "PADDOCK_CI_LAB_TLS="+filepath.Join(l.work, "tls"),
		"PADDOCK_COMPOSE_EXTRA="+extra)
}

// paddock runs ./paddock in the bundle directory and returns its output; a failure fails t.
func (l *Lab) paddock(t *testing.T, args ...string) string {
	t.Helper()
	return l.paddockIn(t, nil, args...)
}

// paddockIn is paddock with stdin.
func (l *Lab) paddockIn(t *testing.T, stdin []byte, args ...string) string {
	t.Helper()
	out, err := l.tryPaddock(stdin, args...)
	if err != nil {
		t.Fatalf("./paddock %s: %v\n%s", strings.Join(args, " "), err, tail([]byte(out)))
	}
	return out
}

// tryPaddock runs ./paddock and returns its output and error.
func (l *Lab) tryPaddock(stdin []byte, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "./paddock", args...)
	cmd.Dir, cmd.Env = l.dir, l.env()
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// mustRun runs a host command; a failure fails t.
func mustRun(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, tail(out))
	}
	return strings.TrimSpace(string(out))
}

// setEnvLine sets name=value in an env file's text, replacing the first line that sets it or its commented default
// ("# name="), or appending it.
func setEnvLine(text, name, value string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, name+"=") || strings.HasPrefix(line, "# "+name+"=") {
			lines[i] = name + "=" + value
			return strings.Join(lines, "\n") + "\n"
		}
	}
	return strings.Join(append(lines, name+"="+value), "\n") + "\n"
}

// writeEnv writes .env from .env.lab.example with smoke-lab.sh's values, backups on and the gates' local root.
func (l *Lab) writeEnv(t *testing.T) {
	t.Helper()
	example, err := os.ReadFile(filepath.Join(l.dir, ".env.lab.example"))
	if err != nil {
		t.Fatal(err)
	}
	addr := strings.Fields(mustRun(t, "", nil, "hostname", "-I"))
	if len(addr) == 0 {
		t.Fatal("the host has no primary address")
	}
	text := string(example)
	for _, kv := range [][2]string{
		{"PADDOCK_PROJECT", labProject}, {"PADDOCK_DOMAIN", labDomain},
		{"PADDOCK_PUBLIC_ADMIN_URL", labAdminURL}, {"PADDOCK_PUBLIC_DEVICE_URL", "https://device." + labDomain},
		{"PADDOCK_INTERCONNECT_ADDR", "127.0.0.1"}, {"PADDOCK_LAB_HTTP_PORT", "8080"},
		{"PADDOCK_LAB_PROXY_ADDR", addr[0]},
		// The subnets compose.ci-lab.yaml pins, as smoke-lab.sh sets them (the same-host proxy variant).
		{"PADDOCK_EDGE_TRUSTED_PROXIES", "172.30.0.1"},
		{"PADDOCK_ADMIN_ALLOWED_CIDRS", "172.30.0.0/24 127.0.0.0/8 " + addr[0] + "/32"},
		{"PADDOCK_INTERNAL_CIDRS", "172.30.0.0/24 172.30.1.0/24 " + addr[0] + "/32"},
		{"PADDOCK_LAB_BACKUP", "yes"}, {"PADDOCK_BACKUP_LOCAL_ROOT", l.localRoot},
	} {
		text = setEnvLine(text, kv[0], kv[1])
	}
	if err := os.WriteFile(filepath.Join(l.dir, ".env"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// initOpenBao initializes OpenBao with five shares and threshold three, keeps three shares for the restores' unseal,
// unseals it and runs bootstrap openbao with the root token, which is revoked afterwards.
func (l *Lab) initOpenBao(t *testing.T) {
	t.Helper()
	var init struct {
		Shares []string `json:"unseal_keys_b64"`
		Root   string   `json:"root_token"`
	}
	out := l.paddock(t, "bao", "operator", "init", "-key-shares=5", "-key-threshold=3", "-format=json")
	if i := strings.Index(out, "{"); i < 0 || json.Unmarshal([]byte(out[i:]), &init) != nil || len(init.Shares) < 3 || init.Root == "" {
		t.Fatal("no unseal shares or root token in the OpenBao init output")
	}
	l.shares = init.Shares[:3]
	l.unseal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	for _, args := range [][]string{{"bootstrap", "openbao"}, {"bao", "token", "revoke", "-self"}} {
		cmd := exec.CommandContext(ctx, "./paddock", args...)
		cmd.Dir, cmd.Env, cmd.Stdin = l.dir, append(l.env(), "BAO_TOKEN="+init.Root), strings.NewReader("")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("./paddock %s: %v\n%s", strings.Join(args, " "), err, tail(out))
		}
	}
}

// unseal types the three shares as the custodians do (./paddock bao operator unseal, here non-interactive through
// sys/unseal with the share on stdin) and waits up to 60 s until OpenBao reports unsealed.
func (l *Lab) unseal(t *testing.T) {
	t.Helper()
	for _, share := range l.shares {
		l.paddockIn(t, []byte(share), "bao", "write", "sys/unseal", "key=-")
	}
	sealed := regexp.MustCompile(`(?m)^Sealed +false`)
	Until(t, "OpenBao unsealed", time.Minute, 2*time.Second, nil, func() bool {
		out, _ := l.tryPaddock([]byte{}, "bao", "status")
		return sealed.MatchString(out)
	})
}

// releaseKeys writes throwaway public release keys, as smoke-lab.sh step 7 does.
func (l *Lab) releaseKeys(t *testing.T) {
	t.Helper()
	keys, dst := filepath.Join(l.work, "keys"), filepath.Join(l.dir, ".secrets", "release-production")
	for _, dir := range []string{keys, dst} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"minisign", "revoke-minisign"} {
		pub := filepath.Join(keys, key+".pub")
		mustRun(t, filepath.Join(l.root, "agent"), append(os.Environ(), "GOTOOLCHAIN=auto"), "go", "run",
			"aead.dev/minisign/cmd/minisign", "-G", "-W", "-p", pub, "-s", filepath.Join(keys, key+".key"))
		data, err := os.ReadFile(pub) //nolint:gosec // generated above
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, key+".pub"), data, 0o644); err != nil { //nolint:gosec // public key
			t.Fatal(err)
		}
	}
}

// startProxy runs the shipped Nginx reference configuration on the host network with the lab's values, as
// smoke-lab.sh step 8 does.
func (l *Lab) startProxy(t *testing.T) {
	t.Helper()
	example, err := os.ReadFile(filepath.Join(l.dir, "nginx", "paddock.conf.example"))
	if err != nil {
		t.Fatal(err)
	}
	conf := strings.NewReplacer("192.0.2.10:8080", "127.0.0.1:8080",
		"/etc/letsencrypt/live/"+labDomain+"/fullchain.pem", "/tls/fullchain.pem",
		"/etc/letsencrypt/live/"+labDomain+"/privkey.pem", "/tls/privkey.pem").Replace(
		strings.ReplaceAll(string(example), "paddock.example.org", labDomain))
	for _, want := range []string{"ssl_certificate     /tls/fullchain.pem;", "ssl_certificate_key /tls/privkey.pem;", "server 127.0.0.1:8080;"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("the Nginx example changed: %q not found after the replacements", want)
		}
	}
	path := filepath.Join(l.work, "nginx.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil { //nolint:gosec // proxy configuration
		t.Fatal(err)
	}
	_ = exec.Command("docker", "rm", "-f", labNginx).Run()
	mustRun(t, "", nil, "docker", "run", "-d", "--name", labNginx, "--network", "host",
		"-v", path+":/etc/nginx/conf.d/default.conf:ro", "-v", filepath.Join(l.work, "tls")+":/tls:ro", l.image(t, "NGINX_IMAGE"))
}

// akShell runs a Python script in Authentik's shell (the script on stdin) and fails t unless it prints ok within five
// minutes: Authentik applies the blueprints that create the groups only after its start.
func (l *Lab) akShell(t *testing.T, script, ok string) {
	t.Helper()
	var out string
	Until(t, "Authentik shell: "+ok, 5*time.Minute, 10*time.Second, nil, func() bool {
		out, _ = l.tryPaddock([]byte(script), "compose", "exec", "-T", "authentik-worker", "ak", "shell")
		return strings.Contains(out, ok)
	})
}

// addUser creates (or updates) an internal Authentik user in group with a WebAuthn device of a new software
// authenticator. A blueprint cannot do it; the script, password included, reaches the shell on stdin only.
func (l *Lab) addUser(t *testing.T, name, group string) *labUser {
	t.Helper()
	key, err := portal.NewWebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	u := &labUser{name: name, password: randomToken(t), key: key}
	script := fmt.Sprintf(`from authentik.core.models import Group, User
from authentik.stages.authenticator_webauthn.models import WebAuthnDevice
u, _ = User.objects.update_or_create(username=%q, defaults={"name": %q, "email": %q, "type": "internal", "is_active": True})
u.set_password(%q)
u.save()
u.groups.add(Group.objects.get(name=%q))
WebAuthnDevice.objects.update_or_create(credential_id=%q, defaults={"user": u, "name": "paddock-systest", "public_key": %q, "rp_id": %q, "confirmed": True})
print("systest identity ok")
`, name, name, name, u.password, group, key.CredentialID(), key.PublicKey(), labRPID)
	l.akShell(t, script, "systest identity ok")
	return u
}

// randomToken is a random password of 32 letters and digits (no comma or whitespace: an SMB password travels in the
// mount options).
func randomToken(t *testing.T) string {
	t.Helper()
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// setupIdentities creates the platform administrator, the organization the VM enrolls into and its administrator.
func (l *Lab) setupIdentities(t *testing.T) {
	t.Helper()
	l.platform = l.addUser(t, "systest-platform-"+l.run+"@paddock.test", "paddock.platform.admins")
	l.orgSlug = "bs-" + l.run
	l.platformCall(t, http.MethodPost, "/api/platform/v1/organizations",
		map[string]string{"slug": l.orgSlug, "name": "Backup gates " + l.run}, http.StatusCreated)
	l.orgAdmin = l.addUser(t, "systest-admin-"+l.run+"@paddock.test", "paddock."+l.orgSlug+".admins")
}

// stack is the organization administrator's Stack for Install and the Device helpers, with the test VMs' login
// settings (devseed's for acme: the VMs' local administrator paddock is a break-glass account the agent leaves alone).
func (l *Lab) stack(t *testing.T) *Stack {
	t.Helper()
	s := &Stack{root: l.root, lab: l}
	s.Login(t)
	var settings map[string]any
	if err := json.Unmarshal(s.Call(t, http.MethodGet, "/api/v1/settings/login", nil, http.StatusOK).Body, &settings); err != nil {
		t.Fatal(err)
	}
	delete(settings, "updated_at")
	settings["break_glass_accounts"] = []string{"paddock"}
	settings["sudoers_d_allowlist"] = []string{"README", "90-paddock"}
	s.StepUp(t)
	s.Call(t, http.MethodPut, "/api/v1/settings/login", settings, http.StatusOK)
	return s
}

// login signs u in, repeating for up to five minutes while the lab's roles and Authentik's flows come up (also after a
// restore).
func (l *Lab) login(t *testing.T, u *labUser) *portal.Session {
	t.Helper()
	var s *portal.Session
	var err error
	Until(t, "sign-in of "+u.name, 5*time.Minute, 10*time.Second, nil, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		s, err = portal.LoginWebAuthn(ctx, l.caFile(), labAdminURL, u.name, u.password, u.key)
		if err != nil {
			t.Logf("sign-in of %s: %v", u.name, err)
		}
		return err == nil
	})
	return s
}

// stepUp runs a step-up of s as u. A refused one is repeated once after the production maximum auth age (20 s): within
// it Authentik answers with the earlier login, which may be too old by the callback (Stack.StepUp).
func (l *Lab) stepUp(t *testing.T, s *portal.Session, u *labUser) {
	t.Helper()
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		final, err := portal.StepUpWebAuthn(ctx, s, labAdminURL, u.password, u.key)
		cancel()
		if err == nil && !strings.Contains(final, "stepup=failed") {
			return
		}
		if attempt == 2 {
			t.Fatalf("step-up of %s: %v (returned to %s)", u.name, err, final)
		}
		t.Logf("step-up of %s refused (%v, returned to %s); repeating after %s", u.name, err, final, stepUpRetryAfter)
		time.Sleep(stepUpRetryAfter)
	}
}

// platformCall sends a platform API request as the platform administrator and expects status. It signs in on first
// use and after a lost session (a restore), and steps up before a write whose last step-up is older than four minutes
// (the step-up window is five).
func (l *Lab) platformCall(t *testing.T, method, path string, body any, status int) portal.Response {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.admin == nil {
		l.admin, l.steppedUp = l.login(t, l.platform), time.Time{}
	}
	if method != http.MethodGet && time.Since(l.steppedUp) > 4*time.Minute {
		l.stepUp(t, l.admin, l.platform)
		l.steppedUp = time.Now()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := l.admin.Do(ctx, method, path, body)
	if err == nil && res.Status == http.StatusUnauthorized && status != http.StatusUnauthorized {
		t.Logf("%s %s: HTTP 401, the platform session ended; signing in again once", method, path)
		l.admin = l.login(t, l.platform)
		if method != http.MethodGet {
			l.stepUp(t, l.admin, l.platform)
			l.steppedUp = time.Now()
		}
		res, err = l.admin.Do(ctx, method, path, body)
	}
	if err != nil || res.Status != status {
		t.Fatalf("%s %s: HTTP %d (want %d) %v %s", method, path, res.Status, status, err, res.Body)
	}
	return res
}

// requireHealthy fails t unless every running service of ./paddock ps is running and, where it has a health check,
// healthy.
func (l *Lab) requireHealthy(t *testing.T) {
	t.Helper()
	out := l.paddockIn(t, []byte{}, "ps", "--format", "{{.Service}} {{.State}} {{.Health}}")
	var bad []string
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(line, "lab profile") {
			continue
		}
		n++
		if f[1] != "running" || (len(f) > 2 && f[2] != "healthy") {
			bad = append(bad, line)
		}
	}
	if n == 0 || len(bad) > 0 {
		t.Fatalf("./paddock ps: %d services, not healthy: %v\n%s", n, bad, out)
	}
}

// psql runs a query in a database container of the lab as its superuser and returns the unaligned rows.
func (l *Lab) psql(t *testing.T, service, user, db, query string) string {
	t.Helper()
	return strings.TrimSpace(l.paddockIn(t, []byte{}, "compose", "exec", "-T", service, "psql", "-v", "ON_ERROR_STOP=1",
		"-U", user, "-d", db, "-Atc", query))
}

// labAuditEvent is an audit event of the lab's audit index.
type labAuditEvent struct {
	Display string         `json:"display"`
	Outcome string         `json:"outcome"`
	Params  map[string]any `json:"params"`
}

// waitAuditEvent waits up to three minutes for an event of code that occurred at or after since and satisfies match,
// read from the lab's audit index as its superuser (platform events have no portal list).
func (l *Lab) waitAuditEvent(t *testing.T, code string, since time.Time, match func(labAuditEvent) bool) labAuditEvent {
	t.Helper()
	query := fmt.Sprintf(`SELECT json_build_object('display', coalesce(actor->>'display', ''), 'outcome', outcome, 'params', params)
		FROM audit_event WHERE code = '%s' AND occurred_at >= '%s' ORDER BY occurred_at`, code, since.UTC().Format(time.RFC3339))
	var found labAuditEvent
	var seen []string
	Until(t, "audit event "+code, 3*time.Minute, 5*time.Second, nil, func() bool {
		out, err := l.tryPaddock([]byte{}, "compose", "exec", "-T", "audit-postgres", "psql", "-U", "postgres", "-d",
			"paddock_audit", "-Atc", query)
		if err != nil {
			return false
		}
		seen = seen[:0]
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			var e labAuditEvent
			if json.Unmarshal([]byte(line), &e) != nil {
				continue
			}
			seen = append(seen, line)
			if match(e) {
				found = e
				return true
			}
		}
		return false
	})
	t.Logf("%s: %+v (of %d)", code, found, len(seen))
	return found
}

// operator is the name ./paddock restore records as the operator: sudo's SUDO_USER, the user running the gates.
func operator(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return u.Username
}

// unsealPrompt is the line restore.sh prints when OpenBao waits for the custodians' shares.
const unsealPrompt = "Three custodians unseal it now"

// restore runs `sudo ./paddock restore <args>` with the backup key and the typed word on stdin, as an operator at the
// terminal; an empty key types only the word (`--only backup-repo` asks for no key). When the restore waits for the
// custodians, the gate unseals OpenBao with the three shares. The output is kept in logs/restore-<n>.log.
func (l *Lab) restore(t *testing.T, key string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	stdin := "restore\n"
	if key != "" {
		stdin = key + "\n" + stdin
	}
	sudoArgs := []string{"-n", "env"}
	for _, e := range l.env() {
		if strings.HasPrefix(e, "PADDOCK_") || strings.HasPrefix(e, "PATH=") {
			sudoArgs = append(sudoArgs, e)
		}
	}
	cmd := exec.CommandContext(ctx, "sudo", append(append(sudoArgs, "./paddock", "restore"), args...)...)
	cmd.Dir, cmd.Stdin = l.dir, strings.NewReader(stdin)
	// A killed restore can leave a grandchild holding the pipe; Run then returns after this delay instead of never.
	cmd.WaitDelay = time.Minute
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	logFile, err := os.CreateTemp(filepath.Join(l.work, "logs"), "restore-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFile.Close() }()
	var out strings.Builder
	var unsealErr, scanErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			out.WriteString(line + "\n")
			_, _ = fmt.Fprintln(logFile, line)
			if strings.Contains(line, unsealPrompt) {
				for i, share := range l.shares {
					if err := l.unsealShare(share); err != nil && unsealErr == nil {
						unsealErr = fmt.Errorf("unseal share %d: %w", i+1, err)
					}
				}
			}
		}
		scanErr = sc.Err()
		// The scanner stops at an overlong line; without the drain the restore would block writing to the pipe.
		_, _ = io.Copy(logFile, pr)
	}()
	err = cmd.Run()
	_ = pw.Close()
	<-done
	if err != nil || unsealErr != nil || scanErr != nil {
		t.Fatalf("sudo ./paddock restore %s: %v %v %v (log %s)\n%s", strings.Join(args, " "), err, unsealErr, scanErr,
			logFile.Name(), tail([]byte(out.String())))
	}
	t.Logf("restore %s finished: %s", strings.Join(args, " "), lastLine(out.String(), "restore completed"))
	l.mu.Lock()
	l.admin = nil
	l.mu.Unlock()
}

// unsealShare types one share as a custodian, retrying for up to two minutes: restore.sh prints its prompt as it starts
// OpenBao, which may not answer yet, and a share that never lands would leave the restore waiting its full unseal
// timeout.
func (l *Lab) unsealShare(share string) error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		out, err := l.tryPaddock([]byte(share), "bao", "write", "sys/unseal", "key=-")
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %s", err, tail([]byte(out)))
		}
		time.Sleep(3 * time.Second)
	}
}

func lastLine(text, substr string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], substr) {
			return lines[i]
		}
	}
	return ""
}

// teardown keeps the logs in logs/, then removes the proxy, the installation with its volumes, the S3 store, the local
// root and the working directory (the restores leave root-owned files there, hence sudo).
func (l *Lab) teardown(t *testing.T) {
	if t.Failed() && os.Getenv("PADDOCK_SYSTEM_KEEP") != "" {
		t.Logf("PADDOCK_SYSTEM_KEEP: the lab stays in %s (project %s); remove it with ./paddock down --volumes, "+
			"docker rm -f %s, the S3 store's containers and network, and sudo rm -rf %s %s", l.dir, labProject, labNginx,
			l.work, l.localRoot)
		return
	}
	evidence := filepath.Join(l.root, "bin", "system-evidence", "lab")
	_ = os.MkdirAll(evidence, 0o755)
	if _, err := os.Stat(filepath.Join(l.dir, ".env")); err == nil {
		if out, err := l.tryPaddock([]byte{}, "logs"); err == nil {
			_ = os.WriteFile(filepath.Join(evidence, "paddock-lab.log"), []byte(out), 0o644) //nolint:gosec // test log
		}
		if out, err := l.tryPaddock([]byte{}, "down", "--volumes"); err != nil {
			t.Errorf("./paddock down --volumes: %v\n%s", err, tail([]byte(out)))
		}
	}
	_ = exec.Command("docker", "rm", "-f", labNginx).Run()
	if l.s3 != nil {
		l.s3.remove()
	}
	_ = exec.Command("sh", "-c", "cp -r "+filepath.Join(l.work, "logs")+"/. "+evidence+"/ 2>/dev/null").Run()
	if out, err := exec.Command("sudo", "-n", "rm", "-rf", l.work, l.localRoot).CombinedOutput(); err != nil {
		t.Errorf("remove the lab's directories: %v %s", err, out)
	}
}

// Command upgradeprobe seeds an installation of an operator bundle and probes it across an upgrade, a restore and a
// rollback (plan M16 decision 10, deploy/bundle/ci/seed.sh and upgrade.sh). It talks to a production stack: every
// sign-in and step-up passes Authentik's WebAuthn validation with a software passkey (authflow.WebAuthn,
// decisions-alpha9 item 53), registered for the job's own administrators with `ak shell`.
//
//	upgradeprobe seed --state <dir> --ak-shell <cmd> --enrollment-config <file>
//	upgradeprobe snapshot --state <dir> --label <name> --device-id <id>
//	upgradeprobe probe --state <dir> --label <name> --since <label> [--touch <text>] [--reveal <device state file>]
//	upgradeprobe backup-key --state <dir> --key-out <file>
//
// seed runs against the previous release; it may only use the admin API both releases have. It creates a platform
// administrator, the organization ci-upgrade with an administrator, a managed file for every device, an
// auto-approving enrollment token (its configuration goes to <file>), a disabled webhook destination and an API
// token. snapshot records the device and the organization's audit event count under <label>. probe signs in anew and
// requires every seeded object with its ID, an audit event count of at least the one of <since>, no failed audit
// chain verification, an API token that still reads; --touch rewrites the managed file's content (a new bundle),
// --reveal steps up and reveals the device's escrowed password, which must equal the one the device escrowed.
// backup-key confirms a backup key (written to <file>, 0600) and creates the local backup target ci-local.
// Configuration: PADDOCK_SECRETS_DIR (caddy-root.crt, authentik_bootstrap_token), PADDOCK_TEST_ADMIN_URL,
// PADDOCK_TEST_AUTH_URL. Secrets go to files in <dir> (0600), never to the output.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

const (
	orgSlug      = "ci-upgrade"
	platformUser = "ci-platform@paddock.localhost"
	orgUser      = "ci-admin@paddock.localhost"
	filePath     = "/etc/paddock-ci/upgrade.conf"
	passkeyName  = "paddock-ci-upgrade"
)

// seed is what seed creates, kept in <dir>/seed.json (0600).
type seed struct {
	OrgID         string            `json:"org_id"`
	FileID        string            `json:"file_id"`
	TokenID       string            `json:"token_id"`
	DestinationID string            `json:"destination_id"`
	APITokenID    string            `json:"api_token_id"`
	APITokenFile  string            `json:"api_token_file"`
	Passwords     map[string]string `json:"passwords"`
	DeviceID      string            `json:"device_id,omitempty"`
	AuditCounts   map[string]int    `json:"audit_counts,omitempty"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "upgradeprobe:", err)
		os.Exit(1)
	}
}

const usage = "usage: upgradeprobe seed|snapshot|probe|backup-key --state <dir> [options]"

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := fs.String("state", "", "state directory")
	akShell := fs.String("ak-shell", "", "command that runs Authentik's ak shell with the script on stdin (seed)")
	enrollOut := fs.String("enrollment-config", "", "file for the enrollment configuration (seed)")
	label := fs.String("label", "", "name of this snapshot or probe")
	since := fs.String("since", "", "snapshot whose audit event count is the minimum (probe)")
	deviceID := fs.String("device-id", "", "the seeded device (snapshot)")
	touch := fs.String("touch", "", "new content line of the managed file (probe)")
	reveal := fs.String("reveal", "", "state file of the device whose password is revealed (probe)")
	keyOut := fs.String("key-out", "", "file for the backup key (backup-key)")
	timeout := fs.Duration("timeout", 10*time.Minute, "overall time limit")
	if err := fs.Parse(args[1:]); err != nil || *dir == "" {
		return errors.New(usage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	switch args[0] {
	case "seed":
		if *akShell == "" || *enrollOut == "" {
			return errors.New(usage)
		}
		return runSeed(ctx, *dir, *akShell, *enrollOut)
	case "snapshot":
		if *label == "" || *deviceID == "" {
			return errors.New(usage)
		}
		return runSnapshot(ctx, *dir, *label, *deviceID)
	case "probe":
		if *label == "" || *since == "" {
			return errors.New(usage)
		}
		return runProbe(ctx, *dir, *label, *since, *touch, *reveal)
	case "backup-key":
		if *keyOut == "" {
			return errors.New(usage)
		}
		return runBackupKey(ctx, *dir, *keyOut)
	}
	return errors.New(usage)
}

func say(format string, a ...any) { fmt.Printf("upgradeprobe: "+format+"\n", a...) }

// --- sessions -------------------------------------------------------------------------------------------------------

// session signs user in with password and the user's passkey from <dir>.
func session(ctx context.Context, dir, user, password string) (*env.Portal, *authflow.WebAuthn, error) {
	key, err := authflow.LoadWebAuthn(passkeyFile(dir, user))
	if err != nil {
		return nil, nil, err
	}
	client, err := env.NewHTTPClient()
	if err != nil {
		return nil, nil, err
	}
	res, err := authflow.LoginMFA(ctx, client, stack.AdminURL(), user, password, key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign-in of %s: %w", user, err)
	}
	return &env.Portal{User: user, Client: res.Client, Final: res.Final}, key, nil
}

// stepUp runs one step-up of the session with the user's passkey. A fresh session needs only one: the step-up
// covers the privileged actions of the next minutes.
func stepUp(ctx context.Context, p *env.Portal, password string, key *authflow.WebAuthn) error {
	res, err := authflow.StepUpMFA(ctx, p.Client, stack.AdminURL(), "/", p.User, password, key, false)
	if err != nil {
		return fmt.Errorf("step-up of %s: %w", p.User, err)
	}
	if strings.Contains(res.Final, "stepup=failed") {
		return fmt.Errorf("step-up of %s refused: %s", p.User, res.Final)
	}
	return nil
}

// do calls the admin API and requires the status; out (optional) receives the JSON body.
func do(ctx context.Context, p *env.Portal, method, path string, body any, want int, out any) error {
	res, err := p.Do(ctx, method, path, body)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	if res.Status != want {
		var p struct {
			Detail string `json:"detail"`
		}
		_ = res.JSON(&p)
		return fmt.Errorf("%s %s: HTTP %d (%s: %s), want %d", method, path, res.Status, res.ProblemCode(), p.Detail, want)
	}
	if out != nil {
		if err := res.JSON(out); err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
	}
	return nil
}

// --- seed -----------------------------------------------------------------------------------------------------------

func runSeed(ctx context.Context, dir, akShell, enrollOut string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	probe, err := env.NewHTTPClient()
	if err != nil {
		return err
	}
	if err := authflow.WaitReady(ctx, probe, stack.AuthURL(), "paddock-admin-login", 5*time.Minute, 3*time.Second); err != nil {
		return err
	}
	ak, err := env.NewAuthentik()
	if err != nil {
		return err
	}
	s := seed{Passwords: map[string]string{}, AuditCounts: map[string]int{}}
	rpID := hostOf(stack.AuthURL())

	// The platform administrator: the job's first administrator (install.md §9 makes one from akadmin by hand).
	if err := admin(ctx, ak, akShell, dir, &s, platformUser, rpID, "paddock.platform.admins"); err != nil {
		return err
	}
	platform, key, err := session(ctx, dir, platformUser, s.Passwords[platformUser])
	if err != nil {
		return err
	}
	if err := stepUp(ctx, platform, s.Passwords[platformUser], key); err != nil {
		return err
	}
	var org struct {
		ID string `json:"id"`
	}
	if err := do(ctx, platform, http.MethodPost, "/api/platform/v1/organizations",
		map[string]string{"slug": orgSlug, "name": "CI Upgrade"}, http.StatusCreated, &org); err != nil {
		return err
	}
	s.OrgID = org.ID
	say("organization %s: %s", orgSlug, s.OrgID)
	group := env.RoleGroup(orgSlug, "admins")
	if err := waitFor(ctx, "the Authentik group "+group, func() (bool, error) {
		pk, err := ak.GroupPK(ctx, group)
		return pk != "", err
	}); err != nil {
		return err
	}
	if err := admin(ctx, ak, akShell, dir, &s, orgUser, rpID, group); err != nil {
		return err
	}
	p, key, err := session(ctx, dir, orgUser, s.Passwords[orgUser])
	if err != nil {
		return err
	}
	if err := stepUp(ctx, p, s.Passwords[orgUser], key); err != nil {
		return err
	}

	var created struct {
		ID string `json:"id"`
	}
	if err := do(ctx, p, http.MethodPost, "/api/v1/managed-files",
		map[string]any{"path": filePath, "mode": "0644", "content": "seed=1\n"}, http.StatusCreated, &created); err != nil {
		return err
	}
	s.FileID = created.ID
	var tok struct {
		Token struct {
			ID string `json:"id"`
		} `json:"token"`
		EnrollmentConfig json.RawMessage `json:"enrollment_config"`
	}
	if err := do(ctx, p, http.MethodPost, "/api/v1/enrollment-tokens", map[string]any{
		"name": "ci upgrade", "expires_at": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"max_uses": 10, "auto_approve": true,
	}, http.StatusCreated, &tok); err != nil {
		return err
	}
	s.TokenID = tok.Token.ID
	if err := os.WriteFile(enrollOut, tok.EnrollmentConfig, 0o600); err != nil {
		return err
	}
	if err := do(ctx, p, http.MethodPost, "/api/v1/notification-destinations", map[string]any{
		"type": "webhook", "name": "ci upgrade", "enabled": false, "filter_mode": "security",
		// The production URL policy refuses a host that does not resolve to a public address; example.com is reserved
		// for documentation and resolves. The destination stays disabled, so nothing is ever sent there.
		"url": "https://example.com/paddock-ci-upgrade",
	}, http.StatusCreated, &created); err != nil {
		return err
	}
	s.DestinationID = created.ID
	var api struct {
		Token struct {
			ID string `json:"id"`
		} `json:"token"`
		Secret string `json:"secret"`
	}
	if err := do(ctx, p, http.MethodPost, "/api/v1/api-tokens", map[string]any{
		"name": "ci upgrade", "role": "org_auditor", "expires_at": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}, http.StatusCreated, &api); err != nil {
		return err
	}
	s.APITokenID = api.Token.ID
	s.APITokenFile = filepath.Join(dir, "api-token")
	if err := os.WriteFile(s.APITokenFile, []byte(api.Secret), 0o600); err != nil {
		return err
	}
	say("seeded: managed file %s, enrollment token %s, destination %s, API token %s", s.FileID, s.TokenID,
		s.DestinationID, s.APITokenID)
	return saveSeed(dir, s)
}

// admin creates an Authentik user in group with a random password and registers a passkey for it.
func admin(ctx context.Context, ak *env.Authentik, akShell, dir string, s *seed, user, rpID, group string) error {
	password := "Ci-" + randomHex(16)
	if _, err := ak.CreateUser(ctx, user, password, group); err != nil {
		return fmt.Errorf("create %s: %w", user, err)
	}
	s.Passwords[user] = password
	key, err := authflow.NewWebAuthn()
	if err != nil {
		return err
	}
	if err := key.Save(passkeyFile(dir, user)); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, akShell) //nolint:gosec // the job's own wrapper
	cmd.Stdin = strings.NewReader(key.RegistrationScript(user, rpID, passkeyName))
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "paddock-webauthn ok") {
		return fmt.Errorf("register the passkey of %s: %v: %s", user, err, out)
	}
	say("administrator %s in %s with a passkey", user, group)
	return saveSeed(dir, *s)
}

// --- snapshot and probe ---------------------------------------------------------------------------------------------

func runSnapshot(ctx context.Context, dir, label, deviceID string) error {
	s, err := loadSeed(dir)
	if err != nil {
		return err
	}
	p, _, err := session(ctx, dir, orgUser, s.Passwords[orgUser])
	if err != nil {
		return err
	}
	n, err := auditCount(ctx, p)
	if err != nil {
		return err
	}
	s.DeviceID = deviceID
	s.AuditCounts[label] = n
	say("snapshot %s: device %s, %d audit events", label, deviceID, n)
	return saveSeed(dir, s)
}

func runProbe(ctx context.Context, dir, label, since, touch, reveal string) error {
	s, err := loadSeed(dir)
	if err != nil {
		return err
	}
	min, ok := s.AuditCounts[since]
	if !ok {
		return fmt.Errorf("no snapshot %s", since)
	}
	platform, _, err := session(ctx, dir, platformUser, s.Passwords[platformUser])
	if err != nil {
		return err
	}
	if err := do(ctx, platform, http.MethodGet, "/api/platform/v1/organizations/"+s.OrgID, nil, http.StatusOK, nil); err != nil {
		return err
	}
	p, key, err := session(ctx, dir, orgUser, s.Passwords[orgUser])
	if err != nil {
		return err
	}
	for _, path := range []string{"/api/v1/managed-files/" + s.FileID, "/api/v1/enrollment-tokens/" + s.TokenID,
		"/api/v1/notification-destinations/" + s.DestinationID, "/api/v1/api-tokens/" + s.APITokenID,
		"/api/v1/devices/" + s.DeviceID} {
		if err := do(ctx, p, http.MethodGet, path, nil, http.StatusOK, nil); err != nil {
			return err
		}
		say("%s: present", path)
	}
	if err := apiTokenReads(ctx, s); err != nil {
		return err
	}
	n, err := auditCount(ctx, p)
	if err != nil {
		return err
	}
	if n < min {
		return fmt.Errorf("the organization has %d audit events, fewer than the %d of %s", n, min, since)
	}
	say("audit events: %d (>= %d of %s)", n, min, since)
	var integrity struct {
		LastFailureAt *string `json:"last_failure_at"`
		LastRun       *struct {
			Status string `json:"status"`
		} `json:"last_run"`
	}
	if err := do(ctx, p, http.MethodGet, "/api/v1/audit/integrity", nil, http.StatusOK, &integrity); err != nil {
		return err
	}
	if integrity.LastFailureAt != nil {
		return fmt.Errorf("the audit chain verification failed at %s", *integrity.LastFailureAt)
	}
	say("audit chain: no failed verification")
	if touch != "" || reveal != "" {
		if err := stepUp(ctx, p, s.Passwords[orgUser], key); err != nil {
			return err
		}
	}
	if touch != "" {
		if err := do(ctx, p, http.MethodPatch, "/api/v1/managed-files/"+s.FileID,
			map[string]any{"content": touch + "\n"}, http.StatusOK, nil); err != nil {
			return err
		}
		say("managed file rewritten: %s", touch)
	}
	if reveal != "" {
		if err := revealMatches(ctx, p, s.DeviceID, reveal); err != nil {
			return err
		}
	}
	s.AuditCounts[label] = n
	return saveSeed(dir, s)
}

// revealMatches reveals the device's local administrator password and compares it with the escrowed one.
func revealMatches(ctx context.Context, p *env.Portal, deviceID, deviceState string) error {
	data, err := os.ReadFile(deviceState) //nolint:gosec // the job's own state file
	if err != nil {
		return err
	}
	var dev struct {
		Hostname string `json:"hostname"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(data, &dev); err != nil || dev.Password == "" {
		return fmt.Errorf("%s holds no escrowed password: %v", deviceState, err)
	}
	var out struct {
		Passwords []struct {
			State    string `json:"state"`
			Password string `json:"password"`
		} `json:"passwords"`
	}
	if err := do(ctx, p, http.MethodPost, "/api/v1/devices/"+deviceID+"/local-admin/reveal",
		map[string]string{"confirm_hostname": dev.Hostname}, http.StatusOK, &out); err != nil {
		return err
	}
	for _, pw := range out.Passwords {
		if pw.State == "active" && pw.Password == dev.Password {
			say("escrow: the revealed password is the escrowed one")
			return nil
		}
	}
	return errors.New("escrow: the revealed active password is not the one the device escrowed")
}

// apiTokenReads lists the audit events with the seeded API token (org_auditor).
func apiTokenReads(ctx context.Context, s seed) error {
	secret, err := os.ReadFile(s.APITokenFile)
	if err != nil {
		return err
	}
	client, err := env.HeaderClient(map[string]string{"Authorization": "Bearer " + strings.TrimSpace(string(secret))})
	if err != nil {
		return err
	}
	res, err := env.Call(ctx, client, http.MethodGet, stack.AdminURL()+"/api/v1/audit-events?page_size=10", nil, false)
	if err != nil {
		return err
	}
	if res.Status != http.StatusOK {
		return fmt.Errorf("the API token reads: HTTP %d (%s), want 200", res.Status, res.ProblemCode())
	}
	say("API token: reads")
	return nil
}

func auditCount(ctx context.Context, p *env.Portal) (int, error) {
	var page struct {
		Total int `json:"total"`
	}
	if err := do(ctx, p, http.MethodGet, "/api/v1/audit-events?page_size=10", nil, http.StatusOK, &page); err != nil {
		return 0, err
	}
	return page.Total, nil
}

// --- backup key -----------------------------------------------------------------------------------------------------

func runBackupKey(ctx context.Context, dir, keyOut string) error {
	s, err := loadSeed(dir)
	if err != nil {
		return err
	}
	p, key, err := session(ctx, dir, platformUser, s.Passwords[platformUser])
	if err != nil {
		return err
	}
	if err := stepUp(ctx, p, s.Passwords[platformUser], key); err != nil {
		return err
	}
	const path = "/api/platform/v1/backup/key"
	var status struct {
		Active *struct {
			KeyID string `json:"key_id"`
		} `json:"active"`
	}
	if err := do(ctx, p, http.MethodGet, path, nil, http.StatusOK, &status); err != nil {
		return err
	}
	// The key text exists only in the answer that generated it: an active key is reused only when this job wrote it.
	if _, err := os.Stat(keyOut); err == nil && status.Active != nil {
		say("backup key %s active", status.Active.KeyID)
	} else {
		if err := newBackupKey(ctx, p, path, keyOut); err != nil {
			return err
		}
	}
	var page struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := do(ctx, p, http.MethodGet, "/api/platform/v1/backup/targets?page_size=100&q=ci-local", nil, http.StatusOK, &page); err != nil {
		return err
	}
	for _, t := range page.Items {
		if t.Name == "ci-local" {
			say("backup target ci-local: %s", t.ID)
			return nil
		}
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := do(ctx, p, http.MethodPost, "/api/platform/v1/backup/targets", map[string]any{
		"name": "ci-local", "type": "local", "enabled": true, "local": map[string]any{"path": "ci"},
	}, http.StatusCreated, &target); err != nil {
		return err
	}
	say("backup target ci-local: %s", target.ID)
	return nil
}

// newBackupKey generates a backup key, writes it to keyOut (0600) and confirms it with the characters the
// confirmation asks for.
func newBackupKey(ctx context.Context, p *env.Portal, path, keyOut string) error {
	var g struct {
		KeyID     string `json:"key_id"`
		Key       string `json:"key"`
		Positions []int  `json:"positions"`
	}
	if err := do(ctx, p, http.MethodPost, path, nil, http.StatusCreated, &g); err != nil {
		return err
	}
	var answer strings.Builder
	for _, pos := range g.Positions {
		if pos < 1 || pos > len(g.Key) {
			return fmt.Errorf("backup key %s: challenge position %d outside the key", g.KeyID, pos)
		}
		answer.WriteByte(g.Key[pos-1])
	}
	if err := os.WriteFile(keyOut, []byte(g.Key+"\n"), 0o600); err != nil {
		return err
	}
	if err := do(ctx, p, http.MethodPost, path+"/"+g.KeyID+"/confirm", map[string]string{"answer": answer.String()},
		http.StatusOK, nil); err != nil {
		return err
	}
	say("backup key %s confirmed", g.KeyID)
	return nil
}

// --- state ----------------------------------------------------------------------------------------------------------

func passkeyFile(dir, user string) string {
	return filepath.Join(dir, "passkey-"+strings.NewReplacer("@", "_", "/", "_").Replace(user)+".pem")
}

func saveSeed(dir string, s seed) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "seed.json"), data, 0o600)
}

func loadSeed(dir string) (seed, error) {
	var s seed
	data, err := os.ReadFile(filepath.Join(dir, "seed.json")) //nolint:gosec // the job's own state
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, err
	}
	if s.AuditCounts == nil {
		s.AuditCounts = map[string]int{}
	}
	return s, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24)
	return hex.EncodeToString(b)
}

func hostOf(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// waitFor polls cond every 2 s until it holds or ctx ends.
func waitFor(ctx context.Context, what string, cond func() (bool, error)) error {
	var last error
	for {
		ok, err := cond()
		if ok {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s (last error: %v)", what, last)
		case <-time.After(2 * time.Second):
		}
	}
}

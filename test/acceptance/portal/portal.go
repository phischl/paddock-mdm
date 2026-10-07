// Package portal opens the acceptance helpers to test modules outside test/acceptance (the system tests of plan
// M2b §3.4): signed-in admin API sessions of the development users, the audit index and the stack's secrets.
package portal

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// Development users.
const (
	PlatformAdmin = env.PlatformAdmin
	Alice         = env.Alice
)

// PlatformOrganization is the pseudo-organization of platform audit events.
var PlatformOrganization = uuid.Nil

// Session is a signed-in portal session (admin API calls, audit log).
type Session = env.Portal

// Response is an admin API answer.
type Response = env.Response

// AuditEvent is an audit event as the admin API returns it.
type AuditEvent = env.AuditEvent

// AuditIndex reads the audit index of any organization.
type AuditIndex = env.AuditIndex

// Login signs in a development user.
func Login(ctx context.Context, user string) (*Session, error) { return env.Login(ctx, user, "") }

// NewAuditIndex connects to the audit index.
func NewAuditIndex(ctx context.Context) (*AuditIndex, error) { return env.NewAuditIndex(ctx) }

// SecretsDir is deploy/compose/.secrets.
func SecretsDir() (string, error) { return stack.SecretsDir() }

// RepoRoot is the repository root.
func RepoRoot() (string, error) { return stack.RepoRoot() }

// Authentik is the Authentik admin API with the bootstrap token.
type Authentik = env.Authentik

// NewAuthentik creates the Authentik admin client.
func NewAuthentik() (*Authentik, error) { return env.NewAuthentik() }

// RootGroup is the Authentik group of an organization's users: paddock.<slug>.
func RootGroup(slug string) string { return env.RootGroup(slug) }

// TOTP generates the codes of a user's TOTP authenticator; the zero value enrolls one at the first approval.
type TOTP = authflow.TOTP

// ErrAccessDenied is the refusal of a device approval by the application's policy.
var ErrAccessDenied = authflow.ErrAccessDenied

// ApproveDeviceCode approves the user code a device shows (greeter or PAM conversation) like the user on a second
// device: the verification URL with the code, password and MFA (plan M3b gate L1). It returns the flow stages passed.
func ApproveDeviceCode(ctx context.Context, userCode, username, password string, totp *TOTP) ([]string, error) {
	dir, err := stack.SecretsDir()
	if err != nil {
		return nil, err
	}
	da := authflow.DeviceAuthorization{
		UserCode: userCode, VerificationURIComplete: stack.AuthURL() + "/device?" + url.Values{"code": {userCode}}.Encode(),
	}
	return authflow.ApproveDevice(ctx, filepath.Join(dir, "caddy-root.crt"), da, username, password, totp)
}

// Compose runs `docker compose` for the development stack and returns the combined output.
func Compose(ctx context.Context, args ...string) (string, error) {
	return stack.Compose(ctx, nil, args...)
}

// LoginAs signs in any user with its password.
func LoginAs(ctx context.Context, user, password string) (*Session, error) {
	return env.Login(ctx, user, password)
}

// RoleGroup is an organization's Authentik role group; role is admins, operators or auditors.
func RoleGroup(slug, role string) string { return env.RoleGroup(slug, role) }

// AddTOTP gives user a TOTP authenticator with a random key, installed in Authentik's shell like `make dev-seed`
// does (the key travels on stdin), and returns its generator.
func AddTOTP(ctx context.Context, user string) (*TOTP, error) {
	key := make([]byte, 20)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	script := fmt.Sprintf("from authentik.core.models import User\nfrom authentik.stages.authenticator_totp.models import TOTPDevice\n"+
		"TOTPDevice.objects.create(user=User.objects.get(username=%q), name=\"paddock-systest\", key=%q, confirmed=True)\n"+
		"print(\"systest totp ok\")\n", user, hex.EncodeToString(key))
	out, err := stack.ComposeInput(ctx, strings.NewReader(script), "exec", "-T", "authentik-worker", "ak", "shell")
	if err != nil || !strings.Contains(out, "systest totp ok") {
		return nil, fmt.Errorf("TOTP authenticator of %s: %v %s", user, err, out)
	}
	return &TOTP{Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)}, nil
}

// StepUpAs runs a step-up of s as user with its password and TOTP and returns the portal URL it returned to; it
// contains stepup=failed when Paddock refused the step-up.
func StepUpAs(ctx context.Context, s *Session, user, password string, totp *TOTP) (string, error) {
	res, err := authflow.StepUp(ctx, s.Client, stack.AdminURL(), "/", user, password, totp, false)
	if err != nil {
		return "", err
	}
	return res.Final, nil
}

// Package portal opens the acceptance helpers to test modules outside test/acceptance (the system tests of plan
// M2b §3.4): signed-in admin API sessions of the development users, the audit index and the stack's secrets.
package portal

import (
	"context"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
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

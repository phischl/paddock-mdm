package app

import (
	"context"
	"fmt"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// SessionEnder ends every portal session of the installation (sessions.Store).
type SessionEnder interface {
	EndAll(ctx context.Context) (int64, error)
}

// Privileged actions of the portal sessions (plan M8s decision 16).
var (
	SpecSessionsEndAll    = ActionSpec{Code: audit.CodePlatformSessionsEnded, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	specSessionsEndAllCLI = ActionSpec{Code: audit.CodePlatformSessionsEnded, Actor: &adminActor}
)

// Sessions ends portal sessions.
type Sessions struct {
	runner *ActionRunner
	store  SessionEnder
}

// NewSessions creates the use case.
func NewSessions(runner *ActionRunner, store SessionEnder) *Sessions {
	return &Sessions{runner: runner, store: store}
}

// EndAll ends every portal session, the caller's own with its next request, and returns the new generation
// (audited: platform.sessions_ended, platform administrators with a step-up only).
func (s *Sessions) EndAll(ctx context.Context) (int64, error) {
	return s.endAll(ctx, SpecSessionsEndAll)
}

// EndAllCLI is EndAll for paddock-server admin end-sessions: a system principal, for when the portal is not usable.
func (s *Sessions) EndAllCLI(ctx context.Context) (int64, error) {
	return s.endAll(systemPlatform(ctx), specSessionsEndAllCLI)
}

func (s *Sessions) endAll(ctx context.Context, spec ActionSpec) (int64, error) {
	var gen int64
	err := s.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, _ *pgstore.Queries, rec Recorder) error {
		var err error
		if gen, err = s.store.EndAll(ctx); err != nil {
			return fmt.Errorf("end sessions: %w", err)
		}
		rec.SetParam("generation", gen)
		return nil
	})
	return gen, err
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// runAgentRollout starts (agent-rollout) or halts (agent-rollout-halt) the staged rollout of a published release with
// the api role's configuration and the system actor of the host commands (ADR 0034 amendment 2026-10-26): in the
// Compose stack as docker compose … run --rm --no-deps paddock-api admin agent-rollout --version <v>. It prints the
// rollout as JSON; a refusal names the API's problem code on stderr.
func runAgentRollout(ctx context.Context, l *config.Loader, cmd adminCommand, stdout io.Writer) error {
	// stdout carries the JSON only; the logs of the use cases go to stderr.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	orgDSN := l.SecretFile("PADDOCK_DB_URL_FILE")
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	development := config.LoadCommon(l).Development()
	if err := l.Err(); err != nil {
		return err
	}
	orgPool, err := db.NewOrgPool(ctx, orgDSN, db.Options{ApplicationName: "paddock-admin", MaxConns: 2})
	if err != nil {
		return err
	}
	defer orgPool.Close()
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, db.Options{ApplicationName: "paddock-admin-platform", MaxConns: 2})
	if err != nil {
		return err
	}
	defer platformPool.Close()
	correlation := "admin-" + uuid.NewString()
	runner := app.NewActionRunner(orgPool, platformPool, func(context.Context) string { return correlation })
	releases := app.NewAgentReleases(runner, platformPool, nil, nil, nil, development)

	run := func() (pgstore.AgentRollout, error) {
		return releases.StartRolloutFromHost(ctx, cmd.version, cmd.rollout)
	}
	if cmd.name == "agent-rollout-halt" {
		run = func() (pgstore.AgentRollout, error) { return releases.HaltFromHost(ctx, cmd.version) }
	}
	r, err := run()
	if err != nil {
		return rolloutRefused(os.Stderr, cmd, err)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rolloutJSON(r))
}

// rolloutRefused prints the refusal with the problem code the API answers with, so that scripts and operators can tell
// "invalid_state" from "already_exists" or "invalid_request".
func rolloutRefused(stderr io.Writer, cmd adminCommand, err error) error {
	var p *problem.Error
	if errors.As(err, &p) {
		fmt.Fprintf(stderr, "%s %s: refused: problem %s: %s\n", cmd.name, cmd.version, p.Code, p.Detail)
	} else {
		fmt.Fprintf(stderr, "%s %s: %v\n", cmd.name, cmd.version, err)
	}
	return err
}

// rolloutJSON is the admin API's representation of a rollout (POST /api/platform/v1/agent-releases/{version}/rollout).
func rolloutJSON(r pgstore.AgentRollout) adminapi.AgentRollout {
	waves := make([]int, len(r.Waves))
	for i, w := range r.Waves {
		waves[i] = int(w)
	}
	return adminapi.AgentRollout{
		Version: r.Version, Waves: waves, CurrentWaveIndex: int(r.CurrentWaveIndex), WaveStartedAt: r.WaveStartedAt.UTC(),
		MinWaveMinutes: int(r.MinWaveMinutes), FailureThresholdPercent: int(r.FailureThresholdPercent),
		FailureThresholdMin: int(r.FailureThresholdMin), Status: adminapi.AgentRolloutStatus(r.Status),
		HaltedReason: r.HaltedReason, StartedBy: r.StartedBy, StartedAt: r.StartedAt.UTC(),
	}
}

// parseWaves parses --waves 1,10,50,100. Only the syntax is checked here: the use case validates the values, so a
// wrong wave list is refused with the API's problem code and audited.
func parseWaves(v string) ([]int, error) {
	parts := strings.Split(v, ",")
	waves := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		waves[i] = n
	}
	return waves, nil
}

// intFlag sets *dst to the flag's integer value; an absent flag leaves the use case's default.
func intFlag(dst **int) func(string) error {
	return func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		*dst = &n
		return nil
	}
}

// onceFlag sets *dst to the flag's value and rejects a second occurrence: ./paddock agent-rollout passes the
// positional version as --version, so a repeated --version must not silently win (last-wins would roll out another
// release than the one named).
func onceFlag(dst *string) func(string) error {
	seen := false
	return func(v string) error {
		if seen {
			return errors.New("flag given twice")
		}
		seen, *dst = true, v
		return nil
	}
}

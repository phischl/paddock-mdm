package app

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/buildinfo"
	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// The statuses of an upgrade check item (plan M16 §6.2).
const (
	CheckPass = "PASS"
	CheckWarn = "WARN"
	CheckFail = "FAIL"
	CheckInfo = "INFO"
)

// The items of the upgrade check, in report order (plan M16 decision 4).
const (
	CheckMigrations = "migrations"
	CheckAgents     = "agents"
	CheckBackups    = "backups"
	CheckOpenBao    = "openbao"
	CheckPending    = "pending"
	CheckSessions   = "sessions"
)

// MaxAgentsOutside bounds the devices the report lists by name; the count covers all of them.
const MaxAgentsOutside = 100

// agentsInDetail bounds the host names in the agents item's detail line.
const agentsInDetail = 20

// ErrUnknownTargetVersion answers a target version that is not in the release sequence this binary carries.
var ErrUnknownTargetVersion = problem.InvalidRequest.WithDetail("target_version is no known Paddock release")

// UpgradeCheckItem is one line of the report.
type UpgradeCheckItem struct {
	Name   string
	Status string
	Detail string
}

// OutdatedAgent is an active device whose agent is outside the target's support window.
type OutdatedAgent struct {
	DeviceID     uuid.UUID
	Hostname     string
	AgentVersion string
}

// UpgradeCheckReport is the read-only report before an upgrade to TargetVersion.
type UpgradeCheckReport struct {
	GeneratedAt   time.Time
	TargetVersion string
	Window        []string
	Items         []UpgradeCheckItem
	AgentsOutside []OutdatedAgent
}

// Failed reports whether an item failed: the host command refuses the upgrade (exit code 1).
func (r UpgradeCheckReport) Failed() bool {
	return slices.ContainsFunc(r.Items, func(i UpgradeCheckItem) bool { return i.Status == CheckFail })
}

// UpgradeSealStatus reads OpenBao's seal status (bao.Client.SealStatus).
type UpgradeSealStatus interface {
	SealStatus(ctx context.Context) (bao.SealStatus, error)
}

// UpgradeSessionCounter counts an account's portal sessions (sessions.Store.CountAccount).
type UpgradeSessionCounter interface {
	CountAccount(ctx context.Context, accountID uuid.UUID) (int, error)
}

// UpgradeCheck reports whether an upgrade to a target release is safe (plan M16 decision 4, ADR 0047 decision 2). It
// changes nothing and is not audited. Every query reads tables the previous release has too and names its columns
// (queries/upgradecheck.sql), so the new binary can check the old database before it is migrated.
type UpgradeCheck struct {
	org      *db.OrgPool
	platform *db.PlatformPool
	seal     UpgradeSealStatus
	sessions UpgradeSessionCounter
	// binaryMigration is the newest migration this binary embeds.
	binaryMigration int64
	now             func() time.Time
}

// NewUpgradeCheck creates the use case; seal and sessions may be nil (their items report n/a).
func NewUpgradeCheck(org *db.OrgPool, platform *db.PlatformPool, seal UpgradeSealStatus, sessions UpgradeSessionCounter,
	binaryMigration int64) *UpgradeCheck {
	return &UpgradeCheck{org: org, platform: platform, seal: seal, sessions: sessions, binaryMigration: binaryMigration, now: time.Now}
}

// Report is the check for a platform administrator (GET /api/platform/v1/upgrade-check).
func (u *UpgradeCheck) Report(ctx context.Context, target string) (UpgradeCheckReport, error) {
	if _, err := RequirePlatform(ctx); err != nil {
		return UpgradeCheckReport{}, err
	}
	if target == "" {
		return UpgradeCheckReport{}, problem.InvalidRequest.WithDetail("target_version is required")
	}
	return u.report(ctx, target)
}

// ReportCLI is the check of paddock-server admin upgrade-check, with a system principal.
func (u *UpgradeCheck) ReportCLI(ctx context.Context, target string) (UpgradeCheckReport, error) {
	return u.report(systemPlatform(ctx), target)
}

func (u *UpgradeCheck) report(ctx context.Context, target string) (UpgradeCheckReport, error) {
	window := buildinfo.Window(target)
	if window == nil {
		return UpgradeCheckReport{}, ErrUnknownTargetVersion
	}
	out := UpgradeCheckReport{GeneratedAt: u.now().UTC(), TargetVersion: target, Window: window}
	migrations, err := u.migrations(ctx)
	if err != nil {
		return out, err
	}
	fleet, err := u.organizations(ctx, window)
	if err != nil {
		return out, err
	}
	platform, err := u.platformState(ctx)
	if err != nil {
		return out, err
	}
	out.AgentsOutside = fleet.listed
	out.Items = []UpgradeCheckItem{
		migrations,
		AgentsItem(fleet.active, fleet.outside, window, fleet.listed),
		platform.backups,
		u.openBao(ctx, platform.autoUnseal),
		PendingItem(platform.runningRollouts, fleet.haltedConfigRollouts, platform.restorePlans),
		u.signedIn(ctx, platform.admins),
	}
	return out, nil
}

// migrations compares the database's applied migration with the binary's. A database where the platform role cannot
// read goose_db_version predates migration 00102 and so cannot be ahead of a binary that carries it. The privilege is
// probed rather than the read attempted and its error caught: a failed read aborts the transaction, which InPlatform
// would then commit.
func (u *UpgradeCheck) migrations(ctx context.Context) (UpgradeCheckItem, error) {
	var version int64
	readable := false
	err := u.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if readable, err = q.UpgradeCheckSchemaVersionReadable(ctx); err != nil || !readable {
			return err
		}
		version, err = q.UpgradeCheckSchemaVersion(ctx)
		return err
	})
	if err != nil {
		return UpgradeCheckItem{}, fmt.Errorf("read the schema version: %w", err)
	}
	if !readable {
		return UpgradeCheckItem{Name: CheckMigrations, Status: CheckPass,
			Detail: fmt.Sprintf("the database predates migration 00102; the upgrade migrates it to %05d", u.binaryMigration)}, nil
	}
	return MigrationsItem(version, u.binaryMigration), nil
}

// MigrationsItem evaluates the database's applied migration against the binary's newest: FAIL when the database is
// ahead (a downgrade).
func MigrationsItem(database, binary int64) UpgradeCheckItem {
	item := UpgradeCheckItem{Name: CheckMigrations, Status: CheckPass}
	switch {
	case database > binary:
		item.Status = CheckFail
		item.Detail = fmt.Sprintf("the database is at migration %05d, ahead of this release's %05d: a downgrade is not supported", database, binary)
	case database == binary:
		item.Detail = fmt.Sprintf("the database is at migration %05d, as this release expects", database)
	default:
		item.Detail = fmt.Sprintf("the database is at migration %05d; the upgrade migrates it to %05d", database, binary)
	}
	return item
}

// AgentsOutsideLimit is the number of active devices outside the window above which the upgrade is refused: 1 % of
// the active devices or 5, whichever is larger (ADR 0047 decision 2).
func AgentsOutsideLimit(active int) float64 {
	return max(float64(active)/100, 5)
}

// AgentsItem evaluates the devices outside the window: FAIL above AgentsOutsideLimit, WARN below, PASS without any.
func AgentsItem(active, outside int, window []string, listed []OutdatedAgent) UpgradeCheckItem {
	item := UpgradeCheckItem{Name: CheckAgents, Status: CheckPass}
	span := strings.Join(window, ", ")
	if outside == 0 {
		item.Detail = fmt.Sprintf("every active device (%d) runs an agent inside the window (%s)", active, span)
		return item
	}
	item.Status = CheckWarn
	if float64(outside) > AgentsOutsideLimit(active) {
		item.Status = CheckFail
	}
	names := make([]string, 0, min(len(listed), agentsInDetail))
	for _, a := range listed[:min(len(listed), agentsInDetail)] {
		names = append(names, a.Hostname)
	}
	more := ""
	if outside > len(names) {
		more = ", …"
	}
	item.Detail = fmt.Sprintf("%d of %d active devices run an agent older than the window (%s): %s%s", outside, active, span,
		strings.Join(names, ", "), more)
	return item
}

// PendingItem evaluates the operations an upgrade interrupts: WARN when an agent rollout runs or a configuration
// rollout is halted (the operator decides, plan M16 §11). restorePlans is "" while the restore plans do not exist.
func PendingItem(runningRollouts []string, haltedConfigRollouts int64, restorePlans string) UpgradeCheckItem {
	item := UpgradeCheckItem{Name: CheckPending, Status: CheckPass}
	var parts []string
	if len(runningRollouts) > 0 {
		item.Status = CheckWarn
		parts = append(parts, "agent rollout running: "+strings.Join(runningRollouts, ", "))
	}
	if haltedConfigRollouts > 0 {
		item.Status = CheckWarn
		parts = append(parts, fmt.Sprintf("%d configuration rollouts halted", haltedConfigRollouts))
	}
	if len(parts) == 0 {
		parts = append(parts, "no agent rollout running, no configuration rollout halted")
	}
	parts = append(parts, restorePlans)
	item.Detail = strings.Join(parts, "; ")
	return item
}

// fleetState is what the organizations' data adds to the report.
type fleetState struct {
	active, outside      int
	listed               []OutdatedAgent
	haltedConfigRollouts int64
}

// organizations reads every organization's active devices and halted configuration rollouts with a system principal
// of that organization (the report covers the whole installation; it is read-only and names no secret).
func (u *UpgradeCheck) organizations(ctx context.Context, window []string) (fleetState, error) {
	var out fleetState
	var orgs []uuid.UUID
	err := u.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		orgs, err = q.UpgradeCheckOrganizationIDs(ctx)
		return err
	})
	if err != nil {
		return out, fmt.Errorf("list organizations: %w", err)
	}
	for _, org := range orgs {
		err := u.org.InOrg(system(ctx, org), func(ctx context.Context, q *pgstore.Queries) error {
			versions, err := q.UpgradeCheckAgentVersions(ctx)
			if err != nil {
				return fmt.Errorf("agent versions: %w", err)
			}
			var outside []string
			for _, v := range versions {
				out.active += int(v.Devices)
				if v.AgentVersion != nil && buildinfo.Outside(window, *v.AgentVersion) {
					out.outside += int(v.Devices)
					outside = append(outside, *v.AgentVersion)
				}
			}
			if room := MaxAgentsOutside - len(out.listed); len(outside) > 0 && room > 0 {
				rows, err := q.UpgradeCheckDevicesWithAgentVersions(ctx, pgstore.UpgradeCheckDevicesWithAgentVersionsParams{
					Versions: outside, MaxRows: int32(room), //nolint:gosec // room ≤ MaxAgentsOutside
				})
				if err != nil {
					return fmt.Errorf("devices outside the window: %w", err)
				}
				for _, r := range rows {
					out.listed = append(out.listed, OutdatedAgent{DeviceID: r.ID, Hostname: r.Hostname, AgentVersion: r.AgentVersion})
				}
			}
			halted, err := q.UpgradeCheckHaltedConfigRollouts(ctx)
			if err != nil {
				return fmt.Errorf("configuration rollouts: %w", err)
			}
			out.haltedConfigRollouts += halted
			return nil
		})
		if err != nil {
			return out, fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return out, nil
}

// platformState is what the platform tables add to the report.
type platformState struct {
	backups         UpgradeCheckItem
	restorePlans    string
	runningRollouts []string
	autoUnseal      autounseal.State
	admins          []uuid.UUID
}

// The backup tables of plan M15; the check probes them, as an older database does not have them.
const (
	backupKeyTable   = "backup_key"
	restorePlanTable = "backup_restore_plan"
)

func (u *UpgradeCheck) platformState(ctx context.Context) (platformState, error) {
	var out platformState
	err := u.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		backups, err := q.UpgradeCheckRelationExists(ctx, backupKeyTable)
		if err != nil {
			return fmt.Errorf("probe the backup tables: %w", err)
		}
		out.backups = UpgradeCheckItem{Name: CheckBackups, Status: CheckInfo,
			Detail: "n/a: the database has no backup configuration (plan M15)"}
		if backups {
			out.backups.Detail = "n/a: the backup state is not evaluated by this release"
		}
		plans, err := q.UpgradeCheckRelationExists(ctx, restorePlanTable)
		if err != nil {
			return fmt.Errorf("probe the restore plans: %w", err)
		}
		out.restorePlans = "restore plans: n/a (plan M15)"
		if plans {
			out.restorePlans = "restore plans: not evaluated by this release"
		}
		if out.runningRollouts, err = q.UpgradeCheckRunningAgentRollouts(ctx); err != nil {
			return fmt.Errorf("agent rollouts: %w", err)
		}
		state, err := q.UpgradeCheckAutoUnsealState(ctx)
		if err != nil {
			return fmt.Errorf("read automatic unseal: %w", err)
		}
		out.autoUnseal = autounseal.State(state)
		if out.admins, err = q.UpgradeCheckPlatformAdminIDs(ctx); err != nil {
			return fmt.Errorf("platform administrators: %w", err)
		}
		return nil
	})
	return out, err
}

// openBao reports the seal state and whether automatic unseal is on: after the upgrade a sealed OpenBao needs the
// unseal path the operator has (ADR 0035).
func (u *UpgradeCheck) openBao(ctx context.Context, state autounseal.State) UpgradeCheckItem {
	item := UpgradeCheckItem{Name: CheckOpenBao, Status: CheckInfo}
	unseal := "automatic unseal " + string(state)
	if u.seal == nil {
		item.Detail = "seal state n/a; " + unseal
		return item
	}
	st, err := u.seal.SealStatus(ctx)
	switch {
	case err != nil || !st.Reachable:
		item.Detail = "OpenBao unreachable; " + unseal
	case st.Sealed:
		item.Detail = "OpenBao sealed; " + unseal
	default:
		item.Detail = "OpenBao unsealed; " + unseal
	}
	return item
}

// signedIn counts the platform administrators with a portal session: the upgrade ends their sessions' requests.
func (u *UpgradeCheck) signedIn(ctx context.Context, admins []uuid.UUID) UpgradeCheckItem {
	item := UpgradeCheckItem{Name: CheckSessions, Status: CheckInfo}
	if u.sessions == nil {
		item.Detail = "n/a: the session store is not configured"
		return item
	}
	n := 0
	for _, id := range admins {
		open, err := u.sessions.CountAccount(ctx, id)
		if err != nil {
			item.Detail = "n/a: the session store is unavailable"
			return item
		}
		if open > 0 {
			n++
		}
	}
	item.Detail = fmt.Sprintf("%d platform administrators signed in", n)
	return item
}

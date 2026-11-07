package app

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Bounds of the access review (plan M12 decisions 25 and 26).
const (
	AccessReviewDefaultPeriod = 90 * 24 * time.Hour
	AccessReviewMaxPeriod     = 400 * 24 * time.Hour
	// AccessReviewRowCap bounds every list of the report; the totals count every item.
	AccessReviewRowCap = 1000
)

// Export formats of the access review.
const (
	AccessReviewJSON = "json"
	AccessReviewCSV  = "csv"
)

// Privileged actions of the access review (plan M12 decision 26). The view of an organization is a read recorded
// through ReadOnce; the platform's is always recorded, as platform reads are not under an organization's switch.
var (
	SpecAccessReviewViewed           = ActionSpec{Code: audit.CodeAccessReviewViewed, AllowedRoles: RolesAudit}
	SpecAccessReviewExported         = ActionSpec{Code: audit.CodeAccessReviewExported, AllowedRoles: RolesAudit}
	SpecPlatformAccessReviewViewed   = ActionSpec{Code: audit.CodePlatformAccessReviewViewed, AllowedRoles: RolesPlatform}
	SpecPlatformAccessReviewExported = ActionSpec{Code: audit.CodePlatformAccessReviewExported, AllowedRoles: RolesPlatform}
)

// Period is the range of an access review; the zero value of a bound selects its default (to: now, from: 90 days
// before to).
type Period struct{ From, To time.Time }

// resolve returns the effective period, truncated to the millisecond of audit timestamps, or the refusal of an empty,
// reversed or too long one.
func (p Period) resolve(now time.Time) (Period, error) {
	to := p.To
	if to.IsZero() {
		to = now
	}
	from := p.From
	if from.IsZero() {
		from = to.Add(-AccessReviewDefaultPeriod)
	}
	out := Period{From: audit.Timestamp(from), To: audit.Timestamp(to)}
	switch {
	case !out.From.Before(out.To):
		return out, problem.InvalidRequest.WithDetail("from must be before to")
	case out.To.Sub(out.From) > AccessReviewMaxPeriod:
		return out, problem.InvalidRequest.WithDetail("the period may span at most 400 days")
	}
	return out, nil
}

// Section is one list of the report: at most AccessReviewRowCap items and the number of all of them.
type Section[T any] struct {
	Total int
	Items []T
}

// RoleMembers are the members of one role as of the worker's last snapshot; SnapshotTakenAt is nil while the role had
// no first comparison.
type RoleMembers struct {
	Role            string
	SnapshotTakenAt *time.Time
	Members         Section[RoleMember]
}

// RoleMember is a member of a role group in the identity provider.
type RoleMember struct {
	Username    string
	AuthentikPK string
	FirstSeenAt time.Time
}

// RoleChange is a member that joined or left a role in the period.
type RoleChange struct {
	At       time.Time
	Code     string
	Username string
	Role     string
	Actor    string
}

// ReviewAccount is an administrator account of the organization.
type ReviewAccount struct {
	Username    string
	DisplayName string
	Role        string
	LastLoginAt *time.Time
	Disabled    bool
}

// ReviewToken is an API token that existed in the period; the secret is never part of it.
type ReviewToken struct {
	Name       string
	Role       string
	Prefix     string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	RevokedBy  *string
}

// Reveal is a reveal or download of a secret or personal data.
type Reveal struct {
	At             time.Time
	Code           string
	Actor          string
	DeviceHostname string
	// Params are the identifying parameters of the event (generation, volume), never a secret.
	Params map[string]any
}

// StepUpCounts are the successful actions of step-up sessions and the refusals for a missing step-up.
type StepUpCounts struct{ Succeeded, Failed int }

// SessionRevocation is the end of every portal session of an account by the server.
type SessionRevocation struct {
	At       time.Time
	Username string
	Reason   string
}

// DestructiveAction is a destructive or locking action.
type DestructiveAction struct {
	At     time.Time
	Code   string
	Actor  string
	Target string
}

// Report is the access review of an organization (plan M12 decision 25).
type Report struct {
	GeneratedAt        time.Time
	Period             Period
	Roles              []RoleMembers
	RoleChanges        Section[RoleChange]
	Accounts           Section[ReviewAccount]
	APITokens          Section[ReviewToken]
	TokenDenials       int
	Reveals            Section[Reveal]
	StepUp             StepUpCounts
	SessionsRevoked    Section[SessionRevocation]
	BreakGlassAccounts []string
	Destructive        Section[DestructiveAction]
}

// PlatformAdministrator is a platform administrator that signed in at least once.
type PlatformAdministrator struct {
	Username    string
	DisplayName string
	LastLoginAt *time.Time
}

// PlatformEvent is a privileged event of the platform pseudo-organization.
type PlatformEvent struct {
	At     time.Time
	Code   string
	Actor  string
	Target string
}

// CreatedOrganization is an organization created in the period.
type CreatedOrganization struct {
	Slug      string
	Name      string
	CreatedAt time.Time
}

// PlatformReport is the access review of the platform (plan M12 decision 25).
type PlatformReport struct {
	GeneratedAt          time.Time
	Period               Period
	Roles                []RoleMembers
	Administrators       Section[PlatformAdministrator]
	RoleChanges          Section[RoleChange]
	Events               Section[PlatformEvent]
	OrganizationsCreated Section[CreatedOrganization]
}

// ReportExport is an exported report: Filename for the Content-Disposition, CSV the rendered file (nil for JSON, which
// the transport renders from the same report as the view).
type ReportExport struct {
	Format   string
	Filename string
	CSV      []byte
	Org      *Report
	Platform *PlatformReport
}

// AccessReview assembles the access review report from the role snapshot, the accounts, the API tokens and the audit
// index (plan M12 decisions 24 to 26).
type AccessReview struct {
	runner *ActionRunner
	org    *db.OrgPool
	reader *db.AuditReader
	now    func() time.Time
}

// NewAccessReview creates the use cases.
func NewAccessReview(runner *ActionRunner, org *db.OrgPool, reader *db.AuditReader) *AccessReview {
	return &AccessReview{runner: runner, org: org, reader: reader, now: time.Now}
}

// Organization returns the report of the caller's organization (org_admin, org_auditor). The view is recorded as
// access_review.viewed once per actor and UTC day, only while audit_search_recorded is on; a role that may not read it
// is recorded as denied, and a refused period as failure while recording is on.
func (a *AccessReview) Organization(ctx context.Context, p Period) (Report, error) {
	now := a.now()
	enabled := func(ctx context.Context, qs *pgstore.Queries) (bool, error) {
		s, err := LoadPrivacySettings(ctx, qs)
		return s.AuditSearchRecorded, err
	}
	spec := SpecAccessReviewViewed
	if org, err := orgOf(ctx); err == nil {
		spec.Target = &audit.Target{Type: "organization", ID: org.String()}
	}
	_, err := a.runner.RecordReadOnce(ctx, spec, enabled, func(ctx context.Context, qs *pgstore.Queries, rec Recorder) (bool, error) {
		eff, err := p.resolve(now)
		if err != nil {
			return false, err
		}
		window := now.UTC().Truncate(24 * time.Hour)
		if fresh, err := claimReadWindow(ctx, qs, audit.CodeAccessReviewViewed, "", window); err != nil || !fresh {
			return false, err
		}
		rec.SetParam("from", eff.From.Format(time.RFC3339Nano))
		rec.SetParam("to", eff.To.Format(time.RFC3339Nano))
		rec.SetParam("window_start", window.Format(time.RFC3339))
		return true, nil
	})
	if err != nil {
		return Report{}, err
	}
	eff, err := p.resolve(now)
	if err != nil {
		return Report{}, err
	}
	var out Report
	err = a.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = a.buildOrganization(ctx, q, eff, now)
		return err
	})
	return out, err
}

// ExportOrganization returns the report of the caller's organization as format (AccessReviewJSON or
// AccessReviewCSV). Every export is recorded as access_review.exported, whatever the privacy settings: success,
// failure for a refused format or period, denied for a role that may not read the report.
func (a *AccessReview) ExportOrganization(ctx context.Context, p Period, format string) (ReportExport, error) {
	now := a.now()
	spec := SpecAccessReviewExported
	if org, err := orgOf(ctx); err == nil {
		spec.Target = &audit.Target{Type: "organization", ID: org.String()}
	}
	var out ReportExport
	err := a.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		eff, err := resolveExport(p, format, now)
		if err != nil {
			return err
		}
		rec.SetParam("from", eff.From.Format(time.RFC3339Nano))
		rec.SetParam("to", eff.To.Format(time.RFC3339Nano))
		rec.SetParam("format", format)
		report, err := a.buildOrganization(ctx, q, eff, now)
		if err != nil {
			return err
		}
		org, err := q.GetOrganization(ctx, mustOrg(ctx))
		if err != nil {
			return fmt.Errorf("organization of the access review export: %w", err)
		}
		out = ReportExport{Format: format, Filename: reviewFilename(org.Slug, eff, format), Org: &report}
		if format == AccessReviewCSV {
			out.CSV, err = report.csv()
		}
		return err
	})
	return out, err
}

func resolveExport(p Period, format string, now time.Time) (Period, error) {
	if format != AccessReviewJSON && format != AccessReviewCSV {
		return Period{}, problem.InvalidRequest.WithDetail("format must be json or csv")
	}
	return p.resolve(now)
}

// reviewFilename is the download name of an export. The slug is lowercase ASCII letters, digits and hyphens and the
// dates are digits, so the name needs no quoting or encoding in Content-Disposition.
func reviewFilename(slug string, p Period, format string) string {
	return fmt.Sprintf("paddock-access-review-%s-%s-%s.%s", slug, p.From.UTC().Format(time.DateOnly),
		p.To.UTC().Format(time.DateOnly), format)
}

// Platform returns the platform's report (platform administrators only). Every view is recorded as
// platform.access_review_viewed: platform reads are not under an organization's privacy switch.
func (a *AccessReview) Platform(ctx context.Context, p Period) (PlatformReport, error) {
	now := a.now()
	var out PlatformReport
	err := a.runner.RunTx(ctx, ScopePlatform, SpecPlatformAccessReviewViewed, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		eff, err := p.resolve(now)
		if err != nil {
			return err
		}
		rec.SetParam("from", eff.From.Format(time.RFC3339Nano))
		rec.SetParam("to", eff.To.Format(time.RFC3339Nano))
		out, err = a.buildPlatform(ctx, q, eff, now)
		return err
	})
	return out, err
}

// ExportPlatform is ExportOrganization for the platform report, recorded as platform.access_review_exported.
func (a *AccessReview) ExportPlatform(ctx context.Context, p Period, format string) (ReportExport, error) {
	now := a.now()
	var out ReportExport
	err := a.runner.RunTx(ctx, ScopePlatform, SpecPlatformAccessReviewExported, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		eff, err := resolveExport(p, format, now)
		if err != nil {
			return err
		}
		rec.SetParam("from", eff.From.Format(time.RFC3339Nano))
		rec.SetParam("to", eff.To.Format(time.RFC3339Nano))
		rec.SetParam("format", format)
		report, err := a.buildPlatform(ctx, q, eff, now)
		if err != nil {
			return err
		}
		out = ReportExport{Format: format, Filename: reviewFilename("platform", eff, format), Platform: &report}
		if format == AccessReviewCSV {
			out.CSV, err = report.csv()
		}
		return err
	})
	return out, err
}

// Event codes of the sections (plan M12 decision 25). device.diagnostics_downloaded is a plain string: the code
// belongs to the diagnostics bundle, which may land after the report.
var (
	roleChangeCodes = []string{string(audit.CodeAdminRoleGranted), string(audit.CodeAdminRoleRevoked)}
	revealCodes     = []string{
		string(audit.CodeLocalAdminRevealed), string(audit.CodeDiskRecoveryKeyRevealed),
		string(audit.CodeDiskHeaderDownloaded), "device.diagnostics_downloaded",
		string(audit.CodeNotificationPseudonymResolved),
	}
	sessionCodes     = []string{string(audit.CodeAdminSessionsRevoked)}
	destructiveCodes = []string{
		string(audit.CodeRevocationApproved),
		string(audit.CodeDeviceEscrowDestroyed), string(audit.CodeDeviceRetired), string(audit.CodeUserLocked),
	}
	tokenDenialCodes = []string{string(audit.CodeAPITokenUseDenied)}
	// revealParams are the parameters of a reveal that identify it; every other parameter is left out.
	revealParams = []string{"generation", "generations", "volume"}
)

// platformEventCodes are the privileged events of the platform pseudo-organization: every platform.* code but the
// vulnerability feed's, and the releases and rollouts of agents.
func platformEventCodes() []string {
	var out []string
	for _, d := range audit.Definitions() {
		c := string(d.Code)
		if d.Emitted && strings.HasPrefix(c, "platform.") && !strings.HasPrefix(c, "platform.osv_") {
			out = append(out, c)
		}
	}
	out = append(out, string(audit.CodeAgentReleasePublished), string(audit.CodeAgentReleaseImported),
		string(audit.CodeAgentRolloutStarted), string(audit.CodeAgentRolloutHalted), string(audit.CodeAgentRolloutCompleted),
		string(audit.CodeAdminSessionsRevoked))
	slices.Sort(out)
	return out
}

// reviewedEvents are the events of one section: at most AccessReviewRowCap of them and the number of all.
type reviewedEvents struct {
	events []auditstore.AuditEvent
	total  int
}

func listReviewEvents(ctx context.Context, q *auditstore.Queries, p Period, codes, outcomes []string, excludeBaseline bool) (reviewedEvents, error) {
	n, err := q.CountAuditEventsForReview(ctx, auditstore.CountAuditEventsForReviewParams{
		FromTime: p.From, ToTime: p.To, Codes: codes, Outcomes: outcomes, ExcludeBaseline: excludeBaseline,
	})
	if err != nil {
		return reviewedEvents{}, fmt.Errorf("count access review events: %w", err)
	}
	rows, err := q.ListAuditEventsForReview(ctx, auditstore.ListAuditEventsForReviewParams{
		FromTime: p.From, ToTime: p.To, Codes: codes, Outcomes: outcomes, ExcludeBaseline: excludeBaseline,
		MaxRows: AccessReviewRowCap,
	})
	if err != nil {
		return reviewedEvents{}, fmt.Errorf("list access review events: %w", err)
	}
	return reviewedEvents{events: rows, total: int(n)}, nil
}

// eventParts are the decoded actor, target and parameters of an index row.
type eventParts struct {
	actor  audit.Actor
	target audit.Target
	params map[string]any
}

func decodeEvent(e auditstore.AuditEvent) eventParts {
	var out eventParts
	_ = json.Unmarshal(e.Actor, &out.actor)
	_ = json.Unmarshal(e.Target, &out.target)
	_ = json.Unmarshal(e.Params, &out.params)
	return out
}

func (e eventParts) actorName() string { return cmp.Or(e.actor.Display, e.actor.Type) }

func (e eventParts) param(key string) string {
	s, _ := e.params[key].(string)
	return s
}

func sectionOf[T any](ev reviewedEvents, row func(auditstore.AuditEvent, eventParts) T) Section[T] {
	out := Section[T]{Total: ev.total, Items: make([]T, 0, len(ev.events))}
	for _, e := range ev.events {
		out.Items = append(out.Items, row(e, decodeEvent(e)))
	}
	return out
}

func roleChangeRow(e auditstore.AuditEvent, d eventParts) RoleChange {
	return RoleChange{At: e.OccurredAt, Code: e.Code, Username: d.param("username"), Role: d.param("role"), Actor: d.actorName()}
}

func snapshotMap[R any](rows []R, key func(R) (string, time.Time)) map[string]time.Time {
	out := make(map[string]time.Time, len(rows))
	for _, r := range rows {
		k, t := key(r)
		out[k] = t
	}
	return out
}

// membersByRole builds the role sections in the order of roles, capping the members of each role.
func membersByRole(roles []string, snapshots map[string]time.Time, members map[string][]RoleMember) []RoleMembers {
	out := make([]RoleMembers, 0, len(roles))
	for _, role := range roles {
		all := members[role]
		r := RoleMembers{Role: role, Members: Section[RoleMember]{Total: len(all), Items: slices.Clone(all[:min(len(all), AccessReviewRowCap)])}}
		if r.Members.Items == nil {
			r.Members.Items = []RoleMember{}
		}
		if t, ok := snapshots[role]; ok {
			r.SnapshotTakenAt = &t
		}
		out = append(out, r)
	}
	return out
}

func (a *AccessReview) buildOrganization(ctx context.Context, q *pgstore.Queries, p Period, now time.Time) (Report, error) {
	out := Report{GeneratedAt: audit.Timestamp(now), Period: p}
	rows, err := q.ListOrganizationRoleMembers(ctx)
	if err != nil {
		return out, fmt.Errorf("access review role members: %w", err)
	}
	members := map[string][]RoleMember{}
	for _, r := range rows {
		members[r.Role] = append(members[r.Role], RoleMember{Username: r.Username, AuthentikPK: r.AuthentikPk, FirstSeenAt: r.FirstSeenAt})
	}
	for _, m := range members {
		slices.SortFunc(m, func(x, y RoleMember) int {
			return cmp.Or(cmp.Compare(x.Username, y.Username), cmp.Compare(x.AuthentikPK, y.AuthentikPK))
		})
	}
	snaps, err := q.ListOrganizationRoleSnapshotTimes(ctx)
	if err != nil {
		return out, fmt.Errorf("access review role snapshots: %w", err)
	}
	out.Roles = membersByRole([]string{string(principal.RoleOrgAdmin), string(principal.RoleOrgOperator), string(principal.RoleOrgAuditor)},
		snapshotMap(snaps, func(r pgstore.ListOrganizationRoleSnapshotTimesRow) (string, time.Time) { return r.Role, r.TakenAt }), members)

	if err := a.accountsAndTokens(ctx, q, p, &out); err != nil {
		return out, err
	}
	login, err := q.GetLoginSettings(ctx)
	switch {
	case db.IsNoRows(err):
	case err != nil:
		return out, fmt.Errorf("access review login settings: %w", err)
	default:
		out.BreakGlassAccounts = slices.Clone(login.BreakGlassAccounts)
	}
	if out.BreakGlassAccounts == nil {
		out.BreakGlassAccounts = []string{}
	}
	slices.Sort(out.BreakGlassAccounts)

	err = a.reader.InOrg(ctx, func(ctx context.Context, qa *auditstore.Queries) error {
		return a.organizationEvents(ctx, qa, p, &out)
	})
	return out, err
}

func (a *AccessReview) accountsAndTokens(ctx context.Context, q *pgstore.Queries, p Period, out *Report) error {
	accounts, err := q.ListAccessReviewAccounts(ctx, AccessReviewRowCap)
	if err != nil {
		return fmt.Errorf("access review accounts: %w", err)
	}
	n, err := q.CountAccessReviewAccounts(ctx)
	if err != nil {
		return fmt.Errorf("count access review accounts: %w", err)
	}
	out.Accounts = Section[ReviewAccount]{Total: int(n), Items: make([]ReviewAccount, 0, len(accounts))}
	for _, r := range accounts {
		out.Accounts.Items = append(out.Accounts.Items, ReviewAccount{Username: r.Username, DisplayName: r.DisplayName,
			Role: r.Role, LastLoginAt: r.LastLoginAt, Disabled: r.Disabled})
	}
	tokens, err := q.ListAccessReviewTokens(ctx, pgstore.ListAccessReviewTokensParams{ToTime: p.To, FromTime: p.From, MaxRows: AccessReviewRowCap})
	if err != nil {
		return fmt.Errorf("access review tokens: %w", err)
	}
	n, err = q.CountAccessReviewTokens(ctx, pgstore.CountAccessReviewTokensParams{ToTime: p.To, FromTime: p.From})
	if err != nil {
		return fmt.Errorf("count access review tokens: %w", err)
	}
	out.APITokens = Section[ReviewToken]{Total: int(n), Items: make([]ReviewToken, 0, len(tokens))}
	for _, r := range tokens {
		out.APITokens.Items = append(out.APITokens.Items, ReviewToken{Name: r.Name, Role: r.Role, Prefix: r.Prefix,
			CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt,
			RevokedAt: r.RevokedAt, RevokedBy: r.RevokedBy})
	}
	return nil
}

var (
	successOnly = []string{string(audit.OutcomeSuccess)}
	deniedOnly  = []string{string(audit.OutcomeDenied)}
)

func (a *AccessReview) organizationEvents(ctx context.Context, qa *auditstore.Queries, p Period, out *Report) error {
	changes, err := listReviewEvents(ctx, qa, p, roleChangeCodes, successOnly, true)
	if err != nil {
		return err
	}
	out.RoleChanges = sectionOf(changes, roleChangeRow)

	reveals, err := listReviewEvents(ctx, qa, p, revealCodes, successOnly, false)
	if err != nil {
		return err
	}
	out.Reveals = sectionOf(reveals, func(e auditstore.AuditEvent, d eventParts) Reveal {
		r := Reveal{At: e.OccurredAt, Code: e.Code, Actor: d.actorName(), DeviceHostname: cmp.Or(d.param("hostname"), d.target.Display),
			Params: map[string]any{}}
		for _, k := range revealParams {
			if v, ok := d.params[k]; ok {
				r.Params[k] = v
			}
		}
		return r
	})

	sessions, err := listReviewEvents(ctx, qa, p, sessionCodes, successOnly, false)
	if err != nil {
		return err
	}
	out.SessionsRevoked = sectionOf(sessions, func(e auditstore.AuditEvent, d eventParts) SessionRevocation {
		return SessionRevocation{At: e.OccurredAt, Username: d.target.Display, Reason: d.param("reason")}
	})

	destructive, err := listReviewEvents(ctx, qa, p, destructiveCodes, successOnly, false)
	if err != nil {
		return err
	}
	out.Destructive = sectionOf(destructive, func(e auditstore.AuditEvent, d eventParts) DestructiveAction {
		return DestructiveAction{At: e.OccurredAt, Code: e.Code, Actor: d.actorName(),
			Target: cmp.Or(d.param("hostname"), d.target.Display, d.param("username"))}
	})

	denials, err := qa.CountAuditEventsForReview(ctx, auditstore.CountAuditEventsForReviewParams{
		FromTime: p.From, ToTime: p.To, Codes: tokenDenialCodes, Outcomes: deniedOnly,
	})
	if err != nil {
		return fmt.Errorf("count access review token denials: %w", err)
	}
	out.TokenDenials = int(denials)

	steps, err := qa.CountStepUpEventsForReview(ctx, auditstore.CountStepUpEventsForReviewParams{FromTime: p.From, ToTime: p.To})
	if err != nil {
		return fmt.Errorf("count access review step-ups: %w", err)
	}
	out.StepUp = StepUpCounts{Succeeded: int(steps.Succeeded), Failed: int(steps.Refused)}
	return nil
}

func (a *AccessReview) buildPlatform(ctx context.Context, q *pgstore.Queries, p Period, now time.Time) (PlatformReport, error) {
	out := PlatformReport{GeneratedAt: audit.Timestamp(now), Period: p}
	rows, err := q.ListPlatformRoleMembers(ctx)
	if err != nil {
		return out, fmt.Errorf("access review platform members: %w", err)
	}
	members := map[string][]RoleMember{}
	for _, r := range rows {
		members[r.Role] = append(members[r.Role], RoleMember{Username: r.Username, AuthentikPK: r.AuthentikPk, FirstSeenAt: r.FirstSeenAt})
	}
	for _, m := range members {
		slices.SortFunc(m, func(x, y RoleMember) int {
			return cmp.Or(cmp.Compare(x.Username, y.Username), cmp.Compare(x.AuthentikPK, y.AuthentikPK))
		})
	}
	snaps, err := q.ListPlatformRoleSnapshotTimes(ctx)
	if err != nil {
		return out, fmt.Errorf("access review platform snapshots: %w", err)
	}
	out.Roles = membersByRole([]string{"platform_admin", "authentik_superuser"},
		snapshotMap(snaps, func(r pgstore.ListPlatformRoleSnapshotTimesRow) (string, time.Time) { return r.Role, r.TakenAt }), members)

	admins, err := q.ListAccessReviewPlatformAdmins(ctx, AccessReviewRowCap)
	if err != nil {
		return out, fmt.Errorf("access review platform administrators: %w", err)
	}
	n, err := q.CountAccessReviewPlatformAdmins(ctx)
	if err != nil {
		return out, fmt.Errorf("count access review platform administrators: %w", err)
	}
	out.Administrators = Section[PlatformAdministrator]{Total: int(n), Items: make([]PlatformAdministrator, 0, len(admins))}
	for _, r := range admins {
		out.Administrators.Items = append(out.Administrators.Items, PlatformAdministrator{Username: r.Username, DisplayName: r.DisplayName, LastLoginAt: r.LastLoginAt})
	}

	orgs, err := q.ListAccessReviewOrganizations(ctx, pgstore.ListAccessReviewOrganizationsParams{FromTime: p.From, ToTime: p.To, MaxRows: AccessReviewRowCap})
	if err != nil {
		return out, fmt.Errorf("access review organizations: %w", err)
	}
	n, err = q.CountAccessReviewOrganizations(ctx, pgstore.CountAccessReviewOrganizationsParams{FromTime: p.From, ToTime: p.To})
	if err != nil {
		return out, fmt.Errorf("count access review organizations: %w", err)
	}
	out.OrganizationsCreated = Section[CreatedOrganization]{Total: int(n), Items: make([]CreatedOrganization, 0, len(orgs))}
	for _, r := range orgs {
		out.OrganizationsCreated.Items = append(out.OrganizationsCreated.Items, CreatedOrganization{Slug: r.Slug, Name: r.Name, CreatedAt: r.CreatedAt})
	}

	err = a.reader.InPlatformScope(ctx, func(ctx context.Context, qa *auditstore.Queries) error {
		changes, err := listReviewEvents(ctx, qa, p, roleChangeCodes, successOnly, true)
		if err != nil {
			return err
		}
		out.RoleChanges = sectionOf(changes, roleChangeRow)
		events, err := listReviewEvents(ctx, qa, p, platformEventCodes(), successOnly, false)
		if err != nil {
			return err
		}
		out.Events = sectionOf(events, func(e auditstore.AuditEvent, d eventParts) PlatformEvent {
			return PlatformEvent{At: e.OccurredAt, Code: e.Code, Actor: d.actorName(), Target: d.target.Display}
		})
		return nil
	})
	return out, err
}

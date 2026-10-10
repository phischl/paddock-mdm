package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/ipallowlist"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Version is the change counter of the IP allow list shared by the api replicas (plan M7a decision 19).
type Version interface {
	Bump(ctx context.Context) error
	Get(ctx context.Context) (int64, error)
}

// IPAllowlist are the platform use cases of the IP allow list of the administrative surfaces (plan M7a decision
// 12) and the host-side break-glass operations (decision 21).
type IPAllowlist struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	version  Version // nil: no replicas to notify
	// afterChange reloads the enforcer of this process synchronously after a commit (decision 18); nil without one.
	afterChange func(context.Context)
}

// NewIPAllowlist creates the use cases.
func NewIPAllowlist(runner *ActionRunner, platform *db.PlatformPool, version Version) *IPAllowlist {
	return &IPAllowlist{runner: runner, platform: platform, version: version}
}

// AfterChange registers the enforcer's synchronous reload, run after every committed change before the handler
// answers.
func (a *IPAllowlist) AfterChange(fn func(context.Context)) { a.afterChange = fn }

// Privileged actions of the IP allow list.
var (
	SpecIPAllowlistChange  = ActionSpec{Code: audit.CodePlatformIPAllowlistChanged, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecIPAllowlistDisable = ActionSpec{Code: audit.CodePlatformIPAllowlistDisabled, Actor: &adminActor}
)

// IPAllowlistItem is an entry with whether it covers the caller's own address.
type IPAllowlistItem struct {
	ipallowlist.Entry
	CoversCaller bool
}

// ipAllowlistTarget is the audit target type of an entry.
const ipAllowlistTarget = "ip_allowlist_entry"

// ipAllowlistCIDRKey is the unique constraint of ip_allowlist_entry.cidr.
const ipAllowlistCIDRKey = "ip_allowlist_entry_cidr_key"

func toIPAllowlistEntry(r pgstore.IpAllowlistEntry) ipallowlist.Entry {
	return ipallowlist.Entry{ID: r.ID, CIDR: r.Cidr, Label: r.Label, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

// callerAddr is the principal's address; invalid when none was resolved.
func callerAddr(p principal.Principal) netip.Addr {
	a, err := netip.ParseAddr(p.IP)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func covers(p netip.Prefix, caller netip.Addr) bool { return caller.IsValid() && p.Contains(caller) }

// List returns one page of entries.
func (a *IPAllowlist) List(ctx context.Context, page ListPage) (Listed[IPAllowlistItem], error) {
	var out Listed[IPAllowlistItem]
	p, err := RequirePlatform(ctx)
	if err != nil {
		return out, err
	}
	caller := callerAddr(p)
	err = a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountIPAllowlistEntries(ctx, pgstore.CountIPAllowlistEntriesParams{QPattern: page.QPattern, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count ip allow list entries: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListIPAllowlistEntries(ctx, pgstore.ListIPAllowlistEntriesParams{
			QPattern: page.QPattern, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list ip allow list entries: %w", err)
		}
		out.Items = make([]IPAllowlistItem, len(rows))
		for i, r := range rows {
			out.Items[i] = IPAllowlistItem{Entry: toIPAllowlistEntry(r), CoversCaller: covers(r.Cidr, caller)}
		}
		return nil
	})
	return out, err
}

// Get returns one entry; 404 not_found when it does not exist.
func (a *IPAllowlist) Get(ctx context.Context, id uuid.UUID) (IPAllowlistItem, error) {
	var out IPAllowlistItem
	p, err := RequirePlatform(ctx)
	if err != nil {
		return out, err
	}
	err = a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		r, err := q.GetIPAllowlistEntry(ctx, id)
		if db.IsNoRows(err) {
			return problem.NotFound
		}
		if err != nil {
			return fmt.Errorf("get ip allow list entry: %w", err)
		}
		out = IPAllowlistItem{Entry: toIPAllowlistEntry(r), CoversCaller: covers(r.Cidr, callerAddr(p))}
		return nil
	})
	return out, err
}

// lockedPrefixes locks the table for the consequence check and returns every prefix (plan M7a decision 12).
func lockedPrefixes(ctx context.Context, q *pgstore.Queries) ([]netip.Prefix, error) {
	if err := q.LockIPAllowlistEntries(ctx); err != nil {
		return nil, fmt.Errorf("lock ip allow list: %w", err)
	}
	rows, err := q.AllIPAllowlistEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("read ip allow list: %w", err)
	}
	out := make([]netip.Prefix, len(rows))
	for i, r := range rows {
		out[i] = r.Cidr
	}
	return out, nil
}

// checkConsequence records the consequence of the change and refuses it unless confirmed. A change that leaves the
// set of ranges as it is (a label change) has no consequence.
func checkConsequence(rec Recorder, before, after []netip.Prefix, caller netip.Addr, confirm ipallowlist.Consequence) error {
	switch confirm {
	case ipallowlist.Unconfirmed, ipallowlist.ConsequenceLockout, ipallowlist.ConsequenceDisable:
	default:
		return problem.InvalidRequest.WithDetail("confirm must be lockout or disable")
	}
	c := ipallowlist.ConsequenceNone
	if !slices.Equal(before, after) {
		c = ipallowlist.ConsequenceOf(before, after, caller)
	}
	rec.SetParam("consequence", string(c))
	switch {
	case c == ipallowlist.ConsequenceNone || confirm == c:
		return nil
	case c == ipallowlist.ConsequenceDisable:
		return problem.DisableConfirmationRequired.WithDetail("removing the last entry switches the IP allow list off; repeat with confirm=disable")
	default:
		return problem.LockoutConfirmationRequired.WithDetail("the change removes your own address " + caller.String() + " from the IP allow list; repeat with confirm=lockout")
	}
}

func parseEntryInput(cidr, label string) (netip.Prefix, string, error) {
	prefix, err := ipallowlist.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return netip.Prefix{}, "", problem.InvalidRequest.WithDetail("cidr: " + err.Error())
	}
	label = strings.TrimSpace(label)
	if err := ipallowlist.ValidateLabel(label); err != nil {
		return netip.Prefix{}, "", problem.InvalidRequest.WithDetail("label: " + err.Error())
	}
	return prefix, label, nil
}

// Create adds an entry (audited: platform.ip_allowlist_changed, action added). confirm acknowledges the computed
// consequence; without it a lockout is refused with 409 lockout_confirmation_required.
func (a *IPAllowlist) Create(ctx context.Context, cidr, label string, confirm ipallowlist.Consequence) (IPAllowlistItem, error) {
	var out IPAllowlistItem
	err := a.runner.RunTx(ctx, ScopePlatform, SpecIPAllowlistChange, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		item, err := a.add(ctx, q, rec, p, cidr, label, confirm, callerAddr(p))
		out = item
		return err
	})
	if err != nil {
		return out, err
	}
	a.changed(ctx)
	return out, nil
}

// add inserts an entry inside a change action; checkConsequence runs when caller is valid or the list is checked
// for the portal (Create); the break-glass add passes an invalid caller and confirm none and skips the check.
func (a *IPAllowlist) add(ctx context.Context, q *pgstore.Queries, rec Recorder, p principal.Principal, cidr, label string,
	confirm ipallowlist.Consequence, caller netip.Addr) (IPAllowlistItem, error) {
	var out IPAllowlistItem
	prefix, label, err := parseEntryInput(cidr, label)
	if err != nil {
		return out, err
	}
	id := uuid.Must(uuid.NewV7())
	rec.SetTarget(audit.Target{Type: ipAllowlistTarget, ID: id.String(), Display: prefix.String()})
	rec.SetParam("action", "added")
	rec.SetParam("cidr", prefix.String())
	rec.SetParam("label", label)
	before, err := lockedPrefixes(ctx, q)
	if err != nil {
		return out, err
	}
	after := append(slices.Clone(before), prefix)
	if p.Kind == principal.KindSystem {
		rec.SetParam("consequence", string(ipallowlist.ConsequenceNone))
	} else if err := checkConsequence(rec, before, after, caller, confirm); err != nil {
		return out, err
	}
	row, err := q.InsertIPAllowlistEntry(ctx, pgstore.InsertIPAllowlistEntryParams{ID: id, Cidr: prefix, Label: label, CreatedBy: p.Display})
	if db.IsUniqueViolation(err, ipAllowlistCIDRKey) {
		return out, problem.AlreadyExists.WithDetail("an entry with this CIDR exists")
	}
	if err != nil {
		return out, fmt.Errorf("insert ip allow list entry: %w", err)
	}
	rec.SetParam("entries", len(after))
	return IPAllowlistItem{Entry: toIPAllowlistEntry(row), CoversCaller: covers(prefix, caller)}, nil
}

// Update changes the CIDR and/or the label of an entry (audited: action updated with the previous values).
func (a *IPAllowlist) Update(ctx context.Context, id uuid.UUID, cidr, label *string, confirm ipallowlist.Consequence) (IPAllowlistItem, error) {
	var out IPAllowlistItem
	err := a.runner.RunTx(ctx, ScopePlatform, SpecIPAllowlistChange, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		caller := callerAddr(p)
		if cidr == nil && label == nil {
			return problem.InvalidRequest.WithDetail("cidr or label is required")
		}
		before, err := lockedPrefixes(ctx, q)
		if err != nil {
			return err
		}
		row, err := q.GetIPAllowlistEntry(ctx, id)
		if db.IsNoRows(err) {
			return problem.NotFound
		}
		if err != nil {
			return fmt.Errorf("get ip allow list entry: %w", err)
		}
		rec.SetTarget(audit.Target{Type: ipAllowlistTarget, ID: id.String(), Display: row.Cidr.String()})
		rec.SetParam("action", "updated")
		rec.SetParam("previous_cidr", row.Cidr.String())
		rec.SetParam("previous_label", row.Label)
		newCIDR, newLabel := row.Cidr.String(), row.Label
		if cidr != nil {
			newCIDR = *cidr
		}
		if label != nil {
			newLabel = *label
		}
		prefix, newLabel, err := parseEntryInput(newCIDR, newLabel)
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: ipAllowlistTarget, ID: id.String(), Display: prefix.String()})
		rec.SetParam("cidr", prefix.String())
		rec.SetParam("label", newLabel)
		after := slices.Clone(before)
		if i := slices.Index(after, row.Cidr); i >= 0 {
			after[i] = prefix
		}
		if err := checkConsequence(rec, before, after, caller, confirm); err != nil {
			return err
		}
		updated, err := q.UpdateIPAllowlistEntry(ctx, pgstore.UpdateIPAllowlistEntryParams{ID: id, Cidr: prefix, Label: newLabel})
		if db.IsUniqueViolation(err, ipAllowlistCIDRKey) {
			return problem.AlreadyExists.WithDetail("an entry with this CIDR exists")
		}
		if err != nil {
			return fmt.Errorf("update ip allow list entry: %w", err)
		}
		rec.SetParam("entries", len(after))
		out = IPAllowlistItem{Entry: toIPAllowlistEntry(updated), CoversCaller: covers(prefix, caller)}
		return nil
	})
	if err != nil {
		return out, err
	}
	a.changed(ctx)
	return out, nil
}

// Delete removes an entry (audited: action removed). Removing the last entry needs confirm=disable, removing the
// caller's own coverage confirm=lockout.
func (a *IPAllowlist) Delete(ctx context.Context, id uuid.UUID, confirm ipallowlist.Consequence) error {
	err := a.runner.RunTx(ctx, ScopePlatform, SpecIPAllowlistChange, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		before, err := lockedPrefixes(ctx, q)
		if err != nil {
			return err
		}
		row, err := q.GetIPAllowlistEntry(ctx, id)
		if db.IsNoRows(err) {
			return problem.NotFound
		}
		if err != nil {
			return fmt.Errorf("get ip allow list entry: %w", err)
		}
		rec.SetTarget(audit.Target{Type: ipAllowlistTarget, ID: id.String(), Display: row.Cidr.String()})
		rec.SetParam("action", "removed")
		rec.SetParam("cidr", row.Cidr.String())
		rec.SetParam("label", row.Label)
		after := slices.DeleteFunc(slices.Clone(before), func(p netip.Prefix) bool { return p == row.Cidr })
		if err := checkConsequence(rec, before, after, callerAddr(p), confirm); err != nil {
			return err
		}
		if _, err := q.DeleteIPAllowlistEntry(ctx, id); err != nil {
			return fmt.Errorf("delete ip allow list entry: %w", err)
		}
		rec.SetParam("entries", len(after))
		return nil
	})
	if err != nil {
		return err
	}
	a.changed(ctx)
	return nil
}

// systemPlatform is the principal of the enforcer's reload and the break-glass operations.
func systemPlatform(ctx context.Context) context.Context {
	return principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: adminActor.Display})
}

// Load reads every prefix with a system principal; used by the enforcer (plan M7a decision 18) and the CLI.
func (a *IPAllowlist) Load(ctx context.Context) ([]netip.Prefix, error) {
	var out []netip.Prefix
	err := a.platform.InPlatform(systemPlatform(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.AllIPAllowlistEntries(ctx)
		if err != nil {
			return fmt.Errorf("read ip allow list: %w", err)
		}
		out = make([]netip.Prefix, len(rows))
		for i, r := range rows {
			out[i] = r.Cidr
		}
		return nil
	})
	return out, err
}

// Entries returns every entry ordered by CIDR with a system principal (paddock-server admin allowlist show).
func (a *IPAllowlist) Entries(ctx context.Context) ([]ipallowlist.Entry, error) {
	var out []ipallowlist.Entry
	err := a.platform.InPlatform(systemPlatform(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.AllIPAllowlistEntries(ctx)
		if err != nil {
			return fmt.Errorf("read ip allow list: %w", err)
		}
		out = make([]ipallowlist.Entry, len(rows))
		for i, r := range rows {
			out[i] = toIPAllowlistEntry(r)
		}
		return nil
	})
	return out, err
}

// DisableAll removes every entry on the host (audited: platform.ip_allowlist_disabled, method cli); with an empty
// list nothing is recorded and removed is empty.
func (a *IPAllowlist) DisableAll(ctx context.Context) (removed []netip.Prefix, err error) {
	current, err := a.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(current) == 0 {
		return nil, nil
	}
	spec := SpecIPAllowlistDisable
	spec.Params = map[string]any{"method": "cli"}
	err = a.runner.RunTx(systemPlatform(ctx), ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := q.LockIPAllowlistEntries(ctx); err != nil {
			return fmt.Errorf("lock ip allow list: %w", err)
		}
		removed, err = q.DeleteAllIPAllowlistEntries(ctx)
		if err != nil {
			return fmt.Errorf("delete ip allow list: %w", err)
		}
		cidrs := make([]string, len(removed))
		for i, p := range removed {
			cidrs[i] = p.String()
		}
		rec.SetParam("entries_removed", len(removed))
		rec.SetParam("removed", cidrs)
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.changed(ctx)
	return removed, nil
}

// AddBreakGlass adds an entry on the host without a consequence check or step-up (audited: action added, actor
// system, created_by "paddock-server admin").
func (a *IPAllowlist) AddBreakGlass(ctx context.Context, cidr, label string) (IPAllowlistItem, error) {
	var out IPAllowlistItem
	spec := SpecIPAllowlistChange
	spec.Actor = &adminActor
	err := a.runner.RunTx(systemPlatform(ctx), ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		item, err := a.add(ctx, q, rec, p, cidr, label, ipallowlist.Unconfirmed, netip.Addr{})
		out = item
		return err
	})
	if err != nil {
		return out, err
	}
	a.changed(ctx)
	return out, nil
}

// RecordBypass records that the api started with PADDOCK_IP_ALLOWLIST_BYPASS (plan M7a decision 22).
func (a *IPAllowlist) RecordBypass(ctx context.Context) error {
	spec := SpecIPAllowlistDisable
	spec.Params = map[string]any{"method": "env", "entries_removed": 0}
	return a.runner.RunTx(systemPlatform(ctx), ScopePlatform, spec, func(context.Context, *pgstore.Queries, Recorder) error { return nil })
}

// changed propagates a committed change: the version for the other replicas (errors are logged; they reload within
// 60 s anyway) and the enforcer of this process.
func (a *IPAllowlist) changed(ctx context.Context) {
	ctx = context.WithoutCancel(ctx)
	if a.version != nil {
		if err := a.version.Bump(ctx); err != nil {
			slog.WarnContext(ctx, "ip allow list version not bumped; replicas reload within 60 s", "error", err)
		}
	}
	if a.afterChange != nil {
		a.afterChange(ctx)
	}
}

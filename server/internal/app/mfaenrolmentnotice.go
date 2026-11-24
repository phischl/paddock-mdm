package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// MFAEnrolmentNoticePeriod is how long after the seed the portal announces the second-factor change to every
// administrator (ADR 0053 decision 6).
const MFAEnrolmentNoticePeriod = 30 * 24 * time.Hour

// mfaNoticePendingTTL bounds how stale the pending count may be: GET /api/v1/me runs on every portal page load, and
// the count needs listings of the identity provider.
const mfaNoticePendingTTL = time.Minute

// mfaNoticeFailureTTL is how long a failed count hides the notice before the next attempt, so that an identity
// provider outage does not cost a listing on every page load of every administrator.
const mfaNoticeFailureTTL = 30 * time.Second

// MFAEnrolmentNotice is the announcement of ADR 0053 decision 6: until when it is shown and how many administrators
// are still marked to set up a passkey at their next sign-in.
type MFAEnrolmentNotice struct {
	Until   time.Time
	Pending int
}

// RoleGroupNamer lists the groups whose direct members hold a portal role (authentik.Client).
type RoleGroupNamer interface {
	PortalRoleGroupNames(ctx context.Context) ([]string, error)
}

// MFAEnrolmentNotices answers the announcement for GET /api/v1/me. The seed time never changes once set and is kept;
// the pending counts are kept for mfaNoticePendingTTL per scope.
type MFAEnrolmentNotices struct {
	platform *db.PlatformPool
	dir      ports.UserDirectory
	groups   RoleGroupNamer
	now      func() time.Time

	mu       sync.Mutex
	seededAt time.Time
	pending  map[string]pendingCount
}

type pendingCount struct {
	n  int
	at time.Time
	// failed marks a count that could not be read; it is kept for mfaNoticeFailureTTL.
	failed bool
}

// NewMFAEnrolmentNotices creates the use case.
func NewMFAEnrolmentNotices(platform *db.PlatformPool, dir ports.UserDirectory, groups RoleGroupNamer) *MFAEnrolmentNotices {
	return &MFAEnrolmentNotices{platform: platform, dir: dir, groups: groups, now: time.Now, pending: map[string]pendingCount{}}
}

// Notice returns the announcement for an administrator of the organization slug, or for a platform administrator
// when slug is empty: the count covers the organization's role groups, or every portal role group. It is nil before
// the seed completed and once the notice period has ended. A count that failed returns the error once and then nil
// without a new attempt for mfaNoticeFailureTTL.
func (n *MFAEnrolmentNotices) Notice(ctx context.Context, slug string) (*MFAEnrolmentNotice, error) {
	seeded, err := n.seeded(ctx)
	if err != nil || seeded.IsZero() {
		return nil, err
	}
	until := seeded.Add(MFAEnrolmentNoticePeriod).UTC()
	now := n.now()
	if !now.Before(until) {
		return nil, nil
	}
	n.mu.Lock()
	c, ok := n.pending[slug]
	n.mu.Unlock()
	switch {
	case ok && c.failed && now.Sub(c.at) < mfaNoticeFailureTTL:
		return nil, nil
	case !ok || c.failed || now.Sub(c.at) >= mfaNoticePendingTTL:
		count, err := n.count(ctx, slug)
		c = pendingCount{n: count, at: now, failed: err != nil}
		n.mu.Lock()
		n.pending[slug] = c
		n.mu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("mfa enrolment notice: %w", err)
		}
	}
	return &MFAEnrolmentNotice{Until: until, Pending: c.n}, nil
}

// seeded reads the completed seed's time once; zero while the seed has not completed. The marker is platform data
// without an organization, read as the system for every administrator.
func (n *MFAEnrolmentNotices) seeded(ctx context.Context) (time.Time, error) {
	n.mu.Lock()
	known := n.seededAt
	n.mu.Unlock()
	if !known.IsZero() {
		return known, nil
	}
	var at *time.Time
	err := n.platform.InPlatform(systemPlatform(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		at, err = q.GetMfaEnrolmentSeededAt(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("mfa enrolment notice: %w", err)
	}
	if at == nil {
		return time.Time{}, nil
	}
	n.mu.Lock()
	n.seededAt = *at
	n.mu.Unlock()
	return *at, nil
}

// count counts the distinct direct members of the scope's role groups that are still marked
// (ports.AttrMFAEnrolAtLogin); a role group that does not exist counts nobody.
func (n *MFAEnrolmentNotices) count(ctx context.Context, slug string) (int, error) {
	var names []string
	if slug != "" {
		names = []string{organization.RoleGroup(slug, organization.GroupAdmins),
			organization.RoleGroup(slug, organization.GroupOperators), organization.RoleGroup(slug, organization.GroupAuditors)}
	} else {
		var err error
		if names, err = n.groups.PortalRoleGroupNames(ctx); err != nil {
			return 0, err
		}
	}
	if len(names) == 0 {
		return 0, nil
	}
	members, err := n.dir.RoleGroupsMembers(ctx, names)
	if err != nil {
		return 0, err
	}
	marked := map[string]bool{}
	for _, users := range members {
		for _, u := range users {
			if u.MFAEnrolAtLogin {
				marked[u.PK] = true
			}
		}
	}
	return len(marked), nil
}

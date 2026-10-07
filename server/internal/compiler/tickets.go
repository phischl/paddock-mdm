package compiler

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/timeticket"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/revocation"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// TimeTicketKey is the Transit key that signs time tickets (plan M4c decision 14).
const TimeTicketKey = "time-ticket"

func timeTicketKeyID(version int) string { return TimeTicketKey + ":v" + strconv.Itoa(version) }

// timeTicketKeys returns every version of the time-ticket public key, oldest first, for the keys object of v2
// bundles.
func timeTicketKeys(ctx context.Context, r KeyReader) ([]bundle.SigningKey, error) {
	keys, err := r.PublicKeys(ctx, TimeTicketKey)
	if err != nil {
		return nil, fmt.Errorf("time-ticket public keys: %w", err)
	}
	versions := make([]int, 0, len(keys))
	for v := range keys {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	out := make([]bundle.SigningKey, len(versions))
	for i, v := range versions {
		out[i] = bundle.SigningKey{KeyID: timeTicketKeyID(v), PublicKey: base64.StdEncoding.EncodeToString(keys[v])}
	}
	return out, nil
}

// loadDMS returns the dead man's switch of the context's organization for v2 bundles (plan M4c decision 15); without
// settings it is off.
func loadDMS(ctx context.Context, q *pgstore.Queries) (*bundle.DMS, error) {
	s, err := q.GetDMSSettings(ctx)
	if db.IsNoRows(err) {
		return &bundle.DMS{PeriodDays: revocation.DefaultPeriodDays, WarnDays: revocation.DefaultWarnDays}, nil
	}
	if err != nil {
		return nil, err
	}
	warn := make([]int, len(s.WarnDays))
	for i, d := range s.WarnDays {
		warn[i] = int(d)
	}
	return &bundle.DMS{Enabled: s.Enabled, PeriodDays: int(s.PeriodDays), WarnDays: warn}, nil
}

// RunTimeTickets issues a time ticket for every organization at start and then every timeticket.Interval (or
// Config.TicketInterval) until ctx ends: {organization_id, issued_at} signed with time-ticket into tt:<organization_id>, which the gateway returns
// with every check-in.
func (c *Compiler) RunTimeTickets(ctx context.Context) {
	for {
		if err := c.IssueTimeTickets(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "issuing time tickets failed; retrying", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.ticketInterval()):
		}
	}
}

func (c *Compiler) ticketInterval() time.Duration {
	if c.cfg.TicketInterval > 0 {
		return c.cfg.TicketInterval
	}
	return timeticket.Interval
}

// IssueTimeTickets signs one ticket per organization in one batch and stores them.
func (c *Compiler) IssueTimeTickets(ctx context.Context) error {
	orgs, err := c.pool.OrganizationIDs(principal.With(ctx, principal.Principal{Kind: principal.KindSystem}))
	if err != nil || len(orgs) == 0 {
		return err
	}
	now := c.now().UTC().Truncate(time.Second)
	payloads := make([][]byte, len(orgs))
	pae := make([][]byte, len(orgs))
	for i, org := range orgs {
		if payloads[i], err = timeticket.Encode(timeticket.Ticket{OrganizationID: org.String(), IssuedAt: now}); err != nil {
			return err
		}
		pae[i] = dsse.PAE(timeticket.PayloadType, payloads[i])
	}
	sigs, err := c.signer.SignBatch(ctx, TimeTicketKey, pae)
	if err != nil {
		return err
	}
	for i, org := range orgs {
		env, err := dsse.New(timeticket.PayloadType, payloads[i], dsse.Signature{
			KeyID: timeTicketKeyID(sigs[i].KeyVersion), Sig: base64.StdEncoding.EncodeToString(sigs[i].Value),
		}).Encode()
		if err != nil {
			return err
		}
		if err := c.cache.PutTimeTicket(ctx, org, env); err != nil {
			return err
		}
	}
	return nil
}

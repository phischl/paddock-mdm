package revocationissuer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/valkey-io/valkey-go"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	domain "github.com/phischl/paddock-mdm/server/internal/domain/revocation"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// RoundInterval is the period of the issuer's round.
const RoundInterval = 60 * time.Second

// TokenRetention is how long raw step-up tokens of finished requests are kept (plan M4c decision 5).
const TokenRetention = 30 * 24 * time.Hour

// Handle is the mq.ConsumeFunc of queue revocation.approved. Every message is acknowledged: a request that fails for
// a transient reason stays approved and the round retries it.
func (i *Issuer) Handle(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case d, ok := <-deliveries:
			if !ok {
				return errors.New("delivery channel closed")
			}
			var msg domain.Approved
			dec := json.NewDecoder(bytes.NewReader(d.Body))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&msg); err != nil {
				slog.ErrorContext(ctx, "invalid revocation.approved message dead-lettered", "message_id", d.MessageId)
				if err := d.Nack(false, false); err != nil {
					return err
				}
				continue
			}
			if err := i.Issue(ctx, msg.OrganizationID, msg.RequestID); err != nil {
				slog.WarnContext(ctx, "issuing a revocation failed; the round retries", "request_id", msg.RequestID, "error", err)
			}
			if err := d.Ack(false); err != nil {
				return err
			}
		}
	}
}

// Run runs the round at start and then every RoundInterval until ctx ends.
func (i *Issuer) Run(ctx context.Context) error {
	tick := time.NewTicker(RoundInterval)
	defer tick.Stop()
	for {
		if err := i.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "revocation round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round issues approved requests that no message handled (lost, failed), puts every open token that is missing into
// cmd:<device_id> again (an emptied Valkey) and deletes the raw step-up tokens of requests finished 30 days ago.
func (i *Issuer) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "revocation-issuer"})
	orgs, err := i.org.OrganizationIDs(sys)
	if err != nil {
		return err
	}
	for _, org := range orgs {
		if err := i.roundOrg(systemContext(ctx, org, "revocation-round"), org); err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return nil
}

func (i *Issuer) roundOrg(ctx context.Context, org uuid.UUID) error {
	var approved []uuid.UUID
	var open []pgstore.ListOpenRevocationTokensRow
	err := i.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if approved, err = q.ListApprovedRevocationRequests(ctx); err != nil {
			return err
		}
		if open, err = q.ListOpenRevocationTokens(ctx, i.now()); err != nil {
			return err
		}
		n, err := q.ClearRevocationStepUpTokens(ctx, i.now().Add(-TokenRetention))
		if n > 0 {
			slog.InfoContext(ctx, "deleted the step-up tokens of finished revocation requests", "approvals", n)
		}
		return err
	})
	if err != nil {
		return err
	}
	for _, id := range approved {
		if err := i.Issue(ctx, org, id); err != nil {
			slog.WarnContext(ctx, "issuing a revocation failed; retrying next round", "request_id", id, "error", err)
		}
	}
	for _, t := range open {
		present, err := i.commands.HasCommand(ctx, t.DeviceID, t.ID)
		if err != nil {
			return err
		}
		if !present {
			if err := i.commands.PutCommand(ctx, t.DeviceID, t.ID, devicecache.Command{ExpiresAt: t.ExpiresAt, Envelope: t.Envelope}); err != nil {
				return err
			}
		}
	}
	return nil
}

// JTIClaims remembers in Valkey which request a step-up token proved (revocation-jti:<jti>), for longer than any
// token can prove an approval (stepupproof.MaxApprovalAge). The issuer keeps it apart from PostgreSQL, so a forged
// approval row cannot reuse a token that proved another request.
type JTIClaims struct{ c valkey.Client }

// NewJTIClaims wraps a Valkey client.
func NewJTIClaims(c valkey.Client) *JTIClaims { return &JTIClaims{c: c} }

// claimTTL outlives stepupproof.MaxApprovalAge.
const claimTTL = 48 * time.Hour

// Claim records that jti proves request; it reports false when jti proved another request before. Claiming the same
// request again (a retry) succeeds.
func (j *JTIClaims) Claim(ctx context.Context, jti string, request uuid.UUID) (bool, error) {
	key := "revocation-jti:" + jti
	err := j.c.Do(ctx, j.c.B().Set().Key(key).Value(request.String()).Nx().Ex(claimTTL).Build()).Error()
	if err == nil {
		return true, nil
	}
	if !valkey.IsValkeyNil(err) {
		return false, err
	}
	owner, err := j.c.Do(ctx, j.c.B().Get().Key(key).Build()).ToString()
	if err != nil {
		return false, err
	}
	return owner == request.String(), nil
}

package admin

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/sessions"
)

// SessionStore keeps the server-side record of every portal session (sessions.Store, plan M8s decision 12).
type SessionStore interface {
	Create(ctx context.Context, sid string, rec sessions.Record, ttl time.Duration) (sessions.Record, error)
	Get(ctx context.Context, sid string) (rec sessions.Record, gen int64, found bool, err error)
	Touch(ctx context.Context, sid string, accountID uuid.UUID, ttl time.Duration) error
	Delete(ctx context.Context, sid string, accountID uuid.UUID) error
}

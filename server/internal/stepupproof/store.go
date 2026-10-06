package stepupproof

import (
	"context"
	"time"

	"github.com/valkey-io/valkey-go"
)

// MaxUses is how many decryptions one step-up token allows (plan M4b.1 decision 6).
const MaxUses = 5

// Store keeps step-up ID tokens in Valkey: the raw token under stepup:<jti> for the step-up window, written by the
// api at the step-up callback and read by its reveal and recovery use cases, and the use counter
// stepup-uses:<jti> of the escrow-reader. Losing them only asks for a new step-up.
type Store struct{ c valkey.Client }

// NewStore wraps a Valkey client.
func NewStore(c valkey.Client) *Store { return &Store{c: c} }

func tokenKey(jti string) string { return "stepup:" + jti }
func usesKey(jti string) string  { return "stepup-uses:" + jti }

// Put keeps the raw token of jti for ttl.
func (s *Store) Put(ctx context.Context, jti, raw string, ttl time.Duration) error {
	return s.c.Do(ctx, s.c.B().Set().Key(tokenKey(jti)).Value(raw).Px(ttl).Build()).Error()
}

// Get returns the raw token of jti; ok is false when it expired or never existed.
func (s *Store) Get(ctx context.Context, jti string) (raw string, ok bool, err error) {
	raw, err = s.c.Do(ctx, s.c.B().Get().Key(tokenKey(jti)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return "", false, nil
	}
	return raw, err == nil, err
}

// Use counts one use of jti and returns the uses so far; the counter expires with the token at until.
func (s *Store) Use(ctx context.Context, jti string, until time.Time) (int64, error) {
	res := s.c.DoMulti(ctx,
		s.c.B().Incr().Key(usesKey(jti)).Build(),
		s.c.B().Expireat().Key(usesKey(jti)).Timestamp(until.Unix()+1).Build())
	if err := res[1].Error(); err != nil {
		return 0, err
	}
	return res[0].AsInt64()
}

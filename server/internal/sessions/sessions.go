// Package sessions keeps the server-side half of portal sessions in Valkey (ADR 0034 decision 4, plan M8s §3.3): a
// record per session that the api requires on every request, a set of the sessions of each account, and a generation
// that ends every older session at once.
package sessions

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"

	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Record is the server-side half of a portal or MCP session (ADR 0034 decision 4, ADR 0044 amendment A2).
type Record struct {
	AccountID uuid.UUID `json:"account_id"`
	Kind      string    `json:"kind"`
	Role      string    `json:"role"`
	Org       uuid.UUID `json:"org"`
	Gen       int64     `json:"gen"`
	CreatedAt int64     `json:"created_at"`
	// Channel is "mcp" for an MCP session. An MCP session has no cookie payload, so the record carries the display
	// name and the Authentik subject itself; portal sessions leave all three empty.
	Channel string `json:"channel,omitempty"`
	Display string `json:"display,omitempty"`
	Subject string `json:"sub,omitempty"`
}

// ErrUnavailable wraps every Valkey error; the api answers it with 503 session_store_unavailable.
var ErrUnavailable = errors.New("sessions: store unavailable")

// Store is the session store.
type Store struct{ c valkey.Client }

// NewStore wraps a Valkey client.
func NewStore(c valkey.Client) *Store { return &Store{c: c} }

const genKey = "sess-gen"

func sessionKey(sid string) string          { return "sess:" + sid }
func accountKey(accountID uuid.UUID) string { return "acct-sess:" + accountID.String() }

// NewID returns 32 random bytes, base64url without padding.
func NewID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// unavailable wraps a Valkey error as ErrUnavailable and problem.SessionStoreUnavailable, so that a use case that
// ends sessions answers 503 like the session lookup.
func unavailable(err error) error {
	return fmt.Errorf("%w (%w): %w", ErrUnavailable, problem.SessionStoreUnavailable, err)
}

// createScript writes the record with the current generation spliced in and adds the session to its account's set.
// The set lives as long as its longest session: NX sets a first expiry, GT only ever extends it.
var createScript = valkey.NewLuaScript(`
local gen = tonumber(redis.call('GET', KEYS[3]) or '0')
redis.call('SET', KEYS[1], ARGV[1] .. gen .. ARGV[2], 'PX', ARGV[3])
redis.call('SADD', KEYS[2], ARGV[4])
redis.call('PEXPIRE', KEYS[2], ARGV[3], 'NX')
redis.call('PEXPIRE', KEYS[2], ARGV[3], 'GT')
return gen
`)

// Create writes sess:<sid> (JSON, PX ttl) and adds sid to acct-sess:<account_id> (EXPIRE ttl); Gen is read from
// sess-gen (missing = 0) inside the same call.
func (s *Store) Create(ctx context.Context, sid string, rec Record, ttl time.Duration) (Record, error) {
	rec.Gen = 0
	raw, err := json.Marshal(rec)
	if err != nil {
		return Record{}, err
	}
	prefix, suffix, ok := strings.Cut(string(raw), `"gen":0`)
	if !ok {
		return Record{}, errors.New("sessions: record without gen")
	}
	prefix += `"gen":`
	gen, err := createScript.Exec(ctx, s.c, []string{sessionKey(sid), accountKey(rec.AccountID), genKey},
		[]string{prefix, suffix, strconv.FormatInt(ttl.Milliseconds(), 10), sid}).AsInt64()
	if err != nil {
		return Record{}, unavailable(err)
	}
	rec.Gen = gen
	return rec, nil
}

// Get returns the record and the current generation (MGET sess:<sid> sess-gen); found is false for a missing key.
func (s *Store) Get(ctx context.Context, sid string) (rec Record, gen int64, found bool, err error) {
	vals, err := s.c.Do(ctx, s.c.B().Mget().Key(sessionKey(sid), genKey).Build()).ToArray()
	if err != nil {
		return Record{}, 0, false, unavailable(err)
	}
	if len(vals) != 2 {
		return Record{}, 0, false, unavailable(fmt.Errorf("MGET answered %d values", len(vals)))
	}
	if g, err := vals[1].ToString(); err == nil {
		if gen, err = strconv.ParseInt(g, 10, 64); err != nil {
			return Record{}, 0, false, unavailable(fmt.Errorf("generation %q: %w", g, err))
		}
	} else if !valkey.IsValkeyNil(err) {
		return Record{}, 0, false, unavailable(err)
	}
	raw, err := vals[0].ToString()
	if valkey.IsValkeyNil(err) {
		return Record{}, gen, false, nil
	}
	if err != nil {
		return Record{}, 0, false, unavailable(err)
	}
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return Record{}, 0, false, fmt.Errorf("sessions: record of %s: %w", sid[:min(len(sid), 8)], err)
	}
	return rec, gen, true, nil
}

// Touch extends the TTL of sess:<sid> and acct-sess:<account_id> to ttl (session re-issue).
func (s *Store) Touch(ctx context.Context, sid string, accountID uuid.UUID, ttl time.Duration) error {
	res := s.c.DoMulti(ctx,
		s.c.B().Pexpire().Key(sessionKey(sid)).Milliseconds(ttl.Milliseconds()).Build(),
		s.c.B().Pexpire().Key(accountKey(accountID)).Milliseconds(ttl.Milliseconds()).Gt().Build())
	for _, r := range res {
		if err := r.Error(); err != nil {
			return unavailable(err)
		}
	}
	return nil
}

// Delete removes sess:<sid> and the set member.
func (s *Store) Delete(ctx context.Context, sid string, accountID uuid.UUID) error {
	res := s.c.DoMulti(ctx,
		s.c.B().Del().Key(sessionKey(sid)).Build(),
		s.c.B().Srem().Key(accountKey(accountID)).Member(sid).Build())
	for _, r := range res {
		if err := r.Error(); err != nil {
			return unavailable(err)
		}
	}
	return nil
}

// revokeScript deletes every session of the set and the set itself, and returns how many sessions still existed.
var revokeScript = valkey.NewLuaScript(`
local n = 0
for _, sid in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  n = n + redis.call('DEL', 'sess:' .. sid)
end
redis.call('DEL', KEYS[1])
return n
`)

// countScript counts the sessions of the set whose record still exists.
var countScript = valkey.NewLuaScript(`
local n = 0
for _, sid in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  n = n + redis.call('EXISTS', 'sess:' .. sid)
end
return n
`)

// CountAccount returns how many sessions of the account exist.
func (s *Store) CountAccount(ctx context.Context, accountID uuid.UUID) (int, error) {
	n, err := countScript.Exec(ctx, s.c, []string{accountKey(accountID)}, nil).AsInt64()
	if err != nil {
		return 0, unavailable(err)
	}
	return int(n), nil
}

// RevokeAccount deletes every session of the account and returns how many existed.
func (s *Store) RevokeAccount(ctx context.Context, accountID uuid.UUID) (int, error) {
	n, err := revokeScript.Exec(ctx, s.c, []string{accountKey(accountID)}, nil).AsInt64()
	if err != nil {
		return 0, unavailable(err)
	}
	return int(n), nil
}

// EndAll increments sess-gen and returns the new generation; every record with a lower Gen is invalid.
func (s *Store) EndAll(ctx context.Context) (int64, error) {
	gen, err := s.c.Do(ctx, s.c.B().Incr().Key(genKey).Build()).AsInt64()
	if err != nil {
		return 0, unavailable(err)
	}
	return gen, nil
}

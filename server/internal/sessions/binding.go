package sessions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

// Binding ties the renewals of an MCP session to its MFA-checked first login (ADR 0044 amendment 2026-10-28):
// Authentik leaves amr out of refreshed ID tokens but carries auth_time over unchanged, so a renewal is accepted only
// for the (sub, auth_time) of a login whose ID token proved the second factor. It lives as long as the refresh token
// of that login, not as long as the idle-expiring session record.
type Binding struct {
	AccountID uuid.UUID `json:"account_id"`
	Kind      string    `json:"kind"`
	Role      string    `json:"role"`
	Org       uuid.UUID `json:"org"`
	Client    string    `json:"client,omitempty"`
	Gen       int64     `json:"gen"`
}

// bindingKey hashes the subject, so that a subject never shapes the key.
func bindingKey(sub string, authTime int64) string {
	sum := sha256.Sum256([]byte(sub))
	return "mcp-bind:" + hex.EncodeToString(sum[:]) + ":" + strconv.FormatInt(authTime, 10)
}

func accountBindingsKey(accountID uuid.UUID) string { return "acct-mcp-bind:" + accountID.String() }

// chainKey is the set of the MCP session records opened under the binding of (sub, authTime), one per access token of
// its refresh chain. revokeScript derives it from the binding key, so both share the suffix after their prefix.
func chainKey(sub string, authTime int64) string {
	return "mcp-chain:" + strings.TrimPrefix(bindingKey(sub, authTime), "mcp-bind:")
}

// ErrNoBinding refuses an MCP renewal record whose login binding ended before the record was written (logout, End all
// sessions or a revocation racing the renewal).
var ErrNoBinding = errors.New("sessions: MCP login binding ended")

// Chain names the login binding an MCP session record belongs to (PDK-468): logout and every end of the binding delete
// all records of its refresh chain, not only the record of the bearer.
type Chain struct {
	Sub      string
	AuthTime int64
	// TTL is how long the chain's set lives at least: the binding's remaining lifetime (auth_time + 8 h).
	TTL time.Duration
	// Renewal requires the binding to exist when the record is written; a first login writes its record before the
	// binding.
	Renewal bool
}

// createMCPScript is createScript for an MCP record that also joins the set of its binding's chain (KEYS[5]), in one
// call: a logout that ends the chain either runs before (a renewal finds no binding, KEYS[4], and writes nothing) or
// after (the chain's set already names the record). The set lives as long as its binding or longest record: NX sets a
// first expiry, GT only ever extends it.
var createMCPScript = valkey.NewLuaScript(`
if ARGV[6] == '1' and redis.call('EXISTS', KEYS[4]) == 0 then
  return -1
end
local gen = tonumber(redis.call('GET', KEYS[3]) or '0')
redis.call('SET', KEYS[1], ARGV[1] .. gen .. ARGV[2], 'PX', ARGV[3])
redis.call('SADD', KEYS[2], ARGV[4])
redis.call('PEXPIRE', KEYS[2], ARGV[3], 'NX')
redis.call('PEXPIRE', KEYS[2], ARGV[3], 'GT')
redis.call('SADD', KEYS[5], ARGV[4])
redis.call('PEXPIRE', KEYS[5], ARGV[5], 'NX')
redis.call('PEXPIRE', KEYS[5], ARGV[5], 'GT')
return gen
`)

// CreateMCP writes an MCP session record as Create does and adds it to the set of its chain, whose expiry it extends
// to the longer of ch.TTL and ttl. A renewal whose binding no longer exists writes nothing and fails with ErrNoBinding.
func (s *Store) CreateMCP(ctx context.Context, sid string, rec Record, ttl time.Duration, ch Chain) (Record, error) {
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
	renewal := "0"
	if ch.Renewal {
		renewal = "1"
	}
	gen, err := createMCPScript.Exec(ctx, s.c,
		[]string{sessionKey(sid), accountKey(rec.AccountID), genKey, bindingKey(ch.Sub, ch.AuthTime), chainKey(ch.Sub, ch.AuthTime)},
		[]string{prefix, suffix, strconv.FormatInt(ttl.Milliseconds(), 10), sid,
			strconv.FormatInt(max(ch.TTL, ttl).Milliseconds(), 10), renewal}).AsInt64()
	if err != nil {
		return Record{}, unavailable(err)
	}
	if gen < 0 {
		return Record{}, ErrNoBinding
	}
	rec.Gen = gen
	return rec, nil
}

// bindScript writes the binding with the current generation spliced in and adds its key to the account's set of
// bindings, which RevokeAccount clears.
var bindScript = valkey.NewLuaScript(`
local gen = tonumber(redis.call('GET', KEYS[3]) or '0')
redis.call('SET', KEYS[1], ARGV[1] .. gen .. ARGV[2], 'PX', ARGV[3])
redis.call('SADD', KEYS[2], KEYS[1])
redis.call('PEXPIRE', KEYS[2], ARGV[3], 'NX')
redis.call('PEXPIRE', KEYS[2], ARGV[3], 'GT')
return gen
`)

// Bind writes the binding of (sub, authTime) for ttl; Gen is read from sess-gen inside the same call, so that End all
// sessions also ends the bindings written before it.
func (s *Store) Bind(ctx context.Context, sub string, authTime int64, b Binding, ttl time.Duration) (Binding, error) {
	if ttl <= 0 {
		return Binding{}, errors.New("sessions: binding without lifetime")
	}
	b.Gen = 0
	raw, err := json.Marshal(b)
	if err != nil {
		return Binding{}, err
	}
	prefix, suffix, ok := strings.Cut(string(raw), `"gen":0`)
	if !ok {
		return Binding{}, errors.New("sessions: binding without gen")
	}
	prefix += `"gen":`
	gen, err := bindScript.Exec(ctx, s.c, []string{bindingKey(sub, authTime), accountBindingsKey(b.AccountID), genKey},
		[]string{prefix, suffix, strconv.FormatInt(ttl.Milliseconds(), 10)}).AsInt64()
	if err != nil {
		return Binding{}, unavailable(err)
	}
	b.Gen = gen
	return b, nil
}

// Binding returns the binding of (sub, authTime) and the current generation; found is false for a missing key.
func (s *Store) Binding(ctx context.Context, sub string, authTime int64) (b Binding, gen int64, found bool, err error) {
	vals, err := s.c.Do(ctx, s.c.B().Mget().Key(bindingKey(sub, authTime), genKey).Build()).ToArray()
	if err != nil {
		return Binding{}, 0, false, unavailable(err)
	}
	if len(vals) != 2 {
		return Binding{}, 0, false, unavailable(fmt.Errorf("MGET answered %d values", len(vals)))
	}
	if g, err := vals[1].ToString(); err == nil {
		if gen, err = strconv.ParseInt(g, 10, 64); err != nil {
			return Binding{}, 0, false, unavailable(fmt.Errorf("generation %q: %w", g, err))
		}
	} else if !valkey.IsValkeyNil(err) {
		return Binding{}, 0, false, unavailable(err)
	}
	raw, err := vals[0].ToString()
	if valkey.IsValkeyNil(err) {
		return Binding{}, gen, false, nil
	}
	if err != nil {
		return Binding{}, 0, false, unavailable(err)
	}
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return Binding{}, 0, false, fmt.Errorf("sessions: MCP login binding: %w", err)
	}
	return b, gen, true, nil
}

// unbindScript deletes every record of the chain's set (KEYS[3]) and its member in the account's set of sessions
// (KEYS[4]), the set itself, the binding (KEYS[1]) and its member in the account's set of bindings (KEYS[2]).
var unbindScript = valkey.NewLuaScript(`
for _, sid in ipairs(redis.call('SMEMBERS', KEYS[3])) do
  redis.call('DEL', 'sess:' .. sid)
  redis.call('SREM', KEYS[4], sid)
end
redis.call('DEL', KEYS[3], KEYS[1])
redis.call('SREM', KEYS[2], KEYS[1])
return 0
`)

// Unbind ends the binding of (sub, authTime): it removes the binding, its member in the account's set and every MCP
// session record of its refresh chain (PDK-468), in one call.
func (s *Store) Unbind(ctx context.Context, sub string, authTime int64, accountID uuid.UUID) error {
	key := bindingKey(sub, authTime)
	err := unbindScript.Exec(ctx, s.c, []string{key, accountBindingsKey(accountID), chainKey(sub, authTime),
		accountKey(accountID)}, nil).Error()
	if err != nil {
		return unavailable(err)
	}
	return nil
}

// UseLoginToken marks a login token presented to an MCP session call as used for ttl (at least one second) and reports
// whether this was its first use (ADR 0044 amendment 2026-10-28): a captured login token cannot reopen a session after
// logout, End all sessions or a role change. identity names the verified token (issuer, subject and jti); only its
// hash is stored.
func (s *Store) UseLoginToken(ctx context.Context, identity string, ttl time.Duration) (bool, error) {
	ttl = max(ttl, time.Second)
	sum := sha256.Sum256([]byte(identity))
	err := s.c.Do(ctx, s.c.B().Set().Key("mcp-used:"+hex.EncodeToString(sum[:])).Value("1").Nx().
		Px(ttl).Build()).Error()
	if valkey.IsValkeyNil(err) {
		return false, nil
	}
	if err != nil {
		return false, unavailable(err)
	}
	return true, nil
}

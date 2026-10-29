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

// Unbind removes the binding of (sub, authTime) and its member in the account's set.
func (s *Store) Unbind(ctx context.Context, sub string, authTime int64, accountID uuid.UUID) error {
	key := bindingKey(sub, authTime)
	res := s.c.DoMulti(ctx,
		s.c.B().Del().Key(key).Build(),
		s.c.B().Srem().Key(accountBindingsKey(accountID)).Member(key).Build())
	for _, r := range res {
		if err := r.Error(); err != nil {
			return unavailable(err)
		}
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

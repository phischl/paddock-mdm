// Package devicecache owns the Valkey keys of the device control plane (architecture §8.3): their names, record
// formats and TTLs. The worker and the compiler write them from PostgreSQL (the api also writes a token right after
// creating or revoking it); the gateway reads them, so the device path never touches the database. Everything except
// nonces can be rebuilt from PostgreSQL.
package devicecache

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

// EnrollmentTTL is how long an enrollment request can be polled (plan M2a decision 10).
const EnrollmentTTL = 7 * 24 * time.Hour

// Cache is the typed access to the device keys in Valkey.
type Cache struct{ c valkey.Client }

// New wraps a Valkey client.
func New(c valkey.Client) *Cache { return &Cache{c: c} }

// Token is the cached enrollment token et:<hex sha256(secret)>.
type Token struct {
	OrganizationID uuid.UUID
	Revoked        bool
	ExpiresAt      time.Time
}

// Usable reports whether the gateway may accept an enrollment with the token (exhaustion is checked by the worker).
func (t Token) Usable(now time.Time) bool { return !t.Revoked && now.Before(t.ExpiresAt) }

func tokenKey(secretSHA256 []byte) string { return "et:" + hex.EncodeToString(secretSHA256) }

// PutToken caches a token until it expires; expired tokens are removed.
func (c *Cache) PutToken(ctx context.Context, secretSHA256 []byte, t Token, now time.Time) error {
	key := tokenKey(secretSHA256)
	if !now.Before(t.ExpiresAt) {
		return c.c.Do(ctx, c.c.B().Del().Key(key).Build()).Error()
	}
	return c.putHash(ctx, key, t.ExpiresAt, map[string]string{
		"org": t.OrganizationID.String(), "revoked": strconv.FormatBool(t.Revoked),
		"expires_at": strconv.FormatInt(t.ExpiresAt.Unix(), 10),
	})
}

// Token reads a cached token.
func (c *Cache) Token(ctx context.Context, secretSHA256 []byte) (Token, bool, error) {
	m, ok, err := c.getHash(ctx, tokenKey(secretSHA256))
	if !ok || err != nil {
		return Token{}, ok, err
	}
	org, err1 := uuid.Parse(m["org"])
	revoked, err2 := strconv.ParseBool(m["revoked"])
	expires, err3 := strconv.ParseInt(m["expires_at"], 10, 64)
	if err := errors.Join(err1, err2, err3); err != nil {
		return Token{}, false, fmt.Errorf("devicecache: corrupt token entry: %w", err)
	}
	return Token{OrganizationID: org, Revoked: revoked, ExpiresAt: time.Unix(expires, 0)}, true, nil
}

// Key statuses of DeviceKey.Status: the device state while the key is active, otherwise KeyRevoked.
const (
	KeyActive      = "active"
	KeyQuarantined = "quarantined"
	KeyRetired     = "retired"
	KeyRejected    = "rejected"
	KeyRevoked     = "revoked"
)

// KeyStatus combines the key status and the device state into DeviceKey.Status.
func KeyStatus(keyStatus, deviceState string) string {
	if keyStatus != "active" {
		return KeyRevoked
	}
	return deviceState
}

// DeviceKey is the cached identity key dk:<key_id>.
type DeviceKey struct {
	DeviceID       uuid.UUID
	OrganizationID uuid.UUID
	Status         string
	PublicKey      []byte // SubjectPublicKeyInfo DER
}

func deviceKeyKey(keyID string) string { return "dk:" + keyID }

// PutDeviceKey caches an identity key without expiry.
func (c *Cache) PutDeviceKey(ctx context.Context, keyID string, k DeviceKey) error {
	return c.putHash(ctx, deviceKeyKey(keyID), time.Time{}, map[string]string{
		"device": k.DeviceID.String(), "org": k.OrganizationID.String(), "status": k.Status,
		"public_key": base64.StdEncoding.EncodeToString(k.PublicKey),
	})
}

// DeviceKey reads a cached identity key.
func (c *Cache) DeviceKey(ctx context.Context, keyID string) (DeviceKey, bool, error) {
	m, ok, err := c.getHash(ctx, deviceKeyKey(keyID))
	if !ok || err != nil {
		return DeviceKey{}, ok, err
	}
	dev, err1 := uuid.Parse(m["device"])
	org, err2 := uuid.Parse(m["org"])
	pub, err3 := base64.StdEncoding.DecodeString(m["public_key"])
	if err := errors.Join(err1, err2, err3); err != nil {
		return DeviceKey{}, false, fmt.Errorf("devicecache: corrupt device key entry: %w", err)
	}
	return DeviceKey{DeviceID: dev, OrganizationID: org, Status: m["status"], PublicKey: pub}, true, nil
}

// Enrollment is the cached enrollment request enr:<enrollment_id>. Status is processing (written by the gateway),
// then pending, active or rejected (written by the worker).
type Enrollment struct {
	KeyID          string
	PublicKey      []byte
	OrganizationID uuid.UUID
	Status         string
	DeviceID       uuid.UUID // uuid.Nil until the worker created the device
	Reason         string    // rejection reason
}

func enrollmentKey(id uuid.UUID) string { return "enr:" + id.String() }

// PutEnrollment caches an enrollment request for EnrollmentTTL.
func (c *Cache) PutEnrollment(ctx context.Context, id uuid.UUID, e Enrollment, now time.Time) error {
	m := map[string]string{
		"key_id": e.KeyID, "public_key": base64.StdEncoding.EncodeToString(e.PublicKey),
		"org": e.OrganizationID.String(), "status": e.Status, "reason": e.Reason, "device": "",
	}
	if e.DeviceID != uuid.Nil {
		m["device"] = e.DeviceID.String()
	}
	return c.putHash(ctx, enrollmentKey(id), now.Add(EnrollmentTTL), m)
}

// Enrollment reads a cached enrollment request.
func (c *Cache) Enrollment(ctx context.Context, id uuid.UUID) (Enrollment, bool, error) {
	m, ok, err := c.getHash(ctx, enrollmentKey(id))
	if !ok || err != nil {
		return Enrollment{}, ok, err
	}
	org, err1 := uuid.Parse(m["org"])
	pub, err2 := base64.StdEncoding.DecodeString(m["public_key"])
	var dev uuid.UUID
	var err3 error
	if m["device"] != "" {
		dev, err3 = uuid.Parse(m["device"])
	}
	if err := errors.Join(err1, err2, err3); err != nil {
		return Enrollment{}, false, fmt.Errorf("devicecache: corrupt enrollment entry: %w", err)
	}
	return Enrollment{KeyID: m["key_id"], PublicKey: pub, OrganizationID: org, Status: m["status"], DeviceID: dev,
		Reason: m["reason"]}, true, nil
}

// putHash replaces a hash in one MULTI/EXEC transaction; expireAt zero means no expiry.
func (c *Cache) putHash(ctx context.Context, key string, expireAt time.Time, fields map[string]string) error {
	hset := c.c.B().Hset().Key(key).FieldValue()
	for f, v := range fields {
		hset = hset.FieldValue(f, v)
	}
	cmds := valkey.Commands{c.c.B().Multi().Build(), c.c.B().Del().Key(key).Build(), hset.Build()}
	if !expireAt.IsZero() {
		cmds = append(cmds, c.c.B().Pexpireat().Key(key).MillisecondsTimestamp(expireAt.UnixMilli()).Build())
	}
	cmds = append(cmds, c.c.B().Exec().Build())
	for _, r := range c.c.DoMulti(ctx, cmds...) {
		if err := r.Error(); err != nil {
			return fmt.Errorf("devicecache: write %s: %w", key, err)
		}
	}
	return nil
}

func (c *Cache) getHash(ctx context.Context, key string) (map[string]string, bool, error) {
	m, err := c.c.Do(ctx, c.c.B().Hgetall().Key(key).Build()).AsStrMap()
	if err != nil {
		return nil, false, fmt.Errorf("devicecache: read %s: %w", key, err)
	}
	return m, len(m) > 0, nil
}

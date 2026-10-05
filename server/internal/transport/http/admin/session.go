package admin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/principal"
)

// Cookie names and lifetimes (plan M0 §6.7).
const (
	SessionCookie   = "paddock_session"
	LoginCookie     = "paddock_login"
	SessionAbsolute = 8 * time.Hour
	SessionIdle     = 30 * time.Minute
	SessionReissue  = 5 * time.Minute
	LoginLifetime   = 10 * time.Minute
)

// ErrInvalidCookie covers tampered, foreign-key, expired and malformed cookies.
var ErrInvalidCookie = errors.New("admin: invalid cookie")

// Keyring holds the AES-256-GCM session keys: current encrypts, previous is accepted for decryption.
type Keyring struct {
	mu       sync.RWMutex
	current  cipher.AEAD
	previous cipher.AEAD
}

// SetKeys installs base64-encoded 32-byte keys.
func (k *Keyring) SetKeys(current, previous string) error {
	cur, err := newAEAD(current)
	if err != nil {
		return fmt.Errorf("current session key: %w", err)
	}
	var prev cipher.AEAD
	if previous != "" {
		if prev, err = newAEAD(previous); err != nil {
			return fmt.Errorf("previous session key: %w", err)
		}
	}
	k.mu.Lock()
	k.current, k.previous = cur, prev
	k.mu.Unlock()
	return nil
}

// Ready reports whether a key is loaded.
func (k *Keyring) Ready() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current != nil
}

func newAEAD(b64 string) (cipher.AEAD, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts v for the cookie name (the name is authenticated data, so cookies cannot be swapped).
func (k *Keyring) Seal(name string, v any) (string, error) {
	k.mu.RLock()
	aead := k.current
	k.mu.RUnlock()
	if aead == nil {
		return "", errors.New("admin: no session key loaded")
	}
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte(name))), nil
}

// Open decrypts a cookie value with the current or the previous key.
func (k *Keyring) Open(name, value string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return ErrInvalidCookie
	}
	k.mu.RLock()
	keys := []cipher.AEAD{k.current, k.previous}
	k.mu.RUnlock()
	for _, aead := range keys {
		if aead == nil || len(raw) < aead.NonceSize() {
			continue
		}
		plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(name))
		if err != nil {
			continue
		}
		if err := json.Unmarshal(plain, v); err != nil {
			return ErrInvalidCookie
		}
		return nil
	}
	return ErrInvalidCookie
}

// KeySource reads the session keys (OpenBao KV secret/paddock/session).
type KeySource func(ctx context.Context) (current, previous string, err error)

// Reload loads the keys now and then every interval until ctx ends.
func (k *Keyring) Reload(ctx context.Context, src KeySource, interval time.Duration, logErr func(error)) {
	for {
		cur, prev, err := src(ctx)
		if err == nil {
			err = k.SetKeys(cur, prev)
		}
		if err != nil {
			logErr(err)
		}
		wait := interval
		if !k.Ready() {
			wait = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Session is the payload of the session cookie.
type Session struct {
	V    int       `json:"v"`
	Sub  string    `json:"sub"`
	PID  uuid.UUID `json:"pid"`
	Kind string    `json:"kind"`
	Role string    `json:"role"`
	Org  uuid.UUID `json:"org"`
	Disp string    `json:"disp"`
	Loc  string    `json:"loc"`
	Iat  int64     `json:"iat"`
	Exp  int64     `json:"exp"`
	Idle int64     `json:"idle"`
	// StepUpAt (unix) and StepUpJTI identify the last step-up authentication of the session (plan M4a decision 6).
	StepUpAt  int64  `json:"stepup_at,omitempty"`
	StepUpJTI string `json:"stepup_jti,omitempty"`
}

// NewSession creates a session for p at now.
func NewSession(p principal.Principal, locale string, now time.Time) Session {
	s := Session{
		V: 1, Sub: p.Subject, PID: p.ID, Kind: string(p.Kind), Role: string(p.Role), Org: p.OrganizationID,
		Disp: p.Display, Loc: locale, Iat: now.Unix(), Exp: now.Add(SessionAbsolute).Unix(), Idle: now.Unix(),
	}
	if !p.StepUpAt.IsZero() {
		s.StepUpAt = p.StepUpAt.Unix()
	}
	return s
}

// Validate checks version, absolute expiry and idle timeout. reissue reports whether the idle mark is older than
// SessionReissue and the cookie should be re-issued.
func (s Session) Validate(now time.Time) (reissue bool, err error) {
	if s.V != 1 || s.PID == uuid.Nil {
		return false, ErrInvalidCookie
	}
	if now.Unix() >= s.Exp {
		return false, ErrInvalidCookie
	}
	idle := time.Unix(s.Idle, 0)
	if now.Sub(idle) >= SessionIdle {
		return false, ErrInvalidCookie
	}
	switch principal.Kind(s.Kind) {
	case principal.KindAdmin:
		if s.Org == uuid.Nil {
			return false, ErrInvalidCookie
		}
	case principal.KindPlatformAdmin:
		if s.Org != uuid.Nil {
			return false, ErrInvalidCookie
		}
	default:
		return false, ErrInvalidCookie
	}
	return now.Sub(idle) > SessionReissue, nil
}

// Principal converts the session into the request principal.
func (s Session) Principal(ip string) principal.Principal {
	p := principal.Principal{
		Kind: principal.Kind(s.Kind), ID: s.PID, Subject: s.Sub, Display: s.Disp, Role: principal.Role(s.Role),
		OrganizationID: s.Org, IP: ip,
	}
	if s.StepUpAt != 0 {
		p.StepUpAt = time.Unix(s.StepUpAt, 0)
	}
	return p
}

// sessionCookie builds the Set-Cookie for a session value ("" clears it).
func sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: SessionCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}
}

func loginCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: LoginCookie, Value: value, Path: "/api/auth", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}
}

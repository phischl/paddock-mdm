// Package bao is the OpenBao client of paddock-server: AppRole login with token renewal, Transit signing, public
// key lookup and KV v2 reads (ADR 0006). Keys never leave OpenBao.
package bao

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// Client logs in with AppRole and keeps a valid token.
type Client struct {
	api      *api.Client
	roleID   string
	secretID string

	mu      sync.Mutex
	renewAt time.Time
	expires time.Time
}

// New creates a client. No request is made until the first operation.
func New(addr, roleID, secretID string) (*Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = addr
	cfg.Timeout = 10 * time.Second
	c, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	c.ClearToken()
	return &Client{api: c, roleID: roleID, secretID: secretID}, nil
}

// NewWithToken creates a client with a fixed token (tests, tooling).
func NewWithToken(addr, token string) (*Client, error) {
	c, err := New(addr, "", "")
	if err != nil {
		return nil, err
	}
	c.api.SetToken(token)
	c.renewAt = time.Now().Add(100 * 365 * 24 * time.Hour)
	c.expires = c.renewAt
	return c, nil
}

// ensureToken logs in or renews the token when two thirds of its lifetime have passed.
func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.api.Token() != "" && now.Before(c.renewAt) {
		return nil
	}
	if c.api.Token() != "" && now.Before(c.expires) {
		s, err := c.api.Auth().Token().RenewSelfWithContext(ctx, 0)
		if err == nil && s != nil && s.Auth != nil && s.Auth.LeaseDuration > 0 {
			c.setLease(now, time.Duration(s.Auth.LeaseDuration)*time.Second)
			return nil
		}
	}
	if c.roleID == "" {
		return errors.New("bao: token expired and no AppRole configured")
	}
	s, err := c.api.Logical().WriteWithContext(ctx, "auth/approle/login", map[string]any{
		"role_id": c.roleID, "secret_id": c.secretID,
	})
	if err != nil {
		return fmt.Errorf("bao: approle login: %w", err)
	}
	if s == nil || s.Auth == nil || s.Auth.ClientToken == "" {
		return errors.New("bao: approle login returned no token")
	}
	c.api.SetToken(s.Auth.ClientToken)
	c.setLease(now, time.Duration(s.Auth.LeaseDuration)*time.Second)
	return nil
}

func (c *Client) setLease(now time.Time, ttl time.Duration) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	c.expires = now.Add(ttl)
	c.renewAt = now.Add(ttl * 2 / 3)
}

// Ping checks that OpenBao is unsealed and the credential works.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.ensureToken(ctx); err != nil {
		return err
	}
	h, err := c.api.Sys().HealthWithContext(ctx)
	if err != nil {
		return err
	}
	if h.Sealed {
		return errors.New("bao: sealed")
	}
	return nil
}

// Signature is a Transit signature.
type Signature struct {
	Value      string // "vault:v<N>:<base64>"
	KeyVersion int
}

// Sign signs message with the Transit key (prehashed=false: the key signs the bytes as given).
func (c *Client) Sign(ctx context.Context, key string, message []byte) (Signature, error) {
	if err := c.ensureToken(ctx); err != nil {
		return Signature{}, err
	}
	s, err := c.api.Logical().WriteWithContext(ctx, "transit/sign/"+key, map[string]any{
		"input": base64.StdEncoding.EncodeToString(message), "prehashed": false,
	})
	if err != nil {
		return Signature{}, fmt.Errorf("bao: sign: %w", err)
	}
	if s == nil || s.Data == nil {
		return Signature{}, errors.New("bao: sign returned no data")
	}
	sig, _ := s.Data["signature"].(string)
	version, err := toInt(s.Data["key_version"])
	if err != nil || sig == "" {
		return Signature{}, fmt.Errorf("bao: unexpected sign response: %v", s.Data)
	}
	return Signature{Value: sig, KeyVersion: version}, nil
}

// PublicKeys returns the public keys of a Transit key by version.
func (c *Client) PublicKeys(ctx context.Context, key string) (map[int][]byte, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}
	s, err := c.api.Logical().ReadWithContext(ctx, "transit/keys/"+key)
	if err != nil {
		return nil, fmt.Errorf("bao: read key: %w", err)
	}
	if s == nil || s.Data == nil {
		return nil, fmt.Errorf("bao: key %s not found", key)
	}
	keys, ok := s.Data["keys"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("bao: unexpected key response")
	}
	out := map[int][]byte{}
	for v, raw := range keys {
		version, err := strconv.Atoi(v)
		if err != nil {
			continue
		}
		entry, _ := raw.(map[string]any)
		pub, _ := entry["public_key"].(string)
		b, err := base64.StdEncoding.DecodeString(pub)
		if err != nil || len(b) == 0 {
			continue
		}
		out[version] = b
	}
	return out, nil
}

// KV reads the data of a KV v2 secret, e.g. path "secret/data/paddock/session".
func (c *Client) KV(ctx context.Context, path string) (map[string]string, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}
	s, err := c.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: read %s: %w", path, err)
	}
	if s == nil || s.Data == nil {
		return nil, fmt.Errorf("bao: %s not found", path)
	}
	data, ok := s.Data["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("bao: %s has no data", path)
	}
	out := map[string]string{}
	for k, v := range data {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out, nil
}

func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case float64:
		return int(n), nil
	case interface{ Int64() (int64, error) }:
		i, err := n.Int64()
		return int(i), err
	case string:
		return strconv.Atoi(n)
	default:
		return 0, fmt.Errorf("not a number: %T", v)
	}
}

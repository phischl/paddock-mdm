// Package escrow is the device side of secret escrow (architecture §12.2 and §12.4, plan M4a decisions 9–12): the
// escrow-wrap public key from the bundle, RSA-OAEP with SHA-256 encryption of a secret to it, and the request and
// status bodies of /v1/escrow. Only OpenBao (Transit key escrow-wrap) can decrypt.
package escrow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// KeyName is the Transit key secrets are wrapped with.
const KeyName = "escrow-wrap"

// KeyID is the key ID of a version of escrow-wrap, e.g. "escrow-wrap:v1".
func KeyID(version int) string { return KeyName + ":v" + strconv.Itoa(version) }

// KeyVersion parses a key ID of escrow-wrap.
func KeyVersion(keyID string) (int, error) {
	v, ok := strings.CutPrefix(keyID, KeyName+":v")
	n, err := strconv.Atoi(v)
	if !ok || err != nil || n < 1 {
		return 0, fmt.Errorf("escrow: invalid key id %q", keyID)
	}
	return n, nil
}

// Kinds of escrowed secrets.
const (
	KindAdminPassword = "admin_password"
)

// MaxCiphertext bounds a ciphertext (decoded) in M4a.
const MaxCiphertext = 4 << 10

// Statuses of GET /v1/escrow/{escrow_id}.
const (
	StatusPending = "pending"
	StatusStored  = "stored"
	StatusFailed  = "failed"
)

// Request is the body of POST /v1/escrow.
type Request struct {
	EscrowID   string `json:"escrow_id"` // UUID chosen by the device
	Kind       string `json:"kind"`
	Generation int64  `json:"generation"`
	KeyVersion int    `json:"key_version"` // version of escrow-wrap the ciphertext is wrapped with
	Ciphertext string `json:"ciphertext"`  // standard base64 RSA-OAEP-SHA256 ciphertext
}

// Accepted is the 202 body of POST /v1/escrow.
type Accepted struct {
	EscrowID string `json:"escrow_id"`
}

// Status is the body of GET /v1/escrow/{escrow_id}.
type Status struct {
	Status string `json:"status"`
}

// ParsePublicKey parses the PEM public key of escrow-wrap and accepts only RSA keys of at least 3072 bits.
func ParsePublicKey(pemKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("escrow: public key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("escrow: public key: %w", err)
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 3072 {
		return nil, errors.New("escrow: public key is not RSA with at least 3072 bits")
	}
	return pub, nil
}

// Encrypt wraps secret with RSA-OAEP and SHA-256 (no label) and returns the standard base64 ciphertext.
func Encrypt(pub *rsa.PublicKey, secret []byte) (string, error) {
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, secret, nil)
	if err != nil {
		return "", fmt.Errorf("escrow: encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

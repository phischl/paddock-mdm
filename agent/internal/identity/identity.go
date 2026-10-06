// Package identity holds the device signing key: ECDSA P-256, stored as PKCS#8 PEM with mode 0600 in a 0700
// directory (plan M2b decision 6, key protection "file").
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Key is the device identity.
type Key struct {
	Private *ecdsa.PrivateKey
	SPKI    []byte // SubjectPublicKeyInfo DER
	KeyID   string // hex SHA-256 of SPKI
}

func newKey(priv *ecdsa.PrivateKey) (Key, error) {
	spki, err := protocol.MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		return Key{}, err
	}
	return Key{Private: priv, SPKI: spki, KeyID: protocol.KeyID(spki)}, nil
}

// Load reads the key at path.
func Load(path string) (Key, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path of the agent layout
	if err != nil {
		return Key{}, fmt.Errorf("read identity key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return Key{}, fmt.Errorf("identity key %s is not a PKCS#8 PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Key{}, fmt.Errorf("parse identity key: %w", err)
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return Key{}, errors.New("identity key is not ECDSA P-256")
	}
	return newKey(priv)
}

// LoadOrCreate loads the key at path or, if there is none, generates and stores a new one.
func LoadOrCreate(path string) (Key, error) {
	k, err := Load(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return k, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Key{}, fmt.Errorf("generate identity key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Key{}, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := fsutil.WriteFile(path, data, 0o600, 0o700); err != nil {
		return Key{}, fmt.Errorf("store identity key: %w", err)
	}
	return newKey(priv)
}

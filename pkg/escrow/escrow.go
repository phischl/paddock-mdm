// Package escrow is the device side of secret escrow (architecture §12.2 and §12.4, plan M4a decisions 9–12, M4b
// decisions 10 and 13): the escrow-wrap public key from the bundle, RSA-OAEP with SHA-256 encryption of a secret to
// it, the sealing of LUKS headers (gzip, AES-256-GCM with a random key wrapped to escrow-wrap), and the request and
// status bodies of /v1/escrow. Only OpenBao (Transit key escrow-wrap) can unwrap.
package escrow

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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
	KindAdminPassword   = "admin_password"
	KindLUKSRecoveryKey = "luks_recovery_key"
	// KindLUKSHeader is a sealed LUKS header backup; it is uploaded to the escrow bucket with a presigned PUT, not
	// through the queue.
	KindLUKSHeader = "luks_header"
)

// Kinds are the kinds POST /v1/escrow accepts.
var Kinds = []string{KindAdminPassword, KindLUKSRecoveryKey, KindLUKSHeader}

// MaxCiphertext bounds a ciphertext (decoded).
const MaxCiphertext = 4 << 10

// Bounds of a sealed header: the uploaded object, and the header once unsealed (LUKS2 headers are 16 MiB by
// default).
const (
	MaxHeaderObject = 32 << 20
	MaxHeader       = 64 << 20
)

// HeaderNonceSize is the size of the AES-GCM nonce of a sealed header.
const HeaderNonceSize = 12

// Statuses of GET /v1/escrow/{escrow_id}.
const (
	StatusPending = "pending"
	StatusStored  = "stored"
	StatusFailed  = "failed"
)

// Request is the body of POST /v1/escrow. Secrets (admin_password, luks_recovery_key) carry Ciphertext; a header
// (luks_header) carries WrappedDEK, Nonce, SHA256 and Size of the sealed object instead and is uploaded to the URL
// of the answer.
type Request struct {
	EscrowID   string `json:"escrow_id"` // UUID chosen by the device
	Kind       string `json:"kind"`
	Generation int64  `json:"generation"`
	KeyVersion int    `json:"key_version"`           // version of escrow-wrap the ciphertext or the DEK is wrapped with
	Ciphertext string `json:"ciphertext,omitempty"`  // standard base64 RSA-OAEP-SHA256 ciphertext
	WrappedDEK string `json:"wrapped_dek,omitempty"` // standard base64 RSA-OAEP-SHA256 ciphertext of the header key
	Nonce      string `json:"nonce,omitempty"`       // standard base64 AES-GCM nonce of the header
	SHA256     string `json:"sha256,omitempty"`      // hex SHA-256 of the sealed header object
	Size       int64  `json:"size,omitempty"`        // bytes of the sealed header object
}

// Accepted is the 202 body of POST /v1/escrow. UploadURL is the presigned PUT of a header (valid 10 minutes).
type Accepted struct {
	EscrowID  string `json:"escrow_id"`
	UploadURL string `json:"upload_url,omitempty"`
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

// HeaderObjectKey is the object of a header generation in the escrow bucket (architecture §12.4); the server
// chooses it, the device only uploads to its presigned URL.
func HeaderObjectKey(org, device string, generation int64) string {
	return HeaderObjectPrefix(org, device) + fmt.Sprintf("%d.bin", generation)
}

// HeaderObjectPrefix is the prefix of every header generation of a device in the escrow bucket.
func HeaderObjectPrefix(org, device string) string {
	return fmt.Sprintf("org/%s/devices/%s/luks-header/", org, device)
}

// SealedHeader is a LUKS header backup sealed for escrow: Object is gzip(header) encrypted with AES-256-GCM under a
// random key (DEK) and the escrow ID as additional data; WrappedDEK is the DEK encrypted to escrow-wrap.
type SealedHeader struct {
	Object     []byte
	WrappedDEK string // standard base64
	Nonce      string // standard base64
	SHA256     string // hex SHA-256 of Object
}

// SealHeader seals a header backup for the escrow with ID escrowID. The DEK is zeroed before SealHeader returns.
func SealHeader(pub *rsa.PublicKey, header []byte, escrowID string) (SealedHeader, error) {
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	if _, err := zw.Write(header); err != nil {
		return SealedHeader{}, fmt.Errorf("escrow: compress header: %w", err)
	}
	if err := zw.Close(); err != nil {
		return SealedHeader{}, fmt.Errorf("escrow: compress header: %w", err)
	}
	dek := make([]byte, 32)
	defer clear(dek)
	nonce := make([]byte, HeaderNonceSize)
	if _, err := rand.Read(dek); err != nil {
		return SealedHeader{}, fmt.Errorf("escrow: header key: %w", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		return SealedHeader{}, fmt.Errorf("escrow: header nonce: %w", err)
	}
	gcm, err := headerAEAD(dek)
	if err != nil {
		return SealedHeader{}, err
	}
	object := gcm.Seal(nil, nonce, zipped.Bytes(), headerAAD(escrowID))
	clear(zipped.Bytes())
	wrapped, err := Encrypt(pub, dek)
	if err != nil {
		return SealedHeader{}, err
	}
	sum := sha256.Sum256(object)
	return SealedHeader{Object: object, WrappedDEK: wrapped, Nonce: base64.StdEncoding.EncodeToString(nonce),
		SHA256: hex.EncodeToString(sum[:])}, nil
}

// OpenHeader decrypts and decompresses a sealed header object with the unwrapped DEK; it fails if the object, the
// nonce or the escrow ID do not match.
func OpenHeader(dek, nonce []byte, escrowID string, object []byte) ([]byte, error) {
	gcm, err := headerAEAD(dek)
	if err != nil {
		return nil, err
	}
	if len(nonce) != HeaderNonceSize {
		return nil, errors.New("escrow: header nonce has the wrong size")
	}
	zipped, err := gcm.Open(nil, nonce, object, headerAAD(escrowID))
	if err != nil {
		return nil, fmt.Errorf("escrow: header does not decrypt: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("escrow: header: %w", err)
	}
	header, err := io.ReadAll(io.LimitReader(zr, MaxHeader+1))
	if err != nil {
		return nil, fmt.Errorf("escrow: header: %w", err)
	}
	if len(header) > MaxHeader {
		return nil, errors.New("escrow: header is larger than 64 MiB")
	}
	return header, nil
}

func headerAEAD(dek []byte) (cipher.AEAD, error) {
	if len(dek) != 32 {
		return nil, errors.New("escrow: header key must have 32 bytes")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// headerAAD binds a sealed header to its escrow ID, so that an object cannot pass for another generation.
func headerAAD(escrowID string) []byte { return []byte("paddock-luks-header:" + escrowID) }

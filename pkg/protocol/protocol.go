// Package protocol is the agent–server device protocol v1 (architecture §6.3, ADR 0004): request signature headers,
// the canonical string, signing and verification with ECDSA P-256, and the request and response bodies of the
// device API (api/openapi/device.yaml).
package protocol

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Signature headers.
const (
	HeaderDevice        = "Paddock-Device"
	HeaderKeyID         = "Paddock-Key-Id"
	HeaderTimestamp     = "Paddock-Timestamp"
	HeaderNonce         = "Paddock-Nonce"
	HeaderContentSHA256 = "Paddock-Content-SHA256"
	HeaderSeq           = "Paddock-Seq"
	HeaderSignature     = "Paddock-Signature"
)

// Version is the first line of the canonical string.
const Version = "paddock-v1"

// EnrollDevice is the Paddock-Device value of enrollment requests, which are signed with a key the server does not
// know yet.
const EnrollDevice = "enroll"

// MaxClockSkew is the accepted difference between Paddock-Timestamp and server time.
const MaxClockSkew = 300 * time.Second

var (
	// ErrMissingHeader means a signature header is absent.
	ErrMissingHeader = errors.New("protocol: missing signature header")
	// ErrMalformedHeader means a signature header has an invalid format.
	ErrMalformedHeader = errors.New("protocol: malformed signature header")
	// ErrClockSkew means the timestamp is outside MaxClockSkew.
	ErrClockSkew = errors.New("protocol: timestamp outside the accepted window")
	// ErrContentMismatch means Paddock-Content-SHA256 does not match the body.
	ErrContentMismatch = errors.New("protocol: content hash does not match the body")
	// ErrBadSignature means the signature does not verify.
	ErrBadSignature = errors.New("protocol: invalid signature")
	// ErrUnsupportedKey means the public key is not ECDSA P-256.
	ErrUnsupportedKey = errors.New("protocol: public key is not ECDSA P-256")
)

// Headers are the parsed signature headers of a request.
type Headers struct {
	Device        string // device ID (UUID) or EnrollDevice
	KeyID         string // KeyID of the signing key
	Timestamp     int64  // unix seconds
	Nonce         string // 16 random bytes, unpadded base64url
	ContentSHA256 string // unpadded base64url SHA-256 of the body
	Seq           int64  // last sequence number received from the server
	Signature     []byte // ASN.1 DER ECDSA signature
}

var (
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	b64Pattern   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	intPattern   = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
)

// ParseHeaders reads and validates the signature headers. It returns ErrMissingHeader or ErrMalformedHeader.
// Validation guarantees that no value can contain a line break, so the canonical string is unambiguous.
func ParseHeaders(h http.Header) (Headers, error) {
	names := []string{HeaderDevice, HeaderKeyID, HeaderTimestamp, HeaderNonce, HeaderContentSHA256, HeaderSeq, HeaderSignature}
	values := make(map[string]string, len(names))
	for _, n := range names {
		v := h.Values(n)
		if len(v) == 0 || v[0] == "" {
			return Headers{}, fmt.Errorf("%w: %s", ErrMissingHeader, n)
		}
		if len(v) > 1 {
			return Headers{}, fmt.Errorf("%w: %s repeated", ErrMalformedHeader, n)
		}
		values[n] = v[0]
	}
	out := Headers{
		Device: values[HeaderDevice], KeyID: values[HeaderKeyID], Nonce: values[HeaderNonce],
		ContentSHA256: values[HeaderContentSHA256],
	}
	malformed := func(name string) error { return fmt.Errorf("%w: %s", ErrMalformedHeader, name) }
	if out.Device != EnrollDevice && !uuidPattern.MatchString(out.Device) {
		return Headers{}, malformed(HeaderDevice)
	}
	if !keyIDPattern.MatchString(out.KeyID) {
		return Headers{}, malformed(HeaderKeyID)
	}
	var err error
	if out.Timestamp, err = parseInt(values[HeaderTimestamp]); err != nil {
		return Headers{}, malformed(HeaderTimestamp)
	}
	if !b64Pattern.MatchString(out.Nonce) || len(out.Nonce) != 22 {
		return Headers{}, malformed(HeaderNonce)
	}
	if !b64Pattern.MatchString(out.ContentSHA256) || len(out.ContentSHA256) != 43 {
		return Headers{}, malformed(HeaderContentSHA256)
	}
	if out.Seq, err = parseInt(values[HeaderSeq]); err != nil {
		return Headers{}, malformed(HeaderSeq)
	}
	if out.Signature, err = base64.RawURLEncoding.DecodeString(values[HeaderSignature]); err != nil || len(out.Signature) > 128 {
		return Headers{}, malformed(HeaderSignature)
	}
	return out, nil
}

func parseInt(s string) (int64, error) {
	if !intPattern.MatchString(s) {
		return 0, errors.New("not a non-negative integer")
	}
	return strconv.ParseInt(s, 10, 64)
}

// CanonicalString is the signed string: Version, method, path including query as sent, and the header values,
// separated by "\n" without a trailing newline.
func CanonicalString(method, pathQuery string, h Headers) string {
	return strings.Join([]string{
		Version, method, pathQuery, h.Device, h.KeyID, strconv.FormatInt(h.Timestamp, 10), h.Nonce, h.ContentSHA256,
		strconv.FormatInt(h.Seq, 10),
	}, "\n")
}

// ContentSHA256 is the Paddock-Content-SHA256 value of body.
func ContentSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// CheckTimestamp returns ErrClockSkew when h.Timestamp differs from now by more than MaxClockSkew.
func CheckTimestamp(h Headers, now time.Time) error {
	d := now.Unix() - h.Timestamp
	if d > int64(MaxClockSkew/time.Second) || d < -int64(MaxClockSkew/time.Second) {
		return ErrClockSkew
	}
	return nil
}

// Verify checks the content hash of body and the signature of the canonical string with pub.
func Verify(pub *ecdsa.PublicKey, method, pathQuery string, h Headers, body []byte) error {
	if ContentSHA256(body) != h.ContentSHA256 {
		return ErrContentMismatch
	}
	digest := sha256.Sum256([]byte(CanonicalString(method, pathQuery, h)))
	if !ecdsa.VerifyASN1(pub, digest[:], h.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Sign sets the signature headers on req for body. key MUST be an ECDSA P-256 signer (a file key or a TPM handle).
// The path including query is taken from req.URL as it will be sent.
func Sign(req *http.Request, body []byte, key crypto.Signer, device, keyID string, seq int64, now time.Time) error {
	nonce, err := NewNonce()
	if err != nil {
		return err
	}
	h := Headers{
		Device: device, KeyID: keyID, Timestamp: now.Unix(), Nonce: nonce, ContentSHA256: ContentSHA256(body), Seq: seq,
	}
	digest := sha256.Sum256([]byte(CanonicalString(req.Method, req.URL.RequestURI(), h)))
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("protocol: sign: %w", err)
	}
	req.Header.Set(HeaderDevice, h.Device)
	req.Header.Set(HeaderKeyID, h.KeyID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(h.Timestamp, 10))
	req.Header.Set(HeaderNonce, h.Nonce)
	req.Header.Set(HeaderContentSHA256, h.ContentSHA256)
	req.Header.Set(HeaderSeq, strconv.FormatInt(h.Seq, 10))
	req.Header.Set(HeaderSignature, base64.RawURLEncoding.EncodeToString(sig))
	return nil
}

// NewNonce returns 16 random bytes as unpadded base64url.
func NewNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("protocol: nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// MarshalPublicKey returns the SubjectPublicKeyInfo DER of pub.
func MarshalPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, ErrUnsupportedKey
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// ParsePublicKey parses a SubjectPublicKeyInfo DER and accepts only ECDSA P-256 keys.
func ParsePublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedKey, err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrUnsupportedKey
	}
	return pub, nil
}

// KeyID is the hex SHA-256 of the SubjectPublicKeyInfo DER.
func KeyID(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

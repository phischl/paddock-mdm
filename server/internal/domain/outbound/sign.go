package outbound

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
)

// Headers of a webhook call (ADR 0031 decision 13, plan M9 §6.4).
const (
	HeaderTimestamp   = "X-Paddock-Timestamp"
	HeaderSignature   = "X-Paddock-Signature"
	HeaderDelivery    = "X-Paddock-Delivery"
	HeaderDestination = "X-Paddock-Destination"
)

// secretBytes is the size of a destination's signing secret.
const secretBytes = 32

// Signature returns the value of X-Paddock-Signature: "v1=" and the hex HMAC-SHA256 with secret over the decimal
// timestamp, ".", and body.
func Signature(secret []byte, timestamp int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(timestamp, 10)))
	m.Write([]byte("."))
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

// NewSecret returns a new signing secret: 32 random bytes in base64url without padding (43 characters). The
// receiver uses the string as the HMAC key.
func NewSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("outbound: secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

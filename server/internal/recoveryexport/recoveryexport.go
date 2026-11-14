// Package recoveryexport builds the encrypted recovery export of an organization during the grace period of its
// deletion (plan M17 amendment b decisions 22 and 23; ADR 0052 amendment b decision 8): the recipient a requester
// supplies, the ASCII-armoured OpenPGP message the escrow-reader streams, and the JSON Lines inside it. A device line
// is appended from the decrypted bytes into a buffer the caller zeroes, so no secret is ever copied into an immutable
// string.
package recoveryexport

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"github.com/google/uuid"
)

// Recipient types of RecoveryExportRequest.recipient.
const (
	RecipientPublicKey  = "public_key"
	RecipientPassphrase = "passphrase"
)

// Bounds of the request (plan M17 amendment b decision 22) and the export limit per grace period (decision 21).
const (
	MaxPublicKeyBytes = 16 << 10
	MinPassphrase     = 16
	MaxPassphrase     = 1024
	MaxExports        = 5
)

// ContentType is the media type of the export (decision 23).
const ContentType = "application/pgp-encrypted"

// ErrInvalid is wrapped by every refusal of a recipient; its text never contains the key or the passphrase.
var ErrInvalid = errors.New("recoveryexport: invalid recipient")

// Recipient is who the export is encrypted to: an OpenPGP public key with an encryption-capable key, or a passphrase.
type Recipient struct {
	kind       string
	entity     *openpgp.Entity
	passphrase []byte
}

// ParseRecipient checks a recipient of the request. The passphrase is copied; Clear zeroes the copy.
func ParseRecipient(kind, publicKey, passphrase string) (Recipient, error) {
	switch kind {
	case RecipientPublicKey:
		if passphrase != "" {
			return Recipient{}, fmt.Errorf("%w: passphrase given for recipient public_key", ErrInvalid)
		}
		e, err := parsePublicKey(publicKey)
		if err != nil {
			return Recipient{}, err
		}
		return Recipient{kind: kind, entity: e}, nil
	case RecipientPassphrase:
		if publicKey != "" {
			return Recipient{}, fmt.Errorf("%w: public_key given for recipient passphrase", ErrInvalid)
		}
		if n := utf8.RuneCountInString(passphrase); !utf8.ValidString(passphrase) || n < MinPassphrase || n > MaxPassphrase {
			return Recipient{}, fmt.Errorf("%w: the passphrase must have %d to %d characters", ErrInvalid, MinPassphrase, MaxPassphrase)
		}
		return Recipient{kind: kind, passphrase: []byte(passphrase)}, nil
	default:
		return Recipient{}, fmt.Errorf("%w: recipient must be public_key or passphrase", ErrInvalid)
	}
}

func parsePublicKey(armored string) (*openpgp.Entity, error) {
	if armored == "" || len(armored) > MaxPublicKeyBytes {
		return nil, fmt.Errorf("%w: public_key must be an ASCII-armoured OpenPGP public key of at most %d bytes", ErrInvalid,
			MaxPublicKeyBytes)
	}
	// ReadArmoredKeyRing reads the first armour block only; a second one would be ignored silently.
	if strings.Count(armored, "-----BEGIN PGP ") != 1 {
		return nil, fmt.Errorf("%w: public_key must be exactly one ASCII-armoured OpenPGP public key block", ErrInvalid)
	}
	keys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("%w: public_key is no ASCII-armoured OpenPGP public key", ErrInvalid)
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("%w: public_key must contain exactly one key, it contains %d", ErrInvalid, len(keys))
	}
	if keys[0].PrivateKey != nil {
		return nil, fmt.Errorf("%w: public_key contains a private key; send the public key only", ErrInvalid)
	}
	if _, ok := keys[0].EncryptionKey(time.Now()); !ok {
		return nil, fmt.Errorf("%w: public_key has no valid encryption-capable key", ErrInvalid)
	}
	return keys[0], nil
}

// Kind is RecipientPublicKey or RecipientPassphrase.
func (r Recipient) Kind() string { return r.kind }

// Fingerprint is the uppercase hex fingerprint of the public key's primary key, "" for a passphrase.
func (r Recipient) Fingerprint() string {
	if r.entity == nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(r.entity.PrimaryKey.Fingerprint))
}

// Clear zeroes the copy of the passphrase.
func (r Recipient) Clear() { clear(r.passphrase) }

// config is AES-256 without compression. A passphrase is stretched with iterated and salted SHA-256 at the highest
// count OpenPGP can encode, not with Argon2 as plan M17 amendment b decision 23 names: GnuPG 2.4 (Ubuntu 24.04, the
// gate's runners) refuses S2K mode 4 ("unknown S2K mode 4"), and the export must open with plain gpg (decision 23,
// acceptance gate OF9). The passphrase has at least 16 characters (decision 22).
func config() *packet.Config {
	return &packet.Config{
		DefaultCipher: packet.CipherAES256,
		DefaultHash:   crypto.SHA256,
		S2KConfig:     &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA256, S2KCount: 65011712},
	}
}

// Encrypt returns the writer of the plaintext of one ASCII-armoured OpenPGP message to r, written to dst as it is
// produced. Close ends the message and its armour; a message that is not closed fails OpenPGP's integrity check.
func Encrypt(dst io.Writer, r Recipient) (io.WriteCloser, error) {
	arm, err := armor.Encode(dst, "PGP MESSAGE", nil)
	if err != nil {
		return nil, fmt.Errorf("recoveryexport: armour: %w", err)
	}
	hints := &openpgp.FileHints{IsBinary: true}
	var plain io.WriteCloser
	switch r.kind {
	case RecipientPublicKey:
		plain, err = openpgp.Encrypt(arm, []*openpgp.Entity{r.entity}, nil, hints, config())
	case RecipientPassphrase:
		plain, err = openpgp.SymmetricallyEncrypt(arm, r.passphrase, hints, config())
	default:
		err = errors.New("no recipient")
	}
	if err != nil {
		return nil, fmt.Errorf("recoveryexport: encrypt: %w", err)
	}
	return &message{plain: plain, arm: arm}, nil
}

type message struct {
	plain io.WriteCloser
	arm   io.WriteCloser
}

func (m *message) Write(p []byte) (int, error) { return m.plain.Write(p) }

func (m *message) Close() error {
	if err := m.plain.Close(); err != nil {
		return err
	}
	return m.arm.Close()
}

// Header is the first line of the plaintext.
type Header struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Slug           string    `json:"slug"`
	ExportedAt     string    `json:"exported_at"`
	Devices        int       `json:"devices"`
}

// NewHeader formats the export time as RFC 3339 in UTC.
func NewHeader(org uuid.UUID, slug string, at time.Time, devices int) Header {
	return Header{OrganizationID: org, Slug: slug, ExportedAt: at.UTC().Format(time.RFC3339), Devices: devices}
}

// AppendHeader appends the header line, newline included.
func AppendHeader(dst []byte, h Header) ([]byte, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return dst, err
	}
	return append(append(dst, b...), '\n'), nil
}

// Volume is one volume's recovery key; UUID is "" for a recovery key escrowed without a volume.
type Volume struct {
	UUID        string
	RecoveryKey []byte
}

// LocalAdmin is the managed local administrator and its newest escrowed password.
type LocalAdmin struct {
	Username string
	Password []byte
}

// Device is one device line.
type Device struct {
	ID         uuid.UUID
	Hostname   string
	Volumes    []Volume
	LocalAdmin *LocalAdmin
}

// AppendDevice appends the device line, newline included. The secrets are escaped from their bytes directly; the
// caller zeroes dst after writing it.
func AppendDevice(dst []byte, d Device) []byte {
	dst = append(dst, `{"device_id":`...)
	dst = appendString(dst, []byte(d.ID.String()))
	dst = append(dst, `,"hostname":`...)
	dst = appendString(dst, []byte(d.Hostname))
	dst = append(dst, `,"volumes":[`...)
	for i, v := range d.Volumes {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `{"uuid":`...)
		dst = appendString(dst, []byte(v.UUID))
		dst = append(dst, `,"recovery_key":`...)
		dst = appendString(dst, v.RecoveryKey)
		dst = append(dst, '}')
	}
	dst = append(dst, `],"local_admin":`...)
	if d.LocalAdmin == nil {
		dst = append(dst, `null`...)
	} else {
		dst = append(dst, `{"username":`...)
		dst = appendString(dst, []byte(d.LocalAdmin.Username))
		dst = append(dst, `,"password":`...)
		dst = appendString(dst, d.LocalAdmin.Password)
		dst = append(dst, '}')
	}
	return append(dst, "}\n"...)
}

// DeviceLineBound is the most bytes AppendDevice can append for d: every byte of a value escapes to at most six. A
// buffer of this capacity never grows while the line is appended.
func DeviceLineBound(d Device) int {
	n := 128 + 6*(len(d.ID.String())+len(d.Hostname))
	for _, v := range d.Volumes {
		n += 32 + 6*(len(v.UUID)+len(v.RecoveryKey))
	}
	if d.LocalAdmin != nil {
		n += 32 + 6*(len(d.LocalAdmin.Username)+len(d.LocalAdmin.Password))
	}
	return n
}

const hexDigits = "0123456789abcdef"

// appendString appends s as a JSON string. Invalid UTF-8 is replaced by U+FFFD, as encoding/json does.
func appendString(dst, s []byte) []byte {
	dst = append(dst, '"')
	for len(s) > 0 {
		c := s[0]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				dst = append(dst, '\\', c)
			case c < 0x20:
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			default:
				dst = append(dst, c)
			}
			s = s[1:]
			continue
		}
		r, size := utf8.DecodeRune(s)
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, `�`...)
		} else {
			dst = append(dst, s[:size]...)
		}
		s = s[size:]
	}
	return append(dst, '"')
}

// Package openpgpkey reads one OpenPGP v4 public key (RFC 4880, RFC 9580 algorithm identifiers) for display and
// validation of package source signing keys (plan M13a decision 3, amendment R6 item 3): fingerprint, algorithm, key
// size or curve, creation time, the advertised expiry and the user IDs.
//
// It is a parse-and-inspect reader only. It never verifies a signature: signature packets are bounded and skipped,
// and the few subpackets it reads from them are unverified claims. Whether a key is valid, unrevoked and unexpired is
// decided by apt or dnf on the device, which verify the repository signatures. Every length field and the input as a
// whole are bounded, so arbitrary input cannot make the reader allocate much or loop long.
package openpgpkey

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- the v4 fingerprint is defined as SHA-1 (RFC 4880 §12.2); no security decision rests on collision resistance here.
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrNotPublicKey is wrapped by every error the package returns: the input is not exactly one well-formed OpenPGP v4
// public key within the bounds below.
var ErrNotPublicKey = errors.New("openpgpkey: not an OpenPGP v4 public key")

// Bounds on the input. MaxInput equals the 65 536-byte limit on a source's signing_key (plan M13a decision 2): a
// typical vendor key is 1–10 KiB armored, so 64 KiB leaves room for many third-party certifications while keeping the
// work per request small. The binary form is bounded by the same number.
const (
	MaxInput         = 64 << 10
	MaxPackets       = 512
	MaxUserIDs       = 32
	MaxUserIDLen     = 1024
	MaxSubkeys       = 32
	MaxMPIBits       = 16384
	MaxSubpackets    = 128
	maxArmorHeaders  = 16
	maxKeyPacketBody = 0xFFFF
)

// Algorithm names a public-key algorithm as it is shown to administrators.
type Algorithm string

// Public-key algorithms the reader accepts.
const (
	RSA     Algorithm = "RSA"
	DSA     Algorithm = "DSA"
	ElGamal Algorithm = "ElGamal"
	ECDH    Algorithm = "ECDH"
	ECDSA   Algorithm = "ECDSA"
	EdDSA   Algorithm = "EdDSA"
	X25519  Algorithm = "X25519"
	X448    Algorithm = "X448"
	Ed25519 Algorithm = "Ed25519"
	Ed448   Algorithm = "Ed448"
)

// Key is the inspected primary key of a transferable public key.
type Key struct {
	// Fingerprint is the v4 fingerprint as 40 uppercase hexadecimal characters.
	Fingerprint string
	Algorithm   Algorithm
	// Bits is the modulus or prime size for RSA, DSA and ElGamal; zero for elliptic-curve keys.
	Bits int
	// Curve names the curve of an elliptic-curve key; empty otherwise.
	Curve   string
	Created time.Time
	// Expires is the key expiration the newest self-certification of the primary user ID advertises, nil when it
	// advertises none. The signature carrying it is NOT verified: the value is display-only and must never gate a
	// security decision.
	Expires *time.Time
	// UserIDs lists the user IDs in packet order; invalid UTF-8 is replaced with U+FFFD.
	UserIDs []string
	// Subkeys is the number of public subkeys.
	Subkeys int
	// Keyring is the binary (dearmored) transferable public key, exactly as read.
	Keyring []byte
}

// Fingerprint reads an ASCII-armored public key block and returns its fingerprint and binary keyring (plan M13a
// §6.4).
func Fingerprint(armored []byte) (fingerprint string, keyring []byte, err error) {
	if !isArmored(armored) {
		return "", nil, notKey("input is not ASCII-armored")
	}
	k, err := Parse(armored)
	if err != nil {
		return "", nil, err
	}
	return k.Fingerprint, k.Keyring, nil
}

// FingerprintBinary reads a binary transferable public key and returns its fingerprint (plan M13a §6.4).
func FingerprintBinary(keyring []byte) (fingerprint string, err error) {
	if isArmored(keyring) {
		return "", notKey("input is ASCII-armored, binary expected")
	}
	k, err := Parse(keyring)
	if err != nil {
		return "", err
	}
	return k.Fingerprint, nil
}

// Parse reads exactly one OpenPGP v4 transferable public key, ASCII-armored or binary. Only public-key, user ID, user
// attribute, signature and public-subkey packets of version 4 are accepted; anything else, including secret keys and
// v3, v5 or v6 packets, is an error wrapping ErrNotPublicKey.
func Parse(data []byte) (*Key, error) {
	if len(data) > MaxInput {
		return nil, notKey(fmt.Sprintf("input exceeds %d bytes", MaxInput))
	}
	raw := data
	if isArmored(data) {
		var err error
		if raw, err = dearmor(data); err != nil {
			return nil, err
		}
	}
	return parsePackets(raw)
}

func notKey(reason string) error {
	return fmt.Errorf("%w: %s", ErrNotPublicKey, reason)
}

func isArmored(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("-----BEGIN "))
}

const (
	armorBegin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	armorEnd   = "-----END PGP PUBLIC KEY BLOCK-----"
)

// dearmor decodes a single public key block (RFC 4880 §6.2). Only whitespace may surround it, so a second block or
// a pasted secret key next to it is refused rather than silently ignored.
func dearmor(data []byte) ([]byte, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t\r")
	}
	if lines[0] != armorBegin {
		return nil, notKey("armor header is not " + armorBegin)
	}
	if len(lines) < 2 || lines[len(lines)-1] != armorEnd {
		return nil, notKey("armor tail " + armorEnd + " missing")
	}
	body := lines[1 : len(lines)-1]
	headers := 0
	for len(body) > 0 && strings.Contains(body[0], ": ") {
		if headers++; headers > maxArmorHeaders {
			return nil, notKey("too many armor headers")
		}
		body = body[1:]
	}
	if len(body) > 0 && body[0] == "" {
		body = body[1:]
	}
	var crc string
	if n := len(body); n > 0 && strings.HasPrefix(body[n-1], "=") {
		crc, body = body[n-1][1:], body[:n-1]
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(body, ""))
	if err != nil {
		return nil, notKey("armor body is not base64")
	}
	if crc != "" {
		sum, err := base64.StdEncoding.DecodeString(crc)
		if err != nil || len(sum) != 3 {
			return nil, notKey("malformed armor checksum")
		}
		if uint32(sum[0])<<16|uint32(sum[1])<<8|uint32(sum[2]) != crc24(raw) {
			return nil, notKey("armor checksum mismatch")
		}
	}
	return raw, nil
}

// crc24 is the armor checksum of RFC 4880 §6.1.
func crc24(data []byte) uint32 {
	const (
		init24 = 0xB704CE
		poly24 = 0x1864CFB
	)
	crc := uint32(init24)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for range 8 {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= poly24
			}
		}
	}
	return crc & 0xFFFFFF
}

const (
	tagSignature     = 2
	tagSecretKey     = 5
	tagPublicKey     = 6
	tagSecretSubkey  = 7
	tagUserID        = 13
	tagPublicSubkey  = 14
	tagUserAttribute = 17
)

type packet struct {
	tag  int
	body []byte
}

// nextPacket splits one packet off data (RFC 4880 §4.2). Partial and indeterminate lengths are refused: no packet a
// transferable public key may contain uses them.
func nextPacket(data []byte) (packet, []byte, error) {
	if len(data) == 0 {
		return packet{}, nil, notKey("truncated packet header")
	}
	h := data[0]
	if h&0x80 == 0 {
		return packet{}, nil, notKey("invalid packet header")
	}
	var tag, n int
	rest := data[1:]
	if h&0x40 == 0 {
		tag = int(h>>2) & 0x0F
		switch h & 0x03 {
		case 0:
			if len(rest) < 1 {
				return packet{}, nil, notKey("truncated packet length")
			}
			n, rest = int(rest[0]), rest[1:]
		case 1:
			if len(rest) < 2 {
				return packet{}, nil, notKey("truncated packet length")
			}
			n, rest = int(binary.BigEndian.Uint16(rest)), rest[2:]
		case 2:
			if len(rest) < 4 {
				return packet{}, nil, notKey("truncated packet length")
			}
			l := binary.BigEndian.Uint32(rest)
			if l > MaxInput {
				return packet{}, nil, notKey("packet length out of bounds")
			}
			n, rest = int(l), rest[4:]
		default:
			return packet{}, nil, notKey("indeterminate packet length")
		}
	} else {
		tag = int(h & 0x3F)
		if len(rest) < 1 {
			return packet{}, nil, notKey("truncated packet length")
		}
		switch l := rest[0]; {
		case l < 192:
			n, rest = int(l), rest[1:]
		case l < 224:
			if len(rest) < 2 {
				return packet{}, nil, notKey("truncated packet length")
			}
			n, rest = (int(l)-192)<<8+int(rest[1])+192, rest[2:]
		case l == 255:
			if len(rest) < 5 {
				return packet{}, nil, notKey("truncated packet length")
			}
			v := binary.BigEndian.Uint32(rest[1:])
			if v > MaxInput {
				return packet{}, nil, notKey("packet length out of bounds")
			}
			n, rest = int(v), rest[5:]
		default:
			return packet{}, nil, notKey("partial packet length")
		}
	}
	if n > len(rest) {
		return packet{}, nil, notKey("truncated packet body")
	}
	return packet{tag: tag, body: rest[:n]}, rest[n:], nil
}

// selfCert is the part of a user ID certification the reader looks at; none of it is verified.
type selfCert struct {
	created time.Time
	expiry  uint32
	primary bool
}

// section is the part of a transferable public key a signature packet attaches to (RFC 4880 §11.1).
type section int

const (
	sectionPrimary section = iota
	sectionUser
	sectionAttribute
	sectionSubkey
)

type userID struct {
	best *selfCert
}

func parsePackets(raw []byte) (*Key, error) {
	if len(raw) > MaxInput {
		return nil, notKey(fmt.Sprintf("key exceeds %d bytes", MaxInput))
	}
	first, rest, err := nextPacket(raw)
	if err != nil {
		return nil, err
	}
	if first.tag != tagPublicKey {
		return nil, unexpectedTag(first.tag)
	}
	k := &Key{}
	if err := inspectKeyMaterial(first.body, true, k); err != nil {
		return nil, err
	}
	fp := v4Fingerprint(first.body)
	k.Fingerprint = strings.ToUpper(hex.EncodeToString(fp))

	var uids []userID
	sec := sectionPrimary
	for packets := 1; len(rest) > 0; {
		if packets++; packets > MaxPackets {
			return nil, notKey(fmt.Sprintf("more than %d packets", MaxPackets))
		}
		var p packet
		if p, rest, err = nextPacket(rest); err != nil {
			return nil, err
		}
		switch p.tag {
		case tagUserID:
			if sec == sectionSubkey {
				return nil, notKey("user ID after a subkey")
			}
			if len(k.UserIDs) == MaxUserIDs {
				return nil, notKey(fmt.Sprintf("more than %d user IDs", MaxUserIDs))
			}
			if len(p.body) == 0 || len(p.body) > MaxUserIDLen {
				return nil, notKey(fmt.Sprintf("user ID length outside 1..%d", MaxUserIDLen))
			}
			k.UserIDs = append(k.UserIDs, toValidUTF8(p.body))
			uids = append(uids, userID{})
			sec = sectionUser
		case tagUserAttribute:
			if sec == sectionSubkey {
				return nil, notKey("user attribute after a subkey")
			}
			sec = sectionAttribute
		case tagPublicSubkey:
			if k.Subkeys == MaxSubkeys {
				return nil, notKey(fmt.Sprintf("more than %d subkeys", MaxSubkeys))
			}
			if err := inspectKeyMaterial(p.body, false, nil); err != nil {
				return nil, err
			}
			k.Subkeys++
			sec = sectionSubkey
		case tagSignature:
			sig, err := inspectSignature(p.body, fp)
			if err != nil {
				return nil, err
			}
			if sec == sectionUser && sig != nil {
				u := &uids[len(uids)-1]
				if u.best == nil || !sig.created.Before(u.best.created) {
					u.best = sig
				}
			}
		default:
			return nil, unexpectedTag(p.tag)
		}
	}
	if len(k.UserIDs) == 0 {
		return nil, notKey("no user ID")
	}
	if cert := primaryCert(uids); cert != nil && cert.expiry != 0 {
		exp := k.Created.Add(time.Duration(cert.expiry) * time.Second)
		k.Expires = &exp
	}
	k.Keyring = raw
	return k, nil
}

func unexpectedTag(tag int) error {
	switch tag {
	case tagSecretKey, tagSecretSubkey:
		return notKey("secret key material is refused")
	default:
		return notKey(fmt.Sprintf("unexpected packet tag %d", tag))
	}
}

// primaryCert picks the newest self-certification that claims the primary user ID flag, else the newest
// self-certification of the first certified user ID (the choice RFC 4880 §5.2.3.19 suggests).
func primaryCert(uids []userID) *selfCert {
	var flagged, first *selfCert
	for _, u := range uids {
		if u.best == nil {
			continue
		}
		if first == nil {
			first = u.best
		}
		if u.best.primary && (flagged == nil || u.best.created.After(flagged.created)) {
			flagged = u.best
		}
	}
	if flagged != nil {
		return flagged
	}
	return first
}

func toValidUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}

func v4Fingerprint(body []byte) []byte {
	h := sha1.New() // #nosec G401 -- see the import.
	hdr := []byte{0x99, 0, 0}
	binary.BigEndian.PutUint16(hdr[1:], uint16(len(body))) // #nosec G115 -- inspectKeyMaterial bounds the body to 0xFFFF bytes.
	h.Write(hdr)
	h.Write(body)
	return h.Sum(nil)
}

// Public-key algorithm identifiers (RFC 9580 §9.1).
const (
	algRSA         = 1
	algRSAEncrypt  = 2
	algRSASign     = 3
	algElGamal     = 16
	algDSA         = 17
	algECDH        = 18
	algECDSA       = 19
	algEdDSALegacy = 22
	algX25519      = 25
	algX448        = 26
	algEd25519     = 27
	algEd448       = 28
)

// curveName maps the DER-encoded curve OIDs GnuPG and RFC 9580 use to display names.
func curveName(oid string) (string, bool) {
	switch oid {
	case "\x2a\x86\x48\xce\x3d\x03\x01\x07":
		return "NIST P-256", true
	case "\x2b\x81\x04\x00\x22":
		return "NIST P-384", true
	case "\x2b\x81\x04\x00\x23":
		return "NIST P-521", true
	case "\x2b\x81\x04\x00\x0a":
		return "secp256k1", true
	case "\x2b\x24\x03\x03\x02\x08\x01\x01\x07":
		return "brainpoolP256r1", true
	case "\x2b\x24\x03\x03\x02\x08\x01\x01\x0b":
		return "brainpoolP384r1", true
	case "\x2b\x24\x03\x03\x02\x08\x01\x01\x0d":
		return "brainpoolP512r1", true
	case "\x2b\x06\x01\x04\x01\xda\x47\x0f\x01":
		return "Ed25519", true
	case "\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01":
		return "Curve25519", true
	case "\x2b\x65\x71":
		return "Ed448", true
	case "\x2b\x65\x6f":
		return "X448", true
	}
	return "", false
}

// inspectKeyMaterial checks a v4 public-key or public-subkey packet body (RFC 4880 §5.5.2) and, for the primary key,
// fills the algorithm fields of k. The algorithm-specific fields must consume the body exactly.
func inspectKeyMaterial(body []byte, primary bool, k *Key) error {
	if len(body) < 1 {
		return notKey("empty key packet")
	}
	if body[0] != 4 {
		return notKey(fmt.Sprintf("key packet version %d is not 4", body[0]))
	}
	if len(body) > maxKeyPacketBody {
		return notKey("key packet too long")
	}
	if len(body) < 6 {
		return notKey("truncated key packet")
	}
	created := time.Unix(int64(binary.BigEndian.Uint32(body[1:5])), 0).UTC()
	alg := body[5]
	r := reader{b: body[6:]}
	var name Algorithm
	var size int
	var curve string
	switch alg {
	case algRSA, algRSAEncrypt, algRSASign:
		name = RSA
		size = bitLen(r.mpi())
		r.mpi()
	case algDSA:
		name = DSA
		size = bitLen(r.mpi())
		r.mpi()
		r.mpi()
		r.mpi()
	case algElGamal:
		name = ElGamal
		size = bitLen(r.mpi())
		r.mpi()
		r.mpi()
	case algECDH, algECDSA, algEdDSALegacy:
		switch alg {
		case algECDH:
			name = ECDH
		case algECDSA:
			name = ECDSA
		default:
			name = EdDSA
		}
		curve = r.oid()
		r.mpi()
		if alg == algECDH {
			// KDF parameters: length 3, reserved 0x01, hash and cipher identifiers (RFC 9580 §11.5).
			if l := r.byte(); l != 3 {
				r.fail("ECDH KDF parameters")
			}
			r.take(3)
		}
	case algX25519:
		name = X25519
		r.take(32)
	case algX448:
		name = X448
		r.take(56)
	case algEd25519:
		name = Ed25519
		r.take(32)
	case algEd448:
		name = Ed448
		r.take(57)
	default:
		return notKey(fmt.Sprintf("unsupported public-key algorithm %d", alg))
	}
	if r.err != nil {
		return r.err
	}
	if len(r.b) != 0 {
		return notKey("trailing bytes in key packet")
	}
	if primary {
		switch alg {
		case algRSAEncrypt, algElGamal, algECDH, algX25519, algX448:
			return notKey(fmt.Sprintf("encryption-only algorithm %s as primary key", name))
		}
		k.Algorithm, k.Bits, k.Curve, k.Created = name, size, curve, created
	}
	return nil
}

// Signature subpacket types (RFC 9580 §5.2.3.7).
const (
	subCreated        = 2
	subKeyExpiry      = 9
	subIssuerKeyID    = 16
	subPrimaryUserID  = 25
	subIssuerFP       = 33
	sigCertGeneric    = 0x10
	sigCertPositive   = 0x13
	issuerFPVersion4  = 4
	issuerFPV4Len     = 21
	keyIDLen          = 8
	subpacketTypeMask = 0x7F
)

// inspectSignature bounds a signature packet and, for a user ID certification that names the primary key as issuer,
// returns the unverified creation time, key expiration and primary user ID flag from its hashed area. It returns nil
// for every other signature. The algorithm-specific signature values are skipped unparsed.
func inspectSignature(body []byte, fp []byte) (*selfCert, error) {
	if len(body) < 1 {
		return nil, notKey("empty signature packet")
	}
	if body[0] != 4 {
		return nil, notKey(fmt.Sprintf("signature packet version %d is not 4", body[0]))
	}
	r := reader{b: body[1:]}
	sigType := r.byte()
	r.take(2)
	hashed := r.take(int(r.uint16()))
	unhashed := r.take(int(r.uint16()))
	r.take(2)
	if r.err != nil {
		return nil, r.err
	}
	cert := &selfCert{}
	issuer := false
	keyID := fp[len(fp)-keyIDLen:]
	err := walkSubpackets(hashed, func(typ byte, v []byte) {
		switch typ {
		case subCreated:
			if len(v) == 4 {
				cert.created = time.Unix(int64(binary.BigEndian.Uint32(v)), 0)
			}
		case subKeyExpiry:
			if len(v) == 4 {
				cert.expiry = binary.BigEndian.Uint32(v)
			}
		case subPrimaryUserID:
			cert.primary = len(v) == 1 && v[0] != 0
		case subIssuerFP:
			issuer = issuer || (len(v) == issuerFPV4Len && v[0] == issuerFPVersion4 && bytes.Equal(v[1:], fp))
		case subIssuerKeyID:
			issuer = issuer || bytes.Equal(v, keyID)
		}
	})
	if err != nil {
		return nil, err
	}
	err = walkSubpackets(unhashed, func(typ byte, v []byte) {
		if typ == subIssuerKeyID {
			issuer = issuer || bytes.Equal(v, keyID)
		}
	})
	if err != nil {
		return nil, err
	}
	if sigType < sigCertGeneric || sigType > sigCertPositive || !issuer {
		return nil, nil
	}
	return cert, nil
}

// walkSubpackets calls fn for each subpacket of one area (RFC 4880 §5.2.3.1).
func walkSubpackets(area []byte, fn func(typ byte, value []byte)) error {
	for n := 0; len(area) > 0; n++ {
		if n == MaxSubpackets {
			return notKey(fmt.Sprintf("more than %d subpackets", MaxSubpackets))
		}
		var l int
		switch first := area[0]; {
		case first < 192:
			l, area = int(first), area[1:]
		case first < 255:
			if len(area) < 2 {
				return notKey("truncated subpacket length")
			}
			l, area = (int(first)-192)<<8+int(area[1])+192, area[2:]
		default:
			if len(area) < 5 {
				return notKey("truncated subpacket length")
			}
			v := binary.BigEndian.Uint32(area[1:])
			if v > MaxInput {
				return notKey("subpacket length out of bounds")
			}
			l, area = int(v), area[5:]
		}
		if l == 0 || l > len(area) {
			return notKey("subpacket length out of bounds")
		}
		fn(area[0]&subpacketTypeMask, area[1:l])
		area = area[l:]
	}
	return nil
}

// reader consumes a packet body; the first failure sticks and every later read returns zero values.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail(what string) {
	if r.err == nil {
		r.err = notKey("malformed " + what)
	}
	r.b = nil
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b) {
		r.fail("packet field")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) byte() byte {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) uint16() uint16 {
	if v := r.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

// bitLen returns the significant bit length of a big-endian unsigned integer.
func bitLen(v []byte) int {
	for len(v) > 0 && v[0] == 0 {
		v = v[1:]
	}
	if len(v) == 0 {
		return 0
	}
	return (len(v)-1)*8 + bits.Len8(v[0])
}

// mpi reads a multiprecision integer (RFC 4880 §3.2), at most MaxMPIBits long.
func (r *reader) mpi() []byte {
	n := int(r.uint16())
	if r.err != nil {
		return nil
	}
	if n == 0 || n > MaxMPIBits {
		r.fail("MPI length")
		return nil
	}
	return r.take((n + 7) / 8)
}

// oid reads a curve OID (RFC 9580 §5.5.5.4); lengths 0 and 0xFF are reserved.
func (r *reader) oid() string {
	n := int(r.byte())
	if r.err != nil {
		return ""
	}
	if n == 0 || n == 0xFF {
		r.fail("curve OID")
		return ""
	}
	name, ok := curveName(string(r.take(n)))
	if r.err == nil && !ok {
		r.err = notKey("unsupported curve")
	}
	return name
}

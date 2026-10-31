package openpgpkey_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
)

// Fingerprints as `gpg --show-keys --with-colons` prints them for the fixtures (GnuPG 2.4.4).
const (
	himmelblauFP = "E87FD8D463A5E4814B9CDBA90CC0D4002C425E03"
	rsaFP        = "7149256BEC1A7DB713A95C7366280043EC88781E"
	ed25519FP    = "8A367815ED9674ED9013609A8F03DFF0EB10E2E4"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unix(sec int64) *time.Time {
	v := time.Unix(sec, 0).UTC()
	return &v
}

func TestParseFixtures(t *testing.T) {
	tests := []struct {
		file    string
		want    openpgpkey.Key
		armored bool
	}{
		{
			file: "himmelblau.gpg",
			want: openpgpkey.Key{
				Fingerprint: himmelblauFP, Params: openpgpkey.Params{Algorithm: openpgpkey.RSA, Bits: 4096},
				Created: *unix(1761166251), Expires: unix(1824238251),
				UserIDs: []string{"Himmelblau Build (2025) <build@himmelblau-idm.org>"},
			},
		},
		{
			file: "rsa.asc", armored: true,
			want: openpgpkey.Key{
				Fingerprint: rsaFP, Params: openpgpkey.Params{Algorithm: openpgpkey.RSA, Bits: 3072},
				Created: *unix(1793479615), Expires: unix(1893495600),
				UserIDs: []string{"Paddock Test RSA <rsa@example.invalid>"},
				Subkeys: []openpgpkey.Params{{Algorithm: openpgpkey.RSA, Bits: 2048}},
			},
		},
		{
			file: "rsa.gpg",
			want: openpgpkey.Key{
				Fingerprint: rsaFP, Params: openpgpkey.Params{Algorithm: openpgpkey.RSA, Bits: 3072},
				Created: *unix(1793479615), Expires: unix(1893495600),
				UserIDs: []string{"Paddock Test RSA <rsa@example.invalid>"},
				Subkeys: []openpgpkey.Params{{Algorithm: openpgpkey.RSA, Bits: 2048}},
			},
		},
		{
			file: "ed25519.asc", armored: true,
			want: openpgpkey.Key{
				Fingerprint: ed25519FP, Params: openpgpkey.Params{Algorithm: openpgpkey.EdDSA, Curve: "Ed25519"},
				Created: *unix(1793479615),
				UserIDs: []string{"Paddock Test Ed25519 <ed25519@example.invalid>", "Second UID <second@example.invalid>"},
				Subkeys: []openpgpkey.Params{{Algorithm: openpgpkey.ECDH, Curve: "Curve25519"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data := fixture(t, tt.file)
			k, err := openpgpkey.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.armored && !bytes.Equal(k.Keyring, data) {
				t.Error("binary input: keyring differs from input")
			}
			got := *k
			got.Keyring = nil
			if got.Fingerprint != tt.want.Fingerprint || got.Algorithm != tt.want.Algorithm ||
				got.Bits != tt.want.Bits || got.Curve != tt.want.Curve || !got.Created.Equal(tt.want.Created) ||
				!slices.Equal(shapes(got.Subkeys), shapes(tt.want.Subkeys)) || strings.Join(got.UserIDs, "|") != strings.Join(tt.want.UserIDs, "|") {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			switch {
			case tt.want.Expires == nil && got.Expires != nil:
				t.Errorf("Expires = %v, want none", got.Expires)
			case tt.want.Expires != nil && (got.Expires == nil || !got.Expires.Equal(*tt.want.Expires)):
				t.Errorf("Expires = %v, want %v", got.Expires, tt.want.Expires)
			}
		})
	}
}

// shapes reduces parameters to algorithm, size and curve, the part the fixture table states.
func shapes(ps []openpgpkey.Params) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s/%d/%s", p.Algorithm, p.Bits, p.Curve))
	}
	return out
}

func TestRSAAndKDFParametersExposed(t *testing.T) {
	k, err := openpgpkey.Parse(fixture(t, "rsa.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.RSAExponent, []byte{1, 0, 1}) || len(k.RSAModulus) != 384 || k.RSAModulus[0]&0x80 == 0 {
		t.Errorf("RSA e = %x, n of %d bytes", k.RSAExponent, len(k.RSAModulus))
	}
	k, err = openpgpkey.Parse(fixture(t, "ed25519.asc"))
	if err != nil {
		t.Fatal(err)
	}
	// GnuPG's defaults for a Curve25519 subkey: SHA-256 (8) and AES-128 (7).
	if sub := k.Subkeys[0]; sub.KDFHash != 8 || sub.KDFCipher != 7 || sub.RSAModulus != nil {
		t.Errorf("ECDH subkey KDF = %d/%d", sub.KDFHash, sub.KDFCipher)
	}
}

func TestArmoredAndBinaryAgree(t *testing.T) {
	fp, keyring, err := openpgpkey.Fingerprint(fixture(t, "rsa.asc"))
	if err != nil {
		t.Fatal(err)
	}
	if fp != rsaFP || !bytes.Equal(keyring, fixture(t, "rsa.gpg")) {
		t.Errorf("Fingerprint = %s and keyring of %d bytes, want %s and rsa.gpg", fp, len(keyring), rsaFP)
	}
	fp, err = openpgpkey.FingerprintBinary(fixture(t, "himmelblau.gpg"))
	if err != nil || fp != himmelblauFP {
		t.Errorf("FingerprintBinary = %s, %v; want %s", fp, err, himmelblauFP)
	}
}

func TestEntryPointsRefuseTheOtherEncoding(t *testing.T) {
	if _, _, err := openpgpkey.Fingerprint(fixture(t, "rsa.gpg")); !errors.Is(err, openpgpkey.ErrNotPublicKey) {
		t.Errorf("Fingerprint(binary) err = %v", err)
	}
	if _, err := openpgpkey.FingerprintBinary(fixture(t, "rsa.asc")); !errors.Is(err, openpgpkey.ErrNotPublicKey) {
		t.Errorf("FingerprintBinary(armored) err = %v", err)
	}
}

func TestArmorVariantsAccepted(t *testing.T) {
	asc := string(fixture(t, "rsa.asc"))
	lines := strings.Split(strings.TrimSpace(asc), "\n")
	withoutCRC := strings.Join(append(append([]string{}, lines[:len(lines)-2]...), lines[len(lines)-1]), "\n")
	withHeader := strings.Replace(asc, "-----\n", "-----\nComment: vendor key\nVersion: test\n", 1)
	for name, in := range map[string]string{
		"crlf":           strings.ReplaceAll(asc, "\n", "\r\n"),
		"no checksum":    withoutCRC,
		"armor headers":  withHeader,
		"surrounding ws": "\n\t " + asc + "\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			k, err := openpgpkey.Parse([]byte(in))
			if err != nil || k.Fingerprint != rsaFP {
				t.Errorf("Parse = %v, %v", k, err)
			}
		})
	}
}

// Synthetic packet builders: only shapes matter here, no signature is valid.

func pkt(tag byte, body []byte) []byte {
	out := []byte{0xC0 | tag, 255, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[2:], uint32(len(body)))
	return append(out, body...)
}

func keyBody(version, alg byte, material []byte) []byte {
	return append([]byte{version, 0x60, 0, 0, 0, alg}, material...)
}

func ed25519Key(version byte) []byte {
	return pkt(6, keyBody(version, 27, make([]byte, 32)))
}

func sub(typ byte, v ...byte) []byte {
	return append([]byte{byte(len(v) + 1), typ}, v...)
}

func sig(version, sigType byte, hashed, unhashed []byte) []byte {
	b := []byte{version, sigType, 27, 10, byte(len(hashed) >> 8), byte(len(hashed))}
	b = append(b, hashed...)
	b = append(b, byte(len(unhashed)>>8), byte(len(unhashed)))
	b = append(b, unhashed...)
	return pkt(2, append(b, 0, 0))
}

func uid(s string) []byte { return pkt(13, []byte(s)) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func syntheticFP(t *testing.T) []byte {
	t.Helper()
	k, err := openpgpkey.Parse(cat(ed25519Key(4), uid("a")))
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := hex.DecodeString(k.Fingerprint)
	return fp
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func TestExpiryFromPrimaryUserIDSelfCertification(t *testing.T) {
	fp := syntheticFP(t)
	issuerFP := sub(33, append([]byte{4}, fp...)...)
	issuerID := sub(16, fp[12:]...)
	created := int64(0x60000000)
	cert := func(sigCreated, expiry uint32, primary bool, issuer []byte) []byte {
		h := cat(sub(2, u32(sigCreated)...), sub(9, u32(expiry)...))
		if primary {
			h = append(h, sub(25, 1)...)
		}
		return sig(4, 0x13, cat(h, issuer), nil)
	}
	tests := []struct {
		name string
		key  []byte
		want *time.Time
	}{
		{"first user ID without primary flag", cat(ed25519Key(4), uid("a"), cert(1, 100, false, issuerFP), uid("b"), cert(1, 200, false, issuerFP)), unix(created + 100)},
		{"flagged user ID wins", cat(ed25519Key(4), uid("a"), cert(1, 100, false, issuerFP), uid("b"), cert(1, 200, true, issuerFP)), unix(created + 200)},
		{"newest certification wins", cat(ed25519Key(4), uid("a"), cert(5, 300, false, issuerFP), cert(1, 100, false, issuerFP)), unix(created + 300)},
		{"issuer key ID in the unhashed area", cat(ed25519Key(4), uid("a"), sig(4, 0x10, cat(sub(2, u32(1)...), sub(9, u32(50)...)), issuerID)), unix(created + 50)},
		{"third-party certification ignored", cat(ed25519Key(4), uid("a"), cert(1, 100, false, sub(16, 1, 2, 3, 4, 5, 6, 7, 8))), nil},
		{"direct-key signature ignored", cat(ed25519Key(4), sig(4, 0x1F, cat(sub(9, u32(10)...), issuerFP), nil), uid("a")), nil},
		{"zero means no expiry", cat(ed25519Key(4), uid("a"), cert(1, 0, false, issuerFP)), nil},
		{"user attribute certification does not attach to the user ID", cat(ed25519Key(4), uid("a"), pkt(17, []byte{1, 2, 3}), cert(1, 100, false, issuerFP)), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := openpgpkey.Parse(tt.key)
			if err != nil {
				t.Fatal(err)
			}
			if (tt.want == nil) != (k.Expires == nil) || (tt.want != nil && !tt.want.Equal(*k.Expires)) {
				t.Errorf("Expires = %v, want %v", k.Expires, tt.want)
			}
		})
	}
}

// mpi encodes an MPI of exactly the given bit length.
func mpi(bits int) []byte {
	b := make([]byte, (bits+7)/8)
	b[0] = 0x80 >> ((8 - bits%8) % 8)
	return append([]byte{byte(bits >> 8), byte(bits)}, b...)
}

// Curve OIDs with their length octet (RFC 9580 §9.2).
var (
	p256       = []byte{8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	secp256k1  = []byte{5, 0x2b, 0x81, 0x04, 0x00, 0x0a}
	brainpool  = []byte{9, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}
	ed25519OID = []byte{9, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}
	cv25519OID = []byte{10, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}
	ed448OID   = []byte{3, 0x2b, 0x65, 0x71}
	x448OID    = []byte{3, 0x2b, 0x65, 0x6f}
)

func ecKey(tag, alg byte, oid []byte) []byte {
	material := cat(oid, mpi(263))
	if alg == 18 {
		material = append(material, 3, 1, 8, 9)
	}
	return pkt(tag, keyBody(4, alg, material))
}

func TestAlgorithms(t *testing.T) {
	tests := []struct {
		name  string
		body  []byte
		alg   openpgpkey.Algorithm
		bits  int
		curve string
	}{
		{"rsa 2047 bits", keyBody(4, 1, cat(mpi(2047), mpi(17))), openpgpkey.RSA, 2047, ""},
		{"dsa", keyBody(4, 17, cat(mpi(2048), mpi(256), mpi(2048), mpi(2048))), openpgpkey.DSA, 2048, ""},
		{"ecdsa p-256", keyBody(4, 19, cat(p256, mpi(515))), openpgpkey.ECDSA, 0, "NIST P-256"},
		{"ed25519 native", keyBody(4, 27, make([]byte, 32)), openpgpkey.Ed25519, 0, ""},
		{"ed448 native", keyBody(4, 28, make([]byte, 57)), openpgpkey.Ed448, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := openpgpkey.Parse(cat(pkt(6, tt.body), uid("a")))
			if err != nil {
				t.Fatal(err)
			}
			if k.Algorithm != tt.alg || k.Bits != tt.bits || k.Curve != tt.curve {
				t.Errorf("got %s/%d/%q", k.Algorithm, k.Bits, k.Curve)
			}
		})
	}
	ecdhSub := ecKey(14, 18, cv25519OID)
	if _, err := openpgpkey.Parse(cat(ed25519Key(4), uid("a"), ecdhSub)); err != nil {
		t.Errorf("Curve25519 ECDH subkey: %v", err)
	}
}

func TestCurveMustFitAlgorithm(t *testing.T) {
	accepted := map[string][]byte{
		"EdDSA Ed25519":     cat(ecKey(6, 22, ed25519OID), uid("a")),
		"EdDSA Ed448":       cat(ecKey(6, 22, ed448OID), uid("a")),
		"ECDSA P-256":       cat(ecKey(6, 19, p256), uid("a")),
		"ECDSA brainpool":   cat(ecKey(6, 19, brainpool), uid("a")),
		"ECDSA secp256k1":   cat(ecKey(6, 19, secp256k1), uid("a")),
		"ECDH X448 subkey":  cat(ed25519Key(4), uid("a"), ecKey(14, 18, x448OID)),
		"ECDH P-256 subkey": cat(ed25519Key(4), uid("a"), ecKey(14, 18, p256)),
	}
	for name, in := range accepted {
		if _, err := openpgpkey.Parse(in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	refused := map[string][]byte{
		"ECDSA Ed25519":             cat(ecKey(6, 19, ed25519OID), uid("a")),
		"ECDSA Curve25519":          cat(ecKey(6, 19, cv25519OID), uid("a")),
		"EdDSA P-256":               cat(ecKey(6, 22, p256), uid("a")),
		"EdDSA Curve25519":          cat(ecKey(6, 22, cv25519OID), uid("a")),
		"EdDSA secp256k1":           cat(ecKey(6, 22, secp256k1), uid("a")),
		"ECDH Ed25519 subkey":       cat(ed25519Key(4), uid("a"), ecKey(14, 18, ed25519OID)),
		"ECDH secp256k1 subkey":     cat(ed25519Key(4), uid("a"), ecKey(14, 18, secp256k1)),
		"ECDSA X448 signing subkey": cat(ed25519Key(4), uid("a"), ecKey(14, 19, x448OID)),
	}
	for name, in := range refused {
		if _, err := openpgpkey.Parse(in); !errors.Is(err, openpgpkey.ErrNotPublicKey) || !strings.Contains(err.Error(), "does not fit") {
			t.Errorf("%s: err = %v, want a curve mismatch", name, err)
		}
	}
}

func TestMPIBitCountMustMatch(t *testing.T) {
	padded := cat(mpi(2048), mpi(17))
	padded[2] = 0x01 // top byte now has 1 significant bit: the value is 2041 bits long but declares 2048.
	leadingZero := append([]byte{0x08, 0x08, 0x00}, make([]byte, 256)...)
	leadingZero[3] = 0x80
	for name, material := range map[string][]byte{
		"declared above actual": padded,
		"leading zero byte":     cat(leadingZero, mpi(17)),
		"exponent mismatch":     cat(mpi(3072), []byte{0, 18, 0x01, 0x00, 0x01}),
	} {
		_, err := openpgpkey.Parse(cat(pkt(6, keyBody(4, 1, material)), uid("a")))
		if !errors.Is(err, openpgpkey.ErrNotPublicKey) || !strings.Contains(err.Error(), "MPI bit count") {
			t.Errorf("%s: err = %v, want an MPI bit count refusal", name, err)
		}
	}
}

func TestUserIDControlAndBidiRunesReplaced(t *testing.T) {
	tests := map[string]string{
		"Vendor \x1b[31mred\x1b[0m":                   "Vendor \ufffd[31mred\ufffd[0m",
		"evil\u202Egpj.exe":                           "evil\ufffdgpj.exe",
		"a\u202Ab\u202Bc\u202Cd\u202De":               "a\ufffdb\ufffdc\ufffdd\ufffde",
		"\u2066isolate\u2069 \u2067\u2068":            "\ufffdisolate\ufffd \ufffd\ufffd",
		"mark\u200E\u200F":                            "mark\ufffd\ufffd",
		"tab\tnl\ndel\x7fc1\u0085":                    "tab\ufffdnl\ufffddel\ufffdc1\ufffd",
		"bad utf8 \xff":                               "bad utf8 \ufffd",
		"Ümlaut <ü@example.invalid>":                  "Ümlaut <ü@example.invalid>",
		"arabic\u061Cmark":                            "arabic\ufffdmark",
		"line\u2028para\u2029":                        "line\ufffdpara\ufffd",
		"zero\u200Bwidth\u200C\u200D\u2060":           "zero\ufffdwidth\ufffd\ufffd\ufffd",
		"\uFEFFbom soft\u00ADhyphen":                  "\ufffdbom soft\ufffdhyphen",
		"tag\U000E0000\U000E0001\U000E0041\U000E007F": "tag\ufffd\ufffd\ufffd\ufffd",
		"private\uE000\U000F0000":                     "private\ufffd\ufffd",
		"cgj a\u034Fb":                                "cgj a\ufffdb",
		"vs a\uFE0Fb\U000E0100":                       "vs a\ufffdb\ufffd",
		"fillers \u115F\u1160\u3164\uFFA0":            "fillers \ufffd\ufffd\ufffd\ufffd",
		"braille \u2800":                              "braille \ufffd",
	}
	for in, want := range tests {
		k, err := openpgpkey.Parse(cat(ed25519Key(4), uid(in)))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if k.UserIDs[0] != want {
			t.Errorf("user ID %q = %q, want %q", in, k.UserIDs[0], want)
		}
	}
}

func TestKeyringDoesNotAliasInput(t *testing.T) {
	in := fixture(t, "rsa.gpg")
	k, err := openpgpkey.Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	in[len(in)-1] ^= 0xFF
	if bytes.Equal(k.Keyring, in) || !bytes.Equal(k.Keyring, fixture(t, "rsa.gpg")) {
		t.Error("Keyring changed with the caller's input buffer")
	}
}

func TestRefused(t *testing.T) {
	rsaGPG := fixture(t, "rsa.gpg")
	asc := string(fixture(t, "rsa.asc"))
	mutate := func(b []byte, i int, v byte) []byte {
		c := bytes.Clone(b)
		c[i] = v
		return c
	}
	crcLine := strings.Split(strings.TrimSpace(asc), "\n")
	crc := crcLine[len(crcLine)-2]
	badCRC := strings.Replace(asc, crc, "="+string(rune('A'+(crc[1]-'A'+1)%26))+crc[2:], 1)
	if !strings.HasPrefix(crc, "=") || crc[1] < 'A' || crc[1] > 'Z' {
		t.Fatalf("fixture checksum line %q is not of the expected shape", crc)
	}
	longUID := uid(strings.Repeat("x", openpgpkey.MaxUserIDLen+1))
	manyUIDs := ed25519Key(4)
	for range openpgpkey.MaxUserIDs + 1 {
		manyUIDs = append(manyUIDs, uid("a")...)
	}
	manyPackets := cat(ed25519Key(4), uid("a"))
	for range openpgpkey.MaxPackets {
		manyPackets = append(manyPackets, sig(4, 0x30, nil, nil)...)
	}
	manySubpackets := bytes.Repeat(sub(2, 0, 0, 0, 1), openpgpkey.MaxSubpackets+1)
	tests := map[string][]byte{
		"empty":                        nil,
		"truncated binary":             rsaGPG[:len(rsaGPG)/2],
		"truncated armor":              []byte(asc[:len(asc)/2]),
		"wrong checksum":               []byte(badCRC),
		"secret key block":             mutate(rsaGPG, 0, 0x95),
		"secret subkey":                cat(ed25519Key(4), uid("a"), pkt(7, keyBody(4, 27, make([]byte, 32)))),
		"private armor header":         []byte(strings.ReplaceAll(asc, "PUBLIC KEY BLOCK", "PRIVATE KEY BLOCK")),
		"v3 key":                       mutate(rsaGPG, 3, 3),
		"v5 key":                       ed25519Key(5),
		"v6 key":                       cat(ed25519Key(6), uid("a")),
		"v3 subkey":                    cat(ed25519Key(4), uid("a"), pkt(14, keyBody(3, 27, make([]byte, 32)))),
		"v3 signature":                 cat(ed25519Key(4), uid("a"), sig(3, 0x13, nil, nil)),
		"v6 signature":                 cat(ed25519Key(4), uid("a"), sig(6, 0x13, nil, nil)),
		"user ID first":                cat(uid("a"), ed25519Key(4)),
		"two primary keys":             cat(ed25519Key(4), uid("a"), ed25519Key(4), uid("b")),
		"literal data packet":          cat(ed25519Key(4), uid("a"), pkt(11, []byte("x"))),
		"trust packet":                 cat(ed25519Key(4), uid("a"), pkt(12, []byte{0})),
		"no user ID":                   ed25519Key(4),
		"empty user ID":                cat(ed25519Key(4), uid("")),
		"user ID too long":             cat(ed25519Key(4), longUID),
		"too many user IDs":            manyUIDs,
		"too many packets":             manyPackets,
		"too many subpackets":          cat(ed25519Key(4), uid("a"), sig(4, 0x13, manySubpackets, nil)),
		"user ID after subkey":         cat(ed25519Key(4), uid("a"), pkt(14, keyBody(4, 27, make([]byte, 32))), uid("b")),
		"unknown algorithm":            cat(pkt(6, keyBody(4, 99, make([]byte, 32))), uid("a")),
		"encryption-only primary":      cat(pkt(6, keyBody(4, 25, make([]byte, 32))), uid("a")),
		"trailing key material":        cat(pkt(6, keyBody(4, 27, make([]byte, 33))), uid("a")),
		"short native key":             cat(pkt(6, keyBody(4, 27, make([]byte, 31))), uid("a")),
		"unknown curve":                cat(pkt(6, keyBody(4, 19, []byte{3, 1, 2, 3, 0, 8, 0xFF})), uid("a")),
		"ECDH KDF reserved byte not 1": cat(ed25519Key(4), uid("a"), pkt(14, keyBody(4, 18, cat(cv25519OID, mpi(263), []byte{3, 2, 8, 7})))),
		"zero-length MPI":              cat(pkt(6, keyBody(4, 1, []byte{0, 0, 0, 1, 1})), uid("a")),
		"oversized MPI":                cat(pkt(6, keyBody(4, 1, []byte{0x40, 0x01})), uid("a")),
		"subpacket overruns area":      cat(ed25519Key(4), uid("a"), sig(4, 0x13, []byte{9, 2, 0}, nil)),
		"zero-length subpacket":        cat(ed25519Key(4), uid("a"), sig(4, 0x13, []byte{0}, nil)),
		"hashed area overruns packet":  cat(ed25519Key(4), uid("a"), pkt(2, []byte{4, 0x13, 27, 10, 0xFF, 0xFF})),
		"partial body length":          cat(ed25519Key(4), []byte{0xCD, 0xE1, 'a', 'b'}),
		"indeterminate old length":     cat(ed25519Key(4), []byte{0xB7, 'a'}),
		"packet length beyond input":   cat(ed25519Key(4), []byte{0xCD, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF}),
		"not a packet":                 []byte("hello"),
		"text before armor":            []byte("key:\n" + asc),
		"two armored blocks":           []byte(asc + asc),
		"oversized input":              append(cat(ed25519Key(4), uid("a")), make([]byte, openpgpkey.MaxInput)...),
		"non-base64 armor body":        []byte(strings.Replace(asc, "\n\n", "\n\n!!!!", 1)),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			k, err := openpgpkey.Parse(in)
			if !errors.Is(err, openpgpkey.ErrNotPublicKey) {
				t.Errorf("Parse = %+v, %v; want ErrNotPublicKey", k, err)
			}
		})
	}
}

// FuzzParse checks that arbitrary input never panics or hangs and that an accepted key is self-consistent. The seed
// corpus is the fixtures plus testdata/fuzz/FuzzParse.
func FuzzParse(f *testing.F) {
	for _, name := range []string{"himmelblau.gpg", "rsa.asc", "rsa.gpg", "ed25519.asc"} {
		f.Add(fixture(f, name))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := openpgpkey.Parse(data)
		if err != nil {
			if !errors.Is(err, openpgpkey.ErrNotPublicKey) {
				t.Fatalf("error %v does not wrap ErrNotPublicKey", err)
			}
			return
		}
		if len(k.Fingerprint) != 40 || len(k.UserIDs) == 0 || len(k.UserIDs) > openpgpkey.MaxUserIDs ||
			len(k.Subkeys) > openpgpkey.MaxSubkeys || len(k.Keyring) == 0 {
			t.Fatalf("accepted key out of bounds: %+v", k)
		}
		again, err := openpgpkey.Parse(k.Keyring)
		if err != nil || again.Fingerprint != k.Fingerprint {
			t.Fatalf("keyring does not reparse to the same key: %v", err)
		}
	})
}

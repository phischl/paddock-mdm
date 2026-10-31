package software_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
)

// Public test keys generated with GnuPG 2.4.4 in a throw-away GNUPGHOME; fingerprints as `gpg --show-keys` prints
// them.
const (
	rsa3072FP   = "5D47E8B7736A9129C4FDA19E1F2C82BB297A4093"
	ed25519FP   = "8A367815ED9674ED9013609A8F03DFF0EB10E2E4"
	nistp256FP  = "5EB637C18FBAE2E7B92FBCC8D41690E536015F53"
	rsa2048FP   = "EBBD1779E3508C777B3E01D3B378F1FA6890CA25"
	brainpoolFP = "0311F1FD19711332107186E93504EB92B130BD0C"
	dsaFP       = "26EB16479113C792A40357F4F0FC57026622ACAD"
	rsaSmallSub = "7149256BEC1A7DB713A95C7366280043EC88781E"
)

func key(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func valid(t *testing.T) software.SourceInput {
	return software.SourceInput{
		Slug: "vendor", Name: "Vendor", URIs: []string{"https://apt.vendor.example/"}, Suites: []string{"stable"},
		Components: []string{"main"}, SigningKey: key(t, "rsa3072.asc"), Fingerprint: rsa3072FP,
	}
}

func TestValidateSourceAccepts(t *testing.T) {
	tests := map[string]func(*software.SourceInput){
		"as is":                             func(*software.SourceInput) {},
		"fingerprint lowercase with spaces": func(in *software.SourceInput) { in.Fingerprint = "5d47 e8b7 736a 9129 c4fd  a19e 1f2c 82bb 297a 4093" },
		"fingerprint with tabs and newline": func(in *software.SourceInput) { in.Fingerprint = "\t" + rsa3072FP + "\n" },
		"shortest slug":                     func(in *software.SourceInput) { in.Slug = "ab" },
		"longest slug":                      func(in *software.SourceInput) { in.Slug = "a" + strings.Repeat("-", 40) },
		"name of 100 characters":            func(in *software.SourceInput) { in.Name = strings.Repeat("ä", 100) },
		"name with surrounding spaces":      func(in *software.SourceInput) { in.Name = "  Vendor  " },
		"four uris with port and path": func(in *software.SourceInput) {
			in.URIs = []string{"https://a.example/", "https://b.example:8443/debian", "https://c.example", "https://[2001:db8::1]/apt/"}
		},
		"uri of 512 characters":       func(in *software.SourceInput) { in.URIs = []string{"https://a.example/" + strings.Repeat("p", 512-18)} },
		"eight suites":                func(in *software.SourceInput) { in.Suites = strings.Fields("a b c d e f g h") },
		"suite with dots and slashes": func(in *software.SourceInput) { in.Suites = []string{"noble-updates/stable_1.0"} },
		"flat repository":             func(in *software.SourceInput) { in.Suites, in.Components = []string{"./"}, nil },
		"two flat suites":             func(in *software.SourceInput) { in.Suites, in.Components = []string{"./", "amd64/"}, nil },
		"name with umlauts and emoji": func(in *software.SourceInput) { in.Name = "Hersteller Ä 📦" },
		"eight components":            func(in *software.SourceInput) { in.Components = strings.Fields("a b c d e f g h") },
		"both architectures":          func(in *software.SourceInput) { in.Architectures = []string{"amd64", "arm64"} },
		"ed25519 key":                 func(in *software.SourceInput) { in.SigningKey, in.Fingerprint = key(t, "ed25519.asc"), ed25519FP },
		"nist p-256 key":              func(in *software.SourceInput) { in.SigningKey, in.Fingerprint = key(t, "nistp256.asc"), nistp256FP },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			in := valid(t)
			mutate(&in)
			fp, keyring, err := software.ValidateSource(in)
			if err != nil {
				t.Fatal(err)
			}
			if fp != software.NormalizeFingerprint(in.Fingerprint) || len(keyring) == 0 {
				t.Errorf("fingerprint %s, keyring of %d bytes", fp, len(keyring))
			}
		})
	}
}

func TestValidateSourceRefuses(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*software.SourceInput)
		detail string
	}{
		{"empty slug", func(in *software.SourceInput) { in.Slug = "" }, "slug"},
		{"one-character slug", func(in *software.SourceInput) { in.Slug = "a" }, "slug"},
		{"slug too long", func(in *software.SourceInput) { in.Slug = "a" + strings.Repeat("b", 41) }, "slug"},
		{"uppercase slug", func(in *software.SourceInput) { in.Slug = "Vendor" }, "slug"},
		{"slug starting with a hyphen", func(in *software.SourceInput) { in.Slug = "-vendor" }, "slug"},
		{"slug with a slash", func(in *software.SourceInput) { in.Slug = "a/b" }, "slug"},
		{"blank name", func(in *software.SourceInput) { in.Name = "   " }, "name"},
		{"name too long", func(in *software.SourceInput) { in.Name = strings.Repeat("a", 101) }, "name"},
		{"name with invalid UTF-8", func(in *software.SourceInput) { in.Name = "Vendor \xff" }, "valid UTF-8"},
		{"name with a newline", func(in *software.SourceInput) { in.Name = "Vendor\nOther" }, "control"},
		{"name with a bidi override", func(in *software.SourceInput) { in.Name = "Vendor\u202Erodnev" }, "control"},
		{"name with a zero-width space", func(in *software.SourceInput) { in.Name = "Ven\u200Bdor" }, "control"},
		{"name with a byte order mark", func(in *software.SourceInput) { in.Name = "\uFEFFVendor" }, "control"},
		{"name with a line separator", func(in *software.SourceInput) { in.Name = "Vendor\u2028x" }, "control"},
		{"name with a paragraph separator", func(in *software.SourceInput) { in.Name = "Vendor\u2029x" }, "control"},
		{"non-flat suite without components", func(in *software.SourceInput) { in.Components = nil }, "at least one entry"},
		{"flat and non-flat suites", func(in *software.SourceInput) { in.Suites, in.Components = []string{"stable", "./"}, nil }, "all flat"},
		{"flat and non-flat suites with components", func(in *software.SourceInput) { in.Suites = []string{"stable", "./"} }, "all flat"},
		{"no uris", func(in *software.SourceInput) { in.URIs = nil }, "uris must have"},
		{"five uris", func(in *software.SourceInput) {
			in.URIs = strings.Fields("https://a https://b https://c https://d https://e")
		}, "uris must have"},
		{"http", func(in *software.SourceInput) { in.URIs = []string{"http://apt.vendor.example/"} }, "uris must use https"},
		{"uppercase scheme", func(in *software.SourceInput) { in.URIs = []string{"HTTPS://apt.vendor.example/"} }, "uris must use https"},
		{"file scheme", func(in *software.SourceInput) { in.URIs = []string{"file:///srv/apt"} }, "uris must use https"},
		{"no scheme", func(in *software.SourceInput) { in.URIs = []string{"apt.vendor.example/"} }, "uris must use https"},
		{"uri too long", func(in *software.SourceInput) { in.URIs = []string{"https://a.example/" + strings.Repeat("p", 512-17)} }, "at most 512"},
		{"query", func(in *software.SourceInput) { in.URIs = []string{"https://apt.vendor.example/?a=b"} }, "query"},
		{"fragment", func(in *software.SourceInput) { in.URIs = []string{"https://apt.vendor.example/#x"} }, "fragment"},
		{"white space", func(in *software.SourceInput) { in.URIs = []string{"https://apt.vendor.example/a b"} }, "white space"},
		{"user info", func(in *software.SourceInput) { in.URIs = []string{"https://user:pw@apt.vendor.example/"} }, "user info"},
		{"no host", func(in *software.SourceInput) { in.URIs = []string{"https:///path"} }, "host"},
		{"no suites", func(in *software.SourceInput) { in.Suites = nil }, "suites must have"},
		{"nine suites", func(in *software.SourceInput) { in.Suites = strings.Fields("a b c d e f g h i") }, "suites must have"},
		{"suite with a space", func(in *software.SourceInput) { in.Suites = []string{"a b"} }, "suites must match"},
		{"suite too long", func(in *software.SourceInput) { in.Suites = []string{strings.Repeat("s", 65)} }, "suites must match"},
		{"flat repository with components", func(in *software.SourceInput) { in.Suites = []string{"./"} }, "flat repository"},
		{"nine components", func(in *software.SourceInput) { in.Components = strings.Fields("a b c d e f g h i") }, "components must have"},
		{"uppercase component", func(in *software.SourceInput) { in.Components = []string{"Main"} }, "components must match"},
		{"three architectures", func(in *software.SourceInput) { in.Architectures = []string{"amd64", "arm64", "amd64"} }, "architectures must have"},
		{"unknown architecture", func(in *software.SourceInput) { in.Architectures = []string{"i386"} }, "amd64 or arm64"},
		{"signing key too long", func(in *software.SourceInput) { in.SigningKey = strings.Repeat("a", software.MaxSigningKeyLength+1) }, "at most 65536 bytes"},
		{"binary signing key", func(in *software.SourceInput) { in.SigningKey = "\x99\x01\x0d" }, "ASCII-armored"},
		{"secret key block", func(in *software.SourceInput) {
			in.SigningKey = strings.ReplaceAll(in.SigningKey, "PUBLIC KEY BLOCK", "PRIVATE KEY BLOCK")
		}, "ASCII-armored"},
		{"missing fingerprint", func(in *software.SourceInput) { in.Fingerprint = "" }, "40 hexadecimal"},
		{"short fingerprint", func(in *software.SourceInput) { in.Fingerprint = rsa3072FP[:39] }, "40 hexadecimal"},
		{"non-hex fingerprint", func(in *software.SourceInput) { in.Fingerprint = "G" + rsa3072FP[1:] }, "40 hexadecimal"},
		{"rsa 2048", func(in *software.SourceInput) { in.SigningKey, in.Fingerprint = key(t, "rsa2048.asc"), rsa2048FP }, "RSA 2048 bits"},
		{"rsa 3072 with a 2048-bit subkey", func(in *software.SourceInput) {
			in.SigningKey, in.Fingerprint = key(t, "rsa3072-sub2048.asc"), rsaSmallSub
		}, "subkey 1 is RSA 2048 bits"},
		{"brainpool", func(in *software.SourceInput) { in.SigningKey, in.Fingerprint = key(t, "brainpool.asc"), brainpoolFP }, "brainpoolP256r1"},
		{"dsa", func(in *software.SourceInput) { in.SigningKey, in.Fingerprint = key(t, "dsa.asc"), dsaFP }, "algorithm DSA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid(t)
			tt.mutate(&in)
			_, _, err := software.ValidateSource(in)
			if !errors.Is(err, software.ErrSource) || errors.Is(err, software.ErrFingerprint) {
				t.Fatalf("err = %v, want ErrSource", err)
			}
			if !strings.Contains(err.Error(), tt.detail) {
				t.Errorf("err = %v, want it to mention %q", err, tt.detail)
			}
		})
	}
}

func TestValidateSourceFingerprintMismatch(t *testing.T) {
	in := valid(t)
	in.Fingerprint = rsa3072FP[:39] + "0"
	_, _, err := software.ValidateSource(in)
	if !errors.Is(err, software.ErrFingerprint) || errors.Is(err, software.ErrSource) {
		t.Fatalf("err = %v, want ErrFingerprint", err)
	}
	if !strings.Contains(err.Error(), rsa3072FP) || !strings.Contains(err.Error(), in.Fingerprint) {
		t.Errorf("err = %v, want both fingerprints", err)
	}
}

func TestValidateSourceKeyringIsTheDearmoredKey(t *testing.T) {
	in := valid(t)
	_, keyring, err := software.ValidateSource(in)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := openpgpkey.FingerprintBinary(keyring)
	if err != nil || fp != rsa3072FP {
		t.Errorf("FingerprintBinary(keyring) = %s, %v", fp, err)
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	if got := software.NormalizeFingerprint(" 5d47 E8B7\t736a\n"); got != "5D47E8B7736A" {
		t.Errorf("NormalizeFingerprint = %q", got)
	}
}

func TestNormalizeName(t *testing.T) {
	if got := software.NormalizeName("  Vendor Repo \t\n"); got != "Vendor Repo" {
		t.Errorf("NormalizeName = %q", got)
	}
}

// rsaParams is an RSA key of the given size with an odd modulus and the given exponent.
func rsaParams(bits int, e ...byte) openpgpkey.Params {
	n := make([]byte, bits/8)
	n[0], n[len(n)-1] = 0x80, 0x01
	return openpgpkey.Params{Algorithm: openpgpkey.RSA, Bits: bits, RSAModulus: n, RSAExponent: e}
}

func TestKeyPolicy(t *testing.T) {
	rsa := func(bits int) openpgpkey.Params { return rsaParams(bits, 1, 0, 1) }
	ec := func(alg openpgpkey.Algorithm, curve string) openpgpkey.Params {
		p := openpgpkey.Params{Algorithm: alg, Curve: curve}
		if alg == openpgpkey.ECDH {
			p.KDFHash, p.KDFCipher = 8, 7
		}
		return p
	}
	kdf := func(curve string, hash, cipher byte) openpgpkey.Params {
		return openpgpkey.Params{Algorithm: openpgpkey.ECDH, Curve: curve, KDFHash: hash, KDFCipher: cipher}
	}
	evenModulus := rsaParams(3072, 1, 0, 1)
	evenModulus.RSAModulus[len(evenModulus.RSAModulus)-1] = 0x02
	ed := ec(openpgpkey.EdDSA, "Ed25519")
	native := func(alg openpgpkey.Algorithm) openpgpkey.Params { return openpgpkey.Params{Algorithm: alg} }
	tests := []struct {
		name    string
		primary openpgpkey.Params
		subkeys []openpgpkey.Params
		ok      bool
	}{
		{"rsa 3072", rsa(3072), nil, true},
		{"rsa 4096 with rsa 3072 subkey", rsa(4096), []openpgpkey.Params{rsa(3072)}, true},
		{"rsa 3071", rsa(3071), nil, false},
		{"rsa 2048", rsa(2048), nil, false},
		{"rsa 4096 with rsa 2048 subkey", rsa(4096), []openpgpkey.Params{rsa(2048)}, false},
		{"eddsa ed25519 with ecdh curve25519", ec(openpgpkey.EdDSA, "Ed25519"), []openpgpkey.Params{ec(openpgpkey.ECDH, "Curve25519")}, true},
		{"eddsa ed448 with ecdh x448", ec(openpgpkey.EdDSA, "Ed448"), []openpgpkey.Params{ec(openpgpkey.ECDH, "X448")}, true},
		{"native ed25519 with x25519", native(openpgpkey.Ed25519), []openpgpkey.Params{native(openpgpkey.X25519)}, true},
		{"native ed448 with x448", native(openpgpkey.Ed448), []openpgpkey.Params{native(openpgpkey.X448)}, true},
		{"ecdsa p-256", ec(openpgpkey.ECDSA, "NIST P-256"), []openpgpkey.Params{ec(openpgpkey.ECDH, "NIST P-256")}, true},
		{"ecdsa p-384", ec(openpgpkey.ECDSA, "NIST P-384"), []openpgpkey.Params{ec(openpgpkey.ECDH, "NIST P-384")}, true},
		{"ecdsa p-521", ec(openpgpkey.ECDSA, "NIST P-521"), []openpgpkey.Params{ec(openpgpkey.ECDSA, "NIST P-521")}, true},
		{"rsa primary with ed25519 signing subkey", rsa(3072), []openpgpkey.Params{ec(openpgpkey.EdDSA, "Ed25519")}, true},
		{"ecdsa brainpool", ec(openpgpkey.ECDSA, "brainpoolP256r1"), nil, false},
		{"ecdsa brainpool 512", ec(openpgpkey.ECDSA, "brainpoolP512r1"), nil, false},
		{"ecdsa secp256k1", ec(openpgpkey.ECDSA, "secp256k1"), nil, false},
		{"ecdh brainpool subkey", ec(openpgpkey.EdDSA, "Ed25519"), []openpgpkey.Params{ec(openpgpkey.ECDH, "brainpoolP384r1")}, false},
		{"ecdh curve25519 as primary", ec(openpgpkey.ECDH, "Curve25519"), nil, false},
		{"native x25519 as primary", native(openpgpkey.X25519), nil, false},
		{"native x448 as primary", native(openpgpkey.X448), nil, false},
		{"eddsa on a nist curve", ec(openpgpkey.EdDSA, "NIST P-256"), nil, false},
		{"ecdsa on ed25519", ec(openpgpkey.ECDSA, "Ed25519"), nil, false},
		{"ecdsa curve25519 signing subkey", ec(openpgpkey.EdDSA, "Ed25519"), []openpgpkey.Params{ec(openpgpkey.ECDSA, "Curve25519")}, false},
		{"dsa", native(openpgpkey.DSA), nil, false},
		{"elgamal subkey", rsa(3072), []openpgpkey.Params{native(openpgpkey.ElGamal)}, false},
		{"rsa exponent 2^32+1", rsaParams(3072, 1, 0, 0, 0, 1), nil, true},
		{"rsa even modulus", evenModulus, nil, false},
		{"rsa even exponent", rsaParams(3072, 1, 0, 2), nil, false},
		{"rsa exponent 3", rsaParams(3072, 3), nil, false},
		{"rsa exponent 65535", rsaParams(3072, 0xFF, 0xFF), nil, false},
		{"rsa subkey exponent 3", rsa(4096), []openpgpkey.Params{rsaParams(3072, 3)}, false},
		{"ecdh sha-512 aes-256", ed, []openpgpkey.Params{kdf("Curve25519", 10, 9)}, true},
		{"ecdh sha-384 aes-192", ed, []openpgpkey.Params{kdf("NIST P-384", 9, 8)}, true},
		{"ecdh sha-1 kdf", ed, []openpgpkey.Params{kdf("Curve25519", 2, 7)}, false},
		{"ecdh sha-224 kdf", ed, []openpgpkey.Params{kdf("Curve25519", 11, 7)}, false},
		{"ecdh camellia kdf", ed, []openpgpkey.Params{kdf("Curve25519", 8, 11)}, false},
		{"ecdh triple-des kdf", ed, []openpgpkey.Params{kdf("Curve25519", 8, 2)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &openpgpkey.Key{Params: tt.primary, Subkeys: tt.subkeys}
			err := software.KeyPolicy(k)
			if tt.ok && err != nil {
				t.Errorf("err = %v, want accepted", err)
			}
			if !tt.ok && !errors.Is(err, software.ErrSource) {
				t.Errorf("err = %v, want ErrSource", err)
			}
		})
	}
}

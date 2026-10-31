// Package software holds the rules of the software catalog (plan M13a): the validation of an organization's APT
// package sources and the policy their signing keys must meet.
package software

import (
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
)

// Validation errors. ErrSource is answered with 400 invalid_request, ErrFingerprint with 422 fingerprint_mismatch.
var (
	ErrSource      = errors.New("invalid software source")
	ErrFingerprint = errors.New("fingerprint mismatch")
)

// Limits of a source (plan M13a decision 2).
const (
	MaxNameLength       = 100
	MaxURIs             = 4
	MaxURILength        = 512
	MaxSuites           = 8
	MaxComponents       = 8
	MaxArchitectures    = 2
	MaxSigningKeyLength = 65536
	// MinRSABits is the smallest RSA key the upload accepts for the primary key and every subkey.
	MinRSABits = 2048
	// StrongRSABits is the RSA size from which a key is no longer flagged as weak (architect decision 2026-10-31,
	// revised: RSA 2048 is acceptable until 2030).
	StrongRSABits = 3072
)

var (
	slugPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}$`)
	suitePattern     = regexp.MustCompile(`^[A-Za-z0-9./_-]{1,64}$`)
	componentPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	fingerprintHex   = regexp.MustCompile(`^[0-9A-F]{40}$`)
	architectures    = []string{"amd64", "arm64"}
)

// SourceInput is a package source as an administrator submits it. SigningKey is the ASCII-armored OpenPGP public key
// and Fingerprint the fingerprint the administrator typed from the vendor's publication.
type SourceInput struct {
	Slug, Name                              string
	URIs, Suites, Components, Architectures []string
	SigningKey, Fingerprint                 string
}

// SourceKey is the checked signing key of a valid source.
type SourceKey struct {
	// Fingerprint is the key's v4 fingerprint, 40 uppercase hexadecimal characters.
	Fingerprint string
	// Keyring is the binary (dearmored) key the agent writes.
	Keyring []byte
	// WeakKey is true when the primary key or a subkey is RSA of MinRSABits up to below StrongRSABits. Such a key is
	// accepted; the use case records weak_key: true in the source view and in the audit params of the source events,
	// and the portal shows it as a warning.
	WeakKey bool
}

// ValidateSource checks a source against plan M13a decision 2 and the signing key policy (KeyPolicy) and returns the
// checked key. Rule violations wrap ErrSource; a typed fingerprint that differs from the key's wraps ErrFingerprint
// and names both values. No signature is verified.
func ValidateSource(in SourceInput) (SourceKey, error) {
	if !slugPattern.MatchString(in.Slug) {
		return SourceKey{}, fmt.Errorf("%w: slug must match ^[a-z0-9][a-z0-9-]{1,40}$", ErrSource)
	}
	if err := validateName(in.Name); err != nil {
		return SourceKey{}, err
	}
	if err := validateURIs(in.URIs); err != nil {
		return SourceKey{}, err
	}
	if err := validateDistribution(in.Suites, in.Components, in.Architectures); err != nil {
		return SourceKey{}, err
	}
	return validateSigningKey(in.SigningKey, in.Fingerprint)
}

// NormalizeName trims surrounding white space from a source name, the form ValidateSource checks and a name is stored
// in.
func NormalizeName(name string) string {
	return strings.TrimSpace(name)
}

// validateName checks the trimmed name. Control, format, invisible and blank-looking characters and line or
// paragraph separators are refused because the name is shown in the portal and the audit log, where bidi controls,
// line breaks or invisible runes could make one source look like another.
func validateName(name string) error {
	name = NormalizeName(name)
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: name must be valid UTF-8", ErrSource)
	}
	if n := utf8.RuneCountInString(name); n < 1 || n > MaxNameLength {
		return fmt.Errorf("%w: name must be 1 to %d characters", ErrSource, MaxNameLength)
	}
	if strings.ContainsFunc(name, invisibleInName) {
		return fmt.Errorf("%w: name must not contain control, format, invisible or line separator characters",
			ErrSource)
	}
	if !strings.ContainsFunc(name, func(r rune) bool { return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S) }) {
		return fmt.Errorf("%w: name must contain at least one letter, digit, punctuation or symbol", ErrSource)
	}
	return nil
}

// invisibleInName reports runes a name must not contain. U+2800 (braille blank) and the Hangul fillers render as
// blanks without being white space; the tag block is listed whole because its unassigned code points have no
// property.
func invisibleInName(r rune) bool {
	switch r {
	case '\u115F', '\u1160', '\u3164', '\uFFA0', '\u2800':
		return true
	}
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Other_Default_Ignorable_Code_Point,
		unicode.Variation_Selector) || (r >= 0xE0000 && r <= 0xE007F)
}

// NormalizeFingerprint removes all white space from a typed fingerprint and upper-cases it, the form fingerprints
// are stored and compared in.
func NormalizeFingerprint(s string) string {
	return strings.ToUpper(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s))
}

func validateURIs(uris []string) error {
	if len(uris) < 1 || len(uris) > MaxURIs {
		return fmt.Errorf("%w: uris must have 1 to %d entries", ErrSource, MaxURIs)
	}
	for _, raw := range uris {
		if !strings.HasPrefix(raw, "https://") {
			return fmt.Errorf("%w: uris must use https", ErrSource)
		}
		if len(raw) > MaxURILength {
			return fmt.Errorf("%w: uris must be at most %d characters", ErrSource, MaxURILength)
		}
		if strings.ContainsFunc(raw, unicode.IsSpace) || strings.ContainsAny(raw, "?#") {
			return fmt.Errorf("%w: uris must not contain white space, a query or a fragment", ErrSource)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || u.User != nil {
			return fmt.Errorf("%w: uris must be https://host[/path] without user info", ErrSource)
		}
	}
	return nil
}

func validateDistribution(suites, components, archs []string) error {
	if len(suites) < 1 || len(suites) > MaxSuites {
		return fmt.Errorf("%w: suites must have 1 to %d entries", ErrSource, MaxSuites)
	}
	flat := 0
	for i, s := range suites {
		if !suitePattern.MatchString(s) {
			return fmt.Errorf("%w: suites must match ^[A-Za-z0-9./_-]{1,64}$", ErrSource)
		}
		if slices.Contains(suites[:i], s) {
			return fmt.Errorf("%w: suites must not repeat %q", ErrSource, s)
		}
		if strings.HasSuffix(s, "/") {
			flat++
		}
	}
	if len(components) > MaxComponents {
		return fmt.Errorf("%w: components must have at most %d entries", ErrSource, MaxComponents)
	}
	for i, c := range components {
		if !componentPattern.MatchString(c) {
			return fmt.Errorf("%w: components must match ^[a-z0-9-]{1,32}$", ErrSource)
		}
		if slices.Contains(components[:i], c) {
			return fmt.Errorf("%w: components must not repeat %q", ErrSource, c)
		}
	}
	// apt treats a suite ending in "/" as a flat repository and refuses components next to it, and refuses a
	// non-flat suite without components; either error stops every apt run on the device, not only this source's.
	switch {
	case flat > 0 && flat < len(suites):
		return fmt.Errorf("%w: suites must be either all flat (ending in /) or none", ErrSource)
	case flat > 0 && len(components) > 0:
		return fmt.Errorf("%w: a flat repository (suite ending in /) must have no components", ErrSource)
	case flat == 0 && len(components) == 0:
		return fmt.Errorf("%w: components must have at least one entry unless the repository is flat", ErrSource)
	}
	if len(archs) > MaxArchitectures {
		return fmt.Errorf("%w: architectures must have at most %d entries", ErrSource, MaxArchitectures)
	}
	for _, a := range archs {
		if !slices.Contains(architectures, a) {
			return fmt.Errorf("%w: architectures must be amd64 or arm64", ErrSource)
		}
	}
	return nil
}

func validateSigningKey(signingKey, typed string) (SourceKey, error) {
	if len(signingKey) > MaxSigningKeyLength {
		return SourceKey{}, fmt.Errorf("%w: signing_key must be at most %d bytes", ErrSource, MaxSigningKeyLength)
	}
	want := NormalizeFingerprint(typed)
	if !fingerprintHex.MatchString(want) {
		return SourceKey{}, fmt.Errorf("%w: fingerprint must be 40 hexadecimal characters", ErrSource)
	}
	key, err := openpgpkey.ParseArmored([]byte(signingKey))
	if err != nil {
		return SourceKey{}, fmt.Errorf("%w: signing_key must be one ASCII-armored OpenPGP v4 public key: %w",
			ErrSource, err)
	}
	weak, err := KeyPolicy(key)
	if err != nil {
		return SourceKey{}, err
	}
	if key.Fingerprint != want {
		return SourceKey{}, fmt.Errorf("%w: the key's fingerprint is %s, the entered one is %s", ErrFingerprint,
			key.Fingerprint, want)
	}
	return SourceKey{Fingerprint: key.Fingerprint, Keyring: key.Keyring, WeakKey: weak}, nil
}

// Curves the upload accepts (ticket PDK-408, architect decision 2026-10-31). Brainpool and secp256k1 are refused;
// Curve25519 and X448 are key-agreement curves and therefore only valid on encryption subkeys.
var (
	signingCurves    = []string{"Ed25519", "Ed448", "NIST P-256", "NIST P-384", "NIST P-521"}
	encryptionCurves = []string{"Curve25519", "X448", "NIST P-256", "NIST P-384", "NIST P-521"}
)

// KeyPolicy checks the algorithms of an uploaded signing key: RSA of at least MinRSABits, or elliptic-curve keys on
// the allowed curves; DSA and ElGamal are refused. It applies to the primary key and to every subkey, as apt accepts
// a repository signature made by any signing subkey. Violations wrap ErrSource. weak reports an accepted key with an
// RSA part below StrongRSABits (see SourceKey.WeakKey).
func KeyPolicy(k *openpgpkey.Key) (weak bool, err error) {
	if weak, err = checkAlgorithm("primary key", k.Params, false); err != nil {
		return false, err
	}
	for i, s := range k.Subkeys {
		w, err := checkAlgorithm(fmt.Sprintf("subkey %d", i+1), s, true)
		if err != nil {
			return false, err
		}
		weak = weak || w
	}
	return weak, nil
}

// KDF algorithms an ECDH subkey may name (RFC 9580 §9.5 hash and §9.3 cipher identifiers): SHA-256/384/512 and
// AES-128/192/256. The reader accepts every identifier RFC 9580 allows; the upload is stricter.
var (
	kdfHashes  = []byte{8, 9, 10}
	kdfCiphers = []byte{7, 8, 9}
)

// Bounds of the RSA public exponent. Smaller ones (3, 17) invite known attacks on padding; the upper bound keeps e
// within what common implementations accept, so a key apt cannot use on the device is refused at upload.
const (
	minRSAExponent = 65537
	maxRSAExponent = 1<<31 - 1
)

// checkAlgorithm applies the policy to one key and reports whether it is an accepted but weak RSA key.
func checkAlgorithm(which string, p openpgpkey.Params, subkey bool) (bool, error) {
	if p.Algorithm == openpgpkey.RSA {
		return checkRSA(which, p)
	}
	return false, checkCurve(which, p, subkey)
}

func checkRSA(which string, p openpgpkey.Params) (bool, error) {
	if p.Bits < MinRSABits {
		return false, fmt.Errorf("%w: signing_key %s is RSA %d bits; at least %d bits are required", ErrSource, which,
			p.Bits, MinRSABits)
	}
	n, e := new(big.Int).SetBytes(p.RSAModulus), new(big.Int).SetBytes(p.RSAExponent)
	if n.Bit(0) == 0 || e.Bit(0) == 0 || e.Cmp(big.NewInt(minRSAExponent)) < 0 ||
		e.Cmp(big.NewInt(maxRSAExponent)) > 0 || e.Cmp(n) >= 0 {
		return false, fmt.Errorf("%w: signing_key %s is not a plausible RSA key (odd modulus and odd exponent of "+
			"65537 to 2^31-1 and below the modulus required)", ErrSource, which)
	}
	return p.Bits < StrongRSABits, nil
}

// checkCurve applies the curve allow list to an elliptic-curve key; every other algorithm (DSA, ElGamal) is refused.
func checkCurve(which string, p openpgpkey.Params, subkey bool) error {
	alg, curve := p.Algorithm, p.Curve
	switch alg {
	case openpgpkey.Ed25519, openpgpkey.Ed448:
		return nil
	case openpgpkey.X25519, openpgpkey.X448:
		if subkey {
			return nil
		}
	case openpgpkey.EdDSA, openpgpkey.ECDSA:
		if slices.Contains(signingCurves, curve) && curveFits(alg, curve) {
			return nil
		}
		return fmt.Errorf("%w: signing_key %s uses %s on curve %s, which is not allowed", ErrSource, which, alg, curve)
	case openpgpkey.ECDH:
		if subkey && slices.Contains(encryptionCurves, curve) {
			if !slices.Contains(kdfHashes, p.KDFHash) || !slices.Contains(kdfCiphers, p.KDFCipher) {
				return fmt.Errorf("%w: signing_key %s has ECDH KDF parameters other than SHA-2 and AES", ErrSource,
					which)
			}
			return nil
		}
		return fmt.Errorf("%w: signing_key %s uses %s on curve %s, which is not allowed", ErrSource, which, alg, curve)
	}
	return fmt.Errorf("%w: signing_key %s uses the algorithm %s, which is not allowed", ErrSource, which, alg)
}

// curveFits repeats pkg/openpgpkey's curve-to-algorithm check for the signing curves, so this policy does not depend
// on the reader having refused a mismatched key.
func curveFits(alg openpgpkey.Algorithm, curve string) bool {
	edwards := curve == "Ed25519" || curve == "Ed448"
	return (alg == openpgpkey.EdDSA) == edwards
}

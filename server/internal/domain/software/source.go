// Package software holds the rules of the software catalog (plan M13a): the validation of an organization's APT
// package sources and the policy their signing keys must meet.
package software

import (
	"errors"
	"fmt"
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
	MinRSABits = 3072
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

// ValidateSource checks a source against plan M13a decision 2 and the signing key policy (KeyPolicy) and returns the
// key's fingerprint (40 uppercase hexadecimal characters) and its binary keyring. Rule violations wrap ErrSource; a
// typed fingerprint that differs from the key's wraps ErrFingerprint and names both values. No signature is verified.
func ValidateSource(in SourceInput) (fingerprint string, keyring []byte, err error) {
	if !slugPattern.MatchString(in.Slug) {
		return "", nil, fmt.Errorf("%w: slug must match ^[a-z0-9][a-z0-9-]{1,40}$", ErrSource)
	}
	if n := utf8.RuneCountInString(strings.TrimSpace(in.Name)); n < 1 || n > MaxNameLength {
		return "", nil, fmt.Errorf("%w: name must be 1 to %d characters", ErrSource, MaxNameLength)
	}
	if err := validateURIs(in.URIs); err != nil {
		return "", nil, err
	}
	if err := validateDistribution(in.Suites, in.Components, in.Architectures); err != nil {
		return "", nil, err
	}
	return validateSigningKey(in.SigningKey, in.Fingerprint)
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
	flat := false
	for _, s := range suites {
		if !suitePattern.MatchString(s) {
			return fmt.Errorf("%w: suites must match ^[A-Za-z0-9./_-]{1,64}$", ErrSource)
		}
		flat = flat || strings.HasSuffix(s, "/")
	}
	if len(components) > MaxComponents {
		return fmt.Errorf("%w: components must have at most %d entries", ErrSource, MaxComponents)
	}
	for _, c := range components {
		if !componentPattern.MatchString(c) {
			return fmt.Errorf("%w: components must match ^[a-z0-9-]{1,32}$", ErrSource)
		}
	}
	// apt treats a suite ending in "/" as a flat repository and rejects components next to it.
	if flat && len(components) > 0 {
		return fmt.Errorf("%w: a flat repository (suite ending in /) must have no components", ErrSource)
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

func validateSigningKey(signingKey, typed string) (string, []byte, error) {
	if len(signingKey) > MaxSigningKeyLength {
		return "", nil, fmt.Errorf("%w: signing_key must be at most %d bytes", ErrSource, MaxSigningKeyLength)
	}
	want := NormalizeFingerprint(typed)
	if !fingerprintHex.MatchString(want) {
		return "", nil, fmt.Errorf("%w: fingerprint must be 40 hexadecimal characters", ErrSource)
	}
	key, err := openpgpkey.ParseArmored([]byte(signingKey))
	if err != nil {
		return "", nil, fmt.Errorf("%w: signing_key must be one ASCII-armored OpenPGP v4 public key: %w", ErrSource, err)
	}
	if err := KeyPolicy(key); err != nil {
		return "", nil, err
	}
	if key.Fingerprint != want {
		return "", nil, fmt.Errorf("%w: the key's fingerprint is %s, the entered one is %s", ErrFingerprint,
			key.Fingerprint, want)
	}
	return key.Fingerprint, key.Keyring, nil
}

// Curves the upload accepts (ticket PDK-408, architect decision 2026-10-31). Brainpool and secp256k1 are refused;
// Curve25519 and X448 are key-agreement curves and therefore only valid on encryption subkeys.
var (
	signingCurves    = []string{"Ed25519", "Ed448", "NIST P-256", "NIST P-384", "NIST P-521"}
	encryptionCurves = []string{"Curve25519", "X448", "NIST P-256", "NIST P-384", "NIST P-521"}
)

// KeyPolicy checks the algorithms of an uploaded signing key: RSA of at least MinRSABits, or elliptic-curve keys on
// the allowed curves; DSA and ElGamal are refused. It applies to the primary key and to every subkey, as apt accepts
// a repository signature made by any signing subkey. Violations wrap ErrSource.
func KeyPolicy(k *openpgpkey.Key) error {
	if err := checkAlgorithm("primary key", k.Algorithm, k.Bits, k.Curve, false); err != nil {
		return err
	}
	for i, s := range k.Subkeys {
		if err := checkAlgorithm(fmt.Sprintf("subkey %d", i+1), s.Algorithm, s.Bits, s.Curve, true); err != nil {
			return err
		}
	}
	return nil
}

func checkAlgorithm(which string, alg openpgpkey.Algorithm, bits int, curve string, subkey bool) error {
	switch alg {
	case openpgpkey.RSA:
		if bits < MinRSABits {
			return fmt.Errorf("%w: signing_key %s is RSA %d bits; at least %d bits are required", ErrSource, which,
				bits, MinRSABits)
		}
		return nil
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

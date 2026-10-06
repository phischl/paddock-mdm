// Package autoinstall renders the Paddock autoinstall (plan M4b decisions 2–4): Ubuntu autoinstall user-data that
// installs a device with LVM inside LUKS2 under a random temporary passphrase, installs the Paddock packages of an
// agent release (pinned by SHA-256), and leaves the enrollment configuration, the passphrase and the pending disk
// setup for the first boot. It is stateless; nothing it generates is stored.
package autoinstall

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"
)

// Releases are the Ubuntu releases the generator supports.
var Releases = []string{"24.04", "26.04"}

// InstallUser is the account the installer requires; its password is locked.
const InstallUser = "paddock-install"

// PassphraseLength is the length of the temporary disk passphrase: 32 alphanumeric characters carry 190 bits.
const PassphraseLength = 32

// Package is one Debian package of the agent release the device installs.
type Package struct {
	Name   string // paddock-agent or paddock-supervisor
	URL    string // public URL below bundles.<domain>/packages/
	SHA256 string // hex
}

// Input is what one rendering needs. EnrollmentConfig is the enrollment configuration as the device reads it.
type Input struct {
	Release          string
	Hostname         string
	Locale           string
	KeyboardLayout   string
	Timezone         string
	EnrollmentConfig []byte
	AgentVersion     string
	Packages         []Package
	BootPINMinLength int
}

// Validation errors.
var (
	ErrRelease  = errors.New("release must be 24.04 or 26.04")
	ErrHostname = errors.New("hostname must be a lowercase host name label of 1 to 63 characters (letters, digits, hyphens)")
	ErrLocale   = errors.New("locale must look like en_US.UTF-8")
	ErrKeyboard = errors.New("keyboard_layout must be an XKB layout name such as us or de")
	ErrTimezone = errors.New("timezone must be an IANA time zone such as Europe/Berlin or Etc/UTC")
)

var (
	hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	localePattern   = regexp.MustCompile(`^[a-z]{2,3}(_[A-Z]{2})?\.UTF-8$`)
	keyboardPattern = regexp.MustCompile(`^[a-z]{2,8}$`)
	timezonePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
)

// Validate checks the fields an administrator chooses.
func Validate(release, hostname, locale, keyboardLayout, timezone string) error {
	switch {
	case !slices.Contains(Releases, release):
		return ErrRelease
	case !hostnamePattern.MatchString(hostname):
		return ErrHostname
	case !localePattern.MatchString(locale):
		return ErrLocale
	case !keyboardPattern.MatchString(keyboardLayout):
		return ErrKeyboard
	case len(timezone) > 64 || !timezonePattern.MatchString(timezone):
		return ErrTimezone
	}
	return nil
}

//go:embed templates/*.tmpl
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{"q": quote, "list": quoteList}).
	ParseFS(templateFS, "templates/*.tmpl"))

// fetchScript downloads argv[1] in the target, checks its SHA-256 against argv[2] and writes it to argv[3]; a
// mismatch fails the installation.
const fetchScript = `import hashlib, sys, urllib.request
url, want, path = sys.argv[1:4]
data = urllib.request.urlopen(url, timeout=300).read()
if hashlib.sha256(data).hexdigest() != want:
    sys.exit("paddock: SHA-256 mismatch for " + url)
open(path, "wb").write(data)
`

// crypttabScript adds tpm2-device=auto to the options of every LUKS entry that has no TPM2 option yet.
const crypttabScript = `/^\s*#/! { /tpm2-device=/! s/^(\S+\s+\S+\s+\S+\s+)(\S*luks\S*)/\1\2,tpm2-device=auto/ }`

// view is the data of a template.
type view struct {
	Input
	GeneratedAt            string
	InstallUser            string
	Passphrase             string
	EnrollmentConfigBase64 string
	DiskSetup              string
	FetchScript            string
	CrypttabScript         string
	Packages               []viewPackage
	PackagePaths           []string
}

type viewPackage struct {
	Package
	Path string // download location in the target
}

// Render renders the user-data of in with a new random passphrase.
func Render(in Input, now time.Time) ([]byte, error) {
	if err := Validate(in.Release, in.Hostname, in.Locale, in.KeyboardLayout, in.Timezone); err != nil {
		return nil, err
	}
	if len(in.Packages) == 0 || !json.Valid(in.EnrollmentConfig) {
		return nil, errors.New("autoinstall: packages and an enrollment configuration are required")
	}
	passphrase, err := NewPassphrase()
	if err != nil {
		return nil, err
	}
	diskSetup, err := json.Marshal(map[string]int{"boot_pin_min_length": in.BootPINMinLength})
	if err != nil {
		return nil, err
	}
	v := view{
		Input: in, GeneratedAt: now.UTC().Format(time.RFC3339), InstallUser: InstallUser, Passphrase: passphrase,
		EnrollmentConfigBase64: base64.StdEncoding.EncodeToString(in.EnrollmentConfig), DiskSetup: string(diskSetup),
		FetchScript: fetchScript, CrypttabScript: crypttabScript,
	}
	for _, p := range in.Packages {
		path := "/tmp/" + p.Name + ".deb"
		v.Packages = append(v.Packages, viewPackage{Package: p, Path: path})
		v.PackagePaths = append(v.PackagePaths, path)
	}
	var out bytes.Buffer
	if err := templates.ExecuteTemplate(&out, "user-data."+in.Release+".yaml.tmpl", v); err != nil {
		return nil, fmt.Errorf("autoinstall: render %s: %w", in.Release, err)
	}
	return out.Bytes(), nil
}

// passphraseAlphabet is alphanumeric, so the passphrase can be typed at any keyboard layout's prompt.
const passphraseAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// NewPassphrase returns PassphraseLength random characters of passphraseAlphabet (rejection sampling, no bias).
func NewPassphrase() (string, error) {
	out := make([]byte, 0, PassphraseLength)
	var b [64]byte
	for len(out) < PassphraseLength {
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("autoinstall: passphrase: %w", err)
		}
		for _, c := range b {
			if int(c) < 4*len(passphraseAlphabet) && len(out) < PassphraseLength {
				out = append(out, passphraseAlphabet[int(c)%len(passphraseAlphabet)])
			}
		}
	}
	return string(out), nil
}

// quote renders s as a JSON string, which YAML reads as a double-quoted scalar.
func quote(s string) (string, error) {
	b, err := json.Marshal(s)
	return string(b), err
}

// quoteList renders strings as comma-separated JSON strings for a flow sequence.
func quoteList(list []string) (string, error) {
	parts := make([]string, len(list))
	for i, s := range list {
		q, err := quote(s)
		if err != nil {
			return "", err
		}
		parts[i] = q
	}
	return strings.Join(parts, ", "), nil
}

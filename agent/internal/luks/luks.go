// Package luks reads the LUKS2 metadata of the device's root volume and changes its keyslots with cryptsetup and
// systemd-cryptenroll (plan M4b, PoC M1 C7–C9). Secrets — the PIN, the recovery key, the unlock key file — never
// appear on a command line or in an error: the PIN travels in the environment of systemd-cryptenroll, the recovery
// key only in its standard output, which is never logged.
package luks

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Tools runs the LUKS tools (findmnt, lsblk, cryptsetup, systemd-cryptenroll) with extra environment variables;
// stdout is returned separately from stderr, which alone may appear in errors. OS implements it; tests fake it.
type Tools interface {
	Command(ctx context.Context, env []string, name string, args ...string) (stdout, stderr string, exit int, err error)
}

// ErrNotEncrypted means the root file system is not on a LUKS volume.
var ErrNotEncrypted = errors.New("luks: the root file system is not on a LUKS volume")

// Volume is the LUKS volume below the root file system.
type Volume struct {
	Device  string // the LUKS partition, e.g. /dev/sda3
	Mapping string // its dm-crypt mapping (the crypttab name), e.g. dm_crypt-0
}

type blockDevice struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	FSType   string        `json:"fstype"`
	Children []blockDevice `json:"children"`
}

// Root finds the LUKS volume the root file system is on: the device of / and, walking its dependencies (lsblk -s),
// the first crypto_LUKS device below a crypt mapping.
func Root(ctx context.Context, t Tools) (Volume, error) {
	src, err := run(ctx, t, nil, "findmnt", "--noheadings", "--output", "SOURCE", "--target", "/")
	if err != nil {
		return Volume{}, err
	}
	// btrfs subvolumes are reported as /dev/sda2[/@].
	src, _, _ = strings.Cut(strings.TrimSpace(src), "[")
	out, err := run(ctx, t, nil, "lsblk", "--inverse", "--json", "--paths", "--output", "NAME,TYPE,FSTYPE", "--", src)
	if err != nil {
		return Volume{}, err
	}
	var tree struct {
		BlockDevices []blockDevice `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(out), &tree); err != nil {
		return Volume{}, fmt.Errorf("luks: lsblk: %w", err)
	}
	if v, ok := findLUKS(tree.BlockDevices, nil); ok {
		return v, nil
	}
	return Volume{}, ErrNotEncrypted
}

func findLUKS(devs []blockDevice, parent *blockDevice) (Volume, bool) {
	for i := range devs {
		d := &devs[i]
		if d.FSType == "crypto_LUKS" && parent != nil && parent.Type == "crypt" {
			return Volume{Device: d.Name, Mapping: filepath.Base(parent.Name)}, true
		}
		if v, ok := findLUKS(d.Children, d); ok {
			return v, true
		}
	}
	return Volume{}, false
}

// Metadata is the LUKS2 JSON metadata (cryptsetup luksDump --dump-json-metadata) as far as Paddock reads it.
type Metadata struct {
	Keyslots map[string]json.RawMessage `json:"keyslots"`
	Tokens   map[string]Token           `json:"tokens"`
	// Raw is the complete JSON metadata; its digest tells whether the header changed since it was escrowed.
	Raw []byte `json:"-"`
}

// Token is a LUKS2 token.
type Token struct {
	Type     string   `json:"type"`
	Keyslots []string `json:"keyslots"`
	TPM2PIN  bool     `json:"tpm2-pin"`
	TPM2PCRs []int    `json:"tpm2-pcrs"`
}

// Kinds of keyslots in an inventory.
const (
	KindTPM2PIN  = "tpm2+pin"
	KindTPM2     = "tpm2"
	KindRecovery = "recovery"
	KindPassword = "password" // a keyslot without a token: a passphrase or a key file
)

// Dump reads the metadata of a LUKS2 volume.
func Dump(ctx context.Context, t Tools, device string) (Metadata, error) {
	out, err := run(ctx, t, nil, "cryptsetup", "luksDump", "--dump-json-metadata", "--", device)
	if err != nil {
		return Metadata{}, err
	}
	var m Metadata
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return Metadata{}, fmt.Errorf("luks: metadata of %s: %w", device, err)
	}
	m.Raw = []byte(out)
	return m, nil
}

// Version returns the LUKS version of a volume (1 or 2).
func Version(ctx context.Context, t Tools, device string) (int, error) {
	out, err := run(ctx, t, nil, "cryptsetup", "luksDump", "--", device)
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "Version:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, fmt.Errorf("luks: no version in the header of %s", device)
}

// Kinds returns the kind of every keyslot, sorted: a keyslot referenced by a systemd-tpm2 token is tpm2+pin (or
// tpm2 without PIN), by systemd-recovery recovery, by another token its type without "systemd-", and a keyslot
// without a token password.
func (m Metadata) Kinds() []string {
	kinds := make([]string, 0, len(m.Keyslots))
	for slot := range m.Keyslots {
		kinds = append(kinds, m.kind(slot))
	}
	sort.Strings(kinds)
	return kinds
}

// Kind returns the kind of keyslot slot, "" if the slot is not in use.
func (m Metadata) Kind(slot int) string {
	key := strconv.Itoa(slot)
	if _, ok := m.Keyslots[key]; !ok {
		return ""
	}
	return m.kind(key)
}

// Slots returns the numbers of the keyslots of kind, sorted.
func (m Metadata) Slots(kind string) []int {
	var slots []int
	for key := range m.Keyslots {
		if n, err := strconv.Atoi(key); err == nil && m.kind(key) == kind {
			slots = append(slots, n)
		}
	}
	sort.Ints(slots)
	return slots
}

func (m Metadata) kind(slot string) string {
	kind := KindPassword
	for _, tok := range m.Tokens {
		if !slices.Contains(tok.Keyslots, slot) {
			continue
		}
		switch tok.Type {
		case "systemd-tpm2":
			kind = KindTPM2
			if tok.TPM2PIN {
				kind = KindTPM2PIN
			}
		case "systemd-recovery":
			kind = KindRecovery
		default:
			kind = strings.TrimPrefix(tok.Type, "systemd-")
		}
	}
	return kind
}

// Has reports whether one of the keyslots is of kind.
func (m Metadata) Has(kind string) bool { return slices.Contains(m.Kinds(), kind) }

// EnrollTPM2PIN adds a TPM2 token with PIN bound to PCR 7 (PoC M1 C7), unlocking with the key file. The PIN is
// passed as NEWPIN in the environment.
func EnrollTPM2PIN(ctx context.Context, t Tools, device, keyFile string, pin []byte) error {
	_, err := run(ctx, t, []string{"NEWPIN=" + string(pin)}, "systemd-cryptenroll", "--tpm2-device=auto", "--tpm2-with-pin=yes",
		"--tpm2-pcrs=7", "--unlock-key-file="+keyFile, device)
	return err
}

// recoveryKeyPattern is the format of systemd-cryptenroll recovery keys: 64 modhex characters (256 bits) in groups
// of eight.
var recoveryKeyPattern = regexp.MustCompile(`^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$`)

// EnrollRecovery adds a systemd-recovery keyslot, unlocking with the key file, and returns the recovery key. The
// caller holds it in memory only and clears it after use.
func EnrollRecovery(ctx context.Context, t Tools, device, keyFile string) ([]byte, error) {
	out, err := run(ctx, t, nil, "systemd-cryptenroll", "--recovery-key", "--unlock-key-file="+keyFile, device)
	if err != nil {
		return nil, err
	}
	var key []byte
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); recoveryKeyPattern.MatchString(line) {
			key = []byte(line)
		}
	}
	if key == nil {
		return nil, errors.New("luks: systemd-cryptenroll printed no recovery key")
	}
	return key, nil
}

// unlockedSlot is cryptsetup's verbose report of the keyslot a key opened.
var unlockedSlot = regexp.MustCompile(`(?m)^Key slot (\d+) unlocked\.$`)

// KeySlot returns the keyslot the key file opens (cryptsetup open --test-passphrase --verbose). Token plugins are not
// loaded, so a TPM2+PIN token never asks for its PIN.
func KeySlot(ctx context.Context, t Tools, device, keyFile string) (int, error) {
	out, err := run(ctx, t, nil, "cryptsetup", "open", "--test-passphrase", "--verbose", "--disable-external-tokens",
		"--key-file", keyFile, device)
	if err != nil {
		return 0, err
	}
	m := unlockedSlot.FindStringSubmatch(out)
	if m == nil {
		return 0, fmt.Errorf("luks: cryptsetup reported no keyslot for the key file on %s", device)
	}
	return strconv.Atoi(m[1])
}

// WipeSlot removes exactly the keyslot slot, unlocking with the key file (plan M4b.1 decision 3). It names the slot by
// number (systemd-cryptenroll --wipe-slot=<n>), never by type, which would remove every keyslot of that type;
// cryptsetup luksKillSlot is not used because it refuses a key file that opens only the slot to be removed.
func WipeSlot(ctx context.Context, t Tools, device, keyFile string, slot int) error {
	if slot < 0 {
		return fmt.Errorf("luks: invalid keyslot %d", slot)
	}
	_, err := run(ctx, t, nil, "systemd-cryptenroll", "--wipe-slot="+strconv.Itoa(slot), "--unlock-key-file="+keyFile, device)
	return err
}

// HeaderBackup writes the header of device to file, which must not exist.
func HeaderBackup(ctx context.Context, t Tools, device, file string) error {
	_, err := run(ctx, t, nil, "cryptsetup", "luksHeaderBackup", device, "--header-backup-file", file)
	return err
}

// TPM2Present reports whether the device has a TPM 2.0 (below root, "/" on a device).
func TPM2Present(root string) bool {
	v, err := os.ReadFile(filepath.Join(root, "/sys/class/tpm/tpm0/tpm_version_major")) //nolint:gosec // fixed sysfs path below the layout root
	return err == nil && strings.TrimSpace(string(v)) == "2"
}

// run runs a tool and fails on a non-zero exit with its stderr (never its stdout).
func run(ctx context.Context, t Tools, env []string, name string, args ...string) (string, error) {
	stdout, stderr, exit, err := t.Command(ctx, env, name, args...)
	if err != nil {
		return "", fmt.Errorf("luks: %s: %w", name, err)
	}
	if exit != 0 {
		return "", fmt.Errorf("luks: %s %s: exit %d: %s", name, firstArg(args), exit, strings.TrimSpace(stderr))
	}
	return stdout, nil
}

// firstArg names the operation in errors without the arguments that follow it.
func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

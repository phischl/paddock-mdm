package revoke

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
)

// CrypttabFile lists the encrypted volumes of the device besides the root volume (plan M4c.1 decision 1).
const CrypttabFile = "/etc/crypttab"

// SelectWithin bounds the classification of the crypttab entries (cryptsetup isLuks): a hung device must not keep
// the root volume from being erased (plan M4c.1, review round 1). Entries not classified in time are unresolved.
const SelectWithin = time.Minute

// Targets are the LUKS volumes a revocation erases: every other LUKS volume of /etc/crypttab first, the root volume
// last (plan M4c.1 decision 1). Unresolved lists the crypttab sources that could not be erased with certainty; they
// are reported in the confirmation, do not stop the erasure of the others (decision 3) and make it incomplete.
type Targets struct {
	Devices    []string
	Unresolved []string
}

// errUnsupportedSource is a crypttab source that is neither UUID=, PARTUUID= nor a /dev path, or a header that is no
// absolute path.
var errUnsupportedSource = errors.New("revoke: unsupported crypttab source")

// crypttabEntry is one line of /etc/crypttab: its source (field 2; the name when it has none) and its options
// (field 4).
type crypttabEntry struct {
	source  string
	options []string
}

// option returns the value of the option name (name=value), or "" and false.
func (e crypttabEntry) option(name string) (string, bool) {
	for _, o := range e.options {
		if v, ok := strings.CutPrefix(o, name+"="); ok {
			return v, true
		}
	}
	return "", false
}

// plain reports whether the entry is a plain dm-crypt volume (plain, swap or tmp): one without keyslots.
func (e crypttabEntry) plain() bool {
	for _, o := range e.options {
		name, _, _ := strings.Cut(o, "=")
		if name == "plain" || name == "swap" || name == "tmp" {
			return true
		}
	}
	return false
}

// classified is the outcome for one crypttab entry: a target, nothing to erase, or unresolved.
type classified struct {
	target     string
	skip       bool
	unresolved bool
}

// crypttabTargets reads /etc/crypttab below root and determines the targets with volumes. Without the file the root
// volume is the only target; an unreadable file is reported as unresolved, and the root volume is still erased.
func crypttabTargets(ctx context.Context, t luks.Tools, root, rootDevice string) Targets {
	crypttab, err := os.ReadFile(filepath.Join("/", root, CrypttabFile)) //nolint:gosec // fixed path of paddock-revoke
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Targets{Devices: []string{rootDevice}, Unresolved: []string{CrypttabFile}}
	}
	return volumes(ctx, t, root, rootDevice, crypttab, SelectWithin)
}

// volumes determines the targets below root ("" on a device) from the root device and the content of /etc/crypttab:
// the entries whose LUKS header (the source, or the header= option of a detached header) is LUKS1 or LUKS2
// (cryptsetup isLuks), without duplicates and without the root device, then the root device. An entry whose
// header is no LUKS header is skipped only when its options mark it plain; any other entry that fails, and every
// entry not classified within within, is unresolved.
func volumes(ctx context.Context, t luks.Tools, root, rootDevice string, crypttab []byte, within time.Duration) Targets {
	rootTarget := rootDevice
	if canonical, err := resolveSource(root, rootDevice); err == nil {
		rootTarget = canonical
	}
	entries := crypttabEntries(crypttab)
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	// The entries are classified in a goroutine, so that a command stuck in the kernel cannot hold up the erasure of
	// the root volume; a result sent after the deadline is dropped.
	results := make(chan classified, len(entries))
	go func() {
		for _, e := range entries {
			if ctx.Err() != nil {
				return
			}
			results <- classify(ctx, t, root, e)
		}
	}()
	var tg Targets
	for i, e := range entries {
		var c classified
		select {
		case c = <-results:
		case <-ctx.Done():
			for _, rest := range entries[i:] {
				tg.Unresolved = append(tg.Unresolved, rest.source)
			}
			tg.Devices = append(tg.Devices, rootTarget)
			return tg
		}
		switch {
		case c.unresolved:
			tg.Unresolved = append(tg.Unresolved, e.source)
		case c.skip, c.target == rootTarget, slices.Contains(tg.Devices, c.target):
		default:
			tg.Devices = append(tg.Devices, c.target)
		}
	}
	tg.Devices = append(tg.Devices, rootTarget)
	return tg
}

// classify resolves the LUKS header of an entry and asks cryptsetup isLuks whether it is one.
func classify(ctx context.Context, t luks.Tools, root string, e crypttabEntry) classified {
	header, detached := e.option("header")
	var target string
	var err error
	if detached {
		target, err = resolveHeader(root, header)
	} else {
		target, err = resolveSource(root, e.source)
	}
	if err != nil {
		return classified{unresolved: true}
	}
	_, _, exit, err := t.Command(ctx, nil, "cryptsetup", "isLuks", "--", target)
	switch {
	case err == nil && exit == 0:
		return classified{target: target}
	case err == nil && exit == 1 && !detached && e.plain():
		return classified{skip: true}
	}
	// isLuks exits 1 for an unreadable device as well as for a plain one: only the options tell them apart.
	return classified{unresolved: true}
}

// crypttabEntries returns the entries of /etc/crypttab, in order.
func crypttabEntries(crypttab []byte) []crypttabEntry {
	var entries []crypttabEntry
	sc := bufio.NewScanner(bytes.NewReader(crypttab))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		e := crypttabEntry{source: f[0]}
		if len(f) >= 2 {
			e.source = f[1]
		}
		if len(f) >= 4 {
			e.options = strings.Split(f[3], ",")
		}
		entries = append(entries, e)
	}
	return entries
}

// resolveSource resolves a crypttab source below root ("" on a device): UUID= and PARTUUID= through the udev links
// in /dev/disk, a /dev path directly; the result is the device path with every symlink followed.
func resolveSource(root, source string) (string, error) {
	var path string
	switch {
	case strings.HasPrefix(source, "UUID="):
		path = diskLink("/dev/disk/by-uuid/", strings.TrimPrefix(source, "UUID="))
	case strings.HasPrefix(source, "PARTUUID="):
		path = diskLink("/dev/disk/by-partuuid/", strings.TrimPrefix(source, "PARTUUID="))
	case strings.HasPrefix(source, "/dev/"):
		path = filepath.Clean(source)
	}
	if !strings.HasPrefix(path, "/dev/") {
		return "", errUnsupportedSource
	}
	device, err := follow(root, path)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(device, "/dev/") {
		return "", errUnsupportedSource
	}
	return device, nil
}

// resolveHeader resolves the header= option of a detached LUKS header: a device like a source, or an absolute file
// path. The path:device form (a file on another device) is not supported and so unresolved.
func resolveHeader(root, header string) (string, error) {
	if strings.HasPrefix(header, "/dev/") || strings.HasPrefix(header, "UUID=") || strings.HasPrefix(header, "PARTUUID=") {
		return resolveSource(root, header)
	}
	if !filepath.IsAbs(header) || strings.ContainsRune(header, ':') {
		return "", errUnsupportedSource
	}
	return follow(root, filepath.Clean(header))
}

// follow follows every symlink of path below root and returns the result as a path on the device.
func follow(root, path string) (string, error) {
	base := filepath.Join("/", root)
	real, err := filepath.EvalSymlinks(filepath.Join(base, path))
	if err != nil {
		return "", err
	}
	return filepath.Join("/", strings.TrimPrefix(real, base)), nil
}

// diskLink is the udev link of an identifier in dir, or "" for an identifier that would leave dir.
func diskLink(dir, id string) string {
	id = strings.Trim(id, `"'`)
	if id == "" || strings.ContainsRune(id, '/') {
		return ""
	}
	return dir + id
}

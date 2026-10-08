package luks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// CrypttabFile lists the encrypted volumes of the device besides the root volume (plan M4c.1 decision 1).
const CrypttabFile = "/etc/crypttab"

// Crypttab is the outcome of reading /etc/crypttab: the root volume and every other LUKS volume, once each and in the
// order of the file. paddock-revoke erases these volumes and the luks reconciler escrows their headers (plan M4c.1
// decision 1, PDK-009): both read them here, so they always agree on the volumes. Unresolved lists the crypttab
// sources that could not be classified with certainty (plan M4c.1 decision 3).
type Crypttab struct {
	Root       string // the root device, with every symlink followed
	Volumes    []CrypttabVolume
	Unresolved []string
}

// CrypttabVolume is a LUKS volume of /etc/crypttab other than the root volume. Header is the path cryptsetup reads
// its LUKS header from: the source device, or the header= option of a detached header. UUID is its LUKS UUID, ""
// when cryptsetup did not report one. Shared marks a volume whose UUID another volume or the root volume has (a
// cloned header, PDK-009 review round 2): it stays a volume to erase, but it is neither escrowed nor tracked, and a
// Lock leaves it alone.
type CrypttabVolume struct {
	Header string
	UUID   string
	Shared bool
}

// errUnsupportedSource is a crypttab source that is neither UUID=, PARTUUID= nor a /dev path, or a header that is no
// absolute path.
var errUnsupportedSource = errors.New("luks: unsupported crypttab source")

// ReadCrypttab reads /etc/crypttab below root ("" or "/" on a device) and classifies its entries within within (see
// ParseCrypttab). Without the file the root volume is the only volume; an unreadable file is reported as unresolved.
func ReadCrypttab(ctx context.Context, t Tools, root, rootDevice string, within time.Duration) Crypttab {
	crypttab, err := os.ReadFile(filepath.Join("/", root, CrypttabFile)) //nolint:gosec // fixed path below the layout root
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Crypttab{Root: canonicalRoot(root, rootDevice), Unresolved: []string{CrypttabFile}}
	}
	return ParseCrypttab(ctx, t, root, rootDevice, crypttab, within)
}

// ParseCrypttab determines the volumes below root from the root device and the content of /etc/crypttab: the entries
// whose LUKS header (the source, or the header= option of a detached header) is LUKS1 or LUKS2 (cryptsetup isLuks),
// without duplicates and without the root device. An entry whose header is no LUKS header is skipped only when its
// options mark it plain; any other entry that fails, and every entry not classified within within, is unresolved.
func ParseCrypttab(ctx context.Context, t Tools, root, rootDevice string, crypttab []byte, within time.Duration) Crypttab {
	c := Crypttab{Root: canonicalRoot(root, rootDevice)}
	entries := crypttabEntries(crypttab)
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	// The entries are classified in a goroutine, so that a command stuck in the kernel cannot hold up the erasure of
	// the root volume (plan M4c.1, review round 1); a result sent after the deadline is dropped.
	rootUUID := make(chan string, 1)
	results := make(chan classified, len(entries))
	go func() {
		id, _ := UUID(ctx, t, c.Root)
		rootUUID <- id
		for _, e := range entries {
			if ctx.Err() != nil {
				return
			}
			results <- classify(ctx, t, root, e)
		}
	}()
	unresolved := func(from int) Crypttab {
		for _, rest := range entries[from:] {
			c.Unresolved = append(c.Unresolved, rest.source)
		}
		return c
	}
	var rootID string
	select {
	case rootID = <-rootUUID:
	case <-ctx.Done():
		return unresolved(0)
	}
	for i, e := range entries {
		var r classified
		select {
		case r = <-results:
		case <-ctx.Done():
			c = markSharedUUIDs(c, rootID)
			return unresolved(i)
		}
		switch {
		case r.unresolved:
			c.Unresolved = append(c.Unresolved, e.source)
		case r.skip, r.volume.Header == c.Root, slices.ContainsFunc(c.Volumes, func(v CrypttabVolume) bool { return v.Header == r.volume.Header }):
		default:
			c.Volumes = append(c.Volumes, r.volume)
		}
	}
	return markSharedUUIDs(c, rootID)
}

// markSharedUUIDs marks every volume whose LUKS UUID another volume or the root volume (rootUUID) has as Shared
// (PDK-009, review round 2): a cloned header cannot be told apart by its UUID, so it cannot be escrowed or tracked,
// but it is still erased by a Destroy.
func markSharedUUIDs(c Crypttab, rootUUID string) Crypttab {
	count := map[string]int{}
	if rootUUID != "" {
		count[rootUUID]++
	}
	for _, v := range c.Volumes {
		if v.UUID != "" {
			count[v.UUID]++
		}
	}
	for i, v := range c.Volumes {
		c.Volumes[i].Shared = v.UUID != "" && count[v.UUID] > 1
	}
	return c
}

// canonicalRoot is the root device with every symlink followed, or as given when it does not resolve.
func canonicalRoot(root, rootDevice string) string {
	if canonical, err := ResolveSource(root, rootDevice); err == nil {
		return canonical
	}
	return rootDevice
}

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

// classified is the outcome for one crypttab entry: a volume, nothing to do, or unresolved.
type classified struct {
	volume     CrypttabVolume
	skip       bool
	unresolved bool
}

// classify resolves the LUKS header of an entry, asks cryptsetup isLuks whether it is one and reads its UUID.
func classify(ctx context.Context, t Tools, root string, e crypttabEntry) classified {
	header, detached := e.option("header")
	var target string
	var err error
	if detached {
		target, err = resolveHeader(root, header)
	} else {
		target, err = ResolveSource(root, e.source)
	}
	if err != nil {
		return classified{unresolved: true}
	}
	_, _, exit, err := t.Command(ctx, nil, "cryptsetup", "isLuks", "--", target)
	switch {
	case err == nil && exit == 0:
		id, _ := UUID(ctx, t, target)
		return classified{volume: CrypttabVolume{Header: target, UUID: id}}
	case err == nil && exit == 1 && !detached && e.plain():
		return classified{skip: true}
	}
	// isLuks exits 1 for an unreadable device as well as for a plain one: only the options tell them apart.
	return classified{unresolved: true}
}

// uuidPattern is the form of a LUKS UUID as cryptsetup prints it.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// UUID returns the LUKS UUID of the header at device (cryptsetup luksUUID), lowercase.
func UUID(ctx context.Context, t Tools, device string) (string, error) {
	out, err := run(ctx, t, nil, "cryptsetup", "luksUUID", "--", device)
	if err != nil {
		return "", err
	}
	id := strings.ToLower(strings.TrimSpace(out))
	if !uuidPattern.MatchString(id) {
		return "", errors.New("luks: cryptsetup reported no UUID for " + device)
	}
	return id, nil
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

// ResolveSource resolves a crypttab source below root ("" on a device): UUID= and PARTUUID= through the udev links
// in /dev/disk, a /dev path directly; the result is the device path with every symlink followed.
func ResolveSource(root, source string) (string, error) {
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
		return ResolveSource(root, header)
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

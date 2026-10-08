package revoke

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
)

// CrypttabFile lists the encrypted volumes of the device besides the root volume (plan M4c.1 decision 1).
const CrypttabFile = "/etc/crypttab"

// Targets are the LUKS volumes a revocation erases: every other LUKS volume of /etc/crypttab first, the root volume
// last (plan M4c.1 decision 1). Unresolved lists the crypttab sources that did not resolve to a device; they are
// reported in the confirmation and do not stop the erasure of the others (decision 3).
type Targets struct {
	Devices    []string
	Unresolved []string
}

// errUnsupportedSource is a crypttab source that is neither UUID=, PARTUUID= nor a /dev path.
var errUnsupportedSource = errors.New("revoke: unsupported crypttab source")

// resolveFunc resolves a crypttab source or a device path to the canonical device path (symlinks followed).
type resolveFunc func(source string) (string, error)

// volumes determines the targets from the root device and the content of /etc/crypttab: the sources that resolve to
// a LUKS1 or LUKS2 device (cryptsetup isLuks), without duplicates and without the root device, then the root device.
func volumes(ctx context.Context, t luks.Tools, rootDevice string, crypttab []byte, resolve resolveFunc) Targets {
	root := rootDevice
	if canonical, err := resolve(rootDevice); err == nil {
		root = canonical
	}
	var tg Targets
	for _, source := range crypttabSources(crypttab) {
		device, err := resolve(source)
		if err != nil {
			tg.Unresolved = append(tg.Unresolved, source)
			continue
		}
		if device == root || slices.Contains(tg.Devices, device) {
			continue
		}
		_, _, exit, err := t.Command(ctx, nil, "cryptsetup", "isLuks", "--", device)
		switch {
		case err != nil || (exit != 0 && exit != 1):
			tg.Unresolved = append(tg.Unresolved, source)
		case exit == 0:
			tg.Devices = append(tg.Devices, device)
		}
		// exit 1: a plain dm-crypt volume (swap with a random key, for example); it has no keyslots to erase.
	}
	tg.Devices = append(tg.Devices, root)
	return tg
}

// crypttabSources returns the second field of every entry of /etc/crypttab, in order; an entry without one is
// returned by its name, so it is reported as unresolved.
func crypttabSources(crypttab []byte) []string {
	var sources []string
	sc := bufio.NewScanner(bytes.NewReader(crypttab))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			sources = append(sources, f[0])
			continue
		}
		sources = append(sources, f[1])
	}
	return sources
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
	base := filepath.Join("/", root)
	real, err := filepath.EvalSymlinks(filepath.Join(base, path))
	if err != nil {
		return "", err
	}
	device := filepath.Join("/", strings.TrimPrefix(real, base))
	if !strings.HasPrefix(device, "/dev/") {
		return "", errUnsupportedSource
	}
	return device, nil
}

// diskLink is the udev link of an identifier in dir, or "" for an identifier that would leave dir.
func diskLink(dir, id string) string {
	id = strings.Trim(id, `"'`)
	if id == "" || strings.ContainsRune(id, '/') {
		return ""
	}
	return dir + id
}

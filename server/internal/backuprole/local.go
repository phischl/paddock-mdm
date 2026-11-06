package backuprole

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// ErrLocalPath marks a local target whose path does not resolve to a real directory below the local root. The host
// step treats it as a refusal: it never mounts a directory it could not confine.
var ErrLocalPath = errors.New("backup target: local path is not a directory below the local root")

// ResolveLocal returns the host directory of a local target: sub below root. Fail closed: root must pass
// backupset.LocalRoot, the subpath backupset.LocalSubpath, and root and every component must exist, be a directory and
// not be a symlink. Root and every component except the leaf must also belong to root and not be writable by group
// or others: the bind mount is resolved again by the kernel on every container start, so whoever can write to a
// parent could swap a component for a symlink after this check. The host step runs it before every compose apply
// and start; it is not a lock.
func ResolveLocal(root, sub string) (string, error) {
	return resolveLocal(root, sub, 0)
}

// resolveLocal is ResolveLocal with the owner the parents must have, so tests can use the current user.
func resolveLocal(root, sub string, owner uint32) (string, error) {
	if err := backupset.LocalRoot(root); err != nil {
		return "", fmt.Errorf("%w: %w", ErrLocalPath, err)
	}
	if err := backupset.LocalSubpath(sub); err != nil {
		return "", fmt.Errorf("%w: %w", ErrLocalPath, err)
	}
	cur := root
	els := strings.Split(sub, "/")
	for i := -1; i < len(els); i++ {
		if i >= 0 {
			cur = filepath.Join(cur, els[i])
		}
		if err := requireDir(cur, i < len(els)-1, owner); err != nil {
			return "", err
		}
	}
	return cur, nil
}

func requireDir(p string, parent bool, owner uint32) error {
	info, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLocalPath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is a symlink or not a directory", ErrLocalPath, p)
	}
	if !parent {
		return nil
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != owner {
		return fmt.Errorf("%w: %s is not owned by uid %d", ErrLocalPath, p, owner)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others", ErrLocalPath, p)
	}
	return nil
}

// Package fsutil writes files atomically: temporary file in the target directory, fsync, rename, fsync of the
// directory (plan M2b decision 6).
package fsutil

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFile atomically replaces path with data. Missing parent directories are created with dirMode.
func WriteFile(path string, data []byte, mode, dirMode fs.FileMode) error {
	return WriteFileOwned(path, data, mode, dirMode, -1, -1)
}

// WriteFileOwned is WriteFile with ownership: uid and gid (-1 = unchanged) are set on the temporary file before the
// rename, so the file never appears with the wrong owner or mode.
func WriteFileOwned(path string, data []byte, mode, dirMode fs.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after the rename
	if err := writeSync(tmp, data, mode, uid, gid); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return SyncDir(dir)
}

func writeSync(f *os.File, data []byte, mode fs.FileMode, uid, gid int) error {
	if _, err := f.Write(data); err != nil {
		return err
	}
	if uid >= 0 || gid >= 0 {
		if err := f.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	return f.Sync()
}

// SyncDir fsyncs a directory so that a rename in it is durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // a directory of the agent layout
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

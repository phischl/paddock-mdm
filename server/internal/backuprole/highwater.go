package backuprole

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// recordHighWater raises the host-side high-water file to the highest device.bundle_seq after a successful round
// (decisions-alpha9 item 68): a restore that cannot read the running stack raises the restored sequences above it. A
// failure only warns: the backups themselves succeeded, and every other restore reads the running stack.
func (e *Engine) recordHighWater(ctx context.Context) {
	if e.cfg.HighWaterFile == "" {
		return
	}
	v, err := e.store.BundleSeqHighWater(ctx)
	if err == nil {
		err = raiseHighWater(e.cfg.HighWaterFile, v)
	}
	if err != nil {
		slog.WarnContext(ctx, "bundle sequence high-water file not updated", "file", e.cfg.HighWaterFile, "error", err)
	}
}

// raiseHighWater writes v to path unless the file already holds v or more, so the file never decreases. Content that is
// no number counts as 0, as in the restore scripts (scripts/bundle-seq.sh), which write the same file.
func raiseHighWater(path string, v int64) error {
	var cur int64
	b, err := os.ReadFile(path) //nolint:gosec // the path is the role's configured high-water file
	switch {
	case err == nil:
		line, _, _ := strings.Cut(string(b), "\n")
		if n, perr := strconv.ParseInt(strings.TrimSpace(line), 10, 64); perr == nil && n > 0 {
			cur = n
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("read %s: %w", path, err)
	}
	if v <= cur {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".high-water-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.WriteString(strconv.FormatInt(v, 10) + "\n")
	if err == nil {
		// Readable by the restore scripts, which may run as another user than the role; it holds no secret.
		err = tmp.Chmod(0o644) //nolint:gosec // a public number, read by the host's restore scripts
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

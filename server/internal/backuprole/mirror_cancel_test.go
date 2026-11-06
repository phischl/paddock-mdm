package backuprole

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// cancelAtList is any target that cancels the mirror's context on its at-th List.
type cancelAtList struct {
	Target
	cancel context.CancelFunc
	at     int
	lists  int
}

func (c *cancelAtList) List(ctx context.Context) (map[string]int64, error) {
	if c.lists++; c.lists == c.at {
		c.cancel()
	}
	return c.Target.List(ctx)
}

// TestCancelledMirrorWritesNoManifest: a mirror whose context ends after it verified its copies (the stall watchdog
// gave up during the step-4 listing) writes no manifest.json, also to an empty target where step 6 has nothing to
// judge, on a memory and on a directory target (PDK-862).
func TestCancelledMirrorWritesNoManifest(t *testing.T) {
	repo, idx := openSet(t, map[string]string{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil)),
		"openbao/20261105T060000Z.snap.enc": "a"})
	targets := map[string]func(t *testing.T) (Target, func() bool){
		"memory": func(*testing.T) (Target, func() bool) {
			m := newMemTarget()
			return m, func() bool { _, ok := m.files[backupset.ManifestPath]; return ok }
		},
		"directory": func(t *testing.T) (Target, func() bool) {
			root := filepath.Join(t.TempDir(), "target")
			if err := os.MkdirAll(root, 0o750); err != nil {
				t.Fatal(err)
			}
			return NewDirTarget(root), func() bool {
				_, err := os.Stat(filepath.Join(root, backupset.ManifestPath))
				return err == nil
			}
		},
	}
	for name, open := range targets {
		t.Run(name, func(t *testing.T) {
			dst, written := open(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wrapped := &cancelAtList{Target: dst, cancel: cancel, at: 2}
			_, err := mirrorSet(ctx, repo, idx, wrapped, map[string]fileInfo{}, testRetention(time.Now()), noHooks())
			if !errors.Is(err, context.Canceled) {
				t.Errorf("error %v, want context.Canceled", err)
			}
			if written() {
				t.Error("manifest.json written after the mirror's context ended")
			}
		})
	}
}

// cancellingReader cancels a context on its first read, as the stall watchdog giving up during a copy.
type cancellingReader struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (c *cancellingReader) Read(b []byte) (int, error) {
	c.cancel()
	return c.r.Read(b)
}

// TestDirTargetPutHonoursContext: a directory target writes nothing, and leaves no temporary file, for a Put whose
// context ended before or during the copy (PDK-862).
func TestDirTargetPutHonoursContext(t *testing.T) {
	root := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	dst := NewDirTarget(root)
	body := strings.Repeat("x", 1<<20)
	t.Run("before", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := dst.Put(ctx, "fleet/a.enc", strings.NewReader(body), int64(len(body))); !errors.Is(err, context.Canceled) {
			t.Errorf("error %v, want context.Canceled", err)
		}
	})
	t.Run("during", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		src := &cancellingReader{r: strings.NewReader(body), cancel: cancel}
		if err := dst.Put(ctx, "fleet/b.enc", src, int64(len(body))); !errors.Is(err, context.Canceled) {
			t.Errorf("error %v, want context.Canceled", err)
		}
	})
	t.Run("not cancelled", func(t *testing.T) {
		if err := dst.Put(context.Background(), "fleet/c.enc", strings.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
	})
	var left []string
	_ = filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			left = append(left, filepath.Base(p))
		}
		return nil
	})
	if len(left) != 1 || left[0] != "c.enc" {
		t.Errorf("target holds %v, want only c.enc", left)
	}
}

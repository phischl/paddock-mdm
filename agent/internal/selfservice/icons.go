package selfservice

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// IconDir caches the catalog icons the agent fetched from the server, one <entry_id>.png each (plan M13b decision 16).
const IconDir = "/var/lib/paddock/cache/icons"

// maxIcon is the server's limit of a catalog icon (software.MaxIconBytes).
const maxIcon = 65536

var (
	pngMagic = []byte("\x89PNG\r\n\x1a\n")
	// entryID is the form of a catalog entry ID; only such an ID becomes a file name.
	entryID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// iconCache knows which entries have a cached icon and which the server had none for (fetched once per entry and
// process).
type iconCache struct {
	mu     sync.Mutex
	cached map[string]bool
	tried  map[string]bool
}

func (c *iconCache) has(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cached[id]
}

func iconPath(id string) string { return IconDir + "/" + id + ".png" }

// Icon returns the cached PNG of an entry p may see; nil when there is none.
func (s *Service) Icon(p Principal, id string) ([]byte, error) {
	s.mu.Lock()
	applied := s.snap.applied
	_, ok := find(s.snap.spec, id, p)
	s.mu.Unlock()
	if !applied {
		return nil, errNoBundle
	}
	notFound := &Problem{Status: http.StatusNotFound, Code: CodeUnknownEntry, Detail: "no icon"}
	if !ok || !entryID.MatchString(id) || !s.icons.has(id) {
		return nil, notFound
	}
	data, _, err := s.cfg.Sys.ReadFile(iconPath(id))
	if err != nil {
		return nil, notFound
	}
	return data, nil
}

// fillIcons fetches the icons of the bundle's entries that are not cached yet, after every SetBundle, and removes
// the icons of entries the bundle no longer has. It runs apart from the executor: a slow server never delays an
// operation.
func (s *Service) fillIcons(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.iconWake:
		}
		s.mu.Lock()
		spec, fetch := s.snap.spec, s.snap.fetch
		s.mu.Unlock()
		s.syncIcons(ctx, spec, fetch)
	}
}

func (s *Service) syncIcons(ctx context.Context, sp bundle.SoftwareSpec, fetch IconFetch) {
	ids := map[string]bool{}
	for _, p := range sp.Packages {
		if p.CatalogEntryID != bundle.SoftwareRuntimeEntryID && entryID.MatchString(p.CatalogEntryID) {
			ids[p.CatalogEntryID] = true
		}
	}
	names, _ := s.cfg.Sys.ReadDir(IconDir) // a missing directory has no icons
	cached := map[string]bool{}
	for _, n := range names {
		id, ok := strings.CutSuffix(n, ".png")
		switch {
		case ok && ids[id]:
			cached[id] = true
		default:
			if err := s.cfg.Sys.Remove(IconDir + "/" + n); err != nil {
				slog.WarnContext(ctx, "removing a cached icon failed", "file", n, "error", err)
			}
		}
	}
	s.setCached(cached)
	if fetch == nil {
		return
	}
	for id := range ids {
		if ctx.Err() != nil {
			return
		}
		s.icons.mu.Lock()
		skip := cached[id] || s.icons.tried[id]
		s.icons.mu.Unlock()
		if skip {
			continue
		}
		data, err := fetch(ctx, id)
		var apiErr *client.APIError
		switch {
		case errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound:
			s.markTried(id)
			continue
		case err != nil:
			slog.DebugContext(ctx, "fetching a catalog icon failed; retrying with the next bundle", "entry_id", id, "error", err)
			continue
		case len(data) > maxIcon || !bytes.HasPrefix(data, pngMagic):
			slog.WarnContext(ctx, "the server sent a catalog icon that is no PNG of at most 64 KiB", "entry_id", id)
			s.markTried(id)
			continue
		}
		if err := s.cfg.Sys.WriteFileAtomic(iconPath(id), data, 0o600, 0, 0); err != nil {
			slog.WarnContext(ctx, "caching a catalog icon failed", "entry_id", id, "error", err)
			continue
		}
		s.markTried(id)
		cached[id] = true
		s.setCached(cached)
	}
}

func (s *Service) setCached(cached map[string]bool) {
	c := make(map[string]bool, len(cached))
	for k, v := range cached {
		c[k] = v
	}
	s.icons.mu.Lock()
	s.icons.cached = c
	s.icons.mu.Unlock()
}

func (s *Service) markTried(id string) {
	s.icons.mu.Lock()
	s.icons.tried[id] = true
	s.icons.mu.Unlock()
}

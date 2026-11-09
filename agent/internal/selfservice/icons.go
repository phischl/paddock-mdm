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
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// IconDir caches the catalog icons the agent fetched from the server, one <entry_id>.png each (plan M13b decision 16).
const IconDir = "/var/lib/paddock/cache/icons"

// maxIcon is the server's limit of a catalog icon (software.MaxIconBytes).
const maxIcon = 65536

// iconGap is the least time between two icon fetches. Every fetch counts against the device key's rate budget of 30
// requests a minute that check-in, events and command results share, so icons take at most half of it.
const iconGap = 4 * time.Second

// iconBackoff is the pause after a 429 without Retry-After.
const iconBackoff = time.Minute

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
	// gap is iconGap; last is when the previous fetch started (wall clock, it paces real requests).
	gap  time.Duration
	last time.Time
	// notBefore is when the server's last 429 lets the next fetch go (cfg.Now).
	notBefore time.Time
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
		// Only an entry with a digest has an icon (plan M13b decision 16); asking for the others would spend the
		// device's rate budget on a 404.
		if p.IconSHA256 != "" && p.CatalogEntryID != bundle.SoftwareRuntimeEntryID && entryID.MatchString(p.CatalogEntryID) {
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
		if !s.paceIcon(ctx) {
			return
		}
		data, err := fetch(ctx, id)
		var apiErr *client.APIError
		switch {
		case errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound:
			s.markTried(id)
			continue
		case errors.As(err, &apiErr) && apiErr.Status == http.StatusTooManyRequests:
			wait := apiErr.RetryAfter
			if wait <= 0 {
				wait = iconBackoff
			}
			s.icons.mu.Lock()
			s.icons.notBefore = s.cfg.Now().Add(wait)
			s.icons.mu.Unlock()
			slog.DebugContext(ctx, "the server limits icon fetches; resuming with a later bundle", "retry_after", wait)
			return
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

// paceIcon waits until the next icon fetch may go; false when the server's last 429 still holds or ctx ends.
func (s *Service) paceIcon(ctx context.Context) bool {
	s.icons.mu.Lock()
	limited := s.cfg.Now().Before(s.icons.notBefore)
	wait := time.Until(s.icons.last.Add(s.icons.gap))
	s.icons.mu.Unlock()
	if limited {
		return false
	}
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
	s.icons.mu.Lock()
	s.icons.last = time.Now()
	s.icons.mu.Unlock()
	return true
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

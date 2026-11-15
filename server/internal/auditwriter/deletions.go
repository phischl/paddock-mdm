package auditwriter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// DeletionStore lists and reads WORM objects (objectstore.Store).
type DeletionStore interface {
	List(ctx context.Context, prefix string) ([]string, error)
	Open(ctx context.Context, key string) (io.ReadCloser, error)
}

// Deletion is one organization.deleted of the platform pseudo-organization.
type Deletion struct {
	OccurredAt     time.Time
	OrganizationID string
	Slug           string
}

// Deletions reads the organization.deleted events that occurred at or after since from the platform
// pseudo-organization's WORM objects, oldest first (plan M17 §7 step 5, RR-138). It reads the objects, not the audit
// index: after a restore to a point before a deletion the index is rolled back, the WORM bucket is not, so this
// finds the deletions the operator must repeat. The objects are listed per recording day from the day before since
// (an event is recorded after it occurred) through the day of now.
func Deletions(ctx context.Context, store DeletionStore, since, now time.Time) ([]Deletion, error) {
	var out []Deletion
	for day := dayOf(since).AddDate(0, 0, -1); !day.After(dayOf(now)); day = day.AddDate(0, 0, 1) {
		prefix := fmt.Sprintf("org/%s/%04d/%02d/%02d/", audit.PlatformOrganizationID, day.Year(), int(day.Month()), day.Day())
		keys, err := store.List(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("auditwriter: list %s: %w", prefix, err)
		}
		for _, key := range keys {
			if !strings.HasSuffix(key, ".jsonl.zst") {
				continue
			}
			events, err := readObject(ctx, store, key)
			if err != nil {
				return nil, err
			}
			for _, ev := range events {
				if ev.Code != audit.CodeOrganizationDeleted || ev.OccurredAt.Before(since) {
					continue
				}
				d := Deletion{OccurredAt: ev.OccurredAt.UTC()}
				if ev.Target != nil {
					d.OrganizationID = ev.Target.ID
				}
				d.Slug, _ = ev.Params["slug"].(string)
				out = append(out, d)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].OccurredAt.Before(out[j].OccurredAt) })
	return out, nil
}

// readObject decodes one WORM object of at most MaxObjectSize bytes.
func readObject(ctx context.Context, store DeletionStore, key string) ([]audit.Event, error) {
	r, err := store.Open(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("auditwriter: open %s: %w", key, err)
	}
	defer func() { _ = r.Close() }()
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, MaxObjectSize+1))
	if err != nil {
		return nil, fmt.Errorf("auditwriter: read %s: %w", key, err)
	}
	if n > MaxObjectSize {
		return nil, fmt.Errorf("auditwriter: %s is larger than %d bytes", key, MaxObjectSize)
	}
	events, err := DecodeObject(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("auditwriter: decode %s: %w", key, err)
	}
	return events, nil
}

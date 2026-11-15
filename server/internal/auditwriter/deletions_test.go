package auditwriter_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

// wormMem is a WORM bucket in memory.
type wormMem map[string][]byte

func (m wormMem) List(_ context.Context, prefix string) ([]string, error) {
	var keys []string
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m wormMem) Open(_ context.Context, key string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m[key])), nil
}

func (m wormMem) put(t *testing.T, org uuid.UUID, recorded time.Time, events ...audit.Event) {
	t.Helper()
	body, err := auditwriter.EncodeObject(events)
	if err != nil {
		t.Fatal(err)
	}
	m[auditwriter.ObjectKey(org, recorded.Truncate(time.Hour), events[0].EventID)] = body
}

func deletedEvent(org uuid.UUID, slug string, at time.Time) audit.Event {
	ev := event(audit.PlatformOrganizationID, at, audit.CodeOrganizationDeleted)
	ev.Target = &audit.Target{Type: "organization", ID: org.String(), Display: slug}
	ev.Params = map[string]any{"slug": slug}
	return ev
}

// TestDeletions: the organization.deleted events of the platform pseudo-organization from the WORM objects, since the
// given moment, oldest first; other codes, other organizations and earlier deletions are left out.
func TestDeletions(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -2)
	first, second, early, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	store := wormMem{}
	store.put(t, audit.PlatformOrganizationID, since.Add(-time.Hour), deletedEvent(early, "early", since.Add(-time.Hour)))
	// Occurred just after since, recorded in the next hour of the same day.
	store.put(t, audit.PlatformOrganizationID, since.Add(time.Hour), deletedEvent(second, "second", since.Add(30*time.Minute)),
		event(audit.PlatformOrganizationID, since.Add(30*time.Minute), audit.CodeOrganizationDeletionStepCompleted))
	store.put(t, audit.PlatformOrganizationID, since.Add(-30*time.Hour+time.Hour), deletedEvent(early, "older", since.Add(-30*time.Hour)))
	store.put(t, audit.PlatformOrganizationID, now.Add(-time.Hour), deletedEvent(first, "first", since.Add(10*time.Minute)))
	store.put(t, foreign, now.Add(-time.Hour), deletedEvent(foreign, "foreign", now.Add(-time.Hour)))

	got, err := auditwriter.Deletions(context.Background(), store, since, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Slug != "first" || got[0].OrganizationID != first.String() ||
		!got[0].OccurredAt.Equal(audit.Timestamp(since.Add(10*time.Minute))) || got[1].Slug != "second" ||
		got[1].OrganizationID != second.String() {
		t.Fatalf("deletions %+v", got)
	}
}

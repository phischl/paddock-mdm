package spool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func newSpool(t *testing.T, capBytes int64) (*Spool, *int64) {
	t.Helper()
	seq := new(int64)
	return New(filepath.Join(t.TempDir(), "spool", "events.jsonl"), capBytes, func() (int64, error) {
		*seq++
		return *seq, nil
	}), seq
}

func TestAddPendingRemove(t *testing.T) {
	s, _ := newSpool(t, DefaultCap)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for i := range 3 {
		if err := s.Add(protocol.EventBundleApplied, now, map[string]int{"version": i}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.Pending()
	if err != nil || len(events) != 3 || events[0].EventSeq != 1 || events[2].EventSeq != 3 {
		t.Fatalf("pending %+v, %v", events, err)
	}
	if err := s.Remove(map[int64]bool{1: true, 3: true}); err != nil {
		t.Fatal(err)
	}
	events, _ = s.Pending()
	if len(events) != 1 || events[0].EventSeq != 2 || string(events[0].Data) != `{"version":1}` {
		t.Fatalf("after remove: %+v", events)
	}
	if fi, _ := os.Stat(s.path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("spool mode %v", fi.Mode().Perm())
	}
}

func TestTornLineIgnored(t *testing.T) {
	s, _ := newSpool(t, DefaultCap)
	_ = s.Add(protocol.EventBundleApplied, time.Now(), nil)
	f, _ := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"event_seq":2,"ty`)
	_ = f.Close()
	if events, err := s.Pending(); err != nil || len(events) != 1 {
		t.Fatalf("%+v, %v", events, err)
	}
}

func TestCapDropsDriftFirst(t *testing.T) {
	s, _ := newSpool(t, 2000)
	now := time.Now()
	pad := strings.Repeat("x", 100)
	// Alternate drift and applied events until the cap forces drops.
	for i := range 20 {
		typ := protocol.EventConfigDriftCorrected
		if i%2 == 1 {
			typ = protocol.EventBundleApplied
		}
		if err := s.Add(typ, now, map[string]string{"pad": pad}); err != nil {
			t.Fatal(err)
		}
	}
	events, _ := s.Pending()
	fi, _ := os.Stat(s.path)
	if fi.Size() > 2000 {
		t.Fatalf("spool %d bytes above the cap", fi.Size())
	}
	var dropped []Dropped
	types := map[string]int{}
	for _, ev := range events {
		types[ev.Type]++
		if ev.Type == protocol.EventAgentEventsDropped {
			var d Dropped
			_ = json.Unmarshal(ev.Data, &d)
			dropped = append(dropped, d)
		}
	}
	if len(dropped) != 1 || dropped[0].Count == 0 || dropped[0].FromSeq > dropped[0].ToSeq {
		t.Fatalf("want one merged agent.events_dropped: %+v", dropped)
	}
	if types[protocol.EventBundleApplied] < 6 {
		t.Fatalf("bundle.applied dropped before drift events: %v", types)
	}
	for i := 1; i < len(events); i++ {
		if events[i].EventSeq <= events[i-1].EventSeq {
			t.Fatalf("events out of order: %d after %d", events[i].EventSeq, events[i-1].EventSeq)
		}
	}
}

func TestCapDropsOldestWhenNoDrift(t *testing.T) {
	s, _ := newSpool(t, 1500)
	for range 20 {
		_ = s.Add(protocol.EventBundleApplied, time.Now(), map[string]string{"pad": strings.Repeat("y", 100)})
	}
	events, _ := s.Pending()
	if events[0].EventSeq == 1 {
		t.Fatal("the oldest event was kept")
	}
	if last := events[len(events)-1]; last.Type != protocol.EventAgentEventsDropped && events[len(events)-2].EventSeq < 19 {
		t.Fatalf("the newest events were dropped: %+v", events)
	}
}

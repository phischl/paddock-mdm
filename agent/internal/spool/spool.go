// Package spool is the device event spool /var/lib/paddock/spool/events.jsonl (plan M2b decision 12): events are
// appended with fsync, sent in batches after each check-in and removed once the server accepted them. The spool is
// capped; when it overflows, the oldest config.drift_corrected events go first, then the oldest of any type, and
// an agent.events_dropped event records the gap.
package spool

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/fsutil"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// DefaultCap is the spool size limit.
const DefaultCap = 50 << 20

// Spool is the event spool. It is used by one goroutine.
type Spool struct {
	path string
	cap  int64
	// next assigns the next event sequence number (persisted by the caller, see agent state).
	next func() (int64, error)
}

// New opens the spool at path. next returns a new, persisted event sequence number.
func New(path string, capBytes int64, next func() (int64, error)) *Spool {
	return &Spool{path: path, cap: capBytes, next: next}
}

// Add appends an event of type typ with data and enforces the cap.
func (s *Spool) Add(typ string, occurred time.Time, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	seq, err := s.next()
	if err != nil {
		return err
	}
	if err := s.append(protocol.Event{EventSeq: seq, Type: typ, OccurredAt: occurred.UTC(), Data: raw}); err != nil {
		return err
	}
	return s.enforceCap(occurred)
}

func (s *Spool) append(ev protocol.Event) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open spool: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("append to spool: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Pending returns all spooled events in order.
func (s *Spool) Pending() ([]protocol.Event, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read spool: %w", err)
	}
	var out []protocol.Event
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var ev protocol.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue // a torn last line after a crash; the event was never acknowledged as spooled
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}

// Remove deletes the events with the given sequence numbers (accepted by the server).
func (s *Spool) Remove(seqs map[int64]bool) error {
	events, err := s.Pending()
	if err != nil {
		return err
	}
	keep := events[:0]
	for _, ev := range events {
		if !seqs[ev.EventSeq] {
			keep = append(keep, ev)
		}
	}
	return s.rewrite(keep)
}

func (s *Spool) rewrite(events []protocol.Event) error {
	var buf bytes.Buffer
	for _, ev := range events {
		line, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		buf.Write(append(line, '\n'))
	}
	return fsutil.WriteFile(s.path, buf.Bytes(), 0o600, 0o700)
}

// Dropped is the data of agent.events_dropped.
type Dropped struct {
	Count   int   `json:"count"`
	FromSeq int64 `json:"from_seq"`
	ToSeq   int64 `json:"to_seq"`
}

// enforceCap drops events until the spool fits into the cap, leaving room for the agent.events_dropped event. An
// undelivered agent.events_dropped event from an earlier overflow is merged into the new one, so a long outage
// leaves one record of the gap.
func (s *Spool) enforceCap(now time.Time) error {
	fi, err := os.Stat(s.path)
	if err != nil || fi.Size() <= s.cap {
		return err
	}
	events, err := s.Pending()
	if err != nil {
		return err
	}
	size := fi.Size()
	const reserve = 256 // the agent.events_dropped line
	drop := map[int64]bool{}
	d := Dropped{FromSeq: -1}
	take := func(ev protocol.Event, from, to int64, count int) {
		line, _ := json.Marshal(ev)
		size -= int64(len(line) + 1)
		drop[ev.EventSeq] = true
		d.Count += count
		if d.FromSeq < 0 || from < d.FromSeq {
			d.FromSeq = from
		}
		d.ToSeq = max(d.ToSeq, to)
	}
	for _, ev := range events {
		var prev Dropped
		if ev.Type == protocol.EventAgentEventsDropped && json.Unmarshal(ev.Data, &prev) == nil {
			take(ev, prev.FromSeq, prev.ToSeq, prev.Count)
		}
	}
	for _, pass := range []func(protocol.Event) bool{
		func(ev protocol.Event) bool { return ev.Type == protocol.EventConfigDriftCorrected },
		func(protocol.Event) bool { return true },
	} {
		for _, ev := range events {
			if size+reserve <= s.cap {
				break
			}
			if !drop[ev.EventSeq] && pass(ev) {
				take(ev, ev.EventSeq, ev.EventSeq, 1)
			}
		}
	}
	if err := s.Remove(drop); err != nil {
		return err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	seq, err := s.next()
	if err != nil {
		return err
	}
	return s.append(protocol.Event{EventSeq: seq, Type: protocol.EventAgentEventsDropped, OccurredAt: now.UTC(), Data: raw})
}

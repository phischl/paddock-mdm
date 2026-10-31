package notifier

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
)

// fakeDelivery is a notification_delivery row.
type fakeDelivery struct {
	dest        uuid.UUID
	kind        string
	refs        []EventRef
	attempts    int
	delivered   bool
	lastError   string
	requestedBy string
}

// fakeStore keeps the notifier's tables in memory with the semantics of the queries in notifier.sql.
type fakeStore struct {
	mu         sync.Mutex
	orgs       []uuid.UUID
	slugs      map[uuid.UUID]string
	rows       map[uuid.UUID]*Row // by destination
	deliveries map[uuid.UUID]*fakeDelivery
	order      []uuid.UUID // test deliveries in request order
	records    []Record
	lookups    map[uuid.UUID]*Lookup
	resolved   map[uuid.UUID]string
	names      []string
	pkey       map[uuid.UUID]string
}

func newFakeStore() *fakeStore {
	return &fakeStore{slugs: map[uuid.UUID]string{}, rows: map[uuid.UUID]*Row{}, deliveries: map[uuid.UUID]*fakeDelivery{},
		lookups: map[uuid.UUID]*Lookup{}, resolved: map[uuid.UUID]string{}, pkey: map[uuid.UUID]string{}}
}

func (f *fakeStore) add(org uuid.UUID, d Destination, st State) *Row {
	d.Org = org
	if st.Status == "" {
		st.Status = StatusActive
	}
	r := &Row{Destination: d, State: st, URLCiphertext: "url:" + d.ID.String(), SecretCiphertext: "secret:" + d.ID.String()}
	f.rows[d.ID] = r
	return r
}

func (f *fakeStore) Organizations(context.Context) ([]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.orgs, nil
}

func (f *fakeStore) Load(_ context.Context, sc Scope) (ScopeData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data := ScopeData{Slug: outbound.PlatformOrganization, PseudonymKey: f.pkey[sc.Org]}
	if !sc.Platform() {
		data.Slug = f.slugs[sc.Org]
	}
	var ids []uuid.UUID
	for id, r := range f.rows {
		if r.Destination.Org == sc.Org {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	for _, id := range ids {
		data.Rows = append(data.Rows, *f.rows[id])
	}
	return data, nil
}

func (f *fakeStore) row(sc Scope, dest uuid.UUID) *Row {
	r := f.rows[dest]
	if r == nil || r.Destination.Org != sc.Org {
		panic(fmt.Sprintf("destination %s not in scope %s", dest, sc.Org))
	}
	return r
}

func (f *fakeStore) setCursor(r *Row, c int64) {
	if c < r.State.Cursor {
		panic("cursor decreased")
	}
	r.State.Cursor = c
}

func (f *fakeStore) StartAtLatest(_ context.Context, sc Scope, dest uuid.UUID, latest int64, dropped uuid.UUID) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.row(sc, dest)
	if !r.State.StartAtLatest {
		return 0, false, nil
	}
	f.setCursor(r, max(r.State.Cursor, latest))
	r.State.StartAtLatest, r.State.Pending, r.State.NextAttemptAt = false, uuid.Nil, nil
	if d := f.deliveries[dropped]; d != nil && !d.delivered {
		d.lastError = "skipped"
	}
	return r.State.Cursor, true, nil
}

func (f *fakeStore) requestTest(dest uuid.UUID, by string) uuid.UUID {
	id := uuid.Must(uuid.NewV7())
	f.deliveries[id] = &fakeDelivery{dest: dest, kind: outbound.KindTest, requestedBy: by}
	f.order = append(f.order, id)
	return id
}

func (f *fakeStore) NextTest(_ context.Context, _ Scope, dest uuid.UUID) (TestDelivery, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range f.order {
		d := f.deliveries[id]
		if d.dest == dest && !d.delivered && d.lastError == "" {
			return TestDelivery{ID: id, RequestedBy: d.requestedBy}, true, nil
		}
	}
	return TestDelivery{}, false, nil
}

func (f *fakeStore) FinishTest(_ context.Context, _ Scope, r TestResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.deliveries[r.Delivery]
	d.attempts++
	d.delivered, d.lastError = r.Class == "", r.Class
	f.records = append(f.records, r.Record)
	return nil
}

func (f *fakeStore) Pending(_ context.Context, _ Scope, delivery uuid.UUID) (PendingBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deliveries[delivery]
	if !ok {
		return PendingBatch{}, errors.New("no rows")
	}
	return PendingBatch{ID: delivery, Attempts: d.attempts, Refs: d.refs}, nil
}

func (f *fakeStore) CreateBatch(_ context.Context, sc Scope, dest uuid.UUID, b NewBatch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.row(sc, dest)
	if b.Refs[0].ForwardSeq != r.State.ForwardSeq+1 {
		return fmt.Errorf("forward_seq gap: %d after %d", b.Refs[0].ForwardSeq, r.State.ForwardSeq)
	}
	f.deliveries[b.ID] = &fakeDelivery{dest: dest, kind: outbound.KindEvents, refs: b.Refs}
	r.State.ForwardSeq, r.State.Pending = b.Refs[len(b.Refs)-1].ForwardSeq, b.ID
	return nil
}

func (f *fakeStore) CreateHeartbeat(_ context.Context, _ Scope, dest, delivery uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveries[delivery] = &fakeDelivery{dest: dest, kind: outbound.KindHeartbeat}
	return nil
}

func (f *fakeStore) AdvanceCursor(_ context.Context, sc Scope, dest uuid.UUID, cursor int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCursor(f.row(sc, dest), cursor)
	return nil
}

func (f *fakeStore) Succeeded(_ context.Context, sc Scope, s Success) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.row(sc, s.Destination)
	d := f.deliveries[s.Delivery]
	d.attempts++
	d.delivered, d.lastError = true, ""
	at := s.At
	if s.Cursor != nil {
		f.setCursor(r, *s.Cursor)
		r.State.Pending, r.State.LastSuccessAt = uuid.Nil, &at
	} else {
		r.State.LastHeartbeatAt = &at
	}
	r.State.ConsecutiveFailures, r.State.FirstFailureAt, r.State.NextAttemptAt = 0, nil, nil
	if s.Record != nil {
		f.records = append(f.records, *s.Record)
	}
	return nil
}

func (f *fakeStore) Resumed(_ context.Context, sc Scope, res Resumption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.row(sc, res.Destination)
	r.State.Status, r.State.StalledSince = StatusActive, nil
	f.records = append(f.records, res.Record)
	return nil
}

func (f *fakeStore) Failed(_ context.Context, sc Scope, fl Failure) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.row(sc, fl.Destination)
	d := f.deliveries[fl.Delivery]
	d.attempts++
	d.lastError = fl.Class
	first, next := fl.FirstFailureAt, fl.NextAttemptAt
	r.State.ConsecutiveFailures, r.State.FirstFailureAt, r.State.NextAttemptAt = fl.ConsecutiveFailures, &first, &next
	r.State.Status, r.State.StalledSince = fl.Status, fl.StalledSince
	if fl.Record != nil {
		f.records = append(f.records, *fl.Record)
	}
	return nil
}

func (f *fakeStore) Lookups(context.Context, Scope) ([]Lookup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Lookup
	for _, l := range f.lookups {
		if _, done := f.resolved[l.ID]; !done {
			out = append(out, *l)
		}
	}
	return out, nil
}

func (f *fakeStore) Usernames(context.Context, Scope) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.names, nil
}

func (f *fakeStore) ResolveLookup(_ context.Context, _ Scope, id uuid.UUID, username string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved[id] = username
	return nil
}

func (f *fakeStore) PurgeLookups(context.Context, Scope, time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return nil
}

func (f *fakeStore) recordsOf(code audit.Code) []Record {
	var out []Record
	for _, r := range f.records {
		if r.Code == code {
			out = append(out, r)
		}
	}
	return out
}

// fakeIndex is the audit index of every scope.
type fakeIndex struct {
	events map[uuid.UUID][]IndexedEvent
	clock  func() time.Time
}

func (x *fakeIndex) append(org uuid.UUID, code audit.Code, n int) []IndexedEvent {
	var added []IndexedEvent
	for range n {
		seq := int64(len(x.events[org]) + 1)
		ev := IndexedEvent{CommitSeq: seq, Event: audit.Event{
			Schema: audit.Schema, EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, Code: code,
			Outcome: audit.OutcomeSuccess, RecordedAt: x.clock(), Actor: audit.Actor{Type: audit.ActorSystem},
			Params: map[string]any{},
		}}
		x.events[org] = append(x.events[org], ev)
		added = append(added, ev)
	}
	return added
}

func (x *fakeIndex) Latest(_ context.Context, sc Scope) (int64, error) {
	return int64(len(x.events[sc.Org])), nil
}

func (x *fakeIndex) After(_ context.Context, sc Scope, after int64, limit int) ([]IndexedEvent, error) {
	var out []IndexedEvent
	for _, ev := range x.events[sc.Org] {
		if ev.CommitSeq > after && len(out) < limit {
			out = append(out, ev)
		}
	}
	return out, nil
}

// fakeKeys "decrypts" a ciphertext of the fake store when the organization and field match.
type fakeKeys struct{}

func (fakeKeys) DecryptContext(_ context.Context, key string, org uuid.UUID, field bao.ContextField, ct string) ([]byte, error) {
	switch {
	case key == app.NotificationWrapKey && field == bao.FieldURL && len(ct) > 4 && ct[:4] == "url:":
		return []byte("https://sink.example/" + ct[4:]), nil
	case key == app.NotificationWrapKey && field == bao.FieldSecret && len(ct) > 7 && ct[:7] == "secret:":
		return []byte("whsec-" + ct[7:]), nil
	case key == app.NotificationPseudonymKey && field == bao.FieldPseudonym && ct == "pkey:"+org.String():
		return []byte("pseudonym-key-" + org.String()), nil
	}
	return nil, errors.New("decrypt refused")
}

// fakeTransport records the messages and answers with fail while it is set.
type fakeTransport struct {
	mu   sync.Mutex
	sent []sentMessage
	fail error
}

type sentMessage struct {
	dest Destination
	msg  outbound.Message
}

func (t *fakeTransport) Deliver(_ context.Context, d Destination, m outbound.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sent = append(t.sent, sentMessage{dest: d, msg: m})
	return t.fail
}

func (t *fakeTransport) kinds(kind string) []outbound.Message {
	var out []outbound.Message
	for _, s := range t.sent {
		if s.msg.Kind == kind {
			out = append(out, s.msg)
		}
	}
	return out
}

// fakeLeader always holds the lock unless busy.
type fakeLeader struct{ busy bool }

func (l fakeLeader) WithLeaderLock(ctx context.Context, _ int64, fn func(ctx context.Context) error) (bool, error) {
	if l.busy {
		return false, nil
	}
	return true, fn(ctx)
}

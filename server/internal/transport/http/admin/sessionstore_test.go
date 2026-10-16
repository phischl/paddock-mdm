package admin_test

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
)

// fakeSessions is the session store of the handler tests, kept as sessions.Store keeps it in Valkey.
type fakeSessions struct {
	mu      sync.Mutex
	records map[string]sessions.Record
	gen     int64
	down    bool // every call fails as with an unreachable Valkey
	calls   int
	touched []string
}

func newFakeSessions() *fakeSessions { return &fakeSessions{records: map[string]sessions.Record{}} }

func (f *fakeSessions) err() error {
	f.calls++
	if f.down {
		return sessions.ErrUnavailable
	}
	return nil
}

func (f *fakeSessions) Create(_ context.Context, sid string, rec sessions.Record, _ time.Duration) (sessions.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return sessions.Record{}, err
	}
	rec.Gen = f.gen
	f.records[sid] = rec
	return rec, nil
}

func (f *fakeSessions) Get(_ context.Context, sid string) (sessions.Record, int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return sessions.Record{}, 0, false, err
	}
	rec, ok := f.records[sid]
	return rec, f.gen, ok, nil
}

func (f *fakeSessions) Touch(_ context.Context, sid string, _ uuid.UUID, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, sid)
	return f.err()
}

func (f *fakeSessions) Delete(_ context.Context, sid string, _ uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return err
	}
	delete(f.records, sid)
	return nil
}

func (f *fakeSessions) RevokeAccount(_ context.Context, accountID uuid.UUID) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return 0, err
	}
	n := 0
	for sid, rec := range f.records {
		if rec.AccountID == accountID {
			delete(f.records, sid)
			n++
		}
	}
	return n, nil
}

func (f *fakeSessions) EndAll(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return 0, problem.SessionStoreUnavailable
	}
	f.gen++
	return f.gen, nil
}

// sessionsRecord is the record a login creates for p.
func sessionsRecord(p principal.Principal) sessions.Record {
	return sessions.Record{AccountID: p.ID, Kind: string(p.Kind), Role: string(p.Role), Org: p.OrganizationID}
}

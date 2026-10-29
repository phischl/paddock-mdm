package admin_test

import (
	"context"
	"errors"
	"fmt"
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
	// afterCreate runs after a record was created (a login that fails later).
	afterCreate func()
	// beforeCreate and beforeBind run before a record or a binding is written, outside the lock (End all sessions
	// racing a login).
	beforeCreate func()
	beforeBind   func()
	ttls         map[string]time.Duration
	// bindings are the MCP login bindings by subject and auth_time.
	bindings map[string]sessions.Binding
	// used are the login tokens presented to MCP session calls.
	used map[string]bool
	// failing names the methods that fail as with an unreachable Valkey; lostReply the methods that write and then
	// fail, as when Valkey's reply is lost.
	failing, lostReply map[string]bool
}

// methodErr fails a call of method when the test made it fail.
func (f *fakeSessions) methodErr(method string) error {
	if f.failing[method] {
		return sessions.ErrUnavailable
	}
	return nil
}

func (f *fakeSessions) UseLoginToken(_ context.Context, identity string, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := errors.Join(f.err(), f.methodErr("UseLoginToken")); err != nil {
		return false, err
	}
	if f.used[identity] {
		return false, nil
	}
	f.used[identity] = true
	return true, nil
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{records: map[string]sessions.Record{}, ttls: map[string]time.Duration{},
		bindings: map[string]sessions.Binding{}, used: map[string]bool{}, failing: map[string]bool{}, lostReply: map[string]bool{}}
}

func bindingID(sub string, authTime int64) string { return fmt.Sprintf("%s|%d", sub, authTime) }

func (f *fakeSessions) Bind(_ context.Context, sub string, authTime int64, b sessions.Binding, ttl time.Duration) (sessions.Binding, error) {
	if f.beforeBind != nil {
		f.beforeBind()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := errors.Join(f.err(), f.methodErr("Bind")); err != nil {
		return sessions.Binding{}, err
	}
	if ttl <= 0 {
		return sessions.Binding{}, errors.New("binding without lifetime")
	}
	b.Gen = f.gen
	f.bindings[bindingID(sub, authTime)] = b
	if f.lostReply["Bind"] {
		return sessions.Binding{}, sessions.ErrUnavailable
	}
	return b, nil
}

func (f *fakeSessions) Binding(_ context.Context, sub string, authTime int64) (sessions.Binding, int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := errors.Join(f.err(), f.methodErr("Binding")); err != nil {
		return sessions.Binding{}, 0, false, err
	}
	b, ok := f.bindings[bindingID(sub, authTime)]
	return b, f.gen, ok, nil
}

func (f *fakeSessions) Unbind(_ context.Context, sub string, authTime int64, _ uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return err
	}
	delete(f.bindings, bindingID(sub, authTime))
	return nil
}

func (f *fakeSessions) err() error {
	f.calls++
	if f.down {
		return sessions.ErrUnavailable
	}
	return nil
}

func (f *fakeSessions) Create(_ context.Context, sid string, rec sessions.Record, ttl time.Duration) (sessions.Record, error) {
	if f.beforeCreate != nil {
		f.beforeCreate()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := errors.Join(f.err(), f.methodErr("Create")); err != nil {
		return sessions.Record{}, err
	}
	rec.Gen = f.gen
	f.records[sid] = rec
	f.ttls[sid] = ttl
	if f.afterCreate != nil {
		f.afterCreate()
	}
	if f.lostReply["Create"] {
		return sessions.Record{}, sessions.ErrUnavailable
	}
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

func (f *fakeSessions) Delete(ctx context.Context, sid string, _ uuid.UUID) error {
	// Valkey refuses a call whose context ended.
	if err := ctx.Err(); err != nil {
		return err
	}
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
	for id, b := range f.bindings {
		if b.AccountID == accountID {
			delete(f.bindings, id)
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

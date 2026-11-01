// Package notifier is the delivery engine of the notifier role (plan M9 decisions 21–25, ADR 0031): it reads each
// scope's committed audit index in commit order, filters it per destination, numbers what it sends with a contiguous
// forward sequence and hands signed messages to the transports, recording delivery, stall and resumption as audit
// events.
package notifier

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// Scope is one organization or, with audit.PlatformOrganizationID, the platform.
type Scope struct{ Org uuid.UUID }

// Platform reports whether the scope is the platform's.
func (s Scope) Platform() bool { return s.Org == audit.PlatformOrganizationID }

// Status values of a destination's state.
const (
	StatusActive  = "active"
	StatusStalled = "stalled"
)

// Destination is what a transport needs to deliver: the configuration and, for a webhook, the decrypted URL and
// signing secret, which never leave the process.
type Destination struct {
	ID                uuid.UUID
	Org               uuid.UUID
	Type              outbound.Type
	Name              string
	Filter            outbound.FilterMode
	Codes             []audit.Code
	Pseudonymize      bool
	IncludeParams     bool
	HeartbeatInterval time.Duration
	Recipients        []string
	EmailMinInterval  time.Duration
	URL               string
	Secret            []byte
	// ScopeName is ScopeData.Name of the destination's scope.
	ScopeName string
}

// State is the delivery state of a destination.
type State struct {
	Cursor        int64
	StartAtLatest bool
	ForwardSeq    int64
	Status        string
	Pending       uuid.UUID // uuid.Nil without a pending batch
	// PendingFrom is the first forward sequence number of the pending batch, 0 without one.
	PendingFrom         int64
	ConsecutiveFailures int
	FirstFailureAt      *time.Time
	StalledSince        *time.Time
	LastSuccessAt       *time.Time
	NextAttemptAt       *time.Time
	LastHeartbeatAt     *time.Time
}

// Row is an enabled destination with its state and the ciphertexts of its URL and secret.
type Row struct {
	Destination      Destination
	State            State
	URLCiphertext    string
	SecretCiphertext string
}

// ScopeData is what one scope's round reads first.
type ScopeData struct {
	// Slug is Message.Organization: the organization's slug, outbound.PlatformOrganization for the platform.
	Slug string
	// Name is the organization's display name, outbound.PlatformOrganization for the platform (e-mail subjects).
	Name string
	Rows []Row
	// PseudonymKey is the ciphertext of the scope's pseudonym key, empty when it has none.
	PseudonymKey string
}

// IndexedEvent is an event of the audit index with its commit sequence.
type IndexedEvent struct {
	CommitSeq int64
	Event     audit.Event
}

// EventRef names a forwarded event of a batch.
type EventRef struct {
	ForwardSeq int64
	EventID    uuid.UUID
	CommitSeq  int64
}

// PendingBatch is a created, not yet delivered batch.
type PendingBatch struct {
	ID       uuid.UUID
	Attempts int
	Refs     []EventRef
}

// NewBatch is a batch about to be created: its delivery and events, and the destination's new forward sequence.
type NewBatch struct {
	ID   uuid.UUID
	Refs []EventRef
}

// TestDelivery is a test delivery an administrator requested.
type TestDelivery struct {
	ID          uuid.UUID
	RequestedBy string
}

// Record is an audit event the store records through the ActionRunner in the same transaction as the state change.
// A non-nil Failure records the outcome failure.
type Record struct {
	Code    audit.Code
	Params  map[string]any
	Failure error
}

// Success is a delivered events batch (Cursor set) or heartbeat (Cursor nil). It applies only while the destination's
// pending batch is still Pending (uuid.Nil for a heartbeat) and the delivery is not marked delivered yet; Resume ends a
// stall in the same transaction.
type Success struct {
	Destination uuid.UUID
	Name        string
	Delivery    uuid.UUID
	Pending     uuid.UUID
	Cursor      *int64
	At          time.Time
	Record      *Record
	Resume      *Record
	// NextAttemptAt is the earliest next delivery of an e-mail digest (plan M9 decision 28), nil otherwise.
	NextAttemptAt *time.Time
}

// Failure is a failed delivery with the destination's new failure state. Delivery is uuid.Nil for a failure before
// any delivery (class internal). It applies only while the destination still has the pending batch Pending and the
// status PreviousStatus.
type Failure struct {
	Destination         uuid.UUID
	Name                string
	Delivery            uuid.UUID
	Pending             uuid.UUID
	PreviousStatus      string
	Class               string
	At                  time.Time
	ConsecutiveFailures int
	FirstFailureAt      time.Time
	NextAttemptAt       time.Time
	Status              string
	StalledSince        *time.Time
	Record              *Record
}

// TestResult is the outcome of a test delivery; Class is empty on success.
type TestResult struct {
	Destination uuid.UUID
	Name        string
	Delivery    uuid.UUID
	Class       string
	At          time.Time
	Record      Record
}

// Lookup is a pending pseudonym lookup.
type Lookup struct {
	ID        uuid.UUID
	Pseudonym string
}

// Store is the notifier's view of the paddock database.
type Store interface {
	Organizations(ctx context.Context) ([]uuid.UUID, error)
	Load(ctx context.Context, sc Scope) (ScopeData, error)
	// StartAtLatest resolves a skip request: the cursor moves to latest (never back) and the pending batch dropped is
	// marked skipped. It reports the new cursor and false when the request was resolved meanwhile.
	StartAtLatest(ctx context.Context, sc Scope, dest uuid.UUID, latest int64, dropped uuid.UUID) (int64, bool, error)
	NextTest(ctx context.Context, sc Scope, dest uuid.UUID) (TestDelivery, bool, error)
	FinishTest(ctx context.Context, sc Scope, r TestResult) error
	Pending(ctx context.Context, sc Scope, delivery uuid.UUID) (PendingBatch, error)
	CreateBatch(ctx context.Context, sc Scope, dest uuid.UUID, b NewBatch) error
	CreateHeartbeat(ctx context.Context, sc Scope, dest, delivery uuid.UUID) error
	AdvanceCursor(ctx context.Context, sc Scope, dest uuid.UUID, cursor int64) error
	// Succeeded and Failed report false, changing and recording nothing, when the state moved on meanwhile.
	Succeeded(ctx context.Context, sc Scope, s Success) (bool, error)
	Failed(ctx context.Context, sc Scope, f Failure) (bool, error)
	Lookups(ctx context.Context, sc Scope) ([]Lookup, error)
	Usernames(ctx context.Context, sc Scope) ([]string, error)
	ResolveLookup(ctx context.Context, sc Scope, id uuid.UUID, username string, at time.Time) error
	PurgeLookups(ctx context.Context, sc Scope, before time.Time) error
}

// Index reads a scope's audit index.
type Index interface {
	Latest(ctx context.Context, sc Scope) (int64, error)
	// After returns up to max events with a commit sequence above after, in commit order.
	After(ctx context.Context, sc Scope, after int64, max int) ([]IndexedEvent, error)
}

// Transport delivers a message to a destination: webhook, e-mail, and syslog (M12) later. Its errors
// carry the class of plan M9 decision 22 (ErrorClass).
type Transport interface {
	Deliver(ctx context.Context, d Destination, m outbound.Message) error
}

// Leader runs fn only while holding the advisory lock key (db.PlatformPool).
type Leader interface {
	WithLeaderLock(ctx context.Context, key int64, fn func(ctx context.Context) error) (bool, error)
}

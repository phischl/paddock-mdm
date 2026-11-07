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
// signing secret, which never leave the process; for a syslog destination its receiver.
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
	// SyslogHost, SyslogPort, SyslogCAPEM and SyslogServerName name the TLS receiver of a syslog destination.
	SyslogHost       string
	SyslogPort       int
	SyslogCAPEM      string
	SyslogServerName string
	// Checkpoints sends the daily checkpoints of the scope's sealed days (plan M12 decision 20); CreatedAt bounds them.
	Checkpoints bool
	CreatedAt   time.Time
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
	// LastCheckpointDay is the last sealed day whose checkpoint was delivered, nil before the first.
	LastCheckpointDay *time.Time
	// ReplayFrom is the forward sequence number a requested replay continues at, 0 without a replay.
	ReplayFrom int64
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

// PendingBatch is a stored numbered delivery: a created, not yet delivered batch, or a delivered one a replay sends
// again. A checkpoint (Kind outbound.KindCheckpoint) has no Refs but its Day and EventCount.
type PendingBatch struct {
	ID         uuid.UUID
	Kind       string
	Attempts   int
	Refs       []EventRef
	From, To   int64
	Day        time.Time
	EventCount int
}

// Manifest is the sealed WORM manifest of a recording day of a scope (audit_manifest).
type Manifest struct {
	Day        time.Time
	SHA256     []byte
	Signature  string
	KeyVersion int
}

// NewCheckpoint is a checkpoint delivery about to be created with the destination's next forward sequence number.
type NewCheckpoint struct {
	ID         uuid.UUID
	ForwardSeq int64
	Day        time.Time
	EventCount int
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
	// CheckpointDay is set for a delivered checkpoint: it ends the pending delivery and becomes last_checkpoint_day.
	CheckpointDay *time.Time
}

// ReplayAdvance is a replayed delivery (Delivery and Record set) or the end of a replay with nothing left to send. It
// applies only while no batch is pending and replay_from is still From; Next is the replay's next forward sequence
// number, 0 when it is complete. Resume ends a stall in the same transaction.
type ReplayAdvance struct {
	Destination uuid.UUID
	Name        string
	Delivery    uuid.UUID
	From        int64
	Next        int64
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
	// CreateBatch and CreateCheckpoint insert a delivery and make it the destination's pending delivery; errStale while
	// a replay is requested.
	CreateBatch(ctx context.Context, sc Scope, dest uuid.UUID, b NewBatch) error
	CreateHeartbeat(ctx context.Context, sc Scope, dest, delivery uuid.UUID) error
	CreateCheckpoint(ctx context.Context, sc Scope, dest uuid.UUID, c NewCheckpoint) error
	// ReplayDeliveries returns up to max delivered event batches and checkpoints whose numbers reach from, in forward
	// order.
	ReplayDeliveries(ctx context.Context, sc Scope, dest uuid.UUID, from int64, max int) ([]PendingBatch, error)
	// Replayed records a replayed delivery and moves replay_from; false, changing and recording nothing, when the state
	// moved on meanwhile.
	Replayed(ctx context.Context, sc Scope, r ReplayAdvance) (bool, error)
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
	// EventAt returns the event with the commit sequence seq; false when the index has none (purged or 0).
	EventAt(ctx context.Context, sc Scope, seq int64) (IndexedEvent, bool, error)
	// CountRecordedOn counts the index events recorded on the UTC day.
	CountRecordedOn(ctx context.Context, sc Scope, day time.Time) (int, error)
	// ManifestsAfter returns up to max sealed days after the UTC day after, in day order.
	ManifestsAfter(ctx context.Context, sc Scope, after time.Time, max int) ([]Manifest, error)
}

// Transport delivers a message to a destination: webhook, e-mail or syslog (plan M12 decision 18). Its errors
// carry the class of plan M9 decision 22 (ErrorClass).
type Transport interface {
	Deliver(ctx context.Context, d Destination, m outbound.Message) error
}

// Leader runs fn only while holding the advisory lock key (db.PlatformPool).
type Leader interface {
	WithLeaderLock(ctx context.Context, key int64, fn func(ctx context.Context) error) (bool, error)
}

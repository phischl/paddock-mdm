package auditwriter

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/pkg/auditevidence"
	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// ExportSchema is the schema of export.json.
const ExportSchema = auditevidence.ExportSchema

// ExportChunkSize is the size of one audit_export_chunk row; the last row of a package may be shorter.
const ExportChunkSize = 8 << 20

// ExportTTL is how long a ready package stays downloadable.
const ExportTTL = 7 * 24 * time.Hour

// ExportStuckAfter is how long an export may stay running before it is taken as abandoned by a restarted exporter.
const ExportStuckAfter = 2 * time.Hour

const (
	exportChunkTimeout   = 2 * time.Minute
	exportErrorLimit     = 500
	exportRecordTimeout  = 30 * time.Second
	exportRecordAttempts = 3
	exportStatusTimeout  = 30 * time.Second
	exportStuckError     = "exporter restarted"
	errorExportFailed    = "export_failed"
	storeAuditExports    = "audit_exports"
	targetAuditExport    = "audit_export"
)

// exportWriteTimeout bounds markReady and failRunning on the client side as well: transaction_timeout ends the
// transaction on the server, but a hung connection or a lost COMMIT acknowledgement would still block the caller.
// The margin lets the server's own timeout error arrive first.
const exportWriteTimeout = db.WriterTransactionTimeout + 30*time.Second

// exportMaxDecodedObject: an object holds at most MaxBatch events, so 256 MiB leaves over 500 KiB per event; anything
// larger is treated as a decompression bomb and reported as undecodable instead of exhausting the writer's memory.
const exportMaxDecodedObject = 256 << 20

var (
	metricExport = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "paddock_audit_export_total", Help: "Evidence exports finished per result (ready, failed, expired).",
	}, []string{"result"})
	metricExportPendingAge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_audit_export_pending_age_seconds",
		Help: "Age of the oldest pending evidence export in seconds; 0 when none is pending.",
	})
	metricExportBuild = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "paddock_audit_export_build_seconds", Help: "Duration of building one evidence package.",
		Buckets: prometheus.ExponentialBuckets(0.1, 2, 16),
	})
)

// Exporter builds the evidence packages of plan M10 §6.5 in the audit domain, so the audit-chain key never leaves
// it (ADR 0032 §5).
type Exporter struct {
	pool      *db.AuditWriterPool
	writer    *Writer
	store     ObjectStore
	signer    Signer
	keys      PublicKeys
	verifier  *Verifier
	version   string
	poll      time.Duration
	now       func() time.Time
	chunkSize int
	// maxDecoded bounds the decompressed size of one object.
	maxDecoded uint64
	// buildTimeout bounds one build; it is ExportStuckAfter. It is measured from the start of Build, the stuck check
	// from started_at, so the stuck check usually fails a hung export first; the bound then mainly frees the goroutine.
	buildTimeout time.Duration
	// writeTimeout bounds every write of the exporter outside the build and the list queries of Expire; it is
	// exportWriteTimeout.
	writeTimeout time.Duration
	// readyCommitted is nil; tests turn a committed ready update into an unknown outcome.
	readyCommitted func(ctx context.Context, id uuid.UUID, err error) error
	// statusRead is nil; tests replace the outcome of a status read after a failed ready update.
	statusRead func(ctx context.Context, id uuid.UUID, status string, err error) (string, error)
	// failCommitted and expiredCommitted are nil; tests turn a committed failure or expiry into an unknown outcome.
	failCommitted    func(ctx context.Context, id uuid.UUID, err error) error
	expiredCommitted func(ctx context.Context, id uuid.UUID, err error) error
	// endRead is nil; tests replace the error of each locked read after a failure or expiry with an unknown outcome.
	endRead func(ctx context.Context, id uuid.UUID, err error) error
}

// NewExporter creates an exporter; version names the generator in the package.
func NewExporter(pool *db.AuditWriterPool, writer *Writer, store ObjectStore, signer Signer, keys PublicKeys,
	verifier *Verifier, version string, poll time.Duration) *Exporter {
	// increase() of PaddockAuditExportFailed needs a sample before the first failure.
	for _, result := range []string{"ready", "failed", "expired"} {
		metricExport.WithLabelValues(result)
	}
	return &Exporter{pool: pool, writer: writer, store: store, signer: signer, keys: keys, verifier: verifier,
		version: version, poll: poll, now: time.Now, chunkSize: ExportChunkSize,
		maxDecoded: exportMaxDecodedObject, buildTimeout: ExportStuckAfter, writeTimeout: exportWriteTimeout}
}

// Run builds pending exports and, in its own loop, expires old ones every poll interval until ctx ends.
func (e *Exporter) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	// A separate loop, because a long or hung build must not freeze the gauge PaddockAuditExportStuck watches.
	wg.Go(func() { e.observeLoop(ctx) })
	// Expiry and the stuck check run apart from the builds as well, so a hung build cannot keep a ready package past its
	// expiry or another replica's abandoned export running.
	wg.Go(func() { e.expireLoop(ctx) })
	for {
		e.round(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(e.poll):
		}
	}
}

func (e *Exporter) round(ctx context.Context) {
	for ctx.Err() == nil {
		export, ok, err := e.Claim(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "evidence export: claim failed", "error", err)
			break
		}
		if !ok {
			break
		}
		if err := e.Build(ctx, export); err != nil {
			slog.ErrorContext(ctx, "evidence export failed", "export_id", export.ID, "organization_id",
				export.OrganizationID, "error", err)
		}
	}
}

func (e *Exporter) expireLoop(ctx context.Context) {
	for {
		if _, err := e.Expire(ctx, e.now()); err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "evidence export expiry failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.poll):
		}
	}
}

func (e *Exporter) observeLoop(ctx context.Context) {
	for {
		if err := e.observePending(ctx); err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "evidence export: pending age not read", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.poll):
		}
	}
}

// Claim moves the oldest pending export to running; ok is false when none is pending. Concurrent exporters claim
// different exports (FOR UPDATE SKIP LOCKED).
func (e *Exporter) Claim(ctx context.Context) (export auditstore.AuditExport, ok bool, err error) {
	err = e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		export, err = q.ClaimPendingAuditExport(ctx)
		return err
	})
	if db.IsNoRows(err) {
		return auditstore.AuditExport{}, false, nil
	}
	return export, err == nil, err
}

func (e *Exporter) observePending(ctx context.Context) error {
	return e.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		age, err := q.OldestPendingAuditExportAge(ctx)
		if err == nil {
			metricExportPendingAge.Set(age)
		}
		return err
	})
}

// built is what a successful build records.
type built struct {
	days, objects int
	events        int
	size          int64
	sum           [32]byte
	verifyOK      bool
	problems      []string
	signature     string
	keyVersion    int
}

// Build produces the package of a running export (plan M10 decision 32), stores it in chunks and marks the export
// ready, or failed with its chunks deleted. Problems of the chain do not fail the build: they go into the package
// so that the auditor sees them. A build is aborted after ExportStuckAfter. When ctx ends during the build, the export
// stays running and the stuck check of a later round fails it.
func (e *Exporter) Build(ctx context.Context, export auditstore.AuditExport) error {
	start := time.Now()
	buildCtx, cancel := context.WithTimeout(ctx, e.buildTimeout)
	res, err := e.build(buildCtx, export)
	if err != nil && ctx.Err() == nil && errors.Is(buildCtx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("the build took longer than %s: %w", e.buildTimeout, err)
	}
	cancel()
	marked := err == nil
	// unread: the ready update was attempted, failed and its outcome could not be read, so it may have committed.
	unread := false
	if marked {
		err = e.markReady(ctx, export, res)
		if errors.Is(err, errNotRunning) {
			return err
		}
		if err != nil {
			ready, read := e.becameReady(ctx, export.ID)
			if ready {
				slog.WarnContext(ctx, "evidence export: ready despite an error", "export_id", export.ID, "error", err)
				err = nil
			}
			unread = !read
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return e.readyAfterAll(ctx, export, res, start, unread, err)
		}
		failed, failErr := e.failRunning(ctx, export.ID, exportErrorText(err))
		if failErr != nil {
			return e.readyAfterAll(ctx, export, res, start, unread, errors.Join(err, failErr))
		}
		if !failed {
			// failRunning waited for any transaction still holding the row, so this read sees a ready update that
			// committed after the first read or whose first read failed; a ready export gets its success event here,
			// because the stuck check only looks at running ones.
			if marked {
				if ready, _ := e.becameReady(ctx, export.ID); ready {
					slog.WarnContext(ctx, "evidence export: ready despite an error", "export_id", export.ID, "error", err)
					e.ready(ctx, export, res, start)
					return nil
				}
			}
			// The stuck check failed the export and recorded its outcome. Only an ended export loses its chunks: a
			// ready update whose outcome becameReady could not read may have committed.
			if _, delErr := e.deleteEndedChunks(context.WithoutCancel(ctx), uuid.NullUUID{UUID: export.ID, Valid: true}); delErr != nil {
				return errors.Join(err, errNotRunning, delErr)
			}
			return errors.Join(err, errNotRunning)
		}
		metricExport.WithLabelValues("failed").Inc()
		e.recordSelf(ctx, completedEvent(export, nil, exportErrorText(err)))
		return err
	}
	e.ready(ctx, export, res, start)
	return nil
}

// readyAfterAll reads the status once more before Build gives up without failing the export: when the first read
// after a failed ready update failed (unread), the update may have committed, and only the build can record the
// success of a ready export. Otherwise it returns err.
func (e *Exporter) readyAfterAll(ctx context.Context, export auditstore.AuditExport, res built, start time.Time,
	unread bool, err error) error {
	if !unread {
		return err
	}
	if ready, _ := e.becameReady(ctx, export.ID); !ready {
		return err
	}
	slog.WarnContext(ctx, "evidence export: ready despite an error", "export_id", export.ID, "error", err)
	e.ready(ctx, export, res, start)
	return nil
}

// ready records the success of a build whose export is ready.
func (e *Exporter) ready(ctx context.Context, export auditstore.AuditExport, res built, start time.Time) {
	metricExport.WithLabelValues("ready").Inc()
	metricExportBuild.Observe(time.Since(start).Seconds())
	slog.InfoContext(ctx, "evidence export ready", "export_id", export.ID, "organization_id", export.OrganizationID,
		"objects", res.objects, "events", res.events, "size", res.size, "verify_ok", res.verifyOK)
	e.recordSelf(ctx, completedEvent(export, &res, ""))
}

// errNotRunning means the export left running while it was built (the stuck check failed it); that check recorded
// its outcome.
var errNotRunning = errors.New("auditwriter: the export is no longer running")

func (e *Exporter) markReady(ctx context.Context, export auditstore.AuditExport, res built) error {
	problems, err := json.Marshal(res.problems)
	if err != nil {
		return err
	}
	readyAt := e.now().UTC()
	expiresAt := readyAt.Add(ExportTTL)
	events, objects, size, ok := int64(res.events), int32(res.objects), res.size, res.verifyOK //nolint:gosec // bounded by 400 days of objects
	version := int32(res.keyVersion)                                                           //nolint:gosec // checked against the published keys
	var updated int64
	wctx, cancel := context.WithTimeout(ctx, e.writeTimeout)
	defer cancel()
	err = e.pool.InWriter(wctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		updated, err = q.UpdateAuditExportReady(ctx, auditstore.UpdateAuditExportReadyParams{
			ID: export.ID, ReadyAt: &readyAt, ExpiresAt: &expiresAt, EventCount: &events, ObjectCount: &objects,
			Size: &size, PackageSha256: res.sum[:], VerifyOk: &ok, VerifyProblems: problems,
			Signature: &res.signature, KeyVersion: &version,
		})
		return err
	})
	if e.readyCommitted != nil {
		err = e.readyCommitted(ctx, export.ID, err)
	}
	if err != nil {
		return err
	}
	if updated == 0 {
		if _, delErr := e.deleteChunks(context.WithoutCancel(ctx), export.ID); delErr != nil {
			return errors.Join(errNotRunning, delErr)
		}
		return errNotRunning
	}
	return nil
}

// failRunning sets a running export failed and deletes its chunks in one transaction; it reports whether the export
// was still running, that is whether this call failed it and must record the failure event.
func (e *Exporter) failRunning(ctx context.Context, id uuid.UUID, message string) (bool, error) {
	// xmin is set only when the closure succeeded after its update matched the row: an error before that is a certain
	// rollback, an error after it leaves only the COMMIT outcome unknown.
	var xmin string
	wctx, cancel := context.WithTimeout(ctx, e.writeTimeout)
	err := e.pool.InWriter(wctx, func(ctx context.Context, q *auditstore.Queries) error {
		xmins, err := q.UpdateAuditExportFailed(ctx, auditstore.UpdateAuditExportFailedParams{ID: id, Error: &message})
		if err != nil || len(xmins) == 0 {
			return err
		}
		if _, err = q.DeleteAuditExportChunks(ctx, id); err != nil {
			return err
		}
		xmin = xmins[0]
		return nil
	})
	cancel()
	if e.failCommitted != nil {
		err = e.failCommitted(ctx, id, err)
	}
	// The COMMIT may have landed although the client never learned it; the stuck check lists only running exports, so
	// nobody else would record the failure. A concurrent stuck check or build may have written the same status and
	// text after this transaction rolled back, so only the transaction id tells whose write is visible.
	if err != nil && xmin != "" && e.wrote(ctx, id, xmin) {
		slog.WarnContext(ctx, "evidence export: failed despite an error", "export_id", id, "error", err)
		return true, nil
	}
	return xmin != "", err
}

// becameReady reports whether the export is ready after markReady failed: the COMMIT may have succeeded although the
// client never learned it, and a ready package must keep its chunks and get its completed event. read reports
// whether the status could be read at all.
func (e *Exporter) becameReady(ctx context.Context, id uuid.UUID) (ready, read bool) {
	export, err := e.lockedExport(ctx, id)
	status := export.AuditExport.Status
	if e.statusRead != nil {
		status, err = e.statusRead(ctx, id, status, err)
	}
	if err != nil {
		slog.ErrorContext(ctx, "evidence export: status not read", "export_id", id, "error", err)
	}
	return err == nil && status == "ready", err == nil
}

// wrote reports whether the visible version of the export was written by the transaction xmin, that is whether a
// write whose COMMIT outcome the client never learned did commit. A failed read is retried once: neither list query
// sees a failed or expired export again, so nobody else would record its event.
func (e *Exporter) wrote(ctx context.Context, id uuid.UUID, xmin string) bool {
	for range 2 {
		export, err := e.lockedExport(ctx, id)
		if e.endRead != nil {
			err = e.endRead(ctx, id, err)
		}
		if err == nil {
			return export.Xmin == xmin
		}
		slog.ErrorContext(ctx, "evidence export: status not read", "export_id", id, "error", err)
	}
	return false
}

// lockedExport reads the export under the row lock, so a COMMIT still in flight is waited out instead of read as the
// old state. It outlives ctx for a bounded time, because a shutdown must not cost the outcome of a committed write.
func (e *Exporter) lockedExport(ctx context.Context, id uuid.UUID) (auditstore.GetAuditExportLockedRow, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), exportStatusTimeout)
	defer cancel()
	var export auditstore.GetAuditExportLockedRow
	err := e.pool.InWriterWithTimeout(ctx, exportStatusTimeout, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		export, err = q.GetAuditExportLocked(ctx, id)
		return err
	})
	return export, err
}

// deleteEndedChunks deletes the chunks of failed and expired exports; with a null id, of all of them.
func (e *Exporter) deleteEndedChunks(ctx context.Context, id uuid.NullUUID) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, e.writeTimeout)
	defer cancel()
	var n int64
	err := e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		n, err = q.DeleteEndedAuditExportChunks(ctx, id)
		return err
	})
	return n, err
}

func (e *Exporter) deleteChunks(ctx context.Context, id uuid.UUID) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, e.writeTimeout)
	defer cancel()
	var n int64
	err := e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		n, err = q.DeleteAuditExportChunks(ctx, id)
		return err
	})
	return n, err
}

// Expire deletes chunks left behind by failed or expired exports, deletes the chunks of ready exports past their expiry
// (status expired, retention.purged in the export's organization) and fails exports that stayed running longer than
// ExportStuckAfter (plan M10 decision 34).
func (e *Exporter) Expire(ctx context.Context, now time.Time) (expired int, err error) {
	// The sweep comes first, so an error of a later pass cannot skip it.
	n, err := e.deleteEndedChunks(ctx, uuid.NullUUID{})
	if err != nil {
		return 0, fmt.Errorf("delete chunks of ended exports: %w", err)
	}
	if n > 0 {
		slog.WarnContext(ctx, "evidence export: deleted leftover chunks", "chunks", n)
	}
	var due, stuck []auditstore.AuditExport
	stuckBefore := now.Add(-ExportStuckAfter)
	lctx, cancel := context.WithTimeout(ctx, e.writeTimeout)
	defer cancel()
	err = e.pool.WithSession(lctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		if due, err = q.ListExpiredAuditExports(ctx, &now); err != nil {
			return err
		}
		stuck, err = q.ListStuckAuditExports(ctx, &stuckBefore)
		return err
	})
	if err != nil {
		return 0, err
	}
	var errs []error
	for _, export := range due {
		// As in failRunning: set only when the closure succeeded after its update matched the row.
		var xmin string
		wctx, cancel := context.WithTimeout(ctx, e.writeTimeout)
		err := e.pool.InWriter(wctx, func(ctx context.Context, q *auditstore.Queries) error {
			xmins, err := q.UpdateAuditExportExpired(ctx, auditstore.UpdateAuditExportExpiredParams{ID: export.ID, Now: &now})
			if err != nil || len(xmins) == 0 {
				return err
			}
			if _, err = q.DeleteAuditExportChunks(ctx, export.ID); err != nil {
				return err
			}
			xmin = xmins[0]
			return nil
		})
		cancel()
		if e.expiredCommitted != nil {
			err = e.expiredCommitted(ctx, export.ID, err)
		}
		// As in failRunning: a lost acknowledgement must not cost the event, and a concurrent expiry by another
		// replica after this transaction rolled back must not add a second one.
		if err != nil && xmin != "" && e.wrote(ctx, export.ID, xmin) {
			slog.WarnContext(ctx, "evidence export: expired despite an error", "export_id", export.ID, "error", err)
			err = nil
		}
		if err != nil {
			// The next export and the stuck check must not wait for this one.
			errs = append(errs, fmt.Errorf("expire export %s: %w", export.ID, err))
			continue
		}
		if xmin == "" {
			continue
		}
		expired++
		metricExport.WithLabelValues("expired").Inc()
		e.recordSelf(ctx, audit.Event{
			OrganizationID: export.OrganizationID, Code: audit.CodeRetentionPurged, Outcome: audit.OutcomeSuccess,
			Target: &audit.Target{Type: targetAuditExport, ID: export.ID.String()},
			Params: map[string]any{
				"store": storeAuditExports, "deleted": 1, "export_id": export.ID.String(),
				"cutoff": now.UTC().Format(time.RFC3339Nano),
			},
		})
	}
	for _, export := range stuck {
		failed, err := e.failRunning(ctx, export.ID, exportStuckError)
		if err != nil {
			// The list is ordered by started_at, so an export that keeps failing must not starve the later ones.
			errs = append(errs, fmt.Errorf("fail stuck export %s: %w", export.ID, err))
			continue
		}
		if !failed {
			continue
		}
		metricExport.WithLabelValues("failed").Inc()
		slog.WarnContext(ctx, "evidence export abandoned", "export_id", export.ID, "started_at", export.StartedAt)
		e.recordSelf(ctx, completedEvent(export, nil, exportStuckError))
	}
	return expired, errors.Join(errs...)
}

func completedEvent(export auditstore.AuditExport, res *built, message string) audit.Event {
	days := int(dayOf(export.ToDay).Sub(dayOf(export.FromDay))/(24*time.Hour)) + 1
	ev := audit.Event{
		OrganizationID: export.OrganizationID, Code: audit.CodeAuditExportCompleted, Outcome: audit.OutcomeSuccess,
		Target:        &audit.Target{Type: targetAuditExport, ID: export.ID.String()},
		CorrelationID: export.CorrelationID,
		Params: map[string]any{
			"export_id": export.ID.String(), "from_day": export.FromDay.Format(time.DateOnly),
			"to_day": export.ToDay.Format(time.DateOnly), "days": days, "objects": 0, "events": 0,
		},
	}
	if res == nil {
		ev.Outcome, ev.ErrorCode, ev.Params["error"] = audit.OutcomeFailure, errorExportFailed, message
		return ev
	}
	ev.Params["objects"], ev.Params["events"], ev.Params["size"] = res.objects, res.events, res.size
	ev.Params["package_sha256"] = hex.EncodeToString(res.sum[:])
	ev.Params["verify_ok"], ev.Params["key_version"] = res.verifyOK, res.keyVersion
	return ev
}

// recordSelf records an event of the exporter after the state it describes was committed; a shutdown must not cost
// that evidence, so it outlives ctx for a bounded time.
func (e *Exporter) recordSelf(ctx context.Context, ev audit.Event) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), exportRecordTimeout)
	defer cancel()
	id, err := uuid.NewV7()
	if err != nil {
		slog.ErrorContext(ctx, "evidence export: event id", "error", err)
		return
	}
	ev.EventID = id
	for attempt := 1; ; attempt++ {
		if err = RecordSelf(ctx, e.writer, ev); err == nil || attempt == exportRecordAttempts {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(attempt) * time.Second):
		}
	}
	if err != nil {
		slog.ErrorContext(ctx, "evidence export: event not recorded", "code", ev.Code, "event_id", id,
			"organization_id", ev.OrganizationID, "params", ev.Params, "error", err)
	}
}

// exportErrorText is the error stored with a failed export: at most exportErrorLimit characters.
func exportErrorText(err error) string {
	s := err.Error()
	if utf8.RuneCountInString(s) <= exportErrorLimit {
		return s
	}
	return string([]rune(s)[:exportErrorLimit])
}

// packDay is one day of the package as read in the first pass.
type packDay struct {
	day      string
	key      string
	raw      []byte
	digest   [32]byte
	manifest auditevidence.Manifest
	objects  []auditevidence.Object
	events   int
}

// collected is everything the first pass learned; the second pass writes the tar from it.
type collected struct {
	days     []packDay
	problems []string
	events   int
	eventsSz int64
	eventsH  [32]byte
}

func (c *collected) addProblem(p string) {
	for _, have := range c.problems {
		if have == p {
			return
		}
	}
	c.problems = append(c.problems, p)
}

// build reads the range twice: the first pass collects manifests, object hashes and the decoded events (temp file),
// so export.json (which carries the README hash) and its signature exist before the README is written first in the tar.
// Objects are re-read in the second pass and must hash as in the first.
func (e *Exporter) build(ctx context.Context, export auditstore.AuditExport) (built, error) {
	org := export.OrganizationID
	from, to := dayOf(export.FromDay), dayOf(export.ToDay)
	var manifests []auditstore.AuditManifest
	var runs []auditstore.AuditVerificationRun
	err := e.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		if manifests, err = q.ListAuditManifests(ctx, auditstore.ListAuditManifestsParams{OrganizationID: org, FromDay: from, ToDay: to}); err != nil {
			return err
		}
		runs, err = q.ListAuditVerificationRunsOverlapping(ctx, auditstore.ListAuditVerificationRunsOverlappingParams{
			OrganizationID: org, FromDay: from, ToDay: to,
		})
		return err
	})
	if err != nil {
		return built{}, err
	}
	byDay := map[string]auditstore.AuditManifest{}
	for _, m := range manifests {
		byDay[dayOf(m.Day).Format(time.DateOnly)] = m
	}
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		if _, ok := byDay[d.Format(time.DateOnly)]; !ok {
			return built{}, fmt.Errorf("day %s: no manifest", d.Format(time.DateOnly))
		}
	}
	report, err := e.verifier.Verify(ctx, org, from, to)
	if err != nil {
		return built{}, fmt.Errorf("verify: %w", err)
	}
	verifiedAt := e.now().UTC()
	keys, err := e.keys(ctx)
	if err != nil {
		return built{}, fmt.Errorf("public keys: %w", err)
	}

	tmp, err := os.CreateTemp("", "paddock-export-*.jsonl")
	if err != nil {
		return built{}, err
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	c := &collected{problems: append([]string{}, report.Problems...)}
	if err := e.collect(ctx, org, from, to, byDay, tmp, c); err != nil {
		return built{}, err
	}

	doc := e.exportDoc(export, c, runs, verifiedAt, keys)
	// The README names the signing key, which only the signer knows; export.json covers the README hash, so the README
	// is rendered before signing for the newest published key and once more if the signer used another one.
	keyVersion := 0
	for v := range keys {
		keyVersion = max(keyVersion, v)
	}
	var readme, canonical, sigFile []byte
	var sig bao.Signature
	for attempt := 0; ; attempt++ {
		readme = renderReadme(doc, keyVersion, auditevidence.Fingerprint(keys[keyVersion]))
		readmeSum := sha256.Sum256(readme)
		doc.ReadmeSHA256 = hex.EncodeToString(readmeSum[:])
		canonical, err = canonicaljson.Marshal(doc)
		if err != nil {
			return built{}, err
		}
		digest := auditevidence.ExportDigest(canonical)
		if sig, err = e.signer.Sign(ctx, SigningKey, digest[:]); err != nil {
			return built{}, fmt.Errorf("sign: %w", err)
		}
		if !auditevidence.VerifySignature(keys, sig.KeyVersion, sig.Value, digest[:]) {
			return built{}, fmt.Errorf("the signature does not verify with the published audit-chain v%d", sig.KeyVersion)
		}
		if sig.KeyVersion == keyVersion {
			break
		}
		if attempt > 0 {
			return built{}, fmt.Errorf("the signer switched from audit-chain v%d to v%d twice", keyVersion, sig.KeyVersion)
		}
		keyVersion = sig.KeyVersion
	}
	sigFile, err = json.Marshal(auditevidence.Signature{Signature: sig.Value, KeyVersion: sig.KeyVersion})
	if err != nil {
		return built{}, err
	}
	err = e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		return ensureSigningKey(ctx, q, sig.KeyVersion, keys[sig.KeyVersion])
	})
	if err != nil {
		return built{}, err
	}

	cw := newChunkWriter(e.chunkSize, func(seq int32, data []byte) error {
		return e.pool.InWriterWithTimeout(ctx, exportChunkTimeout, func(ctx context.Context, q *auditstore.Queries) error {
			n, err := q.InsertAuditExportChunk(ctx, auditstore.InsertAuditExportChunkParams{
				ExportID: export.ID, OrganizationID: org, Seq: seq, Data: data,
			})
			if err == nil && n == 0 {
				return fmt.Errorf("chunk %d: %w", seq, errNotRunning)
			}
			return err
		})
	})
	if err := e.writeTar(ctx, cw, doc.CreatedAt, readme, c, tmp, canonical, sigFile); err != nil {
		if _, delErr := e.deleteChunks(context.WithoutCancel(ctx), export.ID); delErr != nil {
			return built{}, errors.Join(err, delErr)
		}
		return built{}, err
	}
	return built{
		days: len(c.days), objects: len(doc.Objects), events: c.events, size: cw.total, sum: cw.sum(),
		verifyOK: doc.Verification.OK, problems: doc.Verification.Problems, signature: sig.Value,
		keyVersion: sig.KeyVersion,
	}, nil
}

// collect reads every manifest and object of the range in order, appends the decoded events to events and records
// the hashes. A modified object is a problem, not an error; an unreadable one fails the build, because the package
// cannot hold it.
func (e *Exporter) collect(ctx context.Context, org uuid.UUID, from, to time.Time, byDay map[string]auditstore.AuditManifest,
	events *os.File, c *collected) error {
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(e.maxDecoded))
	if err != nil {
		return err
	}
	defer dec.Close()
	h := sha256.New()
	out := io.MultiWriter(events, h)
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		name := d.Format(time.DateOnly)
		m := byDay[name]
		raw, err := e.store.Get(ctx, m.ObjectKey)
		if err != nil {
			return fmt.Errorf("day %s: manifest %s unreadable: %w", name, m.ObjectKey, err)
		}
		pd := packDay{day: name, key: m.ObjectKey, raw: raw}
		var file auditevidence.ManifestFile
		if err := json.Unmarshal(raw, &file); err != nil {
			return fmt.Errorf("day %s: manifest is not valid JSON: %w", name, err)
		}
		canonical, digest, err := auditevidence.ManifestDigest(file)
		if err != nil {
			return fmt.Errorf("day %s: manifest cannot be canonicalized: %w", name, err)
		}
		pd.digest = digest
		if err := json.Unmarshal(canonical, &pd.manifest); err != nil {
			return fmt.Errorf("day %s: manifest does not parse: %w", name, err)
		}
		listed := append([]auditevidence.ManifestObject(nil), pd.manifest.Objects...)
		sort.Slice(listed, func(i, j int) bool { return listed[i].Key < listed[j].Key })
		for _, o := range listed {
			path, err := auditevidence.ObjectPath(org.String(), o.Key)
			if err != nil {
				return fmt.Errorf("day %s: %w", name, err)
			}
			body, err := e.store.Get(ctx, o.Key)
			if err != nil {
				return fmt.Errorf("day %s: object %s unreadable: %w", name, o.Key, err)
			}
			sum := sha256.Sum256(body)
			n := 0
			if hex.EncodeToString(sum[:]) != o.SHA256 {
				// Bytes the chain does not vouch for are packed for the auditor but never decompressed.
				c.addProblem(fmt.Sprintf("%s: object %s was modified (SHA-256 mismatch)", name, o.Key))
			} else if plain, err := dec.DecodeAll(body, nil); err != nil {
				c.addProblem(fmt.Sprintf("%s: object %s cannot be decoded", name, o.Key))
			} else {
				if _, err := out.Write(plain); err != nil {
					return err
				}
				n = bytes.Count(plain, []byte("\n"))
			}
			pd.objects = append(pd.objects, auditevidence.Object{Key: o.Key, Path: path, SHA256: hex.EncodeToString(sum[:]), EventCount: n})
			pd.events += n
		}
		c.events += pd.events
		c.days = append(c.days, pd)
	}
	info, err := events.Stat()
	if err != nil {
		return err
	}
	c.eventsSz = info.Size()
	copy(c.eventsH[:], h.Sum(nil))
	return nil
}

func (e *Exporter) exportDoc(export auditstore.AuditExport, c *collected, runs []auditstore.AuditVerificationRun,
	verifiedAt time.Time, keys map[int][]byte) auditevidence.Export {
	generator := "paddock-server " + e.version
	var requester auditevidence.Actor
	_ = json.Unmarshal(export.RequestedBy, &requester) // written by the request API as an audit.Actor; never invalid JSON
	doc := auditevidence.Export{
		Schema: ExportSchema, ExportID: export.ID.String(), OrganizationID: export.OrganizationID.String(),
		FromDay: export.FromDay.Format(time.DateOnly), ToDay: export.ToDay.Format(time.DateOnly),
		RequestedBy: requester, RequestedAt: export.RequestedAt.UTC(), CreatedAt: e.now().UTC().Truncate(time.Second),
		Purpose: export.Purpose, Generator: generator, Days: []auditevidence.Day{}, Objects: []auditevidence.Object{},
		EventCount: c.events, EventsSHA256: hex.EncodeToString(c.eventsH[:]),
		Verification: auditevidence.Verification{
			OK: len(c.problems) == 0, Problems: c.problems, VerifiedAt: verifiedAt, Verifier: generator,
			Runs: []auditevidence.Run{},
		},
		Keys: []auditevidence.Key{},
	}
	for i, d := range c.days {
		if i == 0 {
			doc.ChainAnchor = d.manifest.PrevManifestSHA256
		}
		doc.Days = append(doc.Days, auditevidence.Day{
			Day: d.day, ManifestKey: d.key, ManifestSHA256: hex.EncodeToString(d.digest[:]),
			ObjectCount: len(d.objects), EventCount: d.events,
		})
		doc.Objects = append(doc.Objects, d.objects...)
	}
	for _, r := range runs {
		problems := []string{}
		if len(r.Problems) > 0 {
			_ = json.Unmarshal(r.Problems, &problems) // stored by Recorder as a JSON array of strings
		}
		if problems == nil {
			problems = []string{}
		}
		doc.Verification.Runs = append(doc.Verification.Runs, auditevidence.Run{
			RunID: r.ID.String(), StartedAt: r.StartedAt.UTC(), FromDay: r.FromDay.Format(time.DateOnly),
			ToDay: r.ToDay.Format(time.DateOnly), OK: r.Ok, Problems: problems,
		})
	}
	versions := make([]int, 0, len(keys))
	for v := range keys {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	for _, v := range versions {
		doc.Keys = append(doc.Keys, auditevidence.Key{KeyVersion: v, PublicKey: keys[v], Fingerprint: auditevidence.Fingerprint(keys[v])})
	}
	return doc
}

// writeTar writes the members of plan M10 §6.5 in order through cw.
func (e *Exporter) writeTar(ctx context.Context, cw *chunkWriter, mtime time.Time, readme []byte, c *collected,
	events *os.File, exportJSON, sigFile []byte) error {
	tw := tar.NewWriter(cw)
	member := func(name string, size int64) error {
		return tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, ModTime: mtime, Typeflag: tar.TypeReg})
	}
	write := func(name string, body []byte) error {
		if err := member(name, int64(len(body))); err != nil {
			return err
		}
		_, err := tw.Write(body)
		return err
	}
	if err := write("README.md", readme); err != nil {
		return err
	}
	for _, d := range c.days {
		if err := write("manifests/"+d.day+".json", d.raw); err != nil {
			return err
		}
	}
	for _, d := range c.days {
		for _, o := range d.objects {
			body, err := e.store.Get(ctx, o.Key)
			if err != nil {
				return fmt.Errorf("day %s: object %s unreadable: %w", d.day, o.Key, err)
			}
			if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != o.SHA256 {
				return fmt.Errorf("day %s: object %s changed during the build", d.day, o.Key)
			}
			if err := write(o.Path, body); err != nil {
				return err
			}
		}
	}
	if _, err := events.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := member("events.jsonl", c.eventsSz); err != nil {
		return err
	}
	if _, err := io.Copy(tw, events); err != nil {
		return err
	}
	if err := write("export.json", exportJSON); err != nil {
		return err
	}
	if err := write("export.sig", sigFile); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return cw.Close()
}

// chunkWriter cuts a stream into rows of exactly size bytes (the last may be shorter) and hashes the whole stream.
type chunkWriter struct {
	size  int
	buf   []byte
	seq   int32
	total int64
	h     hash.Hash
	flush func(seq int32, data []byte) error
}

func newChunkWriter(size int, flush func(seq int32, data []byte) error) *chunkWriter {
	return &chunkWriter{size: size, buf: make([]byte, 0, size), h: sha256.New(), flush: flush}
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		k := min(c.size-len(c.buf), len(p))
		c.buf = append(c.buf, p[:k]...)
		c.h.Write(p[:k])
		c.total += int64(k)
		written += k
		p = p[k:]
		if len(c.buf) == c.size {
			if err := c.emit(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (c *chunkWriter) emit() error {
	if err := c.flush(c.seq, c.buf); err != nil {
		return err
	}
	c.seq++
	c.buf = c.buf[:0]
	return nil
}

// Close writes the last, shorter row if any bytes are left.
func (c *chunkWriter) Close() error {
	if len(c.buf) == 0 {
		return nil
	}
	return c.emit()
}

func (c *chunkWriter) sum() [32]byte {
	var s [32]byte
	copy(s[:], c.h.Sum(nil))
	return s
}

// readmeText renders values of the export into the README; the purpose, the requester's name and problem texts are
// free text, and a line break or control character in them must not start a Markdown block or hide text.
func readmeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
}

// renderReadme is the README.md of plan M10 §6.5; the organization is named by its ID only (amendment 2026-10-30).
func renderReadme(doc auditevidence.Export, keyVersion int, fingerprint string) []byte {
	anchor := "none"
	if doc.ChainAnchor != nil {
		anchor = *doc.ChainAnchor
	}
	display := doc.RequestedBy.Display
	if display == "" {
		display = doc.RequestedBy.Type
	}
	verification := "no problems."
	if len(doc.Verification.Problems) > 0 {
		lines := make([]string, len(doc.Verification.Problems))
		for i, p := range doc.Verification.Problems {
			lines[i] = "- " + readmeText(p)
		}
		verification = "\n\n" + strings.Join(lines, "\n") + "\n"
	}
	failedRuns := 0
	for _, r := range doc.Verification.Runs {
		if !r.OK {
			failedRuns++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Paddock audit evidence package\n\n")
	fmt.Fprintf(&b, "Organization %s, recording days %s to %s, requested by %s on\n%s for: %s. Built by %s on %s. Package ID %s.\n\n",
		doc.OrganizationID, doc.FromDay, doc.ToDay, readmeText(display), doc.RequestedAt.Format(time.RFC3339),
		readmeText(doc.Purpose), doc.Generator, doc.CreatedAt.Format(time.RFC3339), doc.ExportID)
	fmt.Fprintf(&b, `What is inside: manifests/ holds the signed daily manifests of the audit chain (one per recording day), objects/
holds every audit object those manifests list, byte for byte as stored in the WORM bucket, events.jsonl holds the
decoded events of those objects in recording order, export.json describes the package and export.sig is its
signature with the audit-chain key (version %d, SHA-256 fingerprint %s).

How to verify without access to Paddock: install paddockctl (https://github.com/phischl/paddock-mdm/releases) and run

    paddockctl audit verify-export <this file> --fingerprint <fingerprint recorded by your ISMS>

It checks the package signature, every manifest signature and link, every object hash, that events.jsonl equals the
objects, and prints OK or the list of problems. The manifest of the first day links to the manifest of the day
before (chain anchor %s); verify consecutive packages against each other to extend the chain.

`, keyVersion, fingerprint, anchor)
	fmt.Fprintf(&b, "Server-side verification at build time: %s Nightly verification runs\nthat covered days of this range (from the audit writer's verification log): %d runs, %d with problems.\n\n",
		verification, len(doc.Verification.Runs), failedRuns)
	b.WriteString(`This package contains personal data (names and addresses of administrators, user names, host names). Handle it
according to your organization's rules for audit evidence and delete it when the audit is closed.
`)
	return []byte(b.String())
}

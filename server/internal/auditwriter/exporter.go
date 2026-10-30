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
	// readyCommitted is nil; tests turn a committed ready update into an unknown outcome.
	readyCommitted func(ctx context.Context, id uuid.UUID, err error) error
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
		maxDecoded: exportMaxDecodedObject}
}

// Run builds pending exports and expires old ones every poll interval until ctx ends.
func (e *Exporter) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	// A separate loop, because a long or hung build must not freeze the gauge PaddockAuditExportStuck watches.
	wg.Go(func() { e.observeLoop(ctx) })
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
	if ctx.Err() != nil {
		return
	}
	if _, err := e.Expire(ctx, e.now()); err != nil {
		slog.ErrorContext(ctx, "evidence export expiry failed", "error", err)
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
// so that the auditor sees them. When ctx ends during the build, the export stays running and the stuck check of a
// later round fails it.
func (e *Exporter) Build(ctx context.Context, export auditstore.AuditExport) error {
	start := time.Now()
	res, err := e.build(ctx, export)
	if err == nil {
		err = e.markReady(ctx, export, res)
		if errors.Is(err, errNotRunning) {
			return err
		}
		if err != nil && e.becameReady(ctx, export.ID) {
			slog.WarnContext(ctx, "evidence export: ready despite an error", "export_id", export.ID, "error", err)
			err = nil
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		failed, failErr := e.failRunning(ctx, export.ID, exportErrorText(err))
		if failErr != nil {
			return errors.Join(err, failErr)
		}
		if !failed {
			// The stuck check failed the export and recorded its outcome while this build may still have
			// inserted chunks. Only an ended export loses them: a ready update whose outcome becameReady could not
			// read may have committed.
			if _, delErr := e.deleteEndedChunks(context.WithoutCancel(ctx), uuid.NullUUID{UUID: export.ID, Valid: true}); delErr != nil {
				return errors.Join(err, errNotRunning, delErr)
			}
			return errors.Join(err, errNotRunning)
		}
		metricExport.WithLabelValues("failed").Inc()
		e.recordSelf(ctx, completedEvent(export, nil, exportErrorText(err)))
		return err
	}
	metricExport.WithLabelValues("ready").Inc()
	metricExportBuild.Observe(time.Since(start).Seconds())
	slog.InfoContext(ctx, "evidence export ready", "export_id", export.ID, "organization_id", export.OrganizationID,
		"objects", res.objects, "events", res.events, "size", res.size, "verify_ok", res.verifyOK)
	e.recordSelf(ctx, completedEvent(export, &res, ""))
	return nil
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
	err = e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
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
		if _, delErr := e.deleteChunks(ctx, export.ID); delErr != nil {
			return errors.Join(errNotRunning, delErr)
		}
		return errNotRunning
	}
	return nil
}

// failRunning sets a running export failed and deletes its chunks in one transaction; it reports whether the export
// was still running.
func (e *Exporter) failRunning(ctx context.Context, id uuid.UUID, message string) (bool, error) {
	var updated int64
	err := e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		if updated, err = q.UpdateAuditExportFailed(ctx, auditstore.UpdateAuditExportFailedParams{ID: id, Error: &message}); err != nil || updated == 0 {
			return err
		}
		_, err = q.DeleteAuditExportChunks(ctx, id)
		return err
	})
	return updated > 0, err
}

// becameReady reports whether the export is ready after markReady failed: the COMMIT may have succeeded although the
// client never learned it, and a ready package must keep its chunks and get its completed event.
func (e *Exporter) becameReady(ctx context.Context, id uuid.UUID) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), exportStatusTimeout)
	defer cancel()
	var status string
	err := e.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		export, err := q.GetAuditExport(ctx, id)
		status = export.Status
		return err
	})
	if err != nil {
		slog.ErrorContext(ctx, "evidence export: status not read", "export_id", id, "error", err)
	}
	return err == nil && status == "ready"
}

// deleteEndedChunks deletes the chunks of failed and expired exports; with a null id, of all of them.
func (e *Exporter) deleteEndedChunks(ctx context.Context, id uuid.NullUUID) (int64, error) {
	var n int64
	err := e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		n, err = q.DeleteEndedAuditExportChunks(ctx, id)
		return err
	})
	return n, err
}

func (e *Exporter) deleteChunks(ctx context.Context, id uuid.UUID) (int64, error) {
	var n int64
	err := e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		n, err = q.DeleteAuditExportChunks(ctx, id)
		return err
	})
	return n, err
}

// Expire deletes the chunks of ready exports past their expiry (status expired, retention.purged in the export's
// organization), fails exports that stayed running longer than ExportStuckAfter (plan M10 decision 34) and deletes
// chunks left behind by failed or expired exports.
func (e *Exporter) Expire(ctx context.Context, now time.Time) (expired int, err error) {
	var due, stuck []auditstore.AuditExport
	stuckBefore := now.Add(-ExportStuckAfter)
	err = e.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
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
	for _, export := range due {
		var updated int64
		err := e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
			var err error
			if updated, err = q.UpdateAuditExportExpired(ctx, auditstore.UpdateAuditExportExpiredParams{ID: export.ID, Now: &now}); err != nil || updated == 0 {
				return err
			}
			_, err = q.DeleteAuditExportChunks(ctx, export.ID)
			return err
		})
		if err != nil {
			return expired, fmt.Errorf("expire export %s: %w", export.ID, err)
		}
		if updated == 0 {
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
			return expired, fmt.Errorf("fail stuck export %s: %w", export.ID, err)
		}
		if !failed {
			continue
		}
		metricExport.WithLabelValues("failed").Inc()
		slog.WarnContext(ctx, "evidence export abandoned", "export_id", export.ID, "started_at", export.StartedAt)
		e.recordSelf(ctx, completedEvent(export, nil, exportStuckError))
	}
	// A builder that was failed by the stuck check can still insert chunks and then die before deleting them; its
	// outcome is already recorded, so the leftovers need no event but must not outlive the export's expiry.
	n, err := e.deleteEndedChunks(ctx, uuid.NullUUID{})
	if err != nil {
		return expired, fmt.Errorf("delete chunks of ended exports: %w", err)
	}
	if n > 0 {
		slog.WarnContext(ctx, "evidence export: deleted leftover chunks", "chunks", n)
	}
	return expired, nil
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
// so export.json and its signature exist before the README, which names the result, is written first in the tar.
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
	canonical, err := canonicaljson.Marshal(doc)
	if err != nil {
		return built{}, err
	}
	digest := auditevidence.ExportDigest(canonical)
	sig, err := e.signer.Sign(ctx, SigningKey, digest[:])
	if err != nil {
		return built{}, fmt.Errorf("sign: %w", err)
	}
	if !auditevidence.VerifySignature(keys, sig.KeyVersion, sig.Value, digest[:]) {
		return built{}, fmt.Errorf("the signature does not verify with the published audit-chain v%d", sig.KeyVersion)
	}
	sigFile, err := json.Marshal(auditevidence.Signature{Signature: sig.Value, KeyVersion: sig.KeyVersion})
	if err != nil {
		return built{}, err
	}
	err = e.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		return ensureSigningKey(ctx, q, sig.KeyVersion, keys[sig.KeyVersion])
	})
	if err != nil {
		return built{}, err
	}
	readme := renderReadme(doc, sig.KeyVersion, auditevidence.Fingerprint(keys[sig.KeyVersion]))

	cw := newChunkWriter(e.chunkSize, func(seq int32, data []byte) error {
		return e.pool.InWriterWithTimeout(ctx, exportChunkTimeout, func(ctx context.Context, q *auditstore.Queries) error {
			return q.InsertAuditExportChunk(ctx, auditstore.InsertAuditExportChunkParams{
				ExportID: export.ID, OrganizationID: org, Seq: seq, Data: data,
			})
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

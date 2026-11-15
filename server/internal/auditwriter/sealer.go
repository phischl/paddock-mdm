package auditwriter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// ManifestSchema is the schema of the daily manifest.
const ManifestSchema = "paddock.audit-manifest.v1"

// SigningKey is the OpenBao Transit key of the hash chain.
const SigningKey = "audit-chain"

var metricSeal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_audit_seal_total", Help: "Daily manifests sealed per result.",
}, []string{"result"})

// ManifestObject is one object entry of a manifest.
type ManifestObject struct {
	Key        string `json:"key"`
	SHA256     string `json:"sha256"`
	EventCount int    `json:"event_count"`
}

// Manifest is the signed daily summary of one organization.
type Manifest struct {
	Schema             string           `json:"schema"`
	OrganizationID     string           `json:"organization_id"`
	Day                string           `json:"day"`
	Objects            []ManifestObject `json:"objects"`
	PrevManifestSHA256 *string          `json:"prev_manifest_sha256"`
	// Retired marks the last manifest of a retired organization (plan M17 amendment 2026-11-15 o point 7); no manifest
	// follows it. Omitted otherwise, so every other manifest keeps its canonical form.
	Retired bool `json:"retired,omitempty"`
}

// ManifestFile is the stored object org/<org>/manifests/<day>.json.
type ManifestFile struct {
	Manifest   json.RawMessage `json:"manifest"`
	Signature  string          `json:"signature"`
	KeyVersion int             `json:"key_version"`
}

// CanonicalManifest builds the manifest and returns its RFC 8785 canonical bytes and their SHA-256. Objects are
// sorted by key, so the result does not depend on the input order.
func CanonicalManifest(org uuid.UUID, day time.Time, objects []ManifestObject, prev []byte) ([]byte, [32]byte, error) {
	return canonicalManifest(org, day, objects, prev, false)
}

// canonicalManifest is CanonicalManifest with the retired mark.
func canonicalManifest(org uuid.UUID, day time.Time, objects []ManifestObject, prev []byte, retired bool) ([]byte, [32]byte, error) {
	sorted := append([]ManifestObject(nil), objects...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	m := Manifest{
		Schema: ManifestSchema, OrganizationID: org.String(), Day: day.UTC().Format(time.DateOnly), Objects: sorted,
		Retired: retired,
	}
	if m.Objects == nil {
		m.Objects = []ManifestObject{}
	}
	if prev != nil {
		h := hex.EncodeToString(prev)
		m.PrevManifestSHA256 = &h
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, [32]byte{}, err
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return canonical, sha256.Sum256(canonical), nil
}

// Signer signs with the audit-chain key.
type Signer interface {
	Sign(ctx context.Context, key string, message []byte) (bao.Signature, error)
}

// Sealer writes the daily manifests.
type Sealer struct {
	pool   *db.AuditWriterPool
	writer *Writer
	signer Signer
	keys   *KeyPublisher
	now    func() time.Time
}

// NewSealer creates a sealer.
func NewSealer(pool *db.AuditWriterPool, writer *Writer, signer Signer, keys *KeyPublisher) *Sealer {
	return &Sealer{pool: pool, writer: writer, signer: signer, keys: keys, now: time.Now}
}

// ErrLocked means another replica is sealing.
var ErrLocked = errors.New("auditwriter: another replica holds the seal lock")

// ErrKeyVersion means the signer returned a key version that the manifest index cannot record.
var ErrKeyVersion = errors.New("auditwriter: signing key version out of range")

// ErrDayOpen means a requested day can still receive objects and must not be sealed yet.
var ErrDayOpen = errors.New("auditwriter: a day is sealable only from 00:15 UTC of the following day")

// SealDelay is how long after midnight UTC the previous day stays open. It exceeds db.WriterTransactionTimeout, so
// every writer transaction that started on day D has committed or rolled back before D is sealed.
const SealDelay = 15 * time.Minute

// LastSealableDay is the latest day that may be sealed at now: day D once now ≥ D+1 00:15 UTC.
func LastSealableDay(now time.Time) time.Time {
	return dayOf(now.UTC().Add(-SealDelay)).AddDate(0, 0, -1)
}

// SealThrough seals, for every organization with audit data, every unsealed day up to and including last. Days
// without objects get a manifest with objects: []. Only one replica seals at a time (advisory lock). It returns
// ErrDayOpen without sealing anything if last is after LastSealableDay.
func (s *Sealer) SealThrough(ctx context.Context, last time.Time) (int, error) {
	last = dayOf(last)
	if open := LastSealableDay(s.now()); last.After(open) {
		return 0, fmt.Errorf("%w: %s (latest sealable day is %s)", ErrDayOpen, last.Format(time.DateOnly), open.Format(time.DateOnly))
	}
	sealed := 0
	err := s.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		locked, err := q.TryAuditSealLock(ctx)
		if err != nil {
			return err
		}
		if !locked {
			return ErrLocked
		}
		defer func() { _, _ = q.ReleaseAuditSealLock(context.WithoutCancel(ctx)) }()

		orgs, err := q.ListAuditOrganizations(ctx)
		if err != nil {
			return err
		}
		for _, org := range orgs {
			n, err := s.sealOrganization(ctx, q, org, last, false)
			sealed += n
			if err != nil {
				metricSeal.WithLabelValues("error").Inc()
				return fmt.Errorf("seal organization %s: %w", org, err)
			}
		}
		return nil
	})
	return sealed, err
}

// SealOrganizationThrough seals the unsealed days of one organization up to and including last (development tool:
// tests seal the current day of a fresh organization without touching other organizations). Unlike SealThrough it
// does not wait for SealDelay; the CLI allows it only with PADDOCK_ENV=development.
func (s *Sealer) SealOrganizationThrough(ctx context.Context, org uuid.UUID, last time.Time) (int, error) {
	sealed := 0
	err := s.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		locked, err := q.TryAuditSealLock(ctx)
		if err != nil {
			return err
		}
		if !locked {
			return ErrLocked
		}
		defer func() { _, _ = q.ReleaseAuditSealLock(context.WithoutCancel(ctx)) }()
		sealed, err = s.sealOrganization(ctx, q, org, dayOf(last), false)
		return err
	})
	return sealed, err
}

// sealBeforeFinal seals the days of a retired organization that may be sealed at the sealer's clock (LastSealableDay),
// before its final verification is recorded (plan M17 amendment 2026-11-15 o, review 1 m1): the final verification
// then covers them as sealed days. The final event is written after this, on a day that is still open, so none of these
// days can hold it. ErrLocked means the daily seal runs; the caller retries.
func (s *Sealer) sealBeforeFinal(ctx context.Context, org uuid.UUID) (int, error) {
	sealed := 0
	err := s.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		if _, err := q.LastAuditObjectDay(ctx, org); db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		locked, err := q.TryAuditSealLock(ctx)
		if err != nil {
			return err
		}
		if !locked {
			return ErrLocked
		}
		defer func() { _, _ = q.ReleaseAuditSealLock(context.WithoutCancel(ctx)) }()
		sealed, err = s.sealOrganization(ctx, q, org, LastSealableDay(s.now()), true)
		return err
	})
	return sealed, err
}

// sealOrganization seals org's unsealed days through last. beforeFinal is set only by sealBeforeFinal: it seals a
// retired organization whose final verification is not recorded yet, which every other caller leaves alone.
func (s *Sealer) sealOrganization(ctx context.Context, q *auditstore.Queries, org uuid.UUID, last time.Time, beforeFinal bool) (int, error) {
	var day time.Time
	var prev []byte
	latest, err := q.GetLatestAuditManifest(ctx, org)
	switch {
	case err == nil:
		day = dayOf(latest.Day).AddDate(0, 0, 1)
		prev = latest.Sha256
	case db.IsNoRows(err):
		first, err := q.FirstAuditDay(ctx, org)
		if err != nil {
			return 0, err
		}
		day = dayOf(first)
	default:
		return 0, err
	}
	var finalDay time.Time
	stop := false
	if !beforeFinal {
		if finalDay, stop, err = retiredLastDay(ctx, q, org); err != nil {
			return 0, err
		}
	}
	if stop && finalDay.Before(last) {
		last = finalDay
	}
	n := 0
	for ; !day.After(last); day = day.AddDate(0, 0, 1) {
		sum, err := s.sealDay(ctx, org, day, prev, stop && day.Equal(finalDay))
		if err != nil {
			return n, err
		}
		prev = sum
		n++
	}
	return n, nil
}

// retiredLastDay is the last day the sealer seals for a retired organization (plan M17 amendment 2026-11-15 o point 7):
// the day of its newest object, which after the final verification is the day of that verification's event, since
// every later event goes to the platform pseudo-organization. stop is true for a retired organization; while its final
// verification is still being recorded, the last day is the day before its first day, so nothing is sealed and the
// final event cannot land on a day already sealed without the mark.
func retiredLastDay(ctx context.Context, q *auditstore.Queries, org uuid.UUID) (last time.Time, stop bool, err error) {
	row, err := q.GetAuditOrgRetired(ctx, org)
	if db.IsNoRows(err) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	if row.FinalVerifiedAt == nil {
		return time.Time{}, true, nil
	}
	last, err = q.LastAuditObjectDay(ctx, org)
	if err != nil {
		return time.Time{}, false, err
	}
	return dayOf(last), true, nil
}

// sealDay writes and records one manifest in its own transaction. It holds the organization's audit-day lock, so
// every writer transaction that inserted an object of the day has committed before the objects are listed, and every
// later one sees the manifest and files its object under the next day (audit migration 00005).
func (s *Sealer) sealDay(ctx context.Context, org uuid.UUID, day time.Time, prev []byte, retired bool) ([]byte, error) {
	var sum [32]byte
	err := s.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.LockAuditDays(ctx, org); err != nil {
			return err
		}
		rows, err := q.ListAuditObjectsForDay(ctx, auditstore.ListAuditObjectsForDayParams{OrganizationID: org, Day: day})
		if err != nil {
			return err
		}
		objects := make([]ManifestObject, len(rows))
		for i, r := range rows {
			objects[i] = ManifestObject{Key: r.ObjectKey, SHA256: hex.EncodeToString(r.Sha256), EventCount: int(r.EventCount)}
		}
		var canonical []byte
		canonical, sum, err = canonicalManifest(org, day, objects, prev, retired)
		if err != nil {
			return err
		}
		sig, err := s.signer.Sign(ctx, SigningKey, sum[:])
		if err != nil {
			return err
		}
		// Checked before the WORM write: a locked object with an unrecordable key version could never be indexed.
		if sig.KeyVersion < 1 || sig.KeyVersion > math.MaxInt32 {
			return fmt.Errorf("%w: %d", ErrKeyVersion, sig.KeyVersion)
		}
		if err := s.keys.Ensure(ctx, q, sig.KeyVersion); err != nil {
			return err
		}
		file, err := json.Marshal(ManifestFile{Manifest: canonical, Signature: sig.Value, KeyVersion: sig.KeyVersion})
		if err != nil {
			return err
		}
		key := ManifestKey(org, day)
		if err := putLocked(ctx, s.writer.store, putObjectManifest, key, "application/json", file, s.writer.RetainUntil(day)); err != nil {
			return err
		}
		return q.InsertAuditManifest(ctx, auditstore.InsertAuditManifestParams{
			OrganizationID: org, Day: day, Sha256: sum[:], PrevSha256: prev, Signature: sig.Value,
			KeyVersion: int32(sig.KeyVersion), ObjectKey: key,
		})
	})
	if err != nil {
		return nil, err
	}
	metricSeal.WithLabelValues("success").Inc()
	slog.InfoContext(ctx, "audit day sealed", "organization_id", org, "day", day.Format(time.DateOnly))
	return sum[:], nil
}

// RunDaily seals "yesterday" every day at 00:15 UTC (SealDelay) until ctx ends.
func (s *Sealer) RunDaily(ctx context.Context) {
	for {
		now := s.now().UTC()
		next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Add(SealDelay)
		if !next.After(now) {
			next = next.AddDate(0, 0, 1)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next.Sub(now)):
		}
		n, err := s.SealThrough(ctx, LastSealableDay(s.now()))
		switch {
		case errors.Is(err, ErrLocked):
			slog.InfoContext(ctx, "seal skipped: another replica is sealing")
		case err != nil:
			slog.ErrorContext(ctx, "daily seal failed", "error", err)
		default:
			slog.InfoContext(ctx, "daily seal finished", "manifests", n)
		}
	}
}

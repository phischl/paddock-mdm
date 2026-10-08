package app

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/osv"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// OSVStaleAfter is how long Ubuntu's vulnerability data may go without a successful update before the platform
// operator is alerted (ADR 0020, plan M5c decision 4).
const OSVStaleAfter = 72 * time.Hour

// osvBatch is the number of rows per insert statement of an import.
const osvBatch = 5000

// maxOSVError bounds the error text kept in the sync state.
const maxOSVError = 500

// errNoOSVEntries refuses an import without entries: an empty or foreign zip must never replace the data.
var errNoOSVEntries = errors.New("the OSV data has no entries for a managed Ubuntu release")

// OSV keeps Ubuntu's vulnerability data and enriches the findings with it (plan M5c decisions 1, 2 and 4).
type OSV struct {
	runner   *ActionRunner
	org      *db.OrgPool
	platform *db.PlatformPool
}

// NewOSV creates the use cases; org may be nil where only the import runs (paddock-server osv import).
func NewOSV(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool) *OSV {
	return &OSV{runner: runner, org: org, platform: platform}
}

// OSVState is the state of the download.
type OSVState struct {
	ETag          string
	DataVersion   int64
	Entries       int
	LastSuccessAt *time.Time
	LastAttemptAt *time.Time
	LastError     string
	// StaleAlerted is whether the current stale period was alerted; CreatedAt counts as the last success before the
	// first one.
	StaleAlerted bool
	CreatedAt    time.Time
}

// State returns the state of the download (platform scope).
func (o *OSV) State(ctx context.Context) (OSVState, error) {
	var st OSVState
	err := o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		r, err := q.GetOSVSyncState(ctx)
		st = OSVState{ETag: r.Etag, DataVersion: r.DataVersion, Entries: int(r.Entries), LastSuccessAt: r.LastSuccessAt,
			LastAttemptAt: r.LastAttemptAt, LastError: r.LastError, StaleAlerted: r.StaleAlertedAt != nil, CreatedAt: r.CreatedAt}
		return err
	})
	return st, err
}

// Import replaces Ubuntu's data with the entries read calls back with, in one transaction, and records etag (the
// ETag of the download, "" for a file): if read fails or yields no entry, the previous data stays.
func (o *OSV) Import(ctx context.Context, etag string, read func(fn func(osv.Entry) error) (osv.Stats, error)) (osv.Stats, error) {
	var st osv.Stats
	err := o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if err := q.DeleteOSVData(ctx); err != nil {
			return err
		}
		if err := q.DeleteOSVBinaries(ctx); err != nil {
			return err
		}
		var rows pgstore.InsertOSVEntriesParams
		var bins pgstore.InsertOSVBinariesParams
		seen := map[[3]string]bool{}
		flushRows := func() error {
			if len(rows.Cves) == 0 {
				return nil
			}
			err := q.InsertOSVEntries(ctx, rows)
			rows = pgstore.InsertOSVEntriesParams{}
			return err
		}
		flushBins := func() error {
			if len(bins.Binaries) == 0 {
				return nil
			}
			err := q.InsertOSVBinaries(ctx, bins)
			bins = pgstore.InsertOSVBinariesParams{}
			return err
		}
		var err error
		st, err = read(func(e osv.Entry) error {
			rows.Cves, rows.Releases, rows.Packages = append(rows.Cves, e.CVE), append(rows.Releases, e.Release), append(rows.Packages, e.Package)
			rows.Priorities, rows.Fixed, rows.Vectors = append(rows.Priorities, e.Priority), append(rows.Fixed, e.FixedVersion), append(rows.Vectors, e.CVSSVector)
			rows.Modified = append(rows.Modified, e.Modified)
			for _, b := range e.Binaries {
				// A binary package of a CVE's source package is listed again by every other CVE of it.
				if k := [3]string{e.Release, b, e.Package}; b != e.Package && !seen[k] {
					seen[k] = true
					bins.Releases, bins.Binaries, bins.Packages = append(bins.Releases, e.Release), append(bins.Binaries, b), append(bins.Packages, e.Package)
				}
			}
			if len(bins.Binaries) >= osvBatch {
				if err := flushBins(); err != nil {
					return err
				}
			}
			if len(rows.Cves) >= osvBatch {
				return flushRows()
			}
			return nil
		})
		if err != nil {
			return err
		}
		if st.Entries == 0 {
			return errNoOSVEntries
		}
		if err := flushRows(); err != nil {
			return err
		}
		if err := flushBins(); err != nil {
			return err
		}
		return q.MarkOSVImported(ctx, pgstore.MarkOSVImportedParams{Etag: etag, Entries: int32(min(st.Entries, 1<<31-1))}) //nolint:gosec // clamped
	})
	return st, err
}

// NotModified records a download the source answered with 304: the data is current.
func (o *OSV) NotModified(ctx context.Context) error {
	return o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error { return q.MarkOSVNotModified(ctx) })
}

// Failed records a failed download; the data stays.
func (o *OSV) Failed(ctx context.Context, cause error) error {
	msg := cause.Error()
	if len(msg) > maxOSVError {
		msg = msg[:maxOSVError]
	}
	return o.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error { return q.MarkOSVFailed(ctx, msg) })
}

// AlertIfStale records platform.osv_stale once when the data has not been updated successfully for OSVStaleAfter at
// now; it reports whether the data is stale.
func (o *OSV) AlertIfStale(ctx context.Context, now time.Time) (bool, error) {
	st, err := o.State(ctx)
	if err != nil {
		return false, err
	}
	since := st.CreatedAt
	if st.LastSuccessAt != nil {
		since = *st.LastSuccessAt
	}
	if now.Sub(since) < OSVStaleAfter {
		return false, nil
	}
	if st.StaleAlerted {
		return true, nil
	}
	params := map[string]any{"last_error": st.LastError}
	if st.LastSuccessAt != nil {
		params["last_success_at"] = audit.Timestamp(*st.LastSuccessAt).Format(time.RFC3339Nano)
	}
	spec := ActionSpec{Code: audit.CodePlatformOSVStale, Target: &audit.Target{Type: "osv_source", ID: "ubuntu"}, Params: params}
	return true, o.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		return q.MarkOSVStaleAlerted(ctx)
	})
}

// Enrich gives the findings of the organization in ctx Ubuntu's severity, fixed version and CVSS vector for the
// release of their device (plan M5c decision 2) and returns the number of changed findings.
func (o *OSV) Enrich(ctx context.Context) (int64, error) {
	var n int64
	err := o.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		n, err = q.EnrichFindings(ctx, uuid.NullUUID{})
		return err
	})
	return n, err
}

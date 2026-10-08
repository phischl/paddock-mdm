package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/osv"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// osvRoundInterval is how often the worker checks whether a download is due and whether the data is stale.
const osvRoundInterval = time.Minute

// osvMaxAge is the age of the data from which a starting worker downloads at once instead of at its daily minute.
const osvMaxAge = 24 * time.Hour

// osvLockKey is the advisory lock of the osv-sync job ("padd osv").
const osvLockKey = 0x70616464206f7376

var (
	metricOSVLastSuccess = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_osv_last_success_timestamp_seconds",
		Help: "When Ubuntu's vulnerability data was last downloaded, confirmed unchanged or imported; 0 before the first time.",
	})
	metricOSVStale = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_osv_stale",
		Help: "1 while Ubuntu's vulnerability data has not been updated successfully for 3 days, else 0.",
	})
	metricOSVEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_osv_entries",
		Help: "Entries (CVE, release, source package) of Ubuntu's vulnerability data in use.",
	})
)

// OSVSource is the download of Ubuntu's OSV bulk zip (osvfeed.Client).
type OSVSource interface {
	// Fetch calls read with the new ETag and the body unless the file still has etag (notModified).
	Fetch(ctx context.Context, etag string, read func(etag string, body io.Reader) error) (notModified bool, err error)
}

// OSV is the osv-sync job (plan M5c decisions 1, 2 and 4): a download once a day at a random minute, at start when the
// data is older than a day, the enrichment of every organization's findings when the data changed, and the stale
// alert.
type OSV struct {
	osv      *app.OSV
	source   OSVSource
	org      *db.OrgPool
	platform *db.PlatformPool
	every    time.Duration
	slot     time.Duration
	now      func() time.Time

	// started is set after the first due check, enriched is the data version the findings were enriched with (owned
	// by Round; 0 enriches once at start, which also covers an import by paddock-server osv import).
	started  bool
	enriched int64
}

// NewOSV creates the job; every > 0 replaces the daily download by one every interval (development installations,
// gate O1).
func NewOSV(o *app.OSV, source OSVSource, org *db.OrgPool, platform *db.PlatformPool, every time.Duration) *OSV {
	return &OSV{osv: o, source: source, org: org, platform: platform, every: every,
		slot: time.Duration(rand.Int64N(int64(24*time.Hour/time.Minute))) * time.Minute, now: time.Now} //nolint:gosec // spreads downloads over the day

}

// Run runs the round at start and then every osvRoundInterval until ctx ends; only the replica holding the lock acts.
func (o *OSV) Run(ctx context.Context) error {
	interval := osvRoundInterval
	if o.every > 0 {
		interval = min(interval, o.every)
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := o.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "osv round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round downloads the data when it is due, enriches the findings when it changed and raises the stale alert.
func (o *OSV) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	_, err := o.platform.WithLeaderLock(sys, osvLockKey, func(ctx context.Context) error {
		st, err := o.osv.State(ctx)
		if err != nil {
			return err
		}
		if o.due(o.now(), st) {
			o.sync(ctx, st)
			if st, err = o.osv.State(ctx); err != nil {
				return err
			}
		}
		if st.LastSuccessAt != nil {
			metricOSVLastSuccess.Set(float64(st.LastSuccessAt.Unix()))
		}
		metricOSVEntries.Set(float64(st.Entries))
		if st.DataVersion != o.enriched {
			if err := o.enrich(ctx); err != nil {
				return err
			}
			o.enriched = st.DataVersion
		}
		stale, err := o.osv.AlertIfStale(ctx, o.now())
		if stale {
			metricOSVStale.Set(1)
		} else {
			metricOSVStale.Set(0)
		}
		return err
	})
	return err
}

// due reports whether a download is due at now: the first round downloads when the data is older than osvMaxAge,
// later ones once per day at the job's minute (or every interval).
func (o *OSV) due(now time.Time, st app.OSVState) bool {
	if o.every > 0 {
		return st.LastAttemptAt == nil || now.Sub(*st.LastAttemptAt) >= o.every
	}
	if !o.started {
		o.started = true
		if st.LastSuccessAt == nil || now.Sub(*st.LastSuccessAt) >= osvMaxAge {
			return true
		}
	}
	slot := now.Truncate(24 * time.Hour).Add(o.slot)
	if now.Before(slot) {
		slot = slot.Add(-24 * time.Hour)
	}
	return st.LastAttemptAt == nil || st.LastAttemptAt.Before(slot)
}

// sync downloads and imports the data; a failure is recorded and the previous data stays.
func (o *OSV) sync(ctx context.Context, st app.OSVState) {
	start := o.now()
	var stats osv.Stats
	notModified, err := o.source.Fetch(ctx, st.ETag, func(etag string, body io.Reader) error {
		var err error
		stats, err = o.osv.Import(ctx, etag, func(fn func(osv.Entry) error) (osv.Stats, error) { return osv.Read(body, fn) })
		return err
	})
	switch {
	case err != nil:
		slog.WarnContext(ctx, "downloading Ubuntu's vulnerability data failed; the previous data stays", "error", err)
		if err := o.osv.Failed(context.WithoutCancel(ctx), err); err != nil {
			slog.WarnContext(ctx, "recording the failed download failed", "error", err)
		}
	case notModified:
		slog.InfoContext(ctx, "Ubuntu's vulnerability data is unchanged")
		if err := o.osv.NotModified(ctx); err != nil {
			slog.WarnContext(ctx, "recording the unchanged download failed", "error", err)
		}
	default:
		slog.InfoContext(ctx, "Ubuntu's vulnerability data imported", "records", stats.Records, "entries", stats.Entries,
			"skipped", stats.Skipped, "took", o.now().Sub(start).Round(time.Second))
	}
}

// enrich enriches the findings of every organization; a failing organization does not stop the others, and the next
// round tries all again.
func (o *OSV) enrich(ctx context.Context) error {
	orgs, err := o.org.OrganizationIDs(ctx)
	if err != nil {
		return err
	}
	var errs []error
	var changed int64
	for _, org := range orgs {
		n, err := o.osv.Enrich(systemContext(ctx, org, "osv-sync"))
		if err != nil {
			errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
		}
		changed += n
	}
	slog.InfoContext(ctx, "findings enriched with Ubuntu's vulnerability data", "organizations", len(orgs), "changed", changed)
	return errors.Join(errs...)
}

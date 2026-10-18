// Package unsealer unseals OpenBao with the shares on the host while the platform setting allows it (ADR 0035).
package unsealer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
)

// Seal is the part of bao.Client the unsealer uses.
type Seal interface {
	SealStatus(ctx context.Context) (bao.SealStatus, error)
	Unseal(ctx context.Context, share string) (bao.SealStatus, error)
	ResetUnseal(ctx context.Context) error
}

// Store reads the setting and writes the report (db.UnsealerPool through pgstore).
type Store interface {
	State(ctx context.Context) (autounseal.State, error)
	Report(ctx context.Context, sharesPresent bool) error
	RecordUnseal(ctx context.Context) error
	RecordFailure(ctx context.Context, reason string) error
}

// Timing and limits of the unsealer (plan M8u decision 11).
const (
	Interval       = 10 * time.Second // one tick
	FailureBackoff = 60 * time.Second // no attempt after a failed one
	SharesRequired = 3                // lines of the shares file
	MaxShareBytes  = 128              // longest accepted line
)

// stateWarnEvery bounds the warning about an unreadable setting to one per minute.
const stateWarnEvery = time.Minute

// maxSharesFileBytes bounds what ReadShares reads; a longer file cannot hold three valid lines.
const maxSharesFileBytes = SharesRequired * (MaxShareBytes + 64)

var (
	metricSharesPresent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_unsealer_shares_present",
		Help: "1 when the shares file holds exactly three valid lines, else 0.",
	})
	metricSettingEnabled = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_unsealer_setting_enabled",
		Help: "1 while the platform setting of the automatic unseal is enabled, else 0; unchanged while it cannot be read.",
	})
	metricUnseals = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "paddock_unsealer_unseals_total",
		Help: "Automatic unseal attempts of OpenBao by result (success, failure).",
	}, []string{"result"})
)

// Unsealer submits the shares of the host to OpenBao while it is sealed and the setting is enabled.
type Unsealer struct {
	seal         Seal
	store        Store
	sharesPath   string
	now          func() time.Time
	backoffUntil time.Time
	stateWarned  time.Time
	sharesIssue  string
}

// New creates the unsealer.
func New(seal Seal, store Store, sharesPath string) *Unsealer {
	metricUnseals.WithLabelValues("success")
	metricUnseals.WithLabelValues("failure")
	return &Unsealer{seal: seal, store: store, sharesPath: sharesPath, now: time.Now}
}

// Run ticks every Interval until ctx ends.
func (u *Unsealer) Run(ctx context.Context) error {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		u.Tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Tick is one round: read the shares file, read the state, read the seal status, unseal when allowed, report.
func (u *Unsealer) Tick(ctx context.Context) {
	shares, present, err := ReadShares(u.sharesPath)
	u.noteShares(ctx, err)
	metricSharesPresent.Set(boolGauge(present))

	state, err := u.store.State(ctx)
	if err != nil {
		// A gate that cannot be read is closed: no OpenBao call at all.
		if now := u.now(); now.Sub(u.stateWarned) >= stateWarnEvery {
			u.stateWarned = now
			slog.WarnContext(ctx, "automatic unseal: the setting cannot be read; not unsealing", "error", err)
		}
		return
	}
	metricSettingEnabled.Set(boolGauge(state == autounseal.StateEnabled))

	st, err := u.seal.SealStatus(ctx)
	if err != nil {
		st.Reachable = false
	}
	if st.Reachable && st.Initialized && st.Sealed && state == autounseal.StateEnabled && present &&
		!u.now().Before(u.backoffUntil) {
		u.unseal(ctx, shares)
	}

	if err := u.store.Report(ctx, present); err != nil {
		slog.WarnContext(ctx, "automatic unseal: report failed", "error", err)
	}
}

// unseal submits the shares in file order until OpenBao reports unsealed.
func (u *Unsealer) unseal(ctx context.Context, shares []string) {
	for i, share := range shares {
		st, err := u.seal.Unseal(ctx, share)
		if err != nil {
			reason := autounseal.FailureReasonUnreachable
			if errors.Is(err, bao.ErrShareRefused) {
				reason = autounseal.FailureReasonInvalidShare
			}
			u.fail(ctx, reason, i+1)
			return
		}
		if !st.Sealed {
			metricUnseals.WithLabelValues("success").Inc()
			if err := u.store.RecordUnseal(ctx); err != nil {
				slog.WarnContext(ctx, "automatic unseal: recording the unseal failed", "error", err)
			}
			slog.InfoContext(ctx, "OpenBao unsealed automatically", "shares_submitted", i+1)
			return
		}
	}
	u.fail(ctx, autounseal.FailureReasonStillSealed, len(shares))
}

// fail discards the partial progress, records the reason and backs off.
func (u *Unsealer) fail(ctx context.Context, reason string, submitted int) {
	if err := u.seal.ResetUnseal(ctx); err != nil {
		slog.WarnContext(ctx, "automatic unseal: resetting the unseal progress failed", "error", err)
	}
	metricUnseals.WithLabelValues("failure").Inc()
	if err := u.store.RecordFailure(ctx, reason); err != nil {
		slog.WarnContext(ctx, "automatic unseal: recording the failure failed", "error", err)
	}
	u.backoffUntil = u.now().Add(FailureBackoff)
	slog.WarnContext(ctx, "automatic unseal failed", "reason", reason, "shares_submitted", submitted,
		"retry_after", FailureBackoff)
}

// noteShares logs a changed condition of the shares file once, not on every tick.
func (u *Unsealer) noteShares(ctx context.Context, err error) {
	issue := ""
	if err != nil {
		issue = err.Error()
	}
	if issue == u.sharesIssue {
		return
	}
	u.sharesIssue = issue
	if issue == "" {
		slog.InfoContext(ctx, "automatic unseal: the shares file holds three shares")
		return
	}
	slog.InfoContext(ctx, "automatic unseal: no usable shares on the host", "condition", issue)
}

// ReadShares returns the shares of path: present only when the file exists and holds exactly SharesRequired
// non-empty lines of at most MaxShareBytes bytes each (trailing newline and surrounding whitespace trimmed);
// otherwise present is false and err names the condition (count or length), never a line's content.
func ReadShares(path string) (shares []string, present bool, err error) {
	f, err := os.Open(path) //nolint:gosec // the path is operator configuration
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, errors.New("the shares file does not exist")
		}
		return nil, false, errors.New("the shares file cannot be read")
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxSharesFileBytes+1))
	if err != nil {
		return nil, false, errors.New("the shares file cannot be read")
	}
	if len(raw) > maxSharesFileBytes {
		return nil, false, fmt.Errorf("the shares file is longer than %d bytes", maxSharesFileBytes)
	}
	content := strings.TrimSpace(string(raw))
	var lines []string
	if content != "" {
		lines = strings.Split(content, "\n")
	}
	if len(lines) != SharesRequired {
		return nil, false, fmt.Errorf("the shares file holds %d lines, want %d", len(lines), SharesRequired)
	}
	for i, l := range lines {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
			return nil, false, fmt.Errorf("line %d of the shares file is empty", i+1)
		case len(l) > MaxShareBytes:
			return nil, false, fmt.Errorf("line %d of the shares file is longer than %d bytes", i+1, MaxShareBytes)
		}
		lines[i] = l
	}
	return lines, true, nil
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

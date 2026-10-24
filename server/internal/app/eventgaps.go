package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// gapReportCheckins is the number of check-ins after the round that first saw a hole before it is reported (plan M8b
// decision 17): they give event batches that arrived out of order time to be recorded.
const gapReportCheckins = 2

// EventGaps finds holes in the event numbering of devices, reports those that stay open as device.event_gap and
// those that close later as device.event_gap_filled (plan M8b decision 20, worker).
type EventGaps struct {
	runner *ActionRunner
	org    *db.OrgPool
	// afterCandidates runs after the candidates were listed and before any device is evaluated (tests of the race
	// with a reset, PDK-108 review 1).
	afterCandidates func(ctx context.Context) error
}

// NewEventGaps creates the use case.
func NewEventGaps(runner *ActionRunner, org *db.OrgPool) *EventGaps {
	return &EventGaps{runner: runner, org: org}
}

// gapState is what one evaluation knows about a device's numbering, read under the lock of its status row.
type gapState struct {
	pgstore.LockDeviceEventSeqRow
	seen    []int64
	dropped []device.SeqRange
	open    []pgstore.DeviceEventGap
	high    int64
}

// Evaluate checks every active device of the context's organization whose numbering may hold a hole. A device whose
// evaluation fails is logged and skipped; the round goes on with the others.
func (g *EventGaps) Evaluate(ctx context.Context, now time.Time) error {
	var candidates []pgstore.ListEventGapCandidatesRow
	if err := g.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		candidates, err = q.ListEventGapCandidates(ctx)
		return err
	}); err != nil {
		return err
	}
	if g.afterCandidates != nil {
		if err := g.afterCandidates(ctx); err != nil {
			return err
		}
	}
	var errs []error
	for _, c := range candidates {
		if err := g.evaluate(ctx, c.DeviceID, now); err != nil {
			slog.WarnContext(ctx, "event gaps of a device not evaluated; retried next round", "device_id", c.DeviceID, "error", err)
			errs = append(errs, fmt.Errorf("device %s: %w", c.DeviceID, err))
		}
	}
	return errors.Join(errs...)
}

// evaluate advances the device's contiguous pointer, opens a gap row for every new hole, closes the rows whose numbers
// all arrived and reports the rows that stayed open for two further check-ins. It reads and writes in one transaction
// under the lock of the device's status row, which a reset takes as well: a reset never lands between the read and
// the write, where it would let the round restore the old pointer and open gaps of the old numbering.
func (g *EventGaps) evaluate(ctx context.Context, deviceID uuid.UUID, now time.Time) error {
	var st gapState
	var toReport, filledReported []pgstore.DeviceEventGap
	err := g.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if st, err = read(ctx, q, deviceID); err != nil {
			return err
		}
		contiguous, holes := device.Holes(st.EventSeqContiguous, st.high, st.seen, st.dropped)
		// Numbers above the last one read are unknown when the read hit the limit: their rows wait for a later round.
		known := func(r pgstore.DeviceEventGap) bool {
			return len(st.seen) < device.SeenLimit || r.ToSeq <= st.seen[len(st.seen)-1]
		}
		// Every number up to the pointer the evaluation started from was delivered or dropped; it was not read again.
		settled := append([]device.SeqRange{{From: 1, To: st.EventSeqContiguous}}, st.dropped...)
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		if err := q.SetEventSeqContiguous(ctx, pgstore.SetEventSeqContiguousParams{Value: contiguous, DeviceID: deviceID}); err != nil {
			return err
		}
		openRanges := make([]device.SeqRange, 0, len(st.open))
		for _, r := range st.open {
			openRanges = append(openRanges, device.SeqRange{From: r.FromSeq, To: r.ToSeq})
		}
		for _, h := range holes {
			for _, part := range device.Uncovered(h, openRanges) {
				if err := q.InsertDeviceEventGap(ctx, pgstore.InsertDeviceEventGapParams{
					ID: uuid.Must(uuid.NewV7()), OrganizationID: org, DeviceID: deviceID, FromSeq: part.From, ToSeq: part.To,
					FirstSeenAt: now, FirstSeenLastSeq: st.LastSeq,
				}); err != nil {
					return err
				}
			}
		}
		for _, r := range st.open {
			switch {
			case !known(r):
			case device.Covered(device.SeqRange{From: r.FromSeq, To: r.ToSeq}, st.seen, settled):
				if r.ReportedAt != nil {
					filledReported = append(filledReported, r)
					continue
				}
				if _, err := q.FillDeviceEventGap(ctx, pgstore.FillDeviceEventGapParams{Now: &now, ID: r.ID}); err != nil {
					return err
				}
			case r.ReportedAt == nil && st.LastSeq >= r.FirstSeenLastSeq+gapReportCheckins:
				toReport = append(toReport, r)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, r := range filledReported {
		if err := g.recordFilled(ctx, r, now); err != nil {
			return err
		}
	}
	for _, r := range toReport {
		if err := g.recordGap(ctx, deviceID, st.LockDeviceEventSeqRow, r, now); err != nil {
			return err
		}
	}
	return nil
}

// read locks the device's status row and loads the delivered numbers above its pointer, its dropped ranges and open
// gaps, and the highest number the device claimed: the one of its last check-in, or a delivered one the gateway
// received before that check-in. A number received after the check-in is no evidence of a hole below it yet
// (amendment 2026-10-24).
func read(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID) (gapState, error) {
	locked, err := q.LockDeviceEventSeq(ctx, deviceID)
	if err != nil {
		return gapState{}, err
	}
	st := gapState{LockDeviceEventSeqRow: locked, high: locked.EventSeqHigh}
	above := locked.EventSeqContiguous
	if st.seen, err = q.ListDeviceEventSeenAbove(ctx, pgstore.ListDeviceEventSeenAboveParams{DeviceID: deviceID, Above: above}); err != nil {
		return st, err
	}
	dropped, err := q.ListDeviceEventDroppedAbove(ctx, pgstore.ListDeviceEventDroppedAboveParams{DeviceID: deviceID, Above: above})
	if err != nil {
		return st, err
	}
	for _, d := range dropped {
		st.dropped = append(st.dropped, device.SeqRange{From: d.FromSeq, To: d.ToSeq})
	}
	if st.open, err = q.ListOpenDeviceEventGaps(ctx, deviceID); err != nil {
		return st, err
	}
	if locked.LastContactAt != nil {
		before, err := q.MaxDeviceEventSeenBefore(ctx, pgstore.MaxDeviceEventSeenBeforeParams{DeviceID: deviceID, Before: *locked.LastContactAt})
		if err != nil {
			return st, err
		}
		st.high = max(st.high, before)
	}
	return st, nil
}

// recordGap reports an open gap once: the claim marks it reported unless another round did or it was closed meanwhile.
func (g *EventGaps) recordGap(ctx context.Context, deviceID uuid.UUID, st pgstore.LockDeviceEventSeqRow, r pgstore.DeviceEventGap, now time.Time) error {
	params := map[string]any{
		"from_seq": r.FromSeq, "to_seq": r.ToSeq, "event_seq_high": st.EventSeqHigh,
		"first_seen_at": audit.Timestamp(r.FirstSeenAt).Format(time.RFC3339Nano),
	}
	if st.LastContactAt != nil {
		params["last_contact_at"] = audit.Timestamp(*st.LastContactAt).Format(time.RFC3339Nano)
	}
	spec := ActionSpec{Code: audit.CodeDeviceEventGap, Target: &audit.Target{Type: "device", ID: deviceID.String()}, Params: params}
	_, err := g.runner.RecordOnce(ctx, spec, func(ctx context.Context, q *pgstore.Queries) (bool, error) {
		n, err := q.ReportDeviceEventGap(ctx, pgstore.ReportDeviceEventGapParams{Now: &now, ID: r.ID})
		return n == 1, err
	})
	return err
}

// recordFilled closes a reported gap once: the claim closes it unless another round or a reset did.
func (g *EventGaps) recordFilled(ctx context.Context, r pgstore.DeviceEventGap, now time.Time) error {
	spec := ActionSpec{Code: audit.CodeDeviceEventGapFilled, Target: &audit.Target{Type: "device", ID: r.DeviceID.String()},
		Params: map[string]any{"from_seq": r.FromSeq, "to_seq": r.ToSeq, "reported_at": audit.Timestamp(*r.ReportedAt).Format(time.RFC3339Nano)}}
	_, err := g.runner.RecordOnce(ctx, spec, func(ctx context.Context, q *pgstore.Queries) (bool, error) {
		n, err := q.FillDeviceEventGap(ctx, pgstore.FillDeviceEventGapParams{Now: &now, ID: r.ID})
		return n == 1, err
	})
	return err
}

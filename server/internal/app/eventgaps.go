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

// GapCheckLimit is the number of open gap rows of a device one round checks for coverage (PDK-419 review 1, B1): the
// scan position moves on every round, so a device that delivers sparse numbers can open many rows; checking all of
// them every round under the device's lock would grow without bound. A row that is not checked counts as still open
// and is neither filled nor reported in that round.
const GapCheckLimit = 500

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
	// scanFrom is the scan position the delivered numbers in seen lie above (PDK-419).
	scanFrom int64
	seen     []int64
	dropped  []device.SeqRange
	open     []pgstore.DeviceEventGap
	high     int64
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
		scanned, holes := device.Scan(st.scanFrom, st.high, st.seen, st.dropped)
		// Every number up to the pointer the evaluation started from was delivered or dropped.
		settled := append([]device.SeqRange{{From: 1, To: st.EventSeqContiguous}}, st.dropped...)
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		openRanges := make([]device.SeqRange, 0, len(st.open))
		for _, r := range st.open {
			openRanges = append(openRanges, device.SeqRange{From: r.FromSeq, To: r.ToSeq})
		}
		var stillOpen []device.SeqRange
		for _, h := range holes {
			for _, part := range device.Uncovered(h, openRanges) {
				if err := q.InsertDeviceEventGap(ctx, pgstore.InsertDeviceEventGapParams{
					ID: uuid.Must(uuid.NewV7()), OrganizationID: org, DeviceID: deviceID, FromSeq: part.From, ToSeq: part.To,
					FirstSeenAt: now, FirstSeenLastSeq: st.LastSeq,
				}); err != nil {
					return err
				}
				stillOpen = append(stillOpen, part)
			}
		}
		coverage, err := covered(ctx, q, deviceID, openRanges, checkOrder(st.open), settled)
		if err != nil {
			return err
		}
		for i, r := range st.open {
			filled, checked := coverage[i]
			switch {
			case !checked:
				stillOpen = append(stillOpen, openRanges[i])
			case filled && r.ReportedAt != nil:
				filledReported = append(filledReported, r)
			case filled:
				if _, err := q.FillDeviceEventGap(ctx, pgstore.FillDeviceEventGapParams{Now: &now, ID: r.ID}); err != nil {
					return err
				}
			default:
				stillOpen = append(stillOpen, openRanges[i])
				if r.ReportedAt == nil && st.LastSeq >= r.FirstSeenLastSeq+gapReportCheckins {
					toReport = append(toReport, r)
				}
			}
		}
		if err := q.SetEventSeqScanned(ctx, pgstore.SetEventSeqScannedParams{Value: scanned, DeviceID: deviceID}); err != nil {
			return err
		}
		return q.SetEventSeqContiguous(ctx, pgstore.SetEventSeqContiguousParams{Value: device.Contiguous(scanned, stillOpen), DeviceID: deviceID})
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

// read locks the device's status row and loads the delivered numbers above its scan position, its dropped ranges and open
// gaps, and the highest number the device claimed: the one of its last check-in, or a delivered one the gateway
// received before that check-in. A number received after the check-in is no evidence of a hole below it yet
// (amendment 2026-10-24).
func read(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID) (gapState, error) {
	locked, err := q.LockDeviceEventSeq(ctx, deviceID)
	if err != nil {
		return gapState{}, err
	}
	st := gapState{LockDeviceEventSeqRow: locked, high: locked.EventSeqHigh, scanFrom: max(locked.EventSeqScanned, locked.EventSeqContiguous)}
	if st.seen, err = q.ListDeviceEventSeenAbove(ctx, pgstore.ListDeviceEventSeenAboveParams{DeviceID: deviceID, Above: st.scanFrom}); err != nil {
		return st, err
	}
	dropped, err := q.ListDeviceEventDroppedAbove(ctx, pgstore.ListDeviceEventDroppedAboveParams{DeviceID: deviceID, Above: locked.EventSeqContiguous})
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

// covered determines which of the open gap rows at the indices check are covered: every number delivered or in
// settled. It counts the delivered numbers of all their remaining parts in one statement instead of reading them, so a
// row far below the scan position costs no window of delivered numbers (PDK-419). The result holds an entry for every
// checked index only.
func covered(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID, ranges []device.SeqRange, check []int, settled []device.SeqRange) (map[int]bool, error) {
	out := make(map[int]bool, len(check))
	var froms, tos []int64
	var owner []int
	for _, i := range check {
		out[i] = true
		for _, part := range device.Uncovered(ranges[i], settled) {
			froms, tos, owner = append(froms, part.From), append(tos, part.To), append(owner, i)
		}
	}
	if len(froms) == 0 {
		return out, nil
	}
	counts, err := q.CountDeviceEventSeenInRanges(ctx, pgstore.CountDeviceEventSeenInRangesParams{DeviceID: deviceID, FromSeqs: froms, ToSeqs: tos})
	if err != nil {
		return nil, err
	}
	for _, c := range counts {
		k := c.Idx - 1
		if c.Seen < tos[k]-froms[k]+1 {
			out[owner[k]] = false
		}
	}
	return out, nil
}

// checkOrder returns the indices of the open rows one round checks: at most GapCheckLimit, the unreported ones first
// because their report is still due, each group in ascending order (the order of open).
func checkOrder(open []pgstore.DeviceEventGap) []int {
	var unreported, reported []int
	for i, r := range open {
		if r.ReportedAt == nil {
			unreported = append(unreported, i)
		} else {
			reported = append(reported, i)
		}
	}
	return append(unreported, reported...)[:min(len(open), GapCheckLimit)]
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

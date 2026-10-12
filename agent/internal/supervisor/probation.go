package supervisor

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// probation is a switch under observation; it is persisted so that a restarted supervisor resumes it.
type probation struct {
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	FromSlot    string    `json:"from_slot"`
	ToSlot      string    `json:"to_slot"`
	SwitchedAt  time.Time `json:"switched_at"`
	// RollingBack marks a rollback whose flip to FromSlot happened but is not known to be durable; its result waits.
	RollingBack bool `json:"rolling_back,omitempty"`
	// RollbackPending marks a rollback whose flip back failed; the outcome is rollback_failed, the log stays and the
	// flip is retried until it succeeds (ADR 0024).
	RollbackPending bool `json:"rollback_pending,omitempty"`
	// Outcome and DecidedAt are the decided result, recorded and synced before update-result.json is written. The
	// removal of the log that follows is not synced, so a log that comes back after a power loss carries the result
	// already written, and a restart writes it again unchanged instead of deciding anew (PDK-058).
	Outcome   string    `json:"outcome,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
	deadline  time.Time
	exits     int
	markKept  bool // the check-in mark could not be removed, so it cannot prove a check-in of the new agent
	unsynced  bool // the switch to ToSlot is not known to be durable, so it must be confirmed before "updated"
	passed    bool // healthy at the deadline; only the confirmation of the switch is outstanding
	// unrecorded: the decided rollback_failed is not in the log on disk yet, which still is the switch's undecided
	// log; recordPending rewrites it on every tick until the write succeeds.
	unrecorded bool
	retryAt    time.Time
	retryWait  time.Duration
	retries    int
}

// conclude ends the probation p with outcome. It records the outcome in the probation log before it reports it, so
// that the probation ends in exactly one result even if a power loss brings the removed log back (PDK-058).
func (s *Supervisor) conclude(p *probation, outcome string) (recorded bool) {
	p.Outcome, p.DecidedAt = outcome, time.Now().UTC()
	err := writeJSON(s.cfg.ProbationLog, p, s.cfg.SyncFile)
	if err != nil {
		// The result is the device's only report of the probation, so it is written all the same; only a power loss
		// before the log's removal is durable can then let a restart decide again.
		slog.Error("recording the outcome in the probation log failed", "error", err)
	}
	s.report(p, err == nil)
	return err == nil
}

// recordPending rewrites the probation log of a pending rollback whose outcome could not be recorded, so that the
// log on disk names the decision: a restart must not decide the probation anew (PDK-058, ADR 0024 rules 4 and 5).
func (s *Supervisor) recordPending(p *probation) {
	if !p.unrecorded || !p.RollbackPending {
		return
	}
	if err := writeJSON(s.cfg.ProbationLog, p, s.cfg.SyncFile); err == nil {
		p.unrecorded = false
		slog.Info("recorded the pending rollback in the probation log", "version", p.Version)
	}
}

// report writes the result of p and removes the probation log once the result is written; the log of a pending
// rollback stays, so a restart resumes its retries (ADR 0024); if its outcome could not be recorded, recordPending
// rewrites it, and until then a restart recognises the decision by the result (resumeProbation). If writing the result
// fails and the log holds the recorded outcome (recorded), the log stays, so the next start writes the same result
// again (PDK-063). Without a recorded outcome the log is removed all the same: a failed write may still have put the
// result in place (its last step, the directory sync, follows the rename), and a log without an outcome would let the
// next start run the probation again and contradict that result; a lost result is the lesser evil. The same result
// written twice is reported once: the agent turns a result into an event once per "at" (agent.reportUpdate), and the
// server counts an outcome once per device and release.
func (s *Supervisor) report(p *probation, recorded bool) {
	if s.finishAt(p.Version, p.FromVersion, p.Outcome, p.DecidedAt) != nil && recorded || p.RollbackPending {
		return
	}
	_ = os.Remove(s.cfg.ProbationLog)
}

// resumeProbation continues a probation that a restarted supervisor (or device) interrupted.
func (s *Supervisor) resumeProbation() {
	var p probation
	data, err := os.ReadFile(s.cfg.ProbationLog)
	if err != nil {
		return
	}
	if err := json.Unmarshal(data, &p); err != nil {
		// Without the log's content the release and the slots are unknown, so no result could be true; the staged
		// release directory stays, because its version is unknown too.
		slog.Error("dropping an unreadable probation log", "error", err)
		s.dropProbation("")
		return
	}
	// An undecided log on ToSlot whose release the result names as rollback_failed or rolled_back is a decision that
	// the log could not record before the restart (recordPending): it is resumed, not decided anew (PDK-058). Once the
	// agent has delivered and deleted that result, the decision is no longer visible.
	var res struct {
		Version, Outcome string
		At               time.Time
	}
	if data, err := os.ReadFile(s.cfg.Result); p.Outcome == "" && s.activeSlot() == p.ToSlot && err == nil && json.Unmarshal(data, &res) == nil &&
		res.Version == p.Version && (res.Outcome == outcomeRollbackFailed || res.Outcome == outcomeRolledBack) {
		p.Outcome, p.DecidedAt, p.RollbackPending = res.Outcome, res.At, res.Outcome == outcomeRollbackFailed
		p.unrecorded = writeJSON(s.cfg.ProbationLog, &p, s.cfg.SyncFile) != nil
	}
	// A pending rollback, or a rolled_back whose flip back was lost with the power, retries the flip back; with current
	// on FromSlot (flipped by hand, or the rename landed before a crash) only its durability is outstanding.
	if p.RollbackPending || p.Outcome == outcomeRolledBack && s.activeSlot() == p.ToSlot {
		if p.RollbackPending = s.activeSlot() != p.FromSlot; p.RollbackPending && p.Outcome == outcomeRollbackFailed {
			s.report(&p, true)
		}
		s.rolledBack = &p
		slog.Warn("resuming a pending rollback", "version", p.Version, "active_slot", s.activeSlot(), "target_slot", p.FromSlot)
		return
	}
	if p.Outcome != "" {
		slog.Info("the probation already ended; writing its result again", "version", p.Version, "outcome", p.Outcome)
		s.report(&p, true)
		return
	}
	if p.RollingBack && s.activeSlot() == p.FromSlot {
		s.rolledBack = &p
		slog.Info("resuming a rollback that waits for a durable flip back", "version", p.Version)
		return
	}
	// A rollback flip lost with the power leaves current on ToSlot: the probation runs again and decides anew.
	if s.activeSlot() != p.ToSlot {
		// The flip never happened, or a rollback flip back survived whose log could not be marked rolling_back; on disk
		// the two look the same. No result is reported: rolled_back for a switch lost with the power would count the
		// release as failed in the rollout and block it on this device, while without a result the agent stages the
		// release again and its next probation reports. A current on neither slot proves nothing either way.
		slog.Warn("dropping the probation log: current points at neither the new nor a rolled-back slot", "version", p.Version,
			"active_slot", s.activeSlot(), "to_slot", p.ToSlot)
		s.dropProbation(p.Version)
		return
	}
	p.RollingBack = false
	// The previous supervisor may have seen the switch's sync fail; only a confirmed flip may end in "updated".
	p.unsynced = true
	p.SwitchedAt = s.cfg.Now()
	p.deadline = p.SwitchedAt.Add(s.cfg.Probation)
	s.probation = &p
	// Rolling back here would start the old agent before Run starts the current one; checkProbation does it.
	p.markKept = s.forgetCheckin() != nil
	slog.Info("resuming probation", "version", p.Version)
}

// dropProbation gives up a probation that cannot be resumed. A request left behind keeps update.Pending true, so the
// agent would never stage another release (PDK-060). The removal of the request is therefore synced before the log
// is removed: a power loss can bring back the log with or without the request, never the request alone, and the next
// start drops a log that came back again. If the sync fails, the log stays for that retry.
func (s *Supervisor) dropProbation(version string) {
	s.cleanup(version)
	// A staging directory that does not exist holds no request that a power loss could bring back.
	if err := s.cfg.SyncDir(s.cfg.Staging); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("syncing the staging directory failed; the probation log stays until the next start", "error", err)
		return
	}
	_ = os.Remove(s.cfg.ProbationLog)
}

// writeJSON replaces path with v atomically. It syncs the content with sync before the rename: a new file renamed into
// place unsynced can come back empty after a power loss, and an empty probation log is dropped (PDK-059). It syncs the
// directory after the rename with sync as well, so an error returned at that step leaves path already replaced.
func writeJSON(path string, v any, sync func(*os.File) error) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // our own state files
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	err = errors.Join(err, sync(f), f.Close())
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDirWith(filepath.Dir(path), sync)
}

func syncFile(f *os.File) error { return f.Sync() }

func syncDir(dir string) error { return syncDirWith(dir, syncFile) }

func syncDirWith(dir string, sync func(*os.File) error) error {
	d, err := os.Open(dir) //nolint:gosec // our own directories
	if err != nil {
		return err
	}
	return errors.Join(sync(d), d.Close())
}

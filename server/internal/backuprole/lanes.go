package backuprole

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// lane is the mirror in flight of one target (decisions-alpha10 A10-26). A round starts it and never waits for it: a
// slow target holds only its own lane, while the round goes on with the local backups, the key, the requests and the
// tests. idx is the set the lane copies; the local expire keeps every file of it until the lane ended. passes are the
// passes its result settles: the pass of the round that started it and every pass that waited for the target while
// its previous lane ran (their runs are in idx).
type lane struct {
	idx    repoIndex
	passes []*mirrorPass
}

// mirrorPass is the mirror of one round's set: the runs it covers, the finished runs without mirror results when the
// round indexed the set, minus those an earlier pass still covers, and one result per enabled target, each from a lane
// that copied a set holding these runs. Its phase 2 (Store.MirrorRuns) runs once, when the last of those lanes ended;
// the round never runs it for a target no lane carried. A pass a shutdown or a lost leadership cancelled records
// nothing, so the next leader covers its runs again.
type mirrorPass struct {
	runs    []uuid.UUID
	results []backupset.RunTarget
	// pending counts the results still due: one per lane started, plus the round's own share until all are started.
	pending int
	dropped bool
}

// startMirrors opens a mirror pass for the set idx and starts a lane for every enabled target without one in flight.
// A target whose lane still mirrors an earlier set makes the pass wait for the target's next lane, which a later round
// starts with a newer index: that index holds this round's runs, the in-flight lane's does not. A volume target the
// host has not mounted gets its result at once, in this pass and in every pass waiting for it. A pass waiting for a
// target that is no longer enabled stops waiting for it. The lanes run with ctx.
func (e *Engine) startMirrors(ctx context.Context, idx repoIndex, targets []TargetRecord, kinds map[string]kindInfo,
	ret retention) error {
	due, err := e.store.UnmirroredRuns(ctx)
	if err != nil {
		// The lanes still run; the runs keep no mirror results until a later pass covers them.
		err = fmt.Errorf("list the runs without mirror results: %w", err)
	}
	type immediate struct {
		t      TargetRecord
		class  string
		passes []*mirrorPass
	}
	var settled []immediate
	e.laneMu.Lock()
	covered := map[uuid.UUID]bool{}
	for _, p := range e.passes {
		for _, id := range p.runs {
			covered[id] = true
		}
	}
	pass := &mirrorPass{runs: slices.DeleteFunc(due, func(id uuid.UUID) bool { return covered[id] }), pending: 1}
	e.passes = append(e.passes, pass)
	e.enabled, e.repoKinds = nil, kinds
	enabled := map[uuid.UUID]bool{}
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		enabled[t.ID] = true
		e.enabled = append(e.enabled, t)
		pass.pending++
		if e.lanes[t.ID] != nil {
			e.waiting[t.ID] = append(e.waiting[t.ID], pass)
			continue
		}
		passes := append([]*mirrorPass{pass}, e.waiting[t.ID]...)
		delete(e.waiting, t.ID)
		switch {
		case backupset.Mounted(t.Type) && t.HostState == HostPending:
			settled = append(settled, immediate{t, ClassNotMounted, passes})
		case backupset.Mounted(t.Type) && t.HostState == HostUnreachable:
			settled = append(settled, immediate{t, ClassIO, passes})
		default:
			l := &lane{idx: idx, passes: passes}
			e.lanes[t.ID] = l
			e.laneWG.Add(1)
			go e.runLane(ctx, l, t, kinds, ret)
		}
	}
	var abandoned []*mirrorPass
	for id, passes := range e.waiting {
		if !enabled[id] {
			abandoned = append(abandoned, passes...)
			delete(e.waiting, id)
		}
	}
	e.metrics.series.Set(float64(len(backupset.Kinds) * (1 + len(e.enabled))))
	e.publishTargets()
	e.laneMu.Unlock()
	for _, s := range settled {
		e.settle(ctx, nil, s.passes, s.t, kinds, s.class, 0)
	}
	for _, p := range abandoned {
		e.release(ctx, p)
	}
	e.release(ctx, pass)
	return err
}

// runLane mirrors the set to t and settles the result in the lane's passes. A lane that ends because ctx ended
// (shutdown, lost leadership) records nothing: its passes are dropped, and the next leader mirrors from the recorded
// state.
func (e *Engine) runLane(ctx context.Context, l *lane, t TargetRecord, kinds map[string]kindInfo, ret retention) {
	defer e.laneWG.Done()
	held, err := e.mirrorLane(ctx, l.idx, t, ret)
	if ctx.Err() != nil {
		e.laneMu.Lock()
		delete(e.lanes, t.ID)
		for _, pass := range l.passes {
			pass.dropped = true
		}
		e.passes = slices.DeleteFunc(e.passes, func(p *mirrorPass) bool { return slices.Contains(l.passes, p) })
		e.laneMu.Unlock()
		return
	}
	class := ""
	switch {
	case errors.Is(err, errBudget), errors.Is(err, errSetMoved):
		class = ClassContinues
		slog.InfoContext(ctx, "mirror to backup target continues next round", "target", t.Name, "reason", err)
	case err != nil:
		class = ErrorClass(err)
		slog.WarnContext(ctx, "mirror to backup target failed", "target", t.Name, "error_class", class, "error", err)
	}
	e.settle(ctx, l, l.passes, t, kinds, class, held)
}

// mirrorLane mirrors through its own handle on the repository: the round's closes when the round returns.
func (e *Engine) mirrorLane(ctx context.Context, idx repoIndex, t TargetRecord, ret retention) (int, error) {
	repo, err := os.OpenRoot(e.cfg.RepoDir)
	if err != nil {
		return 0, err
	}
	defer func() { _ = repo.Close() }()
	return e.mirrorTarget(ctx, repo, idx, t, ret)
}

// settle records the result of t, from its lane own or decided at once (own nil), in passes: the target's status per
// kind, its state for the metrics, and the run result; the last result due in a pass runs its phase 2. Nothing is
// written once ctx ended: a process that lost the lead must not write beside the next leader.
func (e *Engine) settle(ctx context.Context, own *lane, passes []*mirrorPass, t TargetRecord, kinds map[string]kindInfo,
	class string, held int) {
	if ctx.Err() != nil {
		// The lane slot and its pin go all the same: a slot left behind would keep the target from ever getting a lane
		// again and its index from ever being expired.
		e.laneMu.Lock()
		if own != nil && e.lanes[t.ID] == own {
			delete(e.lanes, t.ID)
		}
		e.laneMu.Unlock()
		return
	}
	for _, kind := range backupset.Kinds {
		st := KindStatus{LastSuccess: kinds[kind].at, Bytes: kinds[kind].bytes, Error: class}
		if class == ClassContinues {
			// Not an error and not current yet: no last_error, and the last success and its size stay.
			st = KindStatus{}
		}
		if err := e.store.SetTargetStatus(ctx, t.ID, kind, st); err != nil {
			slog.WarnContext(ctx, "backup target status not written", "target", t.Name, "error", err)
		}
	}
	e.laneMu.Lock()
	if own != nil && e.lanes[t.ID] == own {
		delete(e.lanes, t.ID)
	}
	if class == "" || class == ClassUnknownPath {
		e.held[t.ID] = held
	}
	switch class {
	case "":
		e.reachable[t.ID] = true
		mirrored := map[string]time.Time{}
		for kind, k := range kinds {
			mirrored[kind] = k.at
		}
		e.mirrored[t.Name] = mirrored
	case ClassContinues:
		e.reachable[t.ID] = true
	default:
		e.reachable[t.ID] = false
	}
	for _, pass := range passes {
		pass.results = append(pass.results, backupset.RunTarget{TargetID: t.ID.String(), OK: class == "",
			ErrorClass: class, Held: held})
	}
	e.publishTargets()
	e.laneMu.Unlock()
	for _, pass := range passes {
		e.release(ctx, pass)
	}
}

// release gives up one result due in pass and runs its phase 2 once none is due. The pass stays open until phase 2
// returned, so a later pass cannot cover its runs in the meantime (one audit event per run).
func (e *Engine) release(ctx context.Context, pass *mirrorPass) {
	e.laneMu.Lock()
	pass.pending--
	last := pass.pending == 0 && !pass.dropped
	e.laneMu.Unlock()
	if !last || ctx.Err() != nil {
		return
	}
	if len(pass.runs) > 0 {
		if err := e.store.MirrorRuns(ctx, pass.results, pass.runs); err != nil {
			slog.WarnContext(ctx, "the mirror results of the runs were not recorded", "error", err)
		}
	}
	e.laneMu.Lock()
	e.passes = slices.DeleteFunc(e.passes, func(p *mirrorPass) bool { return p == pass })
	e.laneMu.Unlock()
}

// publishTargets sets the per-target gauges from the state of the targets' last finished mirrors. The caller holds
// laneMu.
func (e *Engine) publishTargets() {
	e.metrics.reachable.Reset()
	e.metrics.held.Reset()
	e.metrics.lastSuccess.Reset()
	for kind, k := range e.repoKinds {
		e.metrics.lastSuccess.WithLabelValues(kind, RepoTarget).Set(unix(k.at))
	}
	for _, t := range e.enabled {
		e.metrics.held.WithLabelValues(t.Name).Set(float64(e.held[t.ID]))
		if ok, seen := e.reachable[t.ID]; seen {
			v := 0.0
			if ok {
				v = 1
			}
			e.metrics.reachable.WithLabelValues(t.Name).Set(v)
		}
		for kind, at := range e.mirrored[t.Name] {
			e.metrics.lastSuccess.WithLabelValues(kind, t.Name).Set(unix(at))
		}
	}
}

// pinned returns the indexes of the lanes in flight, whose files the local expire keeps.
func (e *Engine) pinned() []repoIndex {
	e.laneMu.Lock()
	defer e.laneMu.Unlock()
	pins := make([]repoIndex, 0, len(e.lanes))
	for _, l := range e.lanes {
		pins = append(pins, l.idx)
	}
	return pins
}

// waitLanes returns once every lane returned.
func (e *Engine) waitLanes() {
	e.laneWG.Wait()
}

// forgetPasses drops every open pass and every lane slot once no lane runs: their runs are still without mirror
// results in the database, and the next leadership's first pass covers them; a slot left by a lane that ended with the
// leadership belongs to no running lane and would keep its target and its pinned files forever.
func (e *Engine) forgetPasses() {
	e.laneMu.Lock()
	defer e.laneMu.Unlock()
	e.passes, e.waiting, e.lanes = nil, map[uuid.UUID][]*mirrorPass{}, map[uuid.UUID]*lane{}
}

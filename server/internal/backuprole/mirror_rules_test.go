package backuprole

import (
	"context"
	"os"
	"time"
)

// rules are the retention inputs of one mirror round in the test matrix (plan M15, amendment 2026-11-05, A1).
type rules struct {
	now time.Time
	// full is retention_full; keep is retention_full × full_interval; kindKeep the keep days of OpenBao and Fleet.
	full     int
	keep     time.Duration
	kindKeep time.Duration
	// retired maps a retired key's repository path to its retired_at; known lists the other paths the database knows.
	retired map[string]time.Time
	known   []string
	// walOK lists "<repository path>/<stanza>" whose local archive is contiguous and verified.
	walOK []string
	// escrow lists the set paths of this round's successful escrow listing; listed is false without a listing.
	escrow []string
	listed bool
	// destroyed maps "<org>/<device>" to its Destroy evidence time; suspicious marks a suspicious listing.
	destroyed  map[string]time.Time
	suspicious bool
	// copied maps a header's set path to the escrow object time the local set's index recorded for its copy.
	copied map[string]time.Time
	// noManifest marks a round whose local manifest could not be written.
	noManifest bool
}

// defaultRules: retention_full 2, a full backup a day, 30 keep days, at matrixNow.
func defaultRules() rules {
	return rules{now: matrixNow, full: 2, keep: 2 * 24 * time.Hour, kindKeep: 30 * 24 * time.Hour,
		retired: map[string]time.Time{}}
}

func (r rules) retention() retention {
	ret := retention{active: pathA, retired: map[string]time.Time{}, known: map[string]bool{pathA: true},
		full: r.full, keep: r.keep, kindKeep: map[string]time.Duration{"openbao/": r.kindKeep, "fleet/": r.kindKeep},
		walOK: map[string]bool{}, manifestOK: !r.noManifest, now: r.now}
	for p, at := range r.retired {
		ret.retired[p], ret.known[p] = at, true
	}
	for _, p := range r.known {
		ret.known[p] = true
	}
	for _, k := range r.walOK {
		ret.walOK[k] = true
	}
	if r.listed {
		ret.escrow = escrowRule{listed: map[string]bool{}, destroyed: r.destroyed, suspicious: r.suspicious,
			copied: r.copied}
		for _, p := range r.escrow {
			ret.escrow.listed[p] = true
		}
	}
	return ret
}

// runMirror runs one mirror round of the set in repo to dst under r and returns the held count.
func runMirror(repo *os.Root, idx repoIndex, dst Target, r rules) (int, error) {
	return mirrorSet(context.Background(), repo, idx, dst, map[string]fileInfo{}, r.retention(), noHooks())
}

// heldKnown reports whether runMirror returns a real held count (the probe of the pre-amendment code does not).
const heldKnown = true

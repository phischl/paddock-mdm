package backuprole

import (
	"os"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// suspiciousShare is the share of the local set's headers that may be missing from the bucket listing without
// evidence before the listing counts as suspicious: more than one in ten (decisions-alpha9 items 27 and 29).
const suspiciousShare = 10

// escrowRule decides which escrowed LUKS header copies may leave the local set and the targets (plan M15, amendment
// 2026-11-05, A2 notes 2026-11-05 b and c). Absence from the bucket listing never deletes on its own: a copy goes only
// when the listing of this round succeeded and was not suspicious, the bucket lacks the header, and the database holds
// audited evidence that its device's escrow was destroyed on purpose (device.escrow_destroyed) that is older than the
// keep window and covers this copy: the escrow object's own time recorded in the local set's index is at or before
// the evidence. The zero value deletes nothing.
type escrowRule struct {
	// listed holds the set path of every header of this round's successful bucket listing; nil without one.
	listed map[string]bool
	// destroyed maps "<org>/<device>" to the time of the device's newest successful Destroy.
	destroyed map[string]time.Time
	// copied maps the set path of a header copy the local set held at the start of the round, or copied in it, to
	// the escrow object's time (LastModified) at copy time; a copy without a recorded time is never evidenced.
	copied map[string]time.Time
	// suspicious is true when the listing lacks, without evidence, all or more than a tenth of the local headers.
	suspicious bool
}

// gone reports whether the header copy at set path p may be deleted at now with keep window keep.
func (r escrowRule) gone(p string, now time.Time, keep time.Duration) bool {
	if r.listed == nil || r.suspicious || r.listed[p] {
		return false
	}
	at, ok := r.evidence(p)
	return ok && now.Sub(at) > keep
}

// evidence returns the time of the Destroy that covers the header copy at set path p. A Destroy covers only copies
// whose escrow object existed at or before it: a generation escrowed after it (a device that had not yet executed
// its Destroy token) is unevidenced, as is a copy without a recorded time (decisions-alpha9 item 31).
func (r escrowRule) evidence(p string) (time.Time, bool) {
	at, ok := r.destroyed[escrowDevice(p)]
	copied, known := r.copied[p]
	if !ok || !known || copied.After(at) {
		return time.Time{}, false
	}
	return at, true
}

// recordedEscrowTimes returns the escrow object time the set's manifest recorded for each header copy the local set
// still holds with the recorded size. A manifest that is missing, unreadable or older than the recorded time yields
// none: such a copy is unevidenced and held.
func recordedEscrowTimes(repo *os.Root, idx repoIndex) map[string]time.Time {
	out := map[string]time.Time{}
	b, err := repo.ReadFile(backupset.ManifestPath)
	if err != nil {
		return out
	}
	m, err := backupset.Parse(b)
	if err != nil {
		return out
	}
	for _, f := range m.Contents.Escrow {
		if fi, ok := idx[f.Path]; ok && fi.size == f.Bytes && !f.At.IsZero() {
			out[f.Path] = f.At.UTC()
		}
	}
	return out
}

// escrowDevice returns "<org>/<device>" of the escrowed header at set path p, empty for any other path.
func escrowDevice(p string) string {
	key, ok := strings.CutPrefix(p, backupset.EscrowKey(""))
	if !ok || !backupset.EscrowHeader(key) {
		return ""
	}
	el := strings.Split(key, "/")
	return el[1] + "/" + el[3]
}

// unevidenced returns the headers of local (set paths) the listing lacks and no Destroy evidence covers, sorted.
func (r escrowRule) unevidenced(local []string) []string {
	var out []string
	for _, p := range local {
		if r.listed[p] {
			continue
		}
		if _, ok := r.evidence(p); !ok {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// suspicious reports whether missing unevidenced headers of total local ones make a listing suspicious: all of them,
// or more than a tenth.
func suspicious(missing, total int) bool {
	return missing > 0 && (missing == total || missing*suspiciousShare > total)
}

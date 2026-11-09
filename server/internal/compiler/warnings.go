package compiler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// Compile warning codes (architect decisions A10-9 and A10-10): stable English identifiers the portal localizes. They
// name what the compiler shortened or dropped from a device's bundle against what an administrator assigned.
const (
	// WarningAudienceTruncated: the audience of an available package named more users than a bundle carries; the
	// first bundle.MaxSoftwareAudience by user name keep it (plan M13b Q13).
	WarningAudienceTruncated = "audience_truncated"
	// WarningFlatpakForbidden: an APT entry forbids or uninstalls flatpak on the device, so its required or available
	// Flatpak application is left out (A10-9).
	WarningFlatpakForbidden = "flatpak_forbidden"
)

// maxDeviceWarnings bounds the warnings one compile stores for a device, so a catalog with many assignments cannot
// grow the table without limit; the rest are logged only.
const maxDeviceWarnings = 100

// compileWarning is one warning of a device's compile, for the assignment and catalog entry it concerns (both invalid
// when it concerns the device only). params hold its values; never user names.
type compileWarning struct {
	code       string
	assignment uuid.NullUUID
	entry      uuid.NullUUID
	params     map[string]any
}

// assignmentWarnings returns one warning with code and params for each assignment in assignments.
func assignmentWarnings(assignments []pgstore.SoftwareAssignment, code string, params map[string]any) []compileWarning {
	out := make([]compileWarning, 0, len(assignments))
	for _, a := range assignments {
		out = append(out, compileWarning{code: code, assignment: uuid.NullUUID{UUID: a.ID, Valid: true},
			entry: uuid.NullUUID{UUID: a.CatalogEntryID, Valid: true}, params: params})
	}
	return out
}

// deviceWarnings are the compile warnings of a device with the bundle seq they belong to: the seq the compile saw
// when the device was unchanged, the seq it committed when it published a bundle.
type deviceWarnings struct {
	seq      int64
	warnings []compileWarning
}

// recordWarnings replaces the stored warnings of every device in warnings with those of its latest compile, so the
// table holds the current state only. A device missing from warnings keeps its rows: its bundle was blocked or not
// published, and the device keeps its previous bundle with its warnings. A device whose bundle_seq moved on since the
// compile keeps its rows too: a concurrent compile published a newer bundle and owns its warnings, which an outdated
// compile must neither overwrite nor delete.
func (c *Compiler) recordWarnings(ctx context.Context, org uuid.UUID, warnings map[uuid.UUID]deviceWarnings) error {
	if len(warnings) == 0 {
		return nil
	}
	return c.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		// Row locks in id order, the order recordPlatform's ORDER BY d.id takes them, so two compiles cannot deadlock.
		devices := slices.SortedFunc(maps.Keys(warnings), func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
		for _, device := range devices {
			dw := warnings[device]
			seq, err := q.LockDeviceBundleSeq(ctx, device)
			if db.IsNoRows(err) || (err == nil && seq != dw.seq) {
				continue
			}
			if err != nil {
				return fmt.Errorf("lock device bundle seq: %w", err)
			}
			if err := q.DeleteCompileWarnings(ctx, device); err != nil {
				return fmt.Errorf("delete compile warnings: %w", err)
			}
			ws := dw.warnings
			if len(ws) > maxDeviceWarnings {
				slog.WarnContext(ctx, "compile warnings of a device beyond the stored limit are logged only", "device_id", device,
					"warnings", len(ws), "stored", maxDeviceWarnings)
				ws = ws[:maxDeviceWarnings]
			}
			for _, w := range ws {
				params, err := json.Marshal(w.params)
				if err != nil {
					return fmt.Errorf("encode compile warning params: %w", err)
				}
				if err := q.InsertCompileWarning(ctx, pgstore.InsertCompileWarningParams{OrganizationID: org, DeviceID: device,
					AssignmentID: w.assignment, CatalogEntryID: w.entry, Code: w.code, Params: params}); err != nil {
					return fmt.Errorf("insert compile warning: %w", err)
				}
			}
		}
		return nil
	})
}

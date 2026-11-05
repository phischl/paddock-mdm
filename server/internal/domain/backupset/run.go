package backupset

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxRunLabelChars bounds the label of a requested run (the CHECK of backup_run.label).
const MaxRunLabelChars = 64

// RunTarget is the mirror result of one run on one target: an element of backup_run.targets, written by the backup
// role and read by the api.
type RunTarget struct {
	TargetID   string `json:"target_id"`
	OK         bool   `json:"ok"`
	ErrorClass string `json:"error_class,omitempty"`
	// Held counts the objects the target keeps although the local set lacks them, because the local expire would not
	// have removed them yet (plan M15, amendment 2026-11-05, A1); a hold is never an error.
	Held int `json:"held,omitempty"`
}

// ParseRunTargets decodes backup_run.targets.
func ParseRunTargets(raw []byte) ([]RunTarget, error) {
	out := []RunTarget{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("backupset: run targets: %w", err)
	}
	return out, nil
}

// ValidRunLabel reports whether label fits backup_run.label and holds no control characters (it is shown in the
// portal and printed by ./paddock backup status).
func ValidRunLabel(label string) bool {
	return utf8.ValidString(label) && utf8.RuneCountInString(label) <= MaxRunLabelChars &&
		!strings.ContainsFunc(label, unicode.IsControl)
}

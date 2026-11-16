// Package offboarding names the steps of an organization's deletion and their error codes (plan M17 decisions 6 and
// 19, §6; ADR 0052 decision 3).
package offboarding

// The steps of an organization's deletion, stored in organization.offboarding_step.
const (
	StepSessions   = "sessions"
	StepDevices    = "devices"
	StepOutbox     = "outbox"
	StepAuthentik  = "authentik"
	StepFleet      = "fleet"
	StepObjects    = "objects"
	StepValkey     = "valkey"
	StepAuditFinal = "audit_final"
	StepDatabase   = "database"
	StepTombstone  = "tombstone"
)

// Steps is the order in which the job runs the steps (plan M17 decision 6): the sessions end first, so nobody acts
// on the organization while it is deleted; the outbox is drained before anything that the audit trail of the
// organization still describes is gone; the database goes after every store that is found through its rows.
func Steps() []string {
	return []string{StepSessions, StepDevices, StepOutbox, StepAuthentik, StepFleet, StepObjects, StepValkey,
		StepAuditFinal, StepDatabase, StepTombstone}
}

// Next returns the step after step; ok is false for the last step and for a name that is no step.
func Next(step string) (next string, ok bool) {
	steps := Steps()
	for i, s := range steps[:len(steps)-1] {
		if s == step {
			return steps[i+1], true
		}
	}
	return "", false
}

// The error codes a failed step stores in organization.offboarding_error_code and records as error_code of
// organization.deletion_step_failed (plan M17 §6, amendment 2026-11-15 k addendum point 3, amendment j point 5, main §37).
const (
	ErrorAuthentikUnavailable   = "authentik_unavailable"
	ErrorFleetUnavailable       = "fleet_unavailable"
	ErrorObjectStoreUnavailable = "object_store_unavailable"
	ErrorObjectRetained         = "object_retained"
	ErrorValkeyUnavailable      = "valkey_unavailable"
	ErrorOutboxPending          = "outbox_pending"
	ErrorAuditWriterPending     = "audit_writer_pending"
	ErrorDatabase               = "database_error"
	// ErrorSigningUnavailable: the step devices could not sign the devices' uninstall commands (OpenBao).
	ErrorSigningUnavailable = "signing_unavailable"
	// ErrorFinalizeWaiting: the tombstone has waited longer than FinalizeWaitAlert for organization transactions that
	// were open when the deletion started.
	ErrorFinalizeWaiting = "finalize_waiting"
)

// ErrorCodes is the closed set of step error codes.
func ErrorCodes() []string {
	return []string{ErrorAuthentikUnavailable, ErrorFleetUnavailable, ErrorObjectStoreUnavailable, ErrorObjectRetained,
		ErrorValkeyUnavailable, ErrorOutboxPending, ErrorAuditWriterPending, ErrorDatabase, ErrorSigningUnavailable, ErrorFinalizeWaiting}
}

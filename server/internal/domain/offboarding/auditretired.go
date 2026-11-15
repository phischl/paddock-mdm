package offboarding

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// The outcomes of the final verification of a deleting organization's audit chain (audit_org_retired.final_outcome,
// organization.audit_final_outcome).
const (
	AuditFinalVerified = "verified"
	AuditFinalFailed   = "failed"
)

// AuditRetired is the audit writer's acknowledgement that it verified a deleting organization's audit chain for the
// last time and closed its log (plan M17 amendment 2026-11-15 o point 5). It travels on paddock.offboarding, is no
// audit event and carries no personal data.
type AuditRetired struct {
	OrganizationID  uuid.UUID `json:"organization_id"`
	FinalOutcome    string    `json:"final_outcome"`
	FinalVerifiedAt time.Time `json:"final_verified_at"`
}

// Validate refuses an acknowledgement without organization, with an unknown outcome or without time.
func (a AuditRetired) Validate() error {
	switch {
	case a.OrganizationID == uuid.Nil:
		return errors.New("offboarding: acknowledgement without organization_id")
	case a.FinalOutcome != AuditFinalVerified && a.FinalOutcome != AuditFinalFailed:
		return errors.New("offboarding: acknowledgement with an unknown final_outcome")
	case a.FinalVerifiedAt.IsZero():
		return errors.New("offboarding: acknowledgement without final_verified_at")
	}
	return nil
}

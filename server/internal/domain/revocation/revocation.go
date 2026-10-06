// Package revocation holds the server-side rules of Lock, Destroy and the self-lock of the dead man's switch
// (architecture §12.3, ADR 0014, plan M4c decisions 5, 7 and 8): request states, the approvals an action needs, the
// limits the revocation-issuer enforces, and the revocation.approved message that hands an approved request to the
// issuer. The signed token is in pkg/revocation.
package revocation

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/revocation"
)

// Actions (the token's action).
const (
	ActionLock     = revocation.ActionLock
	ActionDestroy  = revocation.ActionDestroy
	ActionSelfLock = revocation.ActionSelfLock
)

// Actions are all actions.
var Actions = []string{ActionLock, ActionDestroy, ActionSelfLock}

// States of a request.
const (
	StatusRequested = "requested" // a Destroy waits for its second approval
	StatusApproved  = "approved"  // handed to the issuer
	StatusIssued    = "issued"    // signed and in cmd:<device_id>
	StatusDelivered = "delivered" // the device fetched it
	StatusConfirmed = "confirmed" // the device confirmed the erasure
	StatusFailed    = "failed"
	StatusRejected  = "rejected" // by an administrator or the issuer
	StatusCancelled = "cancelled"
	StatusExpired   = "expired"
)

// Statuses are all states, in lifecycle order.
var Statuses = []string{StatusRequested, StatusApproved, StatusIssued, StatusDelivered, StatusConfirmed, StatusFailed,
	StatusRejected, StatusCancelled, StatusExpired}

// Final reports whether status is a final state.
func Final(status string) bool {
	switch status {
	case StatusConfirmed, StatusFailed, StatusRejected, StatusCancelled, StatusExpired:
		return true
	}
	return false
}

// Approval roles.
const (
	RoleRequester = "requester"
	RoleApprover  = "approver"
)

// Approvals is the number of approvals an action needs before issuance: Destroy needs a second administrator with
// a different subject (two-person rule), Lock only the requester, a self-lock none.
func Approvals(action string) int {
	switch action {
	case ActionDestroy:
		return 2
	case ActionLock:
		return 1
	}
	return 0
}

// MaxReasonLength bounds the reason of a request in characters.
const MaxReasonLength = 500

// ValidReason reports whether a reason is valid UTF-8 of at most MaxReasonLength characters.
func ValidReason(reason string) bool {
	return utf8.ValidString(reason) && utf8.RuneCountInString(reason) <= MaxReasonLength
}

// Limits of ADR 0014, enforced by the issuer over sliding windows of issued Lock and Destroy requests.
const (
	AdminPerHour = 3
	AdminPerDay  = 10
	OrgPerDay    = 20
	// FreezeDuration is how long an administrator who exceeded a limit cannot have revocations issued.
	FreezeDuration = 24 * time.Hour
)

// Rejection reasons of the issuer (revocation_request.rejection, audit param reason).
const (
	RejectedAdminHour     = "limit_admin_hour"
	RejectedAdminDay      = "limit_admin_day"
	RejectedOrgDay        = "limit_organization_day"
	RejectedFrozen        = "admin_frozen"
	RejectedStepUp        = "stepup_invalid"    // signature, iss, aud, auth_time, MFA, subject or reuse
	RejectedApprovals     = "approvals_invalid" // missing approvals or not two distinct administrators and subjects
	RejectedNotAdmin      = "not_org_admin"
	RejectedDisabled      = "revocation_disabled"
	RejectedDeviceRetired = "device_unavailable"
)

// Counts are the issued Lock and Destroy requests the limits look at.
type Counts struct {
	AdminLastHour, AdminLastDay, OrgLastDay int
}

// LimitExceeded returns the rejection reason when one more request would exceed a limit, "" otherwise.
func LimitExceeded(c Counts) string {
	switch {
	case c.AdminLastHour >= AdminPerHour:
		return RejectedAdminHour
	case c.AdminLastDay >= AdminPerDay:
		return RejectedAdminDay
	case c.OrgLastDay >= OrgPerDay:
		return RejectedOrgDay
	}
	return ""
}

// Approved is the payload of the outbox message revocation.<organization_id>: the issuer verifies and issues the
// request (plan M4c decision 8).
type Approved struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	RequestID      uuid.UUID `json:"request_id"`
}

const subjectPrefix = "revocation."

// Subject is the outbox subject of a revocation.approved message of org.
func Subject(org uuid.UUID) string { return subjectPrefix + org.String() }

// ParseSubject returns the organization of a revocation.approved subject.
func ParseSubject(subject string) (uuid.UUID, bool) {
	rest, ok := strings.CutPrefix(subject, subjectPrefix)
	if !ok {
		return uuid.Nil, false
	}
	org, err := uuid.Parse(rest)
	return org, err == nil
}

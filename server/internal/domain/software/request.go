package software

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// The approval of a catalog entry (plan M13c decision 8): none lets every user of an available entry's audience install
// it; required makes them ask first.
const (
	ApprovalNone     = "none"
	ApprovalRequired = "required"
)

// The states of a software request (plan M13c §3.7 "Request"): requested → approved | denied | withdrawn | expired.
const (
	RequestRequested = "requested"
	RequestApproved  = "approved"
	RequestDenied    = "denied"
	RequestExpired   = "expired"
	RequestWithdrawn = "withdrawn"
)

// RequestStates are the states of a software request, in their order of the state table.
var RequestStates = []string{RequestRequested, RequestApproved, RequestDenied, RequestExpired, RequestWithdrawn}

// Why the worker expired a request: its validity ended, its entry no longer requires approval (§3.8 L4), or its
// entry has no available assignment left, so an approval no longer holds either (architect decision A10-17).
const (
	ExpiryValidityEnded     = "validity_ended"
	ExpiryApprovalRemoved   = "approval_removed"
	ExpiryAssignmentRemoved = "assignment_removed"
)

const (
	// RequestValidity is how long a request stays open without a decision (plan M13c decision 9).
	RequestValidity = 30 * 24 * time.Hour
	// RerequestAfterDenial is how long after a denial the same user may ask again on the same device (§3.7).
	RerequestAfterDenial = 24 * time.Hour
	// MaxRequestUsername is the limit of a request's user name, the one of app_user.username.
	MaxRequestUsername = 256
)

// ErrRequest is the validation error of a software request decision, answered with 400 invalid_request.
var ErrRequest = errors.New("invalid software request decision")

// ValidApproval reports whether a is an approval value of a catalog entry.
func ValidApproval(a string) bool { return a == ApprovalNone || a == ApprovalRequired }

// NormalizeDecisionReason trims a decision's reason.
func NormalizeDecisionReason(reason string) string { return strings.TrimSpace(reason) }

// ValidateDecisionReason checks the reason of an approval or a denial: at most MaxReasonLength characters of text
// without control, format or invisible characters (line breaks allowed), and not empty when required (a denial).
func ValidateDecisionReason(reason string, required bool) error {
	if required && reason == "" {
		return fmt.Errorf("%w: a denial needs a reason", ErrRequest)
	}
	return validateFreeText("reason", reason, MaxReasonLength, true, ErrRequest)
}

// ValidRequestUsername reports whether a device's request can name user name u: 1 to MaxRequestUsername characters of
// valid UTF-8, lower case, without white space or control characters — the user names an audience carries.
func ValidRequestUsername(u string) bool {
	return u != "" && utf8.ValidString(u) && utf8.RuneCountInString(u) <= MaxRequestUsername && u == strings.ToLower(u) &&
		!strings.ContainsFunc(u, func(r rune) bool { return invisibleInName(r) || r == ' ' || r == '\t' || r == '\n' })
}

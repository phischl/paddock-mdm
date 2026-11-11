package software

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
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

// Why the worker expired a request: its validity ended, its entry no longer requires approval or changed its approval
// since the request was opened (§3.8 L4), or no available assignment of its entry offers it to the device and user any
// longer, so an approval no longer holds either (architect decision A10-17).
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
// without control, format or invisible characters (line breaks allowed, tabs not), and not empty when required (a
// denial). A denial's reason reaches the user's device in the bundle (architect decision A10-27), so it is held to the
// rule of untrusted text the justification follows (maintainer answer Q7).
func ValidateDecisionReason(reason string, required bool) error {
	if required && reason == "" {
		return fmt.Errorf("%w: a denial needs a reason", ErrRequest)
	}
	if strings.ContainsRune(reason, '\t') {
		return fmt.Errorf("%w: reason must not contain control, format or invisible characters", ErrRequest)
	}
	return validateFreeText("reason", reason, MaxReasonLength, true, ErrRequest)
}

// MaxJustificationLength is the limit of a request's justification in characters (maintainer answer Q7).
const MaxJustificationLength = 500

// ValidJustification reports whether a device's request can carry justification j (maintainer answer Q7): valid
// UTF-8 of at most MaxJustificationLength characters without control characters except line breaks. It is the rule
// the agent applies before it sends the request, so a request a conforming agent sends is never refused for its text.
// Unlike names and reasons, format characters stay allowed: the user types the text, and emoji sequences need them.
func ValidJustification(j string) bool {
	return utf8.ValidString(j) && utf8.RuneCountInString(j) <= MaxJustificationLength &&
		!strings.ContainsFunc(j, func(r rune) bool { return r != '\n' && unicode.Is(unicode.Cc, r) })
}

// ValidRequestUsername reports whether a device's request can name user name u: 1 to MaxRequestUsername characters of
// valid UTF-8, lower case, without white space or control characters — the user names an audience carries.
func ValidRequestUsername(u string) bool {
	return u != "" && utf8.ValidString(u) && utf8.RuneCountInString(u) <= MaxRequestUsername && u == strings.ToLower(u) &&
		!strings.ContainsFunc(u, func(r rune) bool { return invisibleInName(r) || r == ' ' || r == '\t' || r == '\n' })
}

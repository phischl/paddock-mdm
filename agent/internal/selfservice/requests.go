package selfservice

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Limits of software requests (plan M13c decision 9, maintainer answer Q7).
const (
	// MaxJustification bounds the justification of a request in characters (software_request.justification).
	MaxJustification = 500
	// RequestValidity is how long a request stays pending on the device: the server expires it after the same time
	// (software_request.expires_at), and no bundle tells the device so.
	RequestValidity = 30 * 24 * time.Hour
	// RequestsPerHour bounds the requests of one UID per hour: every request is an event, and a user who withdraws and
	// asks again in a loop must not flood the event spool.
	RequestsPerHour = 10
)

// Request states of RequestView.
const (
	RequestRequested = "requested"
	RequestDenied    = "denied"
)

// Codes of the request endpoints' problems.
const (
	CodeNotRequired      = "not_required"
	CodeAlreadyRequested = "already_requested"
	CodeApprovalRequired = "approval_required"
	CodeInvalidRequest   = "invalid_request"
)

// PendingRequest is a request the user made on this device that the bundle does not reflect yet: neither an approval
// nor a denial of it has arrived. It is kept in StateFile so that it survives a restart.
type PendingRequest struct {
	EntryID     string    `json:"entry_id"`
	Username    string    `json:"username"`
	RequestedAt time.Time `json:"requested_at"`
}

// RequestView is the request state of an application that requires approval, as the caller sees it.
type RequestView struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// requestBody is the body of POST /v1/apps/{id}/request.
type requestBody struct {
	Justification string `json:"justification"`
}

// Requests delivers the software.request events; the run loop spools them.
func (s *Service) Requests() <-chan protocol.SoftwareRequest { return s.requests }

// approvedFor reports whether p may install pkg without asking: it requires no approval, or the bundle lists p's UPN
// as approved.
func approvedFor(pkg bundle.SoftwarePackage, p Principal) bool {
	return pkg.Approval != bundle.SoftwareApprovalRequired || p.UPN != "" && pkg.Approved != nil && slices.Contains(*pkg.Approved, p.UPN)
}

// deniedFor returns the reason of p's denied request of pkg, as display text, and whether there is one. Only p's own
// entry is ever read, so p learns nothing about other users' requests.
func deniedFor(pkg bundle.SoftwarePackage, p Principal) (string, bool) {
	if p.UPN == "" || pkg.Approval != bundle.SoftwareApprovalRequired || pkg.Denied == nil {
		return "", false
	}
	i := slices.IndexFunc(*pkg.Denied, func(d bundle.SoftwareDenial) bool { return d.User == p.UPN })
	if i < 0 {
		return "", false
	}
	return displayReason((*pkg.Denied)[i].Reason), true
}

// displayReason makes an administrator's reason safe to show: control and format characters (bidi overrides
// included) are removed except newlines, and the text is cut at bundle.MaxSoftwareDenialReason characters. The
// signed bundle checks the length already; the reason is still untrusted text (maintainer answer Q7, A10-27).
func displayReason(reason string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.ToValidUTF8(reason, "") {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			continue
		}
		if n == bundle.MaxSoftwareDenialReason {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// validJustification reports whether a justification is plain text the server accepts: valid UTF-8 of at most
// MaxJustification characters without control characters except newlines (maintainer answer Q7).
func validJustification(text string) bool {
	return utf8.ValidString(text) && utf8.RuneCountInString(text) <= MaxJustification &&
		!strings.ContainsFunc(text, func(r rune) bool { return r != '\n' && unicode.IsControl(r) })
}

// parseRequestBody reads the body of POST /v1/apps/{id}/request; an empty body is a request without justification.
func parseRequestBody(r *http.Request) (string, error) {
	invalid := &Problem{Status: http.StatusBadRequest, Code: CodeInvalidRequest,
		Detail: "the justification must be plain text of at most 500 characters"}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return "", invalid
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return "", nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var body requestBody
	// encoding/json replaces invalid UTF-8 silently; the text must reach the server as the user typed it or not at all.
	if !utf8.Valid(data) || dec.Decode(&body) != nil || dec.More() || !validJustification(body.Justification) {
		return "", invalid
	}
	return strings.TrimSpace(body.Justification), nil
}

// pendingIndex returns the index of p's pending request of entryID that is still valid at now, -1 when there is none.
// Called with mu held.
func (s *Service) pendingIndex(entryID string, p Principal, now time.Time) int {
	if p.UPN == "" {
		return -1
	}
	return slices.IndexFunc(s.record.Requests, func(r PendingRequest) bool {
		return r.EntryID == entryID && r.Username == p.UPN && now.Sub(r.RequestedAt) < RequestValidity
	})
}

// Request asks an administrator to approve entryID for p (plan M13c decision 9): the entry must be one p may see that
// requires approval p does not have, with no pending request or denial of p. The request is kept until the bundle
// reflects a decision and reported once as software.request. The justification is never logged.
func (s *Service) Request(p Principal, entryID, justification string) (AppView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.snap.applied {
		return AppView{}, errNoBundle
	}
	pkg, ok := find(s.snap.spec, entryID, p)
	if !ok {
		return AppView{}, &Problem{Status: http.StatusNotFound, Code: CodeUnknownEntry, Detail: "no such application"}
	}
	now := s.cfg.Now()
	switch {
	case managed(pkg):
		return AppView{}, &Problem{Status: http.StatusForbidden, Code: protocol.SelfServiceRequiredByPolicy,
			Detail: "the application is managed by your organization"}
	case approvedFor(pkg, p):
		return AppView{}, &Problem{Status: http.StatusConflict, Code: CodeNotRequired, Detail: "the application needs no approval"}
	case p.UPN == "":
		// Approvals name directory users; a local account can never be approved.
		return AppView{}, &Problem{Status: http.StatusForbidden, Code: protocol.SelfServiceNotInAudience,
			Detail: "only directory users can ask for approval"}
	case s.pendingIndex(pkg.CatalogEntryID, p, now) >= 0:
		return AppView{}, &Problem{Status: http.StatusConflict, Code: CodeAlreadyRequested, Detail: "the application is requested already"}
	}
	if _, denied := deniedFor(pkg, p); denied {
		return AppView{}, &Problem{Status: http.StatusConflict, Code: RequestDenied, Detail: "the request was denied"}
	}
	if !s.requestAllowed(p.UID, now) {
		return AppView{}, &Problem{Status: http.StatusTooManyRequests, Code: CodeBusy, Detail: "too many requests"}
	}
	ev := protocol.SoftwareRequest{User: p.UPN, EntryID: pkg.CatalogEntryID, Justification: justification}
	// ADR 0024: only a server that renders a package requiring approval knows software.request, and pkg is one.
	select {
	case s.requests <- ev:
	default:
		return AppView{}, &Problem{Status: http.StatusTooManyRequests, Code: CodeBusy, Detail: "too many requests are waiting"}
	}
	s.record.Requests = append(s.record.Requests, PendingRequest{EntryID: pkg.CatalogEntryID, Username: p.UPN, RequestedAt: now.UTC()})
	if err := saveRecord(s.cfg.Sys, s.record); err != nil {
		slog.Error("writing the self-service record failed", "error", err)
	}
	return s.view(pkg, p), nil
}

// Withdraw clears p's pending request of entryID. The server learns nothing of it: its request ends with a decision
// or its expiry, and a new request on the device is only reported again (plan M13c amendment for PDK-810).
func (s *Service) Withdraw(p Principal, entryID string) (AppView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.snap.applied {
		return AppView{}, errNoBundle
	}
	pkg, ok := find(s.snap.spec, entryID, p)
	if !ok {
		return AppView{}, &Problem{Status: http.StatusNotFound, Code: CodeUnknownEntry, Detail: "no such application"}
	}
	i := s.pendingIndex(pkg.CatalogEntryID, p, s.cfg.Now())
	if i < 0 {
		return AppView{}, &Problem{Status: http.StatusNotFound, Code: CodeNotFound, Detail: "no pending request"}
	}
	s.record.Requests = slices.Delete(s.record.Requests, i, i+1)
	if err := saveRecord(s.cfg.Sys, s.record); err != nil {
		slog.Error("writing the self-service record failed", "error", err)
	}
	return s.view(pkg, p), nil
}

// requestAllowed counts a request of uid at now against RequestsPerHour. Called with mu held.
func (s *Service) requestAllowed(uid int, now time.Time) bool {
	recent := slices.DeleteFunc(s.asked[uid], func(t time.Time) bool { return now.Sub(t) >= time.Hour })
	if len(recent) >= RequestsPerHour {
		s.asked[uid] = recent
		return false
	}
	s.asked[uid] = append(recent, now)
	return true
}

// pruneRequests drops the pending requests the bundle reflects or that ended: the user is approved or denied, the
// entry no longer requires approval or is no longer offered to the user, or the request is older than
// RequestValidity. It reports whether any was dropped.
func pruneRequests(requests []PendingRequest, sp bundle.SoftwareSpec, now time.Time) ([]PendingRequest, bool) {
	kept := slices.DeleteFunc(slices.Clone(requests), func(r PendingRequest) bool {
		if now.Sub(r.RequestedAt) >= RequestValidity {
			return true
		}
		p := Principal{UPN: r.Username}
		i := slices.IndexFunc(sp.Packages, func(pkg bundle.SoftwarePackage) bool {
			return pkg.CatalogEntryID == r.EntryID && inAudience(pkg, p)
		})
		if i < 0 {
			return true
		}
		_, denied := deniedFor(sp.Packages[i], p)
		return approvedFor(sp.Packages[i], p) || denied
	})
	return kept, len(kept) != len(requests)
}

// requestView sets the approval fields of v, the view of pkg for p. Called with mu held.
func (s *Service) requestView(v *AppView, pkg bundle.SoftwarePackage, p Principal, installed, pending bool) {
	if v.Managed || pkg.Approval != bundle.SoftwareApprovalRequired {
		return
	}
	v.Approval = pkg.Approval
	if approvedFor(pkg, p) {
		return
	}
	v.Installable = false
	if reason, denied := deniedFor(pkg, p); denied {
		v.Request = &RequestView{State: RequestDenied, Reason: reason}
	} else if s.pendingIndex(pkg.CatalogEntryID, p, s.cfg.Now()) >= 0 {
		v.Request = &RequestView{State: RequestRequested}
	}
	v.Requestable = p.UPN != "" && !installed && !pending && v.Request == nil
}

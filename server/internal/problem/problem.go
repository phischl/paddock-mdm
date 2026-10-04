// Package problem defines the error codes of the admin API (RFC 9457 problem details, plan M0 §6.6).
// Use cases return *problem.Error; transport maps it to a response, the ActionRunner to an audit error_code.
package problem

import (
	"context"
	"errors"
	"net/http"
)

// Error is an API error with a stable code.
type Error struct {
	Code   string
	Status int
	Detail string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Code + ": " + e.Detail
	}
	return e.Code
}

// Is matches by code, so errors.Is(err, problem.Forbidden) holds for every forbidden error.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// WithDetail returns a copy with a detail message.
func (e *Error) WithDetail(detail string) *Error {
	c := *e
	c.Detail = detail
	return &c
}

// Problem codes of M0, M0.2 and M2a.
var (
	InvalidRequest      = &Error{Code: "invalid_request", Status: http.StatusBadRequest}
	RangeTooLarge       = &Error{Code: "range_too_large", Status: http.StatusBadRequest}
	PageOutOfRange      = &Error{Code: "page_out_of_range", Status: http.StatusBadRequest}
	Unauthenticated     = &Error{Code: "unauthenticated", Status: http.StatusUnauthorized}
	Forbidden           = &Error{Code: "forbidden", Status: http.StatusForbidden}
	NoOrganization      = &Error{Code: "no_organization", Status: http.StatusForbidden}
	CSRFMissing         = &Error{Code: "csrf_missing", Status: http.StatusForbidden}
	NotFound            = &Error{Code: "not_found", Status: http.StatusNotFound}
	NameTaken           = &Error{Code: "name_taken", Status: http.StatusConflict}
	SlugTaken           = &Error{Code: "slug_taken", Status: http.StatusConflict}
	UpstreamUnavailable = &Error{Code: "upstream_unavailable", Status: http.StatusBadGateway}
	InvalidState        = &Error{Code: "invalid_state", Status: http.StatusConflict}
	AlreadyExists       = &Error{Code: "already_exists", Status: http.StatusConflict}
	InUse               = &Error{Code: "in_use", Status: http.StatusConflict}
	PathNotAllowed      = &Error{Code: "path_not_allowed", Status: http.StatusUnprocessableEntity}
	UnitNotAllowed      = &Error{Code: "unit_not_allowed", Status: http.StatusUnprocessableEntity}
	// Enrollment rejections recorded by the worker (error_code of device.enrolled); never sent over HTTP.
	InvalidToken   = &Error{Code: "invalid_token", Status: http.StatusUnprocessableEntity}
	TokenRevoked   = &Error{Code: "token_revoked", Status: http.StatusUnprocessableEntity}
	TokenExpired   = &Error{Code: "token_expired", Status: http.StatusUnprocessableEntity}
	TokenExhausted = &Error{Code: "token_exhausted", Status: http.StatusUnprocessableEntity}
	Internal       = &Error{Code: "internal", Status: http.StatusInternalServerError}
)

// From converts any error into a problem: *Error as is, context cancellation as "canceled", anything else internal.
func From(err error) *Error {
	var p *Error
	if errors.As(err, &p) {
		return p
	}
	if errors.Is(err, context.Canceled) {
		return &Error{Code: "canceled", Status: 499}
	}
	return Internal
}

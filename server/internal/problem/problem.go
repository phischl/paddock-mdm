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

// Problem codes of M0, M0.2, M2a and M3a.
var (
	InvalidRequest      = &Error{Code: "invalid_request", Status: http.StatusBadRequest}
	RangeTooLarge       = &Error{Code: "range_too_large", Status: http.StatusBadRequest}
	PageOutOfRange      = &Error{Code: "page_out_of_range", Status: http.StatusBadRequest}
	Unauthenticated     = &Error{Code: "unauthenticated", Status: http.StatusUnauthorized}
	Forbidden           = &Error{Code: "forbidden", Status: http.StatusForbidden}
	NoOrganization      = &Error{Code: "no_organization", Status: http.StatusForbidden}
	CSRFMissing         = &Error{Code: "csrf_missing", Status: http.StatusForbidden}
	StepUpRequired      = &Error{Code: "step_up_required", Status: http.StatusForbidden}
	NotFound            = &Error{Code: "not_found", Status: http.StatusNotFound}
	NameTaken           = &Error{Code: "name_taken", Status: http.StatusConflict}
	SlugTaken           = &Error{Code: "slug_taken", Status: http.StatusConflict}
	UpstreamUnavailable = &Error{Code: "upstream_unavailable", Status: http.StatusBadGateway}
	InvalidState        = &Error{Code: "invalid_state", Status: http.StatusConflict}
	AlreadyExists       = &Error{Code: "already_exists", Status: http.StatusConflict}
	InUse               = &Error{Code: "in_use", Status: http.StatusConflict}
	SettingLocked       = &Error{Code: "setting_locked", Status: http.StatusConflict}
	// Conflict: a unique value is held by another resource of the organization (plan M8h decision 4: a device name).
	Conflict       = &Error{Code: "conflict", Status: http.StatusConflict}
	PathNotAllowed = &Error{Code: "path_not_allowed", Status: http.StatusUnprocessableEntity}
	UnitNotAllowed = &Error{Code: "unit_not_allowed", Status: http.StatusUnprocessableEntity}
	// Update management (plan M5b decisions 1 and 3).
	InvalidSchedule = &Error{Code: "invalid_schedule", Status: http.StatusUnprocessableEntity}
	PackageOnHold   = &Error{Code: "package_on_hold", Status: http.StatusConflict}
	// InvalidDocument: a declarative configuration violates its schema (plan M6c decision 18); the detail lists up to
	// 20 "path: message" pairs.
	InvalidDocument = &Error{Code: "invalid_document", Status: http.StatusUnprocessableEntity}
	// PlanChanged: the plan of PUT /api/v1/config differs from the one the client confirmed (expected_plan); nothing
	// is applied (plan M6c amendment 2026-10-08).
	PlanChanged    = &Error{Code: "plan_changed", Status: http.StatusPreconditionFailed}
	TooManyDevices = &Error{Code: "too_many_devices", Status: http.StatusUnprocessableEntity}
	// Uninstall (plan M8d decision 37): clear_tpm while a volume unlocks with the TPM; and invalid_request with 422 for
	// a request whose values contradict the device or each other (typed hostname, reset-only options with leave).
	TPMInUseByDisk            = &Error{Code: "tpm_in_use_by_disk", Status: http.StatusConflict}
	InvalidRequestUnprocessed = &Error{Code: "invalid_request", Status: http.StatusUnprocessableEntity}
	// ConversionNotCancellable: a cancel of an in-place encryption the device already started (plan M8e decision 8,
	// portal text problems.conversion_not_cancellable).
	ConversionNotCancellable = &Error{Code: "conversion_not_cancellable", Status: http.StatusConflict}
	// TooManyVolumes is the error code of a header escrow for a 33rd distinct volume of a device (PDK-009, review
	// round 1); recorded by the worker, never sent over HTTP.
	TooManyVolumes = &Error{Code: "too_many_volumes", Status: http.StatusConflict}
	// Identity and privileges (plan M3a).
	UsernameTaken          = &Error{Code: "username_taken", Status: http.StatusConflict}
	DomainTaken            = &Error{Code: "domain_taken", Status: http.StatusConflict}
	AttributeOwnedUpstream = &Error{Code: "attribute_owned_upstream", Status: http.StatusConflict}
	InvalidCommand         = &Error{Code: "invalid_command", Status: http.StatusUnprocessableEntity}
	// ReleaseSignatureMismatch: the signed trusted comment of an agent binary names another version or architecture
	// (plan M4b.1 decision 12).
	ReleaseSignatureMismatch = &Error{Code: "release_signature_mismatch", Status: http.StatusUnprocessableEntity}
	// Agent release import (ADR 0043 decision 7): the source is switched off (recorded as denied), the source did not
	// answer or answered outside its bounds, the version is not newer than the newest published release, or the release
	// lacks a required asset or signature.
	ReleaseSourceDisabled    = &Error{Code: "release_source_disabled", Status: http.StatusForbidden}
	ReleaseSourceUnavailable = &Error{Code: "release_source_unavailable", Status: http.StatusBadGateway}
	ReleaseNotNewer          = &Error{Code: "release_not_newer", Status: http.StatusConflict}
	ReleaseIncomplete        = &Error{Code: "release_incomplete", Status: http.StatusUnprocessableEntity}
	// Revocation (plan M4c): the feature flag PADDOCK_REVOCATION_ENABLED is off (decision 1), or the administrator's
	// revocations are frozen after a limit was exceeded (ADR 0014). Both are recorded as denied.
	RevocationDisabled = &Error{Code: "revocation_disabled", Status: http.StatusForbidden}
	RevocationFrozen   = &Error{Code: "revocation_frozen", Status: http.StatusForbidden}
	// RevocationRejected is the error code of a request the revocation-issuer refused (recorded as denied); never
	// sent over HTTP.
	RevocationRejected = &Error{Code: "revocation_rejected", Status: http.StatusForbidden}
	// RenderFailed is the error code of device.bundle_render_failed (compiler); never sent over HTTP.
	RenderFailed = &Error{Code: "render_failed", Status: http.StatusInternalServerError}
	// IP allow list (plan M7a decision 13): the client address is outside the application allow list (recorded as
	// denied); a change needs the caller's explicit confirmation because it would exclude their own address or switch
	// the feature off. IPAllowlistUnavailable refuses every request while the api has not loaded the list yet
	// (fail closed).
	IPNotAllowed                = &Error{Code: "ip_not_allowed", Status: http.StatusForbidden}
	IPAllowlistUnavailable      = &Error{Code: "ip_allowlist_unavailable", Status: http.StatusServiceUnavailable}
	LockoutConfirmationRequired = &Error{Code: "lockout_confirmation_required", Status: http.StatusConflict}
	DisableConfirmationRequired = &Error{Code: "disable_confirmation_required", Status: http.StatusConflict}
	// SessionStoreUnavailable answers every portal session request while the session store cannot be reached; the
	// session fails closed and the cookie is kept (ADR 0034 decision 4). API tokens are not affected.
	SessionStoreUnavailable = &Error{Code: "session_store_unavailable", Status: http.StatusServiceUnavailable}
	// DisclaimerOutdated: the acknowledged disclaimer of the automatic unseal is not the current version (plan M8u
	// decision 6); recorded as failure.
	DisclaimerOutdated = &Error{Code: "disclaimer_outdated", Status: http.StatusConflict}
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

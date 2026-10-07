// Package revocationissuer is the revocation-issuer role (architecture §12.3, ADR 0014, plan M4c decisions 8 and 9):
// the single active consumer of revocation.approved. It verifies every approval's step-up ID token against
// Authentik, the distinct administrators of a Destroy and the limits, deletes the escrow of a Destroy, signs the
// device-bound revocation token with revocation-signing (its AppRole is the only one that can) and puts it into
// cmd:<device_id>. A compromised api or database alone cannot mint a revocation.
package revocationissuer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/revocation"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	domain "github.com/phischl/paddock-mdm/server/internal/domain/revocation"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/revocationsign"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
)

// metricRefused is the alert of refused revocations (ADR 0014: exceeding a limit raises an alert).
var metricRefused = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_revocation_refused_total", Help: "Revocations the issuer refused, by reason; any limit_* is an alert.",
}, []string{"reason"})

// ProofVerifier checks the step-up ID token of an approval at its approval time (stepupproof.Verifier); refusals wrap
// stepupproof.ErrInvalid.
type ProofVerifier interface {
	VerifyApproval(ctx context.Context, raw string, approvedAt time.Time) (stepupproof.Claims, error)
}

// TokenClaims remembers the step-up tokens that proved an approval (JTIClaims): a token proves one request only.
type TokenClaims interface {
	Claim(ctx context.Context, jti string, request uuid.UUID) (bool, error)
}

// Commands is cmd:<device_id> (devicecache.Cache).
type Commands interface {
	PutCommand(ctx context.Context, device, id uuid.UUID, cmd devicecache.Command) error
	HasCommand(ctx context.Context, device, id uuid.UUID) (bool, error)
	DeleteCommand(ctx context.Context, device, id uuid.UUID) error
}

// Shredder deletes every version of the objects below a prefix of the escrow bucket (objectstore.Store).
type Shredder interface {
	DeleteAllVersions(ctx context.Context, prefix string) (int, error)
}

// Issuer verifies, limits and issues approved revocation requests.
type Issuer struct {
	org      *db.OrgPool // role paddock_revocation
	runner   *app.ActionRunner
	proofs   ProofVerifier
	claims   TokenClaims
	signer   revocationsign.Signer
	commands Commands
	escrow   Shredder
	enabled  bool
	now      func() time.Time
	// mu serializes issuance: the consumer and the round never handle a request at the same time.
	mu sync.Mutex
}

// New creates the issuer; enabled is PADDOCK_REVOCATION_ENABLED (when false it refuses to sign).
func New(org *db.OrgPool, runner *app.ActionRunner, proofs ProofVerifier, claims TokenClaims, signer revocationsign.Signer,
	commands Commands, escrow Shredder, enabled bool) *Issuer {
	return &Issuer{org: org, runner: runner, proofs: proofs, claims: claims, signer: signer, commands: commands,
		escrow: escrow, enabled: enabled, now: time.Now}
}

// systemContext is the context of one request: the issuer as system principal of the organization.
func systemContext(ctx context.Context, org uuid.UUID, correlation string) context.Context {
	ctx = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "revocation-issuer", OrganizationID: org})
	return httpx.WithRequestID(ctx, correlation)
}

// subject is what the issuer loaded for one request.
type subject struct {
	req       pgstore.RevocationRequest
	dev       pgstore.Device
	approvals []pgstore.ListRevocationApprovalTokensRow
}

// Issue handles one request of org: an approved request is either rejected (audited as denied) or issued; any other
// state is left alone. An error means a transient failure; the round retries the request.
func (i *Issuer) Issue(ctx context.Context, org, id uuid.UUID) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	ctx = systemContext(ctx, org, "revocation:"+id.String())
	var s subject
	err := i.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if s.req, err = q.GetRevocationRequest(ctx, id); err != nil {
			return err
		}
		if s.dev, err = q.GetDevice(ctx, s.req.DeviceID); err != nil {
			return err
		}
		s.approvals, err = q.ListRevocationApprovalTokens(ctx, id)
		return err
	})
	if db.IsNoRows(err) {
		slog.WarnContext(ctx, "approved revocation request not found", "request_id", id)
		return nil
	}
	if err != nil || s.req.Status != domain.StatusApproved {
		return err
	}
	code, reason, err := i.check(ctx, s)
	if err != nil {
		return err
	}
	if reason != "" {
		return i.reject(ctx, s, code, reason)
	}
	if s.req.Action == domain.ActionDestroy {
		return i.issueDestroy(ctx, s)
	}
	return i.issueLock(ctx, s)
}

// check runs the issuer's checks in the order of architecture §12.3 and returns the audit code and reason of a
// refusal ("" when the request may be issued). An error is transient.
func (i *Issuer) check(ctx context.Context, s subject) (audit.Code, string, error) {
	refused := audit.CodeRevocationIssueRefused
	// (0) The feature flag: while revocation is disabled the issuer signs nothing (plan M4c decision 1).
	if !i.enabled {
		return refused, domain.RejectedDisabled, nil
	}
	if s.dev.State != device.StateActive && s.dev.State != device.StateQuarantined {
		return refused, domain.RejectedDeviceRetired, nil
	}
	// (1) Every approval's step-up ID token: signature against Authentik's JWKS, iss, aud, MFA, auth_time at most
	// 300 s before the approval, sub and jti as recorded, an organization administrator behind the subject.
	reason, err := i.checkApprovals(ctx, s)
	if err != nil || reason != "" {
		return refused, reason, err
	}
	// (2) The requester is not frozen after an exceeded limit (ADR 0014).
	frozen, err := i.frozen(ctx, s)
	if err != nil || frozen {
		return refused, domain.RejectedFrozen, err
	}
	// (3) The limits of ADR 0014 over sliding windows of issued requests; self-locks do not count.
	reason, err = i.limits(ctx, s)
	return audit.CodeRevocationLimitExceeded, reason, err
}

// checkApprovals verifies the approvals of a request: exactly the approvals its action needs (Destroy: a requester
// and an approver), each token valid for its recorded subject and jti, distinct administrators, subjects and tokens,
// and each token unused by any other request.
func (i *Issuer) checkApprovals(ctx context.Context, s subject) (string, error) {
	if len(s.approvals) != domain.Approvals(s.req.Action) || s.approvals[0].Role != domain.RoleRequester ||
		!s.req.RequestedBy.Valid || s.approvals[0].AdminID != s.req.RequestedBy.UUID {
		return domain.RejectedApprovals, nil
	}
	admins, subjects, jtis := map[uuid.UUID]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range s.approvals {
		claims, err := i.proofs.VerifyApproval(ctx, a.StepupIDToken, a.ApprovedAt)
		if errors.Is(err, stepupproof.ErrInvalid) {
			slog.WarnContext(ctx, "revocation approval with an invalid step-up token", "request_id", s.req.ID, "role", a.Role, "error", err)
			return domain.RejectedStepUp, nil
		}
		if err != nil {
			return "", err
		}
		if claims.Subject != a.Subject || claims.JTI != a.StepupJti {
			return domain.RejectedStepUp, nil
		}
		ok, err := i.isOrgAdmin(ctx, s.req.OrganizationID, a.AdminID, a.Subject)
		if err != nil || !ok {
			return domain.RejectedNotAdmin, err
		}
		if admins[a.AdminID] || subjects[a.Subject] || jtis[a.StepupJti] {
			return domain.RejectedApprovals, nil
		}
		admins[a.AdminID], subjects[a.Subject], jtis[a.StepupJti] = true, true, true
	}
	// Last, so that a refusal above never uses a token up: a token proves exactly one request.
	for jti := range jtis {
		fresh, err := i.claims.Claim(ctx, jti, s.req.ID)
		if err != nil {
			return "", err
		}
		if !fresh {
			return domain.RejectedStepUp, nil
		}
	}
	return "", nil
}

// isOrgAdmin reports whether subject is the organization administrator admin of org.
func (i *Issuer) isOrgAdmin(ctx context.Context, org, admin uuid.UUID, subject string) (bool, error) {
	var ok bool
	err := i.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		a, err := q.GetAdminAccountBySubject(ctx, subject)
		if db.IsNoRows(err) {
			return nil
		}
		ok = err == nil && a.ID == admin && a.OrganizationID == org && a.Role == string(principal.RoleOrgAdmin)
		return err
	})
	return ok, err
}

func (i *Issuer) frozen(ctx context.Context, s subject) (bool, error) {
	var frozen bool
	err := i.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.ActiveRevocationFreeze(ctx, pgstore.ActiveRevocationFreezeParams{AdminID: s.req.RequestedBy.UUID, Now: i.now()})
		frozen = err == nil
		if db.IsNoRows(err) {
			return nil
		}
		return err
	})
	return frozen, err
}

func (i *Issuer) limits(ctx context.Context, s subject) (string, error) {
	now := i.now()
	var c domain.Counts
	err := i.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		admin := s.req.RequestedBy.UUID
		hour, err := q.CountIssuedRevocationsByAdmin(ctx, pgstore.CountIssuedRevocationsByAdminParams{AdminID: uuid.NullUUID{UUID: admin, Valid: true}, Since: now.Add(-time.Hour)})
		if err != nil {
			return err
		}
		day, err := q.CountIssuedRevocationsByAdmin(ctx, pgstore.CountIssuedRevocationsByAdminParams{AdminID: uuid.NullUUID{UUID: admin, Valid: true}, Since: now.Add(-24 * time.Hour)})
		if err != nil {
			return err
		}
		org, err := q.CountIssuedRevocations(ctx, now.Add(-24*time.Hour))
		c = domain.Counts{AdminLastHour: int(hour), AdminLastDay: int(day), OrgLastDay: int(org)}
		return err
	})
	return domain.LimitExceeded(c), err
}

// reject closes the request as rejected and records the refusal as denied in the same transaction; an exceeded limit
// also freezes the requester for 24 h and raises the alert.
func (i *Issuer) reject(ctx context.Context, s subject, code audit.Code, reason string) error {
	spec := i.spec(code, s)
	spec.Params["reason"] = reason
	now := i.now().UTC()
	limit := code == audit.CodeRevocationLimitExceeded
	if limit {
		spec.Params["frozen_until"] = now.Add(domain.FreezeDuration).Format(time.RFC3339)
	}
	err := i.runner.RunTxRefusal(ctx, app.ScopeOrg, spec, problem.RevocationRejected.WithDetail(reason),
		func(ctx context.Context, q *pgstore.Queries, _ app.Recorder) error {
			if _, err := q.CloseRevocationRequest(ctx, pgstore.CloseRevocationRequestParams{
				ID: s.req.ID, Status: domain.StatusRejected, FinishedAt: now, Rejection: &reason,
			}); err != nil {
				return err
			}
			if !limit {
				return nil
			}
			return q.InsertRevocationFreeze(ctx, pgstore.InsertRevocationFreezeParams{
				OrganizationID: s.req.OrganizationID, AdminID: s.req.RequestedBy.UUID, RequestID: s.req.ID,
				FrozenAt: now, FrozenUntil: now.Add(domain.FreezeDuration),
			})
		})
	if !errors.Is(err, problem.RevocationRejected) {
		return err
	}
	metricRefused.WithLabelValues(reason).Inc()
	if limit {
		slog.ErrorContext(ctx, "ALERT: revocation limit exceeded; the administrator is frozen for 24 h", "request_id", s.req.ID,
			"admin_id", s.req.RequestedBy.UUID, "reason", reason)
	} else {
		slog.WarnContext(ctx, "revocation refused", "request_id", s.req.ID, "reason", reason)
	}
	return nil
}

// spec is the audit spec of an issuer action on the request's device.
func (i *Issuer) spec(code audit.Code, s subject) app.ActionSpec {
	return app.ActionSpec{
		Code:   code,
		Target: &audit.Target{Type: "device", ID: s.dev.ID.String(), Display: s.dev.Hostname},
		Params: map[string]any{"action": s.req.Action, "hostname": s.dev.Hostname, "request_id": s.req.ID.String(),
			"requested_by": s.req.RequestedBy.UUID.String()},
	}
}

// issueLock signs a Lock and records it as issued (audited: revocation.issued), then publishes it.
func (i *Issuer) issueLock(ctx context.Context, s subject) error {
	var issued pgstore.RevocationRequest
	spec := i.spec(audit.CodeRevocationIssued, s)
	err := i.runner.RunTx(ctx, app.ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
		var err error
		issued, err = i.sign(ctx, q, rec, s)
		return err
	})
	if err != nil {
		return err
	}
	return i.publish(ctx, issued)
}

// issueDestroy deletes the device's escrow and signs the Destroy (plan M4c decision 9, audited:
// device.escrow_destroyed): first every version of every escrowed header object, then — in the transaction that
// records the request as issued — every recovery key and header row. A failure leaves the request approved; the
// round retries it.
func (i *Issuer) issueDestroy(ctx context.Context, s subject) error {
	var issued pgstore.RevocationRequest
	spec := i.spec(audit.CodeDeviceEscrowDestroyed, s)
	spec.Params["approved_by"] = s.approvals[len(s.approvals)-1].AdminID.String()
	prefix := escrow.HeaderObjectPrefix(s.req.OrganizationID.String(), s.dev.ID.String())
	objects := 0
	err := i.runner.RunExternal(ctx, app.ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, _ app.Recorder) error {
			req, err := q.GetRevocationRequestForUpdate(ctx, s.req.ID)
			if err == nil && req.Status != domain.StatusApproved {
				return problem.InvalidState.WithDetail("the request is no longer approved")
			}
			return err
		},
		func(ctx context.Context) error {
			var err error
			objects, err = i.escrow.DeleteAllVersions(ctx, prefix)
			return err
		},
		func(ctx context.Context, q *pgstore.Queries, rec app.Recorder, externalErr error) error {
			rec.SetParam("objects", objects)
			if externalErr != nil {
				return nil
			}
			rows, err := q.DeleteDeviceLUKSEscrows(ctx, s.dev.ID)
			if err != nil {
				return err
			}
			rec.SetParam("escrows", len(rows))
			issued, err = i.sign(ctx, q, rec, s)
			return err
		})
	if err != nil {
		return err
	}
	return i.publish(ctx, issued)
}

// sign signs the device-bound token (command_id = request ID, valid 30 days) and records the request as issued.
func (i *Issuer) sign(ctx context.Context, q *pgstore.Queries, rec app.Recorder, s subject) (pgstore.RevocationRequest, error) {
	now := i.now().UTC().Truncate(time.Second)
	tok := revocation.Token{
		CommandID: s.req.ID.String(), DeviceID: s.dev.ID.String(), OrganizationID: s.req.OrganizationID.String(),
		Action: s.req.Action, IssuedAt: now, ExpiresAt: now.Add(revocation.Lifetime), RequestID: s.req.ID.String(),
	}
	env, err := revocationsign.Sign(ctx, i.signer, tok)
	if err != nil {
		return pgstore.RevocationRequest{}, err
	}
	rec.SetParam("expires_at", tok.ExpiresAt.Format(time.RFC3339))
	issued, err := q.IssueRevocationRequest(ctx, pgstore.IssueRevocationRequestParams{
		ID: s.req.ID, IssuedAt: now, ExpiresAt: tok.ExpiresAt, Envelope: env,
	})
	if db.IsNoRows(err) {
		return issued, problem.InvalidState.WithDetail("the request is no longer approved")
	}
	return issued, err
}

// publish puts an issued token into cmd:<device_id>; a failure is repaired by the round.
func (i *Issuer) publish(ctx context.Context, r pgstore.RevocationRequest) error {
	if r.ExpiresAt == nil {
		return fmt.Errorf("issued request %s without expiry", r.ID)
	}
	err := i.commands.PutCommand(ctx, r.DeviceID, r.ID, devicecache.Command{ExpiresAt: *r.ExpiresAt, Envelope: r.Envelope})
	if err != nil {
		slog.WarnContext(ctx, "publishing the revocation failed; the round retries", "request_id", r.ID, "error", err)
		return nil
	}
	slog.InfoContext(ctx, "revocation issued", "request_id", r.ID, "device_id", r.DeviceID, "action", r.Action)
	return nil
}

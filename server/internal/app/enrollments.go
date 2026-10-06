package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/enrollment"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Enrollments turn accepted enrollment requests into devices (worker, plan M2a decision 10). The caller's context
// carries a system principal of the request's organization.
type Enrollments struct {
	runner *ActionRunner
	org    *db.OrgPool
	now    func() time.Time
}

// NewEnrollments creates the use case.
func NewEnrollments(runner *ActionRunner, org *db.OrgPool) *Enrollments {
	return &Enrollments{runner: runner, org: org, now: time.Now}
}

// EnrollResult is the device created for (or already created by) an enrollment request.
type EnrollResult struct {
	DeviceID  uuid.UUID
	State     string
	KeyStatus string
}

// Enroll consumes one use of the token, creates the device in state active (auto-approve) or pending, its identity
// key and the token's group membership, and records device.enrolled with the device as actor. A redelivered request
// whose key already exists returns the existing device without a second event. A token that is unknown, revoked,
// expired or exhausted at this point rejects the request with problem.InvalidToken, TokenRevoked, TokenExpired or
// TokenExhausted (recorded as failure).
func (e *Enrollments) Enroll(ctx context.Context, req ingest.Enroll) (EnrollResult, error) {
	if res, found, err := e.existing(ctx, req.KeyID); err != nil || found {
		return res, err
	}
	var res EnrollResult
	spec := ActionSpec{
		Code:   audit.CodeDeviceEnrolled,
		Actor:  &audit.Actor{Type: audit.ActorDevice, ID: req.EnrollmentID.String(), Display: req.Hostname},
		Target: &audit.Target{Type: "device", ID: req.EnrollmentID.String(), Display: req.Hostname},
		Params: map[string]any{"hostname": req.Hostname, "key_protection": req.KeyProtection},
	}
	err := e.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		tok, err := q.LockEnrollmentTokenBySecret(ctx, req.TokenSHA256)
		if err != nil {
			if db.IsNoRows(err) {
				return problem.InvalidToken
			}
			return err
		}
		rec.SetParam("enrolled_with", tok.ID.String())
		if err := usable(tok, e.now()); err != nil {
			return err
		}
		if err := validateEnroll(req); err != nil {
			return err
		}
		state := device.StatePending
		if tok.AutoApprove {
			state = device.StateActive
		}
		rec.SetParam("state", state)
		if err := createDevice(ctx, q, req, tok, state); err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeDevice, req.EnrollmentID)
		res = EnrollResult{DeviceID: req.EnrollmentID, State: state, KeyStatus: "active"}
		return nil
	})
	return res, err
}

func (e *Enrollments) existing(ctx context.Context, keyID string) (EnrollResult, bool, error) {
	var res EnrollResult
	found := false
	err := e.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		key, err := q.GetDeviceIdentityKey(ctx, keyID)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		dev, err := q.GetDevice(ctx, key.DeviceID)
		if err != nil {
			return err
		}
		res, found = EnrollResult{DeviceID: dev.ID, State: dev.State, KeyStatus: key.Status}, true
		return nil
	})
	return res, found, err
}

func usable(tok pgstore.EnrollmentToken, now time.Time) error {
	switch err := enrollment.Usable(tok.RevokedAt, tok.ExpiresAt, int(tok.Uses), int(tok.MaxUses), now); {
	case errors.Is(err, enrollment.ErrRevoked):
		return problem.TokenRevoked
	case errors.Is(err, enrollment.ErrExpired):
		return problem.TokenExpired
	case errors.Is(err, enrollment.ErrExhausted):
		return problem.TokenExhausted
	}
	return nil
}

func validateEnroll(req ingest.Enroll) error {
	if err := device.ValidateReported(req.Hostname, req.HardwareUUID, req.MachineID, req.AgentVersion); err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	if req.KeyProtection != protocol.KeyProtectionFile && req.KeyProtection != protocol.KeyProtectionTPM {
		return problem.InvalidRequest.WithDetail("key_protection must be tpm or file")
	}
	if _, err := protocol.ParsePublicKey(req.PublicKey); err != nil || protocol.KeyID(req.PublicKey) != req.KeyID {
		return problem.InvalidRequest.WithDetail("public key is not an ECDSA P-256 key matching the key id")
	}
	return nil
}

func createDevice(ctx context.Context, q *pgstore.Queries, req ingest.Enroll, tok pgstore.EnrollmentToken, state string) error {
	if err := q.ConsumeEnrollmentTokenUse(ctx, tok.ID); err != nil {
		return err
	}
	osRelease, err := json.Marshal(req.OSRelease)
	if err != nil {
		return err
	}
	if _, err := q.InsertDevice(ctx, pgstore.InsertDeviceParams{
		ID: req.EnrollmentID, OrganizationID: tok.OrganizationID, Hostname: req.Hostname, State: state,
		HardwareUuid: optional(req.HardwareUUID), MachineID: optional(req.MachineID), OsRelease: osRelease,
		EnrollmentTokenID: uuid.NullUUID{UUID: tok.ID, Valid: true},
	}); err != nil {
		return err
	}
	if err := q.InsertDeviceIdentityKey(ctx, pgstore.InsertDeviceIdentityKeyParams{
		KeyID: req.KeyID, OrganizationID: tok.OrganizationID, DeviceID: req.EnrollmentID, PublicKey: req.PublicKey,
		KeyProtection: req.KeyProtection,
	}); err != nil {
		return err
	}
	if !tok.DeviceGroupID.Valid {
		return nil
	}
	return q.InsertDeviceGroupMember(ctx, pgstore.InsertDeviceGroupMemberParams{
		OrganizationID: tok.OrganizationID, DeviceGroupID: tok.DeviceGroupID.UUID, DeviceID: req.EnrollmentID,
	})
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

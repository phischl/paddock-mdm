package app

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Purposes of an escrow decryption: the escrow-reader decrypts only the escrow kind that belongs to the purpose.
const (
	PurposeLocalAdminReveal = "local_admin_reveal"
	PurposeDiskRecoveryKey  = "disk_recovery_key"
	PurposeDiskHeader       = "disk_header"
)

// EscrowDecryptRequest asks the escrow-reader for the plaintexts of escrows of one device, proven by the step-up ID
// token of an organization administrator.
type EscrowDecryptRequest struct {
	OrganizationID uuid.UUID
	DeviceID       uuid.UUID
	EscrowIDs      []uuid.UUID
	StepUpIDToken  string
	Purpose        string
}

// ErrEscrowRefused is wrapped by an EscrowDecrypter when the escrow-reader refused a request: the step-up proof, the
// administrator, the use count of the token or the escrows did not pass its checks.
var ErrEscrowRefused = errors.New("the escrow reader refused the decryption")

// EscrowDecrypter decrypts escrowed secrets in the escrow-reader role (escrowreader.Client, plan M4b.1 decision 5); the
// api never holds the decryption credential. The plaintexts are keyed by escrow ID; the caller zeroes them after use.
type EscrowDecrypter interface {
	Decrypt(ctx context.Context, req EscrowDecryptRequest) (map[uuid.UUID][]byte, error)
}

// StepUpTokens returns the raw ID token of a step-up by its jti (stepupproof.Store); ok is false once it expired.
type StepUpTokens interface {
	Get(ctx context.Context, jti string) (raw string, ok bool, err error)
}

// EscrowAccess decrypts escrows for the reveal and recovery use cases with the step-up ID token of the session.
type EscrowAccess struct {
	decrypter EscrowDecrypter
	tokens    StepUpTokens
}

// NewEscrowAccess combines the escrow-reader client and the step-up token store.
func NewEscrowAccess(decrypter EscrowDecrypter, tokens StepUpTokens) *EscrowAccess {
	return &EscrowAccess{decrypter: decrypter, tokens: tokens}
}

// decrypt returns the plaintexts of ids, one per ID. A missing or refused step-up proof is step_up_required (audited
// as denied), any other failure upstream_unavailable.
func (a *EscrowAccess) decrypt(ctx context.Context, deviceID uuid.UUID, ids []uuid.UUID, purpose string) (map[uuid.UUID][]byte, error) {
	p, ok := principal.From(ctx)
	if !ok || p.StepUpJTI == "" {
		return nil, problem.StepUpRequired
	}
	raw, ok, err := a.tokens.Get(ctx, p.StepUpJTI)
	if err != nil {
		slog.ErrorContext(ctx, "reading the step-up token failed", "error", err)
		return nil, problem.UpstreamUnavailable.WithDetail("the step-up proof could not be read")
	}
	if !ok {
		return nil, problem.StepUpRequired.WithDetail("the step-up proof expired; authenticate again")
	}
	plain, err := a.decrypter.Decrypt(ctx, EscrowDecryptRequest{OrganizationID: p.OrganizationID, DeviceID: deviceID,
		EscrowIDs: ids, StepUpIDToken: raw, Purpose: purpose})
	if errors.Is(err, ErrEscrowRefused) {
		slog.WarnContext(ctx, "the escrow reader refused a decryption", "device_id", deviceID, "purpose", purpose, "error", err)
		return nil, problem.StepUpRequired.WithDetail("the escrow reader refused the step-up proof; authenticate again")
	}
	if err == nil && len(plain) != len(ids) {
		err = errors.New("the escrow reader answered with other escrows")
	}
	for _, id := range ids {
		if _, found := plain[id]; err == nil && !found {
			err = errors.New("the escrow reader answered without escrow " + id.String())
		}
	}
	if err != nil {
		for _, b := range plain {
			clear(b)
		}
		slog.ErrorContext(ctx, "decrypting escrows failed", "device_id", deviceID, "purpose", purpose, "error", err)
		return nil, problem.UpstreamUnavailable.WithDetail("the escrow reader could not decrypt")
	}
	return plain, nil
}

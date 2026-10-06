package escrowreader

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/google/uuid"
)

// DecryptPath is the escrow-reader's only endpoint.
const DecryptPath = "/internal/v1/decrypt"

// macHeader carries the escrow-reader's HMAC-SHA256 of its answer under the shared secret: the api accepts plaintexts
// only from a holder of the secret, as the escrow-reader accepts requests only from one (mutual authentication).
const macHeader = "X-Paddock-Escrow-Reader-Mac"

// maxEscrows bounds the escrows of one request.
const maxEscrows = 16

// decryptRequest is the body of POST /internal/v1/decrypt.
type decryptRequest struct {
	OrganizationID uuid.UUID   `json:"organization_id"`
	DeviceID       uuid.UUID   `json:"device_id"`
	EscrowIDs      []uuid.UUID `json:"escrow_ids"`
	StepUpIDToken  string      `json:"stepup_id_token"`
	Purpose        string      `json:"purpose"`
}

// decryptResponse maps escrow IDs to their plaintexts.
type decryptResponse struct {
	Plaintexts map[uuid.UUID][]byte `json:"plaintexts"`
}

// refusal is the body of a 403: why the escrow-reader refused (refused* constants).
type refusal struct {
	Code string `json:"code"`
}

// Refusal codes.
const (
	refusedStepUp    = "stepup_invalid"   // signature, issuer, audience, expiry, auth_time or MFA
	refusedAdmin     = "not_org_admin"    // the token's subject is no administrator of the organization
	refusedEscrow    = "escrow_mismatch"  // an escrow is not of the device, the organization or the purpose
	refusedExhausted = "stepup_exhausted" // the token was used for MaxUses decryptions already
)

func mac(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

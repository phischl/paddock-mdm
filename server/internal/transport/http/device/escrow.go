package device

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
)

// escrowUpload accepts an encrypted secret (plan M4a decision 12) or announces a sealed LUKS header (plan M4b
// decision 10) and publishes it to ingest.escrow; the worker stores it and sets its status, which the device polls
// with GET /v1/escrow/{escrow_id}. A header is answered with a presigned PUT of the object key the gateway chose.
func (g *gateway) escrowUpload(w http.ResponseWriter, r *http.Request) {
	dev, err := g.authenticateDevice(w, r, maxBody)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	var req escrow.Request
	if err := decodeJSON(dev.body, &req); err != nil {
		g.fail(w, r, err)
		return
	}
	msg, err := validateEscrow(req)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	msg.DeviceID, msg.OrganizationID, msg.ReceivedAt = dev.id, dev.key.OrganizationID, g.d.Now().UTC()
	accepted := escrow.Accepted{EscrowID: msg.EscrowID.String()}
	if req.Kind == escrow.KindLUKSHeader {
		if g.d.Escrow == nil {
			g.fail(w, r, errInternal) // a gateway without the escrow bucket is misconfigured
			return
		}
		volume := ""
		if msg.Volume != nil {
			volume = msg.Volume.String()
		}
		msg.ObjectKey = escrow.HeaderObjectKey(msg.OrganizationID.String(), msg.DeviceID.String(), volume, msg.Generation)
		if accepted.UploadURL, err = g.d.Escrow.PresignPut(r.Context(), msg.ObjectKey, HeaderUploadTTL); err != nil {
			g.fail(w, r, err)
			return
		}
	}
	body, err := json.Marshal(msg)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if err := g.publish(r.Context(), mq.ExchangeIngest, mq.Message{
		RoutingKey: mq.IngestRoutingKey(mq.IngestEscrow, dev.key.OrganizationID), MessageID: msg.EscrowID.String(), Body: body,
	}); err != nil {
		g.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted)
}

// validateEscrow checks a request and returns its message without device, organization and time: a secret needs a
// ciphertext, a header the facts of its sealed object, and neither may carry the fields of the other.
func validateEscrow(req escrow.Request) (ingest.Escrow, error) {
	id, err := uuid.Parse(req.EscrowID)
	if err != nil || id.Variant() != uuid.RFC4122 {
		return ingest.Escrow{}, errInvalidRequest.with("escrow_id must be a UUID")
	}
	if !slices.Contains(escrow.Kinds, req.Kind) {
		return ingest.Escrow{}, errInvalidRequest.with("kind must be admin_password, luks_recovery_key or luks_header")
	}
	if req.Generation < 1 || req.Generation > 1<<31-1 || req.KeyVersion < 1 {
		return ingest.Escrow{}, errInvalidRequest.with("generation and key_version must be positive")
	}
	m := ingest.Escrow{EscrowID: id, Kind: req.Kind, Generation: req.Generation, KeyVersion: req.KeyVersion}
	header := req.WrappedDEK != "" || req.Nonce != "" || req.SHA256 != "" || req.Size != 0 || req.Volume != ""
	if req.Volume != "" {
		volume, err := uuid.Parse(req.Volume)
		if err != nil || volume.String() != req.Volume {
			return ingest.Escrow{}, errInvalidRequest.with("volume must be a lowercase UUID")
		}
		m.Volume = &volume
	}
	if req.Kind != escrow.KindLUKSHeader {
		if m.Ciphertext, err = decoded(req.Ciphertext, 1, escrow.MaxCiphertext); err != nil || header {
			return ingest.Escrow{}, errInvalidRequest.with("ciphertext must be standard base64 of 1 to 4096 bytes, without header fields")
		}
		return m, nil
	}
	if req.Ciphertext != "" {
		return ingest.Escrow{}, errInvalidRequest.with("a luks_header has no ciphertext")
	}
	if m.WrappedDEK, err = decoded(req.WrappedDEK, 1, escrow.MaxCiphertext); err != nil {
		return ingest.Escrow{}, errInvalidRequest.with("wrapped_dek must be standard base64 of 1 to 4096 bytes")
	}
	if m.Nonce, err = decoded(req.Nonce, escrow.HeaderNonceSize, escrow.HeaderNonceSize); err != nil {
		return ingest.Escrow{}, errInvalidRequest.with("nonce must be standard base64 of 12 bytes")
	}
	if sum, err := hex.DecodeString(req.SHA256); err != nil || len(sum) != 32 || hex.EncodeToString(sum) != req.SHA256 {
		return ingest.Escrow{}, errInvalidRequest.with("sha256 must be 64 lowercase hex digits")
	}
	if req.Size < 1 || req.Size > escrow.MaxHeaderObject {
		return ingest.Escrow{}, errInvalidRequest.with("size must be 1 to 33554432 bytes")
	}
	m.SHA256, m.Size = req.SHA256, req.Size
	return m, nil
}

// decoded decodes standard base64 of min to max bytes.
func decoded(s string, minLen, maxLen int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) < minLen || len(b) > maxLen {
		return nil, errInvalidRequest
	}
	return b, nil
}

// escrowStatus answers the storage status of an upload of the signing device: pending until the worker processed
// it, then stored or failed. The status of another device's upload is not found.
func (g *gateway) escrowStatus(w http.ResponseWriter, r *http.Request) {
	dev, err := g.authenticateDevice(w, r, maxBody)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("escrow_id"))
	if err != nil {
		g.fail(w, r, errNotFound)
		return
	}
	owner, status, ok, err := g.d.Cache.EscrowStatus(r.Context(), id)
	switch {
	case err != nil:
		g.fail(w, r, err)
	case !ok:
		writeJSON(w, http.StatusOK, escrow.Status{Status: escrow.StatusPending})
	case owner != dev.id:
		g.fail(w, r, errNotFound)
	default:
		writeJSON(w, http.StatusOK, escrow.Status{Status: status})
	}
}

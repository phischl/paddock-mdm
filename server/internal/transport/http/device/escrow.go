package device

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/escrow"
	"github.com/paddock-mdm/paddock/server/internal/ingest"
	"github.com/paddock-mdm/paddock/server/internal/platform/mq"
)

// escrowUpload accepts an encrypted secret (plan M4a decision 12) and publishes it to ingest.escrow; the worker
// stores it and sets its status, which the device polls with GET /v1/escrow/{escrow_id}.
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
	id, ciphertext, err := validateEscrow(req)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	body, err := json.Marshal(ingest.Escrow{
		DeviceID: dev.id, OrganizationID: dev.key.OrganizationID, EscrowID: id, Kind: req.Kind, Generation: req.Generation,
		KeyVersion: req.KeyVersion, Ciphertext: ciphertext, ReceivedAt: g.d.Now().UTC(),
	})
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if err := g.publish(r.Context(), mq.ExchangeIngest, mq.Message{
		RoutingKey: mq.IngestRoutingKey(mq.IngestEscrow, dev.key.OrganizationID), MessageID: id.String(), Body: body,
	}); err != nil {
		g.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, escrow.Accepted{EscrowID: id.String()})
}

func validateEscrow(req escrow.Request) (uuid.UUID, []byte, error) {
	id, err := uuid.Parse(req.EscrowID)
	if err != nil || id.Variant() != uuid.RFC4122 {
		return uuid.Nil, nil, errInvalidRequest.with("escrow_id must be a UUID")
	}
	if req.Kind != escrow.KindAdminPassword {
		return uuid.Nil, nil, errInvalidRequest.with("kind must be admin_password")
	}
	if req.Generation < 1 || req.Generation > 1<<31-1 || req.KeyVersion < 1 {
		return uuid.Nil, nil, errInvalidRequest.with("generation and key_version must be positive")
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil || len(ct) == 0 || len(ct) > escrow.MaxCiphertext {
		return uuid.Nil, nil, errInvalidRequest.with("ciphertext must be standard base64 of 1 to 4096 bytes")
	}
	return id, ct, nil
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

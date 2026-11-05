package device

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
)

// DiagnosticsUploadTTL is the validity of the presigned PUT of a diagnostics bundle (plan M12 decision 5).
const DiagnosticsUploadTTL = 10 * time.Minute

var errAlreadyUploaded = newError(http.StatusConflict, protocol.CodeAlreadyUploaded)

// diagnosticsUpload answers the announcement of a sealed diagnostics bundle (plan M12 decision 5) with a presigned PUT
// bound to the announced size and publishes the announcement to the worker on the escrow ingest queue. The gateway has
// no database: the command must be a collect_status command held for the device in cmd:<device_id> — the device only
// learns a command's ID by its delivery, and the command leaves Valkey with its result, expiry or withdrawal — and each
// command is announced once (diag:<command_id>).
func (g *gateway) diagnosticsUpload(w http.ResponseWriter, r *http.Request) {
	dev, err := g.authenticateDevice(w, r, maxBody)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	var req protocol.DiagnosticsRequest
	if err := decodeJSON(dev.body, &req); err != nil {
		g.fail(w, r, err)
		return
	}
	msg, err := validateDiagnostics(req)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if g.d.Escrow == nil {
		g.fail(w, r, errInternal) // a gateway without the escrow bucket is misconfigured
		return
	}
	ctx := r.Context()
	if err := g.heldCollectStatus(ctx, dev, msg.DiagnosticsID); err != nil {
		g.fail(w, r, err)
		return
	}
	msg.DeviceID, msg.OrganizationID, msg.ReceivedAt = dev.id, dev.key.OrganizationID, g.d.Now().UTC()
	msg.ObjectKey = escrow.DiagnosticsObjectKey(msg.OrganizationID.String(), msg.DeviceID.String(), msg.DiagnosticsID.String())
	url, err := g.d.Escrow.PresignPut(ctx, msg.ObjectKey, msg.Size, DiagnosticsUploadTTL)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	body, err := json.Marshal(msg)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	fresh, err := g.d.Cache.ClaimDiagnostics(ctx, dev.id, msg.DiagnosticsID)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if !fresh {
		g.fail(w, r, errAlreadyUploaded.with("the bundle of this command was announced before"))
		return
	}
	if err := g.publish(ctx, mq.ExchangeIngest, mq.Message{
		RoutingKey: mq.IngestRoutingKey(mq.IngestEscrow, dev.key.OrganizationID),
		MessageID:  "diagnostics:" + msg.DiagnosticsID.String(), Body: body,
	}); err != nil {
		g.releaseDiagnostics(r, dev.id, msg.DiagnosticsID)
		g.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, protocol.DiagnosticsResponse{DiagnosticsID: msg.DiagnosticsID.String(), UploadURL: url})
}

// heldCollectStatus refuses (404) a command that is not an unexpired collect_status command in the device's
// cmd:<device_id>: another type, another device's command, or one not (or no longer) held for the device.
func (g *gateway) heldCollectStatus(ctx context.Context, dev device, id uuid.UUID) error {
	cmds, err := g.d.Cache.Commands(ctx, dev.id, g.d.Now())
	if err != nil {
		return err
	}
	notFound := errNotFound.with("no delivered collect_status command with this ID")
	cmd, ok := cmds[id]
	if !ok {
		return notFound
	}
	env, payload, err := dsse.Decode(cmd.Envelope)
	if err != nil || env.PayloadType != command.PayloadType {
		return notFound
	}
	var c command.Command
	if err := json.Unmarshal(payload, &c); err != nil || c.Type != command.TypeCollectStatus || c.DeviceID != dev.id.String() {
		return notFound
	}
	return nil
}

// releaseDiagnostics takes back the claim of an announcement whose publish failed; a failure is logged only, the
// device's retry is then refused with 409 and the bundle fails as missing.
func (g *gateway) releaseDiagnostics(r *http.Request, device, id uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), releaseTimeout)
	defer cancel()
	if err := g.d.Cache.ReleaseDiagnostics(ctx, device, id); err != nil {
		slog.WarnContext(ctx, "releasing the diagnostics claim of a failed announcement failed", "device_id", device,
			"command_id", id, "error", err)
	}
}

// validateDiagnostics checks an announcement and returns its message without device, organization, object key and
// time. A size above protocol.MaxDiagnosticsObject is 413.
func validateDiagnostics(req protocol.DiagnosticsRequest) (ingest.DiagnosticsAnnounced, error) {
	id, err := uuid.Parse(req.CommandID)
	if err != nil || id.Variant() != uuid.RFC4122 {
		return ingest.DiagnosticsAnnounced{}, errInvalidRequest.with("command_id must be a UUID")
	}
	if sum, err := hex.DecodeString(req.SHA256); err != nil || len(sum) != 32 || hex.EncodeToString(sum) != req.SHA256 {
		return ingest.DiagnosticsAnnounced{}, errInvalidRequest.with("sha256 must be 64 lowercase hex digits")
	}
	if req.Size > protocol.MaxDiagnosticsObject {
		return ingest.DiagnosticsAnnounced{}, errTooLarge.with("size must be at most 33554432 bytes")
	}
	if req.Size < 1 {
		return ingest.DiagnosticsAnnounced{}, errInvalidRequest.with("size must be 1 to 33554432 bytes")
	}
	// An agent before PDK-749 omits key_version (ADR 0013); a reported one must be a version.
	if req.KeyVersion < 0 || req.KeyVersion > 1<<31-1 {
		return ingest.DiagnosticsAnnounced{}, errInvalidRequest.with("key_version must be positive")
	}
	m := ingest.DiagnosticsAnnounced{DiagnosticsID: id, SHA256: req.SHA256, Size: req.Size, KeyVersion: req.KeyVersion}
	if m.Nonce, err = decoded(req.Nonce, escrow.HeaderNonceSize, escrow.HeaderNonceSize); err != nil {
		return ingest.DiagnosticsAnnounced{}, errInvalidRequest.with("nonce must be standard base64 of 12 bytes")
	}
	if m.WrappedDEK, err = decoded(req.WrappedDEK, 1, escrow.MaxCiphertext); err != nil {
		return ingest.DiagnosticsAnnounced{}, errInvalidRequest.with("wrapped_dek must be standard base64 of 1 to 4096 bytes")
	}
	return m, nil
}

package device

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	domaindevice "github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/enrollment"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
)

// enroll accepts an enrollment request: proof of possession of the new key, token lookup in et:, enr: written as
// processing, ingest.enroll published (plan M2a decision 10).
func (g *gateway) enroll(w http.ResponseWriter, r *http.Request) {
	s, err := g.readSigned(w, r, maxBody)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	var req protocol.EnrollRequest
	if err := decodeJSON(s.body, &req); err != nil {
		g.fail(w, r, err)
		return
	}
	spki, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		g.fail(w, r, errInvalidRequest.with("public_key must be standard base64"))
		return
	}
	if err := g.authenticateEnrollment(r.Context(), r, s, spki); err != nil {
		g.fail(w, r, err)
		return
	}
	if err := validateEnroll(req); err != nil {
		g.fail(w, r, err)
		return
	}
	hash := enrollment.HashSecret(req.Token)
	tok, ok, err := g.d.Cache.Token(r.Context(), hash)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if !ok || !tok.Usable(g.d.Now()) {
		g.fail(w, r, errInvalidToken.with("unknown, revoked or expired enrollment token"))
		return
	}
	id := uuid.Must(uuid.NewV7())
	msg := ingest.Enroll{
		EnrollmentID: id, OrganizationID: tok.OrganizationID, TokenSHA256: hash, KeyID: s.headers.KeyID, PublicKey: spki,
		KeyProtection: req.KeyProtection, Hostname: req.Hostname, HardwareUUID: req.HardwareUUID, MachineID: req.MachineID,
		OSRelease: req.OSRelease, AgentVersion: req.AgentVersion, ReceivedAt: g.d.Now().UTC(),
	}
	body, err := json.Marshal(msg)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	entry := devicecache.Enrollment{KeyID: s.headers.KeyID, PublicKey: spki, OrganizationID: tok.OrganizationID, Status: protocol.EnrollProcessing}
	if err := g.d.Cache.PutEnrollment(r.Context(), id, entry, g.d.Now()); err != nil {
		g.fail(w, r, err)
		return
	}
	if err := g.publish(r.Context(), mq.ExchangeIngest, mq.Message{
		RoutingKey: mq.IngestRoutingKey(mq.IngestEnroll, tok.OrganizationID), MessageID: id.String(), Body: body,
	}); err != nil {
		g.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, protocol.EnrollAccepted{EnrollmentID: id.String()})
}

func validateEnroll(req protocol.EnrollRequest) error {
	if req.KeyProtection != protocol.KeyProtectionFile && req.KeyProtection != protocol.KeyProtectionTPM {
		return errInvalidRequest.with("key_protection must be tpm or file")
	}
	if err := domaindevice.ValidateReported(req.Hostname, req.HardwareUUID, req.MachineID, req.AgentVersion); err != nil {
		return errInvalidRequest.with(err.Error())
	}
	return nil
}

// enrollStatus answers the status of an enrollment, signed with the enrollment key. Once the worker cached the
// device key, the device state in dk: is authoritative (approval or rejection by an administrator).
func (g *gateway) enrollStatus(w http.ResponseWriter, r *http.Request) {
	s, err := g.readSigned(w, r, maxBody)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("enrollment_id"))
	if err != nil {
		g.fail(w, r, errNotFound)
		return
	}
	enr, ok, err := g.d.Cache.Enrollment(r.Context(), id)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if !ok {
		g.fail(w, r, errNotFound)
		return
	}
	if err := g.authenticateEnrollment(r.Context(), r, s, enr.PublicKey); err != nil {
		g.fail(w, r, err)
		return
	}
	out := protocol.EnrollStatus{Status: enr.Status, Reason: enr.Reason}
	if enr.DeviceID != uuid.Nil {
		out.DeviceID = enr.DeviceID.String()
	}
	key, ok, err := g.d.Cache.DeviceKey(r.Context(), enr.KeyID)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if ok {
		out.DeviceID, out.Reason = key.DeviceID.String(), ""
		out.Status = protocol.EnrollRejected
		if key.Status == devicecache.KeyActive || key.Status == devicecache.KeyQuarantined {
			out.Status = protocol.EnrollActive
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// checkin issues the next sequence number, publishes the heartbeat and points to a newer bundle (plan M2a
// decision 11); it carries the device's pending commands (plan M4a decision 3). A quarantined device gets neither
// a bundle URL nor commands.
func (g *gateway) checkin(w http.ResponseWriter, r *http.Request) {
	dev, err := g.authenticateDevice(w, r, maxBody)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	var req protocol.CheckinRequest
	if err := decodeJSON(dev.body, &req); err != nil {
		g.fail(w, r, err)
		return
	}
	seq, err := g.d.Cache.NextSeq(r.Context(), dev.id)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	out := protocol.CheckinResponse{Seq: seq, ServerTime: g.d.Now().UTC(), NextCheckinS: g.d.CheckinDelay(), Commands: []json.RawMessage{}}
	var delivered []uuid.UUID
	if dev.key.Status == devicecache.KeyActive {
		if out.Bundle, err = g.bundleRef(r, dev, req.AppliedBundleVersion); err != nil {
			g.fail(w, r, err)
			return
		}
		if out.AgentUpdate, err = g.agentUpdate(r, dev, req); err != nil {
			g.fail(w, r, err)
			return
		}
		if out.Commands, delivered, err = g.commands(r, dev); err != nil {
			g.fail(w, r, err)
			return
		}
	}
	// The time ticket proves the contact to the dead man's switch (plan M4c decision 14); quarantined devices get it
	// too (fail safe).
	if out.TimeTicket, err = g.d.Cache.TimeTicket(r.Context(), dev.key.OrganizationID); err != nil {
		g.fail(w, r, err)
		return
	}
	issued := seq - 1 // the value the device should have sent
	hb := ingest.Heartbeat{
		DeviceID: dev.id, OrganizationID: dev.key.OrganizationID, ReceivedAt: g.d.Now().UTC(),
		AppliedBundleVersion: req.AppliedBundleVersion, AgentVersion: req.AgentVersion,
		SchemaVersions: boundedSchemaVersions(req.SchemaVersions), Health: req.Health,
		EventSeqHigh: req.EventSeqHigh, Seq: seq, ReportedSeq: dev.headers.Seq,
		CloneSuspected: dev.headers.Seq < issued-1, DeliveredCommands: delivered,
	}
	body, err := json.Marshal(hb)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if err := g.publish(r.Context(), mq.ExchangeIngest, mq.Message{
		RoutingKey: mq.IngestRoutingKey(mq.IngestHeartbeat, dev.key.OrganizationID),
		MessageID:  uuid.Must(uuid.NewV7()).String(), Body: body,
	}); err != nil {
		g.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// maxCommands bounds the commands of one check-in response; the rest follow with the next check-ins.
const maxCommands = 20

// commands returns the device's unexpired command envelopes in ID order (oldest first, UUIDv7) and their IDs.
func (g *gateway) commands(r *http.Request, dev device) ([]json.RawMessage, []uuid.UUID, error) {
	cmds, err := g.d.Cache.Commands(r.Context(), dev.id, g.d.Now())
	if err != nil {
		return nil, nil, err
	}
	ids := slices.SortedFunc(maps.Keys(cmds), func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	ids = ids[:min(len(ids), maxCommands)]
	out := make([]json.RawMessage, len(ids))
	for i, id := range ids {
		out[i] = cmds[id].Envelope
	}
	return out, ids, nil
}

// commandResult accepts the result of a command that is pending for the device (plan M4a decision 3). It is
// idempotent: the same status again is accepted, another status is a conflict. The result is published before it
// is claimed in Valkey, so a failed publish is retried by the device and never lost.
func (g *gateway) commandResult(w http.ResponseWriter, r *http.Request) {
	dev, err := g.authenticateDevice(w, r, maxBody)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("command_id"))
	if err != nil {
		g.fail(w, r, errNotFound)
		return
	}
	var req protocol.CommandResult
	if err := decodeJSON(dev.body, &req); err != nil {
		g.fail(w, r, err)
		return
	}
	if err := validateResult(req); err != nil {
		g.fail(w, r, err)
		return
	}
	ctx := r.Context()
	owner, status, known, err := g.d.Cache.Result(ctx, id)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if !known {
		pending, err := g.d.Cache.HasCommand(ctx, dev.id, id)
		if err != nil {
			g.fail(w, r, err)
			return
		}
		if !pending {
			g.fail(w, r, errNotFound.with("no pending command with this ID"))
			return
		}
		body, err := json.Marshal(ingest.CommandResult{
			DeviceID: dev.id, OrganizationID: dev.key.OrganizationID, CommandID: id, Status: req.Status, Result: req.Result,
			ReceivedAt: g.d.Now().UTC(),
		})
		if err != nil {
			g.fail(w, r, err)
			return
		}
		if err := g.publish(ctx, mq.ExchangeIngest, mq.Message{
			RoutingKey: mq.IngestRoutingKey(mq.IngestCommandResult, dev.key.OrganizationID),
			MessageID:  id.String() + ":" + req.Status, Body: body,
		}); err != nil {
			g.fail(w, r, err)
			return
		}
		if owner, status, err = g.d.Cache.ClaimResult(ctx, dev.id, id, req.Status); err != nil {
			g.fail(w, r, err)
			return
		}
	}
	switch {
	case owner != dev.id:
		g.fail(w, r, errNotFound.with("no pending command with this ID"))
	case status != req.Status:
		g.fail(w, r, errConflict.with("the command already has the result "+status))
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusAccepted)
	}
}

// validateResult checks the status and that the result is a JSON object of at most protocol.MaxCommandResult bytes.
func validateResult(req protocol.CommandResult) error {
	if req.Status != protocol.CommandSucceeded && req.Status != protocol.CommandFailed {
		return errInvalidRequest.with("status must be succeeded or failed")
	}
	if len(req.Result) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if len(req.Result) > protocol.MaxCommandResult || json.Unmarshal(req.Result, &obj) != nil || obj == nil {
		return errInvalidRequest.with("result must be a JSON object of at most 4 KiB")
	}
	return nil
}

// agentUpdate offers the release of the current rollout to an eligible device (plan M2b decision 21): its rollout
// bucket is inside the current wave, it reports another agent version and there is an artifact for its arch.
func (g *gateway) agentUpdate(r *http.Request, dev device, req protocol.CheckinRequest) (*protocol.AgentUpdate, error) {
	if g.d.Artifacts == nil || req.Arch == "" {
		return nil, nil
	}
	offer, ok, err := g.d.Cache.Offer(r.Context())
	if err != nil || !ok {
		return nil, err
	}
	art, ok := offer.For(dev.id, req.Arch, req.AgentVersion)
	if !ok {
		return nil, nil
	}
	url, err := g.d.Artifacts.PresignGet(r.Context(), art.ObjectKey, ArtifactURLTTL)
	if err != nil {
		return nil, err
	}
	return &protocol.AgentUpdate{Version: offer.Version, URL: url, SHA256: art.SHA256, Size: art.Size, Minisig: art.Minisig}, nil
}

func (g *gateway) bundleRef(r *http.Request, dev device, applied int64) (*protocol.BundleRef, error) {
	p, ok, err := g.d.Cache.BundlePointer(r.Context(), dev.id)
	if err != nil || !ok || p.Version <= applied {
		return nil, err
	}
	url, err := g.d.Presigner.PresignGet(r.Context(), p.ObjectKey, BundleURLTTL)
	if err != nil {
		return nil, err
	}
	return &protocol.BundleRef{Version: p.Version, SHA256: p.SHA256, URL: url}, nil
}

// events accepts a batch of at most 500 events of the closed set of types (plan M2a decision 14).
func (g *gateway) events(w http.ResponseWriter, r *http.Request) {
	dev, err := g.authenticateDevice(w, r, maxEventsBody)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	var req protocol.EventsRequest
	if err := decodeJSON(dev.body, &req); err != nil {
		g.fail(w, r, err)
		return
	}
	if len(req.Events) == 0 || len(req.Events) > protocol.MaxEventsPerBatch {
		g.fail(w, r, errInvalidRequest.with("a batch has 1 to 500 events"))
		return
	}
	for _, ev := range req.Events {
		if !slices.Contains(protocol.EventTypes, ev.Type) {
			g.fail(w, r, errUnknownEventType.with("unknown event type "+ev.Type))
			return
		}
		if ev.EventSeq < 0 || ev.OccurredAt.IsZero() {
			g.fail(w, r, errInvalidRequest.with("every event needs event_seq ≥ 0 and occurred_at"))
			return
		}
	}
	body, err := json.Marshal(ingest.Events{
		DeviceID: dev.id, OrganizationID: dev.key.OrganizationID, ReceivedAt: g.d.Now().UTC(), Events: req.Events,
	})
	if err != nil {
		g.fail(w, r, err)
		return
	}
	if err := g.publish(r.Context(), mq.ExchangeIngest, mq.Message{
		RoutingKey: mq.IngestRoutingKey(mq.IngestEvent, dev.key.OrganizationID),
		MessageID:  uuid.Must(uuid.NewV7()).String(), Body: body,
	}); err != nil {
		g.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
}

// boundedSchemaVersions keeps at most 16 plausible schema versions (1–1000) of a check-in; anything else a device
// sends is dropped.
func boundedSchemaVersions(in []int) []int {
	out := []int{}
	for _, v := range in {
		if v >= 1 && v <= 1000 && len(out) < 16 && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

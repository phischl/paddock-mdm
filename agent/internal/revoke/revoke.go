// Package revoke is paddock-revoke, the device side of Lock, Destroy and the dead man's switch (architecture §12.3,
// plan M4c decisions 11–13). It verifies a revocation token against the pinned trust anchor and, only then, terminates
// the user sessions, erases every keyslot of every LUKS volume (plan M4c.1) — for a Lock only of the volumes whose
// header escrow the signed token confirms, besides the root volume (PDK-009) —, confirms the erasure to the server
// and reboots.
//
// Two-person rule (design contract 10): every change to this package and to agent/cmd/paddock-revoke needs the review
// of a second person and a passed test on real hardware (docs/operations/revocation-acceptance.md).
package revoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/revocation"
)

// Files of paddock-revoke.
const (
	TrustFile   = "/etc/paddock/revoke-trust.json"     // pinned at enrollment (plan M4c decision 3)
	EnabledFile = "/etc/paddock/revoke-enabled"        // kept by paddockd from the bundle (decision 1)
	StateFile   = "/var/lib/paddock/revoke/state.json" // executed tokens (decision 11)
	// SelfLockFile is the stored self-lock token of the dead man's switch (decision 15).
	SelfLockFile = "/var/lib/paddock/revoke/self-lock.dsse"
)

// RateLimit is the minimum time between two revocations of a device (ADR 0014).
const RateLimit = 24 * time.Hour

// ConfirmTimeout bounds how long paddock-revoke tries to deliver its confirmation before it reboots (plan M4c
// decision 12).
const ConfirmTimeout = 20 * time.Second

// Reasons of a refusal, reported as revocation.refused {reason}. No keyslot is touched when a token is refused.
const (
	ReasonDisabled     = "disabled"            // /etc/paddock/revoke-enabled is missing
	ReasonNoTrust      = "trust_missing"       // no valid revoke-trust.json
	ReasonSignature    = "signature"           // not signed by a pinned key
	ReasonMalformed    = "malformed"           // payload type or payload
	ReasonWrongDevice  = "wrong_device"        // another device's token
	ReasonExpired      = "expired"             // expires_at has passed
	ReasonNotYetValid  = "not_yet_valid"       // issued in the future
	ReasonExecuted     = "already_executed"    // command_id was executed before
	ReasonRateLimited  = "rate_limited"        // another revocation within RateLimit
	ReasonPeriod       = "period_not_reached"  // a self-lock before period_days of uptime without contact
	ReasonTestTarget   = "test_target_present" // the release build found the test target override
	ReasonNotEncrypted = "not_encrypted"       // the root file system is not on LUKS
	ReasonNotEnrolled  = "not_enrolled"        // no enrolled device identity
	ReasonInternal     = "internal_error"      // a check could not run (unreadable state)
	ReasonNotSelfLock  = "not_self_lock"       // the dead man's switch ran a token that is no self-lock
)

// Refusal is a refused token: the reason, and nothing changed on the device.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return "revocation refused: " + r.Reason }

func refuse(reason string) error { return &Refusal{Reason: reason} }

// System is what paddock-revoke does to the device. OS implements it; tests fake it.
type System interface {
	luks.Tools
	// Loginctl runs loginctl.
	Loginctl(ctx context.Context, args ...string) (stdout string, exit int, err error)
	// Targets returns the LUKS volumes to erase, the root volume last; a refusal for the test target override of a
	// release build.
	Targets(ctx context.Context) (Targets, error)
	// Reboot reboots the device at once (systemctl reboot --force --force).
	Reboot(ctx context.Context) error
	// ReadFile and WriteFile access the files of paddock-revoke (Root of OS in tests).
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte) error
}

// Confirmer posts the confirmation of a token to /v1/commands/{command_id}/result, signed with the device key.
type Confirmer interface {
	Confirm(ctx context.Context, commandID string, res protocol.CommandResult) error
}

// Revoker executes revocation tokens on one enrolled device.
type Revoker struct {
	Sys      System
	Confirm  Confirmer
	DeviceID string // the enrolled identity (paddockd's state.json)
	Now      func() time.Time
	// ConfirmWithin replaces ConfirmTimeout (tests); zero keeps it.
	ConfirmWithin time.Duration
	// SecondaryWithin replaces the constant SecondaryWithin (tests); zero keeps it.
	SecondaryWithin time.Duration
}

// SecondaryWithin bounds the erasure of all volumes before the root volume together; with SelectWithin the volumes
// other than the root volume take at most 3 minutes, so a hung secondary disk cannot keep the root volume from being
// erased (plan M4c.1, review round 1).
const SecondaryWithin = 2 * time.Minute

// Erasure is the confirmation of a token; it is posted as the command result (plan M4c.1 decision 2). Erased is
// true only if every erased volume has no keyslot left and no crypttab entry is unresolved; SlotsBefore and
// SlotsAfter are the sums over the volumes (SlotsAfter -1 when a volume's count is unknown), kept for the
// confirmations of M4c. SkippedNotEscrowed are the volumes a Lock left alone because the token does not confirm
// their header escrow (PDK-009); they do not make the erasure incomplete. SharedUUID lists the devices whose LUKS UUID
// another volume or the root volume has (review round 2): a Destroy erases them, a Lock skips them; they do not make
// the erasure incomplete either.
type Erasure struct {
	Erased             bool            `json:"erased"`
	SlotsBefore        int             `json:"slots_before"`
	SlotsAfter         int             `json:"slots_after"`
	Volumes            []VolumeErasure `json:"volumes"`
	Unresolved         []string        `json:"unresolved,omitempty"`
	SkippedNotEscrowed []SkippedVolume `json:"skipped_not_escrowed,omitempty"`
	SharedUUID         []string        `json:"shared_uuid,omitempty"`
}

// VolumeErasure is the erasure of one LUKS volume.
type VolumeErasure struct {
	Device      string `json:"device"`
	UUID        string `json:"uuid,omitempty"`
	SlotsBefore int    `json:"slots_before"`
	SlotsAfter  int    `json:"slots_after"` // -1: unknown, never reported as erased
	Erased      bool   `json:"erased"`
}

// SkippedVolume is a volume a Lock did not erase; UUID is "" when cryptsetup reported none.
type SkippedVolume struct {
	Device string `json:"device"`
	UUID   string `json:"uuid,omitempty"`
}

// Handle verifies a token paddockd handed over. A Lock or Destroy runs the binding sequence at once; a self-lock
// token is stored in SelfLockFile for the dead man's switch (stored is true), replacing an older one. It returns a
// *Refusal when the token is refused; then no session and no keyslot was touched. A run does not return on a real
// device: it reboots.
func (r *Revoker) Handle(ctx context.Context, envelope []byte) (e Erasure, stored bool, err error) {
	tok, err := r.verify(envelope, true)
	if err != nil {
		return Erasure{}, false, err
	}
	if tok.Action == revocation.ActionSelfLock {
		if err := r.Sys.WriteFile(SelfLockFile, envelope); err != nil {
			return Erasure{}, false, refuse(ReasonInternal)
		}
		return Erasure{}, true, nil
	}
	e, err = r.execute(ctx, tok)
	return e, false, err
}

// SelfLock runs a self-lock token of the dead man's switch after elapsed, the uptime without contact paddockd counted;
// the token's own period_days must have passed (plan M4c decision 16). Refusals and the sequence are those of Handle.
func (r *Revoker) SelfLock(ctx context.Context, envelope []byte, elapsed time.Duration) (Erasure, error) {
	// The stored token's lifetime was checked when it was stored: a wall-clock change must neither defer nor
	// trigger the switch.
	tok, err := r.verify(envelope, false)
	if err != nil {
		return Erasure{}, err
	}
	if tok.Action != revocation.ActionSelfLock {
		return Erasure{}, refuse(ReasonNotSelfLock)
	}
	if elapsed < time.Duration(tok.PeriodDays)*dayLength {
		return Erasure{}, refuse(ReasonPeriod)
	}
	return r.execute(ctx, tok)
}

// execute checks whether the token may run now and runs the binding sequence.
func (r *Revoker) execute(ctx context.Context, tok *revocation.Token) (Erasure, error) {
	targets, err := r.check(ctx, tok)
	if err != nil {
		return Erasure{}, err
	}
	targets, skipped := restorable(tok, targets)
	// Recorded before anything happens: a crash or a power loss in the sequence never leads to a second run of the
	// token, and the 24 h limit counts from here.
	if err := r.record(tok.CommandID); err != nil {
		return Erasure{}, refuse(ReasonInternal)
	}

	// Binding sequence (architecture §12.3, plan M4c decision 12); between (2) and (4) nothing else runs.
	// (1) Terminate the sessions of every non-system user. A failure does not stop the erasure.
	r.terminateSessions(ctx)
	// (2) Erase every keyslot of every target, the root volume last, and verify that none is left.
	result := r.erase(ctx, targets)
	result.SkippedNotEscrowed, result.SharedUUID = skipped, targets.Shared
	// (3) Post the confirmation ourselves, signed with the device key, and wait up to 20 s for the 202.
	r.confirm(ctx, tok.CommandID, result)
	// (4) Reboot regardless of the confirmation's outcome.
	if err := r.Sys.Reboot(ctx); err != nil {
		return result, fmt.Errorf("reboot: %w", err)
	}
	return result, nil
}

// verify checks the marker, the trust anchor and the token: signature of a pinned key, this device and, with
// lifetime, unexpired and not issued in the future.
func (r *Revoker) verify(envelope []byte, lifetime bool) (*revocation.Token, error) {
	if _, err := r.Sys.ReadFile(EnabledFile); err != nil {
		return nil, refuse(ReasonDisabled)
	}
	if r.DeviceID == "" {
		return nil, refuse(ReasonNotEnrolled)
	}
	data, err := r.Sys.ReadFile(TrustFile)
	if err != nil {
		return nil, refuse(ReasonNoTrust)
	}
	trust, err := revocation.ParseTrust(data)
	if err != nil {
		return nil, refuse(ReasonNoTrust)
	}
	var tok *revocation.Token
	if lifetime {
		tok, err = revocation.Verify(envelope, trust, r.DeviceID, r.Now())
	} else {
		tok, err = revocation.VerifyStored(envelope, trust, r.DeviceID)
	}
	if err != nil {
		return nil, refuse(verifyReason(err))
	}
	return tok, nil
}

// check runs the checks before the sequence: whether the token ran before, the 24 h limit and the targets. It
// returns the volumes to erase, or a refusal.
func (r *Revoker) check(ctx context.Context, tok *revocation.Token) (Targets, error) {
	st, err := r.load()
	if err != nil {
		return Targets{}, refuse(ReasonInternal)
	}
	if _, done := st.Executed[tok.CommandID]; done {
		return Targets{}, refuse(ReasonExecuted)
	}
	if last := st.LastRevocationAt; last != nil && r.Now().Sub(*last) < RateLimit {
		return Targets{}, refuse(ReasonRateLimited)
	}
	targets, err := r.Sys.Targets(ctx)
	var refusal *Refusal
	switch {
	case errors.As(err, &refusal):
		return Targets{}, err
	case errors.Is(err, luks.ErrNotEncrypted):
		return Targets{}, refuse(ReasonNotEncrypted)
	case err != nil || len(targets.Devices) == 0:
		return Targets{}, refuse(ReasonInternal)
	}
	return targets, nil
}

// restorable returns the targets of a token: for a Destroy every target; for a Lock and a self-lock the root volume
// and, of the other volumes, exactly those whose LUKS UUID the token lists and that share it with no other volume —
// none while the root volume's UUID is unknown —, so that every erased volume can be restored from its escrowed
// header (PDK-009). The other volumes are returned as
// skipped. The list comes only from the token the revocation-issuer signed; nothing paddockd hands over decides what
// is erased.
func restorable(tok *revocation.Token, tg Targets) (Targets, []SkippedVolume) {
	if tok.Action == revocation.ActionDestroy || len(tg.Devices) == 0 {
		return tg, nil
	}
	last := len(tg.Devices) - 1
	out := Targets{UUIDs: tg.UUIDs, Shared: tg.Shared, Unresolved: tg.Unresolved, RootUnknown: tg.RootUnknown}
	var skipped []SkippedVolume
	for _, d := range tg.Devices[:last] {
		// Without the root volume's UUID a clone of it is not marked shared: no other volume is erased (round 3).
		if id := tg.UUIDs[d]; id != "" && !tg.RootUnknown && !slices.Contains(tg.Shared, d) && slices.Contains(tok.Volumes, id) {
			out.Devices = append(out.Devices, d)
		} else {
			skipped = append(skipped, SkippedVolume{Device: d, UUID: id})
		}
	}
	out.Devices = append(out.Devices, tg.Devices[last])
	return out, skipped
}

func verifyReason(err error) string {
	switch {
	case errors.Is(err, revocation.ErrWrongDevice):
		return ReasonWrongDevice
	case errors.Is(err, revocation.ErrExpired):
		return ReasonExpired
	case errors.Is(err, revocation.ErrNotYetValid):
		return ReasonNotYetValid
	case errors.Is(err, revocation.ErrMalformed):
		return ReasonMalformed
	}
	return ReasonSignature
}

// FirstUserUID is the lowest UID of a non-system user (login.defs UID_MIN); nobody (65534) is a system user.
const FirstUserUID = 1000

// terminateSessions ends every session of a non-system user: `loginctl terminate-user` per UID.
func (r *Revoker) terminateSessions(ctx context.Context) {
	out, exit, err := r.Sys.Loginctl(ctx, "list-users", "--no-legend")
	if err != nil || exit != 0 {
		return
	}
	for _, uid := range userIDs(out) {
		_, _, _ = r.Sys.Loginctl(ctx, "terminate-user", strconv.Itoa(uid))
	}
}

// erase erases every target in order and sums the results; a volume that fails does not stop the others. The
// volumes before the root volume share SecondaryWithin; the root volume is attempted afterwards in any case.
func (r *Revoker) erase(ctx context.Context, tg Targets) Erasure {
	e := Erasure{Erased: len(tg.Devices) > 0 && len(tg.Unresolved) == 0, Unresolved: tg.Unresolved}
	if len(tg.Devices) == 0 {
		return e
	}
	last := len(tg.Devices) - 1
	within := SecondaryWithin
	if r.SecondaryWithin > 0 {
		within = r.SecondaryWithin
	}
	e.Volumes = append(r.eraseWithin(ctx, tg.Devices[:last], within), r.eraseVolume(ctx, tg.Devices[last]))
	for i := range e.Volumes {
		e.Volumes[i].UUID = tg.UUIDs[e.Volumes[i].Device]
	}
	for _, v := range e.Volumes {
		e.SlotsBefore += v.SlotsBefore
		if v.SlotsAfter < 0 || e.SlotsAfter < 0 {
			e.SlotsAfter = -1
		} else {
			e.SlotsAfter += v.SlotsAfter
		}
		e.Erased = e.Erased && v.Erased
	}
	return e
}

// eraseWithin erases devices in order until within has passed. The erasure runs in a goroutine, so that a command
// stuck in the kernel (uninterruptible, beyond its WaitDelay) cannot hold up the root volume; a volume not finished
// in time is reported with an unknown keyslot count.
func (r *Revoker) eraseWithin(ctx context.Context, devices []string, within time.Duration) []VolumeErasure {
	out := make([]VolumeErasure, len(devices))
	for i, d := range devices {
		out[i] = VolumeErasure{Device: d, SlotsAfter: -1}
	}
	if len(devices) == 0 {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	results := make(chan VolumeErasure, len(devices))
	go func() {
		for _, d := range devices {
			if ctx.Err() != nil {
				return
			}
			results <- r.eraseVolume(ctx, d)
		}
	}()
	for i := range devices {
		select {
		case out[i] = <-results:
		case <-ctx.Done():
			return out
		}
	}
	return out
}

// eraseVolume runs `cryptsetup luksErase` on device and counts the keyslots before and after.
func (r *Revoker) eraseVolume(ctx context.Context, device string) VolumeErasure {
	v := VolumeErasure{Device: device}
	if n, err := r.keyslots(ctx, device); err == nil {
		v.SlotsBefore = n
	}
	_, _, exit, err := r.Sys.Command(ctx, nil, "cryptsetup", "luksErase", "--batch-mode", "--", device)
	n, countErr := r.keyslots(ctx, device)
	if countErr != nil {
		v.SlotsAfter = -1
		return v
	}
	v.SlotsAfter = n
	v.Erased = err == nil && exit == 0 && v.SlotsAfter == 0
	return v
}

// keyslots counts the keyslots of device: from the JSON metadata of LUKS2 or, as LUKS1 has none, from the text dump
// of a LUKS1 header ("Version: 1", "Key Slot N: ENABLED").
func (r *Revoker) keyslots(ctx context.Context, device string) (int, error) {
	if m, err := luks.Dump(ctx, r.Sys, device); err == nil {
		return len(m.Keyslots), nil
	}
	out, _, exit, err := r.Sys.Command(ctx, nil, "cryptsetup", "luksDump", "--", device)
	if err != nil || exit != 0 {
		return 0, fmt.Errorf("revoke: no keyslot count for %s", device)
	}
	luks1, n := false, 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 2 && f[0] == "Version:" && f[1] == "1":
			luks1 = true
		case len(f) == 4 && f[0] == "Key" && f[1] == "Slot" && f[3] == "ENABLED":
			n++
		}
	}
	if !luks1 {
		return 0, fmt.Errorf("revoke: no keyslot count for %s", device)
	}
	return n, nil
}

// confirm posts the result until the server accepts it or ConfirmTimeout has passed.
func (r *Revoker) confirm(ctx context.Context, commandID string, e Erasure) {
	within := ConfirmTimeout
	if r.ConfirmWithin > 0 {
		within = r.ConfirmWithin
	}
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	status := protocol.CommandSucceeded
	if !e.Erased {
		status = protocol.CommandFailed
	}
	raw, _ := json.Marshal(e)
	for {
		err := r.Confirm.Confirm(ctx, commandID, protocol.CommandResult{Status: status, Result: raw})
		if err == nil {
			return
		}
		slog.Warn("the confirmation was not accepted; retrying until the timeout", "command_id", commandID, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// state is StateFile.
type state struct {
	Executed         map[string]time.Time `json:"executed"`
	LastRevocationAt *time.Time           `json:"last_revocation_at,omitempty"`
}

func (r *Revoker) load() (state, error) {
	st := state{Executed: map[string]time.Time{}}
	data, err := r.Sys.ReadFile(StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, err
	}
	if st.Executed == nil {
		st.Executed = map[string]time.Time{}
	}
	return st, nil
}

func (r *Revoker) record(commandID string) error {
	st, err := r.load()
	if err != nil {
		return err
	}
	now := r.Now().UTC()
	st.Executed[commandID], st.LastRevocationAt = now, &now
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return r.Sys.WriteFile(StateFile, data)
}

// userIDs returns the UIDs of non-system users in the output of `loginctl list-users --no-legend`, whose first
// column is the UID.
func userIDs(out string) []int {
	var uids []int
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		uid, err := strconv.Atoi(f[0])
		if err == nil && uid >= FirstUserUID && uid != 65534 {
			uids = append(uids, uid)
		}
	}
	return uids
}

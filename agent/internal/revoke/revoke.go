// Package revoke is paddock-revoke, the device side of Lock, Destroy and the dead man's switch (architecture §12.3,
// plan M4c decisions 11–13). It verifies a revocation token against the pinned trust anchor and, only then, terminates
// the user sessions, erases every keyslot of the root volume, confirms the erasure to the server and reboots.
//
// Two-person rule (design contract 10): every change to this package and to agent/cmd/paddock-revoke needs the review
// of a second person and a passed test on real hardware (docs/operations/revocation-acceptance.md).
package revoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	// RootDevice returns the LUKS device to erase; a refusal for the test target override of a release build.
	RootDevice(ctx context.Context) (string, error)
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
}

// Erasure is the confirmation of a token; it is posted as the command result.
type Erasure struct {
	Erased      bool `json:"erased"`
	SlotsBefore int  `json:"slots_before"`
	SlotsAfter  int  `json:"slots_after"`
}

// Execute verifies a token and, if every check passes, runs the binding sequence. elapsed is the uptime without
// contact the dead man's switch counted (self-lock tokens only). It returns a *Refusal when the token is refused;
// then no session and no keyslot was touched. On success it does not return on a real device: it reboots.
func (r *Revoker) Execute(ctx context.Context, envelope []byte, elapsed time.Duration) (Erasure, error) {
	tok, device, err := r.check(ctx, envelope, elapsed)
	if err != nil {
		return Erasure{}, err
	}
	// Recorded before anything happens: a crash or a power loss in the sequence never leads to a second run of the
	// token, and the 24 h limit counts from here.
	if err := r.record(tok.CommandID); err != nil {
		return Erasure{}, refuse(ReasonInternal)
	}

	// Binding sequence (architecture §12.3, plan M4c decision 12); between (2) and (4) nothing else runs.
	// (1) Terminate the sessions of every non-system user. A failure does not stop the erasure.
	r.terminateSessions(ctx)
	// (2) Erase every keyslot of the root volume and verify that none is left.
	result := r.erase(ctx, device)
	// (3) Post the confirmation ourselves, signed with the device key, and wait up to 20 s for the 202.
	r.confirm(ctx, tok.CommandID, result)
	// (4) Reboot regardless of the confirmation's outcome.
	if err := r.Sys.Reboot(ctx); err != nil {
		return result, fmt.Errorf("reboot: %w", err)
	}
	return result, nil
}

// check runs every check before the sequence: the marker, the trust anchor, the token (signature, device, expiry,
// period of a self-lock), whether it ran before, the 24 h limit and the root device. It returns the token and the
// device to erase, or a refusal.
func (r *Revoker) check(ctx context.Context, envelope []byte, elapsed time.Duration) (*revocation.Token, string, error) {
	if _, err := r.Sys.ReadFile(EnabledFile); err != nil {
		return nil, "", refuse(ReasonDisabled)
	}
	if r.DeviceID == "" {
		return nil, "", refuse(ReasonNotEnrolled)
	}
	data, err := r.Sys.ReadFile(TrustFile)
	if err != nil {
		return nil, "", refuse(ReasonNoTrust)
	}
	trust, err := revocation.ParseTrust(data)
	if err != nil {
		return nil, "", refuse(ReasonNoTrust)
	}
	tok, err := revocation.Verify(envelope, trust, r.DeviceID, r.Now())
	if err != nil {
		return nil, "", refuse(verifyReason(err))
	}
	if tok.Action == revocation.ActionSelfLock && elapsed < time.Duration(tok.PeriodDays)*24*time.Hour {
		return nil, "", refuse(ReasonPeriod)
	}
	st, err := r.load()
	if err != nil {
		return nil, "", refuse(ReasonInternal)
	}
	if _, done := st.Executed[tok.CommandID]; done {
		return nil, "", refuse(ReasonExecuted)
	}
	if last := st.LastRevocationAt; last != nil && r.Now().Sub(*last) < RateLimit {
		return nil, "", refuse(ReasonRateLimited)
	}
	device, err := r.Sys.RootDevice(ctx)
	var refusal *Refusal
	switch {
	case errors.As(err, &refusal):
		return nil, "", err
	case errors.Is(err, luks.ErrNotEncrypted):
		return nil, "", refuse(ReasonNotEncrypted)
	case err != nil:
		return nil, "", refuse(ReasonInternal)
	}
	return tok, device, nil
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

// erase runs `cryptsetup luksErase` on device and counts the keyslots before and after (luksDump).
func (r *Revoker) erase(ctx context.Context, device string) Erasure {
	var e Erasure
	if m, err := luks.Dump(ctx, r.Sys, device); err == nil {
		e.SlotsBefore = len(m.Keyslots)
	}
	_, _, exit, err := r.Sys.Command(ctx, nil, "cryptsetup", "luksErase", "--batch-mode", "--", device)
	m, dumpErr := luks.Dump(ctx, r.Sys, device)
	if dumpErr != nil {
		e.SlotsAfter = -1 // unknown: never reported as erased
		return e
	}
	e.SlotsAfter = len(m.Keyslots)
	e.Erased = err == nil && exit == 0 && e.SlotsAfter == 0
	return e
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
		if err := r.Confirm.Confirm(ctx, commandID, protocol.CommandResult{Status: status, Result: raw}); err == nil {
			return
		}
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

// Package localadmin manages the local administrator account of the device (architecture §12.2, plan M4a decision
// 15): it creates the account, rotates its password without ever leaving a password Paddock does not know — the
// new password is set only after the server confirmed it stored the encrypted copy —, detects local changes of the
// account and repairs them. The plaintext password exists only in memory during a rotation and is zeroed after use.
package localadmin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Timing of a rotation (architecture §12.2).
const (
	PollInterval = 30 * time.Second
	EscrowWait   = 15 * time.Minute
	// RetryAfter delays the next automatic rotation after a failed one.
	RetryAfter = 15 * time.Minute
)

// Shell is the login shell of the account.
const Shell = "/bin/bash"

// System is the OS port of the local administrator (reconcile.OS). The account is always read from the local files
// (/etc/passwd, /etc/shadow, /etc/group), never through NSS: Himmelblau's NSS module answers for any user name of
// its domain, so a missing local account would look present.
type System interface {
	ReadFile(path string) ([]byte, fs.FileInfo, error)
	UserTool(ctx context.Context, tool string, args ...string) (string, int, error)
	// Chpasswd sets a password from "name:password\n" without PAM (pam_himmelblau would take it for a change of a
	// directory user's credentials).
	Chpasswd(ctx context.Context, input []byte) (string, int, error)
}

// Escrow uploads encrypted passwords and polls their storage status (device API, bound to the device).
type Escrow interface {
	Upload(ctx context.Context, req escrow.Request) error
	Status(ctx context.Context, escrowID string) (string, error)
}

// Manager runs the local administrator. It is used by one goroutine (the agent's run loop).
type Manager struct {
	Sys    System
	Escrow Escrow
	State  *state.LocalAdmin
	// Save persists State; Emit spools a device event; Result reports the outcome of a rotate command.
	Save   func() error
	Emit   func(typ string, data any)
	Result func(commandID, status string, result map[string]any)
	Now    func() time.Time

	pending *rotation
}

// rotation is a rotation waiting for the server to store the escrowed password.
type rotation struct {
	escrowID   string
	generation int64
	password   []byte
	deadline   time.Time
	nextPoll   time.Time
}

// Request queues a rotate_admin_password command; its result follows the next rotation.
func (m *Manager) Request(commandID string) {
	if !slices.Contains(m.State.Commands, commandID) {
		m.State.Commands = append(m.State.Commands, commandID)
		m.save()
	}
}

// Tick advances the local administrator: it finishes a pending rotation when the server stored the password (or
// gives up after EscrowWait), and otherwise makes sure the account exists unchanged and starts a rotation when one
// is due. spec nil (no login resource) leaves the device alone; keys are the keys of the applied bundle.
func (m *Manager) Tick(ctx context.Context, spec *bundle.LocalAdminSpec, keys *bundle.Keys) {
	if spec == nil {
		return
	}
	if m.pending != nil {
		m.poll(ctx, spec)
		return
	}
	if m.State.Username != spec.Username {
		*m.State = state.LocalAdmin{Username: spec.Username, Commands: m.State.Commands}
		m.save()
	}
	acct, err := m.ensure(ctx, spec.Username)
	if err != nil {
		slog.WarnContext(ctx, "local administrator account not in shape", "username", spec.Username, "error", err)
		return
	}
	needsPassword := m.inspect(ctx, acct)
	if reason := m.due(spec, needsPassword); reason != "" {
		m.start(ctx, spec, keys, reason)
	}
}

// due returns why a rotation is due now, "" if none is: a command, no generation yet, a changed password or lock,
// or the rotation interval. Automatic rotations wait until RetryAt after a failure.
func (m *Manager) due(spec *bundle.LocalAdminSpec, needsPassword bool) string {
	now := m.Now()
	if len(m.State.Commands) > 0 {
		return "command"
	}
	if m.State.RetryAt != nil && now.Before(*m.State.RetryAt) {
		return ""
	}
	switch {
	case m.State.Generation == 0:
		return "initial"
	case needsPassword:
		return "repair"
	case m.State.RotatedAt == nil || now.Sub(*m.State.RotatedAt) >= time.Duration(spec.RotationDays)*24*time.Hour:
		return "interval"
	}
	return ""
}

// start generates the next password, encrypts it to escrow-wrap and uploads it. A failed upload (server not
// reachable) is retried at a later tick; the account keeps its password.
func (m *Manager) start(ctx context.Context, spec *bundle.LocalAdminSpec, keys *bundle.Keys, reason string) {
	if keys == nil || keys.EscrowWrap == nil {
		slog.WarnContext(ctx, "local administrator rotation waits for the escrow key of a newer bundle")
		return
	}
	pub, err := escrow.ParsePublicKey(keys.EscrowWrap.PublicKeyPEM)
	if err != nil {
		slog.ErrorContext(ctx, "escrow key of the bundle unusable", "error", err)
		return
	}
	version, err := escrow.KeyVersion(keys.EscrowWrap.KeyID)
	if err != nil {
		slog.ErrorContext(ctx, "escrow key of the bundle unusable", "error", err)
		return
	}
	password, err := NewPassword()
	if err != nil {
		slog.ErrorContext(ctx, "generating a password failed", "error", err)
		return
	}
	ct, err := escrow.Encrypt(pub, password)
	if err != nil {
		clear(password)
		slog.ErrorContext(ctx, "encrypting the password failed", "error", err)
		return
	}
	generation := max(m.State.Generation, m.State.Attempted) + 1
	m.State.Attempted = generation
	if err := m.trySave(); err != nil {
		clear(password)
		return // a generation that is not recorded must not be uploaded
	}
	id, err := newUUID()
	if err == nil {
		err = m.Escrow.Upload(ctx, escrow.Request{EscrowID: id, Kind: escrow.KindAdminPassword, Generation: generation, KeyVersion: version, Ciphertext: ct})
	}
	if err != nil {
		clear(password)
		slog.WarnContext(ctx, "escrow upload failed; the rotation is retried later", "generation", generation, "error", err)
		return
	}
	now := m.Now()
	m.pending = &rotation{escrowID: id, generation: generation, password: password, deadline: now.Add(EscrowWait), nextPoll: now.Add(PollInterval)}
	slog.InfoContext(ctx, "local administrator rotation started", "username", spec.Username, "generation", generation, "reason", reason)
}

// poll checks the storage status of the pending rotation and applies the password once it is stored.
func (m *Manager) poll(ctx context.Context, spec *bundle.LocalAdminSpec) {
	p, now := m.pending, m.Now()
	if now.Before(p.nextPoll) {
		return
	}
	p.nextPoll = now.Add(PollInterval)
	status, err := m.Escrow.Status(ctx, p.escrowID)
	switch {
	case err == nil && status == escrow.StatusStored:
		m.apply(ctx, spec)
	case err == nil && status == escrow.StatusFailed:
		m.fail(ctx, protocol.RotationEscrowFailed)
	case !now.Before(p.deadline):
		m.fail(ctx, protocol.RotationEscrowTimeout)
	case err != nil:
		slog.WarnContext(ctx, "escrow status unavailable; polling again", "generation", p.generation, "error", err)
	}
}

// apply sets the stored password with chpasswd, repairs shell and group, records the new shadow hash and reports
// the rotation.
func (m *Manager) apply(ctx context.Context, spec *bundle.LocalAdminSpec) {
	p := m.pending
	input := make([]byte, 0, len(spec.Username)+len(p.password)+2)
	input = append(append(append(append(input, spec.Username...), ':'), p.password...), '\n')
	out, exit, err := m.Sys.Chpasswd(ctx, input)
	clear(input)
	if err == nil && exit != 0 {
		err = fmt.Errorf("chpasswd: exit %d: %s", exit, strings.TrimSpace(out))
	}
	if err != nil {
		slog.ErrorContext(ctx, "setting the local administrator password failed", "generation", p.generation, "error", err)
		m.fail(ctx, protocol.RotationApplyFailed)
		return
	}
	m.repairAccount(ctx, spec.Username)
	now := m.Now()
	acct, _ := m.read(ctx, spec.Username)
	m.State.Generation, m.State.RotatedAt, m.State.ShadowSHA256 = p.generation, &now, acct.hashSHA256()
	m.State.Tampered, m.State.RetryAt = nil, nil
	m.finish(protocol.CommandSucceeded, map[string]any{"generation": p.generation})
	m.Emit(protocol.EventLocalAdminRotated, protocol.LocalAdminRotated{Generation: p.generation})
	slog.InfoContext(ctx, "local administrator password rotated", "username", spec.Username, "generation", p.generation)
}

// fail ends the pending rotation; the previous password stays valid.
func (m *Manager) fail(ctx context.Context, reason string) {
	p := m.pending
	retry := m.Now().Add(RetryAfter)
	m.State.RetryAt = &retry
	m.finish(protocol.CommandFailed, map[string]any{"generation": p.generation, "reason": reason})
	m.Emit(protocol.EventLocalAdminRotationFailed, protocol.LocalAdminRotationFailed{Generation: p.generation, Reason: reason})
	slog.WarnContext(ctx, "local administrator rotation failed; the previous password stays valid", "generation", p.generation, "reason", reason)
}

// finish zeroes the password, reports the waiting commands and persists the state.
func (m *Manager) finish(status string, result map[string]any) {
	clear(m.pending.password)
	m.pending = nil
	for _, id := range m.State.Commands {
		m.Result(id, status, result)
	}
	m.State.Commands = nil
	m.save()
}

// trySave persists the state and logs a failure.
func (m *Manager) trySave() error {
	err := m.Save()
	if err != nil {
		slog.Error("saving the local administrator state failed", "error", err)
	}
	return err
}

// save persists the state; a failure is logged and the state is saved again with the next change.
func (m *Manager) save() { _ = m.trySave() }

// passwordAlphabet has 64 characters: each character carries 6 bits.
const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// PasswordLength gives 144 bits (architecture §12.2).
const PasswordLength = 24

// NewPassword returns a random password of PasswordLength characters of passwordAlphabet.
func NewPassword() ([]byte, error) {
	b := make([]byte, PasswordLength)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	for i := range b {
		b[i] = passwordAlphabet[b[i]&63]
	}
	return b, nil
}

// newUUID returns a random (version 4) UUID.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// ErrNoAdminGroup means the device has neither a sudo nor a wheel group.
var ErrNoAdminGroup = errors.New("localadmin: neither group sudo nor wheel exists")

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

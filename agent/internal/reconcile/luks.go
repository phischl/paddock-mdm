package reconcile

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Timing of LUKS escrows: the status is polled every LUKSPollInterval for at most LUKSEscrowWait.
const (
	LUKSPollInterval = 30 * time.Second
	LUKSEscrowWait   = 15 * time.Minute
)

// compliantKeyslots is the keyslot set of a compliant device (plan M4b decision 11).
var compliantKeyslots = []string{luks.KindRecovery, luks.KindTPM2PIN}

// LUKSEscrow uploads escrows of the device (device API, bound to the device).
type LUKSEscrow interface {
	Upload(ctx context.Context, req escrow.Request) error
	// UploadHeader announces a sealed header and uploads object to the presigned URL of the answer.
	UploadHeader(ctx context.Context, req escrow.Request, object []byte) error
	Status(ctx context.Context, escrowID string) (string, error)
}

// LUKS is the luks reconciler (plan M4b decisions 8–12) of a device installed with the Paddock autoinstall: once the
// first-boot disk setup is done it enrolls a recovery key, escrows it and the LUKS header, removes the install
// passphrase and then watches the keyslots. Each pass does at most one change; it never wipes a keyslot it did not
// create, except the install passphrase. It is used by one goroutine (the agent's run loop).
type LUKS struct {
	Tools  luks.Tools
	Layout paths.Layout
	Escrow LUKSEscrow
	State  *state.LUKS
	// Save persists State; Emit spools a device event.
	Save        func() error
	Emit        func(typ string, data any)
	Now         func() time.Time
	TPM2Present func() bool

	pending *luksEscrow
	health  *protocol.DiskHealth
}

// luksEscrow is an escrow waiting for the server: a recovery key (kept in memory until stored) or a header (with
// the digest of the metadata it was taken from).
type luksEscrow struct {
	kind       string
	escrowID   string
	generation int64
	key        []byte
	digest     string
	deadline   time.Time
	nextPoll   time.Time
}

// Tick polls a pending escrow and, with full or once an escrow finished, inventories the root volume and takes the
// next step. keys are the keys of the applied bundle. It returns the disk health, nil before the first inventory.
func (m *LUKS) Tick(ctx context.Context, keys *bundle.Keys, full bool) *protocol.DiskHealth {
	if m.pending != nil && m.poll(ctx) {
		full = true
	}
	if full {
		m.pass(ctx, keys)
	}
	return m.health
}

// pass inventories the volume, reports changed keyslots and takes at most one step.
func (m *LUKS) pass(ctx context.Context, keys *bundle.Keys) {
	vol, err := luks.Root(ctx, m.Tools)
	if errors.Is(err, luks.ErrNotEncrypted) {
		m.health = &protocol.DiskHealth{State: protocol.DiskNotEncrypted}
		return
	}
	if err != nil {
		slog.WarnContext(ctx, "LUKS inventory failed", "error", err)
		return
	}
	md, err := luks.Dump(ctx, m.Tools, vol.Device)
	if err != nil {
		if v, verr := luks.Version(ctx, m.Tools, vol.Device); verr == nil && v != 2 {
			m.health = &protocol.DiskHealth{State: protocol.DiskUnmanaged, LUKSVersion: v}
			return
		}
		slog.WarnContext(ctx, "LUKS inventory failed", "device", vol.Device, "error", err)
		return
	}
	kinds := md.Kinds()
	passphrase := exists(m.Layout.InstallPassphrase())
	if !passphrase && m.State.RecoveryAttempted == 0 && !md.Has(luks.KindRecovery) {
		m.health = m.report(protocol.DiskUnmanaged, kinds)
		return
	}
	if exists(m.Layout.DiskSetupPending()) {
		// The first-boot disk setup has not enrolled the PIN yet; its changes are no tampering.
		m.health = m.report(m.state(md, passphrase), kinds)
		return
	}
	m.watch(kinds)
	if m.pending == nil {
		if err := m.step(ctx, vol.Device, md, passphrase, keys); err != nil {
			slog.ErrorContext(ctx, "LUKS step failed; retrying at the next pass", "device", vol.Device, "error", err)
		}
		if md, err = luks.Dump(ctx, m.Tools, vol.Device); err != nil {
			slog.WarnContext(ctx, "LUKS inventory failed", "device", vol.Device, "error", err)
			return
		}
		kinds, passphrase = md.Kinds(), exists(m.Layout.InstallPassphrase())
	}
	m.health = m.report(m.state(md, passphrase), kinds)
}

// watch reports keyslots that differ from the recorded ones (plan M4b decision 12) and records the new set; the
// changed metadata makes the next steps escrow the header again.
func (m *LUKS) watch(kinds []string) {
	if m.State.Keyslots != nil && slices.Equal(kinds, m.State.Keyslots) {
		return
	}
	if m.State.Keyslots != nil {
		m.Emit(protocol.EventTamperKeyslotChanged, protocol.TamperKeyslotChanged{Before: m.State.Keyslots, After: kinds})
		slog.Warn("LUKS keyslots changed outside Paddock", "before", m.State.Keyslots, "after", kinds)
	}
	m.State.Keyslots = kinds
	m.save()
}

// step takes the next step: replace a recovery key that was lost before the server stored it, enroll and escrow a
// recovery key, escrow the current header, or remove the install passphrase.
func (m *LUKS) step(ctx context.Context, device string, md luks.Metadata, passphrase bool, keys *bundle.Keys) error {
	keyFile := m.Layout.InstallPassphrase()
	switch {
	case md.Has(luks.KindRecovery) && m.State.RecoveryAttempted > m.State.RecoveryStored && passphrase:
		// Enrolled by this agent, but the key was lost (restart, failed escrow) before the server stored it.
		slog.WarnContext(ctx, "replacing a recovery key the server never stored", "generation", m.State.RecoveryAttempted)
		return m.change(ctx, device, func() error { return luks.Wipe(ctx, m.Tools, device, keyFile, luks.KindRecovery) })
	case !md.Has(luks.KindRecovery) && passphrase:
		return m.escrowRecovery(ctx, device, keyFile, keys)
	case m.State.RecoveryStored == 0:
		return nil // a recovery keyslot this agent did not create: nothing to escrow
	case digest(md) != m.State.HeaderDigest:
		return m.escrowHeader(ctx, device, md, keys)
	case passphrase && md.Has(luks.KindTPM2PIN):
		return m.removePassphrase(ctx, device, keyFile)
	}
	return nil
}

// escrowRecovery enrolls a recovery key and uploads it encrypted to escrow-wrap; the key stays in memory until the
// server stored it.
func (m *LUKS) escrowRecovery(ctx context.Context, device, keyFile string, keys *bundle.Keys) error {
	pub, version, err := escrowKey(keys)
	if err != nil {
		return err
	}
	generation := m.State.RecoveryAttempted + 1
	m.State.RecoveryAttempted = generation
	if err := m.Save(); err != nil {
		return err // a generation that is not recorded must not be enrolled
	}
	var key []byte
	if err := m.change(ctx, device, func() error {
		key, err = luks.EnrollRecovery(ctx, m.Tools, device, keyFile)
		return err
	}); err != nil {
		return err
	}
	ct, err := escrow.Encrypt(pub, key)
	if err != nil {
		clear(key)
		return err
	}
	id, err := newUUID()
	if err != nil {
		clear(key)
		return err
	}
	// A failed upload loses the key: the next pass replaces the keyslot with a new generation.
	if err := m.Escrow.Upload(ctx, escrow.Request{EscrowID: id, Kind: escrow.KindLUKSRecoveryKey, Generation: generation,
		KeyVersion: version, Ciphertext: ct}); err != nil {
		clear(key)
		return fmt.Errorf("escrow the recovery key: %w", err)
	}
	slog.InfoContext(ctx, "recovery key enrolled and uploaded for escrow", "generation", generation)
	m.start(luksEscrow{kind: escrow.KindLUKSRecoveryKey, escrowID: id, generation: generation, key: key})
	return nil
}

// escrowHeader backs the header up to tmpfs, seals it to escrow-wrap and uploads it; the backup file is removed at
// once.
func (m *LUKS) escrowHeader(ctx context.Context, device string, md luks.Metadata, keys *bundle.Keys) error {
	pub, version, err := escrowKey(keys)
	if err != nil {
		return err
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	dir := m.Layout.HeaderBackupDir()
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // /run/paddock; the backup itself is 0600
		return err
	}
	file := filepath.Join(dir, "luks-header-"+id+".img")
	err = luks.HeaderBackup(ctx, m.Tools, device, file)
	header, rerr := os.ReadFile(file) //nolint:gosec // a file this function named
	_ = os.Remove(file)
	if err == nil {
		err = rerr
	}
	if err != nil {
		return fmt.Errorf("header backup: %w", err)
	}
	sealed, err := escrow.SealHeader(pub, header, id)
	clear(header)
	if err != nil {
		return err
	}
	generation := max(m.State.HeaderAttempted, m.State.HeaderStored) + 1
	m.State.HeaderAttempted = generation
	if err := m.Save(); err != nil {
		return err
	}
	if err := m.Escrow.UploadHeader(ctx, escrow.Request{EscrowID: id, Kind: escrow.KindLUKSHeader, Generation: generation,
		KeyVersion: version, WrappedDEK: sealed.WrappedDEK, Nonce: sealed.Nonce, SHA256: sealed.SHA256,
		Size: int64(len(sealed.Object))}, sealed.Object); err != nil {
		return fmt.Errorf("escrow the header: %w", err)
	}
	slog.InfoContext(ctx, "LUKS header uploaded for escrow", "generation", generation, "size", len(sealed.Object))
	m.start(luksEscrow{kind: escrow.KindLUKSHeader, escrowID: id, generation: generation, digest: digest(md)})
	return nil
}

// removePassphrase wipes the install passphrase keyslot and, once exactly TPM2+PIN and the recovery key remain,
// deletes the passphrase file (plan M4b decision 11).
func (m *LUKS) removePassphrase(ctx context.Context, device, keyFile string) error {
	if err := m.change(ctx, device, func() error { return luks.Wipe(ctx, m.Tools, device, keyFile, luks.KindPassword) }); err != nil {
		return err
	}
	md, err := luks.Dump(ctx, m.Tools, device)
	if err != nil {
		return err
	}
	if !slices.Equal(md.Kinds(), compliantKeyslots) {
		return fmt.Errorf("after removing the install passphrase the keyslots are %v, not %v", md.Kinds(), compliantKeyslots)
	}
	if err := shred(keyFile); err != nil {
		return fmt.Errorf("delete the install passphrase: %w", err)
	}
	slog.InfoContext(ctx, "install passphrase removed; the disk unlocks with TPM2+PIN or the recovery key")
	return nil
}

// change runs a keyslot change of this agent and records the resulting keyslots, so that it is not reported as
// tampering.
func (m *LUKS) change(ctx context.Context, device string, fn func() error) error {
	err := fn()
	if md, derr := luks.Dump(ctx, m.Tools, device); derr == nil {
		m.State.Keyslots = md.Kinds()
		m.save()
	}
	return err
}

// start records an escrow that waits for the server.
func (m *LUKS) start(e luksEscrow) {
	now := m.Now()
	e.deadline, e.nextPoll = now.Add(LUKSEscrowWait), now.Add(LUKSPollInterval)
	m.pending = &e
}

// poll checks the pending escrow and reports whether it finished; one the server refused or did not store in time is
// dropped, and the next pass starts over with a new generation.
func (m *LUKS) poll(ctx context.Context) bool {
	p, now := m.pending, m.Now()
	if now.Before(p.nextPoll) {
		return false
	}
	p.nextPoll = now.Add(LUKSPollInterval)
	status, err := m.Escrow.Status(ctx, p.escrowID)
	switch {
	case err == nil && status == escrow.StatusStored:
		if p.kind == escrow.KindLUKSRecoveryKey {
			m.State.RecoveryStored = p.generation
		} else {
			m.State.HeaderStored, m.State.HeaderDigest = p.generation, p.digest
		}
		slog.InfoContext(ctx, "LUKS escrow stored", "kind", p.kind, "generation", p.generation)
	case err == nil && status == escrow.StatusFailed, !now.Before(p.deadline):
		slog.WarnContext(ctx, "LUKS escrow not stored; starting over", "kind", p.kind, "generation", p.generation, "status", status)
	default:
		if err != nil {
			slog.WarnContext(ctx, "escrow status unavailable; polling again", "kind", p.kind, "error", err)
		}
		return false
	}
	clear(p.key)
	m.pending = nil
	m.save()
	return true
}

// state is the disk state of a managed volume.
func (m *LUKS) state(md luks.Metadata, passphrase bool) string {
	switch {
	case !md.Has(luks.KindTPM2PIN) && !md.Has(luks.KindTPM2) && !m.TPM2Present():
		return protocol.DiskTPMMissing
	case !md.Has(luks.KindTPM2PIN):
		return protocol.DiskTPMPINMissing
	case passphrase || m.pending != nil || m.State.RecoveryStored == 0 || digest(md) != m.State.HeaderDigest ||
		!slices.Equal(md.Kinds(), compliantKeyslots):
		return protocol.DiskEscrowPending
	}
	return protocol.DiskCompliant
}

func (m *LUKS) report(s string, kinds []string) *protocol.DiskHealth {
	return &protocol.DiskHealth{State: s, LUKSVersion: 2, Tokens: kinds, Keyslots: len(kinds)}
}

func (m *LUKS) save() {
	if err := m.Save(); err != nil {
		slog.Error("saving the LUKS state failed", "error", err)
	}
}

// escrowKey is the escrow-wrap key of the bundle.
func escrowKey(keys *bundle.Keys) (*rsa.PublicKey, int, error) {
	if keys == nil || keys.EscrowWrap == nil {
		return nil, 0, errors.New("the escrow key arrives with a newer bundle")
	}
	pub, err := escrow.ParsePublicKey(keys.EscrowWrap.PublicKeyPEM)
	if err != nil {
		return nil, 0, err
	}
	version, err := escrow.KeyVersion(keys.EscrowWrap.KeyID)
	return pub, version, err
}

// digest identifies the LUKS2 metadata: keyslots, tokens, digests and segments.
func digest(md luks.Metadata) string {
	sum := sha256.Sum256(md.Raw)
	return hex.EncodeToString(sum[:])
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// shred overwrites a file with zeros, flushes it and removes it.
func shred(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // the install passphrase of the layout
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil {
		_, err = f.Write(make([]byte, info.Size()))
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Remove(path)
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

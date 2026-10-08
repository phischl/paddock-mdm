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
	"strings"
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
// passphrase and then watches the keyslots. Each pass does at most one change. It removes only the keyslots it
// recorded — the install passphrase's, found before the first change, and the one its recovery key was enrolled in —
// never another keyslot of the same kind (plan M4b.1 decision 3). Once the root volume is escrowed, it escrows the
// header of every other LUKS volume of /etc/crypttab — the volumes paddock-revoke erases — and escrows it again after
// a keyslot change (PDK-009 decisions 1–3); it never changes their keyslots and adds no recovery key to them. It is
// used by one goroutine (the agent's run loop).
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

	pending  *luksEscrow
	health   *protocol.DiskHealth
	rootUUID string // the LUKS UUID of the root volume in the current pass ("" when cryptsetup reported none)
	// volumeSet identifies the volumes of /etc/crypttab of the last pass (their UUIDs, sorted).
	volumeSet string
}

// RefusedRetry is how long the agent does not escrow a volume again whose header the server refused, unless the
// volumes of /etc/crypttab change (PDK-009 review round 2).
const RefusedRetry = 24 * time.Hour

// CrypttabWithin bounds the classification of /etc/crypttab in a pass (as paddock-revoke's SelectWithin).
const CrypttabWithin = time.Minute

// luksEscrow is an escrow waiting for the server: a recovery key (kept in memory until stored) or a header of the
// root volume or of volume (with the digest of the metadata it was taken from).
type luksEscrow struct {
	kind       string
	escrowID   string
	generation int64
	key        []byte
	digest     string
	root       bool
	volume     string
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
	if m.rootUUID, err = luks.UUID(ctx, m.Tools, vol.Device); err != nil {
		slog.WarnContext(ctx, "the LUKS UUID of the root volume is unknown", "device", vol.Device, "error", err)
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
	m.volumes(ctx, vol.Device, md, keys)
}

// volumes inventories the root volume and every other LUKS volume of /etc/crypttab for health.disk, reports changed
// keyslots of the other volumes and, once the root volume's current header is stored and no escrow is pending,
// escrows the header of the first volume whose current header is not stored (PDK-009 decisions 1–4). The disk is
// compliant only when every volume is escrowed.
func (m *LUKS) volumes(ctx context.Context, rootDevice string, root luks.Metadata, keys *bundle.Keys) {
	h := m.health
	rootEscrowed := m.pending == nil && m.State.HeaderStored > 0 && digest(root) == m.State.HeaderDigest
	h.Volumes = []protocol.DiskVolume{{UUID: m.rootUUID, Device: rootDevice, Root: true, LUKSVersion: 2, Tokens: h.Tokens,
		Keyslots: h.Keyslots, Escrowed: rootEscrowed, HeaderGeneration: m.State.HeaderStored}}
	ready := rootEscrowed && m.State.RecoveryStored > 0
	ct := luks.ReadCrypttab(ctx, m.Tools, m.Layout.Root, rootDevice, CrypttabWithin)
	h.Unresolved = ct.Unresolved
	m.volumeSet = volumeSet(ct)
	for _, v := range ct.Volumes {
		dv := protocol.DiskVolume{UUID: v.UUID, Device: v.Header}
		if v.Shared {
			// A cloned header cannot be told apart by its UUID: it is neither escrowed nor tracked (review round 2).
			dv.SharedUUID = true
			h.Volumes = append(h.Volumes, dv)
			continue
		}
		inv, err := luks.Inspect(ctx, m.Tools, v.Header)
		if err != nil || v.UUID == "" {
			slog.WarnContext(ctx, "LUKS volume not inventoried", "device", v.Header, "uuid", v.UUID, "error", err)
			h.Volumes = append(h.Volumes, dv)
			continue
		}
		st := m.volumeState(v.UUID)
		m.watchVolume(v.UUID, st, inv.Kinds)
		dv.LUKSVersion, dv.Tokens, dv.Keyslots, dv.HeaderGeneration = inv.Version, inv.Kinds, len(inv.Kinds), st.HeaderStored
		dv.Escrowed = st.HeaderStored > 0 && st.HeaderDigest == inv.Digest && !m.pendingFor(v.UUID)
		dv.Refused = m.refused(st)
		if !dv.Escrowed && !dv.Refused && ready && m.pending == nil {
			if err := m.escrowHeader(ctx, v.Header, v.UUID, false, inv.Digest, keys); err != nil {
				slog.ErrorContext(ctx, "LUKS header escrow failed; retrying at the next pass", "device", v.Header, "volume", v.UUID, "error", err)
			}
		}
		h.Volumes = append(h.Volumes, dv)
	}
	if h.State == protocol.DiskCompliant && slices.ContainsFunc(h.Volumes, func(v protocol.DiskVolume) bool { return !v.Escrowed }) {
		h.State = protocol.DiskEscrowPending
	}
}

// volumeState is the recorded state of a volume other than the root volume.
func (m *LUKS) volumeState(uuid string) *state.LUKSVolume {
	if m.State.Volumes == nil {
		m.State.Volumes = map[string]*state.LUKSVolume{}
	}
	st, ok := m.State.Volumes[uuid]
	if !ok {
		st = &state.LUKSVolume{}
		m.State.Volumes[uuid] = st
	}
	return st
}

// watchVolume reports keyslots of a volume other than the root volume that differ from the recorded ones (PDK-009
// decision 3); the changed metadata makes the volume's header escrowed again. The first inventory only records.
func (m *LUKS) watchVolume(uuid string, st *state.LUKSVolume, kinds []string) {
	if st.Keyslots != nil && slices.Equal(kinds, st.Keyslots) {
		return
	}
	if st.Keyslots != nil {
		m.Emit(protocol.EventTamperKeyslotChanged, protocol.TamperKeyslotChanged{Volume: uuid, Before: st.Keyslots, After: kinds})
		slog.Warn("LUKS keyslots changed outside Paddock", "volume", uuid, "before", st.Keyslots, "after", kinds)
	}
	st.Keyslots = kinds
	m.save()
}

// refused reports whether the server refused the volume's header within RefusedRetry while /etc/crypttab lists the
// same volumes.
func (m *LUKS) refused(st *state.LUKSVolume) bool {
	return st.RefusedAt != nil && m.Now().Before(st.RefusedAt.Add(RefusedRetry)) && st.RefusedSet == m.volumeSet
}

// volumeSet identifies the volumes of a crypttab selection: their UUIDs (or headers without one), sorted.
func volumeSet(ct luks.Crypttab) string {
	ids := make([]string, 0, len(ct.Volumes))
	for _, v := range ct.Volumes {
		id := v.UUID
		if id == "" {
			id = v.Header
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return strings.Join(ids, ",")
}

// pendingFor reports whether a header escrow of volume waits for the server.
func (m *LUKS) pendingFor(volume string) bool {
	return m.pending != nil && !m.pending.root && m.pending.volume == volume
}

// watch reports keyslots that differ from the recorded ones (plan M4b decision 12) and records the new set; the
// changed metadata makes the next steps escrow the header again.
func (m *LUKS) watch(kinds []string) {
	if m.State.Keyslots != nil && slices.Equal(kinds, m.State.Keyslots) {
		return
	}
	if m.State.Keyslots != nil {
		m.Emit(protocol.EventTamperKeyslotChanged, protocol.TamperKeyslotChanged{Volume: m.rootUUID, Before: m.State.Keyslots, After: kinds})
		slog.Warn("LUKS keyslots changed outside Paddock", "volume", m.rootUUID, "before", m.State.Keyslots, "after", kinds)
	}
	m.State.Keyslots = kinds
	m.save()
}

// step takes the next step: replace a recovery key that was lost before the server stored it, enroll and escrow a
// recovery key, escrow the current header, or remove the install passphrase. The install passphrase's keyslot is
// recorded first.
func (m *LUKS) step(ctx context.Context, device string, md luks.Metadata, passphrase bool, keys *bundle.Keys) error {
	keyFile := m.Layout.InstallPassphrase()
	if passphrase && m.State.PassphraseSlot == nil {
		if err := m.recordPassphraseSlot(ctx, device, keyFile, md); err != nil {
			return err
		}
	}
	own := m.State.RecoverySlot != nil && md.Kind(*m.State.RecoverySlot) == luks.KindRecovery
	switch {
	case own && m.State.RecoveryAttempted > m.State.RecoveryStored && passphrase:
		// Enrolled by this agent, but the key was lost (restart, failed escrow) before the server stored it.
		slog.WarnContext(ctx, "replacing a recovery key the server never stored", "generation", m.State.RecoveryAttempted,
			"keyslot", *m.State.RecoverySlot)
		return m.change(ctx, device, func() error {
			if err := m.wipe(ctx, device, keyFile, md, *m.State.RecoverySlot, luks.KindRecovery); err != nil {
				return err
			}
			m.State.RecoverySlot = nil
			return nil
		})
	case !own && passphrase:
		return m.escrowRecovery(ctx, device, keyFile, md, keys)
	case m.State.RecoveryStored == 0:
		return nil // a recovery keyslot this agent did not create: nothing to escrow
	case digest(md) != m.State.HeaderDigest:
		return m.escrowHeader(ctx, device, m.rootUUID, true, digest(md), keys)
	case passphrase && md.Has(luks.KindTPM2PIN):
		return m.removePassphrase(ctx, device, keyFile, md)
	}
	return nil
}

// recordPassphraseSlot records the keyslot the install passphrase opens.
func (m *LUKS) recordPassphraseSlot(ctx context.Context, device, keyFile string, md luks.Metadata) error {
	slot, err := luks.KeySlot(ctx, m.Tools, device, keyFile)
	if err != nil {
		return fmt.Errorf("find the keyslot of the install passphrase: %w", err)
	}
	if kind := md.Kind(slot); kind != luks.KindPassword {
		return fmt.Errorf("the install passphrase opens keyslot %d of kind %q, not a passphrase keyslot", slot, kind)
	}
	m.State.PassphraseSlot = &slot
	slog.InfoContext(ctx, "install passphrase keyslot recorded", "keyslot", slot)
	return m.Save()
}

// wipe removes the recorded keyslot slot if it still is of kind.
func (m *LUKS) wipe(ctx context.Context, device, keyFile string, md luks.Metadata, slot int, kind string) error {
	if got := md.Kind(slot); got != kind {
		return fmt.Errorf("keyslot %d is %q, not the recorded %s keyslot; it is not removed", slot, got, kind)
	}
	return luks.WipeSlot(ctx, m.Tools, device, keyFile, slot)
}

// escrowRecovery enrolls a recovery key, records its keyslot (the recovery keyslot that was not there before) and
// uploads the key encrypted to escrow-wrap; the key stays in memory until the server stored it.
func (m *LUKS) escrowRecovery(ctx context.Context, device, keyFile string, before luks.Metadata, keys *bundle.Keys) error {
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
	if err := m.recordRecoverySlot(ctx, device, before); err != nil {
		clear(key)
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

// recordRecoverySlot records the one recovery keyslot that the enrollment added to before.
func (m *LUKS) recordRecoverySlot(ctx context.Context, device string, before luks.Metadata) error {
	after, err := luks.Dump(ctx, m.Tools, device)
	if err != nil {
		return err
	}
	var added []int
	for _, slot := range after.Slots(luks.KindRecovery) {
		if before.Kind(slot) != luks.KindRecovery {
			added = append(added, slot)
		}
	}
	if len(added) != 1 {
		return fmt.Errorf("the recovery key enrollment added the recovery keyslots %v, not exactly one", added)
	}
	m.State.RecoverySlot = &added[0]
	return m.Save()
}

// escrowHeader backs the header of device (the LUKS volume with UUID volume, the root volume if root) up to tmpfs,
// seals it to escrow-wrap and uploads it with sum, the digest of the metadata it was taken from; the backup file is
// removed at once. Header generations count across all volumes.
func (m *LUKS) escrowHeader(ctx context.Context, device, volume string, root bool, sum string, keys *bundle.Keys) error {
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
		Volume: volume, KeyVersion: version, WrappedDEK: sealed.WrappedDEK, Nonce: sealed.Nonce, SHA256: sealed.SHA256,
		Size: int64(len(sealed.Object))}, sealed.Object); err != nil {
		return fmt.Errorf("escrow the header: %w", err)
	}
	slog.InfoContext(ctx, "LUKS header uploaded for escrow", "volume", volume, "generation", generation, "size", len(sealed.Object))
	m.start(luksEscrow{kind: escrow.KindLUKSHeader, escrowID: id, generation: generation, digest: sum, root: root, volume: volume})
	return nil
}

// removePassphrase wipes the install passphrase's keyslot and, once it is gone and TPM2+PIN and the agent's recovery
// key remain, deletes the passphrase file (plan M4b decision 11). Other keyslots stay; if the result is not exactly
// TPM2+PIN and the recovery key, the extra keyslots are reported as tamper.keyslot_changed (plan M4b.1 decision 3).
func (m *LUKS) removePassphrase(ctx context.Context, device, keyFile string, before luks.Metadata) error {
	slot := *m.State.PassphraseSlot
	if err := m.change(ctx, device, func() error { return m.wipe(ctx, device, keyFile, before, slot, luks.KindPassword) }); err != nil {
		return err
	}
	md, err := luks.Dump(ctx, m.Tools, device)
	if err != nil {
		return err
	}
	if md.Kind(slot) != "" || !md.Has(luks.KindTPM2PIN) || m.State.RecoverySlot == nil || md.Kind(*m.State.RecoverySlot) != luks.KindRecovery {
		return fmt.Errorf("after removing the install passphrase (keyslot %d) the keyslots are %v", slot, md.Kinds())
	}
	if err := shred(keyFile); err != nil {
		return fmt.Errorf("delete the install passphrase: %w", err)
	}
	slog.InfoContext(ctx, "install passphrase removed; the disk unlocks with TPM2+PIN or the recovery key", "keyslot", slot)
	if kinds := md.Kinds(); !slices.Equal(kinds, compliantKeyslots) {
		m.Emit(protocol.EventTamperKeyslotChanged, protocol.TamperKeyslotChanged{Volume: m.rootUUID, Before: compliantKeyslots, After: kinds})
		slog.WarnContext(ctx, "LUKS keyslots not created by Paddock are kept", "expected", compliantKeyslots, "keyslots", kinds)
	}
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
		switch {
		case p.kind == escrow.KindLUKSRecoveryKey:
			m.State.RecoveryStored = p.generation
		case p.root:
			m.State.HeaderStored, m.State.HeaderDigest = p.generation, p.digest
		default:
			st := m.volumeState(p.volume)
			st.HeaderStored, st.HeaderDigest, st.RefusedAt, st.RefusedSet = p.generation, p.digest, nil, ""
		}
		slog.InfoContext(ctx, "LUKS escrow stored", "kind", p.kind, "volume", p.volume, "generation", p.generation)
	case err == nil && status == escrow.StatusRefused && !p.root:
		st := m.volumeState(p.volume)
		at := now
		st.RefusedAt, st.RefusedSet = &at, m.volumeSet
		slog.WarnContext(ctx, "the server refused the LUKS header: the device escrows the most volumes a revocation token carries; not retried for a day",
			"volume", p.volume, "generation", p.generation)
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

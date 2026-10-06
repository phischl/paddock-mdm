package reconcile_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const testRecoveryKey = "fhjdtbcl-cuhkvnbr-huhbbcbt-klhvrgcj-kvjrhfdv-fnvlechn-rvgrgtiu-cnfdjbnl"

// volume simulates the LUKS2 root volume /dev/sda3 behind the LUKS tools: its keyslots by kind (nil: a free slot).
type volume struct {
	t          *testing.T
	slots      []string
	plain      bool // the root is not on LUKS
	keyFile    string
	failEnroll bool
	changes    []string // keyslot changes made through the tools
}

func (v *volume) Command(_ context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	switch {
	case name == "findmnt":
		return "/dev/mapper/vg-root\n", "", 0, nil
	case name == "lsblk" && v.plain:
		return `{"blockdevices":[{"name":"/dev/mapper/vg-root","type":"lvm","fstype":"ext4","children":[{"name":"/dev/sda3","type":"part","fstype":"LVM2_member"}]}]}`, "", 0, nil
	case name == "lsblk":
		return `{"blockdevices":[{"name":"/dev/mapper/vg-root","type":"lvm","fstype":"ext4","children":[{"name":"/dev/mapper/dm_crypt-0","type":"crypt","fstype":"LVM2_member","children":[{"name":"/dev/sda3","type":"part","fstype":"crypto_LUKS"}]}]}]}`, "", 0, nil
	case line == "cryptsetup luksDump --dump-json-metadata -- /dev/sda3":
		return v.metadata(), "", 0, nil
	case line == "systemd-cryptenroll --recovery-key --unlock-key-file="+v.keyFile+" /dev/sda3":
		if v.failEnroll {
			return "", "Failed to unlock", 1, nil
		}
		v.add("recovery")
		return testRecoveryKey + "\n", "", 0, nil
	case strings.HasPrefix(line, "systemd-cryptenroll --wipe-slot="):
		kind := strings.TrimPrefix(args[0], "--wipe-slot=")
		v.changes = append(v.changes, "wipe "+kind)
		for i, k := range v.slots {
			if k == kind {
				v.slots[i] = ""
			}
		}
		return "", "", 0, nil
	case strings.HasPrefix(line, "cryptsetup luksHeaderBackup /dev/sda3 --header-backup-file "):
		file := args[3]
		if _, err := os.Stat(file); err == nil {
			return "", "file exists", 1, nil
		}
		return "", "", 0, os.WriteFile(file, []byte(v.metadata()+strings.Repeat("\x00", 4096)), 0o600)
	}
	v.t.Errorf("unexpected command %s", line)
	return "", "", -1, errors.New("unexpected command")
}

func (v *volume) add(kind string) {
	v.changes = append(v.changes, "add "+kind)
	for i, k := range v.slots {
		if k == "" {
			v.slots[i] = kind
			return
		}
	}
	v.slots = append(v.slots, kind)
}

// metadata renders the LUKS2 JSON metadata of the keyslots.
func (v *volume) metadata() string {
	keyslots, tokens := map[string]any{}, map[string]any{}
	for i, kind := range v.slots {
		if kind == "" {
			continue
		}
		slot := strconv.Itoa(i)
		keyslots[slot] = map[string]any{"type": "luks2"}
		switch kind {
		case "tpm2+pin":
			tokens[slot] = map[string]any{"type": "systemd-tpm2", "keyslots": []string{slot}, "tpm2-pin": true, "tpm2-pcrs": []int{7}}
		case "recovery":
			tokens[slot] = map[string]any{"type": "systemd-recovery", "keyslots": []string{slot}}
		}
	}
	b, _ := json.Marshal(map[string]any{"keyslots": keyslots, "tokens": tokens, "segments": map[string]any{}})
	return string(b)
}

// escrowServer answers escrows like the server: status by escrow ID, stored unless answer says otherwise.
type escrowServer struct {
	key       *rsa.PrivateKey
	requests  []escrow.Request
	objects   map[string][]byte
	answer    func(req escrow.Request) string
	uploadErr error
}

func (e *escrowServer) Upload(_ context.Context, req escrow.Request) error {
	if e.uploadErr != nil {
		return e.uploadErr
	}
	e.requests = append(e.requests, req)
	return nil
}

func (e *escrowServer) UploadHeader(ctx context.Context, req escrow.Request, object []byte) error {
	if err := e.Upload(ctx, req); err != nil {
		return err
	}
	e.objects[req.EscrowID] = object
	return nil
}

func (e *escrowServer) Status(_ context.Context, id string) (string, error) {
	for _, r := range e.requests {
		if r.EscrowID == id {
			if e.answer != nil {
				return e.answer(r), nil
			}
			return escrow.StatusStored, nil
		}
	}
	return escrow.StatusPending, nil
}

func (e *escrowServer) of(kind string) []escrow.Request {
	var out []escrow.Request
	for _, r := range e.requests {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

type luksFixture struct {
	t      *testing.T
	m      *reconcile.LUKS
	vol    *volume
	server *escrowServer
	layout paths.Layout
	st     state.LUKS
	events []protocol.Event
	now    time.Time
	keys   *bundle.Keys
	tpm    bool
}

func newLUKSFixture(t *testing.T, slots ...string) *luksFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	f := &luksFixture{t: t, layout: paths.Layout{Root: t.TempDir()}, now: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC), tpm: true,
		server: &escrowServer{key: key, objects: map[string][]byte{}},
		keys: &bundle.Keys{EscrowWrap: &bundle.EncryptionKey{KeyID: "escrow-wrap:v1",
			PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}}
	f.vol = &volume{t: t, slots: slots, keyFile: f.layout.InstallPassphrase()}
	f.write(f.layout.InstallPassphrase(), "installpassphrase")
	f.m = &reconcile.LUKS{Tools: f.vol, Layout: f.layout, Escrow: f.server, State: &f.st, Save: func() error { return nil },
		Emit: func(typ string, data any) {
			raw, _ := json.Marshal(data)
			f.events = append(f.events, protocol.Event{Type: typ, Data: raw})
		},
		Now: func() time.Time { return f.now }, TPM2Present: func() bool { return f.tpm }}
	return f
}

func (f *luksFixture) write(path, content string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// pass runs a full pass and returns the disk state.
func (f *luksFixture) pass() string {
	f.t.Helper()
	h := f.m.Tick(context.Background(), f.keys, true)
	if h == nil {
		f.t.Fatal("no disk health")
	}
	return h.State
}

// poll lets the poll interval pass and ticks without a full pass.
func (f *luksFixture) poll() string {
	f.t.Helper()
	f.now = f.now.Add(reconcile.LUKSPollInterval)
	return f.m.Tick(context.Background(), f.keys, false).State
}

func (f *luksFixture) passphrase() bool {
	_, err := os.Stat(f.layout.InstallPassphrase())
	return err == nil
}

func TestLUKSToCompliant(t *testing.T) {
	f := newLUKSFixture(t, "password", "tpm2+pin")
	if s := f.pass(); s != protocol.DiskEscrowPending || len(f.server.of(escrow.KindLUKSRecoveryKey)) != 1 {
		t.Fatalf("first pass: %s, escrows %+v", s, f.server.requests)
	}
	rec := f.server.of(escrow.KindLUKSRecoveryKey)[0]
	ct, _ := base64.StdEncoding.DecodeString(rec.Ciphertext)
	plain, err := rsa.DecryptOAEP(sha256.New(), nil, f.server.key, ct, nil)
	if err != nil || string(plain) != testRecoveryKey || rec.Generation != 1 || rec.KeyVersion != 1 {
		t.Fatalf("escrowed recovery key %q generation %d: %v", plain, rec.Generation, err)
	}
	if f.pass(); len(f.server.requests) != 1 {
		t.Fatal("a pass while the recovery key is pending must not start another escrow")
	}
	// Stored: the header is escrowed next.
	if s := f.poll(); s != protocol.DiskEscrowPending || len(f.server.of(escrow.KindLUKSHeader)) != 1 || f.st.RecoveryStored != 1 {
		t.Fatalf("after the recovery key: %s %+v", s, f.st)
	}
	f.checkHeader(f.server.of(escrow.KindLUKSHeader)[0], 1)
	// Stored: the install passphrase goes, and the header changed by that is escrowed again.
	if s := f.poll(); s != protocol.DiskEscrowPending || f.passphrase() || !slices.Equal(f.vol.slots, []string{"", "tpm2+pin", "recovery"}) {
		t.Fatalf("after the header: %s, passphrase %v, slots %v", s, f.passphrase(), f.vol.slots)
	}
	if s := f.pass(); s != protocol.DiskEscrowPending || len(f.server.of(escrow.KindLUKSHeader)) != 2 {
		t.Fatalf("second header: %s %+v", s, f.server.requests)
	}
	f.checkHeader(f.server.of(escrow.KindLUKSHeader)[1], 2)
	if s := f.poll(); s != protocol.DiskCompliant {
		t.Fatalf("final state %s %+v", s, f.st)
	}
	if s := f.pass(); s != protocol.DiskCompliant || len(f.server.requests) != 3 || len(f.events) != 0 {
		t.Fatalf("steady state %s, %d escrows, events %v", s, len(f.server.requests), f.events)
	}
	if !slices.Equal(f.vol.changes, []string{"add recovery", "wipe password"}) {
		t.Fatalf("keyslot changes %v", f.vol.changes)
	}
	h := f.m.Tick(context.Background(), f.keys, true)
	if h.LUKSVersion != 2 || h.Keyslots != 2 || !slices.Equal(h.Tokens, []string{"recovery", "tpm2+pin"}) {
		t.Fatalf("health %+v", h)
	}
}

// checkHeader opens an escrowed header with the server's key.
func (f *luksFixture) checkHeader(req escrow.Request, generation int64) {
	f.t.Helper()
	object := f.server.objects[req.EscrowID]
	wrapped, _ := base64.StdEncoding.DecodeString(req.WrappedDEK)
	dek, err := rsa.DecryptOAEP(sha256.New(), nil, f.server.key, wrapped, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(req.Nonce)
	header, err := escrow.OpenHeader(dek, nonce, req.EscrowID, object)
	sum := sha256.Sum256(object)
	if err != nil || !bytes.HasPrefix(header, []byte(`{"keyslots"`)) || req.Generation != generation || req.Size != int64(len(object)) ||
		req.SHA256 != fmt.Sprintf("%x", sum) {
		f.t.Fatalf("header generation %d (want %d): %v", req.Generation, generation, err)
	}
	if entries, _ := os.ReadDir(f.layout.HeaderBackupDir()); len(entries) != 0 {
		f.t.Fatalf("header backup left in %s", f.layout.HeaderBackupDir())
	}
}

func (f *luksFixture) toCompliant() {
	f.t.Helper()
	f.pass()
	for range 3 {
		f.poll()
		f.pass()
	}
	if s := f.pass(); s != protocol.DiskCompliant {
		f.t.Fatalf("not compliant: %s %+v", s, f.st)
	}
}

func TestLUKSTamper(t *testing.T) {
	f := newLUKSFixture(t, "password", "tpm2+pin")
	f.toCompliant()
	headers := len(f.server.of(escrow.KindLUKSHeader))
	f.vol.slots = append(f.vol.slots, "password") // someone adds a passphrase
	if s := f.pass(); s != protocol.DiskEscrowPending || len(f.events) != 1 || f.events[0].Type != protocol.EventTamperKeyslotChanged {
		t.Fatalf("tamper: %s, events %v", s, f.events)
	}
	var data protocol.TamperKeyslotChanged
	_ = json.Unmarshal(f.events[0].Data, &data)
	if !slices.Equal(data.Before, []string{"recovery", "tpm2+pin"}) || !slices.Equal(data.After, []string{"password", "recovery", "tpm2+pin"}) {
		t.Fatalf("tamper data %+v", data)
	}
	if len(f.server.of(escrow.KindLUKSHeader)) != headers+1 {
		t.Fatal("the changed header was not escrowed again")
	}
	f.poll()
	// The foreign keyslot stays (the agent never wipes what it did not create): reported once, not compliant.
	if s := f.pass(); s != protocol.DiskEscrowPending || len(f.events) != 1 {
		t.Fatalf("after the tamper: %s, events %d, changes %v", s, len(f.events), f.vol.changes)
	}
	if n := strings.Count(strings.Join(f.vol.changes, ","), "wipe password"); n != 1 {
		t.Fatalf("the added passphrase was wiped: %v", f.vol.changes)
	}
}

func TestLUKSPINSkipped(t *testing.T) {
	f := newLUKSFixture(t, "password")
	f.pass()
	f.poll()
	f.pass()
	if s := f.poll(); s != protocol.DiskTPMPINMissing || !f.passphrase() || slices.Contains(f.vol.changes, "wipe password") {
		t.Fatalf("skipped PIN: %s, passphrase %v, changes %v", s, f.passphrase(), f.vol.changes)
	}
	if len(f.server.of(escrow.KindLUKSRecoveryKey)) != 1 || len(f.server.of(escrow.KindLUKSHeader)) != 1 {
		t.Fatalf("escrows %+v", f.server.requests)
	}
	f.tpm = false
	if s := f.pass(); s != protocol.DiskTPMMissing {
		t.Fatalf("without TPM: %s", s)
	}
}

func TestLUKSUnmanagedAndPlain(t *testing.T) {
	f := newLUKSFixture(t, "password")
	if err := os.Remove(f.layout.InstallPassphrase()); err != nil {
		t.Fatal(err)
	}
	if s := f.pass(); s != protocol.DiskUnmanaged || len(f.vol.changes) != 0 || len(f.server.requests) != 0 || f.st.Keyslots != nil {
		t.Fatalf("unmanaged: %s %v", s, f.vol.changes)
	}
	f.vol.plain = true
	if s := f.pass(); s != protocol.DiskNotEncrypted {
		t.Fatalf("plain: %s", s)
	}
}

func TestLUKSWaitsForDiskSetup(t *testing.T) {
	f := newLUKSFixture(t, "password")
	f.write(f.layout.DiskSetupPending(), "")
	if s := f.pass(); s != protocol.DiskTPMPINMissing || len(f.vol.changes) != 0 || f.st.Keyslots != nil {
		t.Fatalf("pending disk setup: %s %v %v", s, f.vol.changes, f.st.Keyslots)
	}
	// The disk setup enrolls the PIN: that is no tampering.
	f.vol.slots = append(f.vol.slots, "tpm2+pin")
	if err := os.Remove(f.layout.DiskSetupPending()); err != nil {
		t.Fatal(err)
	}
	if f.pass(); len(f.events) != 0 || len(f.server.of(escrow.KindLUKSRecoveryKey)) != 1 {
		t.Fatalf("after the disk setup: events %v, escrows %+v", f.events, f.server.requests)
	}
}

func TestLUKSRecoveryKeyLost(t *testing.T) {
	f := newLUKSFixture(t, "password", "tpm2+pin")
	f.server.answer = func(req escrow.Request) string {
		if req.Kind == escrow.KindLUKSRecoveryKey && req.Generation == 1 {
			return escrow.StatusFailed
		}
		return escrow.StatusStored
	}
	f.pass()
	// Refused: the key is gone, so the keyslot is replaced by a new generation.
	f.poll()
	if !slices.Equal(f.vol.changes, []string{"add recovery", "wipe recovery"}) {
		t.Fatalf("changes %v", f.vol.changes)
	}
	f.pass()
	if recs := f.server.of(escrow.KindLUKSRecoveryKey); len(recs) != 2 || recs[1].Generation != 2 || len(f.events) != 0 {
		t.Fatalf("recovery escrows %+v, events %v", recs, f.events)
	}
	f.poll()
	if f.st.RecoveryStored != 2 {
		t.Fatalf("state %+v", f.st)
	}

	// An upload that does not reach the server loses the key too.
	g := newLUKSFixture(t, "password", "tpm2+pin")
	g.server.uploadErr = errors.New("server unreachable")
	g.pass()
	g.server.uploadErr = nil
	g.pass()
	g.pass()
	if !slices.Equal(g.vol.changes, []string{"add recovery", "wipe recovery", "add recovery"}) || len(g.server.of(escrow.KindLUKSRecoveryKey)) != 1 {
		t.Fatalf("changes %v, escrows %+v", g.vol.changes, g.server.requests)
	}
}

func TestLUKSWithoutEscrowKey(t *testing.T) {
	f := newLUKSFixture(t, "password", "tpm2+pin")
	f.keys = nil
	if s := f.pass(); s != protocol.DiskEscrowPending || len(f.vol.changes) != 0 {
		t.Fatalf("without the escrow key: %s %v", s, f.vol.changes)
	}
}

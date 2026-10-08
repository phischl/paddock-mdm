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
	"reflect"
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

// volume simulates the LUKS2 root volume /dev/sda3 behind the LUKS tools: its keyslots by kind ("": a free slot).
// The install passphrase (keyFile) opens keyslot installSlot only (-1: none); other password keyslots are passphrases
// of their own.
type volume struct {
	t           *testing.T
	slots       []string
	plain       bool // the root is not on LUKS
	keyFile     string
	installSlot int
	failEnroll  bool
	changes     []string               // keyslot changes made through the tools
	extra       map[string]*dataVolume // the other volumes of /etc/crypttab by device
}

// LUKS UUIDs of the fixture's volumes.
const (
	rootUUID = "0d8f4c62-0000-4000-8000-0000000000aa"
	dataUUID = "0d8f4c62-0000-4000-8000-0000000000bb"
	oldUUID  = "0d8f4c62-0000-4000-8000-0000000000cc"
)

// dataVolume is a LUKS volume of /etc/crypttab other than the root volume: LUKS2 with password keyslots, or LUKS1
// (text dump only). An empty uuid makes luksUUID fail.
type dataVolume struct {
	uuid  string
	luks1 bool
	slots int
}

func (d *dataVolume) command(line, device string, args []string) (string, string, int, error) {
	switch {
	case line == "cryptsetup isLuks -- "+device:
		return "", "", 0, nil
	case line == "cryptsetup luksUUID -- "+device && d.uuid != "":
		return d.uuid + "\n", "", 0, nil
	case line == "cryptsetup luksUUID -- "+device:
		return "", "no UUID", 1, nil
	case line == "cryptsetup luksDump --dump-json-metadata -- "+device && d.luks1:
		return "", "Dump operation is not supported for this device type.", 1, nil
	case line == "cryptsetup luksDump --dump-json-metadata -- "+device:
		return d.dump(), "", 0, nil
	case line == "cryptsetup luksDump -- "+device:
		return d.dump(), "", 0, nil
	case strings.HasPrefix(line, "cryptsetup luksHeaderBackup "+device+" --header-backup-file "):
		return "", "", 0, os.WriteFile(args[3], []byte(d.dump()), 0o600)
	}
	return "", "unexpected", -1, errors.New("unexpected command " + line)
}

// dump is the LUKS2 JSON metadata or the LUKS1 text dump of the keyslots.
func (d *dataVolume) dump() string {
	if d.luks1 {
		out := "LUKS header information for " + d.uuid + "\n\nVersion:       \t1\n"
		for i := range 8 {
			state := "DISABLED"
			if i < d.slots {
				state = "ENABLED"
			}
			out += fmt.Sprintf("Key Slot %d: %s\n", i, state)
		}
		return out
	}
	keyslots := map[string]any{}
	for i := range d.slots {
		keyslots[strconv.Itoa(i)] = map[string]any{"type": "luks2"}
	}
	b, _ := json.Marshal(map[string]any{"keyslots": keyslots, "tokens": map[string]any{}, "segments": map[string]any{}, "uuid": d.uuid})
	return string(b)
}

func (v *volume) Command(_ context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	for device, d := range v.extra {
		if slices.Contains(args, device) {
			return d.command(line, device, args)
		}
	}
	switch {
	case name == "findmnt":
		return "/dev/mapper/vg-root\n", "", 0, nil
	case name == "lsblk" && v.plain:
		return `{"blockdevices":[{"name":"/dev/mapper/vg-root","type":"lvm","fstype":"ext4","children":[{"name":"/dev/sda3","type":"part","fstype":"LVM2_member"}]}]}`, "", 0, nil
	case name == "lsblk":
		return `{"blockdevices":[{"name":"/dev/mapper/vg-root","type":"lvm","fstype":"ext4","children":[{"name":"/dev/mapper/dm_crypt-0","type":"crypt","fstype":"LVM2_member","children":[{"name":"/dev/sda3","type":"part","fstype":"crypto_LUKS"}]}]}]}`, "", 0, nil
	case line == "cryptsetup luksDump --dump-json-metadata -- /dev/sda3":
		return v.metadata(), "", 0, nil
	case line == "cryptsetup luksUUID -- /dev/sda3":
		return rootUUID + "\n", "", 0, nil
	case line == "cryptsetup open --test-passphrase --verbose --disable-external-tokens --key-file "+v.keyFile+" /dev/sda3":
		if v.installSlot < 0 {
			return "No usable token is available.\n", "No key available with this passphrase.", 2, nil
		}
		return fmt.Sprintf("No usable token is available.\nKey slot %d unlocked.\nCommand successful.\n", v.installSlot), "", 0, nil
	case line == "systemd-cryptenroll --recovery-key --unlock-key-file="+v.keyFile+" /dev/sda3":
		if v.failEnroll || v.installSlot < 0 {
			return "", "Failed to unlock", 1, nil
		}
		v.add("recovery")
		return testRecoveryKey + "\n", "", 0, nil
	case strings.HasPrefix(line, "systemd-cryptenroll --wipe-slot=") && args[1] == "--unlock-key-file="+v.keyFile:
		slot, err := strconv.Atoi(strings.TrimPrefix(args[0], "--wipe-slot="))
		if err != nil {
			v.t.Errorf("keyslots wiped by type: %s", line)
			return "", "", -1, err
		}
		if v.installSlot < 0 || slot >= len(v.slots) || v.slots[slot] == "" {
			return "", "Failed to unlock or no such keyslot", 1, nil
		}
		v.changes = append(v.changes, "wipe "+v.slots[slot])
		v.slots[slot] = ""
		if slot == v.installSlot {
			v.installSlot = -1
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
	f.vol = &volume{t: t, slots: slots, keyFile: f.layout.InstallPassphrase(), installSlot: slices.Index(slots, "password")}
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
	// PDK-009: the root volume's headers carry its UUID, and health.disk lists it as escrowed.
	for _, r := range f.server.of(escrow.KindLUKSHeader) {
		if r.Volume != rootUUID {
			t.Fatalf("root header without its volume: %+v", r)
		}
	}
	want := []protocol.DiskVolume{{UUID: rootUUID, Device: "/dev/sda3", Root: true, LUKSVersion: 2,
		Tokens: []string{"recovery", "tpm2+pin"}, Keyslots: 2, Escrowed: true, HeaderGeneration: 2}}
	if !reflect.DeepEqual(h.Volumes, want) {
		t.Fatalf("volumes %+v", h.Volumes)
	}
}

// addVolume adds a LUKS volume to /etc/crypttab and the fixture's /dev.
func (f *luksFixture) addVolume(device string, d *dataVolume) {
	f.t.Helper()
	if f.vol.extra == nil {
		f.vol.extra = map[string]*dataVolume{}
	}
	f.vol.extra[device] = d
	f.write(f.layout.Join(device), "")
	crypttab, _ := os.ReadFile(f.layout.Join("/etc/crypttab"))
	f.write(f.layout.Join("/etc/crypttab"), string(crypttab)+filepath.Base(device)+" "+device+" none luks\n")
}

// settle runs passes and polls until no escrow starts any more and returns the state.
func (f *luksFixture) settle() string {
	f.t.Helper()
	s := f.pass()
	for range 20 {
		n := len(f.server.requests)
		f.poll()
		if s = f.pass(); len(f.server.requests) == n && s == f.pass() {
			break
		}
	}
	return s
}

// volumeHeaders returns the header escrows of volume.
func (f *luksFixture) volumeHeaders(volume string) []escrow.Request {
	var out []escrow.Request
	for _, r := range f.server.of(escrow.KindLUKSHeader) {
		if r.Volume == volume {
			out = append(out, r)
		}
	}
	return out
}

// TestLUKSEscrowsEveryVolume (PDK-009 decisions 1, 2 and 4): once the root volume is escrowed, the header of every
// other LUKS volume of /etc/crypttab — LUKS2 and LUKS1 — is escrowed with its UUID, one at a time, with header
// generations counted across all volumes; no recovery key is added to them and their keyslots stay untouched. The
// device is compliant only when every volume is escrowed.
func TestLUKSEscrowsEveryVolume(t *testing.T) {
	f := newLUKSFixture(t, "password", "tpm2+pin")
	f.addVolume("/dev/vdb1", &dataVolume{uuid: dataUUID, slots: 2})
	f.addVolume("/dev/vdc", &dataVolume{uuid: oldUUID, luks1: true, slots: 1})
	// Before the root volume is done, no other header is escrowed.
	f.pass()
	if len(f.volumeHeaders(dataUUID))+len(f.volumeHeaders(oldUUID)) != 0 {
		t.Fatal("another volume was escrowed before the root volume")
	}
	if s := f.settle(); s != protocol.DiskCompliant {
		t.Fatalf("not compliant: %s %+v", s, f.st)
	}
	data, old := f.volumeHeaders(dataUUID), f.volumeHeaders(oldUUID)
	if len(data) != 1 || len(old) != 1 || len(f.server.of(escrow.KindLUKSRecoveryKey)) != 1 {
		t.Fatalf("escrows %+v", f.server.requests)
	}
	roots := f.volumeHeaders(rootUUID)
	if data[0].Generation <= roots[len(roots)-1].Generation || old[0].Generation <= data[0].Generation {
		t.Fatalf("generations: root %d, data %d, old %d", roots[len(roots)-1].Generation, data[0].Generation, old[0].Generation)
	}
	if string(f.openHeader(data[0])) != f.vol.extra["/dev/vdb1"].dump() {
		t.Fatal("the escrowed header is not the data volume's")
	}
	h := f.m.Tick(context.Background(), f.keys, true)
	got := map[string]protocol.DiskVolume{}
	for _, v := range h.Volumes {
		got[v.UUID] = v
	}
	if len(h.Volumes) != 3 || !h.Volumes[0].Root ||
		!reflect.DeepEqual(got[dataUUID], protocol.DiskVolume{UUID: dataUUID, Device: "/dev/vdb1", LUKSVersion: 2, Tokens: []string{"password", "password"},
			Keyslots: 2, Escrowed: true, HeaderGeneration: data[0].Generation}) ||
		got[oldUUID].LUKSVersion != 1 || got[oldUUID].Keyslots != 1 || !got[oldUUID].Escrowed {
		t.Fatalf("volumes %+v", h.Volumes)
	}
	if len(f.events) != 0 {
		t.Fatalf("events %v", f.events)
	}
}

// openHeader decrypts an escrowed header with the server's key.
func (f *luksFixture) openHeader(req escrow.Request) []byte {
	f.t.Helper()
	wrapped, _ := base64.StdEncoding.DecodeString(req.WrappedDEK)
	dek, err := rsa.DecryptOAEP(sha256.New(), nil, f.server.key, wrapped, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(req.Nonce)
	header, err := escrow.OpenHeader(dek, nonce, req.EscrowID, f.server.objects[req.EscrowID])
	if err != nil {
		f.t.Fatal(err)
	}
	return header
}

// TestLUKSVolumeTamper (PDK-009 decision 3): a keyslot change on another volume is reported with its UUID, makes the
// device escrow_pending, and its header is escrowed again.
func TestLUKSVolumeTamper(t *testing.T) {
	f := newLUKSFixture(t, "password", "tpm2+pin")
	f.addVolume("/dev/vdb1", &dataVolume{uuid: dataUUID, slots: 1})
	if s := f.settle(); s != protocol.DiskCompliant {
		t.Fatalf("not compliant: %s", s)
	}
	f.vol.extra["/dev/vdb1"].slots = 2 // someone adds a passphrase to the data volume
	if s := f.pass(); s != protocol.DiskEscrowPending || len(f.events) != 1 || f.events[0].Type != protocol.EventTamperKeyslotChanged {
		t.Fatalf("tamper: %s, events %v", s, f.events)
	}
	var data protocol.TamperKeyslotChanged
	_ = json.Unmarshal(f.events[0].Data, &data)
	if data.Volume != dataUUID || !slices.Equal(data.Before, []string{"password"}) || !slices.Equal(data.After, []string{"password", "password"}) {
		t.Fatalf("tamper data %+v", data)
	}
	if s := f.settle(); s != protocol.DiskCompliant || len(f.volumeHeaders(dataUUID)) != 2 || len(f.events) != 1 {
		t.Fatalf("after the re-escrow: %s, headers %d, events %d", s, len(f.volumeHeaders(dataUUID)), len(f.events))
	}
}

// TestLUKSVolumeWithoutUUID (PDK-009 decision 4): a LUKS volume whose UUID cannot be read cannot be escrowed; it is
// reported, and the device is not compliant.
func TestLUKSVolumeWithoutUUID(t *testing.T) {
	f := newLUKSFixture(t, "password", "tpm2+pin")
	f.addVolume("/dev/vdb1", &dataVolume{slots: 1})
	if s := f.settle(); s != protocol.DiskEscrowPending {
		t.Fatalf("state %s", s)
	}
	h := f.m.Tick(context.Background(), f.keys, true)
	if len(h.Volumes) != 2 || !reflect.DeepEqual(h.Volumes[1], protocol.DiskVolume{Device: "/dev/vdb1"}) || len(f.volumeHeaders("")) != 0 {
		t.Fatalf("volumes %+v", h.Volumes)
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
	if data.Volume != rootUUID || !slices.Equal(data.Before, []string{"recovery", "tpm2+pin"}) || !slices.Equal(data.After, []string{"password", "recovery", "tpm2+pin"}) {
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

// An operator's passphrase keyslot and a recovery keyslot the agent did not create survive the replacement of a lost
// recovery key and the removal of the install passphrase; the remaining extra keyslots are reported (plan M4b.1 AC2).
func TestLUKSKeepsForeignKeyslots(t *testing.T) {
	f := newLUKSFixture(t, "password", "tpm2+pin", "password", "recovery")
	f.server.answer = func(req escrow.Request) string {
		if req.Kind == escrow.KindLUKSRecoveryKey && req.Generation == 1 {
			return escrow.StatusFailed
		}
		return escrow.StatusStored
	}
	f.pass()
	if f.st.PassphraseSlot == nil || *f.st.PassphraseSlot != 0 || f.st.RecoverySlot == nil || *f.st.RecoverySlot != 4 {
		t.Fatalf("recorded keyslots: passphrase %v, recovery %v", f.st.PassphraseSlot, f.st.RecoverySlot)
	}
	f.poll() // generation 1 refused: its keyslot is replaced
	f.pass() // generation 2
	f.poll() // stored: header
	f.poll() // header stored: the install passphrase goes
	if f.passphrase() || len(f.events) != 1 || f.events[0].Type != protocol.EventTamperKeyslotChanged {
		t.Fatalf("after the passphrase removal: passphrase %v, events %v, slots %v", f.passphrase(), f.events, f.vol.slots)
	}
	var data protocol.TamperKeyslotChanged
	_ = json.Unmarshal(f.events[0].Data, &data)
	if !slices.Equal(data.Before, []string{"recovery", "tpm2+pin"}) || !slices.Equal(data.After, []string{"password", "recovery", "recovery", "tpm2+pin"}) {
		t.Fatalf("tamper data %+v", data)
	}
	f.pass()
	if s := f.poll(); s != protocol.DiskEscrowPending || f.st.HeaderStored != 2 {
		t.Fatalf("with foreign keyslots: %s %+v", s, f.st)
	}
	if !slices.Equal(f.vol.slots, []string{"", "tpm2+pin", "password", "recovery", "recovery"}) {
		t.Fatalf("keyslots %v", f.vol.slots)
	}
	if !slices.Equal(f.vol.changes, []string{"add recovery", "wipe recovery", "add recovery", "wipe password"}) {
		t.Fatalf("keyslot changes %v", f.vol.changes)
	}
	if f.pass(); len(f.events) != 1 || len(f.vol.changes) != 4 {
		t.Fatalf("steady state: events %v, changes %v", f.events, f.vol.changes)
	}
}

// A recorded keyslot that holds another kind now (removed and reused outside Paddock) is never wiped; neither is
// anything wiped when the install passphrase opens no keyslot.
func TestLUKSWipesOnlyRecordedKeyslots(t *testing.T) {
	f := newLUKSFixture(t, "password", "tpm2+pin")
	f.server.answer = func(escrow.Request) string { return escrow.StatusFailed }
	f.pass()
	f.vol.slots[*f.st.RecoverySlot] = "password" // the recovery keyslot was replaced by a passphrase
	f.poll()
	f.pass()
	if strings.Contains(strings.Join(f.vol.changes, ","), "wipe") {
		t.Fatalf("a keyslot that is no longer the recorded one was wiped: %v", f.vol.changes)
	}

	g := newLUKSFixture(t, "password", "tpm2+pin")
	g.vol.installSlot = -1
	if g.pass(); len(g.vol.changes) != 0 || g.st.PassphraseSlot != nil || len(g.server.requests) != 0 {
		t.Fatalf("without a keyslot for the install passphrase: changes %v, state %+v", g.vol.changes, g.st)
	}
}

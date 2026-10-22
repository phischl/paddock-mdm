package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// rootVolume is the converted root volume behind the LUKS tools of the luks reconciler: the conversion key's keyslot
// (password, 0), the TPM keyslot (1) and the recovery keyslot (2). It records wipes and any overlapping call.
type rootVolume struct {
	t       *testing.T
	mu      sync.Mutex
	slots   []string
	wipes   []int
	in      atomic.Int32
	overlap atomic.Bool
}

func (v *rootVolume) Command(_ context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	if v.in.Add(1) > 1 {
		v.overlap.Store(true)
	}
	defer v.in.Add(-1)
	// Long enough for a second caller to show up while a call runs.
	time.Sleep(100 * time.Microsecond)
	v.mu.Lock()
	defer v.mu.Unlock()
	line := strings.Join(append([]string{name}, args...), " ")
	switch {
	case name == "findmnt" && strings.Contains(line, "/boot"):
		return "", "", 1, nil
	case name == "findmnt":
		return "/dev/mapper/dm_crypt-0\n", "", 0, nil
	case name == "lsblk":
		return `{"blockdevices":[{"name":"/dev/mapper/dm_crypt-0","type":"crypt","fstype":"ext4","children":[` +
			`{"name":"/dev/sda3","type":"part","fstype":"crypto_LUKS"}]}]}`, "", 0, nil
	case line == "cryptsetup luksDump --dump-json-metadata -- /dev/sda3":
		return v.metadata(), "", 0, nil
	case line == "cryptsetup luksUUID -- /dev/sda3":
		return testLUKSUUID + "\n", "", 0, nil
	case strings.HasPrefix(line, "systemd-cryptenroll --wipe-slot="):
		slot, err := strconv.Atoi(strings.TrimPrefix(args[0], "--wipe-slot="))
		if err != nil || slot >= len(v.slots) || v.slots[slot] == "" {
			return "", "no such keyslot", 1, nil
		}
		v.wipes = append(v.wipes, slot)
		v.slots[slot] = ""
		return "", "", 0, nil
	}
	return "", "", 1, nil
}

func (v *rootVolume) metadata() string {
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

func (v *rootVolume) wiped() []int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]int(nil), v.wipes...)
}

// keyslotAgent is a converted agent whose initrd work is due, with the luks reconciler on rootVolume. With escrowed,
// the recovery key and the header are escrowed: the next luks pass after the hold wipes the conversion key's keyslot.
func keyslotAgent(t *testing.T, escrowed bool) (*Agent, *convDevice, *rootVolume) {
	t.Helper()
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	d.set(func(d *convDevice) { d.slots = []string{"password", "tpm2+pin", "reencrypt"} })
	vol := &rootVolume{t: t, slots: []string{"password", "tpm2+pin", "recovery"}}
	a.d.LUKS = vol
	a.luks = a.luksReconciler()
	a.luks.Background = func(fn func()) { fn() }
	if a.st.DeviceID == "" {
		a.st.DeviceID = "device-1"
	}
	install, recovery := 0, 2
	a.st.LUKS.InstallSlot = &install
	if escrowed {
		md, err := luks.Dump(context.Background(), vol, "/dev/sda3")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(md.Raw)
		a.st.LUKS.RecoverySlot, a.st.LUKS.RecoveryAttempted, a.st.LUKS.RecoveryStored = &recovery, 1, 1
		a.st.LUKS.HeaderStored, a.st.LUKS.HeaderDigest, a.st.LUKS.Keyslots = 1, hex.EncodeToString(sum[:]), md.Kinds()
	}
	d.Write("/var/lib/paddock/install-passphrase", "the conversion key")
	// The boot PIN is set (the TPM keyslot exists): the first-boot disk setup is done.
	if err := os.Remove(d.Path("/var/lib/paddock/disk-setup-pending")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return a, d, vol
}

// TestKeyslotWipedWithRegeneration: plan M8e amendment 2026-10-21, item 19 (RR-71) — once the initrd is regenerated,
// the same worker run wipes the conversion key's keyslot and then shreds the key file, through the luks reconciler's
// own pass.
func TestKeyslotWipedWithRegeneration(t *testing.T) {
	a, d, vol := keyslotAgent(t, true)
	runWorker(t, a)
	if !a.st.Conversion.InitrdRegenerated {
		t.Fatalf("not regenerated: %+v", a.st.Conversion)
	}
	if w := vol.wiped(); len(w) != 1 || w[0] != 0 || d.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("wipes %v, key file there %v", w, d.Exists("/var/lib/paddock/install-passphrase"))
	}
}

// TestKeyslotStaysOnFailedPrecondition: item 19 (RR-71) — a precondition of the luks reconciler that does not hold
// (here: no recovery key escrowed yet) keeps the keyslot and the key file after the regeneration, the disk is not
// compliant, and the next pass wipes the keyslot once it holds.
func TestKeyslotStaysOnFailedPrecondition(t *testing.T) {
	a, d, vol := keyslotAgent(t, false)
	runWorker(t, a)
	if !a.st.Conversion.InitrdRegenerated || len(vol.wiped()) != 0 || !d.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("wipes %v", vol.wiped())
	}
	if h := a.luks.Tick(context.Background(), nil, false, ""); h == nil || h.State == "compliant" {
		t.Fatalf("health %+v", h)
	}
	md, err := luks.Dump(context.Background(), vol, "/dev/sda3")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(md.Raw)
	recovery := 2
	a.st.LUKS.RecoverySlot, a.st.LUKS.RecoveryAttempted, a.st.LUKS.RecoveryStored = &recovery, 1, 1
	a.st.LUKS.HeaderStored, a.st.LUKS.HeaderDigest = 1, hex.EncodeToString(sum[:])
	a.tickLUKS(context.Background(), true)
	if w := vol.wiped(); len(w) != 1 || w[0] != 0 || d.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("next pass: wipes %v", w)
	}
}

// TestKeyslotWipedAfterCrash: item 19 (RR-71) — an agent stopped between recording the regenerated initrd and the
// wipe catches up at its next luks pass.
func TestKeyslotWipedAfterCrash(t *testing.T) {
	a, d, vol := keyslotAgent(t, true)
	a.st.Conversion.InitrdRegenerated = true
	a.tickLUKS(context.Background(), true)
	if w := vol.wiped(); len(w) != 1 || w[0] != 0 || d.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("wipes %v", w)
	}
}

// TestKeyslotPassNotParallel: item 19 (RR-71) — the luks pass the worker brings forward runs on the run loop, like the
// regular passes, and never at the same time as one (run with -race).
func TestKeyslotPassNotParallel(t *testing.T) {
	a, _, vol := keyslotAgent(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runConversions(ctx)
	}()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	timeout := time.After(10 * time.Second)
	for finished := false; !finished; {
		select {
		case fn := <-a.conversionCalls:
			fn()
			finished = !a.conversionBusy
		case <-tick.C:
			a.tickLUKS(ctx, true)
		case <-timeout:
			t.Fatal("the conversion worker hangs")
		}
	}
	// The worker's pass has run by now; regular passes go on, which a pass of the worker's own would overlap.
	for range 50 {
		a.tickLUKS(ctx, true)
	}
	cancel()
	<-done
	if vol.overlap.Load() || len(vol.wiped()) != 1 {
		t.Fatalf("overlap %v, wipes %v", vol.overlap.Load(), vol.wiped())
	}
}

// TestEnrollmentAfterCompletionNoTamper: plan M8e amendment 2026-10-22, item 22 — the luks passes and the conversion
// passes through the completion, the armed disk setup and the boot that enrolls the boot PIN report no tampering; a
// foreign keyslot added at the same boot is reported.
func TestEnrollmentAfterCompletionNoTamper(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		a, d, _ := convertedAgent(t)
		a.startConversion(context.Background())
		d.set(func(d *convDevice) { d.slots = []string{"password", "recovery"} })
		vol := &rootVolume{t: t, slots: []string{"password", "", "recovery"}}
		a.d.LUKS = vol
		a.luks = a.luksReconciler()
		a.luks.Background = func(fn func()) { fn() }
		if a.st.DeviceID == "" {
			a.st.DeviceID = "device-1"
		}
		md, err := luks.Dump(context.Background(), vol, "/dev/sda3")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(md.Raw)
		install, recovery := 0, 2
		a.st.LUKS.InstallSlot, a.st.LUKS.RecoverySlot, a.st.LUKS.RecoveryAttempted, a.st.LUKS.RecoveryStored = &install, &recovery, 1, 1
		a.st.LUKS.HeaderStored, a.st.LUKS.HeaderDigest, a.st.LUKS.Keyslots = 1, hex.EncodeToString(sum[:]), md.Kinds()
		d.Write("/var/lib/paddock/install-passphrase", "the conversion key")

		a.tickLUKS(context.Background(), true)
		a.tickConversion(context.Background())
		runWorker(t, a)
		a.tickLUKS(context.Background(), true)
		if a.st.Conversion.Phase != state.ConversionCompleted || !d.Exists("/var/lib/paddock/disk-setup-pending") ||
			!a.st.LUKS.EnrollmentExpected {
			t.Fatalf("foreign %v: completed %+v, expected %v", foreign, a.st.Conversion, a.st.LUKS.EnrollmentExpected)
		}

		// The next boot: disk-setup enrolls the PIN and removes the marker.
		vol.mu.Lock()
		vol.slots[1] = "tpm2+pin"
		if foreign {
			vol.slots = append(vol.slots, "password")
		}
		vol.mu.Unlock()
		d.set(func(d *convDevice) { d.slots = append(d.slots, "tpm2+pin") })
		if err := os.Remove(d.Path("/var/lib/paddock/disk-setup-pending")); err != nil {
			t.Fatal(err)
		}
		a.tickLUKS(context.Background(), true)
		a.tickConversion(context.Background())
		runWorker(t, a)
		a.tickLUKS(context.Background(), true)
		if n := len(eventsOfType(t, a, protocol.EventTamperKeyslotChanged)); (n == 1) != foreign || n > 1 {
			t.Fatalf("foreign %v: tamper events %d", foreign, n)
		}
		if !foreign && !a.st.Conversion.InitrdRegenerated || a.st.LUKS.EnrollmentExpected {
			t.Fatalf("not regenerated: %+v, expected %v", a.st.Conversion, a.st.LUKS.EnrollmentExpected)
		}
	}
}

// TestEnrollmentExpectationRevoked (item 22, amendment 2026-10-22 b): a revocation hand-over after the completion
// withdraws the expected enrollment at once and in the saved state, so that any later keyslot change is reported; a
// conversion pass after a revocation withdraws one that is set; the cleared conversion leaves none behind.
func TestEnrollmentExpectationRevoked(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	runWorker(t, a)
	d.set(func(d *convDevice) { d.slots = []string{"password"} })
	a.tickConversion(context.Background())
	runWorker(t, a)
	if a.st.Conversion.Phase != state.ConversionCompleted || !a.st.LUKS.EnrollmentExpected {
		t.Fatalf("completed %+v, expected %v", a.st.Conversion, a.st.LUKS.EnrollmentExpected)
	}
	a.d.Sleep = func(context.Context, time.Duration) error { return nil }
	var saved bool
	a.d.Revoke = func(context.Context, []byte) (string, error) {
		st, _ := state.Load(a.d.Layout.State())
		saved = st.LUKS.EnrollmentExpected
		return "", nil
	}
	a.handRevocations(context.Background(), []json.RawMessage{revocationEnvelope(t, `{"a":1}`)})
	if a.st.Conversion.RevokedAt == nil || a.st.LUKS.EnrollmentExpected || saved {
		t.Fatalf("after the hand-over: revoked %v, expected %v, saved %v", a.st.Conversion.RevokedAt, a.st.LUKS.EnrollmentExpected, saved)
	}
	a.st.LUKS.EnrollmentExpected = true
	a.tickConversion(context.Background())
	if a.st.LUKS.EnrollmentExpected {
		t.Fatal("still expected at the pass after the revocation")
	}
}

// TestEnrollmentExpectationCleared (item 22): clearing a completed, regenerated conversion withdraws an expectation
// that no TPM keyslot ended.
func TestEnrollmentExpectationCleared(t *testing.T) {
	a, _, _ := convertedAgent(t)
	a.st.Conversion.Phase, a.st.Conversion.InitrdRegenerated, a.st.LUKS.EnrollmentExpected = state.ConversionCompleted, true, true
	a.d.Health.Update(func(r *health.Report) { r.Disk = &protocol.DiskHealth{State: protocol.DiskCompliant} })
	a.clearConversion(context.Background())
	if a.st.Conversion != nil || a.st.LUKS.EnrollmentExpected {
		t.Fatalf("conversion %+v, expected %v", a.st.Conversion, a.st.LUKS.EnrollmentExpected)
	}
}

// TestEnrollmentExpectedWithUnreadableHeader (item 22): the pass that records the completion expects the enrollment
// even when it cannot read the header.
func TestEnrollmentExpectedWithUnreadableHeader(t *testing.T) {
	a, d, _ := convertedAgent(t)
	a.startConversion(context.Background())
	runWorker(t, a)
	d.set(func(d *convDevice) { d.slots = []string{"password"} })
	inner := d.Handle
	d.Handle = func(line string) (string, int, bool) {
		if line == "cryptsetup luksDump --dump-json-metadata -- "+testPartition && a.st.Conversion.Phase == state.ConversionCompleted {
			return "", 1, true
		}
		return inner(line)
	}
	a.tickConversion(context.Background())
	if a.st.Conversion.Phase != state.ConversionCompleted || !a.st.LUKS.EnrollmentExpected {
		t.Fatalf("completed %+v, expected %v", a.st.Conversion, a.st.LUKS.EnrollmentExpected)
	}
}

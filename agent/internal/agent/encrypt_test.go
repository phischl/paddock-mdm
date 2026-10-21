package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/encrypt/encrypttest"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const (
	testConversionID = "5b0e7c1a-2f4d-4e8b-9a6c-3d1f0e2b4a7c"
	testPartition    = "/dev/disk/by-partuuid/8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f"
	testKernel       = "6.8.0-85-generic"
	testLUKSUUID     = "0e373e21-dd76-4f34-bdf4-c815419e5a55"
)

// initrdListing is what lsinitrd shows for an initrd built with the module.
const initrdListing = "paddock-encrypt\netc/paddock/encrypt-plan.env\netc/paddock/encrypt-key\n" +
	"usr/lib/systemd/system/paddock-encrypt-init.service\nusr/sbin/cryptsetup\nusr/sbin/e2fsck\nusr/sbin/resize2fs\nusr/sbin/lvm\n"

// convDevice is the fake device of the agent's conversion tests: the eligible lvm device of the encrypt tests with
// dracut installed. isLuks answers luks; dracut builds every installed kernel's initrd with the module while
// ModuleConf and plan.env exist (the module's check()) and with /etc/crypttab, unless dracutExit fails it; lsinitrd
// lists what the last build put in. With luks, luksDump shows slots; the unit of the background helper is unit.
type convDevice struct {
	*encrypttest.Host
	mu         sync.Mutex
	luks       bool
	slots      []string
	unit       string
	dracutExit int
	// stopStuck keeps the helper's unit active after systemctl stop.
	stopStuck bool
	// onLine runs at every command line before the device answers it (without mu).
	onLine func(line string)
	// headerReadable makes luksDump answer although isLuks says no (one tool's wrong answer).
	headerReadable bool
	// partDevices is what blkid names for the partition's PARTUUID ("" = one device, /dev/sda3).
	partDevices string
}

func (d *convDevice) setLUKS(v bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.luks = v
}

func (d *convDevice) set(fn func(d *convDevice)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fn(d)
}

// build is dracut -f --regenerate-all on the fake: the initrd of every kernel with /boot/vmlinuz-<v>.
func (d *convDevice) build() {
	module := d.Exists(encrypt.ModuleConf) && d.Exists("/var/lib/paddock/encrypt/plan.env")
	images, _ := filepath.Glob(d.Path("/boot/vmlinuz-*"))
	for _, img := range images {
		d.buildInitrd(filepath.Join(filepath.Dir(img), "initrd.img-"+strings.TrimPrefix(filepath.Base(img), "vmlinuz-")), module)
	}
}

// buildInitrd writes one initrd as lsinitrd shows it (the header with the dracut modules, then ls -l lines), then
// after crypttabMark the crypttab it carries.
func (d *convDevice) buildInitrd(path string, module bool) {
	modules := "systemd\ncrypt\n"
	files := []string{"usr/sbin/cryptsetup", "usr/lib/systemd/systemd-cryptsetup", "usr/lib/x86_64-linux-gnu/libtss2-esys.so.0"}
	if module {
		modules += "paddock-encrypt\n"
		for line := range strings.Lines(initrdListing) {
			if f := strings.TrimSpace(line); f != "paddock-encrypt" {
				files = append(files, f)
			}
		}
	}
	crypttab, err := os.ReadFile(d.Path("/etc/crypttab"))
	if err == nil {
		files = append(files, "etc/crypttab")
	}
	var b strings.Builder
	b.WriteString("Image: initrd\n====\nVersion: dracut-060\n\ndracut modules:\n" + modules + "====\n")
	for _, f := range files {
		b.WriteString("-rwxr-xr-x   1 root     root          123 Oct 21 10:00 " + f + "\n")
	}
	_ = os.WriteFile(path, []byte(b.String()+crypttabMark+string(crypttab)), 0o600)
}

// crypttabMark separates a fake initrd's listing from the crypttab it carries.
const crypttabMark = "--- etc/crypttab ---\n"

// metadata is the LUKS2 metadata of the slots, by kind.
func (d *convDevice) metadata() string {
	keyslots, tokens := map[string]any{}, map[string]any{}
	for i, kind := range d.slots {
		slot := strconv.Itoa(i)
		keyslots[slot] = map[string]any{"type": "luks2"}
		switch kind {
		case "tpm2+pin":
			tokens[slot] = map[string]any{"type": "systemd-tpm2", "keyslots": []string{slot}, "tpm2-pin": true}
		case "tpm2":
			tokens[slot] = map[string]any{"type": "systemd-tpm2", "keyslots": []string{slot}}
		case "recovery":
			tokens[slot] = map[string]any{"type": "systemd-recovery", "keyslots": []string{slot}}
		case "reencrypt":
			keyslots[slot] = map[string]any{"type": "reencrypt"}
		}
	}
	b, _ := json.Marshal(map[string]any{"keyslots": keyslots, "tokens": tokens})
	return string(b)
}

var testEscrowKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		panic(err)
	}
	return key
})

// convAgent is an enrolled agent on the fake device, with the escrow key and the module of a test build.
func convAgent(t *testing.T) (*Agent, *testgw.Gateway, *convDevice) {
	t.Helper()
	g := testgw.New(t)
	a := newAgent(t, g)
	d := &convDevice{Host: encrypttest.LoadInto(t, "../encrypt/testdata/lvm.txt", a.d.Layout.Root), unit: "inactive",
		slots: []string{"password", "reencrypt"}}
	d.Write("/proc/sys/kernel/osrelease", testKernel+"\n")
	d.Write("/boot/vmlinuz-"+testKernel, "")
	d.Write("/lib/modules/"+testKernel+"/modules.dep", "")
	d.Write("/boot/initrd.img-"+testKernel, "")
	d.MkdirAll("/sys/module/dm_crypt")
	d.Write(testPartition, "")
	d.Handle = func(line string) (string, int, bool) {
		d.mu.Lock()
		hook := d.onLine
		d.mu.Unlock()
		if hook != nil {
			hook(line)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		switch line {
		case "dpkg-query -W -f=${db:Status-Status} dracut":
			return "installed", 0, true
		case "cryptsetup isLuks " + testPartition:
			if d.luks {
				return "", 0, true
			}
			return "", 1, true
		case "blockdev --getsize64 " + testPartition:
			return "40793800704\n", 0, true
		case "lvm lvs --noheadings --units b --nosuffix -o lv_size /dev/ubuntu-vg/ubuntu-lv":
			return "20396900352\n", 0, true
		case "lvm vgs --noheadings --units b --nosuffix -o vg_extent_size ubuntu-vg":
			return "4194304\n", 0, true
		case "dracut -f --regenerate-all":
			if d.dracutExit != 0 {
				return "", d.dracutExit, true
			}
			d.build()
			return "", 0, true
		case "blkid -o device -t PARTUUID=8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f":
			if d.partDevices == "" {
				return "/dev/sda3\n", 0, true
			}
			return d.partDevices, 0, true
		case "cryptsetup luksDump --dump-json-metadata -- " + testPartition:
			if !d.luks && !d.headerReadable {
				return "", 1, true
			}
			return d.metadata(), 0, true
		case "systemctl is-active " + encrypt.ResumeUnit:
			if d.unit == "active" {
				return "active\n", 0, true
			}
			return d.unit + "\n", 3, true
		case "systemctl stop --no-block " + encrypt.ResumeUnit:
			if !d.stopStuck {
				d.unit = "inactive"
			}
			return "", 0, true
		}
		if rest, ok := strings.CutPrefix(line, "dracut -f --no-uefi /boot/.initrd.img-"); ok {
			if d.dracutExit != 0 {
				return "", d.dracutExit, true
			}
			d.buildInitrd(d.Path("/boot/.initrd.img-"+strings.Fields(rest)[0]),
				d.Exists(encrypt.ModuleConf) && d.Exists("/var/lib/paddock/encrypt/plan.env"))
			return "", 0, true
		}
		if rest, ok := strings.CutPrefix(line, "dracut -f --no-uefi --omit paddock-encrypt "); ok {
			if d.dracutExit != 0 {
				return "", d.dracutExit, true
			}
			tmp := d.Path(strings.Fields(rest)[0])
			d.buildInitrd(tmp, false)
			// What real lsinitrd prints for a build with --omit: dracut's command line names the module.
			raw, _ := os.ReadFile(tmp)
			_ = os.WriteFile(tmp, []byte(strings.Replace(string(raw), "Version: dracut-060\n",
				"Version: dracut-060\nArguments: -f --omit 'paddock-encrypt'\n", 1)), 0o600)
			return "", 0, true
		}
		if initrd, ok := strings.CutPrefix(line, "lsinitrd -m "); ok {
			raw, _ := os.ReadFile(d.Path(initrd))
			head, _, _ := strings.Cut(string(raw), "====\n-")
			return head, 0, true
		}
		if initrd, ok := strings.CutPrefix(line, "lsinitrd -f etc/crypttab "); ok {
			raw, _ := os.ReadFile(d.Path(initrd))
			_, crypttab, _ := strings.Cut(string(raw), crypttabMark)
			return crypttab, 0, true
		}
		if initrd, ok := strings.CutPrefix(line, "lsinitrd "); ok {
			raw, err := os.ReadFile(d.Path(initrd))
			if err != nil {
				return "", 1, true
			}
			listing, _, _ := strings.Cut(string(raw), crypttabMark)
			return listing, 0, true
		}
		return "", 0, false
	}
	der, _ := x509.MarshalPKIXPublicKey(&testEscrowKey().PublicKey)
	keys := testgw.CommandKeys()
	keys.EscrowWrap = &bundle.EncryptionKey{KeyID: "escrow-wrap:v1",
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
	a.current = &bundle.Bundle{Keys: keys, Disk: &bundle.DiskSpec{UnlockMode: bundle.UnlockModeTPMPIN}}
	a.d.Encrypt = d
	a.d.EncryptModule = fstest.MapFS{"module-setup.sh": {Data: []byte("#!/bin/bash\n")},
		"paddock-encrypt-init.service": {Data: []byte("[Unit]\n")}}
	a.d.Sleep = func(context.Context, time.Duration) error { return nil }
	a.d.Health.Update(func(r *health.Report) { r.Disk = &protocol.DiskHealth{State: protocol.DiskNotEncrypted} })
	return a, g, d
}

func encryptCmd(typ, id, params string) *command.Command {
	return &command.Command{CommandID: id, Type: typ, Params: json.RawMessage(params), IssuedAt: time.Now()}
}

// runWorker runs the conversion worker for the queued job, serving its calls like the run loop.
func runWorker(t *testing.T, a *Agent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runConversions(ctx)
	}()
	for {
		select {
		case fn := <-a.conversionCalls:
			fn()
			if !a.conversionBusy {
				cancel()
				<-done
				return
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the conversion worker hangs")
		}
	}
}

func spooled(t *testing.T, a *Agent) []protocol.Event {
	t.Helper()
	events, err := a.d.Spool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func eventData(t *testing.T, e protocol.Event) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(e.Data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestEncryptDiskRefused: plan M8e decision 12's refusals change nothing.
func TestEncryptDiskRefused(t *testing.T) {
	valid := `{"conversion_id":"` + testConversionID + `"}`
	for name, tc := range map[string]struct {
		params  string
		setup   func(a *Agent, d *convDevice)
		reason  string
		reasons []string
	}{
		"not a uuid":    {params: `{"conversion_id":"nope"}`, reason: "invalid_params"},
		"unknown field": {params: `{"conversion_id":"` + testConversionID + `","unlock_mode":"tpm_only"}`, reason: "invalid_params"},
		"revocation": {params: valid, reason: "revocation_pending", setup: func(a *Agent, _ *convDevice) {
			a.st.HandedRevocations = map[string]time.Time{"h": time.Now().Add(-time.Hour)}
		}},
		"uninstall": {params: valid, reason: "uninstall_pending", setup: func(a *Agent, _ *convDevice) {
			a.st.PendingUninstall = &state.PendingUninstall{CommandID: "c-un", Mode: "leave"}
		}},
		"preflight": {params: valid, reason: "not_eligible", reasons: []string{"release_unsupported"}, setup: func(_ *Agent, d *convDevice) {
			d.Write("/etc/os-release", "VERSION_ID=\"22.04\"\n")
		}},
		"encrypted": {params: valid, reason: "not_eligible", reasons: []string{"already_encrypted"}, setup: func(a *Agent, _ *convDevice) {
			a.d.Health.Update(func(r *health.Report) { r.Disk = &protocol.DiskHealth{State: protocol.DiskEncrypting} })
		}},
		"cleanup pending": {params: valid, reason: "not_eligible", reasons: []string{"cleanup_pending"}, setup: func(a *Agent, _ *convDevice) {
			a.st.Conversion = &state.DiskConversion{ID: "other", Phase: state.ConversionCancelled, CleanupPending: true}
		}},
		"open conversion": {params: valid, reason: "not_eligible", reasons: []string{"already_encrypted"}, setup: func(a *Agent, _ *convDevice) {
			a.st.Conversion = &state.DiskConversion{ID: "other", Phase: state.ConversionPrepared}
		}},
		"no module": {params: valid, reason: "not_eligible", setup: func(a *Agent, _ *convDevice) { a.d.EncryptModule = nil }},
	} {
		a, _, d := convAgent(t)
		if tc.setup != nil {
			tc.setup(a, d)
		}
		before := a.st.Conversion
		status, result := a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", tc.params))
		got, _ := result["reasons"].([]string)
		if status != protocol.CommandFailed || result["accepted"] != false || result["reason"] != tc.reason ||
			strings.Join(got, ",") != strings.Join(tc.reasons, ",") {
			t.Fatalf("%s: %s %v", name, status, result)
		}
		if a.st.Conversion != before || len(a.conversionJobs) != 0 {
			t.Fatalf("%s: conversion changed or queued", name)
		}
	}
}

// TestEncryptDiskAcceptedOnce: an eligible device stores the conversion as preparing, queues the worker and answers
// accepted; the executor never runs the same command twice.
func TestEncryptDiskAcceptedOnce(t *testing.T) {
	a, _, _ := convAgent(t)
	c := testCommand("0190f000-0000-7000-8000-0000000000e1", command.TypeEncryptDisk, time.Now().UTC().Truncate(time.Second))
	c.Params = json.RawMessage(`{"conversion_id":"` + testConversionID + `"}`)
	env := []json.RawMessage{testgw.SignedCommand(t, c)}
	a.handleCommands(context.Background(), env)
	a.handleCommands(context.Background(), env)
	if len(a.st.CommandResults) != 1 || a.st.CommandResults[0].Status != protocol.CommandSucceeded ||
		string(a.st.CommandResults[0].Result) != `{"accepted":true}` {
		t.Fatalf("results %+v", a.st.CommandResults)
	}
	conv := a.st.Conversion
	if conv == nil || conv.ID != testConversionID || conv.CommandID != c.CommandID || conv.Phase != state.ConversionPreparing ||
		conv.RequestedAt.IsZero() || len(a.conversionJobs) != 1 || !a.conversionBusy {
		t.Fatalf("conversion %+v, queued %d", conv, len(a.conversionJobs))
	}
	if st, _ := state.Load(a.d.Layout.State()); st.Conversion == nil || st.Conversion.Phase != state.ConversionPreparing {
		t.Fatalf("not persisted: %+v", st.Conversion)
	}
}

// TestConversionWorker: the worker prepares through the run loop: the escrow goes to the device API as the next
// recovery key generation, the conversion ends prepared and disk.conversion_prepared is spooled.
func TestConversionWorker(t *testing.T) {
	a, g, _ := convAgent(t)
	if status, _ := a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1",
		`{"conversion_id":"`+testConversionID+`"}`)); status != protocol.CommandSucceeded {
		t.Fatal("not accepted")
	}
	runWorker(t, a)
	conv := a.st.Conversion
	if conv.Phase != state.ConversionPrepared || conv.KeyEscrowGeneration != 1 || a.st.LUKS.RecoveryStored != 1 || a.conversionBusy {
		t.Fatalf("conversion %+v, luks %+v", conv, a.st.LUKS)
	}
	if len(g.Escrows) != 1 || g.Escrows[0].Kind != "luks_recovery_key" || g.Escrows[0].Generation != 1 || g.Escrows[0].Volume != conv.LUKSUUID {
		t.Fatalf("escrows %+v", g.Escrows)
	}
	events := spooled(t, a)
	if len(events) != 1 || events[0].Type != protocol.EventDiskConversionPrepared || eventData(t, events[0])["volume"] != conv.LUKSUUID {
		t.Fatalf("events %+v", events)
	}
}

// TestEncryptDiskAbortCommand: plan M8e decision 27 in every phase.
func TestEncryptDiskAbortCommand(t *testing.T) {
	params := `{"conversion_id":"` + testConversionID + `"}`
	refused := func(t *testing.T, a *Agent, params, want string) {
		t.Helper()
		before := *a.st.Conversion
		status, result := a.encryptDiskAbortCommand(context.Background(), encryptCmd(command.TypeEncryptDiskAbort, "c-abort", params))
		if status != protocol.CommandFailed || result["aborted"] != false || result["reason"] != want {
			t.Fatalf("%s %v", status, result)
		}
		if a.st.Conversion.Phase != before.Phase || a.st.Conversion.AbortRequested || len(spooled(t, a)) != 0 {
			t.Fatal("the refusal changed the conversion")
		}
	}
	for _, phase := range []string{state.ConversionEncrypting, state.ConversionCompleted, state.ConversionFailed, state.ConversionCancelled} {
		a, _, _ := convAgent(t)
		a.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: phase, Partition: testPartition}
		refused(t, a, params, "not_abortable")
	}
	a, _, _ := convAgent(t)
	a.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: state.ConversionPrepared, Partition: testPartition}
	refused(t, a, `{"conversion_id":"00000000-0000-4000-8000-000000000000"}`, "unknown_conversion")
	refused(t, a, `{}`, "invalid_params")

	// prepared: aborted at once.
	a, _, d := convAgent(t)
	a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", params))
	runWorker(t, a)
	_ = os.Remove(a.d.Layout.Spool())
	status, result := a.encryptDiskAbortCommand(context.Background(), encryptCmd(command.TypeEncryptDiskAbort, "c-abort", params))
	if status != protocol.CommandSucceeded || result["aborted"] != true || a.st.Conversion.Phase != state.ConversionCancelled ||
		d.Exists(encrypt.ModuleDir) || d.Exists("/var/lib/paddock/install-passphrase") {
		t.Fatalf("prepared: %s %v %+v", status, result, a.st.Conversion)
	}
	if events := spooled(t, a); len(events) != 1 || events[0].Type != protocol.EventDiskConversionAborted || eventData(t, events[0])["by"] != "admin" {
		t.Fatalf("events %+v", events)
	}

	// preparing: deferred; the worker aborts before its next step and posts the result.
	a, g, _ := convAgent(t)
	a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", params))
	status, _ = a.encryptDiskAbortCommand(context.Background(), encryptCmd(command.TypeEncryptDiskAbort, "c-abort", params))
	if status != commands.Deferred || !a.st.Conversion.AbortRequested {
		t.Fatalf("preparing: %s %+v", status, a.st.Conversion)
	}
	runWorker(t, a)
	if a.st.Conversion.Phase != state.ConversionCancelled || len(g.Escrows) != 0 || len(a.st.CommandResults) != 1 ||
		a.st.CommandResults[0].CommandID != "c-abort" || string(a.st.CommandResults[0].Result) != `{"aborted":true}` ||
		a.st.Conversion.AbortCommandID != "" {
		t.Fatalf("preparing after the worker: %+v, results %+v", a.st.Conversion, a.st.CommandResults)
	}
}

// TestStartConversionAdopts: the I2 check at the start runs before the re-queue: a LUKS partition adopts the
// conversion as encrypting and drops the preparation; otherwise the preparation is queued again.
func TestStartConversionAdopts(t *testing.T) {
	a, _, d := convAgent(t)
	a.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: state.ConversionPreparing, Partition: testPartition,
		LUKSUUID: "0e373e21-dd76-4f34-bdf4-c815419e5a55", AbortCommandID: "c-abort", AbortRequested: true}
	d.setLUKS(true)
	a.startConversion(context.Background())
	// The job queued is the converted disk's initrd work (decisions 18, 20 and 52), not the preparation.
	if c := a.st.Conversion; c.Phase != state.ConversionEncrypting || c.StartedAt == nil || len(a.conversionJobs) != 1 || c.AbortRequested {
		t.Fatalf("conversion %+v, queued %d", c, len(a.conversionJobs))
	}
	events := spooled(t, a)
	if len(events) != 1 || events[0].Type != protocol.EventDiskConversionStarted || eventData(t, events[0])["init_result"] != "unknown" {
		t.Fatalf("events %+v", events)
	}
	if len(a.st.CommandResults) != 1 || string(a.st.CommandResults[0].Result) != `{"aborted":false,"reason":"not_abortable"}` {
		t.Fatalf("abort answer %+v", a.st.CommandResults)
	}
	a.tickConversion(context.Background())
	if len(spooled(t, a)) != 1 {
		t.Fatal("adopted twice")
	}

	b, _, _ := convAgent(t)
	b.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: state.ConversionPreparing, Partition: testPartition}
	b.startConversion(context.Background())
	if b.st.Conversion.Phase != state.ConversionPreparing || len(b.conversionJobs) != 1 {
		t.Fatalf("not re-queued: %+v", b.st.Conversion)
	}
}

// TestTickConversionRetriesCleanup: an unfinished cleanup is retried at a full pass on the conversion worker — the run
// loop never runs dracut for it — and never while the partition is LUKS or cannot be checked (I1).
func TestTickConversionRetriesCleanup(t *testing.T) {
	for name, tc := range map[string]struct {
		luks, missing, done bool
	}{
		"not LUKS":          {done: true},
		"LUKS":              {luks: true},
		"partition missing": {missing: true},
	} {
		a, _, d := convAgent(t)
		d.Write("/var/lib/paddock/install-passphrase", "key")
		d.Write(encrypt.ModuleConf, "conf")
		d.setLUKS(tc.luks)
		if tc.missing {
			_ = os.Remove(d.Path(testPartition))
		}
		a.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: state.ConversionCancelled, Partition: testPartition,
			Mapping: "dm_crypt-0", LUKSUUID: testLUKSUUID, CleanupPending: true}
		a.tickConversion(context.Background())
		if !tc.luks && !tc.missing && (d.Count("dracut -f --regenerate-all") != 0 || len(a.conversionJobs) != 1 || !a.conversionBusy) {
			t.Fatalf("%s: the cleanup ran on the loop or was not queued", name)
		}
		if tc.luks {
			if a.st.Conversion.Phase != state.ConversionEncrypting || a.st.Conversion.CleanupPending {
				t.Fatalf("%s: queued a cleanup instead of adopting", name)
			}
			runWorker(t, a)
			if !d.Exists("/var/lib/paddock/install-passphrase") {
				t.Fatalf("%s: the adopted conversion's key was removed", name)
			}
			continue
		}
		runWorker(t, a)
		if done := !a.st.Conversion.CleanupPending && !d.Exists("/var/lib/paddock/install-passphrase"); done != tc.done {
			t.Fatalf("%s: cleanup done %v: %+v", name, done, a.st.Conversion)
		}
		if !tc.done && (!d.Exists(encrypt.ModuleConf) || d.Count("dracut -f --regenerate-all") != 0) {
			t.Fatalf("%s: cleanup ran on a guess", name)
		}
	}
}

// TestWorkerAnswersRefusedAbort: an encrypt_disk_abort the worker cannot run (the partition cannot be checked, I1) is
// answered not_abortable at once, and the preparation is queued again instead of staying preparing without a worker;
// its steps wait until the header can be checked (PDK-367).
func TestWorkerAnswersRefusedAbort(t *testing.T) {
	a, _, d := convAgent(t)
	params := `{"conversion_id":"` + testConversionID + `"}`
	a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", params))
	if status, _ := a.encryptDiskAbortCommand(context.Background(), encryptCmd(command.TypeEncryptDiskAbort, "c-abort", params)); status != commands.Deferred {
		t.Fatalf("not deferred: %s", status)
	}
	a.st.Conversion.Partition = testPartition
	_ = os.Remove(d.Path(testPartition))
	runWorker(t, a)
	c := a.st.Conversion
	if len(a.st.CommandResults) != 1 || a.st.CommandResults[0].CommandID != "c-abort" ||
		string(a.st.CommandResults[0].Result) != `{"aborted":false,"reason":"not_abortable"}` {
		t.Fatalf("abort answer %+v", a.st.CommandResults)
	}
	if c.AbortRequested || c.AbortCommandID != "" || c.Phase != state.ConversionPreparing || a.conversionBusy ||
		d.Count("dracut -f --regenerate-all") != 0 {
		t.Fatalf("conversion %+v, busy %v", c, a.conversionBusy)
	}
}

// TestLoopAbortSurvivesStop: Review 2, minor-3 — an abort of a prepared conversion on the run loop (encrypt_disk_abort
// and `paddockd encrypt-abort`) finishes its cleanup when the agent is stopping: its tools are not killed with ctx.
func TestLoopAbortSurvivesStop(t *testing.T) {
	params := `{"conversion_id":"` + testConversionID + `"}`
	for _, via := range []string{"command", "request"} {
		a, _, d := convAgent(t)
		a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", params))
		runWorker(t, a)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if via == "command" {
			a.encryptDiskAbortCommand(ctx, encryptCmd(command.TypeEncryptDiskAbort, "c-abort", params))
		} else {
			req, _ := json.Marshal(encrypt.AbortRequest{Nonce: "n1", ConversionID: testConversionID, By: "operator", RequestedAt: a.d.Now()})
			if err := fsutil.WriteFile(a.d.Layout.EncryptAbortRequest(), req, 0o600, 0o700); err != nil {
				t.Fatal(err)
			}
			a.handleAbortRequest(ctx)
		}
		if c := a.st.Conversion; c.Phase != state.ConversionCancelled || c.CleanupPending || d.Exists("/var/lib/paddock/install-passphrase") {
			t.Fatalf("%s: cleanup cut short by the stop: %+v", via, c)
		}
	}
}

// TestStoreSaveFailureChangesNothing: Review 2, minor-4 — when the state cannot be saved, the abort's phase change is
// undone in memory and its event is not emitted; the abort is refused.
func TestStoreSaveFailureChangesNothing(t *testing.T) {
	params := `{"conversion_id":"` + testConversionID + `"}`
	a, _, d := convAgent(t)
	a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", params))
	runWorker(t, a)
	_ = os.Remove(a.d.Layout.Spool())
	if err := os.Remove(a.d.Layout.State()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(a.d.Layout.State(), "blocked"), 0o700); err != nil {
		t.Fatal(err)
	}
	status, result := a.encryptDiskAbortCommand(context.Background(), encryptCmd(command.TypeEncryptDiskAbort, "c-abort", params))
	if status != protocol.CommandFailed || result["reason"] != encrypt.ReasonNotAbortable {
		t.Fatalf("%s %v", status, result)
	}
	if c := a.st.Conversion; c.Phase != state.ConversionPrepared || c.CleanupPending || !d.Exists(encrypt.ModuleDir) {
		t.Fatalf("memory changed although the save failed: %+v", c)
	}
	if events, _ := a.d.Spool.Pending(); len(events) != 0 {
		t.Fatalf("events %+v", events)
	}
}

// TestAdoptClearsBusy: Review 2, minor-5 — an adoption that drops the queued job also clears conversionBusy, so a later
// full pass can queue the cleanup retry.
func TestAdoptClearsBusy(t *testing.T) {
	a, _, d := convAgent(t)
	a.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: state.ConversionPreparing, Partition: testPartition}
	a.queueConversion()
	d.setLUKS(true)
	if !a.adoptConversion(context.Background()) || len(a.conversionJobs) != 0 || a.conversionBusy {
		t.Fatalf("queued %d, busy %v", len(a.conversionJobs), a.conversionBusy)
	}
}

// failAtInitrd makes step 8 fail (initrd_incomplete) and runs then before it answers.
func failAtInitrd(d *convDevice, then func()) {
	handle := d.Handle
	done := false
	d.Handle = func(line string) (string, int, bool) {
		// Step 8's listing, not the preflight's (which runs before the module exists).
		if line == "lsinitrd /boot/.initrd.img-"+testKernel+".paddock" && !done && d.Exists(encrypt.ModuleConf) {
			done = true
			then()
			return "usr/sbin/cryptsetup\n", 0, true
		}
		return handle(line)
	}
}

// TestWorkerRetriesUnsavedFailure: Review 3, major-3 — a failure whose save failed leaves the conversion preparing;
// the next full pass queues it again, and an encrypt_disk_abort deferred meanwhile is answered by that run.
func TestWorkerRetriesUnsavedFailure(t *testing.T) {
	params := `{"conversion_id":"` + testConversionID + `"}`
	a, _, d := convAgent(t)
	failAtInitrd(d, func() {
		_ = os.Remove(a.d.Layout.State())
		_ = os.MkdirAll(filepath.Join(a.d.Layout.State(), "blocked"), 0o700)
	})
	a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", params))
	runWorker(t, a)
	if c := a.st.Conversion; c.Phase != state.ConversionPreparing || a.conversionBusy || len(a.conversionJobs) != 0 {
		t.Fatalf("after the unsaved failure: %+v, busy %v", c, a.conversionBusy)
	}
	if err := os.RemoveAll(a.d.Layout.State()); err != nil {
		t.Fatal(err)
	}
	if status, _ := a.encryptDiskAbortCommand(context.Background(), encryptCmd(command.TypeEncryptDiskAbort, "c-abort", params)); status != commands.Deferred {
		t.Fatalf("not deferred: %s", status)
	}
	a.tickConversion(context.Background())
	if len(a.conversionJobs) != 1 {
		t.Fatal("the preparation was not queued again at the full pass")
	}
	runWorker(t, a)
	if c := a.st.Conversion; c.Phase != state.ConversionCancelled || len(a.st.CommandResults) != 1 ||
		a.st.CommandResults[0].CommandID != "c-abort" || string(a.st.CommandResults[0].Result) != `{"aborted":true}` {
		t.Fatalf("conversion %+v, results %+v", c, a.st.CommandResults)
	}
}

// TestWorkerAdoptsInsteadOfCleanup: Review 3, major-2 — a preparation failing at step 8 on a partition that is LUKS
// (the disk converted at a boot the agent could not tell at its start) is adopted by the worker, not cleaned up.
func TestWorkerAdoptsInsteadOfCleanup(t *testing.T) {
	params := `{"conversion_id":"` + testConversionID + `"}`
	a, _, d := convAgent(t)
	failAtInitrd(d, func() { d.luks = true })
	a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", params))
	runWorker(t, a)
	if c := a.st.Conversion; c.Phase != state.ConversionEncrypting || c.FailureReason != "" ||
		!d.Exists("/var/lib/paddock/install-passphrase") || !d.Exists(encrypt.ModuleDir) {
		t.Fatalf("conversion %+v", c)
	}
}

// TestUninstallConversionPending: plan M8e decision 36 — refused while a conversion may still need the module and the
// key, accepted once nothing can convert or the initrd was regenerated.
func TestUninstallConversionPending(t *testing.T) {
	for name, tc := range map[string]struct {
		conv      *state.DiskConversion
		luks      bool
		refused   bool
		reencrypt bool
	}{
		"preparing":            {conv: &state.DiskConversion{Phase: state.ConversionPreparing}, refused: true},
		"prepared":             {conv: &state.DiskConversion{Phase: state.ConversionPrepared}, refused: true},
		"encrypting":           {conv: &state.DiskConversion{Phase: state.ConversionEncrypting}, refused: true},
		"completed":            {conv: &state.DiskConversion{Phase: state.ConversionCompleted}, refused: true},
		"failed resume":        {conv: &state.DiskConversion{Phase: state.ConversionFailed, FailureStage: state.StageResume}, refused: true},
		"failed prepare, LUKS": {conv: &state.DiskConversion{Phase: state.ConversionFailed, FailureStage: state.StagePrepare}, luks: true, refused: true},
		"cancelled, cleanup":   {conv: &state.DiskConversion{Phase: state.ConversionCancelled, CleanupPending: true}, refused: true},
		"failed, cleanup":      {conv: &state.DiskConversion{Phase: state.ConversionFailed, FailureStage: state.StagePrepare, CleanupPending: true}, refused: true},
		"completed, cleanup":   {conv: &state.DiskConversion{Phase: state.ConversionCompleted, InitrdRegenerated: true, CleanupPending: true}, refused: true},
		"reencrypt keyslot":    {reencrypt: true, refused: true},
		"cancelled":            {conv: &state.DiskConversion{Phase: state.ConversionCancelled}},
		"failed prepare":       {conv: &state.DiskConversion{Phase: state.ConversionFailed, FailureStage: state.StagePrepare}},
		"failed init":          {conv: &state.DiskConversion{Phase: state.ConversionFailed, FailureStage: state.StageInit}},
		"failed preflight":     {conv: &state.DiskConversion{Phase: state.ConversionFailed, FailureStage: state.StagePreflight}},
		"completed, rebuilt":   {conv: &state.DiskConversion{Phase: state.ConversionCompleted, InitrdRegenerated: true}},
		"no conversion":        {},
	} {
		a, _, d := convAgent(t)
		a.d.Executable = filepath.Join(t.TempDir(), "paddockd")
		if err := os.WriteFile(a.d.Executable, []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if tc.conv != nil {
			tc.conv.ID, tc.conv.Partition, tc.conv.Mapping, tc.conv.LUKSUUID = testConversionID, testPartition, "dm_crypt-0", testLUKSUUID
		}
		a.st.Conversion = tc.conv
		d.setLUKS(tc.luks)
		if tc.reencrypt {
			a.d.LUKS = reencryptingRoot{t}
		}
		status, result := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`))
		if refused := result["reason"] == "conversion_pending"; refused != tc.refused {
			t.Fatalf("%s: %s %v", name, status, result)
		}
		if tc.refused && (status != protocol.CommandFailed || result["accepted"] != false || a.st.PendingUninstall != nil) {
			t.Fatalf("%s: %s %v", name, status, result)
		}
	}
}

// reencryptingRoot is a root volume on LUKS2 with an unfinished reencryption (luks.Tools).
type reencryptingRoot struct{ t *testing.T }

func (r reencryptingRoot) Command(_ context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	switch {
	case name == "findmnt":
		return "/dev/mapper/dm_crypt-0\n", "", 0, nil
	case name == "lsblk":
		return `{"blockdevices":[{"name":"/dev/mapper/dm_crypt-0","type":"crypt","fstype":"ext4","children":[` +
			`{"name":"/dev/sda3","type":"part","fstype":"crypto_LUKS"}]}]}`, "", 0, nil
	case name == "cryptsetup" && len(args) > 0 && args[0] == "luksDump":
		raw, err := os.ReadFile("../luks/testdata/reencrypt-password.json")
		if err != nil {
			r.t.Fatal(err)
		}
		return string(raw), "", 0, nil
	}
	r.t.Errorf("unexpected %s %v", name, args)
	return "", "", 1, nil
}

// TestSupervisorUpgradeHeldWhilePreparing: plan M8e decision 37 as amended on 2026-10-21 (item 18) — no supervisor
// upgrade starts while the worker runs a preparation step; a preparation waiting between its passes (packages_busy,
// possibly for a long time) does not hold the agent's update channel.
func TestSupervisorUpgradeHeldWhilePreparing(t *testing.T) {
	a, _, launched := supervisorAgent(t, "")
	since := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	a.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: state.ConversionPreparing, PackagesBusySince: &since}
	a.conversionBusy = true
	a.Cycle(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("installed while a preparation step ran: %v", *launched)
	}
	a.conversionBusy = false
	a.Cycle(context.Background())
	if len(*launched) != 1 {
		t.Fatalf("held back while the preparation waits for the dpkg lock: %v", *launched)
	}
}

// TestHoldForSupervisor: the worker waits while supervisor-upgrade.json exists, at most 30 minutes from its start
// (the mtime of an unreadable marker), and not at all without one.
func TestHoldForSupervisor(t *testing.T) {
	a, _, _ := convAgent(t)
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	sleeps := 0
	a.d.Sleep = func(_ context.Context, d time.Duration) error {
		sleeps++
		now = now.Add(d)
		return nil
	}
	if err := a.holdForSupervisor(context.Background()); err != nil || sleeps != 0 {
		t.Fatalf("waited without a marker: %d %v", sleeps, err)
	}
	marker, _ := json.Marshal(supervisorpkg.Marker{Version: "1.2.0", StartedAt: now.Add(-20 * time.Minute)})
	if err := fsutil.WriteFile(a.d.Layout.SupervisorUpgrade(), marker, 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := a.holdForSupervisor(context.Background()); err != nil || sleeps != 20 {
		t.Fatalf("sleeps %d %v", sleeps, err)
	}
	if err := os.WriteFile(a.d.Layout.SupervisorUpgrade(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(a.d.Layout.SupervisorUpgrade(), now, now.Add(-29*time.Minute)); err != nil {
		t.Fatal(err)
	}
	sleeps = 0
	if err := a.holdForSupervisor(context.Background()); err != nil || sleeps != 2 {
		t.Fatalf("unreadable marker: sleeps %d %v", sleeps, err)
	}
}

// TestEncryptAbortRequest: `paddockd encrypt-abort` through the agent (plan M8e decision 14 as corrected): a prepared
// conversion is aborted with by operator; a conversion on a LUKS partition is refused and nothing changes.
func TestEncryptAbortRequest(t *testing.T) {
	params := `{"conversion_id":"` + testConversionID + `"}`
	for _, luks := range []bool{false, true} {
		a, _, d := convAgent(t)
		a.encryptDiskCommand(context.Background(), encryptCmd(command.TypeEncryptDisk, "c-1", params))
		runWorker(t, a)
		_ = os.Remove(a.d.Layout.Spool())
		d.setLUKS(luks)
		req, _ := json.Marshal(encrypt.AbortRequest{Nonce: "n1", ConversionID: testConversionID, By: "operator", RequestedAt: a.d.Now()})
		if err := fsutil.WriteFile(a.d.Layout.EncryptAbortRequest(), req, 0o600, 0o700); err != nil {
			t.Fatal(err)
		}
		a.handleAbortRequest(context.Background())
		var resp encrypt.AbortResponse
		raw, _ := os.ReadFile(a.d.Layout.EncryptAbortResponse())
		_ = json.Unmarshal(raw, &resp)
		if d.Exists("/var/lib/paddock/encrypt-abort.request") || resp.Nonce != "n1" || resp.State != encrypt.AbortDone {
			t.Fatalf("luks %v: response %+v", luks, resp)
		}
		events := spooled(t, a)
		if luks {
			if resp.Aborted || resp.Reason != "not_abortable" || a.st.Conversion.Phase != state.ConversionPrepared || len(events) != 0 ||
				!d.Exists(encrypt.ModuleDir) {
				t.Fatalf("refusal changed something: %+v %+v", resp, a.st.Conversion)
			}
			continue
		}
		if !resp.Aborted || a.st.Conversion.Phase != state.ConversionCancelled || len(events) != 1 ||
			eventData(t, events[0])["by"] != "operator" || d.Exists(encrypt.ModuleDir) {
			t.Fatalf("abort: %+v %+v %v", resp, a.st.Conversion, events)
		}
	}
}

// TestRestartNotificationOnSessionPoll: while prepared the session poll notifies the graphical sessions and records
// them in the state; in another phase it does not.
func TestRestartNotificationOnSessionPoll(t *testing.T) {
	a, _, d := convAgent(t)
	runs := 0
	inner := d.Handle
	d.Handle = func(line string) (string, int, bool) {
		switch {
		case line == "loginctl list-sessions --no-legend":
			return "3 1000 u -\n", 0, true
		case strings.HasPrefix(line, "loginctl show-session"):
			return "Id=3\nUser=1000\nName=u\nClass=user\nType=wayland\n", 0, true
		case line == "getent passwd 1000":
			return "u:x:1000:1000::/home/u:/bin/bash\n", 0, true
		case strings.HasPrefix(line, "systemd-run "):
			runs++
			return "", 0, true
		}
		return inner(line)
	}
	a.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: state.ConversionPreparing}
	a.tickConversionSessions(context.Background())
	if runs != 0 {
		t.Fatal("notified while preparing")
	}
	a.st.Conversion.Phase = state.ConversionPrepared
	a.tickConversionSessions(context.Background())
	a.tickConversionSessions(context.Background())
	if runs != 1 {
		t.Fatalf("runs %d", runs)
	}
	if st, _ := state.Load(a.d.Layout.State()); st.Conversion == nil || len(st.Conversion.Notified) != 1 {
		t.Fatalf("notified not persisted: %+v", st.Conversion)
	}
}

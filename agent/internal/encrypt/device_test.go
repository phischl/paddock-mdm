package encrypt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/encrypt/encrypttest"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
)

// Kernels of the fake device: the running one and an older one whose initrd GRUB still offers.
const (
	runningKernel = "6.8.0-85-generic"
	olderKernel   = "6.8.0-79-generic"
	conversionID  = "5b0e7c1a-2f4d-4e8b-9a6c-3d1f0e2b4a7c"
)

// device is the fake system of a preparation: the lvm fixture plus dpkg, apt-get, dracut and lsinitrd that answer
// from what the code under test did.
type device struct {
	*encrypttest.Host
	t      *testing.T
	layout paths.Layout

	mu sync.Mutex
	// packages are the dpkg states; installDracut moves dracut in and removes realRemove (the state "rc" counts).
	packages   map[string]string
	realRemove map[string]string
	aptExit    int
	dracutExit int
	// incomplete makes dracut build an initrd without resize2fs; stale keeps paddock-encrypt in the older kernel's
	// initrd whatever dracut does.
	incomplete, stale bool
	luks              bool
	// luksExit makes cryptsetup isLuks exit with this code (4: the device could not be opened).
	luksExit int
	// dpkgExit makes dpkg-query fail with this exit code for dracut (2: dpkg could not answer).
	dpkgExit int
	// missing are the tools that are not installed.
	missing map[string]bool
}

// partition is the root partition of the lvm fixture; it exists below the root like udev's link.
const partition = "/dev/disk/by-partuuid/8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f"

func newDevice(t *testing.T) *device {
	t.Helper()
	h := encrypttest.Load(t, "testdata/lvm.txt")
	d := &device{Host: h, t: t, layout: paths.Layout{Root: h.Root},
		packages: map[string]string{"brltty": "installed", "initramfs-tools": "installed", "bash": "installed",
			"old-tool": "config-files"},
		realRemove: map[string]string{"brltty": "config-files", "initramfs-tools": "not-installed"}}
	h.Write("/proc/sys/kernel/osrelease", runningKernel+"\n")
	h.Write("/boot/vmlinuz-"+runningKernel, "kernel")
	h.MkdirAll("/lib/modules/" + runningKernel)
	h.MkdirAll("/lib/modules/" + olderKernel)
	h.Write("/boot/initrd.img-"+runningKernel, "initramfs-tools image\n")
	h.Write("/boot/initrd.img-"+olderKernel, "initramfs-tools image\n")
	h.MkdirAll("/sys/module/dm_crypt")
	h.Write(partition, "")
	h.Handle = d.handle
	h.NotFound = func(name string) bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.missing[name]
	}
	return d
}

func (d *device) handle(line string) (string, int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case line == "dpkg-query -W -f=${db:Status-Status} dracut":
		if d.dpkgExit != 0 {
			return "", d.dpkgExit, true
		}
		if s, ok := d.packages["dracut"]; ok {
			return s, 0, true
		}
		return "", 1, true
	case line == "dpkg-query -W -f=${Package} ${db:Status-Status}\n":
		var b strings.Builder
		for p, s := range d.packages {
			b.WriteString(p + " " + s + "\n")
		}
		return b.String(), 0, true
	case line == "apt-get install -y dracut":
		if d.aptExit != 0 {
			return "E: failed", d.aptExit, true
		}
		d.packages["dracut"], d.packages["dracut-core"] = "installed", "installed"
		for p, s := range d.realRemove {
			d.packages[p] = s
		}
		return "", 0, true
	case line == "blockdev --getsize64 /dev/disk/by-partuuid/8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f":
		return "40793800704\n", 0, true
	case line == "lvm lvs --noheadings --units b --nosuffix -o lv_size /dev/ubuntu-vg/ubuntu-lv":
		return "  20396900352\n", 0, true
	case line == "lvm vgs --noheadings --units b --nosuffix -o vg_extent_size ubuntu-vg":
		return "  4194304\n", 0, true
	case line == "cryptsetup isLuks "+partition:
		if d.luksExit != 0 {
			return "", d.luksExit, true
		}
		if d.luks {
			return "", 0, true
		}
		return "", 1, true
	case line == "dracut -f --regenerate-all":
		if d.dracutExit != 0 {
			return "", d.dracutExit, true
		}
		d.buildInitrds()
		return "", 0, true
	case strings.HasPrefix(line, "lsinitrd /boot/initrd.img-"), strings.HasPrefix(line, "lsinitramfs /boot/initrd.img-"):
		raw, err := os.ReadFile(d.Path(line[strings.Index(line, " ")+1:]))
		if err != nil {
			return "", 1, true
		}
		return string(raw), 0, true
	}
	return "", 0, false
}

// buildInitrds writes, as dracut would, an initrd listing for every kernel: with the module while its configuration
// and plan.env exist (the module's check()).
func (d *device) buildInitrds() {
	listing := "Image: initrd\ndracut modules:\nsystemd\ncrypt\n" +
		"-rwxr-xr-x   1 root root   123 Oct 21 10:00 usr/sbin/cryptsetup\n" +
		"-rwxr-xr-x   1 root root   123 Oct 21 10:00 usr/sbin/e2fsck\n" +
		"-rwxr-xr-x   1 root root   123 Oct 21 10:00 usr/sbin/lvm\n"
	if !d.incomplete {
		listing += "-rwxr-xr-x   1 root root   123 Oct 21 10:00 usr/sbin/resize2fs\n"
	}
	module := d.Exists(encrypt.ModuleConf) && d.Exists(encrypt.ModuleDir) && d.Exists("/var/lib/paddock/encrypt/plan.env")
	if module {
		listing += "paddock-encrypt\n" +
			"-rw-------   1 root root   300 Oct 21 10:00 etc/paddock/encrypt-plan.env\n" +
			"-rw-------   1 root root    71 Oct 21 10:00 etc/paddock/encrypt-key\n" +
			"-rw-r--r--   1 root root   400 Oct 21 10:00 usr/lib/systemd/system/paddock-encrypt-init.service\n"
	}
	for _, v := range []string{runningKernel, olderKernel} {
		content := listing
		if v == olderKernel && d.stale {
			content += "paddock-encrypt\n"
		}
		d.Write("/boot/initrd.img-"+v, content)
	}
}

func (d *device) set(fn func(d *device)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fn(d)
}

// initrdCarriesModule reports whether a kernel's initrd lists the module.
func (d *device) initrdCarriesModule(v string) bool {
	raw, _ := os.ReadFile(d.Path("/boot/initrd.img-" + v))
	return strings.Contains(string(raw), "paddock-encrypt")
}

// event is an emitted device event.
type event struct {
	typ  string
	data map[string]any
}

// memStore is encrypt.Store in memory.
type memStore struct {
	mu     sync.Mutex
	c      *state.DiskConversion
	luks   state.LUKS
	events []event
	// beforeUpdate runs inside Update before fn: a change the run loop made in between.
	beforeUpdate func(c *state.DiskConversion)
	// saveErr fails an Update or Transition before it changes anything when it returns an error: the state could not
	// be saved.
	saveErr func(c *state.DiskConversion) error
	// goneAfter ends the store (the run loop is gone, the agent stops) after the Update or Transition it returns true
	// for: every later call fails.
	goneAfter func(c *state.DiskConversion) bool
	gone      bool
}

func (s *memStore) Conversion() (state.DiskConversion, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.c == nil || s.gone {
		return state.DiskConversion{}, false
	}
	return *s.c, true
}

func (s *memStore) Update(fn func(c *state.DiskConversion, l *state.LUKS)) error {
	return s.Transition(func(c *state.DiskConversion, l *state.LUKS) *encrypt.Event {
		fn(c, l)
		return nil
	})
}

func (s *memStore) Transition(fn func(c *state.DiskConversion, l *state.LUKS) *encrypt.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gone {
		return errors.New("run loop gone")
	}
	if s.c == nil {
		return errors.New("no conversion")
	}
	if s.beforeUpdate != nil {
		s.beforeUpdate(s.c)
	}
	if s.saveErr != nil {
		if err := s.saveErr(s.c); err != nil {
			return err
		}
	}
	if ev := fn(s.c, &s.luks); ev != nil {
		s.events = append(s.events, event{ev.Type, ev.Data})
	}
	if s.goneAfter != nil && s.goneAfter(s.c) {
		s.gone = true
	}
	return nil
}

func (s *memStore) types() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.events {
		out = append(out, e.typ)
	}
	return out
}

// escrowServer is the device API's escrow endpoint: it answers Status from statuses in turn ("stored" when used up)
// and calls onStatus first.
type escrowServer struct {
	mu       sync.Mutex
	key      *rsa.PrivateKey
	requests []escrow.Request
	statuses []string
	onStatus func()
}

func (e *escrowServer) Upload(_ context.Context, req escrow.Request) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requests = append(e.requests, req)
	return nil
}

func (e *escrowServer) Status(context.Context, string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.onStatus != nil {
		e.onStatus()
	}
	if len(e.statuses) == 0 {
		return escrow.StatusStored, nil
	}
	s := e.statuses[0]
	e.statuses = e.statuses[1:]
	return s, nil
}

// module is the embedded module of a test build.
var module = fstest.MapFS{
	"module-setup.sh":              {Data: []byte("#!/bin/bash\ncheck() { return 0; }\n")},
	"paddock-encrypt-init.sh":      {Data: []byte("#!/bin/sh\n")},
	"paddock-encrypt-init.service": {Data: []byte("[Unit]\n")},
}

// fixture is a preparation on the fake device.
type fixture struct {
	t      *testing.T
	dev    *device
	store  *memStore
	server *escrowServer
	keys   *bundle.Keys
	now    time.Time
}

// escrowWrapKey is one escrow-wrap key for every test (3072 bits, the minimum escrow.Encrypt accepts).
var escrowWrapKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		panic(err)
	}
	return key
})

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := escrowWrapKey()
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	f := &fixture{t: t, dev: newDevice(t), server: &escrowServer{key: key}, now: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC),
		store: &memStore{c: &state.DiskConversion{ID: conversionID, CommandID: "c-1", Phase: state.ConversionPreparing},
			luks: state.LUKS{RecoveryAttempted: 2, RecoveryStored: 2}},
		keys: &bundle.Keys{EscrowWrap: &bundle.EncryptionKey{KeyID: "escrow-wrap:v1",
			PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}}
	return f
}

func (f *fixture) preparer() *encrypt.Preparer {
	return &encrypt.Preparer{Sys: f.dev, Layout: f.dev.layout, Escrow: f.server, Keys: f.keys,
		Disk: &bundle.DiskSpec{UnlockMode: bundle.UnlockModeTPMOnly, BootPINMinLength: 6}, State: f.store, Module: module,
		Now: func() time.Time { return f.now },
		Sleep: func(_ context.Context, d time.Duration) error {
			f.now = f.now.Add(d)
			return nil
		}}
}

func (f *fixture) conversion() state.DiskConversion {
	c, _ := f.store.Conversion()
	return c
}

func (f *fixture) read(path string) string {
	f.t.Helper()
	raw, err := os.ReadFile(f.dev.Path(path))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw)
}

func (f *fixture) mode(path string) os.FileMode {
	f.t.Helper()
	info, err := os.Stat(f.dev.Path(path))
	if err != nil {
		f.t.Fatal(err)
	}
	return info.Mode().Perm()
}

// moduleGone reports whether the module directory and its configuration are removed.
func (f *fixture) moduleGone() bool {
	return !f.dev.Exists(encrypt.ModuleDir) && !f.dev.Exists(encrypt.ModuleConf)
}

func (f *fixture) longCalls(prefix string) int {
	return len(slices.DeleteFunc(f.dev.Long(), func(l string) bool { return !strings.HasPrefix(l, prefix) }))
}

func glob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func statMode(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Mode().Perm(), nil
}

func removeAll(path string) error { return os.RemoveAll(path) }

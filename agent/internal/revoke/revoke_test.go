package revoke

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/revocation"
)

const (
	device = "0190f000-0000-7000-8000-000000000001"
	org    = "0190f000-0000-7000-8000-0000000000aa"
)

var (
	now        = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	trustedKey = ed25519.NewKeyFromSeed([]byte("paddock-revoke-test-trusted-key!"))
	otherKey   = ed25519.NewKeyFromSeed([]byte("paddock-revoke-test-other---key!"))
)

// fakeVolume is a LUKS volume of fakeSys.
type fakeVolume struct {
	slots     int
	luks1     bool // only the text dump of a LUKS1 header, no JSON metadata
	eraseFail bool
}

// fakeSys is a device with two keyslots on its root volume /dev/vda3, the marker and the trust anchor; it logs every
// action. targets are the volumes Targets returns, root last.
type fakeSys struct {
	mu      sync.Mutex
	files   map[string][]byte
	volumes map[string]*fakeVolume
	targets Targets
	log     []string
	rootErr error
}

func newSys(t *testing.T) *fakeSys {
	t.Helper()
	trust, _ := json.Marshal(revocation.TrustFile{RevocationKeys: []revocation.Key{{KeyID: "revocation-signing:v1",
		PublicKey: base64.StdEncoding.EncodeToString(trustedKey.Public().(ed25519.PublicKey))}}})
	return &fakeSys{files: map[string][]byte{EnabledFile: {}, TrustFile: trust},
		volumes: map[string]*fakeVolume{"/dev/vda3": {slots: 2}}, targets: Targets{Devices: []string{"/dev/vda3"}}}
}

func (s *fakeSys) add(entry string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, entry)
}

func (s *fakeSys) Command(_ context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	s.add(name + " " + strings.Join(args, " "))
	v := s.volumes[args[len(args)-1]]
	switch {
	case name != "cryptsetup" || v == nil:
	case args[0] == "luksDump" && args[1] == "--dump-json-metadata":
		if v.luks1 {
			return "", "Unsupported for LUKS1", 1, nil
		}
		slots := map[string]any{}
		for i := range v.slots {
			slots[string(rune('0'+i))] = map[string]any{"type": "luks2"}
		}
		out, _ := json.Marshal(map[string]any{"keyslots": slots, "tokens": map[string]any{}})
		return string(out), "", 0, nil
	case args[0] == "luksDump" && v.luks1:
		var out strings.Builder
		out.WriteString("LUKS header information for " + args[len(args)-1] + "\n\nVersion:       \t1\nCipher name:   \taes\n\n")
		for i := range 8 {
			state := "DISABLED"
			if i < v.slots {
				state = "ENABLED"
			}
			fmt.Fprintf(&out, "Key Slot %d: %s\n", i, state)
		}
		return out.String(), "", 0, nil
	case args[0] == "luksErase":
		if v.eraseFail {
			return "", "erase failed", 1, nil
		}
		v.slots = 0
		return "", "", 0, nil
	}
	return "", "unexpected", 1, nil
}

func (s *fakeSys) Loginctl(_ context.Context, args ...string) (string, int, error) {
	s.add("loginctl " + strings.Join(args, " "))
	if args[0] == "list-users" {
		return "120 gdm no active\n1000 paddock no active\n200001 alice no online\n65534 nobody no closing\n", 0, nil
	}
	return "", 0, nil
}

func (s *fakeSys) Targets(context.Context) (Targets, error) {
	if s.rootErr != nil {
		return Targets{}, s.rootErr
	}
	return s.targets, nil
}

func (s *fakeSys) Reboot(context.Context) error { s.add("reboot"); return nil }

func (s *fakeSys) ReadFile(path string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return data, nil
}

func (s *fakeSys) WriteFile(path string, data []byte) error {
	s.add("write " + path)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[path] = data
	return nil
}

// fakeConfirmer records confirmations; fail makes every one fail.
type fakeConfirmer struct {
	sys     *fakeSys
	results []protocol.CommandResult
	fail    bool
}

func (c *fakeConfirmer) Confirm(_ context.Context, id string, res protocol.CommandResult) error {
	c.sys.add("confirm " + id)
	if c.fail {
		return errors.New("server unreachable")
	}
	c.results = append(c.results, res)
	return nil
}

func token(t *testing.T, key ed25519.PrivateKey, change func(*revocation.Token)) []byte {
	t.Helper()
	tok := revocation.Token{CommandID: "0190f000-0000-7000-8000-0000000000c1", DeviceID: device, OrganizationID: org,
		Action: revocation.ActionLock, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(revocation.Lifetime - time.Hour),
		RequestID: "0190f000-0000-7000-8000-0000000000c1"}
	if change != nil {
		change(&tok)
	}
	payload, err := revocation.Encode(tok)
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.New(revocation.PayloadType, payload,
		dsse.SignEd25519(key, "revocation-signing:v1", revocation.PayloadType, payload)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func revoker(sys *fakeSys, c *fakeConfirmer) *Revoker {
	return &Revoker{Sys: sys, Confirm: c, DeviceID: device, Now: func() time.Time { return now }, ConfirmWithin: 2 * time.Second}
}

// TestSequence (plan M4c decision 12): state first, then the sessions of non-system users, the erasure with its
// verification, the confirmation, the reboot — in this order and nothing in between.
func TestSequence(t *testing.T) {
	sys := newSys(t)
	c := &fakeConfirmer{sys: sys}
	e, stored, err := revoker(sys, c).Handle(context.Background(), token(t, trustedKey, nil))
	if err != nil || stored || !reflect.DeepEqual(e, Erasure{Erased: true, SlotsBefore: 2, SlotsAfter: 0,
		Volumes: []VolumeErasure{{Device: "/dev/vda3", SlotsBefore: 2, SlotsAfter: 0, Erased: true}}}) {
		t.Fatalf("execute: %+v %v", e, err)
	}
	want := []string{
		"write " + StateFile,
		"loginctl list-users --no-legend", "loginctl terminate-user 1000", "loginctl terminate-user 200001",
		"cryptsetup luksDump --dump-json-metadata -- /dev/vda3",
		"cryptsetup luksErase --batch-mode -- /dev/vda3",
		"cryptsetup luksDump --dump-json-metadata -- /dev/vda3",
		"confirm 0190f000-0000-7000-8000-0000000000c1",
		"reboot",
	}
	if !slices.Equal(sys.log, want) {
		t.Fatalf("sequence\n%s\nwant\n%s", strings.Join(sys.log, "\n"), strings.Join(want, "\n"))
	}
	if len(c.results) != 1 || c.results[0].Status != protocol.CommandSucceeded ||
		string(c.results[0].Result) != `{"erased":true,"slots_before":2,"slots_after":0,`+
			`"volumes":[{"device":"/dev/vda3","slots_before":2,"slots_after":0,"erased":true}]}` {
		t.Fatalf("confirmation %s", c.results[0].Result)
	}
}

// TestEveryVolume (plan M4c.1 decisions 1–3): every target is erased and verified, the root volume last; the
// confirmation lists every volume and the unresolved crypttab entries, and erased is true as every volume has no
// keyslot left. A LUKS1 volume is counted from its text dump.
func TestEveryVolume(t *testing.T) {
	sys := newSys(t)
	sys.volumes["/dev/vdb1"] = &fakeVolume{slots: 3}
	sys.volumes["/dev/vdc"] = &fakeVolume{slots: 1, luks1: true}
	sys.targets = Targets{Devices: []string{"/dev/vdb1", "/dev/vdc", "/dev/vda3"}, Unresolved: []string{"UUID=0000-gone"}}
	c := &fakeConfirmer{sys: sys}
	e, _, err := revoker(sys, c).Handle(context.Background(), token(t, trustedKey, nil))
	want := Erasure{Erased: true, SlotsBefore: 6, SlotsAfter: 0, Unresolved: []string{"UUID=0000-gone"}, Volumes: []VolumeErasure{
		{Device: "/dev/vdb1", SlotsBefore: 3, SlotsAfter: 0, Erased: true},
		{Device: "/dev/vdc", SlotsBefore: 1, SlotsAfter: 0, Erased: true},
		{Device: "/dev/vda3", SlotsBefore: 2, SlotsAfter: 0, Erased: true},
	}}
	t.Logf("per-volume results: %+v", e)
	if err != nil || !reflect.DeepEqual(e, want) {
		t.Fatalf("execute: %+v %v\nwant %+v", e, err, want)
	}
	erases := []string{}
	for _, entry := range sys.log {
		if strings.HasPrefix(entry, "cryptsetup luksErase") {
			erases = append(erases, entry)
		}
	}
	if !slices.Equal(erases, []string{"cryptsetup luksErase --batch-mode -- /dev/vdb1",
		"cryptsetup luksErase --batch-mode -- /dev/vdc", "cryptsetup luksErase --batch-mode -- /dev/vda3"}) {
		t.Fatalf("erasures %v", erases)
	}
	if tail := sys.log[len(sys.log)-2:]; !slices.Equal(tail, []string{"confirm 0190f000-0000-7000-8000-0000000000c1", "reboot"}) {
		t.Fatalf("sequence ends with %v", tail)
	}
	var posted Erasure
	if len(c.results) != 1 || c.results[0].Status != protocol.CommandSucceeded ||
		json.Unmarshal(c.results[0].Result, &posted) != nil || !reflect.DeepEqual(posted, want) {
		t.Fatalf("confirmation %+v", c.results)
	}
}

// TestOneVolumeLeftKeyslots (plan M4c.1 decision 2): a volume whose erasure failed does not stop the others, and the
// confirmation reports the revocation as failed with that volume's keyslots.
func TestOneVolumeLeftKeyslots(t *testing.T) {
	sys := newSys(t)
	sys.volumes["/dev/vdb1"] = &fakeVolume{slots: 3, eraseFail: true}
	sys.targets = Targets{Devices: []string{"/dev/vdb1", "/dev/vda3"}}
	c := &fakeConfirmer{sys: sys}
	e, _, err := revoker(sys, c).Handle(context.Background(), token(t, trustedKey, nil))
	t.Logf("per-volume results: %+v", e)
	if err != nil || e.Erased || e.SlotsBefore != 5 || e.SlotsAfter != 3 || len(e.Volumes) != 2 ||
		e.Volumes[0] != (VolumeErasure{Device: "/dev/vdb1", SlotsBefore: 3, SlotsAfter: 3}) ||
		e.Volumes[1] != (VolumeErasure{Device: "/dev/vda3", SlotsBefore: 2, SlotsAfter: 0, Erased: true}) {
		t.Fatalf("execute: %+v %v", e, err)
	}
	if len(c.results) != 1 || c.results[0].Status != protocol.CommandFailed || sys.log[len(sys.log)-1] != "reboot" {
		t.Fatalf("confirmation %+v, log %v", c.results, sys.log)
	}
}

// TestUnknownKeyslotCount: a volume whose keyslots cannot be counted after the erasure is never reported as erased.
func TestUnknownKeyslotCount(t *testing.T) {
	sys := newSys(t)
	sys.targets = Targets{Devices: []string{"/dev/vdz", "/dev/vda3"}}
	e, _, err := revoker(sys, &fakeConfirmer{sys: sys}).Handle(context.Background(), token(t, trustedKey, nil))
	if err != nil || e.Erased || e.SlotsAfter != -1 || e.Volumes[0].SlotsAfter != -1 || e.Volumes[0].Erased || !e.Volumes[1].Erased {
		t.Fatalf("execute: %+v %v", e, err)
	}
}

// TestRebootWithoutConfirmation: the device reboots although the server never confirms; an erasure that left a
// keyslot is reported as failed.
func TestRebootWithoutConfirmation(t *testing.T) {
	sys := newSys(t)
	sys.volumes["/dev/vda3"].eraseFail = true
	c := &fakeConfirmer{sys: sys, fail: true}
	start := time.Now()
	e, _, err := revoker(sys, c).Handle(context.Background(), token(t, trustedKey, nil))
	if err != nil || e.Erased || e.SlotsAfter != 2 {
		t.Fatalf("execute: %+v %v", e, err)
	}
	if sys.log[len(sys.log)-1] != "reboot" || time.Since(start) < 2*time.Second {
		t.Fatalf("no reboot after the confirmation timeout: %v after %s", sys.log, time.Since(start))
	}
	if n := strings.Count(strings.Join(sys.log, "\n"), "confirm "); n < 2 {
		t.Fatalf("confirmation tried %d times", n)
	}
}

// TestRefusals is gate R4 at the unit level: every refusal leaves sessions and keyslots alone.
func TestRefusals(t *testing.T) {
	executed := func(sys *fakeSys) {
		st, _ := json.Marshal(state{Executed: map[string]time.Time{"0190f000-0000-7000-8000-0000000000c1": now.Add(-48 * time.Hour)}})
		sys.files[StateFile] = st
	}
	recent := func(sys *fakeSys) {
		at := now.Add(-23 * time.Hour)
		st, _ := json.Marshal(state{Executed: map[string]time.Time{"other": at}, LastRevocationAt: &at})
		sys.files[StateFile] = st
	}
	cases := map[string]struct {
		prepare func(*fakeSys)
		token   func(*testing.T) []byte
		elapsed time.Duration // > 0: run as the dead man's switch
		reason  string
	}{
		"missing marker":  {prepare: func(s *fakeSys) { delete(s.files, EnabledFile) }, reason: ReasonDisabled},
		"no trust anchor": {prepare: func(s *fakeSys) { delete(s.files, TrustFile) }, reason: ReasonNoTrust},
		"untrusted key":   {token: func(t *testing.T) []byte { return token(t, otherKey, nil) }, reason: ReasonSignature},
		"garbage":         {token: func(*testing.T) []byte { return []byte("{}") }, reason: ReasonSignature},
		"wrong device":    {token: func(t *testing.T) []byte { return token(t, trustedKey, func(k *revocation.Token) { k.DeviceID = org }) }, reason: ReasonWrongDevice},
		"expired": {token: func(t *testing.T) []byte {
			return token(t, trustedKey, func(k *revocation.Token) { k.ExpiresAt = now })
		}, reason: ReasonExpired},
		"already executed":   {prepare: executed, reason: ReasonExecuted},
		"second within 24 h": {prepare: recent, reason: ReasonRateLimited},
		"self-lock before its period": {token: func(t *testing.T) []byte {
			return token(t, trustedKey, func(k *revocation.Token) { k.Action, k.PeriodDays = revocation.ActionSelfLock, 30 })
		}, elapsed: 30*dayLength - time.Second, reason: ReasonPeriod},
		"dead man's switch with a Lock":  {elapsed: 30 * dayLength, reason: ReasonNotSelfLock},
		"test target in a release build": {prepare: func(s *fakeSys) { s.rootErr = refuse(ReasonTestTarget) }, reason: ReasonTestTarget},
		"root not on LUKS":               {prepare: func(s *fakeSys) { s.rootErr = luks.ErrNotEncrypted }, reason: ReasonNotEncrypted},
		"no target":                      {prepare: func(s *fakeSys) { s.targets = Targets{Unresolved: []string{"UUID=x"}} }, reason: ReasonInternal},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			sys := newSys(t)
			if c.prepare != nil {
				c.prepare(sys)
			}
			env := token(t, trustedKey, nil)
			if c.token != nil {
				env = c.token(t)
			}
			r := revoker(sys, &fakeConfirmer{sys: sys})
			var err error
			if c.elapsed > 0 {
				_, err = r.SelfLock(context.Background(), env, c.elapsed)
			} else {
				_, _, err = r.Handle(context.Background(), env)
			}
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Reason != c.reason {
				t.Fatalf("got %v, want refusal %s", err, c.reason)
			}
			if len(sys.log) != 0 {
				t.Fatalf("a refused token changed the device: %v", sys.log)
			}
		})
	}
}

// TestSelfLockStoredThenRun (plan M4c decisions 15 and 16): a self-lock token paddockd hands over is stored, not run;
// the dead man's switch runs it once its period has passed.
func TestSelfLockStoredThenRun(t *testing.T) {
	sys := newSys(t)
	r := revoker(sys, &fakeConfirmer{sys: sys})
	env := token(t, trustedKey, func(k *revocation.Token) { k.Action, k.PeriodDays = revocation.ActionSelfLock, 30 })
	if _, stored, err := r.Handle(context.Background(), env); err != nil || !stored || string(sys.files[SelfLockFile]) != string(env) {
		t.Fatalf("hand-off of a self-lock: stored %v, %v", stored, err)
	}
	if len(sys.log) != 1 || sys.log[0] != "write "+SelfLockFile {
		t.Fatalf("storing changed more: %v", sys.log)
	}
	// A wall clock set two years ahead neither expires nor defers the stored token.
	r.Now = func() time.Time { return now.Add(2 * 365 * 24 * time.Hour) }
	e, err := r.SelfLock(context.Background(), env, 30*dayLength)
	if err != nil || !e.Erased || sys.log[len(sys.log)-1] != "reboot" {
		t.Fatalf("self-lock after its period: %+v %v %v", e, err, sys.log)
	}
}

// TestSecondTokenRefused: after a revocation every token is refused for 24 h, the same token for ever.
func TestSecondTokenRefused(t *testing.T) {
	sys := newSys(t)
	r := revoker(sys, &fakeConfirmer{sys: sys})
	if _, _, err := r.Handle(context.Background(), token(t, trustedKey, nil)); err != nil {
		t.Fatal(err)
	}
	other := token(t, trustedKey, func(k *revocation.Token) { k.CommandID = "0190f000-0000-7000-8000-0000000000c2" })
	var refusal *Refusal
	if _, _, err := r.Handle(context.Background(), other); !errors.As(err, &refusal) || refusal.Reason != ReasonRateLimited {
		t.Fatalf("second token: %v", err)
	}
	r.Now = func() time.Time { return now.Add(25 * time.Hour) }
	if _, _, err := r.Handle(context.Background(), token(t, trustedKey, nil)); !errors.As(err, &refusal) || refusal.Reason != ReasonExecuted {
		t.Fatalf("same token a day later: %v", err)
	}
}

func TestUserIDs(t *testing.T) {
	if got := userIDs("120 gdm no active\n1000 paddock\n 200001 alice\n65534 nobody\n\nUID USER\n"); !slices.Equal(got, []int{1000, 200001}) {
		t.Fatalf("uids %v", got)
	}
}

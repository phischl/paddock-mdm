package revoke

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

// fakeSys is a device with two keyslots on /dev/vda3, the marker and the trust anchor; it logs every action.
type fakeSys struct {
	mu        sync.Mutex
	files     map[string][]byte
	slots     int
	log       []string
	rootErr   error
	eraseFail bool
}

func newSys(t *testing.T) *fakeSys {
	t.Helper()
	trust, _ := json.Marshal(revocation.TrustFile{RevocationKeys: []revocation.Key{{KeyID: "revocation-signing:v1",
		PublicKey: base64.StdEncoding.EncodeToString(trustedKey.Public().(ed25519.PublicKey))}}})
	return &fakeSys{files: map[string][]byte{EnabledFile: {}, TrustFile: trust}, slots: 2}
}

func (s *fakeSys) add(entry string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, entry)
}

func (s *fakeSys) Command(_ context.Context, _ []string, name string, args ...string) (string, string, int, error) {
	s.add(name + " " + strings.Join(args, " "))
	switch {
	case name == "cryptsetup" && args[0] == "luksDump":
		slots := map[string]any{}
		for i := range s.slots {
			slots[string(rune('0'+i))] = map[string]any{"type": "luks2"}
		}
		out, _ := json.Marshal(map[string]any{"keyslots": slots, "tokens": map[string]any{}})
		return string(out), "", 0, nil
	case name == "cryptsetup" && args[0] == "luksErase":
		if s.eraseFail {
			return "", "erase failed", 1, nil
		}
		s.slots = 0
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

func (s *fakeSys) RootDevice(context.Context) (string, error) {
	if s.rootErr != nil {
		return "", s.rootErr
	}
	return "/dev/vda3", nil
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
	e, err := revoker(sys, c).Execute(context.Background(), token(t, trustedKey, nil), 0)
	if err != nil || e != (Erasure{Erased: true, SlotsBefore: 2, SlotsAfter: 0}) {
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
		string(c.results[0].Result) != `{"erased":true,"slots_before":2,"slots_after":0}` {
		t.Fatalf("confirmation %+v", c.results)
	}
}

// TestRebootWithoutConfirmation: the device reboots although the server never confirms; an erasure that left a
// keyslot is reported as failed.
func TestRebootWithoutConfirmation(t *testing.T) {
	sys := newSys(t)
	sys.eraseFail = true
	c := &fakeConfirmer{sys: sys, fail: true}
	start := time.Now()
	e, err := revoker(sys, c).Execute(context.Background(), token(t, trustedKey, nil), 0)
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
		elapsed time.Duration
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
		}, elapsed: 30*24*time.Hour - time.Second, reason: ReasonPeriod},
		"test target in a release build": {prepare: func(s *fakeSys) { s.rootErr = refuse(ReasonTestTarget) }, reason: ReasonTestTarget},
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
			_, err := revoker(sys, &fakeConfirmer{sys: sys}).Execute(context.Background(), env, c.elapsed)
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Reason != c.reason {
				t.Fatalf("got %v, want refusal %s", err, c.reason)
			}
			if len(sys.log) != 0 {
				t.Fatalf("a refused token changed the device: %v", sys.log)
			}
		})
	}
	// A self-lock after its period runs.
	sys := newSys(t)
	env := token(t, trustedKey, func(k *revocation.Token) { k.Action, k.PeriodDays = revocation.ActionSelfLock, 30 })
	if _, err := revoker(sys, &fakeConfirmer{sys: sys}).Execute(context.Background(), env, 30*24*time.Hour); err != nil {
		t.Fatalf("self-lock after its period: %v", err)
	}
}

// TestSecondTokenRefused: after a revocation every token is refused for 24 h, the same token for ever.
func TestSecondTokenRefused(t *testing.T) {
	sys := newSys(t)
	r := revoker(sys, &fakeConfirmer{sys: sys})
	if _, err := r.Execute(context.Background(), token(t, trustedKey, nil), 0); err != nil {
		t.Fatal(err)
	}
	other := token(t, trustedKey, func(k *revocation.Token) { k.CommandID = "0190f000-0000-7000-8000-0000000000c2" })
	var refusal *Refusal
	if _, err := r.Execute(context.Background(), other, 0); !errors.As(err, &refusal) || refusal.Reason != ReasonRateLimited {
		t.Fatalf("second token: %v", err)
	}
	r.Now = func() time.Time { return now.Add(25 * time.Hour) }
	if _, err := r.Execute(context.Background(), token(t, trustedKey, nil), 0); !errors.As(err, &refusal) || refusal.Reason != ReasonExecuted {
		t.Fatalf("same token a day later: %v", err)
	}
}

func TestUserIDs(t *testing.T) {
	if got := userIDs("120 gdm no active\n1000 paddock\n 200001 alice\n65534 nobody\n\nUID USER\n"); !slices.Equal(got, []int{1000, 200001}) {
		t.Fatalf("uids %v", got)
	}
}

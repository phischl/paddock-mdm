package localadmin_test

import (
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
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/localadmin"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// fakeSys is a device with the local accounts the tools change.
type fakeSys struct {
	shell  map[string]string // passwd: name → shell
	hash   map[string]string // shadow: name → hash
	expire map[string]string
	groups map[string][]string
	calls  []string
	// chpasswdFails makes chpasswd fail.
	chpasswdFails bool
	password      string // the last password chpasswd set
	// accountsService makes localadmin.AccountsServiceUsers exist; files are the files written there.
	accountsService bool
	files           map[string]string
	writeFails      bool
}

func newFakeSys() *fakeSys {
	return &fakeSys{shell: map[string]string{}, hash: map[string]string{}, expire: map[string]string{},
		groups: map[string][]string{"sudo": {"paddock"}}, files: map[string]string{}}
}

// ReadFile serves the local account databases; NSS (and Himmelblau's answers for any name) is never asked.
func (f *fakeSys) ReadFile(path string) ([]byte, fs.FileInfo, error) {
	var b strings.Builder
	switch path {
	case "/etc/shadow":
		for name, h := range f.hash {
			fmt.Fprintf(&b, "%s:%s:20000:0:99999:7::%s:\n", name, h, f.expire[name])
		}
	case "/etc/passwd":
		b.WriteString("root:x:0:0:root:/root:/bin/bash\n")
		for name, sh := range f.shell {
			fmt.Fprintf(&b, "%s:x:1001:1001::/home/%s:%s\n", name, name, sh)
		}
	case "/etc/group":
		for name, m := range f.groups {
			fmt.Fprintf(&b, "%s:x:27:%s\n", name, strings.Join(m, ","))
		}
	case localadmin.AccountsServiceUsers:
		if !f.accountsService {
			return nil, nil, fs.ErrNotExist
		}
		info, err := fs.Stat(fstest.MapFS{"users": {Mode: fs.ModeDir | 0o700}}, "users")
		return nil, info, err
	default:
		data, ok := f.files[path]
		if !ok {
			return nil, nil, fs.ErrNotExist
		}
		return []byte(data), nil, nil
	}
	return []byte(b.String()), nil, nil
}

func (f *fakeSys) WriteFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	f.calls = append(f.calls, fmt.Sprintf("write %s %04o %d:%d", path, mode, uid, gid))
	if f.writeFails {
		return errors.New("read-only file system")
	}
	f.files[path] = string(data)
	return nil
}

func (f *fakeSys) Systemctl(_ context.Context, args ...string) (string, int, error) {
	f.calls = append(f.calls, "systemctl "+strings.Join(args, " "))
	return "", 0, nil
}

func (f *fakeSys) UserTool(_ context.Context, tool string, args ...string) (string, int, error) {
	f.calls = append(f.calls, tool+" "+strings.Join(args, " "))
	if len(args) < 2 || args[len(args)-2] != "--" {
		return "missing --", 2, nil
	}
	name := args[len(args)-1]
	switch tool {
	case "useradd":
		f.shell[name], f.hash[name] = args[slices.Index(args, "-s")+1], ""
		g := args[slices.Index(args, "-G")+1]
		f.groups[g] = append(f.groups[g], name)
	case "passwd":
		f.hash[name] = "!" + f.hash[name]
	case "usermod":
		switch args[0] {
		case "-s":
			f.shell[name] = args[1]
		case "-a":
			if !slices.Contains(f.groups[args[2]], name) {
				f.groups[args[2]] = append(f.groups[args[2]], name)
			}
		case "-e":
			f.expire[name] = ""
		}
	}
	return "", 0, nil
}

func (f *fakeSys) Chpasswd(_ context.Context, input []byte) (string, int, error) {
	f.calls = append(f.calls, "chpasswd")
	if f.chpasswdFails {
		return "chpasswd: failure", 1, nil
	}
	name, pw, ok := strings.Cut(strings.TrimSuffix(string(input), "\n"), ":")
	if !ok {
		return "bad input", 1, nil
	}
	f.password = pw
	sum := sha256.Sum256([]byte(pw))
	f.hash[name] = "$y$" + base64.RawStdEncoding.EncodeToString(sum[:])
	return "", 0, nil
}

// fakeEscrow keeps uploads and answers the status the test sets.
type fakeEscrow struct {
	key       *rsa.PrivateKey
	uploads   []escrow.Request
	status    string // answer of Status
	uploadErr error
}

func (e *fakeEscrow) Upload(_ context.Context, req escrow.Request) error {
	if e.uploadErr != nil {
		return e.uploadErr
	}
	e.uploads = append(e.uploads, req)
	return nil
}

func (e *fakeEscrow) Status(context.Context, string) (string, error) { return e.status, nil }

// plaintext decrypts the last upload as OpenBao would.
func (e *fakeEscrow) plaintext(t *testing.T) string {
	t.Helper()
	ct, _ := base64.StdEncoding.DecodeString(e.uploads[len(e.uploads)-1].Ciphertext)
	pt, err := rsa.DecryptOAEP(sha256.New(), nil, e.key, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	return string(pt)
}

type event struct {
	typ  string
	data string
}

type world struct {
	t       *testing.T
	sys     *fakeSys
	esc     *fakeEscrow
	m       *localadmin.Manager
	st      *state.LocalAdmin
	events  []event
	results []string
	now     time.Time
	spec    *bundle.LocalAdminSpec
	keys    *bundle.Keys
}

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		panic(err)
	}
	return k
}()

func newWorld(t *testing.T) *world {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(&testKey.PublicKey)
	w := &world{t: t, sys: newFakeSys(), esc: &fakeEscrow{key: testKey, status: escrow.StatusPending}, st: &state.LocalAdmin{},
		now:  time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC),
		spec: &bundle.LocalAdminSpec{Username: "paddock-admin", RotationDays: 30},
		keys: &bundle.Keys{EscrowWrap: &bundle.EncryptionKey{KeyID: "escrow-wrap:v2",
			PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}}
	w.m = &localadmin.Manager{Sys: w.sys, Escrow: w.esc, State: w.st, Save: func() error { return nil },
		Emit: func(typ string, data any) {
			b, _ := json.Marshal(data)
			w.events = append(w.events, event{typ, string(b)})
		},
		Result: func(id, status string, result map[string]any) {
			b, _ := json.Marshal(result)
			w.results = append(w.results, id+" "+status+" "+string(b))
		},
		Now: func() time.Time { return w.now }}
	return w
}

func (w *world) tick() { w.m.Tick(context.Background(), w.spec, w.keys) }

// advance moves the clock and ticks.
func (w *world) advance(d time.Duration) {
	w.now = w.now.Add(d)
	w.tick()
}

func (w *world) takeEvents() []event {
	e := w.events
	w.events = nil
	return e
}

// rotate runs a rotation to completion: started by the current tick, stored by the server at the next poll.
func (w *world) rotate() string {
	w.t.Helper()
	w.tick()
	w.esc.status = escrow.StatusStored
	w.advance(localadmin.PollInterval)
	w.esc.status = escrow.StatusPending
	return w.esc.plaintext(w.t)
}

func TestFirstRotation(t *testing.T) {
	w := newWorld(t)
	w.tick()
	if w.sys.calls[0] != "useradd --prefix /. -m -K HOME_MODE=0700 -s /bin/bash -G sudo -- paddock-admin" || w.sys.calls[1] != "passwd -l -- paddock-admin" {
		t.Fatalf("calls %v", w.sys.calls)
	}
	if !strings.HasPrefix(w.sys.hash["paddock-admin"], "!") || len(w.esc.uploads) != 1 {
		t.Fatalf("account %q, uploads %d", w.sys.hash["paddock-admin"], len(w.esc.uploads))
	}
	up := w.esc.uploads[0]
	pw := w.esc.plaintext(t)
	if up.Generation != 1 || up.KeyVersion != 2 || up.Kind != "admin_password" || len(pw) != localadmin.PasswordLength || w.st.Attempted != 1 {
		t.Fatalf("upload %+v, password length %d", up, len(pw))
	}
	// Until the server stored it, the password is not set; polls happen every 30 s.
	w.advance(10 * time.Second)
	w.advance(localadmin.PollInterval)
	if slices.Contains(w.sys.calls, "chpasswd") || len(w.esc.uploads) != 1 {
		t.Fatalf("password set before it was stored: %v", w.sys.calls)
	}
	w.esc.status = escrow.StatusStored
	w.advance(localadmin.PollInterval)
	if w.sys.password != pw || w.st.Generation != 1 || w.st.RotatedAt == nil || w.st.ShadowSHA256 == "" || strings.HasPrefix(w.sys.hash["paddock-admin"], "!") {
		t.Fatalf("after storing: password set %v, state %+v", w.sys.password == pw, w.st)
	}
	if got := w.takeEvents(); !slices.Equal(got, []event{{protocol.EventLocalAdminRotated, `{"generation":1}`}}) {
		t.Fatalf("events %v", got)
	}
	// Nothing is due afterwards.
	w.esc.status = escrow.StatusStored
	w.advance(time.Hour)
	if len(w.esc.uploads) != 1 || len(w.takeEvents()) != 0 {
		t.Fatalf("a second rotation started: %d uploads", len(w.esc.uploads))
	}
	// After the rotation interval the next generation follows.
	w.esc.status = escrow.StatusPending
	w.now = w.now.Add(30 * 24 * time.Hour)
	pw2 := w.rotate()
	if w.sys.password != pw2 || pw2 == pw || w.st.Generation != 2 {
		t.Fatalf("interval rotation: generation %d", w.st.Generation)
	}
}

// TestRotationNotStoredKeepsThePassword (gate LA1, confirmation failure): without "stored" within 15 minutes the
// device keeps the old password, reports rotation_failed and fails the command; the next rotation uses a new
// generation.
func TestRotationNotStoredKeepsThePassword(t *testing.T) {
	w := newWorld(t)
	pw1 := w.rotate()
	w.takeEvents()
	w.m.Request("cmd-1")
	w.tick()
	for range 30 {
		w.advance(localadmin.PollInterval)
	}
	if w.sys.password != pw1 || w.st.Generation != 1 || w.st.Attempted != 2 {
		t.Fatalf("password changed or state %+v", w.st)
	}
	if got := w.takeEvents(); !slices.Equal(got, []event{{protocol.EventLocalAdminRotationFailed, `{"generation":2,"reason":"escrow_timeout"}`}}) {
		t.Fatalf("events %v", got)
	}
	if !slices.Equal(w.results, []string{`cmd-1 failed {"generation":2,"reason":"escrow_timeout"}`}) {
		t.Fatalf("results %v", w.results)
	}
	// An automatic rotation waits RetryAfter; a command does not.
	w.m.Request("cmd-2")
	pw3 := w.rotate()
	if w.esc.uploads[len(w.esc.uploads)-1].Generation != 3 || w.sys.password != pw3 || w.st.Generation != 3 ||
		w.results[1] != `cmd-2 succeeded {"generation":3}` {
		t.Fatalf("next rotation: %+v, results %v", w.st, w.results)
	}
}

func TestRotationFailures(t *testing.T) {
	t.Run("server refused", func(t *testing.T) {
		w := newWorld(t)
		w.tick()
		w.esc.status = escrow.StatusFailed
		w.advance(localadmin.PollInterval)
		if got := w.takeEvents(); len(got) != 1 || got[0].data != `{"generation":1,"reason":"escrow_failed"}` || w.st.RetryAt == nil {
			t.Fatalf("events %v, state %+v", got, w.st)
		}
		w.advance(time.Minute)
		if len(w.esc.uploads) != 1 {
			t.Fatal("retried before RetryAfter")
		}
		w.advance(localadmin.RetryAfter)
		if len(w.esc.uploads) != 2 || w.esc.uploads[1].Generation != 2 {
			t.Fatalf("retry: %d uploads", len(w.esc.uploads))
		}
	})
	t.Run("chpasswd fails", func(t *testing.T) {
		w := newWorld(t)
		w.sys.chpasswdFails = true
		w.rotate()
		if got := w.takeEvents(); len(got) != 1 || got[0].data != `{"generation":1,"reason":"apply_failed"}` || w.st.Generation != 0 {
			t.Fatalf("events %v, state %+v", got, w.st)
		}
	})
	t.Run("server unreachable", func(t *testing.T) {
		w := newWorld(t)
		w.esc.uploadErr = errors.New("connection refused")
		w.tick()
		if w.st.Attempted != 1 || len(w.takeEvents()) != 0 {
			t.Fatalf("state %+v", w.st)
		}
		w.esc.uploadErr = nil
		w.rotate()
		if w.st.Generation != 2 {
			t.Fatalf("after the server is back: %+v", w.st)
		}
	})
	t.Run("no escrow key", func(t *testing.T) {
		w := newWorld(t)
		w.keys = nil
		w.tick()
		if len(w.esc.uploads) != 0 {
			t.Fatal("upload without key")
		}
	})
}

// TestTamper (gate LA2): a changed password, shell or group membership is reported once; shell and group are
// repaired at once and the next rotation restores a known password.
func TestTamper(t *testing.T) {
	w := newWorld(t)
	w.rotate()
	w.takeEvents()
	w.esc.status = escrow.StatusPending

	w.sys.hash["paddock-admin"] = "$y$set-locally"
	w.sys.shell["paddock-admin"] = "/usr/sbin/nologin"
	w.sys.groups["sudo"] = []string{"paddock"}
	w.advance(time.Minute)
	got := w.takeEvents()
	want := []event{
		{protocol.EventTamperLocalAdminChanged, `{"field":"password"}`},
		{protocol.EventTamperLocalAdminChanged, `{"field":"shell"}`},
		{protocol.EventTamperLocalAdminChanged, `{"field":"group"}`},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("events %v", got)
	}
	if w.sys.shell["paddock-admin"] != "/bin/bash" || !slices.Contains(w.sys.groups["sudo"], "paddock-admin") || len(w.esc.uploads) != 2 {
		t.Fatalf("not repaired: shell %s, sudo %v, uploads %d", w.sys.shell["paddock-admin"], w.sys.groups["sudo"], len(w.esc.uploads))
	}
	// Reported once while the rotation runs; the rotation restores a known password.
	w.advance(10 * time.Second)
	if len(w.takeEvents()) != 0 {
		t.Fatal("tamper reported again")
	}
	w.esc.status = escrow.StatusStored
	w.advance(localadmin.PollInterval)
	if w.st.Generation != 2 || len(w.st.Tampered) != 0 || w.sys.password != w.esc.plaintext(t) {
		t.Fatalf("after the repair rotation: %+v", w.st)
	}

	// A locked account (passwd -l) and an expiry are reported as locked.
	w.takeEvents()
	w.sys.hash["paddock-admin"] = "!" + w.sys.hash["paddock-admin"]
	w.advance(time.Minute)
	if got := w.takeEvents(); len(got) != 2 || got[0].data != `{"field":"password"}` || got[1].data != `{"field":"locked"}` {
		t.Fatalf("lock events %v", got)
	}
}

func TestDeletedAccountIsRecreated(t *testing.T) {
	w := newWorld(t)
	w.rotate()
	w.takeEvents()
	delete(w.sys.shell, "paddock-admin")
	delete(w.sys.hash, "paddock-admin")
	w.esc.status = escrow.StatusPending
	w.advance(time.Minute)
	if got := w.takeEvents(); len(got) < 1 || got[0].data != `{"field":"missing"}` || w.sys.shell["paddock-admin"] != "/bin/bash" || len(w.esc.uploads) != 2 {
		t.Fatalf("events %v, uploads %d", got, len(w.esc.uploads))
	}
}

// TestHiddenFromLoginScreen (plan M4a.1 decision 4): the AccountsService file marks the account as a system account
// before the account is created; a removed or changed file is restored and AccountsService restarted, keys
// AccountsService adds itself are kept.
func TestHiddenFromLoginScreen(t *testing.T) {
	path := localadmin.AccountsServiceUsers + "/paddock-admin"
	write, restart := "write "+path+" 0600 0:0", "systemctl try-restart accounts-daemon.service"
	w := newWorld(t)
	w.sys.accountsService = true
	w.tick()
	if len(w.sys.calls) < 3 || w.sys.calls[0] != write || w.sys.calls[1] != restart || !strings.HasPrefix(w.sys.calls[2], "useradd ") {
		t.Fatalf("calls %v", w.sys.calls)
	}
	if w.sys.files[path] != "[User]\nSystemAccount=true\n" {
		t.Fatalf("file %q", w.sys.files[path])
	}
	w.rotate()

	cases := map[string]struct {
		content string // "" removes the file
		restore bool
	}{
		"kept with keys AccountsService adds": {"[InputSource0]\nxkb=us\n\n[User]\nIcon=/home/paddock-admin/.face\nSystemAccount = true\n", false},
		"removed":                             {"", true},
		"no system account":                   {"[User]\nSystemAccount=false\n", true},
		"in another group":                    {"[User]\nIcon=/x\n[Other]\nSystemAccount=true\n", true},
		"empty":                               {"\n", true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w.sys.files[path] = c.content
			if c.content == "" {
				delete(w.sys.files, path)
			}
			w.sys.calls = nil
			w.advance(time.Minute)
			restored := slices.Contains(w.sys.calls, write) && slices.Contains(w.sys.calls, restart)
			if restored != c.restore {
				t.Fatalf("restored %v, calls %v", restored, w.sys.calls)
			}
			if c.restore && w.sys.files[path] != "[User]\nSystemAccount=true\n" {
				t.Fatalf("file %q", w.sys.files[path])
			}
		})
	}
}

func TestHidingFailureKeepsTheAccount(t *testing.T) {
	t.Run("without AccountsService", func(t *testing.T) {
		w := newWorld(t)
		w.tick()
		if slices.ContainsFunc(w.sys.calls, func(c string) bool { return !strings.HasPrefix(c, "useradd ") && !strings.HasPrefix(c, "passwd ") }) {
			t.Fatalf("calls %v", w.sys.calls)
		}
	})
	t.Run("write fails", func(t *testing.T) {
		w := newWorld(t)
		w.sys.accountsService, w.sys.writeFails = true, true
		w.tick()
		if slices.ContainsFunc(w.sys.calls, func(c string) bool { return strings.HasPrefix(c, "systemctl ") }) || w.sys.shell["paddock-admin"] != "/bin/bash" ||
			len(w.esc.uploads) != 1 {
			t.Fatalf("calls %v, uploads %d", w.sys.calls, len(w.esc.uploads))
		}
	})
}

func TestWithoutSpecNothingHappens(t *testing.T) {
	w := newWorld(t)
	w.spec = nil
	w.tick()
	if len(w.sys.calls) != 0 {
		t.Fatalf("calls %v", w.sys.calls)
	}
}

func TestNewPassword(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		pw, err := localadmin.NewPassword()
		if err != nil || len(pw) != 24 || strings.Trim(string(pw), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" || seen[string(pw)] {
			t.Fatalf("password %q %v", pw, err)
		}
		seen[string(pw)] = true
	}
}

func TestParseJournal(t *testing.T) {
	cases := map[string]struct {
		line string
		want *localadmin.Login
	}{
		"ssh": {`{"MESSAGE":"pam_unix(sshd:session): session opened for user paddock-admin(uid=1001) by paddock-admin(uid=0)","__REALTIME_TIMESTAMP":"1791187200000000"}`,
			&localadmin.Login{Service: "sshd", User: "paddock-admin", At: time.Unix(1791187200, 0).UTC()}},
		"console": {`{"MESSAGE":"pam_unix(login:session): session opened for user paddock-admin(uid=1001) by LOGIN(uid=0)","__REALTIME_TIMESTAMP":"1791187200000000"}`,
			&localadmin.Login{Service: "login", User: "paddock-admin", At: time.Unix(1791187200, 0).UTC()}},
		"systemd user":  {`{"MESSAGE":"pam_unix(systemd-user:session): session opened for user paddock-admin(uid=1001) by paddock-admin(uid=0)"}`, nil},
		"session close": {`{"MESSAGE":"pam_unix(sshd:session): session closed for user paddock-admin"}`, nil},
		"binary":        {`{"MESSAGE":[1,2,3]}`, nil},
		"not json":      {`x`, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := localadmin.ParseJournal([]byte(c.line))
			if c.want == nil {
				if ok {
					t.Fatalf("parsed %+v", got)
				}
				return
			}
			if !ok || got != *c.want {
				t.Fatalf("got %+v %v", got, ok)
			}
		})
	}
}

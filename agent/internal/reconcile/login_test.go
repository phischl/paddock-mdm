package reconcile_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // OpenPGP v4 fingerprints are SHA-1 by definition (RFC 4880 §12.2)
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/paddock-mdm/paddock/agent/internal/reconcile"
	"github.com/paddock-mdm/paddock/agent/internal/reconcile/fakesys"
	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

const (
	pamAuth = "auth\trequisite\tpam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed\n" +
		"auth\t[success=3 default=ignore]    pam_himmelblau.so ignore_unknown_user set_authtok\n" +
		"auth\t[success=2 default=ignore]\tpam_unix.so nullok try_first_pass\n"
	pamAccount = "# comment\naccount\trequired\tpam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed\n" +
		"account\t[success=2 auth_err=die default=ignore]    pam_himmelblau.so ignore_unknown_user\n"
	passwd = "root:x:0:0:root:/root:/bin/bash\ngdm:x:120:125::/var/lib/gdm3:/bin/false\npaddock:x:1000:1000::/home/paddock:/bin/bash\n" +
		"dave:x:1001:1001::/home/dave:/bin/bash\nbob:x:70000:70000::/home/bob:/bin/bash\n"
)

// event is a device event a reconciler emitted.
type event struct {
	typ  string
	data string
}

// loginFixture is an Ubuntu 24.04 device with the paddock-agent PAM profile in effect and no Himmelblau.
func loginFixture(t *testing.T) (*fakesys.System, *reconcile.Login, *[]event) {
	t.Helper()
	sys := fakesys.New()
	sys.AptVersion = "4.0.4-ubuntu24.04"
	for path, content := range map[string]string{
		"/usr/lib/os-release": "PRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n", "/etc/passwd": passwd,
		"/etc/pam.d/common-auth": pamAuth, "/etc/pam.d/common-account": pamAccount,
	} {
		sys.Files[path] = &fakesys.File{Data: []byte(content), Mode: 0o644}
	}
	sys.Files["/etc/os-release"] = &fakesys.File{Symlink: true} // → ../usr/lib/os-release, as on Ubuntu
	for _, u := range []string{"himmelblaud.service", "himmelblaud-tasks.service"} {
		sys.Units[u] = &fakesys.Unit{State: "enabled"}
	}
	var events []event
	emit := func(typ string, data any) {
		b, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event{typ, string(b)})
	}
	return sys, &reconcile.Login{Sys: sys, Events: &reconcile.Events{Emit: emit}}, &events
}

func loginSpec() bundle.LoginSpec {
	return bundle.LoginSpec{
		Provider: bundle.ProviderHimmelblau,
		Himmelblau: bundle.HimmelblauSpec{
			OIDCIssuerURL: "https://auth.paddock.localhost:8443/application/o/paddock-device-acme/", AppID: "paddock-device-acme",
			Domain: "acme.test", PamAllowGroups: []string{"paddock.acme"}, EnableHello: true, HelloPinMinLength: 6,
			PackageVersion: "4.0.4",
		},
		SessionAction: bundle.SessionActionLockScreen, BreakGlassAccounts: []string{"paddock"},
	}
}

func loginResource(t *testing.T, s bundle.LoginSpec) bundle.Resource {
	t.Helper()
	r, err := bundle.LoginResource(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func takeEvents(e *[]event) []event {
	out := *e
	*e = nil
	return out
}

const wantConf = `# Managed by Paddock. Do not edit: local changes are reverted.
[global]
oidc_issuer_url = https://auth.paddock.localhost:8443/application/o/paddock-device-acme/
app_id = paddock-device-acme
domain = acme.test
pam_allow_groups = paddock.acme
allow_console_password_only = false
enable_hello = true
hello_pin_min_length = 6
local_groups = users
idmap_range = 200000-999999999
`

func TestLoginInstallsAndConfigures(t *testing.T) {
	ctx := context.Background()
	sys, l, events := loginFixture(t)
	r := loginResource(t, loginSpec())
	changes, err := l.Plan(ctx, r)
	if err != nil || !slices.Equal(changes, []string{"package", "config"}) {
		t.Fatalf("plan %v %v", changes, err)
	}
	if res := l.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	calls := sys.TakeCalls()
	want := []string{
		"write /etc/apt/keyrings/himmelblau.gpg", "write /etc/apt/sources.list.d/paddock-himmelblau.list", "apt-get update",
		"apt-get install himmelblau pam-himmelblau nss-himmelblau himmelblau-qr-greeter himmelblau-sshd-config",
		"write /etc/himmelblau/himmelblau.conf",
		"systemctl reset-failed himmelblaud.service", "systemctl reset-failed himmelblaud-tasks.service",
		"systemctl restart himmelblaud.service", "systemctl restart himmelblaud-tasks.service",
	}
	if !slices.Equal(calls, want) {
		t.Fatalf("calls\n%q\nwant\n%q", calls, want)
	}
	if got := string(sys.Files["/etc/apt/sources.list.d/paddock-himmelblau.list"].Data); got !=
		"deb [signed-by=/etc/apt/keyrings/himmelblau.gpg] https://packages.himmelblau-idm.org/stable/4.0.4/deb/ubuntu24.04/ ./\n" {
		t.Fatalf("source %q", got)
	}
	if f := sys.Files["/etc/himmelblau/himmelblau.conf"]; string(f.Data) != wantConf || f.Mode != 0o644 || f.UID != 0 {
		t.Fatalf("himmelblau.conf %o %d\n%s", f.Mode, f.UID, f.Data)
	}
	if _, ok := sys.Files["/etc/paddock/login-deny"]; ok {
		t.Fatal("deny list written without locked users")
	}
	if got := takeEvents(events); !slices.Equal(got, []event{{protocol.EventLoginApplied, `{"changed":["package","config"]}`}}) {
		t.Fatalf("events %v", got)
	}

	// A second run changes nothing and restarts nothing.
	if changes, err := l.Plan(ctx, r); err != nil || len(changes) != 0 {
		t.Fatalf("second plan %v %v", changes, err)
	}
	if res := l.Apply(ctx, r); res.Status != reconcile.OK || len(sys.TakeCalls()) != 0 || len(takeEvents(events)) != 0 {
		t.Fatalf("second apply %+v", res)
	}

	// A local edit is reverted with a restart.
	sys.Files["/etc/himmelblau/himmelblau.conf"].Data = []byte("[global]\npam_allow_groups = everyone\n")
	if res := l.Apply(ctx, r); res.Status != reconcile.Changed || !slices.Contains(sys.TakeCalls(), "systemctl restart himmelblaud.service") {
		t.Fatalf("drift %+v", res)
	}
}

func TestLoginAllowListLineIsAlwaysWritten(t *testing.T) {
	ctx := context.Background()
	sys, l, _ := loginFixture(t)
	s := loginSpec()
	s.Suspended, s.Himmelblau.PamAllowGroups = true, nil
	if res := l.Apply(ctx, loginResource(t, s)); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	conf := string(sys.Files["/etc/himmelblau/himmelblau.conf"].Data)
	if !strings.Contains(conf, "\npam_allow_groups =\n") {
		t.Fatalf("suspended configuration lacks the empty allow list:\n%s", conf)
	}
	s.Suspended, s.Himmelblau.PamAllowGroups = false, []string{"paddock.acme.d.dev", "paddock.acme.g.ops"}
	l.Apply(ctx, loginResource(t, s))
	if conf := string(sys.Files["/etc/himmelblau/himmelblau.conf"].Data); !strings.Contains(conf, "\npam_allow_groups = paddock.acme.d.dev,paddock.acme.g.ops\n") {
		t.Fatalf("allow list:\n%s", conf)
	}
}

func TestLoginDenyListNames(t *testing.T) {
	ctx := context.Background()
	sys, l, events := loginFixture(t)
	r := loginResource(t, loginSpec())
	l.Apply(ctx, r)
	sys.TakeCalls()
	takeEvents(events)

	s := loginSpec()
	// dave is also a local account (UID 1001): its short name is never denied. bob's local UID is a directory UID.
	// paddock is a break-glass account and is never denied.
	s.LockedUsers = []string{"bob@acme.test", "dave@acme.test", "erin@acme.test", "paddock"}
	r = loginResource(t, s)
	if changes, _ := l.Plan(ctx, r); !slices.Equal(changes, []string{"deny_list"}) {
		t.Fatalf("plan %v", changes)
	}
	if res := l.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	f := sys.Files["/etc/paddock/login-deny"]
	if got := string(f.Data); got != "bob@acme.test\nbob\ndave@acme.test\nerin@acme.test\nerin\n" || f.Mode != 0o644 {
		t.Fatalf("deny list %o:\n%s", f.Mode, got)
	}
	if calls := sys.TakeCalls(); slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "systemctl") }) {
		t.Fatalf("a deny list change restarted the daemon: %v", calls)
	}
	// Unlocking everyone removes the file.
	l.Apply(ctx, loginResource(t, loginSpec()))
	if _, ok := sys.Files["/etc/paddock/login-deny"]; ok {
		t.Fatal("deny list left after the unlock")
	}
}

// deviceSessions: the local admin over SSH and its service manager, the GDM greeter (Ubuntu 26.04: a dynamic user
// above UID 60000), dave at the console and on a TTY, erin.
var deviceSessions = []fakesys.Session{
	{ID: "5", UID: 1000, User: "paddock", Class: "user"},
	{ID: "6", UID: 1000, User: "paddock", Class: "manager"},
	{ID: "c1", UID: 60578, User: "gdm-greeter", Class: "greeter"},
	{ID: "7", UID: 811622788, User: "dave@acme.test", Class: "user"},
	{ID: "8", UID: 811622788, User: "dave@acme.test", Class: "manager"},
	{ID: "9", UID: 811622788, User: "dave@acme.test", Class: "user"},
	{ID: "11", UID: 923001122, User: "erin@acme.test", Class: "user"},
}

func TestLoginLocksSessionsOfNewlyLockedUsers(t *testing.T) {
	ctx := context.Background()
	sys, l, events := loginFixture(t)
	sys.Sessions = deviceSessions
	l.Apply(ctx, loginResource(t, loginSpec()))
	sys.TakeCalls()
	takeEvents(events)

	s := loginSpec()
	s.LockedUsers = []string{"dave@acme.test"}
	l.Apply(ctx, loginResource(t, s))
	if calls := sys.TakeCalls(); !slices.Equal(calls, []string{"write /etc/paddock/login-deny", "loginctl lock-session 7", "loginctl lock-session 9"}) {
		t.Fatalf("calls %v", calls)
	}
	want := []event{
		{protocol.EventLoginApplied, `{"changed":["deny_list"]}`},
		{protocol.EventUserLockApplied, `{"username":"dave@acme.test","sessions_locked":2,"sessions_terminated":0}`},
	}
	if got := takeEvents(events); !slices.Equal(got, want) {
		t.Fatalf("events %v", got)
	}
	// dave stays locked: nothing happens again. erin is locked with session action terminate.
	l.Apply(ctx, loginResource(t, s))
	if calls := sys.TakeCalls(); len(calls) != 0 {
		t.Fatalf("locked again: %v", calls)
	}
	s.LockedUsers, s.SessionAction = []string{"dave@acme.test", "erin@acme.test"}, bundle.SessionActionTerminate
	l.Apply(ctx, loginResource(t, s))
	if calls := sys.TakeCalls(); !slices.Equal(calls, []string{"write /etc/paddock/login-deny", "loginctl terminate-user 923001122"}) {
		t.Fatalf("calls %v", calls)
	}
	if got := takeEvents(events); len(got) != 2 || got[1] != (event{protocol.EventUserLockApplied, `{"username":"erin@acme.test","sessions_locked":0,"sessions_terminated":1}`}) {
		t.Fatalf("events %v", got)
	}
}

func TestLoginSuspensionTerminatesDirectorySessions(t *testing.T) {
	ctx := context.Background()
	sys, l, events := loginFixture(t)
	sys.Sessions = deviceSessions
	l.Apply(ctx, loginResource(t, loginSpec()))
	sys.TakeCalls()
	takeEvents(events)

	s := loginSpec()
	s.Suspended, s.Himmelblau.PamAllowGroups = true, []string{}
	l.Apply(ctx, loginResource(t, s))
	calls := sys.TakeCalls()
	if !slices.Equal(calls[len(calls)-2:], []string{"loginctl terminate-user 811622788", "loginctl terminate-user 923001122"}) {
		t.Fatalf("calls %v", calls)
	}
	if slices.ContainsFunc(calls, func(c string) bool {
		return strings.Contains(c, "terminate-user 1000") || strings.Contains(c, "terminate-user 60578")
	}) {
		t.Fatalf("a local account was terminated: %v", calls)
	}
	if got := takeEvents(events); got[len(got)-1] != (event{protocol.EventLoginsSuspensionApplied, `{"sessions_terminated":3}`}) {
		t.Fatalf("events %v", got)
	}
	// Still suspended: no second termination.
	l.Apply(ctx, loginResource(t, s))
	if calls := sys.TakeCalls(); len(calls) != 0 {
		t.Fatalf("terminated again: %v", calls)
	}
}

func TestLoginAptFailureIsReportedOnceAndLocksStillApply(t *testing.T) {
	ctx := context.Background()
	sys, l, events := loginFixture(t)
	sys.FailCmd = "apt-get install"
	s := loginSpec()
	s.LockedUsers = []string{"erin@acme.test"}
	r := loginResource(t, s)
	for range 2 {
		if res := l.Apply(ctx, r); res.Status != reconcile.Error || !strings.HasPrefix(res.Message, "apt: apt-get install: exit 100") {
			t.Fatalf("apply %+v", res)
		}
	}
	if _, ok := sys.Files["/etc/paddock/login-deny"]; !ok {
		t.Fatal("a failed installation kept the deny list from being written")
	}
	if _, ok := sys.Files["/etc/himmelblau/himmelblau.conf"]; ok {
		t.Fatal("configuration written without the package")
	}
	got := takeEvents(events)
	var failed []event
	for _, e := range got {
		if e.typ == protocol.EventLoginApplyFailed {
			failed = append(failed, e)
		}
	}
	if len(failed) != 1 || !strings.HasPrefix(failed[0].data, `{"stage":"apt","message":"apt-get install: exit 100`) {
		t.Fatalf("login.apply_failed events %v (all %v)", failed, got)
	}
	sys.FailCmd = ""
	if res := l.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("after the lock was released: %+v", res)
	}
}

func TestLoginVerifiesThePAMProfile(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name, auth, account, file string
	}{
		{"auth line missing", "auth\t[success=2 default=ignore]    pam_himmelblau.so\n", pamAccount, "/etc/pam.d/common-auth"},
		{"auth line after himmelblau", "auth [success=3 default=ignore] pam_himmelblau.so\n" +
			"auth requisite pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed\n", pamAccount, "/etc/pam.d/common-auth"},
		{"account line missing", pamAuth, "account [success=2] pam_himmelblau.so\n", "/etc/pam.d/common-account"},
		{"commented out", pamAuth, strings.ReplaceAll(pamAccount, "account", "#account"), "/etc/pam.d/common-account"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sys, l, events := loginFixture(t)
			r := loginResource(t, loginSpec())
			l.Apply(ctx, r)
			takeEvents(events)
			// The profile is removed after Himmelblau was set up.
			sys.Files["/etc/pam.d/common-auth"].Data = []byte(tt.auth)
			sys.Files["/etc/pam.d/common-account"].Data = []byte(tt.account)
			if changes, _ := l.Plan(ctx, r); !slices.Equal(changes, []string{"pam " + tt.file}) {
				t.Fatalf("plan %v", changes)
			}
			sys.TakeCalls()
			for range 2 {
				if res := l.Apply(ctx, r); res.Status != reconcile.Error || !strings.HasPrefix(res.Message, "pam: ") {
					t.Fatalf("apply %+v", res)
				}
			}
			if calls := sys.TakeCalls(); len(calls) != 0 {
				t.Fatalf("the agent changed the system: %v", calls)
			}
			want := []event{
				{protocol.EventTamperProtectedFileChanged, `{"file":"` + tt.file + `"}`},
				{protocol.EventLoginApplyFailed, `{"stage":"pam","message":"the paddock-deny PAM profile is not in effect in ` + tt.file +
					`; run dpkg-reconfigure paddock-agent"}`},
			}
			if got := takeEvents(events); !slices.Equal(got, want) {
				t.Fatalf("events %v", got)
			}
			// dpkg-reconfigure paddock-agent restored the profile.
			sys.Files["/etc/pam.d/common-auth"].Data = []byte(pamAuth)
			sys.Files["/etc/pam.d/common-account"].Data = []byte(pamAccount)
			if res := l.Apply(ctx, r); res.Status != reconcile.OK || len(takeEvents(events)) != 0 {
				t.Fatalf("after the restore %+v", res)
			}
		})
	}
}

func TestLoginRefusesInvalidSpecs(t *testing.T) {
	ctx := context.Background()
	for name, mutate := range map[string]func(*bundle.LoginSpec){
		"provider":         func(s *bundle.LoginSpec) { s.Provider = "sssd" },
		"version":          func(s *bundle.LoginSpec) { s.Himmelblau.PackageVersion = "4.0.4/../x" },
		"session action":   func(s *bundle.LoginSpec) { s.SessionAction = "logout" },
		"newline":          func(s *bundle.LoginSpec) { s.Himmelblau.Domain = "acme.test\npam_allow_groups =" },
		"group separator":  func(s *bundle.LoginSpec) { s.Himmelblau.PamAllowGroups = []string{"a,b"} },
		"locked user line": func(s *bundle.LoginSpec) { s.LockedUsers = []string{"eve\nroot"} },
	} {
		t.Run(name, func(t *testing.T) {
			sys, l, _ := loginFixture(t)
			s := loginSpec()
			mutate(&s)
			if res := l.Apply(ctx, loginResource(t, s)); res.Status != reconcile.Error || len(sys.TakeCalls()) != 0 {
				t.Fatalf("apply %+v", res)
			}
		})
	}
}

// TestHimmelblauKeyFingerprint verifies the embedded repository key at build time: one public key packet whose v4
// fingerprint is E87F D8D4 63A5 E481 4B9C DBA9 0CC0 D400 2C42 5E03 (PoC M1, plan M3b decision 6).
func TestHimmelblauKeyFingerprint(t *testing.T) {
	key := reconcile.HimmelblauKey()
	if len(key) < 3 || key[0]&0x80 == 0 {
		t.Fatal("not a binary OpenPGP key")
	}
	var body []byte
	switch {
	case key[0]&0x40 != 0: // new format: tag 6, one- or two-octet length
		if key[0]&0x3f != 6 {
			t.Fatalf("first packet has tag %d, want 6 (public key)", key[0]&0x3f)
		}
		n, off := int(key[1]), 2
		if n >= 192 && n < 224 {
			n, off = (n-192)<<8+int(key[2])+192, 3
		}
		body = key[off : off+n]
	default: // old format: tag in bits 5–2, length type in bits 1–0
		if (key[0]>>2)&0x0f != 6 {
			t.Fatalf("first packet has tag %d, want 6 (public key)", (key[0]>>2)&0x0f)
		}
		switch key[0] & 0x03 {
		case 0:
			body = key[2 : 2+int(key[1])]
		case 1:
			body = key[3 : 3+(int(key[1])<<8|int(key[2]))]
		default:
			t.Fatal("unsupported packet length type")
		}
	}
	if body[0] != 4 {
		t.Fatalf("key version %d, want 4", body[0])
	}
	h := sha1.New() //nolint:gosec // see import
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	if got := strings.ToUpper(hex.EncodeToString(h.Sum(nil))); got != "E87FD8D463A5E4814B9CDBA90CC0D4002C425E03" {
		t.Fatalf("fingerprint %s", got)
	}
}

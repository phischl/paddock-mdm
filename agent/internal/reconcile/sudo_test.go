package reconcile_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/paddock-mdm/paddock/agent/internal/reconcile"
	"github.com/paddock-mdm/paddock/agent/internal/reconcile/fakesys"
	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/pkg/sudoers"
)

const sudoersFile = "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n"

// sudoFixture is a device with the stock sudoers configuration of the test VMs: README, 90-paddock and the
// break-glass account paddock in the group sudo.
func sudoFixture(t *testing.T) (*fakesys.System, *reconcile.Sudo, *[]event) {
	t.Helper()
	sys := fakesys.New()
	sys.Files["/etc/sudoers"] = &fakesys.File{Data: []byte(sudoersFile), Mode: 0o440}
	sys.Files["/etc/sudoers.d/README"] = &fakesys.File{Data: []byte("# sudoers.d README\n"), Mode: 0o440}
	sys.Files["/etc/sudoers.d/90-paddock"] = &fakesys.File{Data: []byte("paddock ALL=(ALL) NOPASSWD:ALL\n"), Mode: 0o440}
	sys.Passwd = map[string]int{"dave@acme.test": 811622788, "erin@acme.test": 923001122}
	sys.Members = map[string][]string{"sudo": {"paddock"}, "admin": {}}
	var events []event
	emit := func(typ string, data any) {
		b, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event{typ, string(b)})
	}
	return sys, &reconcile.Sudo{Sys: sys, Events: &reconcile.Events{Emit: emit}}, &events
}

func restricted(username string, commands ...string) sudoers.Entry {
	return sudoers.Entry{Username: username, Class: sudoers.ClassRestricted, Commands: commands, RequirePassword: true,
		TimestampTimeoutMin: 5, Lecture: sudoers.LectureOnce}
}

func sudoResource(t *testing.T, entries ...sudoers.Entry) bundle.Resource {
	t.Helper()
	r, err := bundle.SudoResource(bundle.SudoSpec{
		LectureText: "Be careful.\n", Entries: entries, PrivilegedGroups: []string{"sudo", "admin", "wheel"},
		SudoersDAllowlist: []string{"README", "90-paddock"}, BreakGlassAccounts: []string{"paddock"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func render(t *testing.T, e sudoers.Entry, uid uint32) string {
	t.Helper()
	b, err := sudoers.Render(e, uid)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSudoWritesEntriesWithTheApplyProcedure(t *testing.T) {
	ctx := context.Background()
	sys, s, events := sudoFixture(t)
	dave := restricted("dave@acme.test", "/usr/bin/systemctl restart nginx.service")
	r := sudoResource(t, dave)
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	name := "/etc/sudoers.d/" + sudoers.FileName("dave@acme.test")
	calls := sys.TakeCalls()
	// /etc/sudoers is recorded at the first apply, then the lecture, then the procedure of architecture §10.3.
	if len(calls) != 7 || calls[0] != "visudo -c" || calls[1] != "write /var/lib/paddock/state/sudoers.sha256" ||
		calls[2] != "write /etc/paddock/sudo_lecture" || !strings.HasPrefix(calls[3], "write /etc/sudoers.d/.paddock-tmp-") ||
		calls[4] != "visudo -c -f "+strings.TrimPrefix(calls[3], "write ") || calls[5] != "rename "+strings.TrimPrefix(calls[3], "write ")+" "+name ||
		calls[6] != "visudo -c" {
		t.Fatalf("calls %q", calls)
	}
	if f := sys.Files[name]; string(f.Data) != render(t, dave, 811622788) || f.Mode != 0o440 || f.UID != 0 {
		t.Fatalf("%s %o\n%s", name, f.Mode, f.Data)
	}
	if !strings.Contains(string(sys.Files[name].Data), "#811622788 ALL=(root) /usr/bin/systemctl restart nginx.service\n") {
		t.Fatalf("not rendered with the UID: %s", sys.Files[name].Data)
	}
	if got := string(sys.Files["/etc/paddock/sudo_lecture"].Data); got != "Be careful.\n" {
		t.Fatalf("lecture %q", got)
	}
	if len(takeEvents(events)) != 0 {
		t.Fatal("events on a clean apply")
	}
	if changes, err := s.Plan(ctx, r); err != nil || len(changes) != 0 {
		t.Fatalf("second plan %v %v", changes, err)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.OK || len(sys.TakeCalls()) != 0 {
		t.Fatalf("second apply %+v", res)
	}

	// A profile change rewrites the file; a removed entry removes it.
	dave.Commands = append(dave.Commands, "/usr/bin/journalctl")
	s.Apply(ctx, sudoResource(t, dave))
	if !strings.Contains(string(sys.Files[name].Data), "/usr/bin/systemctl restart nginx.service, /usr/bin/journalctl\n") {
		t.Fatalf("profile change not applied: %s", sys.Files[name].Data)
	}
	if f := sys.Files["/var/lib/paddock/rollback/"+sudoers.FileName("dave@acme.test")]; f == nil || f.Mode != 0o600 {
		t.Fatal("no rollback copy")
	}
	if res := s.Apply(ctx, sudoResource(t)); res.Status != reconcile.Changed || sys.Files[name] != nil {
		t.Fatalf("stale file kept: %+v", res)
	}
}

func TestSudoUnresolvedUserIsRetried(t *testing.T) {
	ctx := context.Background()
	sys, s, events := sudoFixture(t)
	r := sudoResource(t, restricted("frank@acme.test", "/usr/bin/true"))
	for range 2 {
		s.Apply(ctx, r)
	}
	if got := takeEvents(events); !slices.Equal(got, []event{{protocol.EventSudoUserUnresolved, `{"username":"frank@acme.test"}`}}) {
		t.Fatalf("events %v", got)
	}
	if changes, _ := s.Plan(ctx, r); !slices.Equal(changes, []string{"resolve frank@acme.test"}) {
		t.Fatalf("plan %v (the drift pass must retry)", changes)
	}
	sys.Passwd["frank@acme.test"] = 811000001
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed || sys.Files["/etc/sudoers.d/"+sudoers.FileName("frank@acme.test")] == nil {
		t.Fatalf("after the first login: %+v", res)
	}
}

func TestSudoVisudoFailureKeepsThePreviousState(t *testing.T) {
	ctx := context.Background()
	sys, s, events := sudoFixture(t)
	dave := restricted("dave@acme.test", "/usr/bin/true")
	s.Apply(ctx, sudoResource(t, dave))
	name := "/etc/sudoers.d/" + sudoers.FileName("dave@acme.test")
	before := string(sys.Files[name].Data)

	// The file itself fails visudo -c -f: never renamed into place.
	sys.VisudoReject = "^"
	broken := restricted("dave@acme.test", "/usr/bin/x ^")
	for range 2 {
		if res := s.Apply(ctx, sudoResource(t, broken)); res.Status != reconcile.Error {
			t.Fatalf("apply %+v", res)
		}
	}
	if string(sys.Files[name].Data) != before {
		t.Fatal("a file that failed visudo replaced the working one")
	}
	for path := range sys.Files {
		if strings.Contains(path, ".paddock-tmp-") {
			t.Fatalf("temporary file left: %s", path)
		}
	}
	got := takeEvents(events)
	if len(got) != 1 || got[0].typ != protocol.EventSudoApplyFailed || got[0].data != `{"username":"dave@acme.test","message":"visudo -c -f `+name+`: `+name+`:2:16: syntax error"}` {
		t.Fatalf("events %v (want exactly one sudo.apply_failed)", got)
	}

	// The whole configuration fails after the rename (another file is broken): the previous file is restored.
	sys.VisudoReject = "BROKEN"
	sys.Files["/etc/sudoers.d/README"].Data = []byte("BROKEN\n")
	if res := s.Apply(ctx, sudoResource(t, restricted("dave@acme.test", "/usr/bin/false"))); res.Status != reconcile.Error {
		t.Fatalf("apply %+v", res)
	}
	if string(sys.Files[name].Data) != before {
		t.Fatalf("not restored:\n%s", sys.Files[name].Data)
	}
	// A new file that breaks the configuration is removed again.
	if s.Apply(ctx, sudoResource(t, dave, restricted("erin@acme.test", "/usr/bin/true"))); sys.Files["/etc/sudoers.d/"+sudoers.FileName("erin@acme.test")] != nil {
		t.Fatal("a new file that broke the configuration was kept")
	}
}

func TestSudoQuarantinesForeignFiles(t *testing.T) {
	ctx := context.Background()
	sys, s, events := sudoFixture(t)
	s.Apply(ctx, sudoResource(t))
	takeEvents(events)
	sys.Files["/etc/sudoers.d/evil"] = &fakesys.File{Data: []byte("eve ALL=(ALL) NOPASSWD: ALL\n"), Mode: 0o440}
	r := sudoResource(t)
	if changes, _ := s.Plan(ctx, r); !slices.Equal(changes, []string{"quarantine evil"}) {
		t.Fatalf("plan %v", changes)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Changed {
		t.Fatalf("apply %+v", res)
	}
	if sys.Files["/etc/sudoers.d/evil"] != nil || sys.Files["/etc/sudoers.d/90-paddock"] == nil || sys.Files["/etc/sudoers.d/README"] == nil {
		t.Fatal("wrong files quarantined")
	}
	got := takeEvents(events)
	var ev protocol.TamperSudoersDFile
	if len(got) != 1 || got[0].typ != protocol.EventTamperSudoersDFile || json.Unmarshal([]byte(got[0].data), &ev) != nil || ev.File != "evil" ||
		!strings.HasPrefix(ev.QuarantinedAs, reconcile.QuarantineDir+"/evil.") {
		t.Fatalf("events %v", got)
	}
	if f := sys.Files[ev.QuarantinedAs]; f == nil || f.Mode != 0o600 || string(f.Data) != "eve ALL=(ALL) NOPASSWD: ALL\n" {
		t.Fatalf("quarantine copy %+v", f)
	}
}

func TestSudoDetectsSudoersChanges(t *testing.T) {
	ctx := context.Background()
	sys, s, events := sudoFixture(t)
	r := sudoResource(t)
	s.Apply(ctx, r)
	sum := func(data string) string {
		h := sha256.Sum256([]byte(data))
		return hex.EncodeToString(h[:])
	}
	changed := sudoersFile + "Defaults !lecture\n"
	sys.Files["/etc/sudoers"].Data = []byte(changed)
	sys.TakeCalls()
	if res := s.Apply(ctx, r); res.Status != reconcile.OK {
		t.Fatalf("apply %+v", res)
	}
	if calls := sys.TakeCalls(); slices.Contains(calls, "write /etc/sudoers") {
		t.Fatal("the agent rewrote /etc/sudoers")
	}
	want := event{protocol.EventTamperSudoersChanged, `{"sha256_before":"` + sum(sudoersFile) + `","sha256_after":"` + sum(changed) + `"}`}
	if got := takeEvents(events); !slices.Equal(got, []event{want}) {
		t.Fatalf("events %v", got)
	}
	// Without the includedir the change is reported again together with sudo.apply_failed.
	noInclude := "root ALL=(ALL:ALL) ALL\n"
	sys.Files["/etc/sudoers"].Data = []byte(noInclude)
	if res := s.Apply(ctx, r); res.Status != reconcile.Error {
		t.Fatalf("apply %+v", res)
	}
	got := takeEvents(events)
	if len(got) != 2 || got[0].typ != protocol.EventTamperSudoersChanged ||
		got[1] != (event{protocol.EventSudoApplyFailed, `{"message":"/etc/sudoers lacks @includedir /etc/sudoers.d"}`}) {
		t.Fatalf("events %v", got)
	}
}

func TestPrivilegedGroupsKeepOnlyBreakGlassAccounts(t *testing.T) {
	ctx := context.Background()
	sys, s, events := sudoFixture(t)
	sys.Members["sudo"] = []string{"paddock", "eve", "dave@acme.test"}
	sys.Members["admin"] = []string{"mallory"}
	sys.FailCmd = "gpasswd -d mallory admin"
	r := sudoResource(t)
	if changes, _ := s.Plan(ctx, r); !slices.Contains(changes, "remove eve from sudo") || !slices.Contains(changes, "remove dave@acme.test from sudo") {
		t.Fatalf("plan %v", changes)
	}
	if res := s.Apply(ctx, r); res.Status != reconcile.Error {
		t.Fatalf("apply %+v", res)
	}
	if !slices.Equal(sys.Members["sudo"], []string{"paddock"}) {
		t.Fatalf("sudo members %v", sys.Members["sudo"])
	}
	want := []event{
		{protocol.EventTamperSudoGroupMember, `{"group":"admin","username":"mallory","removed":false}`},
		{protocol.EventTamperSudoGroupMember, `{"group":"sudo","username":"eve","removed":true}`},
		{protocol.EventTamperSudoGroupMember, `{"group":"sudo","username":"dave@acme.test","removed":true}`},
	}
	if got := takeEvents(events); !slices.Equal(got, want) {
		t.Fatalf("events %v", got)
	}
}

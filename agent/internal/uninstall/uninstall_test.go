package uninstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// world is a device below a temporary root with a fake tool runner and TPM.
type world struct {
	t     *testing.T
	root  string
	calls []string
	fail  map[string]int // command line prefix → exit code
	tpm   *fakeTPM
	sent  [][]protocol.Event
	now   time.Time
	// eventSeq is the agent state's last event sequence number.
	eventSeq int64
	// out is the output of a tool run by command line prefix.
	out map[string]string
	// onRun is called with every tool run before its result.
	onRun func(line string)
	// sendErr fails the next sends.
	sendErr int
}

type fakeTPM struct {
	inUse     bool
	inUseErr  error
	clearErr  error
	cleared   bool
	requested bool
}

func (f *fakeTPM) InUse(context.Context) (bool, error) { return f.inUse, f.inUseErr }
func (f *fakeTPM) Clear(context.Context) error {
	if f.clearErr == nil {
		f.cleared = true
	}
	return f.clearErr
}
func (f *fakeTPM) RequestClear() error { f.requested = true; return nil }

const (
	passwd = "root:x:0:0:root:/root:/bin/bash\n" +
		"paddock-admin:x:1001:1001::/home/paddock-admin:/bin/bash\n" +
		"vagrant:x:1000:1000::/home/vagrant:/bin/bash\n"
	shadow = "root:!:19000::::::\npaddock-admin:$6$a:19000::::::\nvagrant:$6$v:19000::::::\n"
	group  = "root:x:0:\nsudo:x:27:vagrant,paddock-admin\nvagrant:x:1000:\npaddock-admin:x:1001:\n"
)

func newWorld(t *testing.T) *world {
	w := &world{t: t, root: t.TempDir(), fail: map[string]int{}, tpm: &fakeTPM{}, now: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC),
		eventSeq: 9}
	managed := "unchanged content"
	sum := sha256.Sum256([]byte(managed))
	managedJSON, _ := json.Marshal(map[string]any{"files": map[string]string{
		"/etc/motd": hex.EncodeToString(sum[:]), "/etc/changed.conf": hex.EncodeToString(sum[:]),
		"/etc/sudoers.d/denied": hex.EncodeToString(sum[:]),
	}})
	for file, data := range map[string]string{
		"/etc/passwd": passwd, "/etc/shadow": shadow, "/etc/group": group,
		"/etc/sudoers.d/paddock-u-alice": "alice ALL=(ALL) ALL\n", "/etc/sudoers.d/paddock-u-bob": "bob ALL=(ALL) ALL\n",
		"/etc/sudoers.d/vagrant":  "vagrant ALL=(ALL) NOPASSWD: ALL\n",
		"/etc/paddock/login-deny": "x\n", "/etc/paddock/notice": "n\n", "/etc/paddock/agent.yml": "server_url: x\n",
		"/etc/issue.d/90-paddock.issue": "n", "/etc/ssh/sshd_config.d/90-paddock-banner.conf": "Banner x",
		"/etc/dconf/db/gdm.d/90-paddock-notice": "n", "/etc/apt/preferences.d/50paddock": "p",
		"/etc/apt/apt.conf.d/52paddock-unattended": "u", "/etc/systemd/system/paddock-updates.timer": "t",
		"/var/lib/paddock/state/held-packages": "curl\nvim\n", "/var/lib/paddock/state/managed.json": string(managedJSON),
		"/var/lib/paddock/quarantine/paddock-q-1": "quarantined\n", "/var/lib/paddock/identity/sign.key": "key",
		"/etc/motd": managed, "/etc/changed.conf": "changed by hand", "/etc/sudoers.d/denied": managed,
		"/etc/himmelblau/himmelblau.conf": "c", "/var/cache/himmelblau/cache": "c", "/var/lib/himmelblau/db": "d",
		"/opt/paddock/agent/A/paddockd": "bin", "/opt/orbit/secret.txt": "s",
		"/var/lib/AccountsService/users/paddock-admin": "a",
		"/home/alice/thesis.odt":                       "user data", "/home/paddock-admin/notes": "admin data", "/srv/share/x": "data",
		"/root/.bashrc": "rc", "/root/paddock-uninstall/paddockd": "helper", "/root/paddock-uninstall/plan.json": "{}",
	} {
		w.write(file, data)
	}
	return w
}

func (w *world) write(file, data string) {
	w.t.Helper()
	p := filepath.Join(w.root, file)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) exists(file string) bool {
	_, err := os.Stat(filepath.Join(w.root, file))
	return err == nil
}

func (w *world) helper() *Helper {
	return &Helper{Root: w.root, Now: func() time.Time { return w.now }, TPM: w.tpm, ReportFor: ReportFor, LocalAdmin: "paddock-admin",
		EventSeq:    func() int64 { return w.eventSeq },
		Preparation: []string{filepath.Join(w.root, "/root/paddock-uninstall/plan.json"), filepath.Join(w.root, "/root/paddock-uninstall/paddockd")},
		Run: func(_ context.Context, _ time.Duration, name string, args ...string) (string, int, error) {
			line := strings.Join(append([]string{name}, args...), " ")
			w.calls = append(w.calls, line)
			if w.onRun != nil {
				w.onRun(line)
			}
			for prefix, out := range w.out {
				if strings.HasPrefix(line, prefix) {
					return out, 0, nil
				}
			}
			for prefix, exit := range w.fail {
				if strings.HasPrefix(line, prefix) {
					return "error: " + line, exit, nil
				}
			}
			return "", 0, nil
		},
		Sleep: func(_ context.Context, d time.Duration) error { w.now = w.now.Add(d); return nil },
		Send: func(_ context.Context, events []protocol.Event) error {
			if w.sendErr > 0 {
				w.sendErr--
				return errors.New("offline")
			}
			w.sent = append(w.sent, events)
			return nil
		},
	}
}

func (w *world) called(prefix string) bool {
	return slices.ContainsFunc(w.calls, func(c string) bool { return strings.HasPrefix(c, prefix) })
}

// userDataIntact asserts that nothing below /home, /srv and /root (except the helper's own directory) changed.
func (w *world) userDataIntact() {
	w.t.Helper()
	for _, f := range []string{"/home/alice/thesis.odt", "/home/paddock-admin/notes", "/srv/share/x", "/root/.bashrc"} {
		if !w.exists(f) {
			w.t.Fatalf("%s was removed", f)
		}
	}
}

// TestLeave (plan M8d decision 40, mode leave): Paddock's services, update configuration, sudoers files, deny list,
// notices and packages go; Himmelblau, managed files, the local administrator and every user file stay; the outcome
// is reported once and Paddock's directories are removed afterwards.
func TestLeave(t *testing.T) {
	w := newWorld(t)
	s := w.helper().Execute(context.Background(), Plan{CommandID: "c1", Mode: "leave", DeviceID: "d1", EventSeqBase: 5})
	if s.Outcome != protocol.UninstallCompleted || s.LocalAdmin != LocalAdminKept || s.TPM != TPMNotRequested || !s.Delivered {
		t.Fatalf("summary %+v", s)
	}
	for step, want := range map[string]string{StepStop: "done", StepUpdates: "done", StepAccess: "done", StepQuarantine: "done",
		StepManaged: "skipped", StepHimmelblau: "skipped", StepLocalAdmin: "skipped", StepPackages: "done", StepTPM: "skipped"} {
		if s.Steps[step] != want {
			t.Fatalf("step %s = %q, want %q (%v)", step, s.Steps[step], want, s.Steps)
		}
	}
	for _, gone := range []string{"/etc/sudoers.d/paddock-u-alice", "/etc/sudoers.d/paddock-u-bob", "/etc/paddock", "/var/lib/paddock",
		"/etc/issue.d/90-paddock.issue", "/etc/ssh/sshd_config.d/90-paddock-banner.conf", "/etc/dconf/db/gdm.d/90-paddock-notice",
		"/etc/apt/preferences.d/50paddock", "/etc/apt/apt.conf.d/52paddock-unattended", "/etc/systemd/system/paddock-updates.timer",
		"/opt/paddock", "/opt/orbit", "/root/paddock-uninstall/paddockd", "/root/paddock-uninstall/plan.json"} {
		if w.exists(gone) {
			t.Fatalf("%s left", gone)
		}
	}
	for _, kept := range []string{"/etc/sudoers.d/vagrant", "/etc/himmelblau/himmelblau.conf", "/etc/motd", "/etc/changed.conf",
		"/var/lib/AccountsService/users/paddock-admin", "/root/paddock-uninstall/quarantine/paddock-q-1", "/root/paddock-uninstall/result.json"} {
		if !w.exists(kept) {
			t.Fatalf("%s removed", kept)
		}
	}
	w.userDataIntact()
	for _, call := range []string{"systemctl stop paddock-supervisor.service", "systemctl disable paddock-supervisor.service",
		"apt-mark unhold curl vim", "visudo -c", "systemctl try-reload-or-restart ssh.service", "dconf update",
		"apt-get remove --purge -y fleet-osquery paddock-revoke paddock-agent paddock-supervisor"} {
		if !w.called(call) {
			t.Fatalf("no %q in %v", call, w.calls)
		}
	}
	if w.called("userdel") || w.called("apt-get remove --purge -y himmelblau") {
		t.Fatalf("leave touched the account or Himmelblau: %v", w.calls)
	}
	if len(w.sent) != 1 || len(w.sent[0]) != 1 || w.sent[0][0].Type != protocol.EventAgentUninstalled || w.sent[0][0].EventSeq != 10 {
		t.Fatalf("sent %+v", w.sent)
	}
	var data protocol.AgentUninstalled
	if err := json.Unmarshal(w.sent[0][0].Data, &data); err != nil || data.CommandID != "c1" || data.Outcome != "completed" ||
		len(data.Steps) != 9 {
		t.Fatalf("event data %+v, %v", data, err)
	}
	var summary Summary
	raw, _ := os.ReadFile(filepath.Join(w.root, "/root/paddock-uninstall/result.json"))
	if err := json.Unmarshal(raw, &summary); err != nil || !summary.Delivered || summary.CommandID != "c1" {
		t.Fatalf("result.json %s (%v)", raw, err)
	}
	if info, _ := os.Stat(filepath.Join(w.root, "/root/paddock-uninstall/result.json")); info.Mode().Perm() != 0o600 {
		t.Fatalf("result.json mode %v", info.Mode())
	}
}

// TestReset (mode reset): additionally Himmelblau with its caches, the unchanged managed files (never a changed one
// or one on a denied path) and the managed local administrator — without its home directory — are removed.
func TestReset(t *testing.T) {
	w := newWorld(t)
	s := w.helper().Execute(context.Background(), Plan{CommandID: "c2", Mode: "reset", DeviceID: "d1"})
	if s.Outcome != protocol.UninstallCompleted || s.LocalAdmin != LocalAdminRemoved || s.Steps[StepManaged] != "done" ||
		s.Steps[StepHimmelblau] != "done" || s.Steps[StepLocalAdmin] != "done" {
		t.Fatalf("summary %+v", s)
	}
	for _, gone := range []string{"/etc/motd", "/etc/himmelblau", "/var/cache/himmelblau", "/var/lib/himmelblau",
		"/var/lib/AccountsService/users/paddock-admin"} {
		if w.exists(gone) {
			t.Fatalf("%s left", gone)
		}
	}
	for _, kept := range []string{"/etc/changed.conf", "/etc/sudoers.d/denied"} {
		if !w.exists(kept) {
			t.Fatalf("%s removed", kept)
		}
	}
	w.userDataIntact()
	if !w.called("userdel -- paddock-admin") || w.called("userdel --remove") ||
		!w.called("apt-get remove --purge -y himmelblau pam-himmelblau nss-himmelblau himmelblau-qr-greeter himmelblau-sshd-config") {
		t.Fatalf("calls %v", w.calls)
	}
	if w.tpm.cleared {
		t.Fatal("TPM cleared without clear_tpm")
	}
}

// TestFailedVisudoRestoresTheLastFile: a failing check puts the file removed last back and marks the step failed; the
// following steps still run and the outcome is partial.
func TestFailedVisudoRestoresTheLastFile(t *testing.T) {
	w := newWorld(t)
	w.fail["visudo -c"] = 1
	s := w.helper().Execute(context.Background(), Plan{CommandID: "c3", Mode: "leave", DeviceID: "d1"})
	if !strings.HasPrefix(s.Steps[StepAccess], "failed:") || s.Outcome != protocol.UninstallPartial || s.Steps[StepPackages] != "done" {
		t.Fatalf("summary %+v", s)
	}
	if w.exists("/etc/sudoers.d/paddock-u-alice") || !w.exists("/etc/sudoers.d/paddock-u-bob") {
		t.Fatal("not the last removed file was restored")
	}
}

// TestLastAdminGuard (plan M8d decision 40 step 7): the managed local administrator is removed only when another
// local account can administer the device.
func TestLastAdminGuard(t *testing.T) {
	for _, tc := range []struct {
		name, passwd, shadow, group, want string
	}{
		{name: "another sudo member", passwd: passwd, shadow: shadow, group: group, want: LocalAdminRemoved},
		{name: "only the managed administrator", passwd: passwd, shadow: shadow,
			group: "sudo:x:27:paddock-admin\nvagrant:x:1000:\n", want: LocalAdminKeptLastAdmin},
		{name: "only a locked account", passwd: passwd, shadow: "paddock-admin:$6$a::\nvagrant:!$6$v::\n", group: group,
			want: LocalAdminKeptLastAdmin},
		{name: "only an account without a password", passwd: passwd, shadow: "paddock-admin:$6$a::\nvagrant:*::\n", group: group,
			want: LocalAdminKeptLastAdmin},
		{name: "only a nologin shell", passwd: "paddock-admin:x:1001:1001::/h:/bin/bash\nvagrant:x:1000:1000::/h:/usr/sbin/nologin\n",
			shadow: shadow, group: group, want: LocalAdminKeptLastAdmin},
		{name: "only a system account", passwd: "paddock-admin:x:1001:1001::/h:/bin/bash\nsvc:x:999:27::/h:/bin/bash\n",
			shadow: "paddock-admin:$6$a::\nsvc:$6$s::\n", group: group, want: LocalAdminKeptLastAdmin},
		{name: "wheel member", passwd: passwd, shadow: shadow, group: "wheel:x:10:vagrant\n", want: LocalAdminRemoved},
		{name: "admin group as primary group", passwd: "paddock-admin:x:1001:1001::/h:/bin/bash\nops:x:1002:116::/h:/bin/zsh\n",
			shadow: "paddock-admin:$6$a::\nops:$6$o::\n", group: "admin:x:116:\n", want: LocalAdminRemoved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.write("/etc/passwd", tc.passwd)
			w.write("/etc/shadow", tc.shadow)
			w.write("/etc/group", tc.group)
			got, _ := w.helper().localAdmin(context.Background())
			if got != tc.want || (got == LocalAdminRemoved) != w.called("userdel") {
				t.Fatalf("local_admin %s (calls %v), want %s", got, w.calls, tc.want)
			}
		})
	}
	t.Run("keep_local_admin", func(t *testing.T) {
		w := newWorld(t)
		s := w.helper().Execute(context.Background(), Plan{CommandID: "c4", Mode: "reset", KeepLocalAdmin: true, DeviceID: "d1"})
		if s.LocalAdmin != LocalAdminKept || w.called("userdel") {
			t.Fatalf("summary %+v, calls %v", s, w.calls)
		}
	})
}

// TestTPM (plan M8d decision 40 step 9): a disk that unlocks with the TPM is never cleared; an authorization failure
// asks the firmware; another failure is reported.
func TestTPM(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tpm     fakeTPM
		want    string
		cleared bool
		ppi     bool
	}{
		{name: "in use", tpm: fakeTPM{inUse: true}, want: TPMSkippedInUse},
		{name: "volume unreadable", tpm: fakeTPM{inUseErr: errors.New("luksDump failed")}, want: TPMSkippedInUse},
		{name: "cleared", want: TPMCleared, cleared: true},
		{name: "authorization", tpm: fakeTPM{clearErr: ErrTPMAuth}, want: TPMRequestedAtNextBoot, ppi: true},
		{name: "other failure", tpm: fakeTPM{clearErr: errors.New("no TPM")}, want: TPMFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			*w.tpm = tc.tpm
			s := w.helper().Execute(context.Background(), Plan{CommandID: "c5", Mode: "reset", ClearTPM: true, DeviceID: "d1"})
			if s.TPM != tc.want || w.tpm.cleared != tc.cleared || w.tpm.requested != tc.ppi {
				t.Fatalf("tpm %s (cleared %v, ppi %v), want %s", s.TPM, w.tpm.cleared, w.tpm.requested, tc.want)
			}
		})
	}
}

// TestReport: the spooled events go first, then agent.uninstalled with the next sequence number; failed sends are
// retried with a back-off, and after 30 minutes the helper gives up and still removes Paddock's directories.
func TestReport(t *testing.T) {
	w := newWorld(t)
	spooled := `{"event_seq":11,"type":"bundle.applied","occurred_at":"2026-10-18T08:00:00Z","data":{}}` + "\n" +
		`{"event_seq":12,"type":"bundle.applied","occurred_at":"2026-10-18T08:01:00Z","data":{}}` + "\n"
	w.write("/var/lib/paddock/spool/events.jsonl", spooled)
	w.sendErr = 2
	s := w.helper().Execute(context.Background(), Plan{CommandID: "c6", Mode: "leave", DeviceID: "d1"})
	if !s.Delivered || len(w.sent) != 2 || len(w.sent[0]) != 2 || w.sent[1][0].EventSeq != 13 {
		t.Fatalf("delivered %v, sent %+v", s.Delivered, w.sent)
	}

	w = newWorld(t)
	w.sendErr = 1000
	start := w.now
	s = w.helper().Execute(context.Background(), Plan{CommandID: "c7", Mode: "leave", DeviceID: "d1"})
	if s.Delivered || w.now.Sub(start) > ReportFor || w.exists("/var/lib/paddock") || w.exists("/etc/paddock") ||
		!w.exists("/root/paddock-uninstall/result.json") {
		t.Fatalf("delivered %v after %s", s.Delivered, w.now.Sub(start))
	}
}

// TestResetPurgesHimmelblauDependencies: packages named himmelblau* that dpkg lists as installed or with configuration
// files left (himmelblau-apparmor, a dependency on Ubuntu 26.04) are purged with the installer's selection; one dpkg
// knows only as not installed is not named.
func TestResetPurgesHimmelblauDependencies(t *testing.T) {
	w := newWorld(t)
	w.out = map[string]string{"dpkg-query -W": "himmelblau ii \nhimmelblau-apparmor ii \nhimmelblau-old rc \n" +
		"himmelblau-qr-greeter ii \nhimmelblau-unused un \n"}
	s := w.helper().Execute(context.Background(), Plan{CommandID: "c9", Mode: "reset", DeviceID: "d1"})
	want := "apt-get remove --purge -y himmelblau pam-himmelblau nss-himmelblau himmelblau-qr-greeter himmelblau-sshd-config " +
		"himmelblau-apparmor himmelblau-old"
	if s.Steps[StepHimmelblau] != "done" || !slices.Contains(w.calls, want) {
		t.Fatalf("step %s, calls %v", s.Steps[StepHimmelblau], w.calls)
	}
}

// TestReportSequenceAfterStop: the agent keeps running until the helper stops it and may spool and deliver events in
// that window; the final event takes the sequence number the agent state has after the stop, so it never repeats one
// the server has already seen (and would drop). Hardening: suspected but not the cause of the S-UN1 failure of
// 2026-10-19, whose reports used the next free number.
func TestReportSequenceAfterStop(t *testing.T) {
	w := newWorld(t)
	w.onRun = func(line string) {
		if strings.HasPrefix(line, "systemctl stop paddock-supervisor.service") {
			w.eventSeq = 14
		}
	}
	s := w.helper().Execute(context.Background(), Plan{CommandID: "c8", Mode: "leave", DeviceID: "d1", EventSeqBase: 9})
	if !s.Delivered || len(w.sent) != 1 || w.sent[0][0].EventSeq != 15 {
		t.Fatalf("delivered %v, sent %+v", s.Delivered, w.sent)
	}
}

func TestPlanValidate(t *testing.T) {
	for _, p := range []Plan{{CommandID: "c", DeviceID: "d", Mode: "wipe"}, {CommandID: "c", DeviceID: "d", Mode: "leave", ClearTPM: true},
		{DeviceID: "d", Mode: "leave"}} {
		if p.Validate() == nil {
			t.Fatalf("%+v accepted", p)
		}
	}
}

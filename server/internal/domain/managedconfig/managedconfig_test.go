package managedconfig

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidatePath(t *testing.T) {
	allowed := []string{
		"/etc/motd", "/etc/chrony/chrony.conf", "/usr/local/etc/app.conf", "/opt/vendor/config.ini",
		"/etc/systemd/system/backup.service", "/etc/sudoers-not-really", "/etc/passwd.d/x", "/etc/aptitude.conf",
	}
	for _, p := range allowed {
		if err := ValidatePath(p); err != nil {
			t.Errorf("%s rejected: %v", p, err)
		}
	}
	rejected := []string{
		"", "etc/motd", "/etc", "/etc/", "/opt/", "/usr/local/etc/", "/var/lib/x", "/usr/bin/sudo", "/root/.ssh/x",
		"/etc/../root/x", "/etc/./motd", "/etc//motd", "/etc/motd/", "/etc/a/../b",
		"/etc/sudoers", "/etc/sudoers.d/paddock", "/etc/sudoers.d", "/etc/pam.d/common-auth", "/etc/security/limits.conf",
		"/etc/nsswitch.conf", "/etc/himmelblau/himmelblau.conf", "/etc/paddock/trust.json", "/etc/paddock",
		"/opt/paddock/bin/paddockd", "/opt/paddock", "/etc/crypttab", "/etc/fstab", "/etc/passwd", "/etc/shadow",
		"/etc/group", "/etc/gshadow", "/etc/apt/sources.list", "/etc/apt", "/etc/systemd/system/paddockd.service",
		"/etc/systemd/system/paddock-supervisor.service", "/etc/mo\ntd", "/etc/mo\x00td", "/etc/a\\b",
		"/etc/" + strings.Repeat("a", 1100),
	}
	for _, p := range rejected {
		if err := ValidatePath(p); !errors.Is(err, ErrPathNotAllowed) {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestValidateModeOwnerContent(t *testing.T) {
	for _, m := range []string{"0644", "0600", "0755", "0000", "0777"} {
		if ValidateMode(m) != nil {
			t.Errorf("mode %s rejected", m)
		}
	}
	for _, m := range []string{"644", "4755", "2755", "1777", "0844", "06444", "", "0o644"} {
		if ValidateMode(m) == nil {
			t.Errorf("mode %s accepted", m)
		}
	}
	for _, o := range []string{"root", "_chrony", "www-data", "a", strings.Repeat("a", 32)} {
		if ValidateOwner(o) != nil {
			t.Errorf("owner %s rejected", o)
		}
	}
	for _, o := range []string{"", "Root", "1user", "us er", strings.Repeat("a", 33), "user$"} {
		if ValidateOwner(o) == nil {
			t.Errorf("owner %q accepted", o)
		}
	}
	if ValidateContent(strings.Repeat("x", MaxContentBytes)) != nil {
		t.Error("64 KiB rejected")
	}
	if !errors.Is(ValidateContent(strings.Repeat("x", MaxContentBytes+1)), ErrContentTooLarge) {
		t.Error("more than 64 KiB accepted")
	}
	if !errors.Is(ValidateContent("a\x00b"), ErrInvalidContent) || !errors.Is(ValidateContent("\xff"), ErrInvalidContent) {
		t.Error("binary content accepted")
	}
}

func TestValidateUnit(t *testing.T) {
	for _, u := range []string{"chrony.service", "backup.timer", "cups.socket", "watch.path", "getty@tty1.service"} {
		if ValidateUnit(u) != nil {
			t.Errorf("unit %s rejected", u)
		}
	}
	for _, u := range []string{
		"chrony", "x.mount", "x.target", "paddockd.service", "Paddock.service", "himmelblaud.service",
		"fleet-osquery.service", "ssh.service", "sshd.socket", "gdm.service", "systemd-timesyncd.service",
		"a b.service", "../x.service", "",
	} {
		if !errors.Is(ValidateUnit(u), ErrUnitNotAllowed) {
			t.Errorf("unit %q accepted", u)
		}
	}
}

func TestResolve(t *testing.T) {
	g1, g2, g3 := uuid.New(), uuid.New(), uuid.New()
	id := uuid.MustParse
	files := []File{
		{ID: id("00000000-0000-0000-0000-000000000001"), Path: "/etc/a", Content: "org"},
		{ID: id("00000000-0000-0000-0000-000000000002"), GroupID: &g1, Path: "/etc/a", Content: "g1"},
		{ID: id("00000000-0000-0000-0000-000000000003"), Path: "/etc/b", Content: "org only"},
		{ID: id("00000000-0000-0000-0000-000000000005"), GroupID: &g2, Path: "/etc/c", Content: "g2"},
		{ID: id("00000000-0000-0000-0000-000000000004"), GroupID: &g1, Path: "/etc/c", Content: "g1"},
		{ID: id("00000000-0000-0000-0000-000000000006"), GroupID: &g3, Path: "/etc/d", Content: "not a member"},
	}
	units := []Unit{
		{ID: id("00000000-0000-0000-0000-000000000007"), Unit: "x.service", Enabled: true},
		{ID: id("00000000-0000-0000-0000-000000000008"), GroupID: &g2, Unit: "x.service"},
	}
	e := Resolve(files, units, []uuid.UUID{g1, g2})
	got := map[string]string{}
	for _, f := range e.Files {
		got[f.Path] = f.Content
	}
	want := map[string]string{"/etc/a": "g1", "/etc/b": "org only", "/etc/c": "g1"}
	if len(got) != len(want) {
		t.Fatalf("files %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if e.Files[0].Path != "/etc/a" || e.Files[2].Path != "/etc/c" {
		t.Errorf("files not sorted: %v", e.Files)
	}
	if len(e.Units) != 1 || e.Units[0].Enabled {
		t.Errorf("group unit should override the organization unit: %+v", e.Units)
	}
	if len(e.Conflicts) != 1 || e.Conflicts[0].Resource != "file:/etc/c" ||
		e.Conflicts[0].Winner != id("00000000-0000-0000-0000-000000000004") || len(e.Conflicts[0].Losers) != 1 {
		t.Fatalf("conflicts %+v", e.Conflicts)
	}

	none := Resolve(files, units, nil)
	if len(none.Files) != 2 || len(none.Units) != 1 || len(none.Conflicts) != 0 {
		t.Fatalf("device without groups: %+v", none)
	}
}

func TestResources(t *testing.T) {
	g := uuid.New()
	e := Resolve([]File{{ID: uuid.New(), Path: "/etc/z", Mode: "0644", Owner: "root", Group: "root", Content: "z"}},
		[]Unit{{ID: uuid.New(), GroupID: &g, Unit: "a.service", Enabled: true, Active: true}}, []uuid.UUID{g})
	rs, err := Resources(e)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rs {
		ids = append(ids, r.ID+"="+r.Type)
	}
	if strings.Join(ids, ",") != "file:/etc/z=file,time=time,unit:a.service=systemd_unit" {
		t.Fatalf("resources %v", ids)
	}
	if !strings.Contains(string(rs[0].Spec), `"content_sha256":"594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06"`) {
		t.Fatalf("file spec %s", rs[0].Spec)
	}
}

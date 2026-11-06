package backuprole

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

var (
	renderAt = time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	smbID    = uuid.MustParse("10000000-0000-4000-8000-000000000001")
	nfsID    = uuid.MustParse("20000000-0000-4000-8000-000000000002")
	localID  = uuid.MustParse("30000000-0000-4000-8000-000000000003")
	goneID   = uuid.MustParse("40000000-0000-4000-8000-000000000004")
)

func hostTargets() []HostTarget {
	return []HostTarget{
		{ID: localID, Name: "local", Type: backupset.TypeLocal, Settings: backupset.Settings{Path: "paddock-backup"}, Revision: 1},
		{ID: smbID, Name: "nas", Type: backupset.TypeSMB, Revision: 3,
			Settings:    backupset.Settings{Host: "nas.example.org", Share: "backup$", Path: "paddock", Username: "svc", Domain: "CORP", Options: "seal"},
			Credentials: backupset.Credentials{Username: "svc", Password: `pa"s\s$x`}},
		{ID: nfsID, Name: "nfs", Type: backupset.TypeNFS, Revision: 2,
			Settings: backupset.Settings{Host: "files.example.org", Export: "/export", Path: "paddock", Options: "vers=4.1,hard"}},
		{ID: goneID, Name: "old share", Type: backupset.TypeSMB, Revision: 5, Deleted: true},
	}
}

// decode splits the render output into the compose file and the other records.
func decode(t *testing.T, out string) (string, []string) {
	t.Helper()
	var doc string
	var rest []string
	for l := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
		if b64, ok := strings.CutPrefix(l, "compose "); ok {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				t.Fatal(err)
			}
			doc = string(raw)
			continue
		}
		rest = append(rest, l)
	}
	return doc, rest
}

func TestWriteHostRenderShape(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHostRender(&buf, renderAt, "/srv/paddock-backup", hostTargets()); err != nil {
		t.Fatal(err)
	}
	doc, records := decode(t, buf.String())
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	smbVol := VolumeName(smbID, 3, "cifs", "//nas.example.org/backup$/paddock",
		"uid=999,gid=999,file_mode=0640,dir_mode=0750,vers=3,seal,username=svc,domain=CORP")
	nfsVol := VolumeName(nfsID, 2, "nfs", ":/export/paddock", "addr=files.example.org,vers=4.1,hard")
	localVol := VolumeName(localID, 1, "none", "/srv/paddock-backup/paddock-backup", "bind")
	want := `# Rendered by ./paddock backup-target apply on 2026-11-06T10:00:00Z from the database; do not edit.
# Holds share passwords: mode 0600, never commit, copy or print it.
# revisions: 10000000-0000-4000-8000-000000000001=3 20000000-0000-4000-8000-000000000002=2 30000000-0000-4000-8000-000000000003=1
# local: ` + b64("/srv/paddock-backup/paddock-backup") + `
services:
  paddock-backup:
    volumes:
      - "` + smbVol + `:/backup-targets/10000000-0000-4000-8000-000000000001"
      - "` + nfsVol + `:/backup-targets/20000000-0000-4000-8000-000000000002"
      - "` + localVol + `:/backup-targets/30000000-0000-4000-8000-000000000003"
volumes:
  ` + smbVol + `:
    driver: local
    driver_opts:
      type: "cifs"
      device: "//nas.example.org/backup$$/paddock"
      o: "uid=999,gid=999,file_mode=0640,dir_mode=0750,vers=3,seal,username=svc,domain=CORP,password=pa\"s\\s$$x"
  ` + nfsVol + `:
    driver: local
    driver_opts:
      type: "nfs"
      device: ":/export/paddock"
      o: "addr=files.example.org,vers=4.1,hard"
  ` + localVol + `:
    driver: local
    driver_opts:
      type: "none"
      device: "/srv/paddock-backup/paddock-backup"
      o: "bind"
`
	if doc != want {
		t.Errorf("compose file:\n%s\nwant:\n%s", doc, want)
	}
	wantRecords := []string{
		"mount 10000000-0000-4000-8000-000000000001 3 " + b64("nas") + " " + smbVol,
		"mount 20000000-0000-4000-8000-000000000002 2 " + b64("nfs") + " " + nfsVol,
		"mount 30000000-0000-4000-8000-000000000003 1 " + b64("local") + " " + localVol,
		"deleted 40000000-0000-4000-8000-000000000004 " + b64("old share"),
	}
	if strings.Join(records, "\n") != strings.Join(wantRecords, "\n") {
		t.Errorf("records %q", records)
	}
	if !strings.HasPrefix(buf.String(), "compose ") {
		t.Errorf("the compose record must come first: %q", buf.String()[:20])
	}
}

func TestWriteHostRenderDefaultsAndRoot(t *testing.T) {
	targets := []HostTarget{
		{ID: smbID, Name: "nas", Type: backupset.TypeSMB, Revision: 1,
			Settings:    backupset.Settings{Host: "10.0.0.5", Share: "b", Username: "svc"},
			Credentials: backupset.Credentials{Password: "pw"}},
		{ID: nfsID, Name: "nfs", Type: backupset.TypeNFS, Revision: 1, Settings: backupset.Settings{Host: "h", Export: "/e"}},
		{ID: localID, Name: "local", Type: backupset.TypeLocal, Settings: backupset.Settings{Path: "a/b"}, Revision: 1},
	}
	var buf bytes.Buffer
	if err := WriteHostRender(&buf, renderAt, "", targets); err != nil {
		t.Fatal(err)
	}
	doc, _ := decode(t, buf.String())
	for _, want := range []string{
		`o: "uid=999,gid=999,file_mode=0640,dir_mode=0750,vers=3,username=svc,password=pw"`,
		`device: "//10.0.0.5/b"`,
		`o: "addr=h,vers=4"`,
		`device: ":/e"`,
		`device: "` + backupset.DefaultLocalRoot + `/a/b"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %s in\n%s", want, doc)
		}
	}
}

func TestWriteHostRenderRefuses(t *testing.T) {
	smb := func(user, domain, pw string) HostTarget {
		return HostTarget{ID: smbID, Name: "nas", Type: backupset.TypeSMB, Revision: 1,
			Settings:    backupset.Settings{Host: "h", Share: "s", Domain: domain},
			Credentials: backupset.Credentials{Username: user, Password: pw}}
	}
	local := func(p string) HostTarget {
		return HostTarget{ID: localID, Name: "local", Type: backupset.TypeLocal, Settings: backupset.Settings{Path: p}, Revision: 1}
	}
	cases := map[string]struct {
		root    string
		targets []HostTarget
	}{
		"root /":                     {"/", []HostTarget{local("x")}},
		"first-level root":           {"/srv", []HostTarget{local("x")}},
		"relative root":              {"srv/backup", nil},
		"unclean root":               {"/srv/../srv/backup", nil},
		"absolute local path":        {"/srv/paddock-backup", []HostTarget{local("/etc")}},
		"dot-dot local path":         {"/srv/paddock-backup", []HostTarget{local("a/../../etc")}},
		"comma in the username":      {"", []HostTarget{smb("svc,ip=10.6.6.6", "", "pw")}},
		"comma in the domain":        {"", []HostTarget{smb("svc", "CORP,sec=none", "pw")}},
		"no password":                {"", []HostTarget{smb("svc", "", "")}},
		"control character password": {"", []HostTarget{smb("svc", "", "a\nb")}},
		"comma password, bind flag":  {"", []HostTarget{smb("svc", "", "x,bind")}},
		"comma password, ro flag":    {"", []HostTarget{smb("svc", "", "x,ro")}},
		"comma password, no flag":    {"", []HostTarget{smb("svc", "", "p,,a")}},
		"space password":             {"", []HostTarget{smb("svc", "", "correct horse battery staple")}},
		"no-break space password":    {"", []HostTarget{smb("svc", "", "a\u00a0b")}},
		"s3 is no volume target":     {"", []HostTarget{{ID: smbID, Name: "s3", Type: backupset.TypeS3}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteHostRender(&buf, renderAt, c.root, c.targets); !errors.Is(err, ErrHostRender) {
				t.Errorf("err = %v, want ErrHostRender", err)
			}
			if buf.Len() != 0 {
				t.Errorf("rendered %q", buf.String())
			}
		})
	}
}

// TestHostRenderNamesThePasswordFix: a stored password from before the input check tells the operator what to do and
// never repeats the password (PDK-733 review 3, R3-M1).
func TestHostRenderNamesThePasswordFix(t *testing.T) {
	err := WriteHostRender(io.Discard, renderAt, "", []HostTarget{{ID: smbID, Name: "nas", Type: backupset.TypeSMB,
		Revision: 1, Settings: backupset.Settings{Host: "h", Share: "s"},
		Credentials: backupset.Credentials{Username: "svc", Password: "correct horse"}}})
	if err == nil || !strings.Contains(err.Error(), "comma or whitespace") || !strings.Contains(err.Error(), "choose another password") ||
		strings.Contains(err.Error(), "horse") {
		t.Errorf("err = %v, want the comma-or-whitespace refusal without the password", err)
	}
}

// TestVolumeNameFollowsTheMount: Docker keeps an existing volume's options, so whatever changes the mount must change
// the name, also without a new revision (PDK-733 review 1, R1-M1).
func TestVolumeNameFollowsTheMount(t *testing.T) {
	local := []HostTarget{{ID: localID, Name: "local", Type: backupset.TypeLocal, Settings: backupset.Settings{Path: "p"}, Revision: 4}}
	name := func(root string, targets []HostTarget) string {
		t.Helper()
		var buf bytes.Buffer
		if err := WriteHostRender(&buf, renderAt, root, targets); err != nil {
			t.Fatal(err)
		}
		_, records := decode(t, buf.String())
		fields := strings.Fields(records[0])
		if len(fields) != 5 || fields[0] != "mount" {
			t.Fatalf("record %q", records[0])
		}
		doc, _ := decode(t, buf.String())
		if !strings.Contains(doc, "\n  "+fields[4]+":\n") || !strings.Contains(doc, `- "`+fields[4]+`:/backup-targets/`) {
			t.Fatalf("volume %s is not the rendered one:\n%s", fields[4], doc)
		}
		return fields[4]
	}
	a := name("/srv/paddock-backup", local)
	if !strings.HasPrefix(a, "backup-target-"+localID.String()+"-r4-") {
		t.Errorf("name %q", a)
	}
	if b := name("/srv/paddock-backup", local); b != a {
		t.Errorf("the same mount renders %q and %q", a, b)
	}
	if b := name("/srv/other-root", local); b == a {
		t.Errorf("another local root keeps the volume name %q", a)
	}
	smb := func(opts, pw string) []HostTarget {
		return []HostTarget{{ID: smbID, Name: "nas", Type: backupset.TypeSMB, Revision: 2,
			Settings:    backupset.Settings{Host: "h", Share: "s", Options: opts},
			Credentials: backupset.Credentials{Username: "svc", Password: pw}}}
	}
	s := name("", smb("", "secret-one"))
	if name("", smb("seal", "secret-one")) == s {
		t.Error("other SMB options keep the volume name")
	}
	if name("", smb("", "secret-two")) != s {
		t.Error("the password must not enter the name, which the host step prints")
	}
}

func TestWriteHostRenderOnlyDeleted(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHostRender(&buf, renderAt, "", []HostTarget{{ID: goneID, Name: "x", Type: backupset.TypeNFS, Deleted: true}}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "deleted "+goneID.String()+" eA==\n" {
		t.Errorf("render %q", buf.String())
	}
	if got := Revisions(nil); got != "none" {
		t.Errorf("Revisions(nil) = %q", got)
	}
}

func TestWriteMountMarker(t *testing.T) {
	dir := t.TempDir()
	id := uuid.New()
	rec := TargetRecord{ID: id, HostRevision: 4}
	if err := WriteMountMarker(dir, id, 4); err == nil {
		t.Error("a missing mount must fail")
	}
	if err := os.Mkdir(filepath.Join(dir, id.String()), 0o750); err != nil {
		t.Fatal(err)
	}
	if got := HostState(dir, rec); got != HostPending {
		t.Errorf("before the marker: %s", got)
	}
	if err := WriteMountMarker(dir, id, 4); err != nil {
		t.Fatal(err)
	}
	if err := WriteMountMarker(dir, id, 4); err != nil {
		t.Fatalf("a second write must succeed: %v", err)
	}
	if got := HostState(dir, rec); got != HostMounted {
		t.Errorf("after the marker: %s", got)
	}
	if got := HostState(dir, TargetRecord{ID: id, HostRevision: 5}); got != HostPending {
		t.Errorf("a newer revision than the marker: %s", got)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, id.String()))
	if len(entries) != 1 {
		t.Errorf("leftover files: %v", entries)
	}

	planted := uuid.New()
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, planted.String())); err != nil {
		t.Fatal(err)
	}
	if err := WriteMountMarker(dir, planted, 1); err == nil {
		t.Error("a symlinked mount must be refused")
	}
}

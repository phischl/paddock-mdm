package backupset_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

func testCAPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func local(mut func(*backupset.Target)) backupset.Target {
	t := backupset.Target{Name: "nas local", Type: backupset.TypeLocal, Local: backupset.Local{Path: "nas/backup"}}
	if mut != nil {
		mut(&t)
	}
	return t
}

func smb(mut func(*backupset.Target)) backupset.Target {
	t := backupset.Target{Name: "office-nas", Type: backupset.TypeSMB, SMB: backupset.SMB{Host: "nas.example.org",
		Share: "backup$", Path: "paddock/set", Username: "svc-paddock", Password: "p=a$s;x", Domain: "CORP",
		Options: "vers=3.1.1,seal,cache=strict,actimeo=30"}}
	if mut != nil {
		mut(&t)
	}
	return t
}

// TestSMBPasswordCommaOrWhitespace: a password with a comma or whitespace is refused at input with a message that
// names the field and tells the operator to choose another one (PDK-733 review 3, R3-M1).
func TestSMBPasswordCommaOrWhitespace(t *testing.T) {
	for _, pw := range []string{"x,bind", "correct horse battery staple", "trailing ", "a\u00a0b"} {
		err := backupset.ValidateTarget(smb(func(t *backupset.Target) { t.SMB.Password = pw }))
		if !errors.Is(err, backupset.ErrInvalidTarget) || !strings.Contains(err.Error(), "smb.password") ||
			!strings.Contains(err.Error(), "comma or whitespace") || !strings.Contains(err.Error(), "choose another password") {
			t.Errorf("password %q: ValidateTarget = %v, want the comma-or-whitespace refusal", pw, err)
		}
	}
	for _, pw := range []string{"p=a$s;x", "S3cr3t!#%&*()[]{}<>?", "ümläut-€"} {
		if err := backupset.ValidateTarget(smb(func(t *backupset.Target) { t.SMB.Password = pw })); err != nil {
			t.Errorf("password %q: ValidateTarget = %v, want nil", pw, err)
		}
	}
}

func nfs(mut func(*backupset.Target)) backupset.Target {
	t := backupset.Target{Name: "nfs_1", Type: backupset.TypeNFS, NFS: backupset.NFS{Host: "10.0.0.5",
		Export: "/export/backup", Path: "paddock", Options: "vers=4.2,hard,timeo=600,retrans=2,nconnect=4"}}
	if mut != nil {
		mut(&t)
	}
	return t
}

func s3(mut func(*backupset.Target)) backupset.Target {
	t := backupset.Target{Name: "offsite.s3", Type: backupset.TypeS3, S3: backupset.S3{
		Endpoint: "https://s3.eu-central-1.example.com", Bucket: "paddock-backup.eu", Region: "eu-central-1",
		Prefix: "lab/set", AccessKey: "AKIAEXAMPLE", SecretKey: "secret/with+chars"}}
	if mut != nil {
		mut(&t)
	}
	return t
}

// TestValidateTargetAccepts covers the valid shapes of plan M15 §6.1.
func TestValidateTargetAccepts(t *testing.T) {
	ca := testCAPEM(t)
	for name, tg := range map[string]backupset.Target{
		"local":                local(nil),
		"smb":                  smb(nil),
		"smb minimal":          smb(func(t *backupset.Target) { t.SMB.Path, t.SMB.Domain, t.SMB.Options = "", "", "" }),
		"smb ipv6 host":        smb(func(t *backupset.Target) { t.SMB.Host = "2001:db8::5" }),
		"smb options":          smb(func(t *backupset.Target) { t.SMB.Options = "vers=3.0,noperm,cache=none" }),
		"nfs":                  nfs(nil),
		"nfs minimal":          nfs(func(t *backupset.Target) { t.NFS.Path, t.NFS.Options = "", "" }),
		"nfs vers 4":           nfs(func(t *backupset.Target) { t.NFS.Options = "vers=4" }),
		"nfs vers 4.1":         nfs(func(t *backupset.Target) { t.NFS.Options = "vers=4.1" }),
		"s3":                   s3(nil),
		"s3 no region, prefix": s3(func(t *backupset.Target) { t.S3.Region, t.S3.Prefix = "", "" }),
		"s3 port":              s3(func(t *backupset.Target) { t.S3.Endpoint = "https://minio.example.com:9000" }),
		"s3 public ip":         s3(func(t *backupset.Target) { t.S3.Endpoint = "https://93.184.215.14" }),
		"s3 ca":                s3(func(t *backupset.Target) { t.S3.CAPEM = ca }),
		"s3 two cas":           s3(func(t *backupset.Target) { t.S3.CAPEM = ca + ca }),
	} {
		if err := backupset.ValidateTarget(tg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestValidateTargetRefuses covers every invalid case of plan M15 §6.1, the option allow lists and the deny list.
func TestValidateTargetRefuses(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	for name, tg := range map[string]backupset.Target{
		"name empty":         local(func(t *backupset.Target) { t.Name = "" }),
		"name leading dot":   local(func(t *backupset.Target) { t.Name = ".x" }),
		"name too long":      local(func(t *backupset.Target) { t.Name = long(65) }),
		"name slash":         local(func(t *backupset.Target) { t.Name = "a/b" }),
		"type":               local(func(t *backupset.Target) { t.Type = "ftp" }),
		"local absolute":     local(func(t *backupset.Target) { t.Local.Path = "/srv/backup" }),
		"local etc":          local(func(t *backupset.Target) { t.Local.Path = "/etc" }),
		"local empty":        local(func(t *backupset.Target) { t.Local.Path = "" }),
		"local dotdot":       local(func(t *backupset.Target) { t.Local.Path = "nas/../../etc" }),
		"local only dotdot":  local(func(t *backupset.Target) { t.Local.Path = ".." }),
		"local dot":          local(func(t *backupset.Target) { t.Local.Path = "nas/./x" }),
		"local trailing":     local(func(t *backupset.Target) { t.Local.Path = "nas/" }),
		"local double":       local(func(t *backupset.Target) { t.Local.Path = "nas//x" }),
		"local backslash":    local(func(t *backupset.Target) { t.Local.Path = "nas\\x" }),
		"local too long":     local(func(t *backupset.Target) { t.Local.Path = long(257) }),
		"local newline":      local(func(t *backupset.Target) { t.Local.Path = "nas/b\nx: y" }),
		"smb host empty":     smb(func(t *backupset.Target) { t.SMB.Host = "" }),
		"smb host comma":     smb(func(t *backupset.Target) { t.SMB.Host = "nas,uid=0" }),
		"smb host url":       smb(func(t *backupset.Target) { t.SMB.Host = "//nas/share" }),
		"smb host long":      smb(func(t *backupset.Target) { t.SMB.Host = strings.Repeat("a.", 127) + "a" }),
		"smb host zone":      smb(func(t *backupset.Target) { t.SMB.Host = "fe80::1%eth0" }),
		"smb share empty":    smb(func(t *backupset.Target) { t.SMB.Share = "" }),
		"smb share slash":    smb(func(t *backupset.Target) { t.SMB.Share = "a/b" }),
		"smb share long":     smb(func(t *backupset.Target) { t.SMB.Share = long(81) }),
		"smb path abs":       smb(func(t *backupset.Target) { t.SMB.Path = "/paddock" }),
		"smb path dotdot":    smb(func(t *backupset.Target) { t.SMB.Path = "a/../.." }),
		"smb user empty":     smb(func(t *backupset.Target) { t.SMB.Username = "" }),
		"smb user long":      smb(func(t *backupset.Target) { t.SMB.Username = long(105) }),
		"smb password":       smb(func(t *backupset.Target) { t.SMB.Password = "" }),
		"smb password long":  smb(func(t *backupset.Target) { t.SMB.Password = long(257) }),
		"smb password nl":    smb(func(t *backupset.Target) { t.SMB.Password = "a\nb" }),
		"smb password comma": smb(func(t *backupset.Target) { t.SMB.Password = "x,bind" }),
		"smb password space": smb(func(t *backupset.Target) { t.SMB.Password = "correct horse" }),
		"smb password nbsp":  smb(func(t *backupset.Target) { t.SMB.Password = "a\u00a0b" }),
		"smb password ideo":  smb(func(t *backupset.Target) { t.SMB.Password = "a\u3000b" }),
		"smb domain long":    smb(func(t *backupset.Target) { t.SMB.Domain = long(65) }),
		"smb opt vers 2":     smb(func(t *backupset.Target) { t.SMB.Options = "vers=2.0" }),
		"smb opt uid":        smb(func(t *backupset.Target) { t.SMB.Options = "seal,uid=0" }),
		"smb opt cred":       smb(func(t *backupset.Target) { t.SMB.Options = "credentials=/etc/shadow" }),
		"smb opt cache":      smb(func(t *backupset.Target) { t.SMB.Options = "cache=loose" }),
		"smb opt actimeo":    smb(func(t *backupset.Target) { t.SMB.Options = "actimeo=x" }),
		"smb opt empty":      smb(func(t *backupset.Target) { t.SMB.Options = "seal,,noperm" }),
		"smb opt nfs":        smb(func(t *backupset.Target) { t.SMB.Options = "hard" }),
		"smb opt long":       smb(func(t *backupset.Target) { t.SMB.Options = strings.Repeat("seal,", 52) + "seal" }),
		"nfs host":           nfs(func(t *backupset.Target) { t.NFS.Host = "-nas" }),
		"nfs export rel":     nfs(func(t *backupset.Target) { t.NFS.Export = "export" }),
		"nfs export long":    nfs(func(t *backupset.Target) { t.NFS.Export = "/" + long(256) }),
		"nfs path abs":       nfs(func(t *backupset.Target) { t.NFS.Path = "/x" }),
		"nfs path dotdot":    nfs(func(t *backupset.Target) { t.NFS.Path = ".." }),
		"nfs opt vers 3":     nfs(func(t *backupset.Target) { t.NFS.Options = "vers=3" }),
		"nfs opt soft":       nfs(func(t *backupset.Target) { t.NFS.Options = "soft" }),
		"nfs opt smb":        nfs(func(t *backupset.Target) { t.NFS.Options = "seal" }),
		"nfs opt nconnect":   nfs(func(t *backupset.Target) { t.NFS.Options = "nconnect=128" }),
		"nfs opt suid":       nfs(func(t *backupset.Target) { t.NFS.Options = "hard,suid" }),
		"s3 http":            s3(func(t *backupset.Target) { t.S3.Endpoint = "http://s3.example.com" }),
		"s3 no scheme":       s3(func(t *backupset.Target) { t.S3.Endpoint = "s3.example.com" }),
		"s3 empty":           s3(func(t *backupset.Target) { t.S3.Endpoint = "" }),
		"s3 userinfo":        s3(func(t *backupset.Target) { t.S3.Endpoint = "https://u:p@s3.example.com" }),
		"s3 query":           s3(func(t *backupset.Target) { t.S3.Endpoint = "https://s3.example.com/?x=1" }),
		"s3 empty query":     s3(func(t *backupset.Target) { t.S3.Endpoint = "https://s3.example.com/?" }),
		"s3 fragment":        s3(func(t *backupset.Target) { t.S3.Endpoint = "https://s3.example.com/#x" }),
		"s3 loopback":        s3(func(t *backupset.Target) { t.S3.Endpoint = "https://127.0.0.1:9000" }),
		"s3 private":         s3(func(t *backupset.Target) { t.S3.Endpoint = "https://10.1.2.3" }),
		"s3 link-local":      s3(func(t *backupset.Target) { t.S3.Endpoint = "https://169.254.169.254" }),
		"s3 ipv6 loopback":   s3(func(t *backupset.Target) { t.S3.Endpoint = "https://[::1]:9000" }),
		"s3 ipv6 ula":        s3(func(t *backupset.Target) { t.S3.Endpoint = "https://[fd00::1]" }),
		"s3 mapped v4":       s3(func(t *backupset.Target) { t.S3.Endpoint = "https://[::ffff:10.0.0.1]" }),
		"s3 bad host":        s3(func(t *backupset.Target) { t.S3.Endpoint = "https://s3_example.com" }),
		"s3 bucket short":    s3(func(t *backupset.Target) { t.S3.Bucket = "ab" }),
		"s3 bucket upper":    s3(func(t *backupset.Target) { t.S3.Bucket = "Paddock" }),
		"s3 bucket long":     s3(func(t *backupset.Target) { t.S3.Bucket = long(64) }),
		"s3 bucket dotdot":   s3(func(t *backupset.Target) { t.S3.Bucket = "a..b" }),
		"s3 bucket ip":       s3(func(t *backupset.Target) { t.S3.Bucket = "192.168.5.4" }),
		"s3 bucket xn":       s3(func(t *backupset.Target) { t.S3.Bucket = "xn--paddock" }),
		"s3 bucket alias":    s3(func(t *backupset.Target) { t.S3.Bucket = "paddock-s3alias" }),
		"s3 bucket dash":     s3(func(t *backupset.Target) { t.S3.Bucket = "paddock-" }),
		"s3 region":          s3(func(t *backupset.Target) { t.S3.Region = "eu central" }),
		"s3 prefix slash":    s3(func(t *backupset.Target) { t.S3.Prefix = "/lab" }),
		"s3 prefix long":     s3(func(t *backupset.Target) { t.S3.Prefix = long(129) }),
		"s3 prefix dotdot":   s3(func(t *backupset.Target) { t.S3.Prefix = "lab/../x" }),
		"s3 access empty":    s3(func(t *backupset.Target) { t.S3.AccessKey = "" }),
		"s3 access long":     s3(func(t *backupset.Target) { t.S3.AccessKey = long(129) }),
		"s3 secret empty":    s3(func(t *backupset.Target) { t.S3.SecretKey = "" }),
		"s3 secret long":     s3(func(t *backupset.Target) { t.S3.SecretKey = long(257) }),
		"s3 ca garbage":      s3(func(t *backupset.Target) { t.S3.CAPEM = "not a pem" }),
		"s3 ca key": s3(func(t *backupset.Target) {
			t.S3.CAPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
		}),
		"s3 ca bad der": s3(func(t *backupset.Target) {
			t.S3.CAPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		}),
		"s3 ca too large": s3(func(t *backupset.Target) { t.S3.CAPEM = long(backupset.MaxCAPEMBytes + 1) }),
	} {
		err := backupset.ValidateTarget(tg)
		if !errors.Is(err, backupset.ErrInvalidTarget) {
			t.Errorf("%s: ValidateTarget = %v, want ErrInvalidTarget", name, err)
			continue
		}
		for _, secret := range []string{tg.SMB.Password, tg.S3.SecretKey, tg.S3.AccessKey} {
			if len(secret) > 3 && strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error repeats a credential: %v", name, err)
			}
		}
	}
	ca := testCAPEM(t)
	if err := backupset.ValidateTarget(s3(func(t *backupset.Target) { t.S3.CAPEM = ca + "trailing" })); err == nil {
		t.Error("s3 ca with trailing text accepted")
	}
}

// TestValidateTargetDevelopmentPolicy: the development stack's policy admits a private address and plain http for
// S3 (PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE), but nothing else of the refused cases.
func TestValidateTargetDevelopmentPolicy(t *testing.T) {
	dev := backupset.Policy{AllowPrivate: true}
	for _, ep := range []string{"http://rustfs-audit:9000", "https://127.0.0.1:9000", "http://10.0.0.1"} {
		if err := dev.ValidateTarget(s3(func(t *backupset.Target) { t.S3.Endpoint = ep })); err != nil {
			t.Errorf("%s: %v", ep, err)
		}
		if err := backupset.ValidateTarget(s3(func(t *backupset.Target) { t.S3.Endpoint = ep })); err == nil {
			t.Errorf("%s accepted by the production policy", ep)
		}
	}
	for _, ep := range []string{"ftp://10.0.0.1", "https://u:p@10.0.0.1", "http://10.0.0.1/?a"} {
		if err := dev.ValidateTarget(s3(func(t *backupset.Target) { t.S3.Endpoint = ep })); err == nil {
			t.Errorf("%s accepted by the development policy", ep)
		}
	}
}

func TestValidateSchedule(t *testing.T) {
	if err := backupset.ValidateSchedule(backupset.DefaultSchedule()); err != nil {
		t.Fatalf("default schedule refused: %v", err)
	}
	lo := backupset.Schedule{FullIntervalHours: 6, OpenBaoIntervalHours: 1, FleetIntervalHours: 6,
		EscrowIntervalHours: 1, RetentionFull: 2, OpenBaoKeepDays: 7, FleetKeepDays: 7}
	hi := backupset.Schedule{FullIntervalHours: 168, OpenBaoIntervalHours: 24, FleetIntervalHours: 168,
		EscrowIntervalHours: 24, RetentionFull: 60, OpenBaoKeepDays: 365, FleetKeepDays: 365}
	for _, s := range []backupset.Schedule{lo, hi} {
		if err := backupset.ValidateSchedule(s); err != nil {
			t.Fatalf("bound %+v refused: %v", s, err)
		}
	}
	fields := []func(*backupset.Schedule) *int{
		func(s *backupset.Schedule) *int { return &s.FullIntervalHours },
		func(s *backupset.Schedule) *int { return &s.OpenBaoIntervalHours },
		func(s *backupset.Schedule) *int { return &s.FleetIntervalHours },
		func(s *backupset.Schedule) *int { return &s.EscrowIntervalHours },
		func(s *backupset.Schedule) *int { return &s.RetentionFull },
		func(s *backupset.Schedule) *int { return &s.OpenBaoKeepDays },
		func(s *backupset.Schedule) *int { return &s.FleetKeepDays },
	}
	for i, f := range fields {
		below, above := lo, hi
		*f(&below)--
		*f(&above)++
		for _, s := range []backupset.Schedule{below, above} {
			if err := backupset.ValidateSchedule(s); !errors.Is(err, backupset.ErrInvalidSchedule) {
				t.Errorf("field %d: %+v: %v, want ErrInvalidSchedule", i, s, err)
			}
		}
	}
}

func TestLocalRoot(t *testing.T) {
	for root, ok := range map[string]bool{
		backupset.DefaultLocalRoot: true, "/srv/paddock-backup/x": true, "/": false, "/srv": false, "": false,
		"srv/backup": false, "/srv/backup/": false, "/srv//backup": false, "/srv/../backup": false,
	} {
		if err := backupset.LocalRoot(root); (err == nil) != ok {
			t.Errorf("LocalRoot(%q) = %v, want ok=%v", root, err, ok)
		}
	}
}

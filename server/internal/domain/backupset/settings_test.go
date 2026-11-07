package backupset

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSettingsCarryNoSecrets: the settings of every type hold the type's fields and never a password or key.
func TestSettingsCarryNoSecrets(t *testing.T) {
	for _, tc := range []struct {
		target Target
		want   Settings
	}{
		{Target{Type: TypeLocal, Local: Local{Path: "nas/backup"}}, Settings{Path: "nas/backup"}},
		{Target{Type: TypeSMB, SMB: SMB{Host: "nas", Share: "backup$", Path: "p", Username: "u", Password: "pw-1",
			Domain: "D", Options: "seal"}},
			Settings{Host: "nas", Share: "backup$", Path: "p", Username: "u", Domain: "D", Options: "seal"}},
		{Target{Type: TypeNFS, NFS: NFS{Host: "nas", Export: "/e", Path: "p", Options: "hard"}},
			Settings{Host: "nas", Export: "/e", Path: "p", Options: "hard"}},
		{Target{Type: TypeS3, S3: S3{Endpoint: "https://s3", Bucket: "b", Prefix: "x", AccessKey: "ak-1", SecretKey: "sk-1"}},
			Settings{Endpoint: "https://s3", Bucket: "b", Region: DefaultRegion, Prefix: "x"}},
	} {
		got := SettingsOf(tc.target)
		if got != tc.want {
			t.Errorf("%s: settings %+v, want %+v", tc.target.Type, got, tc.want)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"pw-1", "ak-1", "sk-1", "password", "secret_key", "access_key"} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("%s: settings JSON %s holds %q", tc.target.Type, raw, secret)
			}
		}
		back, err := ParseSettings(raw)
		if err != nil || back != got {
			t.Errorf("%s: round trip %+v %v", tc.target.Type, back, err)
		}
	}
}

func TestCredentialsOf(t *testing.T) {
	if c, ok := CredentialsOf(Target{Type: TypeSMB, SMB: SMB{Username: "u", Password: "p"}}); !ok || c != (Credentials{Username: "u", Password: "p"}) {
		t.Errorf("smb: %+v %v", c, ok)
	}
	if c, ok := CredentialsOf(Target{Type: TypeS3, S3: S3{AccessKey: "a", SecretKey: "s"}}); !ok || c != (Credentials{AccessKey: "a", SecretKey: "s"}) {
		t.Errorf("s3: %+v %v", c, ok)
	}
	for _, typ := range []TargetType{TypeLocal, TypeNFS} {
		if _, ok := CredentialsOf(Target{Type: typ}); ok {
			t.Errorf("%s has credentials", typ)
		}
	}
	if _, err := ParseSettings([]byte("[")); err == nil {
		t.Error("malformed settings accepted")
	}
}

func TestKindsAndMounted(t *testing.T) {
	for _, k := range []string{"postgres", "authentik", "openbao", "fleet", "escrow"} {
		if !ValidKind(k) {
			t.Errorf("%s refused", k)
		}
	}
	if ValidKind("audit") || ValidKind("") {
		t.Error("unknown kind accepted")
	}
	if !Mounted(TypeLocal) || !Mounted(TypeSMB) || !Mounted(TypeNFS) || Mounted(TypeS3) {
		t.Error("Mounted")
	}
}

func TestRunTargetsAndLabel(t *testing.T) {
	got, err := ParseRunTargets([]byte(`[{"target_id":"a","ok":true},{"target_id":"b","ok":false,"error_class":"auth"}]`))
	if err != nil || len(got) != 2 || got[1] != (RunTarget{TargetID: "b", ErrorClass: "auth"}) {
		t.Fatalf("parse: %+v %v", got, err)
	}
	if got, err := ParseRunTargets(nil); err != nil || got == nil || len(got) != 0 {
		t.Errorf("empty: %+v %v", got, err)
	}
	if _, err := ParseRunTargets([]byte("{")); err == nil {
		t.Error("malformed targets accepted")
	}
	if !ValidRunLabel("") || !ValidRunLabel(strings.Repeat("ä", 64)) {
		t.Error("valid label refused")
	}
	if ValidRunLabel(strings.Repeat("a", 65)) || ValidRunLabel("a\nb") || ValidRunLabel("\xff") {
		t.Error("invalid label accepted")
	}
}

// TestDestinationChange: every setting that decides where SMB or S3 credentials go is a change; path, prefix and the
// types without credentials are not.
func TestDestinationChange(t *testing.T) {
	smb := Settings{Host: "nas", Share: "backup$", Path: "p", Username: "u", Domain: "D", Options: "seal"}
	s3 := Settings{Endpoint: "https://s3", Bucket: "b", Region: DefaultRegion, Prefix: "x", CAPEM: "pem"}
	for _, tc := range []struct {
		typ    TargetType
		cur    Settings
		change func(*Settings)
		want   string
	}{
		{TypeSMB, smb, func(s *Settings) { s.Host = "evil" }, "smb.host"},
		{TypeSMB, smb, func(s *Settings) { s.Share = "other$" }, "smb.share"},
		{TypeSMB, smb, func(s *Settings) { s.Domain = "E" }, "smb.domain"},
		{TypeSMB, smb, func(s *Settings) { s.Username = "v" }, "smb.username"},
		{TypeSMB, smb, func(s *Settings) { s.Options = "seal,ip=192.0.2.7" }, "smb.options"},
		{TypeSMB, smb, func(s *Settings) { s.Path = "q" }, ""},
		{TypeSMB, smb, func(*Settings) {}, ""},
		{TypeS3, s3, func(s *Settings) { s.Endpoint = "https://evil" }, "s3.endpoint"},
		{TypeS3, s3, func(s *Settings) { s.Bucket = "c" }, "s3.bucket"},
		{TypeS3, s3, func(s *Settings) { s.Region = "eu-central-1" }, "s3.region"},
		{TypeS3, s3, func(s *Settings) { s.CAPEM = "other" }, "s3.ca_pem"},
		{TypeS3, s3, func(s *Settings) { s.Prefix = "y" }, ""},
		{TypeNFS, Settings{Host: "nas", Export: "/e"}, func(s *Settings) { s.Host = "other" }, ""},
		{TypeLocal, Settings{Path: "/a"}, func(s *Settings) { s.Path = "/b" }, ""},
	} {
		next := tc.cur
		tc.change(&next)
		if got := DestinationChange(tc.typ, tc.cur, next); got != tc.want {
			t.Errorf("%s %+v → %+v: %q, want %q", tc.typ, tc.cur, next, got, tc.want)
		}
	}
}

package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/canonicaljson"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/sudoers"
)

const (
	device = "0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11"
	org    = "5c1e6d2a-7f0e-4b0d-8f8b-0a3b9b1e2c33"
)

var signingKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))

func sample(t *testing.T) Bundle {
	t.Helper()
	f, err := FileResource(FileSpec{Path: "/etc/motd", Mode: "0644", Owner: "root", Group: "root", Content: "hi\n"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := UnitResource(UnitSpec{Unit: "chrony.service", Enabled: true, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	tm, err := TimeResource(TimeSpec{NTP: true})
	if err != nil {
		t.Fatal(err)
	}
	rs := []Resource{u, tm, f}
	SortResources(rs)
	return Bundle{
		SchemaVersion: SchemaVersion, BundleVersion: 5, DeviceID: device, OrganizationID: org,
		IssuedAt: time.Date(2026, 10, 3, 8, 15, 0, 0, time.UTC), Agent: AgentCfg{CheckinIntervalS: 300}, Resources: rs,
	}
}

func seal(t *testing.T, b Bundle, key ed25519.PrivateKey, payloadType string) []byte {
	t.Helper()
	payload, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.New(payloadType, payload, dsse.SignEd25519(key, "bundle-signing:v1", payloadType, payload)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func trust() Trust {
	return Trust{Keys: map[string]ed25519.PublicKey{"bundle-signing:v1": signingKey.Public().(ed25519.PublicKey)}}
}

func TestEncodeGolden(t *testing.T) {
	got, err := Encode(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agent":{"checkin_interval_s":300},"bundle_version":5,"device_id":"` + device + `",` +
		`"issued_at":"2026-10-03T08:15:00Z","organization_id":"` + org + `","resources":[` +
		`{"id":"file:/etc/motd","spec":{"content":"hi\n","content_sha256":"98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4","group":"root","mode":"0644","owner":"root","path":"/etc/motd"},"type":"file"},` +
		`{"id":"time","spec":{"ntp":true},"type":"time"},` +
		`{"id":"unit:chrony.service","spec":{"active":true,"enabled":true,"unit":"chrony.service"},"type":"systemd_unit"}],` +
		`"schema_version":1}`
	if string(got) != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestContentSHA256IgnoresIssuedAtAndVersion(t *testing.T) {
	a := sample(t)
	b := a
	b.IssuedAt = b.IssuedAt.Add(time.Hour)
	b.BundleVersion = 99
	ha, err := ContentSHA256(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := ContentSHA256(b)
	if ha != hb {
		t.Fatal("issued_at or bundle_version changed the content hash")
	}
	c := a
	c.Resources = c.Resources[:2]
	if hc, _ := ContentSHA256(c); hc == ha {
		t.Fatal("removing a resource did not change the content hash")
	}
	d := a
	d.DeviceID = org
	if hd, _ := ContentSHA256(d); hd == ha {
		t.Fatal("device id is not part of the content hash")
	}
}

func TestVerify(t *testing.T) {
	good := seal(t, sample(t), signingKey, PayloadType)
	b, err := Verify(good, trust(), device, org, 4)
	if err != nil {
		t.Fatal(err)
	}
	if b.BundleVersion != 5 || len(b.Resources) != 3 {
		t.Fatalf("decoded %+v", b)
	}

	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	schema2 := sample(t)
	schema2.SchemaVersion = 2
	cases := map[string]struct {
		env           []byte
		device, org   string
		min           int64
		want          error
		trustOverride *Trust
	}{
		"untrusted key":       {env: seal(t, sample(t), other, PayloadType), want: ErrSignature},
		"no trusted keys":     {env: good, want: ErrSignature, trustOverride: &Trust{}},
		"not an envelope":     {env: []byte(`{"x":1}`), want: ErrSignature},
		"tampered payload":    {env: bytes.Replace(good, []byte(`"payload":"`), []byte(`"payload":"e`), 1), want: ErrSignature},
		"wrong payload type":  {env: seal(t, sample(t), signingKey, "application/json"), want: ErrSchema},
		"wrong device":        {env: good, device: "11111111-1111-4111-8111-111111111111", want: ErrWrongDevice},
		"wrong organization":  {env: good, org: "11111111-1111-4111-8111-111111111111", want: ErrWrongDevice},
		"same version":        {env: good, min: 5, want: ErrDowngrade},
		"older version":       {env: good, min: 6, want: ErrDowngrade},
		"unsupported schema":  {env: seal(t, schema2, signingKey, PayloadType), want: ErrSchema},
		"payload is not JSON": {env: sealRaw(t, []byte("not json")), want: ErrSchema},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d, o := device, org
			if c.device != "" {
				d = c.device
			}
			if c.org != "" {
				o = c.org
			}
			tr := trust()
			if c.trustOverride != nil {
				tr = *c.trustOverride
			}
			if _, err := Verify(c.env, tr, d, o, c.min); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func sealRaw(t *testing.T, payload []byte) []byte {
	t.Helper()
	env, err := dsse.New(PayloadType, payload, dsse.SignEd25519(signingKey, "bundle-signing:v1", PayloadType, payload)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestTrustFromKeys(t *testing.T) {
	pub := base64.StdEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey))
	tr, err := TrustFromKeys([]protocol.BundleKey{{KeyID: "bundle-signing:v1", PublicKey: pub}})
	if err != nil || len(tr.Keys) != 1 {
		t.Fatalf("%v %v", tr, err)
	}
	if _, err := TrustFromKeys(nil); err == nil {
		t.Error("empty trust accepted")
	}
	if _, err := TrustFromKeys([]protocol.BundleKey{{KeyID: "k", PublicKey: "AAAA"}}); err == nil {
		t.Error("short key accepted")
	}
}

func TestValidHimmelblauVersion(t *testing.T) {
	for v, want := range map[string]bool{"4.0.4": true, "10.12.0": true, "4.0": false, "4.0.4-1": false, "../4.0.4": false, "": false} {
		if got := ValidHimmelblauVersion(v); got != want {
			t.Errorf("ValidHimmelblauVersion(%q) = %v", v, got)
		}
	}
}

func TestV2ResourcesGolden(t *testing.T) {
	login, err := LoginResource(LoginSpec{
		Provider: ProviderHimmelblau,
		Himmelblau: HimmelblauSpec{
			OIDCIssuerURL: "https://auth.example.org/application/o/paddock-device-acme/", AppID: "paddock-device-acme",
			Domain: "acme.test", EnableHello: true, HelloPinMinLength: 6, PackageVersion: "4.0.4",
		},
		Suspended: true, SessionAction: SessionActionLockScreen,
	})
	if err != nil {
		t.Fatal(err)
	}
	sudo, err := SudoResource(SudoSpec{
		LectureText: "Be careful.",
		Entries: []sudoers.Entry{{Username: "erin@acme.test", Class: sudoers.ClassFull, RequirePassword: true,
			Lecture: sudoers.LectureOnce, ProfileDigest: "d"}},
		PrivilegedGroups: []string{"sudo", "admin", "wheel"}, SudoersDAllowlist: []string{"README"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := sample(t)
	b.SchemaVersion = SchemaVersion2
	b.Resources = []Resource{sudo, login}
	SortResources(b.Resources)
	got, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	// Suspension empties pam_allow_groups, which is encoded as an explicit empty list, never omitted (PoC M1 C3).
	for _, want := range []string{
		`{"id":"login","spec":{"break_glass_accounts":[],"himmelblau":{"app_id":"paddock-device-acme","domain":"acme.test",` +
			`"enable_hello":true,"hello_pin_min_length":6,"oidc_issuer_url":"https://auth.example.org/application/o/paddock-device-acme/",` +
			`"package_version":"4.0.4","pam_allow_groups":[]},"locked_users":[],"provider":"himmelblau","session_action":"lock_screen","suspended":true},"type":"login"}`,
		`{"id":"sudo","spec":{"break_glass_accounts":[],"entries":[{"class":"full","commands":[],"lecture":"once",` +
			`"profile_digest":"d","require_password":true,"root_equivalent":false,"timestamp_timeout_min":0,"username":"erin@acme.test"}],` +
			`"lecture_text":"Be careful.","privileged_groups":["sudo","admin","wheel"],"sudoers_d_allowlist":["README"]},"type":"sudo"}`,
		`"schema_version":2}`,
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("payload lacks\n%s\ngot\n%s", want, got)
		}
	}
}

func TestVerifyVersions(t *testing.T) {
	v2 := sample(t)
	v2.SchemaVersion = SchemaVersion2
	env := seal(t, v2, signingKey, PayloadType)
	if _, err := Verify(env, trust(), device, org, 0); !errors.Is(err, ErrSchema) {
		t.Fatalf("Verify accepted schema 2: %v", err)
	}
	b, err := VerifyVersions(env, trust(), device, org, 0, []int{SchemaVersion, SchemaVersion2})
	if err != nil || b.SchemaVersion != SchemaVersion2 {
		t.Fatalf("VerifyVersions: %v, %v", b, err)
	}
}

func TestValidSchedule(t *testing.T) {
	for s, want := range map[string]bool{
		"Sat 04:00": true, "Mon,Thu 12:30": true, "02:00": true, "Sun 23:59": true,
		"Sat 4:00": false, "Sat 24:00": false, "Sat,Sat 04:00": false, "sat 04:00": false, "Mon..Fri 04:00": false,
		"*-*-* 04:00": false, "Sat  04:00": false, "Sat 04:00\nExecStart=x": false, "": false, "Sat": false,
	} {
		if got := ValidSchedule(s); got != want {
			t.Errorf("ValidSchedule(%q) = %v", s, got)
		}
	}
}

func TestValidPackageAndVersion(t *testing.T) {
	for p, want := range map[string]bool{"openssl": true, "libc6": true, "g++": true, "libstdc++6": true, "x": false,
		"-o": false, "Openssl": false, "open ssl": false, "": false, "a\nb": false} {
		if got := ValidPackage(p); got != want {
			t.Errorf("ValidPackage(%q) = %v", p, got)
		}
	}
	for v, want := range map[string]bool{"3.0.13-0ubuntu3.4": true, "1:2.3~rc1+b2": true, "": false, "1.0 2": false, "1.0\n": false} {
		if got := ValidPackageVersion(v); got != want {
			t.Errorf("ValidPackageVersion(%q) = %v", v, got)
		}
	}
}

func TestUpdatesResourceGolden(t *testing.T) {
	v := "3.0.13-0ubuntu3.4"
	r, err := UpdatesResource(UpdatesSpec{SecurityDailyAt: "03:00", RegularSchedule: "Sat 04:00", RegularUpdatesEnabled: true,
		MaxRandomDelayMin: 60, Holds: []Hold{{Package: "linux-generic"}, {Package: "openssl", Version: &v}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"holds":[{"package":"linux-generic","version":null},{"package":"openssl","version":"3.0.13-0ubuntu3.4"}],` +
		`"max_random_delay_min":60,"regular_schedule":"Sat 04:00","regular_updates_enabled":true,"security_daily_at":"03:00"}`
	got, err := canonicaljson.Marshal(r.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "updates" || r.Type != TypeUpdates || string(got) != want {
		t.Errorf("resource %s/%s spec\n%s\nwant\n%s", r.ID, r.Type, got, want)
	}
	empty, _ := UpdatesResource(UpdatesSpec{SecurityDailyAt: "03:00", RegularSchedule: "02:00"})
	if !bytes.Contains(empty.Spec, []byte(`"holds":[]`)) {
		t.Errorf("nil holds not encoded as []: %s", empty.Spec)
	}
	if err := ValidateUpdates(UpdatesSpec{SecurityDailyAt: "03:00", RegularSchedule: "Sat 04:00", Holds: []Hold{{Package: "-o"}}}); err == nil {
		t.Error("ValidateUpdates accepted an option as package")
	}
}

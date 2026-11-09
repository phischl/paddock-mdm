package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
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

func TestValidHostname(t *testing.T) {
	cases := map[string]bool{
		"a": true, "lap-0421": true, strings.Repeat("a", 63): true,
		"": false, "-a": false, "a-": false, "A1": false, "a.b": false, "localhost": false,
		strings.Repeat("a", 64): false, "a_b": false,
	}
	for name, want := range cases {
		if got := ValidHostname(name); got != want {
			t.Errorf("ValidHostname(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestHostnameResource(t *testing.T) {
	r, err := HostnameResource(HostnameSpec{Name: "lap-0421"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "hostname" || r.Type != TypeHostname || string(r.Spec) != `{"name":"lap-0421"}` {
		t.Errorf("resource %s/%s spec %s", r.ID, r.Type, r.Spec)
	}
	a := sample(t)
	b := a
	b.Hostname = &HostnameSpec{Name: "lap-0421"}
	ha, _ := ContentSHA256(a)
	hb, err := ContentSHA256(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Error("the hostname section is not part of the content hash")
	}
}

func TestVerifyModes(t *testing.T) {
	for mode, wantErr := range map[string]bool{ModeEnforce: false, ModeReportOnly: false, "dry": true} {
		b := sample(t)
		b.Mode = mode
		_, err := Verify(seal(t, b, signingKey, PayloadType), trust(), device, org, 0)
		if wantErr != errors.Is(err, ErrSchema) || (!wantErr && err != nil) {
			t.Errorf("mode %q: err %v, want ErrSchema %v", mode, err, wantErr)
		}
	}
	plain, withMode := sample(t), sample(t)
	withMode.Mode = ModeReportOnly
	hp, _ := ContentSHA256(plain)
	hm, _ := ContentSHA256(withMode)
	if hp == hm {
		t.Fatal("mode is not part of the content hash")
	}
}

func TestWatchResource(t *testing.T) {
	r, err := WatchResource(WatchSpec{Units: []string{"wazuh-agent.service"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "watch" || r.Type != TypeWatch || string(r.Spec) != `{"units":["wazuh-agent.service"]}` {
		t.Errorf("resource %s/%s spec %s", r.ID, r.Type, r.Spec)
	}
	a := sample(t)
	b := a
	b.Watch = &WatchSpec{Units: []string{"wazuh-agent.service"}}
	ha, _ := ContentSHA256(a)
	hb, err := ContentSHA256(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Error("the watch section is not part of the content hash")
	}
	enc, err := Encode(b)
	if err != nil || !strings.Contains(string(enc), `"watch":{"units":["wazuh-agent.service"]}`) {
		t.Errorf("encoded bundle lacks the watch section: %s (%v)", enc, err)
	}
	enc, err = Encode(a)
	if err != nil || strings.Contains(string(enc), `"watch"`) {
		t.Errorf("a bundle without watched units must carry no watch section: %s (%v)", enc, err)
	}
}

// TestWatchSectionDecodes (plan M9 decision 39): a signed v2 bundle carries the watch section to the agent, and the
// decoder ignores a section it does not know, which is how an older agent applies a bundle with watch section.
func TestWatchSectionDecodes(t *testing.T) {
	v2 := sample(t)
	v2.SchemaVersion = SchemaVersion2
	v2.Watch = &WatchSpec{Units: []string{"wazuh-agent.service"}}
	b, err := VerifyVersions(seal(t, v2, signingKey, PayloadType), trust(), device, org, 0, []int{SchemaVersion, SchemaVersion2})
	if err != nil || b.Watch == nil || !slices.Equal(b.Watch.Units, v2.Watch.Units) {
		t.Fatalf("watch section %+v (%v)", b, err)
	}
	payload, err := Encode(v2)
	if err != nil {
		t.Fatal(err)
	}
	future := bytes.Replace(payload, []byte(`"watch":`), []byte(`"watch_next":{"units":["x.service"]},"watch":`), 1)
	if bytes.Equal(future, payload) {
		t.Fatal("payload has no watch section")
	}
	if b, err = VerifyVersions(sealRaw(t, future), trust(), device, org, 0, []int{SchemaVersion2}); err != nil || len(b.Resources) != len(v2.Resources) {
		t.Fatalf("a bundle with an unknown section: %+v (%v)", b, err)
	}
}

func validSoftware() SoftwareSpec {
	v := "1.0"
	return SoftwareSpec{
		Sources: []SoftwareSource{{Slug: "vendor", URIs: []string{"https://repo.example.com/apt"}, Suites: []string{"stable"},
			Components: []string{"main"}, Architectures: []string{"amd64"}, Keyring: base64.StdEncoding.EncodeToString([]byte("key")),
			Fingerprint: strings.Repeat("AB", 20)}},
		Packages: []SoftwarePackage{
			{Package: "nano", Intent: SoftwareRequired, Version: &v, Source: "vendor", CatalogEntryID: "0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11"},
			{Package: "vim", Intent: SoftwareRequired, CatalogEntryID: "5c1e6d2a-7f0e-4b0d-8f8b-0a3b9b1e2c33"},
		},
	}
}

// available makes the second package of a validSoftware section available to audience.
func available(s *SoftwareSpec, audience *SoftwareAudience) {
	s.Packages[1].Intent, s.Packages[1].Version, s.Packages[1].Audience = SoftwareAvailable, nil, audience
}

// flatpak adds the Flatpak remote flathub and makes the second package of a validSoftware section the application ref
// from it in scope.
func flatpak(s *SoftwareSpec, ref, scope string) {
	s.Sources = append(s.Sources, SoftwareSource{Slug: "flathub", Kind: SoftwareSourceFlatpak, URIs: []string{"https://dl.flathub.org/repo/"},
		Keyring: base64.StdEncoding.EncodeToString([]byte("key")), Fingerprint: strings.Repeat("CD", 20)})
	s.Packages[1].Package, s.Packages[1].FlatpakRef, s.Packages[1].Scope, s.Packages[1].Source = "", ref, scope, "flathub"
}

// targeted makes the second package of a validSoftware section the user-scope Flatpak application org.gimp.GIMP with
// intent and the targeted users.
func targeted(s *SoftwareSpec, intent string, users ...string) {
	flatpak(s, "org.gimp.GIMP", SoftwareScopeUser)
	s.Packages[1].Intent, s.Packages[1].Version = intent, nil
	if users != nil {
		s.Packages[1].Users = &users
	}
}

// audienceOf returns n sorted, distinct user names.
func audienceOf(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("user%04d@example.org", i)
	}
	return out
}

func TestValidateSoftware(t *testing.T) {
	v := "2.0"
	cases := map[string]struct {
		change func(*SoftwareSpec)
		ok     bool
	}{
		"valid":                    {func(*SoftwareSpec) {}, true},
		"required without version": {func(s *SoftwareSpec) { s.Packages[0].Version = nil }, true},
		"hold with version":        {func(s *SoftwareSpec) { s.Packages[1].Intent, s.Packages[1].Version = SoftwareHold, &v }, true},
		"flat repository":          {func(s *SoftwareSpec) { s.Sources[0].Suites, s.Sources[0].Components = []string{"./"}, nil }, true},
		"http uri":                 {func(s *SoftwareSpec) { s.Sources[0].URIs = []string{"http://repo.example.com/apt"} }, false},
		"uri with newline":         {func(s *SoftwareSpec) { s.Sources[0].URIs = []string{"https://repo.example.com/\nSigned-By: x"} }, false},
		"uri with user info":       {func(s *SoftwareSpec) { s.Sources[0].URIs = []string{"https://u@repo.example.com/"} }, false},
		"uri with U+FFFD":          {func(s *SoftwareSpec) { s.Sources[0].URIs = []string{"https://example.com/\uFFFDrepo"} }, false},
		"uri with braille blank":   {func(s *SoftwareSpec) { s.Sources[0].URIs = []string{"https://example.com/\u2800"} }, false},
		"uri with a quote":         {func(s *SoftwareSpec) { s.Sources[0].URIs = []string{`https://example.com/a"b`} }, false},
		"uri with port 99999":      {func(s *SoftwareSpec) { s.Sources[0].URIs = []string{"https://example.com:99999/"} }, false},
		"uri with port and idn":    {func(s *SoftwareSpec) { s.Sources[0].URIs = []string{"https://bücher.example:8443/apt"} }, true},
		"forbid superseding hold": {func(s *SoftwareSpec) {
			s.Packages[1].Intent, s.Packages[1].SupersededHold = SoftwareForbid, true
		}, true},
		"uninstall superseding hold": {func(s *SoftwareSpec) {
			s.Packages[1].Intent, s.Packages[1].SupersededHold = SoftwareUninstall, true
		}, true},
		"required superseding hold":  {func(s *SoftwareSpec) { s.Packages[1].SupersededHold = true }, false},
		"fully protected required":   {func(s *SoftwareSpec) { s.Packages[1].Package = "paddock-agent" }, false},
		"fully protected hold":       {func(s *SoftwareSpec) { s.Packages[1].Package, s.Packages[1].Intent = "pam-himmelblau", SoftwareHold }, false},
		"removal protected forbid":   {func(s *SoftwareSpec) { s.Packages[1].Package, s.Packages[1].Intent = "sudo", SoftwareForbid }, false},
		"removal protected removal":  {func(s *SoftwareSpec) { s.Packages[1].Package, s.Packages[1].Intent = "dracut", SoftwareUninstall }, false},
		"removal protected required": {func(s *SoftwareSpec) { s.Packages[1].Package = "sudo" }, true},
		"conflicting required":       {func(s *SoftwareSpec) { s.Packages[1].Package = "initramfs-tools" }, false},
		"conflicting hold":           {func(s *SoftwareSpec) { s.Packages[1].Package, s.Packages[1].Intent = "initramfs-tools", SoftwareHold }, false},
		"conflicting forbid":         {func(s *SoftwareSpec) { s.Packages[1].Package, s.Packages[1].Intent = "initramfs-tools", SoftwareForbid }, true},
		"slug A":                     {func(s *SoftwareSpec) { s.Sources[0].Slug, s.Packages[0].Source = "A", "A" }, false},
		"unknown source":             {func(s *SoftwareSpec) { s.Packages[0].Source = "other" }, false},
		"duplicate package":          {func(s *SoftwareSpec) { s.Packages[1].Package = "nano" }, false},
		"duplicate source": {func(s *SoftwareSpec) {
			s.Sources = append(s.Sources, s.Sources[0])
		}, false},
		"uninstall with version":     {func(s *SoftwareSpec) { s.Packages[0].Intent = SoftwareUninstall }, false},
		"forbid with version":        {func(s *SoftwareSpec) { s.Packages[0].Intent = SoftwareForbid }, false},
		"unknown intent":             {func(s *SoftwareSpec) { s.Packages[1].Intent = "suggested" }, false},
		"option as package":          {func(s *SoftwareSpec) { s.Packages[1].Package = "-o" }, false},
		"invalid version":            {func(s *SoftwareSpec) { bad := "1 0"; s.Packages[0].Version = &bad }, false},
		"fingerprint of 39":          {func(s *SoftwareSpec) { s.Sources[0].Fingerprint = s.Sources[0].Fingerprint[:39] }, false},
		"lowercase fingerprint":      {func(s *SoftwareSpec) { s.Sources[0].Fingerprint = strings.Repeat("ab", 20) }, false},
		"keyring not base64":         {func(s *SoftwareSpec) { s.Sources[0].Keyring = "not base64!" }, false},
		"empty keyring":              {func(s *SoftwareSpec) { s.Sources[0].Keyring = "" }, false},
		"no suites":                  {func(s *SoftwareSpec) { s.Sources[0].Suites = nil }, false},
		"suite with newline":         {func(s *SoftwareSpec) { s.Sources[0].Suites = []string{"stable\nX"} }, false},
		"no components":              {func(s *SoftwareSpec) { s.Sources[0].Components = nil }, false},
		"flat with components":       {func(s *SoftwareSpec) { s.Sources[0].Suites = []string{"./"} }, false},
		"unknown architecture":       {func(s *SoftwareSpec) { s.Sources[0].Architectures = []string{"i386"} }, false},
		"invalid catalog entry id":   {func(s *SoftwareSpec) { s.Packages[1].CatalogEntryID = "x" }, false},
		"uppercase catalog entry id": {func(s *SoftwareSpec) { s.Packages[1].CatalogEntryID = strings.ToUpper(s.Packages[1].CatalogEntryID) }, false},
		// Architect decision A10-14: the digest of the entry's icon.
		"icon digest":           {func(s *SoftwareSpec) { s.Packages[1].IconSHA256 = strings.Repeat("ab", 32) }, true},
		"short icon digest":     {func(s *SoftwareSpec) { s.Packages[1].IconSHA256 = strings.Repeat("ab", 31) }, false},
		"uppercase icon digest": {func(s *SoftwareSpec) { s.Packages[1].IconSHA256 = strings.Repeat("AB", 32) }, false},
		"runtime with icon digest": {func(s *SoftwareSpec) {
			s.Packages[1].CatalogEntryID, s.Packages[1].IconSHA256 = SoftwareRuntimeEntryID, strings.Repeat("ab", 32)
		}, false},
		// Plan M13b decision 7: available, audiences and Flatpak.
		"available to all": {func(s *SoftwareSpec) { available(s, &SoftwareAudience{All: true}) }, true},
		"available to users": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{Users: []string{"alice@example.org", "bob@example.org"}})
		}, true},
		"available to 200":      {func(s *SoftwareSpec) { available(s, &SoftwareAudience{Users: audienceOf(MaxSoftwareAudience)}) }, true},
		"available to 201":      {func(s *SoftwareSpec) { available(s, &SoftwareAudience{Users: audienceOf(MaxSoftwareAudience + 1)}) }, false},
		"available no audience": {func(s *SoftwareSpec) { available(s, nil) }, false},
		"available empty":       {func(s *SoftwareSpec) { available(s, &SoftwareAudience{}) }, false},
		"available all and users": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true, Users: []string{"alice@example.org"}})
		}, false},
		"available unsorted": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{Users: []string{"bob@example.org", "alice@example.org"}})
		}, false},
		"available duplicate user": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{Users: []string{"alice@example.org", "alice@example.org"}})
		}, false},
		"available upper-case user": {func(s *SoftwareSpec) { available(s, &SoftwareAudience{Users: []string{"Alice@example.org"}}) }, false},
		"available empty user":      {func(s *SoftwareSpec) { available(s, &SoftwareAudience{Users: []string{""}}) }, false},
		// Review 1 finding 2: the limit is app_user.username's, 256 characters.
		"available 256-character user": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{Users: []string{strings.Repeat("a", 244) + "@example.org"}})
		}, true},
		"available 256-character multibyte user": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{Users: []string{strings.Repeat("ä", 244) + "@example.org"}})
		}, true},
		"available 257-character user": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{Users: []string{strings.Repeat("a", 245) + "@example.org"}})
		}, false},
		"available user with space": {func(s *SoftwareSpec) { available(s, &SoftwareAudience{Users: []string{"a b@example.org"}}) }, false},
		"available with version": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Version = &v
		}, false},
		"required with audience": {func(s *SoftwareSpec) { s.Packages[1].Audience = &SoftwareAudience{All: true} }, false},
		"conflicting available": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Package = "initramfs-tools"
		}, false},
		"fully protected available": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Package = "paddock-agent"
		}, false},
		"flatpak system": {func(s *SoftwareSpec) { flatpak(s, "org.gimp.GIMP", "") }, true},
		"flatpak user available": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", SoftwareScopeUser)
			available(s, &SoftwareAudience{Users: []string{"alice@example.org"}})
		}, true},
		"flatpak invalid scope": {func(s *SoftwareSpec) { flatpak(s, "org.gimp.GIMP", "global") }, false},
		"flatpak invalid ref":   {func(s *SoftwareSpec) { flatpak(s, "gimp", "") }, false},
		"flatpak ref too long":  {func(s *SoftwareSpec) { flatpak(s, "org.example."+strings.Repeat("a", 250), "") }, false},
		"package and flatpak_ref": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			s.Packages[1].Package = "gimp"
		}, false},
		"flatpak_ref from apt source": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			s.Packages[1].Source = "vendor"
		}, false},
		"flatpak_ref without source": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			s.Packages[1].Source = ""
		}, false},
		"available flatpak_ref without source": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Source = ""
		}, false},
		// Architect decision A10-7: forbid, uninstall and hold of an application never bring its remote.
		"forbid flatpak_ref without source": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			s.Packages[1].Intent, s.Packages[1].Source, s.Sources = SoftwareForbid, "", s.Sources[:1]
		}, true},
		"uninstall flatpak_ref without source": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", SoftwareScopeUser)
			s.Packages[1].Intent, s.Packages[1].Source, s.Sources = SoftwareUninstall, "", s.Sources[:1]
		}, true},
		"hold flatpak_ref without source": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			s.Packages[1].Intent, s.Packages[1].Source, s.Sources = SoftwareHold, "", s.Sources[:1]
		}, true},
		"forbid flatpak_ref from apt source": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			s.Packages[1].Intent, s.Packages[1].Source = SoftwareForbid, "vendor"
		}, false},
		"apt package from flatpak source": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			s.Packages[0].Source, s.Packages[0].Version = "flathub", nil
		}, false},
		"apt package with scope": {func(s *SoftwareSpec) { s.Packages[1].Scope = SoftwareScopeSystem }, false},
		"flatpak source two uris": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			s.Sources[1].URIs = append(s.Sources[1].URIs, "https://b.example/")
		}, false},
		"flatpak source suites": {func(s *SoftwareSpec) { flatpak(s, "org.gimp.GIMP", ""); s.Sources[1].Suites = []string{"stable"} }, false},
		"flatpak source no key": {func(s *SoftwareSpec) { flatpak(s, "org.gimp.GIMP", ""); s.Sources[1].Keyring = "" }, false},
		"unknown source kind":   {func(s *SoftwareSpec) { s.Sources[0].Kind = "snap" }, false},
		"runtime nil entry id": {func(s *SoftwareSpec) {
			s.Packages[1].Package, s.Packages[1].CatalogEntryID = "flatpak", SoftwareRuntimeEntryID
		}, true},
		"duplicate flatpak_ref": {func(s *SoftwareSpec) {
			flatpak(s, "org.gimp.GIMP", "")
			s.Packages = append(s.Packages, s.Packages[1])
		}, false},
		// Plan M13c decision 9: approval of an available package and its approved users.
		"available requires approval": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Approval = SoftwareApprovalRequired
		}, true},
		"available approved users": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{Users: audienceOf(3)})
			s.Packages[1].Approval, s.Packages[1].Approved = SoftwareApprovalRequired, &[]string{audienceOf(3)[0], audienceOf(3)[2]}
		}, true},
		"available 200 approved": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			approved := audienceOf(MaxSoftwareAudience)
			s.Packages[1].Approval, s.Packages[1].Approved = SoftwareApprovalRequired, &approved
		}, true},
		"available 201 approved": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			approved := audienceOf(MaxSoftwareAudience + 1)
			s.Packages[1].Approval, s.Packages[1].Approved = SoftwareApprovalRequired, &approved
		}, false},
		"approval unknown value": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Approval = "none"
		}, false},
		"required with approval": {func(s *SoftwareSpec) { s.Packages[1].Approval = SoftwareApprovalRequired }, false},
		"approved without approval": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Approved = &[]string{"alice@example.org"}
		}, false},
		"approved empty": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Approval, s.Packages[1].Approved = SoftwareApprovalRequired, &[]string{}
		}, false},
		"approved unsorted": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Approval, s.Packages[1].Approved = SoftwareApprovalRequired, &[]string{"bob@example.org", "alice@example.org"}
		}, false},
		"approved upper-case": {func(s *SoftwareSpec) {
			available(s, &SoftwareAudience{All: true})
			s.Packages[1].Approval, s.Packages[1].Approved = SoftwareApprovalRequired, &[]string{"Alice@example.org"}
		}, false},
		// Architect decision A10-11: the targeted users of a user-scope application, with the limits of an audience.
		"flatpak user required for users": {func(s *SoftwareSpec) { targeted(s, SoftwareRequired, "alice@example.org", "bob@example.org") }, true},
		"flatpak user forbid for users":   {func(s *SoftwareSpec) { targeted(s, SoftwareForbid, "alice@example.org") }, true},
		"flatpak user uninstall for users": {func(s *SoftwareSpec) {
			targeted(s, SoftwareUninstall, "alice@example.org")
			s.Packages[1].Source, s.Sources = "", s.Sources[:1]
		}, true},
		"flatpak user required without users": {func(s *SoftwareSpec) { targeted(s, SoftwareRequired) }, true},
		"flatpak user empty users": {func(s *SoftwareSpec) {
			targeted(s, SoftwareRequired)
			s.Packages[1].Users = &[]string{}
		}, false},
		"flatpak user 200 users": {func(s *SoftwareSpec) { targeted(s, SoftwareRequired, audienceOf(MaxSoftwareAudience)...) }, true},
		"flatpak user 201 users": {func(s *SoftwareSpec) { targeted(s, SoftwareRequired, audienceOf(MaxSoftwareAudience+1)...) }, false},
		"flatpak user unsorted users": {func(s *SoftwareSpec) {
			targeted(s, SoftwareRequired, "bob@example.org", "alice@example.org")
		}, false},
		"flatpak user duplicate users": {func(s *SoftwareSpec) {
			targeted(s, SoftwareRequired, "alice@example.org", "alice@example.org")
		}, false},
		"flatpak user upper-case user": {func(s *SoftwareSpec) { targeted(s, SoftwareRequired, "Alice@example.org") }, false},
		"flatpak user user with space": {func(s *SoftwareSpec) { targeted(s, SoftwareRequired, "a b@example.org") }, false},
		"flatpak user 256 character user": {func(s *SoftwareSpec) {
			targeted(s, SoftwareRequired, strings.Repeat("ä", 244)+"@example.org")
		}, true},
		"flatpak user 257 character user": {func(s *SoftwareSpec) {
			targeted(s, SoftwareRequired, strings.Repeat("a", 245)+"@example.org")
		}, false},
		"flatpak system with users": {func(s *SoftwareSpec) {
			targeted(s, SoftwareRequired, "alice@example.org")
			s.Packages[1].Scope = SoftwareScopeSystem
		}, false},
		"flatpak user hold with users": {func(s *SoftwareSpec) {
			targeted(s, SoftwareHold, "alice@example.org")
			s.Packages[1].Source, s.Sources = "", s.Sources[:1]
		}, false},
		"flatpak user available with users": {func(s *SoftwareSpec) {
			targeted(s, SoftwareAvailable, "alice@example.org")
			s.Packages[1].Audience = &SoftwareAudience{All: true}
		}, false},
		"apt package with users": {func(s *SoftwareSpec) { s.Packages[1].Users = &[]string{"alice@example.org"} }, false},
	}
	for name, tc := range cases {
		s := validSoftware()
		tc.change(&s)
		if err := ValidateSoftware(s); (err == nil) != tc.ok {
			t.Errorf("%s: ValidateSoftware = %v, want ok %v", name, err, tc.ok)
		}
	}
}

func TestSoftwareResource(t *testing.T) {
	r, err := SoftwareResource(SoftwareSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "software" || r.Type != TypeSoftware || string(r.Spec) != `{"sources":[],"packages":[]}` {
		t.Errorf("resource %s/%s spec %s", r.ID, r.Type, r.Spec)
	}
	a := sample(t)
	b := a
	s := validSoftware()
	b.Software = &s
	ha, _ := ContentSHA256(a)
	hb, err := ContentSHA256(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Error("the software section is not part of the content hash")
	}
	enc, err := Encode(b)
	if err != nil || strings.Contains(string(enc), `superseded_hold`) {
		t.Errorf("superseded_hold must be absent unless set: %s (%v)", enc, err)
	}
	s.Packages[1].Intent, s.Packages[1].SupersededHold = SoftwareForbid, true
	if enc, err = Encode(b); err != nil || !strings.Contains(string(enc), `"superseded_hold":true`) {
		t.Errorf("superseded_hold not encoded: %s (%v)", enc, err)
	}
	enc, err = Encode(a)
	if err != nil || strings.Contains(string(enc), `"software"`) {
		t.Errorf("a bundle without software must carry no software section: %s (%v)", enc, err)
	}
}

// TestSoftwareAudienceContentHash (plan M13b decision 7): the new fields are additive — absent from a section that does
// not use them, so its payload is unchanged for every agent — and part of the content hash, so a changed audience is a
// new bundle version.
func TestSoftwareAudienceContentHash(t *testing.T) {
	a := sample(t)
	s := validSoftware()
	a.Software = &s
	enc, err := Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"kind"`, `"flatpak_ref"`, `"scope"`, `"audience"`, `"users"`, `"approval"`, `"approved"`} {
		if strings.Contains(string(enc), field) {
			t.Errorf("%s encoded although unset: %s", field, enc)
		}
	}
	hash := func(audience *SoftwareAudience) [32]byte {
		t.Helper()
		b := a
		sp := validSoftware()
		available(&sp, audience)
		if err := ValidateSoftware(sp); err != nil {
			t.Fatal(err)
		}
		b.Software = &sp
		h, err := ContentSHA256(b)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	alice := hash(&SoftwareAudience{Users: []string{"alice@example.org"}})
	if alice == hash(&SoftwareAudience{Users: []string{"alice@example.org", "bob@example.org"}}) {
		t.Error("a changed audience keeps the content hash")
	}
	if alice == hash(&SoftwareAudience{All: true}) {
		t.Error("an audience of everyone has the hash of one user")
	}
	if alice != hash(&SoftwareAudience{Users: []string{"alice@example.org"}}) {
		t.Error("the same audience hashes differently")
	}
}

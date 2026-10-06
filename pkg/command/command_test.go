package command

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/dsse"
)

const (
	device = "0190f000-0000-7000-8000-000000000001"
	org    = "0190f000-0000-7000-8000-0000000000aa"
)

var issued = time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)

func key(t *testing.T) (ed25519.PrivateKey, Trust) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := TrustFromKeys([]bundle.SigningKey{{KeyID: "command-signing:v1", PublicKey: base64.StdEncoding.EncodeToString(pub)}})
	if err != nil {
		t.Fatal(err)
	}
	return priv, trust
}

func sample() Command {
	return Command{CommandID: "0190f000-0000-7000-8000-0000000000c1", DeviceID: device, OrganizationID: org,
		Type: TypeRotateAdminPassword, IssuedAt: issued, ExpiresAt: issued.Add(7 * 24 * time.Hour)}
}

func sign(t *testing.T, priv ed25519.PrivateKey, payloadType string, payload []byte) []byte {
	t.Helper()
	env, err := dsse.New(payloadType, payload, dsse.SignEd25519(priv, "command-signing:v1", payloadType, payload)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func envelope(t *testing.T, priv ed25519.PrivateKey, c Command) []byte {
	t.Helper()
	payload, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	return sign(t, priv, PayloadType, payload)
}

func TestEncodeIsCanonical(t *testing.T) {
	payload, err := Encode(sample())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"command_id":"0190f000-0000-7000-8000-0000000000c1","device_id":"` + device + `","expires_at":"2026-10-12T08:00:00Z",` +
		`"issued_at":"2026-10-05T08:00:00Z","organization_id":"` + org + `","params":{},"type":"rotate_admin_password"}`
	if string(payload) != want {
		t.Fatalf("payload\n%s\nwant\n%s", payload, want)
	}
}

func TestVerify(t *testing.T) {
	priv, trust := key(t)
	other, _ := key(t)
	good := envelope(t, priv, sample())
	if c, err := Verify(good, trust, device, org, issued.Add(time.Hour)); err != nil || c.Type != TypeRotateAdminPassword {
		t.Fatalf("valid command: %+v %v", c, err)
	}
	withParams := sample()
	withParams.Params = json.RawMessage(`{"a":1}`)
	payload, _ := Encode(withParams)
	unknownField := []byte(`{"command_id":"x","device_id":"` + device + `","organization_id":"` + org + `","type":"t","params":{},` +
		`"issued_at":"2026-10-05T08:00:00Z","expires_at":"2026-10-06T08:00:00Z","extra":1}`)
	tampered := sign(t, priv, PayloadType, payload)
	var env dsse.Envelope
	_ = json.Unmarshal(tampered, &env)
	env.Payload = base64.StdEncoding.EncodeToString([]byte(string(payload[:len(payload)-1]) + ` `))
	tamperedEnv, _ := env.Encode()

	cases := map[string]struct {
		env    []byte
		device string
		now    time.Time
		want   error
	}{
		"other key":           {envelope(t, other, sample()), device, issued, ErrSignature},
		"tampered payload":    {tamperedEnv, device, issued, ErrSignature},
		"not an envelope":     {[]byte(`{}`), device, issued, ErrSignature},
		"bundle payload type": {sign(t, priv, bundle.PayloadType, payload), device, issued, ErrMalformed},
		"unknown field":       {sign(t, priv, PayloadType, unknownField), device, issued, ErrMalformed},
		"other device":        {good, "0190f000-0000-7000-8000-000000000002", issued, ErrWrongDevice},
		"expired":             {good, device, issued.Add(7*24*time.Hour + ClockTolerance), ErrExpired},
		"issued in future":    {good, device, issued.Add(-ClockTolerance - time.Second), ErrNotYetValid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(c.env, trust, c.device, org, c.now); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	// Within the clock tolerance on both ends.
	for _, now := range []time.Time{issued.Add(-ClockTolerance + time.Second), issued.Add(7*24*time.Hour + ClockTolerance - time.Second)} {
		if _, err := Verify(good, trust, device, org, now); err != nil {
			t.Fatalf("at %s: %v", now, err)
		}
	}
}

func TestLifetime(t *testing.T) {
	if d, ok := Lifetime(TypeRotateAdminPassword); !ok || d != 7*24*time.Hour {
		t.Fatalf("rotate_admin_password: %v %v", d, ok)
	}
	if _, ok := Lifetime("install_now"); ok {
		t.Fatal("install_now is not a type of this release")
	}
}

func TestTrustFromKeys(t *testing.T) {
	if _, err := TrustFromKeys(nil); err == nil {
		t.Fatal("no keys accepted")
	}
	if _, err := TrustFromKeys([]bundle.SigningKey{{KeyID: "k", PublicKey: "AAAA"}}); err == nil {
		t.Fatal("short key accepted")
	}
}

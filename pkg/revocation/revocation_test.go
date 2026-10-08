package revocation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/command"
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
	trust, err := TrustFromKeys([]Key{{KeyID: "revocation-signing:v1", PublicKey: base64.StdEncoding.EncodeToString(pub)}})
	if err != nil {
		t.Fatal(err)
	}
	return priv, trust
}

func sample() Token {
	return Token{CommandID: "0190f000-0000-7000-8000-0000000000c1", DeviceID: device, OrganizationID: org,
		Action: ActionLock, IssuedAt: issued, ExpiresAt: issued.Add(Lifetime), RequestID: "0190f000-0000-7000-8000-0000000000r1"}
}

func sign(t *testing.T, priv ed25519.PrivateKey, payloadType string, payload []byte) []byte {
	t.Helper()
	env, err := dsse.New(payloadType, payload, dsse.SignEd25519(priv, "revocation-signing:v1", payloadType, payload)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func envelope(t *testing.T, priv ed25519.PrivateKey, tok Token) []byte {
	t.Helper()
	payload, err := Encode(tok)
	if err != nil {
		t.Fatal(err)
	}
	return sign(t, priv, PayloadType, payload)
}

// Volume UUIDs of the tokens, in ascending order.
const (
	volA = "1b6a3c1e-0000-4000-8000-00000000000a"
	volB = "1b6a3c1e-0000-4000-8000-00000000000b"
)

// manyVolumes returns n distinct volume UUIDs in ascending order.
func manyVolumes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("1b6a3c1e-0000-4000-8000-%012d", i)
	}
	return out
}

// TestEncodeVolumes (PDK-009): a token without volumes encodes as before, so paddock-revoke builds that do not know
// the field still accept it; volumes are encoded as given.
func TestEncodeVolumes(t *testing.T) {
	tok := sample()
	tok.Volumes = []string{volA}
	payload, err := Encode(tok)
	if err != nil || !strings.Contains(string(payload), `"volumes":["`+volA+`"]`) {
		t.Fatalf("payload %s %v", payload, err)
	}
}

func TestEncodeIsCanonical(t *testing.T) {
	payload, err := Encode(sample())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"action":"lock","command_id":"0190f000-0000-7000-8000-0000000000c1","device_id":"` + device +
		`","expires_at":"2026-11-04T08:00:00Z","issued_at":"2026-10-05T08:00:00Z","organization_id":"` + org +
		`","request_id":"0190f000-0000-7000-8000-0000000000r1"}`
	if string(payload) != want {
		t.Fatalf("payload\n%s\nwant\n%s", payload, want)
	}
}

func TestVerify(t *testing.T) {
	priv, trust := key(t)
	other, _ := key(t)
	good := envelope(t, priv, sample())
	if tok, err := Verify(good, trust, device, issued.Add(time.Hour)); err != nil || tok.Action != ActionLock {
		t.Fatalf("valid token: %+v %v", tok, err)
	}
	selfLock := sample()
	selfLock.Action, selfLock.PeriodDays, selfLock.Volumes = ActionSelfLock, 30, []string{volA, volB}
	if tok, err := Verify(envelope(t, priv, selfLock), trust, device, issued); err != nil || tok.PeriodDays != 30 ||
		!slices.Equal(tok.Volumes, []string{volA, volB}) {
		t.Fatalf("self_lock token: %+v %v", tok, err)
	}
	lock := sample()
	lock.Volumes = manyVolumes(MaxVolumes)
	if tok, err := Verify(envelope(t, priv, lock), trust, device, issued); err != nil || len(tok.Volumes) != MaxVolumes {
		t.Fatalf("lock token with volumes: %+v %v", tok, err)
	}

	payload, _ := Encode(sample())
	var env dsse.Envelope
	_ = json.Unmarshal(sign(t, priv, PayloadType, payload), &env)
	env.Payload = base64.StdEncoding.EncodeToString(append(payload[:len(payload)-1:len(payload)-1], []byte(` }`)...))
	tampered, _ := env.Encode()
	unknownField := []byte(`{"action":"lock","command_id":"x","device_id":"` + device + `","organization_id":"` + org +
		`","request_id":"r","issued_at":"2026-10-05T08:00:00Z","expires_at":"2026-10-06T08:00:00Z","extra":1}`)
	invalid := func(change func(*Token)) []byte {
		tok := sample()
		change(&tok)
		return envelope(t, priv, tok)
	}

	cases := map[string]struct {
		env  []byte
		now  time.Time
		want error
	}{
		"other key":                 {envelope(t, other, sample()), issued, ErrSignature},
		"tampered payload":          {tampered, issued, ErrSignature},
		"not an envelope":           {[]byte(`{}`), issued, ErrSignature},
		"command payload type":      {sign(t, priv, command.PayloadType, payload), issued, ErrMalformed},
		"unknown field":             {sign(t, priv, PayloadType, unknownField), issued, ErrMalformed},
		"unknown action":            {invalid(func(t *Token) { t.Action = "wipe" }), issued, ErrMalformed},
		"self_lock without period":  {invalid(func(t *Token) { t.Action = ActionSelfLock }), issued, ErrMalformed},
		"lock with period":          {invalid(func(t *Token) { t.PeriodDays = 1 }), issued, ErrMalformed},
		"destroy with volumes":      {invalid(func(t *Token) { t.Action, t.Volumes = ActionDestroy, []string{volA} }), issued, ErrMalformed},
		"volume not a uuid":         {invalid(func(t *Token) { t.Volumes = []string{"/dev/sdb1"} }), issued, ErrMalformed},
		"volume upper case":         {invalid(func(t *Token) { t.Volumes = []string{strings.ToUpper(volA)} }), issued, ErrMalformed},
		"volumes unsorted":          {invalid(func(t *Token) { t.Volumes = []string{volB, volA} }), issued, ErrMalformed},
		"volumes duplicated":        {invalid(func(t *Token) { t.Volumes = []string{volA, volA} }), issued, ErrMalformed},
		"too many volumes":          {invalid(func(t *Token) { t.Volumes = manyVolumes(MaxVolumes + 1) }), issued, ErrMalformed},
		"missing request":           {invalid(func(t *Token) { t.RequestID = "" }), issued, ErrMalformed},
		"other device":              {invalid(func(t *Token) { t.DeviceID = "0190f000-0000-7000-8000-000000000002" }), issued, ErrWrongDevice},
		"expired":                   {good, issued.Add(Lifetime), ErrExpired},
		"issued in the future":      {good, issued.Add(-ClockTolerance - time.Second), ErrNotYetValid},
		"larger than the max. size": {make([]byte, MaxEnvelopeSize+1), issued, ErrMalformed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(c.env, trust, device, c.now); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	if _, err := Verify(good, trust, device, issued.Add(Lifetime-time.Second)); err != nil {
		t.Fatalf("a second before expiry: %v", err)
	}
}

func TestParseTrust(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := json.Marshal(TrustFile{RevocationKeys: []Key{{KeyID: "revocation-signing:v1", PublicKey: base64.StdEncoding.EncodeToString(pub)}}})
	if tr, err := ParseTrust(good); err != nil || len(tr.Keys) != 1 {
		t.Fatalf("valid trust file: %v %v", tr, err)
	}
	for name, data := range map[string]string{
		"empty":     `{"revocation_keys":[]}`,
		"short key": `{"revocation_keys":[{"key_id":"k","public_key":"AAAA"}]}`,
		"no key id": `{"revocation_keys":[{"key_id":"","public_key":"` + base64.StdEncoding.EncodeToString(pub) + `"}]}`,
		"not json":  `revocation`,
	} {
		if _, err := ParseTrust([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIsRevocation(t *testing.T) {
	priv, _ := key(t)
	if !IsRevocation(envelope(t, priv, sample())) {
		t.Fatal("revocation envelope not recognised")
	}
	if IsRevocation(sign(t, priv, command.PayloadType, []byte(`{}`))) || IsRevocation([]byte(`not json`)) {
		t.Fatal("other envelope recognised")
	}
}

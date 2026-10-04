package dsse

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The PAE vector of the DSSE specification (protocol.md).
func TestPAEVector(t *testing.T) {
	got := PAE("http://example.com/HelloWorld", []byte("hello world"))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := PAE("", nil); string(got) != "DSSEv1 0  0 " {
		t.Fatalf("empty PAE: %q", got)
	}
}

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

// Ed25519 is deterministic, so the envelope of a fixed key and payload is a stable vector.
func TestSignGolden(t *testing.T) {
	key := testKey(1)
	sig := SignEd25519(key, "k1", "application/example", []byte(`{"a":1}`))
	env := New("application/example", []byte(`{"a":1}`), sig)
	b, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"payloadType":"application/example","payload":"eyJhIjoxfQ==","signatures":[{"keyid":"k1","sig":"` + sig.Sig + `"}]}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	if sig.Sig != base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(`DSSEv1 19 application/example 7 {"a":1}`))) {
		t.Fatal("signature is not over the PAE")
	}
}

func TestRoundTripAndTamper(t *testing.T) {
	key := testKey(2)
	other := testKey(3)
	payload := []byte(`{"hello":"world"}`)
	env := New("t/v1", payload, SignEd25519(key, "k", "t/v1", payload))
	raw, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{"k": key.Public().(ed25519.PublicKey)}

	dec, got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload %s", got)
	}
	if id, err := dec.VerifyEd25519(got, trusted); err != nil || id != "k" {
		t.Fatalf("verify: %q %v", id, err)
	}

	cases := map[string]func(e *Envelope) []byte{
		"payload changed": func(*Envelope) []byte { return []byte(`{"hello":"mars"}`) },
		"type changed": func(e *Envelope) []byte {
			e.PayloadType = "t/v2"
			return payload
		},
		"unknown key id": func(e *Envelope) []byte {
			e.Signatures[0].KeyID = "other"
			return payload
		},
		"signed by other key": func(e *Envelope) []byte {
			e.Signatures[0] = SignEd25519(other, "k", "t/v1", payload)
			return payload
		},
		"garbage signature": func(e *Envelope) []byte {
			e.Signatures[0].Sig = "!!!"
			return payload
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := dec
			e.Signatures = append([]Signature(nil), dec.Signatures...)
			p := mutate(&e)
			if _, err := e.VerifyEd25519(p, trusted); !errors.Is(err, ErrNoValidSignature) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAnyTrustedSignatureSuffices(t *testing.T) {
	a, b := testKey(4), testKey(5)
	payload := []byte("x")
	env := New("t", payload, SignEd25519(a, "a", "t", payload), SignEd25519(b, "b", "t", payload))
	id, err := env.VerifyEd25519(payload, map[string]ed25519.PublicKey{"b": b.Public().(ed25519.PublicKey)})
	if err != nil || id != "b" {
		t.Fatalf("got %q %v", id, err)
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, in := range []string{
		``, `[]`, `{}`, `{"payloadType":"t","payload":"eA==","signatures":[]}`,
		`{"payloadType":"t","payload":"%%%","signatures":[{"keyid":"k","sig":"eA=="}]}`,
		`{"payloadType":"","payload":"eA==","signatures":[{"keyid":"k","sig":"eA=="}]}`,
	} {
		if _, _, err := Decode([]byte(in)); !errors.Is(err, ErrMalformed) {
			t.Errorf("Decode(%q) = %v", in, err)
		}
	}
	big := `{"payload":"` + strings.Repeat("A", MaxEnvelopeSize) + `"}`
	if _, _, err := Decode([]byte(big)); !errors.Is(err, ErrMalformed) {
		t.Errorf("oversized envelope accepted: %v", err)
	}
}

func TestDecodeAcceptsURLSafeBase64(t *testing.T) {
	key := testKey(6)
	payload := []byte{0xfb, 0xff, 0xfe}
	sig := SignEd25519(key, "k", "t", payload)
	raw := `{"payloadType":"t","payload":"` + base64.URLEncoding.EncodeToString(payload) + `","signatures":[{"keyid":"k","sig":"` + sig.Sig + `"}]}`
	e, got, err := Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.VerifyEd25519(got, map[string]ed25519.PublicKey{"k": key.Public().(ed25519.PublicKey)}); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecode(f *testing.F) {
	key := testKey(7)
	payload := []byte(`{"a":1}`)
	good, _ := New("t", payload, SignEd25519(key, "k", "t", payload)).Encode()
	f.Add(good)
	f.Add([]byte(`{"payloadType":"t","payload":"","signatures":[{"keyid":"","sig":""}]}`))
	f.Add([]byte(`null`))
	trusted := map[string]ed25519.PublicKey{"k": key.Public().(ed25519.PublicKey)}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, p, err := Decode(b)
		if err != nil {
			return
		}
		if id, err := e.VerifyEd25519(p, trusted); err == nil {
			// Only the genuine payload and type can carry a valid signature of the test key.
			if id != "k" || e.PayloadType != "t" || !bytes.Equal(p, payload) {
				t.Fatalf("forged envelope verified: %s", b)
			}
		}
	})
}

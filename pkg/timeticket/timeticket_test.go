package timeticket

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/dsse"
)

const org = "0190f000-0000-7000-8000-0000000000aa"

func sign(t *testing.T, key ed25519.PrivateKey, payloadType string, tk Ticket) []byte {
	t.Helper()
	payload, err := Encode(tk)
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.New(payloadType, payload, dsse.SignEd25519(key, "time-ticket:v1", payloadType, payload)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"time-ticket:v1": pub}
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	got, err := Verify(sign(t, priv, PayloadType, Ticket{OrganizationID: org, IssuedAt: at}), keys, org)
	if err != nil || !got.IssuedAt.Equal(at) {
		t.Fatalf("valid ticket: %+v %v", got, err)
	}
	for name, env := range map[string][]byte{
		"other key":          sign(t, other, PayloadType, Ticket{OrganizationID: org, IssuedAt: at}),
		"other organization": sign(t, priv, PayloadType, Ticket{OrganizationID: "x", IssuedAt: at}),
		"other payload type": sign(t, priv, "application/vnd.paddock.command.v1+json", Ticket{OrganizationID: org, IssuedAt: at}),
		"no time":            sign(t, priv, PayloadType, Ticket{OrganizationID: org}),
		"garbage":            []byte("{}"),
	} {
		if _, err := Verify(env, keys, org); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

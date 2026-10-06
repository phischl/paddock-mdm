package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/revocation"
)

// revocationKey is a revocation-signing key "revocation-signing:v<seed>" derived from seed.
func revocationKey(seed byte) bundle.SigningKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	return bundle.SigningKey{KeyID: "revocation-signing:v" + string('0'+seed),
		PublicKey: base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey))}
}

func pinnedKeys(t *testing.T, a *Agent) map[string]ed25519.PublicKey {
	t.Helper()
	data, err := os.ReadFile(a.d.Layout.RevokeTrust())
	if err != nil {
		t.Fatalf("revoke-trust.json: %v", err)
	}
	tr, err := revocation.ParseTrust(data)
	if err != nil {
		t.Fatal(err)
	}
	return tr.Keys
}

// TestRevocationSection (plan M4c decisions 1 and 3): the marker follows revocation.enabled, also against local
// changes; a device enrolled before M4c pins the bundle's keys once and reports it; a pinned anchor is never
// replaced from a bundle.
func TestRevocationSection(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	withSystem(t, a)
	marker := a.d.Layout.RevokeEnabled()

	b := testBundle(t, 1, testgw.DeviceID, "x\n")
	b.Revocation = &bundle.Revocation{Enabled: true, Keys: []bundle.SigningKey{revocationKey(1)}}
	g.OfferBundle(testgw.SignedBundleOffer(t, b))
	a.Cycle(ctx)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker: %v", err)
	}
	if keys := pinnedKeys(t, a); len(keys) != 1 || keys["revocation-signing:v1"] == nil {
		t.Fatalf("pinned %v", keys)
	}
	if ev := eventsOf(g, protocol.EventRevocationTrustPinnedTOFU); len(ev) != 1 || string(ev[0].Data) != `{"file":"/etc/paddock/revoke-trust.json"}` {
		t.Fatalf("tofu events %+v", ev)
	}

	// A local removal of the marker is reverted by the drift pass.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	a.drift(ctx)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker after drift: %v", err)
	}

	// Other keys in a later bundle never replace the pinned anchor; the flag off removes the marker.
	b = testBundle(t, 2, testgw.DeviceID, "x\n")
	b.Revocation = &bundle.Revocation{Enabled: false, Keys: []bundle.SigningKey{revocationKey(2)}}
	g.OfferBundle(testgw.SignedBundleOffer(t, b))
	a.Cycle(ctx)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker with the flag off: %v", err)
	}
	if keys := pinnedKeys(t, a); len(keys) != 1 || keys["revocation-signing:v1"] == nil {
		t.Fatalf("pinned anchor replaced: %v", keys)
	}
	if ev := eventsOf(g, protocol.EventRevocationTrustPinnedTOFU); len(ev) != 1 {
		t.Fatalf("tofu reported again: %+v", ev)
	}

	// A locally created marker goes as well; a bundle without the section means disabled.
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	a.drift(ctx)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("local marker kept: %v", err)
	}
}

// TestRevocationAnchorFromEnrollment: a device enrolled with revocation keys never pins bundle keys and reports
// nothing.
func TestRevocationAnchorFromEnrollment(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	withSystem(t, a)
	if err := config.SaveRevokeTrust(a.d.Layout.RevokeTrust(), g.EnrollmentConfig().RevocationKeys); err != nil {
		t.Fatal(err)
	}
	b := testBundle(t, 1, testgw.DeviceID, "x\n")
	b.Revocation = &bundle.Revocation{Enabled: true, Keys: []bundle.SigningKey{revocationKey(3)}}
	g.OfferBundle(testgw.SignedBundleOffer(t, b))
	a.Cycle(ctx)
	keys := pinnedKeys(t, a)
	want := testgw.RevocationKey.Public().(ed25519.PublicKey)
	if len(keys) != 1 || !keys["revocation-signing:v1"].Equal(want) {
		t.Fatalf("pinned %v", keys)
	}
	if ev := eventsOf(g, protocol.EventRevocationTrustPinnedTOFU); len(ev) != 0 {
		t.Fatalf("tofu events %+v", ev)
	}
}

// revocationEnvelope is a DSSE envelope with the revocation payload type; paddockd never looks inside.
func revocationEnvelope(t *testing.T, payload string) json.RawMessage {
	t.Helper()
	env, err := dsse.New(revocation.PayloadType, []byte(payload), dsse.Signature{KeyID: "revocation-signing:v1", Sig: "c2ln"}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestRevocationHandoff (plan M4c decision 11): paddockd hands every revocation envelope to paddock-revoke exactly
// once, without verifying it, keeps it away from the command executor and reports a refusal.
func TestRevocationHandoff(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	var handed [][]byte
	refuse := "rate_limited"
	a.d.Revoke = func(_ context.Context, env []byte) (string, error) {
		handed = append(handed, env)
		return refuse, nil
	}
	a.d.Commands = commands.New(map[string]commands.Handler{}, time.Now)
	a.current = &bundle.Bundle{Keys: testgw.CommandKeys()}
	first, second := revocationEnvelope(t, `{"a":1}`), revocationEnvelope(t, `{"a":2}`)
	g.Mu.Lock()
	g.Checkin.Commands = []json.RawMessage{first}
	g.Mu.Unlock()
	a.Cycle(context.Background())
	a.Cycle(context.Background())
	if len(handed) != 1 || string(handed[0]) != string(first) {
		t.Fatalf("handed %d envelopes", len(handed))
	}
	if ev := eventsOf(g, protocol.EventRevocationRefused); len(ev) != 1 || string(ev[0].Data) != `{"reason":"rate_limited"}` {
		t.Fatalf("refused events %+v", ev)
	}
	if st, _ := state.Load(a.d.Layout.State()); len(st.HandedRevocations) != 1 || len(st.ExecutedCommands) != 0 || len(st.CommandResults) != 0 {
		t.Fatalf("state %+v", st)
	}

	// An executed token reports nothing; a missing paddock-revoke is reported as not_installed.
	refuse = ""
	g.Mu.Lock()
	g.Checkin.Commands = []json.RawMessage{first, second}
	g.Mu.Unlock()
	a.Cycle(context.Background())
	if len(handed) != 2 || len(eventsOf(g, protocol.EventRevocationRefused)) != 1 {
		t.Fatalf("handed %d, events %+v", len(handed), eventsOf(g, protocol.EventRevocationRefused))
	}
	if refused, err := runRevoke(context.Background(), a.d.Layout.RevokeBinary(), first); refused != "" || revokeReason(err) != "not_installed" {
		t.Fatalf("missing paddock-revoke: %q %v", refused, err)
	}
}

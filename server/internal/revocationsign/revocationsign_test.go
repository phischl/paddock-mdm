package revocationsign_test

import (
	"context"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/revocation"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/revocationsign"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/baotest"
)

func client(t *testing.T, b *baotest.Bao, role string) *bao.Client {
	t.Helper()
	r := b.AppRole(t, role)
	c, err := bao.New(b.Addr, r.RoleID, r.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestOnlyTheIssuerSigns: a token signed through OpenBao with the issuer's AppRole verifies with the public keys the
// api and the compiler read; no other role can sign with revocation-signing (plan M4c decision 2).
func TestOnlyTheIssuerSigns(t *testing.T) {
	b := baotest.Start(t)
	ctx := context.Background()
	issuer := client(t, b, "paddock-revocation-issuer")
	keys, err := revocationsign.PublicKeys(ctx, client(t, b, "paddock-api"))
	if err != nil || len(keys) != 1 || keys[0].KeyID != "revocation-signing:v1" {
		t.Fatalf("public keys %+v %v", keys, err)
	}
	if _, err := revocationsign.PublicKeys(ctx, client(t, b, "paddock-compiler")); err != nil {
		t.Fatalf("the compiler cannot read the public keys: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tok := revocation.Token{CommandID: "0190f000-0000-7000-8000-0000000000c1", DeviceID: "0190f000-0000-7000-8000-000000000001",
		OrganizationID: "0190f000-0000-7000-8000-0000000000aa", Action: revocation.ActionLock, IssuedAt: now,
		ExpiresAt: now.Add(revocation.Lifetime), RequestID: "0190f000-0000-7000-8000-0000000000d1"}
	env, err := revocationsign.Sign(ctx, issuer, tok)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := revocation.TrustFromKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := revocation.Verify(env, trust, tok.DeviceID, now); err != nil || got.CommandID != tok.CommandID {
		t.Fatalf("verify: %+v %v", got, err)
	}
	for _, role := range []string{"paddock-api", "paddock-compiler", "paddock-worker", "paddock-escrow-reader", "paddock-audit-writer"} {
		if _, err := revocationsign.Sign(ctx, client(t, b, role), tok); err == nil {
			t.Errorf("%s can sign revocations", role)
		}
	}
}

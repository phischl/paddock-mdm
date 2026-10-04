package bao_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/paddock-mdm/paddock/server/internal/platform/bao"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/baotest"
)

// TestBundleSigning checks the M2a stop condition: OpenBao batch-signs with an Ed25519 Transit key, the compiler
// AppRole may sign and read the public key, the api AppRole may only read it.
func TestBundleSigning(t *testing.T) {
	b := baotest.Start(t)
	ctx := context.Background()
	role := b.AppRole(t, "paddock-compiler")
	compiler, err := bao.New(b.Addr, role.RoleID, role.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	msgs := make([][]byte, 1003) // more than one batch
	for i := range msgs {
		msgs[i] = []byte(fmt.Sprintf("DSSEv1 4 test %d payload-%d", len(fmt.Sprint(i))+8, i))
	}
	sigs, err := compiler.SignBatch(ctx, "bundle-signing", msgs)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := compiler.PublicKeys(ctx, "bundle-signing")
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != len(msgs) {
		t.Fatalf("%d signatures for %d messages", len(sigs), len(msgs))
	}
	for i, s := range sigs {
		pub := ed25519.PublicKey(keys[s.KeyVersion])
		if s.KeyVersion != 1 || !ed25519.Verify(pub, msgs[i], s.Value) {
			t.Fatalf("signature %d does not verify (key version %d)", i, s.KeyVersion)
		}
	}

	apiRole := b.AppRole(t, "paddock-api")
	api, err := bao.New(b.Addr, apiRole.RoleID, apiRole.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.PublicKeys(ctx, "bundle-signing"); err != nil {
		t.Fatalf("api cannot read the public key: %v", err)
	}
	if _, err := api.SignBatch(ctx, "bundle-signing", msgs[:1]); err == nil {
		t.Fatal("api may sign bundles")
	}
}

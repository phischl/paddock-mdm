package bao_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/baotest"
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

// TestEscrowWrap checks the M4a stop condition S1 (plan M4a decision 10): a secret encrypted on a device with Go's
// RSA-OAEP and SHA-256 to the escrow-wrap public key the compiler reads is decrypted by OpenBao Transit with the
// escrow-reader AppRole; the compiler may not decrypt and the escrow reader may not read the key.
func TestEscrowWrap(t *testing.T) {
	b := baotest.Start(t)
	ctx := context.Background()
	compilerRole := b.AppRole(t, "paddock-compiler")
	compiler, err := bao.New(b.Addr, compilerRole.RoleID, compilerRole.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	version, pemKey, err := compiler.LatestPublicKeyPEM(ctx, escrow.KeyName)
	if err != nil || version != 1 {
		t.Fatalf("public key: v%d %v", version, err)
	}
	pub, err := escrow.ParsePublicKey(pemKey)
	if err != nil || pub.N.BitLen() != 4096 {
		t.Fatalf("parse public key: %v", err)
	}
	secret := []byte("Correct-Horse-Battery-Staple-24")
	ct, err := escrow.Encrypt(pub, secret)
	if err != nil {
		t.Fatal(err)
	}
	readerRole := b.AppRole(t, "paddock-escrow-reader")
	reader, err := bao.New(b.Addr, readerRole.RoleID, readerRole.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := reader.Decrypt(ctx, escrow.KeyName, version, ct)
	if err != nil || string(plain) != string(secret) {
		t.Fatalf("decrypt: %q %v", plain, err)
	}
	if _, err := compiler.Decrypt(ctx, escrow.KeyName, version, ct); err == nil {
		t.Fatal("the compiler may decrypt escrowed secrets")
	}
	if _, _, err := reader.LatestPublicKeyPEM(ctx, escrow.KeyName); err == nil {
		t.Fatal("the escrow reader may read the key")
	}
}

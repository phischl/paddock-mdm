package bao_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	openbao "github.com/openbao/openbao/api/v2"

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

// TestNotificationWrap checks ADR 0031 decision 11 and plan M9 decision 12 with the fix-round binding of PDK-122: the
// api AppRole encrypts destination secrets and obtains wrapped pseudonym keys with the derived key notification-wrap,
// never a plaintext key, and cannot decrypt; the notifier AppRole decrypts and cannot encrypt; a ciphertext decrypts
// only under the organization (context) it was made for; no other role decrypts.
func TestNotificationWrap(t *testing.T) {
	b := baotest.Start(t)
	ctx := context.Background()
	client := func(name string) *bao.Client {
		role := b.AppRole(t, name)
		c, err := bao.New(b.Addr, role.RoleID, role.SecretID)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	api, notifier, worker := client("paddock-api"), client("paddock-notifier"), client("paddock-worker")
	orgA := uuid.MustParse("7d0a3c1e-0000-4000-8000-00000000000a")
	orgB := uuid.MustParse("7d0a3c1e-0000-4000-8000-00000000000b")
	secret := []byte("https://hooks.slack.com/services/T0/B0/secret")
	ct, err := api.Encrypt(ctx, "notification-wrap", orgA, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "vault:v1:") || strings.Contains(ct, string(secret)) {
		t.Fatalf("ciphertext %q", ct)
	}
	plain, err := notifier.DecryptContext(ctx, "notification-wrap", orgA, ct)
	if err != nil || string(plain) != string(secret) {
		t.Fatalf("decrypt: %q %v", plain, err)
	}
	if _, err := notifier.DecryptContext(ctx, "notification-wrap", orgB, ct); err == nil {
		t.Fatal("a ciphertext of organization A decrypts under organization B")
	}
	if _, err := api.DecryptContext(ctx, "notification-wrap", orgA, ct); err == nil {
		t.Fatal("the api may decrypt destination secrets")
	}
	if _, err := worker.DecryptContext(ctx, "notification-wrap", orgA, ct); err == nil {
		t.Fatal("the worker may decrypt destination secrets")
	}
	if _, err := notifier.Encrypt(ctx, "notification-wrap", orgA, secret); err == nil {
		t.Fatal("the notifier may encrypt")
	}

	wrapped, err := api.WrappedDataKey(ctx, "notification-wrap", orgA)
	if err != nil {
		t.Fatal(err)
	}
	key, err := notifier.DecryptContext(ctx, "notification-wrap", orgA, wrapped)
	if err != nil || len(key) != 32 {
		t.Fatalf("unwrap pseudonym key: %d bytes, %v", len(key), err)
	}
	if _, err := notifier.DecryptContext(ctx, "notification-wrap", orgB, wrapped); err == nil {
		t.Fatal("a pseudonym key of organization A unwraps under organization B")
	}
	if _, err := notifier.WrappedDataKey(ctx, "notification-wrap", orgA); err == nil {
		t.Fatal("the notifier may create data keys")
	}
	apiRole := b.AppRole(t, "paddock-api")
	raw, err := openbao.NewClient(&openbao.Config{Address: b.Addr})
	if err != nil {
		t.Fatal(err)
	}
	login, err := raw.Logical().Write("auth/approle/login", map[string]any{
		"role_id": apiRole.RoleID, "secret_id": apiRole.SecretID,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw.SetToken(login.Auth.ClientToken)
	if _, err := raw.Logical().Write("transit/datakey/plaintext/notification-wrap", map[string]any{
		"context": bao.OrganizationContext(orgA),
	}); err == nil {
		t.Fatal("the api may obtain a plaintext data key")
	}
}

// TestOrganizationContext: the context is the lowercase canonical organization ID, base64-encoded, whatever form the
// ID was parsed from.
func TestOrganizationContext(t *testing.T) {
	org := uuid.MustParse("{7D0A3C1E-ABCD-4000-8000-00000000000A}")
	raw, err := base64.StdEncoding.DecodeString(bao.OrganizationContext(org))
	if err != nil || string(raw) != "7d0a3c1e-abcd-4000-8000-00000000000a" {
		t.Fatalf("context %q (%v)", raw, err)
	}
	if bao.OrganizationContext(uuid.Nil) != base64.StdEncoding.EncodeToString([]byte(uuid.Nil.String())) {
		t.Fatal("platform context differs from the nil organization ID")
	}
}

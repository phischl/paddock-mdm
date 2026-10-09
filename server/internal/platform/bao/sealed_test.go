package bao_test

import (
	"context"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/baotest"
)

// TestSealed reads the seal status without a token (plan M6a decision 9: paddock_openbao_sealed); an unreachable
// OpenBao is an error, not "unsealed".
func TestSealed(t *testing.T) {
	b := baotest.Start(t)
	ctx := context.Background()
	c, err := bao.New(b.Addr, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if sealed, err := c.Sealed(ctx); err != nil || sealed {
		t.Fatalf("dev OpenBao: sealed=%v err=%v", sealed, err)
	}
	if err := b.Root.Sys().Seal(); err != nil {
		t.Fatal(err)
	}
	if sealed, err := c.Sealed(ctx); err != nil || !sealed {
		t.Fatalf("after seal: sealed=%v err=%v", sealed, err)
	}
	down, err := bao.New("http://127.0.0.1:1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := down.Sealed(ctx); err == nil {
		t.Fatal("an unreachable OpenBao must be an error")
	}
}

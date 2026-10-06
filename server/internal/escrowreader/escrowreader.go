// Package escrowreader is the only decryption path for escrowed secrets (plan M4a decision 9, plan M4b.1 decisions 5
// and 6): the service of the escrow-reader role, which decrypts with the AppRole paddock-escrow-reader only after it
// verified a fresh step-up proof of an organization administrator, and the api's client of that service.
package escrowreader

import (
	"context"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
)

// Reader decrypts escrowed secrets with escrow-wrap.
type Reader struct{ c *bao.Client }

// New creates a reader for the AppRole paddock-escrow-reader.
func New(addr, roleID, secretID string) (*Reader, error) {
	c, err := bao.New(addr, roleID, secretID)
	if err != nil {
		return nil, err
	}
	return &Reader{c: c}, nil
}

// Decrypt returns the plaintext of a ciphertext (standard base64) wrapped with version of escrow-wrap. The caller
// zeroes it after use and never logs it.
func (r *Reader) Decrypt(ctx context.Context, version int, ciphertext string) ([]byte, error) {
	return r.c.Decrypt(ctx, escrow.KeyName, version, ciphertext)
}

// Ping checks that OpenBao is unsealed and the credential works.
func (r *Reader) Ping(ctx context.Context) error { return r.c.Ping(ctx) }

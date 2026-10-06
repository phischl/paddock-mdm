// Package revocationsign names the OpenBao Transit key that signs revocation tokens, signs their envelopes with it
// (AppRole paddock-revocation-issuer only) and turns its public keys into the revocation trust anchor devices pin at
// enrollment (plan M4c decisions 2 and 3).
package revocationsign

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"

	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/revocation"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
)

// KeyName is the Transit key that signs revocation tokens.
const KeyName = "revocation-signing"

// KeyID is the DSSE key ID of a version of the revocation-signing key, e.g. "revocation-signing:v1".
func KeyID(version int) string { return KeyName + ":v" + strconv.Itoa(version) }

// PublicKeyReader reads the public keys of a Transit key by version (bao.Client).
type PublicKeyReader interface {
	PublicKeys(ctx context.Context, key string) (map[int][]byte, error)
}

// PublicKeys returns every version of the revocation-signing public key, oldest first.
func PublicKeys(ctx context.Context, r PublicKeyReader) ([]revocation.Key, error) {
	keys, err := r.PublicKeys(ctx, KeyName)
	if err != nil {
		return nil, fmt.Errorf("revocation-signing public keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("revocation-signing public keys: key %s has no versions", KeyName)
	}
	versions := make([]int, 0, len(keys))
	for v := range keys {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	out := make([]revocation.Key, len(versions))
	for i, v := range versions {
		out[i] = revocation.Key{KeyID: KeyID(v), PublicKey: base64.StdEncoding.EncodeToString(keys[v])}
	}
	return out, nil
}

// Signer signs with a Transit key (bao.Client).
type Signer interface {
	SignBatch(ctx context.Context, key string, messages [][]byte) ([]bao.RawSignature, error)
}

// Sign returns the DSSE envelope of t, signed with the current version of the revocation-signing key.
func Sign(ctx context.Context, s Signer, t revocation.Token) ([]byte, error) {
	payload, err := revocation.Encode(t)
	if err != nil {
		return nil, err
	}
	sigs, err := s.SignBatch(ctx, KeyName, [][]byte{dsse.PAE(revocation.PayloadType, payload)})
	if err != nil {
		return nil, fmt.Errorf("sign revocation %s: %w", t.CommandID, err)
	}
	return dsse.New(revocation.PayloadType, payload, dsse.Signature{
		KeyID: KeyID(sigs[0].KeyVersion), Sig: base64.StdEncoding.EncodeToString(sigs[0].Value),
	}).Encode()
}

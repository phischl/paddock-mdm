// Package bundlesign names the OpenBao Transit key that signs bundles and turns its public keys into the trust
// anchor devices receive in their enrollment configuration (plan M2a decisions 6 and 15).
package bundlesign

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// KeyName is the Transit key that signs bundles.
const KeyName = "bundle-signing"

// KeyID is the DSSE key ID of a version of the bundle-signing key, e.g. "bundle-signing:v1".
func KeyID(version int) string { return KeyName + ":v" + strconv.Itoa(version) }

// PublicKeyReader reads the public keys of a Transit key by version (bao.Client).
type PublicKeyReader interface {
	PublicKeys(ctx context.Context, key string) (map[int][]byte, error)
}

// PublicKeys returns every version of the bundle-signing public key, oldest first.
func PublicKeys(ctx context.Context, r PublicKeyReader) ([]protocol.BundleKey, error) {
	keys, err := r.PublicKeys(ctx, KeyName)
	if err != nil {
		return nil, fmt.Errorf("bundle-signing public keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("bundle-signing public keys: key %s has no versions", KeyName)
	}
	versions := make([]int, 0, len(keys))
	for v := range keys {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	out := make([]protocol.BundleKey, len(versions))
	for i, v := range versions {
		out[i] = protocol.BundleKey{KeyID: KeyID(v), PublicKey: base64.StdEncoding.EncodeToString(keys[v])}
	}
	return out, nil
}

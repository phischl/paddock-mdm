// Package commandsign names the OpenBao Transit key that signs device commands, signs command envelopes with it and
// turns its public keys into the keys.command_signing of bundles (plan M4a decisions 2 and 5).
package commandsign

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/command"
	"github.com/paddock-mdm/paddock/pkg/dsse"
	"github.com/paddock-mdm/paddock/server/internal/platform/bao"
)

// KeyName is the Transit key that signs commands.
const KeyName = "command-signing"

// KeyID is the DSSE key ID of a version of the command-signing key, e.g. "command-signing:v1".
func KeyID(version int) string { return KeyName + ":v" + strconv.Itoa(version) }

// PublicKeyReader reads the public keys of a Transit key by version (bao.Client).
type PublicKeyReader interface {
	PublicKeys(ctx context.Context, key string) (map[int][]byte, error)
}

// PublicKeys returns every version of the command-signing public key, oldest first.
func PublicKeys(ctx context.Context, r PublicKeyReader) ([]bundle.SigningKey, error) {
	keys, err := r.PublicKeys(ctx, KeyName)
	if err != nil {
		return nil, fmt.Errorf("command-signing public keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("command-signing public keys: key %s has no versions", KeyName)
	}
	versions := make([]int, 0, len(keys))
	for v := range keys {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	out := make([]bundle.SigningKey, len(versions))
	for i, v := range versions {
		out[i] = bundle.SigningKey{KeyID: KeyID(v), PublicKey: base64.StdEncoding.EncodeToString(keys[v])}
	}
	return out, nil
}

// Signer signs with a Transit key (bao.Client).
type Signer interface {
	SignBatch(ctx context.Context, key string, messages [][]byte) ([]bao.RawSignature, error)
}

// Sign returns the DSSE envelope of c, signed with the current version of the command-signing key.
func Sign(ctx context.Context, s Signer, c command.Command) ([]byte, error) {
	payload, err := command.Encode(c)
	if err != nil {
		return nil, err
	}
	sigs, err := s.SignBatch(ctx, KeyName, [][]byte{dsse.PAE(command.PayloadType, payload)})
	if err != nil {
		return nil, fmt.Errorf("sign command %s: %w", c.CommandID, err)
	}
	return dsse.New(command.PayloadType, payload, dsse.Signature{
		KeyID: KeyID(sigs[0].KeyVersion), Sig: base64.StdEncoding.EncodeToString(sigs[0].Value),
	}).Encode()
}

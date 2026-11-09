// Package aptsign generates the OpenPGP signing key of an organization's Paddock repository and signs the repository's
// Release file with it (ADR 0050 decision 3, plan M13c decision 13), with github.com/ProtonMail/go-crypto (approved by
// the maintainer, decisions-alpha10 §32 Q4; BSD-3-Clause). The key is a v4 EdDSA key on Ed25519 without subkeys and
// without expiry, which apt verifies through gpgv (Ubuntu 24.04) and sqv (Ubuntu 26.04).
//
// The private key leaves this package only as the binary transferable secret key that the caller encrypts with Transit
// at once; the caller zeroes it after use, and Sign zeroes its parsed copy.
package aptsign

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Signer generates repository keys and signs Release files; it holds no key.
type Signer struct{}

// config returns the settings of every key and signature: legacy EdDSA on Ed25519 (v4; gpgv of Ubuntu 24.04 does not
// read the RFC 9580 Ed25519 algorithm) and SHA-512, with the given time as the creation time, and without the
// library's random salt notation, so the same Release signed at the same time gives the same signature.
func config(now time.Time) *packet.Config {
	deterministic := false
	return &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519, DefaultHash: crypto.SHA512,
		Time: func() time.Time { return now }, NonDeterministicSignaturesViaNotation: &deterministic}
}

// GenerateKey creates the key of the repository of the organization with the given slug; its user ID is
// "Paddock <slug>" (ADR 0050 decision 3). It returns the ASCII-armored transferable public key (the form of a software
// source's signing_key), its v4 fingerprint (40 uppercase hexadecimal characters) and the unencrypted binary
// transferable secret key, which the caller encrypts and zeroes.
func (Signer) GenerateKey(slug string, now time.Time) (publicKey, fingerprint string, private []byte, err error) {
	e, err := openpgp.NewEntity("Paddock", "", slug, config(now))
	if err != nil {
		return "", "", nil, fmt.Errorf("aptsign: generate key: %w", err)
	}
	defer wipe(e)
	// Repository signing needs no encryption subkey; without it the published key is the primary key alone.
	e.Subkeys = nil
	var pub bytes.Buffer
	aw, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", "", nil, err
	}
	if err := e.Serialize(aw); err != nil {
		return "", "", nil, fmt.Errorf("aptsign: serialize public key: %w", err)
	}
	if err := aw.Close(); err != nil {
		return "", "", nil, err
	}
	pub.WriteByte('\n')
	var priv bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&priv, nil); err != nil {
		return "", "", nil, fmt.Errorf("aptsign: serialize private key: %w", err)
	}
	return pub.String(), strings.ToUpper(fmt.Sprintf("%x", e.PrimaryKey.Fingerprint)), priv.Bytes(), nil
}

// Sign returns the clearsigned InRelease and the armored detached Release.gpg of release, each carrying one signature
// per private key of GenerateKey, in the given order, made at the given time. apt accepts the files when any signature
// verifies with its keyring, which keeps a device with the previous key working during a rotation's overlap (plan M13c
// §3.8 L5). It never keeps a key.
func (Signer) Sign(privates [][]byte, release []byte, now time.Time) (inRelease, releaseGPG []byte, err error) {
	if len(privates) == 0 {
		return nil, nil, errors.New("aptsign: no signing key")
	}
	entities := make([]*openpgp.Entity, 0, len(privates))
	defer func() {
		for _, e := range entities {
			wipe(e)
		}
	}()
	keys := make([]*packet.PrivateKey, 0, len(privates))
	for _, private := range privates {
		e, err := openpgp.ReadEntity(packet.NewReader(bytes.NewReader(private)))
		if err != nil {
			return nil, nil, fmt.Errorf("aptsign: read private key: %w", err)
		}
		entities = append(entities, e)
		if e.PrivateKey == nil || e.PrivateKey.Encrypted {
			return nil, nil, errors.New("aptsign: no usable private key")
		}
		keys = append(keys, e.PrivateKey)
	}
	cfg := config(now)
	var in bytes.Buffer
	w, err := clearsign.EncodeMulti(&in, keys, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("aptsign: clearsign: %w", err)
	}
	// The line break before the signature belongs to the armor, as gpg --clearsign writes it.
	if _, err := w.Write(bytes.TrimSuffix(release, []byte("\n"))); err != nil {
		return nil, nil, err
	}
	if err := w.Close(); err != nil {
		return nil, nil, fmt.Errorf("aptsign: clearsign: %w", err)
	}
	in.WriteByte('\n')
	var detached bytes.Buffer
	aw, err := armor.Encode(&detached, openpgp.SignatureType, nil)
	if err != nil {
		return nil, nil, err
	}
	// A detached signature with several signers is the signature packets one after another (RFC 4880 §11.4).
	for _, e := range entities {
		if err := openpgp.DetachSign(aw, e, bytes.NewReader(release), cfg); err != nil {
			return nil, nil, fmt.Errorf("aptsign: detached signature: %w", err)
		}
	}
	if err := aw.Close(); err != nil {
		return nil, nil, fmt.Errorf("aptsign: detached signature: %w", err)
	}
	detached.WriteByte('\n')
	return in.Bytes(), detached.Bytes(), nil
}

// wipe zeroes the secret scalar of a parsed or generated key, so it does not stay in memory until the next collection.
func wipe(e *openpgp.Entity) {
	if e == nil || e.PrivateKey == nil {
		return
	}
	if k, ok := e.PrivateKey.PrivateKey.(*eddsa.PrivateKey); ok {
		clear(k.D)
	}
}

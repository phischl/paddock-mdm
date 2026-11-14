package recoveryexport_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/recoveryexport"
)

const passphrase = "correct horse battery staple"

func newKey(t *testing.T) (*openpgp.Entity, string) {
	t.Helper()
	return newKeyWith(t, &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
}

// newKeyWith generates a key with cfg and returns it with its armoured public key.
func newKeyWith(t *testing.T, cfg *packet.Config) (*openpgp.Entity, string) {
	t.Helper()
	e, err := openpgp.NewEntity("Export Test", "", "export@example.test", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return e, buf.String()
}

// export writes a header and two device lines into a message to r.
func export(t *testing.T, r recoveryexport.Recipient, org uuid.UUID) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := recoveryexport.Encrypt(&out, r)
	if err != nil {
		t.Fatal(err)
	}
	line, err := recoveryexport.AppendHeader(nil, recoveryexport.NewHeader(org, "acme", time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC), 2))
	if err != nil {
		t.Fatal(err)
	}
	line = recoveryexport.AppendDevice(line, recoveryexport.Device{
		ID: uuid.MustParse("0193a1c2-0000-7000-8000-000000000001"), Hostname: "laptop-1",
		Volumes:    []recoveryexport.Volume{{UUID: "4f1c", RecoveryKey: []byte("11111-22222-33333")}},
		LocalAdmin: &recoveryexport.LocalAdmin{Username: "paddock-admin", Password: []byte("p\"a\\s\ns\x01w-ä")},
	})
	line = recoveryexport.AppendDevice(line, recoveryexport.Device{
		ID: uuid.MustParse("0193a1c2-0000-7000-8000-000000000002"), Hostname: "laptop-2",
	})
	if _, err := w.Write(line); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func decrypt(msg []byte, keys openpgp.EntityList, pass []byte) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	tried := false
	md, err := openpgp.ReadMessage(block.Body, keys, func([]openpgp.Key, bool) ([]byte, error) {
		if tried {
			return nil, errors.New("wrong passphrase")
		}
		tried = true
		return pass, nil
	}, nil)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(md.UnverifiedBody)
}

type deviceLine struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Volumes  []struct {
		UUID        string `json:"uuid"`
		RecoveryKey string `json:"recovery_key"`
	} `json:"volumes"`
	LocalAdmin *struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"local_admin"`
}

func checkPlaintext(t *testing.T, plain []byte, org uuid.UUID) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(plain))
	var lines [][]byte
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	if len(lines) != 3 {
		t.Fatalf("lines: %d\n%s", len(lines), plain)
	}
	var h recoveryexport.Header
	if err := json.Unmarshal(lines[0], &h); err != nil || h.OrganizationID != org || h.Slug != "acme" ||
		h.ExportedAt != "2026-11-14T12:00:00Z" || h.Devices != 2 {
		t.Fatalf("header: %+v %v", h, err)
	}
	var d1, d2 deviceLine
	if err := json.Unmarshal(lines[1], &d1); err != nil {
		t.Fatalf("device line %s: %v", lines[1], err)
	}
	if d1.Hostname != "laptop-1" || len(d1.Volumes) != 1 || d1.Volumes[0].UUID != "4f1c" ||
		d1.Volumes[0].RecoveryKey != "11111-22222-33333" || d1.LocalAdmin == nil ||
		d1.LocalAdmin.Username != "paddock-admin" || d1.LocalAdmin.Password != "p\"a\\s\ns\x01w-ä" {
		t.Fatalf("device 1: %+v", d1)
	}
	if err := json.Unmarshal(lines[2], &d2); err != nil || d2.LocalAdmin != nil || d2.Volumes == nil || len(d2.Volumes) != 0 {
		t.Fatalf("device 2: %s %v", lines[2], err)
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	e, armored := newKey(t)
	r, err := recoveryexport.ParseRecipient(recoveryexport.RecipientPublicKey, armored, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint() == "" || r.Fingerprint() != strings.ToUpper(r.Fingerprint()) || len(r.Fingerprint()) != 40 {
		t.Fatalf("fingerprint %q", r.Fingerprint())
	}
	org := uuid.New()
	msg := export(t, r, org)
	if !bytes.HasPrefix(msg, []byte("-----BEGIN PGP MESSAGE-----")) || bytes.Contains(msg, []byte("11111-22222")) {
		t.Fatalf("not an armoured ciphertext:\n%s", msg)
	}
	plain, err := decrypt(msg, openpgp.EntityList{e}, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkPlaintext(t, plain, org)
	other, _ := newKey(t)
	if _, err := decrypt(msg, openpgp.EntityList{other}, nil); err == nil {
		t.Fatal("another key decrypts the export")
	}
}

func TestPassphraseRoundTrip(t *testing.T) {
	r, err := recoveryexport.ParseRecipient(recoveryexport.RecipientPassphrase, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint() != "" {
		t.Fatal("a passphrase has a fingerprint")
	}
	org := uuid.New()
	msg := export(t, r, org)
	plain, err := decrypt(msg, nil, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	checkPlaintext(t, plain, org)
	if _, err := decrypt(msg, nil, []byte(passphrase+"!")); err == nil {
		t.Fatal("a wrong passphrase decrypts the export")
	}
}

// TestTruncatedMessageFails: an export that breaks off while streaming does not decrypt (decision 25).
func TestTruncatedMessageFails(t *testing.T) {
	r, err := recoveryexport.ParseRecipient(recoveryexport.RecipientPassphrase, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	msg := export(t, r, uuid.New())
	if _, err := decrypt(msg[:len(msg)*2/3], nil, []byte(passphrase)); err == nil {
		t.Fatal("a truncated export decrypts")
	}
}

// TestGPGDecrypts checks that standard gpg opens both kinds of export (decision 23).
func TestGPGDecrypts(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg is not installed; the acceptance gate OF9 requires it")
	}
	home := t.TempDir()
	run := func(stdin []byte, args ...string) ([]byte, error) {
		cmd := exec.Command(gpg, append([]string{"--homedir", home, "--batch", "--yes", "--pinentry-mode", "loopback"}, args...)...)
		cmd.Stdin = bytes.NewReader(stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return out, errors.New(err.Error() + ": " + stderr.String())
		}
		return out, nil
	}
	org := uuid.New()

	r, err := recoveryexport.ParseRecipient(recoveryexport.RecipientPassphrase, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := run(export(t, r, org), "--passphrase", passphrase, "--decrypt")
	if err != nil {
		t.Fatalf("gpg passphrase: %v", err)
	}
	checkPlaintext(t, plain, org)

	if _, err := run(nil, "--passphrase", "", "--quick-gen-key", "export@example.test", "default", "default", "never"); err != nil {
		t.Fatalf("gpg key: %v", err)
	}
	pub, err := run(nil, "--armor", "--export", "export@example.test")
	if err != nil {
		t.Fatal(err)
	}
	r, err = recoveryexport.ParseRecipient(recoveryexport.RecipientPublicKey, string(pub), "")
	if err != nil {
		t.Fatalf("gpg public key: %v", err)
	}
	file := filepath.Join(t.TempDir(), "export.asc")
	if err := os.WriteFile(file, export(t, r, org), 0o600); err != nil {
		t.Fatal(err)
	}
	plain, err = run(nil, "--decrypt", file)
	if err != nil {
		t.Fatalf("gpg public key decrypt: %v", err)
	}
	checkPlaintext(t, plain, org)
}

func TestParseRecipientRefusals(t *testing.T) {
	e, armored := newKey(t)
	var private bytes.Buffer
	w, _ := armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err := e.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	_, second := newKey(t)
	cases := map[string][3]string{
		"unknown recipient":   {"pgp", "", ""},
		"short passphrase":    {"passphrase", "", strings.Repeat("x", 19)},
		"long passphrase":     {"passphrase", "", strings.Repeat("x", 1025)},
		"invalid utf-8":       {"passphrase", "", strings.Repeat("\xff", 20)},
		"passphrase with key": {"passphrase", armored, passphrase},
		"key with passphrase": {"public_key", armored, passphrase},
		"no key":              {"public_key", "", ""},
		"garbage key":         {"public_key", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n", ""},
		"oversized key":       {"public_key", armored + strings.Repeat(" ", recoveryexport.MaxPublicKeyBytes), ""},
		"private key":         {"public_key", private.String(), ""},
		"two keys":            {"public_key", armored + second, ""},
	}
	for name, c := range cases {
		_, err := recoveryexport.ParseRecipient(c[0], c[1], c[2])
		if !errors.Is(err, recoveryexport.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), passphrase) || strings.Contains(err.Error(), "xxxxxxxx") {
			t.Errorf("%s: the refusal echoes the secret: %v", name, err)
		}
	}
	if _, err := recoveryexport.ParseRecipient("passphrase", "", strings.Repeat("ä", 20)); err != nil {
		t.Fatalf("20 characters refused: %v", err)
	}
}

// TestDeviceLineBound: a line appended into a buffer of its bound never grows, also when every byte escapes.
func TestDeviceLineBound(t *testing.T) {
	d := recoveryexport.Device{ID: uuid.New(), Hostname: strings.Repeat("\x01", 64),
		Volumes:    []recoveryexport.Volume{{UUID: uuid.NewString(), RecoveryKey: bytes.Repeat([]byte{0x02}, 48)}},
		LocalAdmin: &recoveryexport.LocalAdmin{Username: "\"", Password: bytes.Repeat([]byte{0x1f}, 64)}}
	buf := make([]byte, 0, recoveryexport.DeviceLineBound(d))
	out := recoveryexport.AppendDevice(buf, d)
	if cap(out) != cap(buf) || &out[:1][0] != &buf[:1][0] {
		t.Fatalf("the line grew beyond its bound: %d > %d", len(out), cap(buf))
	}
}

// TestWeakRecipientKeys (review 1 finding 3): the key the export is encrypted to must be RSA of at least 3072 bits,
// X25519, X448 or ECDH on another curve than secp256k1, and valid now.
func TestWeakRecipientKeys(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour)
	for name, cfg := range map[string]*packet.Config{
		"RSA-1024":  {Algorithm: packet.PubKeyAlgoRSA, RSABits: 1024},
		"RSA-2048":  {Algorithm: packet.PubKeyAlgoRSA, RSABits: 2048},
		"secp256k1": {Algorithm: packet.PubKeyAlgoECDSA, Curve: packet.CurveSecP256k1},
		"expired":   {Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 3600, Time: func() time.Time { return past }},
	} {
		_, armored := newKeyWith(t, cfg)
		if _, err := recoveryexport.ParseRecipient(recoveryexport.RecipientPublicKey, armored, ""); !errors.Is(err, recoveryexport.ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	for name, cfg := range map[string]*packet.Config{
		"RSA-3072":   {Algorithm: packet.PubKeyAlgoRSA, RSABits: 3072},
		"Curve25519": {Algorithm: packet.PubKeyAlgoEdDSA},
		"P-384":      {Algorithm: packet.PubKeyAlgoECDSA, Curve: packet.CurveNistP384},
	} {
		_, armored := newKeyWith(t, cfg)
		if _, err := recoveryexport.ParseRecipient(recoveryexport.RecipientPublicKey, armored, ""); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

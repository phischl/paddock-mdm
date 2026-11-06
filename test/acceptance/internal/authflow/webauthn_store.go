package authflow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// The upgrade job (deploy/bundle/ci/upgrade.sh, PDK-744) signs its administrators in from several processes over one
// run, before and after the upgrade, so it keeps their authenticators in files and registers them with `ak shell`
// (decisions-alpha9 item 53).

const webAuthnPEMType = "PADDOCK TEST WEBAUTHN KEY"

// Save writes the authenticator to path (0600): the PKCS#8 key as PEM with the credential ID as a header.
func (w *WebAuthn) Save(path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(w.key)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: webAuthnPEMType, Headers: map[string]string{"Credential-Id": w.CredentialID()}, Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// LoadWebAuthn reads an authenticator that Save wrote.
func LoadWebAuthn(path string) (*WebAuthn, error) {
	data, err := os.ReadFile(path) //nolint:gosec // test helper
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != webAuthnPEMType {
		return nil, fmt.Errorf("authflow: %s holds no WebAuthn key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("authflow: %s: not a P-256 key", path)
	}
	id, err := b64url.DecodeString(block.Headers["Credential-Id"])
	if err != nil || len(id) == 0 {
		return nil, fmt.Errorf("authflow: %s: no credential ID", path)
	}
	return &WebAuthn{key: key, id: id}, nil
}

// RegistrationScript is the Python for Authentik's `ak shell` that registers this authenticator for username under
// name, replacing an earlier registration of the same name. Only model fields the installed Authentik has are set.
func (w *WebAuthn) RegistrationScript(username, rpID, name string) string {
	return fmt.Sprintf(`from authentik.core.models import User
from authentik.stages.authenticator_webauthn.models import WebAuthnDevice
user = User.objects.get(username=%q)
fields = {f.name for f in WebAuthnDevice._meta.get_fields()}
values = {"credential_id": %q, "public_key": %q, "sign_count": 0, "rp_id": %q, "confirmed": True}
WebAuthnDevice.objects.filter(user=user, name=%q).delete()
WebAuthnDevice.objects.create(user=user, name=%q, **{k: v for k, v in values.items() if k in fields})
print("paddock-webauthn ok")
`, username, w.CredentialID(), w.PublicKey(), rpID, name, name)
}

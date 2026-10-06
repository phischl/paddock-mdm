package device

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
)

// signed is a request whose signature and nonce were verified.
type signed struct {
	headers protocol.Headers
	body    []byte
}

// device is a verified request of an enrolled device.
type device struct {
	signed
	id  uuid.UUID
	key devicecache.DeviceKey
}

// pathQuery is the path including query as sent, which the device signed. The escaped path and the raw query keep
// the client's encoding; the request target is not used directly because it may be in absolute form.
func pathQuery(r *http.Request) string { return r.URL.RequestURI() }

// readSigned applies the per-address limit, reads the body and checks header presence and the timestamp — the
// steps before a key is known.
func (g *gateway) readSigned(w http.ResponseWriter, r *http.Request, limit int64) (signed, error) {
	if err := g.limit(r.Context(), "ip:"+httpx.ClientIP(r), g.d.PerIPLimit); err != nil {
		return signed{}, err
	}
	body, err := readBody(w, r, limit)
	if err != nil {
		return signed{}, err
	}
	h, err := protocol.ParseHeaders(r.Header)
	if err != nil {
		return signed{}, errInvalidSignature.with(err.Error())
	}
	if err := protocol.CheckTimestamp(h, g.d.Now()); err != nil {
		return signed{}, errClockSkew.with("timestamp outside ±300 s of server time")
	}
	return signed{headers: h, body: body}, nil
}

// verify checks the signature with pub, then the nonce, then the per-key limit.
func (g *gateway) verify(ctx context.Context, r *http.Request, s signed, pub *ecdsa.PublicKey) error {
	if err := protocol.Verify(pub, r.Method, pathQuery(r), s.headers, s.body); err != nil {
		return errInvalidSignature.with(err.Error())
	}
	fresh, err := g.d.Cache.UseNonce(ctx, s.headers.Device, s.headers.Nonce)
	if err != nil {
		return err
	}
	if !fresh {
		return errReplay.with("nonce already used")
	}
	return g.limit(ctx, "key:"+s.headers.KeyID, g.d.PerKeyLimit)
}

// authenticateDevice verifies a request of an enrolled device in the order of architecture §6.3: header presence,
// timestamp, key lookup in dk:, key status, signature, nonce. Quarantined devices pass (fail safe); the handlers
// withhold new bundles from them.
func (g *gateway) authenticateDevice(w http.ResponseWriter, r *http.Request, limit int64) (device, error) {
	s, err := g.readSigned(w, r, limit)
	if err != nil {
		return device{}, err
	}
	if s.headers.Device == protocol.EnrollDevice {
		return device{}, errInvalidSignature.with("enrollment keys cannot call this endpoint")
	}
	key, ok, err := g.d.Cache.DeviceKey(r.Context(), s.headers.KeyID)
	if err != nil {
		return device{}, err
	}
	if !ok || key.DeviceID.String() != s.headers.Device {
		return device{}, errInvalidSignature.with("unknown key")
	}
	if key.Status != devicecache.KeyActive && key.Status != devicecache.KeyQuarantined {
		return device{}, errIdentityRevoked.with("the device identity is not active")
	}
	pub, err := protocol.ParsePublicKey(key.PublicKey)
	if err != nil {
		return device{}, errors.Join(errInvalidSignature, err)
	}
	if err := g.verify(r.Context(), r, s, pub); err != nil {
		return device{}, err
	}
	return device{signed: s, id: key.DeviceID, key: key}, nil
}

// authenticateEnrollment verifies a request signed with the key of an enrollment (Paddock-Device: enroll). The
// public key comes from the request body (POST /v1/enroll) or from enr: (GET /v1/enroll/{id}); the key ID must be
// its SHA-256, which binds the signature to the key (proof of possession).
func (g *gateway) authenticateEnrollment(ctx context.Context, r *http.Request, s signed, spki []byte) error {
	if s.headers.Device != protocol.EnrollDevice || protocol.KeyID(spki) != s.headers.KeyID {
		return errInvalidSignature.with("key id does not match the enrollment key")
	}
	pub, err := protocol.ParsePublicKey(spki)
	if err != nil {
		return errInvalidRequest.with("public_key must be an ECDSA P-256 SubjectPublicKeyInfo")
	}
	return g.verify(ctx, r, s, pub)
}

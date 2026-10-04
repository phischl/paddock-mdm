package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCanonicalStringGolden(t *testing.T) {
	h := Headers{
		Device: "0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11", KeyID: strings.Repeat("ab", 32), Timestamp: 1790000000,
		Nonce: "AAAAAAAAAAAAAAAAAAAAAA", ContentSHA256: ContentSHA256(nil), Seq: 41,
	}
	got := CanonicalString(http.MethodPost, "/v1/checkin?x=1", h)
	want := "paddock-v1\nPOST\n/v1/checkin?x=1\n0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11\n" + strings.Repeat("ab", 32) +
		"\n1790000000\nAAAAAAAAAAAAAAAAAAAAAA\n47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU\n41"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

type signed struct {
	key   *ecdsa.PrivateKey
	keyID string
	req   *http.Request
	body  []byte
	now   time.Time
}

func newSigned(t *testing.T) signed {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := MarshalPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"applied_bundle_version":3}`)
	req, err := http.NewRequest(http.MethodPost, "https://device.example/v1/checkin?debug=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1790000000, 0)
	if err := Sign(req, body, key, "0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11", KeyID(spki), 7, now); err != nil {
		t.Fatal(err)
	}
	return signed{key: key, keyID: KeyID(spki), req: req, body: body, now: now}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := newSigned(t)
	h, err := ParseHeaders(s.req.Header)
	if err != nil {
		t.Fatal(err)
	}
	if h.Seq != 7 || h.KeyID != s.keyID || h.Timestamp != s.now.Unix() {
		t.Fatalf("headers %+v", h)
	}
	if err := CheckTimestamp(h, s.now); err != nil {
		t.Fatal(err)
	}
	if err := Verify(&s.key.PublicKey, s.req.Method, s.req.URL.RequestURI(), h, s.body); err != nil {
		t.Fatal(err)
	}
}

// Every signed input changes the canonical string; altering any of them must break the signature.
func TestTamperedFieldFails(t *testing.T) {
	s := newSigned(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		header, value string
		method, path  string
		body          []byte
		key           *ecdsa.PublicKey
		want          error
	}{
		"device":    {header: HeaderDevice, value: "11111111-1111-4111-8111-111111111111", want: ErrBadSignature},
		"key id":    {header: HeaderKeyID, value: strings.Repeat("0", 64), want: ErrBadSignature},
		"timestamp": {header: HeaderTimestamp, value: strconv.FormatInt(s.now.Unix()+1, 10), want: ErrBadSignature},
		"nonce":     {header: HeaderNonce, value: "BBBBBBBBBBBBBBBBBBBBBB", want: ErrBadSignature},
		"content":   {header: HeaderContentSHA256, value: ContentSHA256([]byte("other")), want: ErrContentMismatch},
		"seq":       {header: HeaderSeq, value: "8", want: ErrBadSignature},
		"signature": {header: HeaderSignature, value: "MEUCIQ", want: ErrBadSignature},
		"method":    {method: http.MethodPut, want: ErrBadSignature},
		"path":      {path: "/v1/events?debug=1", want: ErrBadSignature},
		"query":     {path: "/v1/checkin?debug=2", want: ErrBadSignature},
		"body":      {body: []byte(`{"applied_bundle_version":4}`), want: ErrContentMismatch},
		"key":       {key: &other.PublicKey, want: ErrBadSignature},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			hdr := s.req.Header.Clone()
			if c.header != "" {
				hdr.Set(c.header, c.value)
			}
			method, path, body, key := s.req.Method, s.req.URL.RequestURI(), s.body, &s.key.PublicKey
			if c.method != "" {
				method = c.method
			}
			if c.path != "" {
				path = c.path
			}
			if c.body != nil {
				body = c.body
			}
			if c.key != nil {
				key = c.key
			}
			h, err := ParseHeaders(hdr)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(key, method, path, h, body); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestCheckTimestampBoundary(t *testing.T) {
	now := time.Unix(1790000000, 0)
	for offset, ok := range map[int64]bool{0: true, 300: true, -300: true, 301: false, -301: false} {
		err := CheckTimestamp(Headers{Timestamp: now.Unix() + offset}, now)
		if (err == nil) != ok {
			t.Errorf("offset %d: %v", offset, err)
		}
		if err != nil && !errors.Is(err, ErrClockSkew) {
			t.Errorf("offset %d: wrong error %v", offset, err)
		}
	}
}

func TestParseHeadersErrors(t *testing.T) {
	s := newSigned(t)
	for _, name := range []string{HeaderDevice, HeaderKeyID, HeaderTimestamp, HeaderNonce, HeaderContentSHA256, HeaderSeq, HeaderSignature} {
		hdr := s.req.Header.Clone()
		hdr.Del(name)
		if _, err := ParseHeaders(hdr); !errors.Is(err, ErrMissingHeader) {
			t.Errorf("without %s: %v", name, err)
		}
	}
	malformed := map[string]string{
		HeaderDevice:        "not-a-uuid",
		HeaderKeyID:         strings.Repeat("AB", 32),
		HeaderTimestamp:     "-5",
		HeaderNonce:         "short",
		HeaderContentSHA256: strings.Repeat("+", 43),
		HeaderSeq:           "01",
		HeaderSignature:     "***",
	}
	for name, value := range malformed {
		hdr := s.req.Header.Clone()
		hdr.Set(name, value)
		if _, err := ParseHeaders(hdr); !errors.Is(err, ErrMalformedHeader) {
			t.Errorf("%s=%q: %v", name, value, err)
		}
	}
	hdr := s.req.Header.Clone()
	hdr.Add(HeaderNonce, "BBBBBBBBBBBBBBBBBBBBBB")
	if _, err := ParseHeaders(hdr); !errors.Is(err, ErrMalformedHeader) {
		t.Errorf("repeated header: %v", err)
	}
	hdr = s.req.Header.Clone()
	hdr.Set(HeaderDevice, EnrollDevice)
	if _, err := ParseHeaders(hdr); err != nil {
		t.Errorf("enroll device: %v", err)
	}
}

func TestPublicKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := MarshalPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(spki)
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatalf("parse: %v", err)
	}
	if len(KeyID(spki)) != 64 {
		t.Fatal("key id length")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := MarshalPublicKey(&p384.PublicKey); !errors.Is(err, ErrUnsupportedKey) {
		t.Errorf("P-384 marshaled: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParsePublicKey(der); !errors.Is(err, ErrUnsupportedKey) {
		t.Errorf("P-384 parsed: %v", err)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // test of a rejected key type
	der, _ = x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if _, err := ParsePublicKey(der); !errors.Is(err, ErrUnsupportedKey) {
		t.Errorf("RSA parsed: %v", err)
	}
	if _, err := ParsePublicKey([]byte("garbage")); !errors.Is(err, ErrUnsupportedKey) {
		t.Errorf("garbage parsed: %v", err)
	}
}

// FuzzParseHeaders checks that every accepted header set yields a canonical string with exactly nine lines, so no
// header value can inject or hide a field.
func FuzzParseHeaders(f *testing.F) {
	f.Add("0b6d4c8e-6c55-4a5e-9a2f-1f7f0f5b4a11", strings.Repeat("ab", 32), "1790000000", "AAAAAAAAAAAAAAAAAAAAAA",
		ContentSHA256(nil), "0", "MEUCIQ")
	f.Add("enroll", strings.Repeat("0", 64), "0", "AAAAAAAAAAAAAAAAAAAAA\n", "x", "1\n2", "")
	f.Fuzz(func(t *testing.T, device, keyID, ts, nonce, content, seq, sig string) {
		hdr := http.Header{}
		hdr[HeaderDevice] = []string{device}
		hdr[HeaderKeyID] = []string{keyID}
		hdr[HeaderTimestamp] = []string{ts}
		hdr[HeaderNonce] = []string{nonce}
		hdr[HeaderContentSHA256] = []string{content}
		hdr[HeaderSeq] = []string{seq}
		hdr[HeaderSignature] = []string{sig}
		h, err := ParseHeaders(hdr)
		if err != nil {
			return
		}
		lines := strings.Split(CanonicalString("POST", "/v1/checkin", h), "\n")
		if len(lines) != 9 {
			t.Fatalf("canonical string has %d lines for %+v", len(lines), h)
		}
		if lines[3] != device || lines[4] != keyID || lines[5] != ts || lines[6] != nonce || lines[7] != content || lines[8] != seq {
			t.Fatalf("canonical string does not reproduce the headers: %q", lines)
		}
	})
}

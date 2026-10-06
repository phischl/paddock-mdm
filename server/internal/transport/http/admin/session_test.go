package admin

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
)

func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func testSession(now time.Time) Session {
	return NewSession(principal.Principal{
		Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Subject: "sub-1", Display: "alice@acme.test",
		Role: principal.RoleOrgAdmin, OrganizationID: uuid.Must(uuid.NewV7()),
	}, "en", now)
}

func TestSessionRoundTrip(t *testing.T) {
	k := &Keyring{}
	if err := k.SetKeys(newKey(t), ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	in := testSession(now)
	v, err := k.Seal(SessionCookie, in)
	if err != nil {
		t.Fatal(err)
	}
	var out Session
	if err := k.Open(SessionCookie, v, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip changed the session: %+v != %+v", out, in)
	}
	if p := out.Principal("192.0.2.1"); p.OrganizationID != in.Org || p.Role != principal.RoleOrgAdmin || p.IP != "192.0.2.1" {
		t.Fatalf("principal %+v", p)
	}
}

func TestPreviousKeyIsAccepted(t *testing.T) {
	oldKey, newKeyB64 := newKey(t), newKey(t)
	k := &Keyring{}
	_ = k.SetKeys(oldKey, "")
	v, _ := k.Seal(SessionCookie, testSession(time.Now()))
	if err := k.SetKeys(newKeyB64, oldKey); err != nil {
		t.Fatal(err)
	}
	var out Session
	if err := k.Open(SessionCookie, v, &out); err != nil {
		t.Fatalf("cookie sealed with the previous key rejected: %v", err)
	}
	// After the next rotation the old key is gone.
	_ = k.SetKeys(newKey(t), newKeyB64)
	if err := k.Open(SessionCookie, v, &out); !errors.Is(err, ErrInvalidCookie) {
		t.Fatalf("cookie of a retired key accepted: %v", err)
	}
}

func TestTamperedCookieIsRejected(t *testing.T) {
	k := &Keyring{}
	_ = k.SetKeys(newKey(t), "")
	v, _ := k.Seal(SessionCookie, testSession(time.Now()))
	raw, _ := base64.RawURLEncoding.DecodeString(v)
	for _, i := range []int{0, len(raw) / 2, len(raw) - 1} {
		tampered := append([]byte(nil), raw...)
		tampered[i] ^= 0x01
		var out Session
		if err := k.Open(SessionCookie, base64.RawURLEncoding.EncodeToString(tampered), &out); !errors.Is(err, ErrInvalidCookie) {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	var out Session
	if err := k.Open(SessionCookie, "not-base64!", &out); !errors.Is(err, ErrInvalidCookie) {
		t.Fatal("garbage accepted")
	}
	// A login cookie cannot be replayed as a session cookie (the name is authenticated data).
	login, _ := k.Seal(LoginCookie, testSession(time.Now()))
	if err := k.Open(SessionCookie, login, &out); !errors.Is(err, ErrInvalidCookie) {
		t.Fatal("login cookie accepted as session cookie")
	}
}

func TestSessionExpiry(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	s := testSession(start)

	if reissue, err := s.Validate(start.Add(time.Minute)); err != nil || reissue {
		t.Fatalf("fresh session: reissue=%v err=%v", reissue, err)
	}
	if reissue, err := s.Validate(start.Add(6 * time.Minute)); err != nil || !reissue {
		t.Fatalf("after 6 min: reissue=%v err=%v, want re-issue", reissue, err)
	}
	if _, err := s.Validate(start.Add(30 * time.Minute)); !errors.Is(err, ErrInvalidCookie) {
		t.Fatal("idle timeout of 30 min not enforced")
	}
	// Activity every 20 minutes keeps the session alive until the absolute lifetime of 8 h.
	for at := start; at.Before(start.Add(SessionAbsolute)); at = at.Add(20 * time.Minute) {
		if _, err := s.Validate(at); err != nil {
			t.Fatalf("active session rejected at %s", at.Sub(start))
		}
		s.Idle = at.Unix()
	}
	if _, err := s.Validate(start.Add(SessionAbsolute)); !errors.Is(err, ErrInvalidCookie) {
		t.Fatal("absolute lifetime of 8 h not enforced")
	}
}

func TestSessionShapeIsChecked(t *testing.T) {
	now := time.Now()
	s := testSession(now)
	s.Org = uuid.Nil
	if _, err := s.Validate(now); err == nil {
		t.Fatal("admin session without organization accepted")
	}
	p := testSession(now)
	p.Kind = string(principal.KindPlatformAdmin)
	if _, err := p.Validate(now); err == nil {
		t.Fatal("platform session with organization accepted")
	}
	v := testSession(now)
	v.V = 2
	if _, err := v.Validate(now); err == nil {
		t.Fatal("unknown version accepted")
	}
	sys := testSession(now)
	sys.Kind = string(principal.KindSystem)
	if _, err := sys.Validate(now); err == nil {
		t.Fatal("system session accepted")
	}
}

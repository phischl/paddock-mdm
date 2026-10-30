package admin_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// fallbacks are the admin.login events of the identity: "<organization>|<outcome>|<target type>|<fallback>|<denial>".
func (u *twoRoles) fallbacks() []string {
	u.w.t.Helper()
	rows, err := u.w.e.super.Query(context.Background(), `SELECT organization_id::text || '|' || outcome || '|' ||
		coalesce(target->>'type', '-') || '|' || coalesce(params->>'fallback', '-') || '|' || coalesce(params->>'denial_reason', '-')
		FROM action WHERE code = 'admin.login' AND actor->>'display' = $1 ORDER BY started_at, id`, u.username)
	if err != nil {
		u.w.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			u.w.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// TestSignInFallsBackToPlatform covers the ADR 0045 amendment 2026-10-29 (PDK-458): a plain sign-in of a two-role
// identity whose organization is unknown or not active enters the platform role, records admin.login with fallback
// organization_inactive and tells the portal through role_fallback; an explicit switch to the organization stays
// refused.
func TestSignInFallsBackToPlatform(t *testing.T) {
	w := newLoginWorld(t, nil)
	e := w.e
	platform := uuid.Nil.String()
	suspended := "susp-" + uuid.NewString()[:8]
	if _, err := e.super.Exec(context.Background(), `INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, $3, 'suspended')`,
		uuid.Must(uuid.NewV7()), suspended, "Suspended "+suspended); err != nil {
		t.Fatal(err)
	}

	for name, slug := range map[string]string{"unknown organization": "gone-" + uuid.NewString()[:8], "suspended organization": suspended} {
		t.Run(name, func(t *testing.T) {
			u := newTwoRoles(w)
			claims := u.claims(organization.PlatformAdminsGroup(), organization.RoleGroup(slug, organization.GroupAdmins))
			c := u.signIn(claims)
			sess := u.session(c)
			if sess.Kind != "platform_admin" || sess.Role != "platform_admin" || sess.Org != uuid.Nil || sess.Fallback != "organization_inactive" ||
				sess.AltRole != "org_admin" || sess.AltSlug != slug {
				t.Fatalf("fallback session %+v", sess)
			}
			m := u.me(c)
			if m.Role != adminapi.MeRolePlatformAdmin || m.RoleFallback == nil || *m.RoleFallback != adminapi.OrganizationInactive ||
				m.AlternateRole == nil || m.AlternateRole.Role != adminapi.MeAlternateRoleRoleOrgAdmin {
				t.Fatalf("me after the fallback: role %s, fallback %v, alternate %+v", m.Role, m.RoleFallback, m.AlternateRole)
			}
			if r := e.do(call{method: "PATCH", path: "/api/v1/me", cookie: c, body: map[string]any{"locale": "de"}}); r.status != http.StatusOK {
				t.Fatalf("PATCH /api/v1/me: %d %s", r.status, r.body)
			} else {
				var pm adminapi.Me
				r.decode(t, &pm)
				if pm.RoleFallback == nil || *pm.RoleFallback != adminapi.OrganizationInactive {
					t.Fatalf("PATCH role_fallback %v", pm.RoleFallback)
				}
			}
			if r := e.do(call{method: "GET", path: "/api/platform/v1/organizations", cookie: c}); r.status != http.StatusOK {
				t.Fatalf("platform API from the fallback session: %d %s", r.status, r.body)
			}
			if got := u.fallbacks(); len(got) != 1 || got[0] != platform+"|success|platform_admin|organization_inactive|-" {
				t.Fatalf("sign-in events %v", got)
			}

			start := u.startSwitch(c, map[string]any{"role": "organization"})
			if start.status != http.StatusOK {
				t.Fatalf("switch: %d %s", start.status, start.body)
			}
			res := u.complete(start, claims)
			if res.Code != http.StatusFound || res.Header().Get("Location") != "/login-denied?reason=organization_inactive" ||
				cookieFrom(res) != nil {
				t.Fatalf("switch callback: %d %s", res.Code, res.Header().Get("Location"))
			}
			if got := u.fallbacks(); len(got) != 2 || got[1] != platform+"|denied|-|-|organization_inactive" {
				t.Fatalf("switch events %v", got)
			}
			if !u.hasRecord(sess.SID) {
				t.Fatal("the refused switch ended the platform session")
			}
			if m := u.me(c); m.Role != adminapi.MeRolePlatformAdmin || m.RoleFallback == nil {
				t.Fatalf("platform session after the refused switch: role %s, fallback %v", m.Role, m.RoleFallback)
			}
		})
	}
}

// TestSignInWithoutFallback: an active organization, a switch and a single-role identity never fall back (PDK-458).
func TestSignInWithoutFallback(t *testing.T) {
	w := newLoginWorld(t, nil)
	e := w.e
	acme := e.acme.String()

	t.Run("two roles, active organization", func(t *testing.T) {
		u := newTwoRoles(w)
		c := u.signIn(u.both())
		if s := u.session(c); s.Role != "org_admin" || s.Org != e.acme || s.Fallback != "" {
			t.Fatalf("session %+v", s)
		}
		if m := u.me(c); m.RoleFallback != nil {
			t.Fatalf("role_fallback %v", *m.RoleFallback)
		}
		start := u.startSwitch(c, map[string]any{"role": "platform"})
		if start.status != http.StatusOK {
			t.Fatalf("switch: %d %s", start.status, start.body)
		}
		pc := cookieFrom(u.complete(start, u.both()))
		if pc == nil {
			t.Fatal("switch to the platform role refused")
		}
		if s := u.session(pc); s.Role != "platform_admin" || s.Fallback != "" {
			t.Fatalf("switched session %+v", s)
		}
		if m := u.me(pc); m.RoleFallback != nil {
			t.Fatalf("role_fallback after the switch %v", *m.RoleFallback)
		}
		if got := u.fallbacks(); len(got) != 2 || got[0] != acme+"|success|admin_account|-|-" ||
			got[1] != uuid.Nil.String()+"|success|platform_admin|-|-" {
			t.Fatalf("events %v", got)
		}
	})
	t.Run("organization role only, unknown organization", func(t *testing.T) {
		u := newTwoRoles(w)
		res := w.login(context.Background(), u.claims(organization.RoleGroup("gone-"+uuid.NewString()[:8], organization.GroupAdmins)))
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/login-denied?reason=organization_inactive" ||
			cookieFrom(res) != nil {
			t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
		}
		if got := u.fallbacks(); len(got) != 1 || got[0] != uuid.Nil.String()+"|denied|-|-|organization_inactive" {
			t.Fatalf("events %v", got)
		}
	})
	t.Run("single-role sessions", func(t *testing.T) {
		u := newTwoRoles(w)
		if m := u.me(e.platformSession()); m.RoleFallback != nil {
			t.Fatalf("platform session role_fallback %v", *m.RoleFallback)
		}
		if m := u.me(e.session(e.acme, "org_admin")); m.RoleFallback != nil {
			t.Fatalf("organization session role_fallback %v", *m.RoleFallback)
		}
	})
}

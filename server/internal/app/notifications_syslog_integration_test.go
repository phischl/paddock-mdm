package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

func syslogCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SIEM CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func syslogInput(name string) app.NotificationDestinationInput {
	return app.NotificationDestinationInput{Type: outbound.TypeSyslog, Name: name, Enabled: true,
		FilterMode: outbound.FilterSecurity, SyslogHost: "siem.example.org"}
}

// TestNotificationDestinationSyslog: a syslog destination stores its receiver in plain text (no Transit call, no
// secret), defaults the port to 6514, never returns the CA bundle but says whether one is stored; an update without
// syslog_ca_pem keeps it and "" removes it; a private receiver, a URL, a bad PEM and checkpoints on e-mail are refused
// (plan M12 decisions 17 and 19).
func TestNotificationDestinationSyslog(t *testing.T) {
	w := newNotificationWorld(t, true)
	ctx := stepped(w.org, principal.RoleOrgAdmin)
	bg := context.Background()
	ca := syslogCAPEM(t)
	in := syslogInput("SIEM syslog")
	in.SyslogCAPEM, in.Checkpoints, in.HeartbeatIntervalS = &ca, true, 300
	d, secret, err := w.n.Create(ctx, app.ScopeOrg, in)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" || len(w.keys.calls) != 0 {
		t.Errorf("secret %q, transit calls %v: a syslog destination has no secret", secret, w.keys.calls)
	}
	if d.Type != "syslog" || *d.SyslogHost != "siem.example.org" || *d.SyslogPort != outbound.DefaultSyslogPort ||
		d.SyslogServerName != nil || !d.SyslogCAPEMSet || !d.Checkpoints || d.URLDisplay != nil {
		t.Fatalf("created %+v", d)
	}
	storedCA := func() *string {
		var s *string
		if err := w.super.QueryRow(bg, "SELECT syslog_ca_pem FROM notification_destination WHERE id = $1", d.ID).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if got := storedCA(); got == nil || *got != ca {
		t.Fatal("the CA bundle was not stored")
	}

	up := syslogInput("SIEM syslog")
	up.SyslogPort, up.SyslogServerName = 10514, "collector.example.org"
	got, err := w.n.Update(ctx, app.ScopeOrg, d.ID, up)
	if err != nil || *got.SyslogPort != 10514 || *got.SyslogServerName != "collector.example.org" || !got.SyslogCAPEMSet ||
		got.Checkpoints {
		t.Fatalf("update without syslog_ca_pem: %+v %v", got, err)
	}
	empty := ""
	up.SyslogCAPEM = &empty
	if got, err := w.n.Update(ctx, app.ScopeOrg, d.ID, up); err != nil || got.SyslogCAPEMSet || storedCA() != nil {
		t.Fatalf("update with an empty syslog_ca_pem: %+v %v", got, err)
	}

	for name, mut := range map[string]func(*app.NotificationDestinationInput){
		"private host": func(in *app.NotificationDestinationInput) { in.SyslogHost = "intranet.example.org" },
		"loopback":     func(in *app.NotificationDestinationInput) { in.SyslogHost = "127.0.0.1" },
		"no host":      func(in *app.NotificationDestinationInput) { in.SyslogHost = "" },
		"port":         func(in *app.NotificationDestinationInput) { in.SyslogPort = 70000 },
		"bad pem": func(in *app.NotificationDestinationInput) {
			bad := "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"
			in.SyslogCAPEM = &bad
		},
		"url": func(in *app.NotificationDestinationInput) {
			u := "https://hooks.example.org/x"
			in.URL = &u
		},
	} {
		in := syslogInput("refused " + name)
		mut(&in)
		_, _, err := w.n.Create(ctx, app.ScopeOrg, in)
		wantProblem(t, err, problem.InvalidRequest, name)
	}

	email := app.NotificationDestinationInput{Type: outbound.TypeEmail, Name: "mail", Enabled: true,
		FilterMode: outbound.FilterAll, Recipients: []string{"secops@example.org"}, EmailMinIntervalS: 300,
		Checkpoints: true}
	_, _, err = w.n.Create(ctx, app.ScopeOrg, email)
	wantProblem(t, err, problem.InvalidRequest, "checkpoints on e-mail")
	hook := webhookInput("hook with checkpoints")
	hook.Checkpoints = true
	if h, _, err := w.n.Create(ctx, app.ScopeOrg, hook); err != nil || !h.Checkpoints || h.SyslogHost != nil {
		t.Fatalf("webhook with checkpoints: %+v %v", h, err)
	}

	_, err = w.n.RotateSecret(ctx, app.ScopeOrg, d.ID)
	wantProblem(t, err, problem.InvalidState, "rotate a syslog destination's secret")
	if _, err := w.n.Test(ctx, app.ScopeOrg, d.ID); err != nil {
		t.Fatalf("test request: %v", err)
	}
}

// TestNotificationDestinationSyslogUnresolvable: once the receiver no longer resolves, a syslog destination can still
// be disabled and renamed; enabling it again or moving it to another host is refused while that host does not resolve
// or resolves to a private address (PDK-751 review).
func TestNotificationDestinationSyslogUnresolvable(t *testing.T) {
	w := newNotificationWorld(t, true)
	ctx := stepped(w.org, principal.RoleOrgAdmin)
	w.dns["gone.example.org"] = w.dns["siem.example.org"]
	in := syslogInput("SIEM gone")
	in.SyslogHost = "gone.example.org"
	d, _, err := w.n.Create(ctx, app.ScopeOrg, in)
	if err != nil {
		t.Fatal(err)
	}
	delete(w.dns, "gone.example.org")

	in.Enabled = false
	if got, err := w.n.Update(ctx, app.ScopeOrg, d.ID, in); err != nil || got.Enabled {
		t.Fatalf("disable: %+v %v", got, err)
	}
	in.Name = "SIEM gone paused"
	if got, err := w.n.Update(ctx, app.ScopeOrg, d.ID, in); err != nil || got.Name != in.Name {
		t.Fatalf("rename: %+v %v", got, err)
	}

	enable := in
	enable.Enabled, enable.Cursor = true, app.CursorContinue
	_, err = w.n.Update(ctx, app.ScopeOrg, d.ID, enable)
	wantProblem(t, err, problem.InvalidRequest, "enable with an unresolvable host")
	moved := in
	moved.SyslogHost = "unknown.example.org"
	_, err = w.n.Update(ctx, app.ScopeOrg, d.ID, moved)
	wantProblem(t, err, problem.InvalidRequest, "move to an unresolvable host")

	w.dns["gone.example.org"] = w.dns["intranet.example.org"]
	_, err = w.n.Update(ctx, app.ScopeOrg, d.ID, enable)
	wantProblem(t, err, problem.InvalidRequest, "enable with a host that resolves to a private address")
	moved.SyslogHost = "intranet.example.org"
	_, err = w.n.Update(ctx, app.ScopeOrg, d.ID, moved)
	wantProblem(t, err, problem.InvalidRequest, "move to a host that resolves to a private address")
}

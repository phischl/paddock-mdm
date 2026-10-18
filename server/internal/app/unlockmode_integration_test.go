package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/loginsettings"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestLoginSettingsUnlockMode (plan M8d decision 44): the unlock mode defaults to tpm_pin, is changed with
// settings.login_changed recording it, is kept when the request omits it, and an unknown mode is refused.
func TestLoginSettingsUnlockMode(t *testing.T) {
	w := newHistoryWorld(t)
	cur, err := w.settings.Get(w.admin)
	if err != nil || cur.DiskUnlockMode != "tpm_pin" {
		t.Fatalf("default %q, %v", cur.DiskUnlockMode, err)
	}
	update := func(mode *string) error { return setUnlockMode(t, w, mode) }
	if err := update(ptr("tpm")); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("unknown mode: %v", err)
	}
	if err := update(ptr("tpm_only")); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := w.super.QueryRow(context.Background(), `SELECT payload -> 'params' FROM outbox WHERE payload ->> 'code' = 'settings.login_changed'
		AND payload ->> 'outcome' = 'success' AND payload -> 'target' ->> 'id' = $1 ORDER BY id DESC LIMIT 1`, w.org.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	_ = json.Unmarshal(raw, &params)
	if params["disk_unlock_mode"] != "tpm_only" {
		t.Fatalf("params %v", params)
	}
	if err := update(nil); err != nil {
		t.Fatal(err)
	}
	if cur, _ := w.settings.Get(w.admin); cur.DiskUnlockMode != "tpm_only" {
		t.Fatalf("an omitted mode changed it to %q", cur.DiskUnlockMode)
	}
}

// setUnlockMode changes only the unlock mode (nil: none) of the organization's login settings.
func setUnlockMode(t *testing.T, w historyWorld, mode *string) error {
	t.Helper()
	cur, err := w.settings.Get(w.admin)
	if err != nil {
		return err
	}
	var hours *int
	if cur.RotateAfterRevealHours != nil {
		h := int(*cur.RotateAfterRevealHours)
		hours = &h
	}
	_, err = w.settings.Update(w.admin, loginsettings.Settings{
		HelloEnabled: cur.HelloEnabled, HelloPinMinLength: int(cur.HelloPinMinLength), UserLockSessionAction: cur.UserLockSessionAction,
		BreakGlassAccounts: cur.BreakGlassAccounts, SudoersDAllowlist: cur.SudoersDAllowlist, SudoLectureText: cur.SudoLectureText,
		LocalAdminUsername: cur.LocalAdminUsername, LocalAdminRotationDays: int(cur.LocalAdminRotationDays),
		RotateAfterRevealHours: hours, NoticeText: cur.NoticeText, BootPinMinLength: int(cur.BootPinMinLength), DiskUnlockMode: mode,
	})
	return err
}

// TestDeclarativeKeepsLoginHistoryAndUnlockMode (plan M8d decisions 15 and 44): a document that omits the unlock
// mode and cannot express the login history leaves both as stored; a document with the mode applies it.
func TestDeclarativeKeepsLoginHistoryAndUnlockMode(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	if _, err := h.super.Exec(context.Background(), `UPDATE organization_login_settings SET login_history_enabled = true,
		login_history_days = 30, disk_unlock_mode = 'tpm_only' WHERE organization_id = $1`, h.org); err != nil {
		t.Fatal(err)
	}
	doc := h.export(t, admin)
	if doc.Settings.Login.DiskUnlockMode != "tpm_only" {
		t.Fatalf("export %+v", doc.Settings.Login)
	}
	doc.Settings.Login.DiskUnlockMode = ""
	doc.Settings.Login.HelloEnabled = !doc.Settings.Login.HelloEnabled
	ctx := principal.With(context.Background(), admin)
	if _, _, err := h.config.Apply(ctx, raw(t, doc), ""); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, `SELECT count(*) FROM organization_login_settings WHERE organization_id = $1 AND login_history_enabled
		AND login_history_days = 30 AND disk_unlock_mode = 'tpm_only'`, h.org); n != 1 {
		t.Fatal("the document changed the login history or the unlock mode it omits")
	}
	doc = h.export(t, admin)
	doc.Settings.Login.DiskUnlockMode = "tpm_pin"
	if _, _, err := h.config.Apply(ctx, raw(t, doc), ""); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, "SELECT count(*) FROM organization_login_settings WHERE organization_id = $1 AND disk_unlock_mode = 'tpm_pin'", h.org); n != 1 {
		t.Fatal("the document's unlock mode was not applied")
	}
}

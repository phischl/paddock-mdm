package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// reportOnly inserts an adopted, report-only device.
func (w nameWorld) reportOnly(t *testing.T, org uuid.UUID, hostname, state string) uuid.UUID {
	t.Helper()
	id := w.device(t, org, hostname, state)
	if _, err := w.super.Exec(context.Background(), "UPDATE device SET enrollment_method = 'adopted', config_mode = 'report_only' WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (w nameWorld) enforce(p principal.Principal, id uuid.UUID, hostname string) error {
	_, err := w.devices.Enforce(principal.With(context.Background(), p), id, hostname)
	return err
}

// attention returns the detail of the report_only attention condition of device id ("" without one).
func (w nameWorld) reportOnlyAttention(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var detail string
	err := w.super.QueryRow(context.Background(), "SELECT detail FROM attention_condition WHERE kind = 'report_only' AND device_id = $1", id).Scan(&detail)
	if err != nil && !strings.Contains(err.Error(), "no rows") {
		t.Fatal(err)
	}
	return detail
}

// TestEnforceDevice (plan M11 decision 42): an operator enables enforcement with the device's hostname; the attempt is
// one device.enforcement_enabled with hostname, enrollment_method and report_only_since, the device is recompiled and
// the report_only attention condition ends.
func TestEnforceDevice(t *testing.T) {
	w := newNameWorld(t)
	dev := w.reportOnly(t, w.org, "lt-adopted", "active")
	var enrolled time.Time
	if err := w.super.QueryRow(context.Background(), "SELECT enrolled_at FROM device WHERE id = $1", dev).Scan(&enrolled); err != nil {
		t.Fatal(err)
	}
	if got := w.reportOnlyAttention(t, dev); got != "adopted" {
		t.Fatalf("attention detail %q, want adopted", got)
	}

	got := w.during(t, func() {
		d, err := w.devices.Enforce(principal.With(context.Background(), w.operator), dev, "lt-adopted")
		if err != nil {
			t.Fatalf("enforce = %v", err)
		}
		if d.ConfigMode != "enforce" || d.ConfigModeChangedAt == nil || d.EnrollmentMethod != "adopted" {
			t.Fatalf("device %+v", d)
		}
	})
	if strings.Join(got, ",") != "device.enforcement_enabled:success:" {
		t.Fatalf("actions %v", got)
	}
	ev := w.lastEvent(t)
	if ev.Params["hostname"] != "lt-adopted" || ev.Params["enrollment_method"] != "adopted" ||
		ev.Params["report_only_since"] != enrolled.UTC().Format(time.RFC3339) || ev.Target == nil || ev.Target.Display != "lt-adopted" {
		t.Fatalf("event %+v", ev)
	}
	if n := w.recompiles(t, dev); n != 1 {
		t.Fatalf("%d recompiles, want 1", n)
	}
	if got := w.reportOnlyAttention(t, dev); got != "" {
		t.Fatalf("attention after enforce: %q", got)
	}
}

// TestEnforceDeviceRefusals: a wrong hostname, an enforced device, a pending report-only device, an auditor and a
// foreign device are refused; every attempt is exactly one audited event and changes nothing.
func TestEnforceDeviceRefusals(t *testing.T) {
	w := newNameWorld(t)
	dev := w.reportOnly(t, w.org, "lt-adopted", "active")
	enforced := w.device(t, w.org, "lt-enforced", "active")
	pending := w.reportOnly(t, w.org, "lt-pending", "pending")

	got := w.during(t, func() {
		if err := w.enforce(w.operator, dev, "lt-adopte"); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("wrong hostname = %v", err)
		}
		if err := w.enforce(w.operator, enforced, "lt-enforced"); !errors.Is(err, problem.InvalidState) {
			t.Errorf("enforced device = %v", err)
		}
		if err := w.enforce(w.operator, pending, "lt-pending"); !errors.Is(err, problem.InvalidState) {
			t.Errorf("pending device = %v", err)
		}
		if err := w.enforce(w.account(t, principal.RoleOrgAuditor, false), dev, "lt-adopted"); !errors.Is(err, problem.Forbidden) {
			t.Errorf("auditor = %v", err)
		}
	})
	want := "device.enforcement_enabled:failure:invalid_request,device.enforcement_enabled:failure:invalid_state," +
		"device.enforcement_enabled:failure:invalid_state,device.enforcement_enabled:denied:forbidden"
	if strings.Join(got, ",") != want {
		t.Fatalf("actions %v", got)
	}
	var mode string
	if err := w.super.QueryRow(context.Background(), "SELECT config_mode FROM device WHERE id = $1", dev).Scan(&mode); err != nil || mode != "report_only" {
		t.Fatalf("mode after refusals %q, %v", mode, err)
	}

	other := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'B', 'active')",
		other, "b"+other.String()[24:]); err != nil {
		t.Fatal(err)
	}
	foreign := w.reportOnly(t, other, "foreign", "active")
	if err := w.enforce(w.operator, foreign, "foreign"); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign device = %v", err)
	}
}

package app_test

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

func newRolloutSettings(t *testing.T, h harness, development bool) *app.RolloutSettings {
	t.Helper()
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return app.NewRolloutSettings(h.runner, pool, development)
}

func (h harness) group(t *testing.T, org uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, $3)",
		id, org, "g-"+id.String()); err != nil {
		t.Fatal(err)
	}
	return id
}

func rolloutInput(canary *uuid.UUID) app.RolloutConfig {
	return app.RolloutConfig{
		Settings: configrollout.Settings{Enabled: true, Waves: []int{5, 50, 100}, MinWaveMinutes: 30,
			FailureThresholdPercent: 4, FailureThresholdMin: 2},
		CanaryDeviceGroupID: canary,
	}
}

func TestRolloutSettingsDefaultsWithoutRow(t *testing.T) {
	h := newHarness(t)
	r := newRolloutSettings(t, h, false)
	got, err := r.Get(h.admin(principal.RoleOrgAuditor))
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || !slices.Equal(got.Waves, []int{1, 10, 50, 100}) || got.MinWaveMinutes != 60 ||
		got.FailureThresholdPercent != 2 || got.FailureThresholdMin != 3 || got.CanaryDeviceGroupID != nil || got.UpdatedAt != nil {
		t.Fatalf("defaults %+v", got)
	}
}

func TestRolloutSettingsUpdateRecordsEveryField(t *testing.T) {
	h := newHarness(t)
	r := newRolloutSettings(t, h, false)
	group := h.group(t, h.org)
	got, err := r.Update(h.admin(principal.RoleOrgAdmin), rolloutInput(&group))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || !slices.Equal(got.Waves, []int{5, 50, 100}) || got.MinWaveMinutes != 30 ||
		got.CanaryDeviceGroupID == nil || *got.CanaryDeviceGroupID != group || got.UpdatedAt == nil {
		t.Fatalf("updated %+v", got)
	}
	ev := expectOne(t, h, audit.OutcomeSuccess, "")
	if ev.Code != audit.CodeSettingsRolloutChanged {
		t.Fatalf("code %s", ev.Code)
	}
	def, _ := audit.Lookup(audit.CodeSettingsRolloutChanged)
	for _, k := range def.Params {
		if _, ok := ev.Params[k]; !ok {
			t.Errorf("param %s missing from %v", k, ev.Params)
		}
	}
	if ev.Params["canary_device_group_id"] != group.String() {
		t.Fatalf("canary param %v", ev.Params["canary_device_group_id"])
	}
	back, err := r.Get(h.admin(principal.RoleOrgOperator))
	if err != nil || back.MinWaveMinutes != 30 {
		t.Fatalf("reload %+v %v", back, err)
	}
}

func TestRolloutSettingsValidation(t *testing.T) {
	cases := map[string]struct {
		mutate      func(*app.RolloutConfig)
		development bool
		ok          bool
	}{
		"waves not ending with 100":    {func(c *app.RolloutConfig) { c.Waves = []int{10, 50} }, false, false},
		"minimum below production":     {func(c *app.RolloutConfig) { c.MinWaveMinutes = 14 }, false, false},
		"minimum 15 in production":     {func(c *app.RolloutConfig) { c.MinWaveMinutes = 15 }, false, true},
		"one minute in development":    {func(c *app.RolloutConfig) { c.MinWaveMinutes = 1 }, true, true},
		"zero minutes in development":  {func(c *app.RolloutConfig) { c.MinWaveMinutes = 0 }, true, false},
		"threshold percent above 100":  {func(c *app.RolloutConfig) { c.FailureThresholdPercent = 101 }, false, false},
		"negative threshold minimum":   {func(c *app.RolloutConfig) { c.FailureThresholdMin = -1 }, false, false},
		"organization-wide, no canary": {func(c *app.RolloutConfig) {}, false, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			r := newRolloutSettings(t, h, c.development)
			in := rolloutInput(nil)
			c.mutate(&in)
			_, err := r.Update(h.admin(principal.RoleOrgAdmin), in)
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				expectOne(t, h, audit.OutcomeSuccess, "")
				return
			}
			if problem.From(err).Code != "invalid_request" {
				t.Fatalf("err %v", err)
			}
			expectOne(t, h, audit.OutcomeFailure, "invalid_request")
		})
	}
}

func TestRolloutSettingsForeignAndUnknownCanaryAreNotFound(t *testing.T) {
	for _, name := range []string{"foreign", "unknown"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			r := newRolloutSettings(t, h, false)
			id := uuid.Must(uuid.NewV7())
			if name == "foreign" {
				other := uuid.Must(uuid.NewV7())
				if _, err := h.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Other', 'active')",
					other, "o"+other.String()[24:]); err != nil {
					t.Fatal(err)
				}
				id = h.group(t, other)
			}
			_, err := r.Update(h.admin(principal.RoleOrgAdmin), rolloutInput(&id))
			if problem.From(err).Code != "not_found" {
				t.Fatalf("err %v", err)
			}
			expectOne(t, h, audit.OutcomeFailure, "not_found")
		})
	}
}

func TestRolloutSettingsOperatorIsDenied(t *testing.T) {
	h := newHarness(t)
	r := newRolloutSettings(t, h, false)
	_, err := r.Update(h.admin(principal.RoleOrgOperator), rolloutInput(nil))
	if problem.From(err).Status != 403 {
		t.Fatalf("err %v", err)
	}
	expectOne(t, h, audit.OutcomeDenied, "forbidden")
	var n int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM organization_rollout_settings WHERE organization_id = $1", h.org).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows %d %v", n, err)
	}
}

func TestRolloutSettingsAreIsolatedPerOrganization(t *testing.T) {
	h := newHarness(t)
	r := newRolloutSettings(t, h, false)
	if _, err := r.Update(h.admin(principal.RoleOrgAdmin), rolloutInput(nil)); err != nil {
		t.Fatal(err)
	}
	other := newHarness(t)
	got, err := r.Get(other.admin(principal.RoleOrgAdmin))
	if err != nil || got.Enabled || got.UpdatedAt != nil {
		t.Fatalf("other organization sees %+v %v", got, err)
	}
}

func TestRolloutSettingsCanaryGroupDeletionSetsNull(t *testing.T) {
	h := newHarness(t)
	r := newRolloutSettings(t, h, false)
	group := h.group(t, h.org)
	if _, err := r.Update(h.admin(principal.RoleOrgAdmin), rolloutInput(&group)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(context.Background(), "DELETE FROM device_group WHERE id = $1", group); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(h.admin(principal.RoleOrgAdmin))
	if err != nil || got.CanaryDeviceGroupID != nil || !got.Enabled {
		t.Fatalf("after deletion %+v %v", got, err)
	}
}

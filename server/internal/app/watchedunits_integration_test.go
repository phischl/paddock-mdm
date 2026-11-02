package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestWatchedUnits (plan M9 decision 38): only an organization administrator with a step-up changes the watched
// units; reserved units, non-services, duplicates and more than 32 are refused naming the cause; a change records
// added and removed once and queues a state change.
func TestWatchedUnits(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	units := app.NewWatchedUnits(h.runner, pool)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	auditor := h.account(t, principal.RoleOrgAuditor, true)
	token := h.create(t, steppedUp, "ci", principal.RoleOrgAdmin)
	tp, _, err := h.tokens.Authenticate(context.Background(), token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	wazuh := []string{"wazuh-agent.service"}
	tooMany := make([]string, app.MaxWatchedUnits+1)
	for i := range tooMany {
		tooMany[i] = "edr-" + strings.Repeat("a", i%5) + string(rune('a'+i/5)) + ".service"
	}

	refused := map[string]struct {
		in   []string
		code *problem.Error
	}{
		"paddockd":  {[]string{"paddockd.service"}, problem.UnitNotAllowed},
		"orbit":     {[]string{"orbit.service"}, problem.UnitNotAllowed},
		"timer":     {[]string{"foo.timer"}, problem.UnitNotAllowed},
		"duplicate": {[]string{"a.service", "a.service"}, problem.InvalidRequest},
		"33 units":  {tooMany, problem.InvalidRequest},
	}
	got := h.during(t, func() {
		if _, err := units.Set(ctx(operator), wazuh); !errors.Is(err, problem.Forbidden) {
			t.Errorf("operator = %v", err)
		}
		if _, err := units.Set(ctx(admin), wazuh); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("admin without step-up = %v", err)
		}
		if _, err := units.Set(ctx(tp), wazuh); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("token = %v", err)
		}
		for name, c := range refused {
			err := func() error { _, err := units.Set(ctx(steppedUp), c.in); return err }()
			if !errors.Is(err, c.code) {
				t.Errorf("%s = %v, want %s", name, err, c.code.Code)
			}
		}
	})
	if n := strings.Count(strings.Join(got, ","), "settings.watched_units_changed"); n != 3+len(refused) {
		t.Fatalf("actions %v", got)
	}
	if _, err := units.Set(ctx(steppedUp), []string{"paddockd.service"}); !strings.Contains(problem.From(err).Detail, "paddockd.service") {
		t.Fatalf("the refusal does not name the unit: %v", err)
	}

	s, err := units.Set(ctx(steppedUp), wazuh)
	if err != nil || !slices.Equal(s.Units, wazuh) || s.UpdatedAt == nil {
		t.Fatalf("set = %+v, %v", s, err)
	}
	ev := h.lastEvent(t)
	if !ev.Actor.StepUp || !slices.Equal(anyStrings(ev.Params["added"]), wazuh) || len(anyStrings(ev.Params["removed"])) != 0 ||
		!slices.Equal(anyStrings(ev.Params["units"]), wazuh) {
		t.Fatalf("event %+v", ev)
	}
	if _, err := units.Set(ctx(steppedUp), []string{"falcon-sensor.service"}); err != nil {
		t.Fatal(err)
	}
	ev = h.lastEvent(t)
	if !slices.Equal(anyStrings(ev.Params["added"]), []string{"falcon-sensor.service"}) || !slices.Equal(anyStrings(ev.Params["removed"]), wazuh) {
		t.Fatalf("replace event %+v", ev)
	}
	s, err = units.Get(ctx(auditor))
	if err != nil || !slices.Equal(s.Units, []string{"falcon-sensor.service"}) {
		t.Fatalf("auditor get = %+v, %v", s, err)
	}
	if s, err = units.Set(ctx(steppedUp), []string{}); err != nil || len(s.Units) != 0 || s.UpdatedAt != nil {
		t.Fatalf("clear = %+v, %v", s, err)
	}
}

func anyStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, len(items))
	for i, it := range items {
		out[i], _ = it.(string)
	}
	return out
}

// TestWatchedUnitsDeclarative: the settings.watched_units section of the document follows the same rule, shows its
// diff in a plan and exports the stored list.
func TestWatchedUnitsDeclarative(t *testing.T) {
	h := newConfigHarness(t)
	operator := h.account(t, principal.RoleOrgOperator, true)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	doc := h.export(t, steppedUp)
	if doc.Settings.WatchedUnits == nil || len(*doc.Settings.WatchedUnits) != 0 {
		t.Fatalf("exported units %v", doc.Settings.WatchedUnits)
	}
	want := []string{"wazuh-agent.service"}
	doc.Settings.WatchedUnits = &want
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	if _, _, err := h.config.Apply(ctx(operator), raw(t, doc), ""); !errors.Is(err, problem.Forbidden) ||
		!strings.HasPrefix(problem.From(err).Detail, "/settings/watched_units: ") {
		t.Fatalf("operator = %v", err)
	}
	if _, _, err := h.config.Apply(ctx(admin), raw(t, doc), ""); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("admin without step-up = %v", err)
	}
	plan, err := h.config.Plan(ctx(steppedUp), raw(t, doc))
	if err != nil || len(plan.Changes) != 1 || plan.Changes[0].Section != "settings.watched_units" {
		t.Fatalf("dry-run plan %+v, %v", plan, err)
	}
	bad := []string{"orbit.service"}
	doc.Settings.WatchedUnits = &bad
	if _, _, err := h.config.Apply(ctx(steppedUp), raw(t, doc), ""); !errors.Is(err, problem.UnitNotAllowed) ||
		!strings.HasPrefix(problem.From(err).Detail, "/settings/watched_units: ") {
		t.Fatalf("reserved unit = %v", err)
	}
	doc.Settings.WatchedUnits = &want
	if _, _, err := h.config.Apply(ctx(steppedUp), raw(t, doc), ""); err != nil {
		t.Fatalf("stepped-up admin = %v", err)
	}
	if got := h.export(t, steppedUp).Settings.WatchedUnits; got == nil || !slices.Equal(*got, want) {
		t.Fatalf("exported units %v", got)
	}
	plan, err = h.config.Plan(ctx(steppedUp), raw(t, doc))
	if err != nil || len(plan.Changes) != 0 {
		t.Fatalf("plan of an unchanged list: %+v, %v", plan, err)
	}
	empty := []string{}
	doc.Settings.WatchedUnits = &empty
	if _, _, err := h.config.Apply(ctx(steppedUp), raw(t, doc), ""); err != nil {
		t.Fatal(err)
	}
	if got := h.export(t, steppedUp).Settings.WatchedUnits; got == nil || len(*got) != 0 {
		t.Fatalf("exported units after clearing %v", got)
	}
}

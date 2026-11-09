package compiler_test

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
)

// TestRolloutOverlaySoftwareAssignments (plan M13c decision 3, ADR 0033 amendment 2026-11-05): a rollout staged an
// update of Nano's organization assignment (before: forbid), the creation of Vim's assignment to g1 and the deletion of
// Curl's organization assignment. Outside the wave a device renders the before assignments, inside it the live ones;
// Htop's unstaged assignment is live for both, and the bundle of the device inside names the rollout.
func TestRolloutOverlaySoftwareAssignments(t *testing.T) {
	w := newWorld(t)
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	vim := w.entry("Vim", nil, [4]string{"ubuntu", "*", "*", "vim"})
	curl := w.entry("Curl", nil, [4]string{"ubuntu", "*", "*", "curl"})
	htop := w.entry("Htop", nil, [4]string{"ubuntu", "*", "*", "htop"})
	nanoRow := w.assign(nano, nil, "required", "latest", nil)
	vimRow := w.assign(vim, w.g1, "required", "latest", nil)
	w.assign(htop, nil, "required", "latest", nil)
	curlRow := uuid.Must(uuid.NewV7())

	rollout, changeSet := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	plan := map[string]any{"changes": []map[string]any{
		{"section": "software_assignments", "key": `[null,"Curl","organization",null]`, "action": "delete"},
		{"section": "software_assignments", "key": `[null,"Nano","organization",null]`, "action": "update"},
		{"section": "software_assignments", "key": `["g1","Vim","device_group",null]`, "action": "create"},
	}, "created": 1, "updated": 1, "deleted": 1}
	before := map[string]map[string]any{"software_assignments": {
		`[null,"Curl","organization",null]`: map[string]any{"id": curlRow, "entry": "Curl",
			"target": map[string]any{"type": "organization"}, "intent": "required", "update_rule": "latest", "version": nil, "reason": ""},
		`[null,"Nano","organization",null]`: map[string]any{"id": nanoRow, "entry": "Nano",
			"target": map[string]any{"type": "organization"}, "intent": "forbid", "update_rule": "latest", "version": nil, "reason": ""},
	}}
	rows := map[string]configrollout.StagedAssignment{
		`[null,"Curl","organization",null]`: {ID: curlRow, Entry: curl},
		`[null,"Nano","organization",null]`: {ID: nanoRow, Entry: nano},
		`["g1","Vim","device_group",null]`:  {ID: vimRow, Entry: vim, Target: &w.g1},
	}
	in, out := w.softwareRollout(rollout, changeSet, plan, before, rows, w.g1)

	intents := func(dev uuid.UUID) map[string]string {
		got := map[string]string{}
		s := w.fetch(dev).Software
		for _, name := range []string{"nano", "vim", "curl", "htop"} {
			if p := pkgOf(s, name); p != nil {
				got[name] = p.Intent
			}
		}
		return got
	}
	if got := intents(in); len(got) != 3 || got["nano"] != bundle.SoftwareRequired || got["vim"] != bundle.SoftwareRequired ||
		got["htop"] != bundle.SoftwareRequired {
		t.Fatalf("inside the wave %v", got)
	}
	if got := intents(out); len(got) != 3 || got["nano"] != bundle.SoftwareForbid || got["curl"] != bundle.SoftwareRequired ||
		got["htop"] != bundle.SoftwareRequired {
		t.Fatalf("outside the wave %v", got)
	}
	stagedWorld{world: w}.expectRollout(in, &rollout)
	stagedWorld{world: w}.expectRollout(out, nil)
}

// softwareRollout stores a running rollout of a change set with plan and before and the rows of its staged
// assignments, enrolls one device inside the first wave (50 %) and one outside it in groups, and compiles.
func (w *world) softwareRollout(rollout, changeSet uuid.UUID, plan map[string]any, before map[string]map[string]any,
	rows map[string]configrollout.StagedAssignment, groups ...uuid.UUID) (in, out uuid.UUID) {
	w.t.Helper()
	planJSON, _ := json.Marshal(plan)
	beforeJSON, _ := json.Marshal(before)
	rowsJSON, _ := json.Marshal(rows)
	w.exec(`INSERT INTO change_set (id, organization_id, actor, source, created_n, updated_n, deleted_n, sections, plan, before, rollout)
		VALUES ($1, $2, '{"type":"admin","display":"a"}', 'session', 1, 1, 1, '{software_assignments}', $3, $4, 'staged')`,
		changeSet, w.org, planJSON, beforeJSON)
	w.exec(`INSERT INTO config_rollout (id, organization_id, change_set_id, waves, min_wave_minutes, failure_threshold_percent,
		failure_threshold_min, status, started_by, staged_assignments) VALUES ($1, $2, $3, '{50,100}', 60, 2, 3, 'running', 'a', $4)`,
		rollout, w.org, changeSet, rowsJSON)
	for in == uuid.Nil || out == uuid.Nil {
		d := w.v2Device("{1,2}", groups...)
		w.ubuntu(d, "amd64")
		if configrollout.Bucket(d, rollout) < 50 {
			if in == uuid.Nil {
				in = d
			}
		} else if out == uuid.Nil {
			out = d
		}
	}
	w.mustCompile(statechange.ScopeOrg, w.org)
	return in, out
}

// TestRolloutOverlaySoftwareUserRenamed (PDK-808 review 1): identity sync renames the user of a staged update while
// the rollout runs. The overlay matches the live row and the before item by the IDs the rollout recorded, so a device
// of that user outside the wave keeps the before-state (forbid) and one inside gets the live state (required).
func TestRolloutOverlaySoftwareUserRenamed(t *testing.T) {
	w := newWorld(t)
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	user := w.user("erin", false)
	row := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_assignment (id, organization_id, catalog_entry_id, user_id, intent) VALUES ($1, $2, $3, $4, 'required')`,
		row, w.org, nano, user)
	rawKey, _ := json.Marshal([]any{nil, "Nano", "user", w.username(user)})
	key := string(rawKey)
	rollout, changeSet := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	plan := map[string]any{"changes": []map[string]any{{"section": "software_assignments", "key": key, "action": "update"}}, "updated": 1}
	before := map[string]map[string]any{"software_assignments": {key: map[string]any{"id": row, "entry": "Nano",
		"target": map[string]any{"type": "user", "username": w.username(user)}, "intent": "forbid", "update_rule": "latest", "version": nil, "reason": ""}}}
	w.exec("UPDATE app_user SET username = 'renamed@c.test' WHERE id = $1", user)
	in, out := w.softwareRollout(rollout, changeSet, plan, before,
		map[string]configrollout.StagedAssignment{key: {ID: row, Entry: nano, Target: &user}})
	w.own(in, user)
	w.own(out, user)
	w.mustCompile(statechange.ScopeOrg, w.org)

	intent := func(dev uuid.UUID) string {
		if p := pkgOf(w.fetch(dev).Software, "nano"); p != nil {
			return p.Intent
		}
		return ""
	}
	if got := intent(in); got != bundle.SoftwareRequired {
		t.Fatalf("inside the wave nano is %q", got)
	}
	if got := intent(out); got != bundle.SoftwareForbid {
		t.Fatalf("outside the wave nano is %q, want the before-state", got)
	}
}

// expectRollout asserts that the newest bundle of dev carries rollout (nil: none).
func (w stagedWorld) expectRollout(dev uuid.UUID, rollout *uuid.UUID) {
	w.t.Helper()
	got := w.bundleRollout(dev)
	if (got == nil) != (rollout == nil) || (got != nil && *got != *rollout) {
		w.t.Fatalf("bundle of %s carries rollout %v, want %v", dev, got, rollout)
	}
}

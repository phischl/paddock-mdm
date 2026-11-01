package compiler_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
)

// stagedWorld is a world with an open rollout of waves [50,100] (plan M11 decision 30) that staged, against the live
// tables: an update of /etc/acme/a.conf, the creation of /etc/acme/b.conf, the deletion of /etc/acme/c.conf of g1, an
// update of x.service, the creation of the hold of openssl and an update of the update settings. /etc/acme/d.conf is
// not staged. in is inside the wave by bucket, canary by the canary group g2, out is outside.
type stagedWorld struct {
	*world
	rollout, changeSet uuid.UUID
	in, canary, out    uuid.UUID
}

func newStagedWorld(t *testing.T) stagedWorld {
	t.Helper()
	w := stagedWorld{world: newWorld(t), rollout: uuid.Must(uuid.NewV7()), changeSet: uuid.Must(uuid.NewV7())}
	file := func(group any, path, content string) {
		w.exec("INSERT INTO managed_file (id, organization_id, device_group_id, path, mode, content) VALUES ($1, $2, $3, $4, '0644', $5)",
			uuid.Must(uuid.NewV7()), w.org, group, path, content)
	}
	file(nil, "/etc/acme/a.conf", "new")
	file(nil, "/etc/acme/b.conf", "created")
	file(nil, "/etc/acme/d.conf", "live")
	w.exec("INSERT INTO managed_unit (id, organization_id, unit, enabled, active) VALUES ($1, $2, 'x.service', true, true)", uuid.Must(uuid.NewV7()), w.org)
	w.exec("INSERT INTO package_hold (id, organization_id, package) VALUES ($1, $2, 'openssl')", uuid.Must(uuid.NewV7()), w.org)
	w.exec(`INSERT INTO organization_update_settings (organization_id, security_daily_at, regular_schedule, regular_updates_enabled,
		max_random_delay_min) VALUES ($1, '02:30', 'Mon 12:30', false, 0)`, w.org)

	plan := map[string]any{"changes": []map[string]any{
		{"section": "managed_files", "key": `[null,"/etc/acme/a.conf"]`, "action": "update"},
		{"section": "managed_files", "key": `[null,"/etc/acme/b.conf"]`, "action": "create"},
		{"section": "managed_files", "key": `["g1","/etc/acme/c.conf"]`, "action": "delete"},
		{"section": "managed_units", "key": `[null,"x.service"]`, "action": "update"},
		{"section": "package_holds", "key": `[null,"openssl"]`, "action": "create"},
		{"section": "settings.updates", "key": "", "action": "update"},
	}, "created": 2, "updated": 3, "deleted": 1}
	before := map[string]map[string]any{
		"managed_files": {
			`[null,"/etc/acme/a.conf"]`: map[string]any{"id": uuid.Must(uuid.NewV7()), "path": "/etc/acme/a.conf", "device_group": nil,
				"mode": "0600", "owner": "root", "group": "adm", "content": "old"},
			`["g1","/etc/acme/c.conf"]`: map[string]any{"id": uuid.Must(uuid.NewV7()), "path": "/etc/acme/c.conf", "device_group": "g1",
				"mode": "0644", "owner": "root", "group": "root", "content": "deleted"},
		},
		"managed_units": {`[null,"x.service"]`: map[string]any{"id": uuid.Must(uuid.NewV7()), "unit": "x.service", "device_group": nil,
			"enabled": false, "active": false}},
		"settings.updates": {"": map[string]any{"security_daily_at": "01:00", "regular_schedule": "Sat 04:00", "regular_updates_enabled": true,
			"max_random_delay_min": 30, "staleness_warning_h": 72, "staleness_critical_h": 168}},
	}
	planJSON, _ := json.Marshal(plan)
	beforeJSON, _ := json.Marshal(before)
	w.exec(`INSERT INTO change_set (id, organization_id, actor, source, created_n, updated_n, deleted_n, sections, plan, before, rollout)
		VALUES ($1, $2, '{"type":"admin","display":"a"}', 'session', 2, 3, 1, '{managed_files}', $3, $4, 'staged')`,
		w.changeSet, w.org, planJSON, beforeJSON)
	w.exec(`INSERT INTO config_rollout (id, organization_id, change_set_id, waves, min_wave_minutes, failure_threshold_percent,
		failure_threshold_min, canary_device_group_id, status, started_by) VALUES ($1, $2, $3, '{50,100}', 60, 2, 3, $4, 'running', 'a')`,
		w.rollout, w.org, w.changeSet, w.g2)
	for w.in == uuid.Nil || w.out == uuid.Nil || w.canary == uuid.Nil {
		d := w.v2Device("{1,2}", w.g1)
		switch {
		case configrollout.Bucket(d, w.rollout) < 50:
			if w.in == uuid.Nil {
				w.in = d
			}
		case w.out == uuid.Nil:
			w.out = d
		case w.canary == uuid.Nil:
			w.canary = d
			w.exec("INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)", w.org, w.g2, d)
		}
	}
	return w
}

// bundleRollout is the config_rollout_id of the device's newest bundle row.
func (w stagedWorld) bundleRollout(dev uuid.UUID) *uuid.UUID {
	w.t.Helper()
	var id *uuid.UUID
	if err := w.super.QueryRow(context.Background(), "SELECT config_rollout_id FROM bundle WHERE device_id = $1 ORDER BY version DESC LIMIT 1", dev).Scan(&id); err != nil {
		w.t.Fatal(err)
	}
	return id
}

// expectLive asserts that dev renders the live tables and its bundle carries rollout (nil: none).
func (w stagedWorld) expectLive(dev uuid.UUID, rollout *uuid.UUID) {
	w.t.Helper()
	b := w.fetch(dev)
	if got := managedIDs(b); got != "file:/etc/acme/a.conf,file:/etc/acme/b.conf,file:/etc/acme/d.conf,unit:x.service" {
		w.t.Fatalf("live resources of %s: %s", dev, got)
	}
	if f := spec[bundle.FileSpec](w.t, b, "file:/etc/acme/a.conf"); f.Content != "new" || f.Mode != "0644" {
		w.t.Fatalf("live a.conf %+v", f)
	}
	if u := spec[bundle.UnitSpec](w.t, b, "unit:x.service"); !u.Enabled || !u.Active {
		w.t.Fatalf("live unit %+v", u)
	}
	if u := b.Updates; u == nil || u.SecurityDailyAt != "02:30" || len(u.Holds) != 1 || u.Holds[0].Package != "openssl" {
		w.t.Fatalf("live updates %+v", u)
	}
	got := w.bundleRollout(dev)
	if (got == nil) != (rollout == nil) || (got != nil && *got != *rollout) {
		w.t.Fatalf("bundle of %s carries rollout %v, want %v", dev, got, rollout)
	}
}

// expectBefore asserts that dev renders the before-state of every staged key, the live unstaged file, and no rollout.
func (w stagedWorld) expectBefore(dev uuid.UUID) {
	w.t.Helper()
	b := w.fetch(dev)
	if got := managedIDs(b); got != "file:/etc/acme/a.conf,file:/etc/acme/c.conf,file:/etc/acme/d.conf,unit:x.service" {
		w.t.Fatalf("overlaid resources of %s: %s", dev, got)
	}
	if f := spec[bundle.FileSpec](w.t, b, "file:/etc/acme/a.conf"); f.Content != "old" || f.Mode != "0600" || f.Group != "adm" {
		w.t.Fatalf("before a.conf %+v", f)
	}
	if f := spec[bundle.FileSpec](w.t, b, "file:/etc/acme/c.conf"); f.Content != "deleted" {
		w.t.Fatalf("before c.conf %+v", f)
	}
	if f := spec[bundle.FileSpec](w.t, b, "file:/etc/acme/d.conf"); f.Content != "live" {
		w.t.Fatalf("unstaged d.conf %+v", f)
	}
	if u := spec[bundle.UnitSpec](w.t, b, "unit:x.service"); u.Enabled || u.Active {
		w.t.Fatalf("before unit %+v", u)
	}
	if u := b.Updates; u == nil || u.SecurityDailyAt != "01:00" || u.MaxRandomDelayMin != 30 || len(u.Holds) != 0 {
		w.t.Fatalf("before updates %+v", u)
	}
	if got := w.bundleRollout(dev); got != nil {
		w.t.Fatalf("bundle of %s outside the wave carries rollout %v", dev, got)
	}
}

// managedIDs are the IDs of the managed file and unit resources of b; the overlay touches no other resource.
func managedIDs(b *bundle.Bundle) string {
	var ids []string
	for _, r := range b.Resources {
		if strings.HasPrefix(r.ID, "file:") || strings.HasPrefix(r.ID, "unit:") {
			ids = append(ids, r.ID)
		}
	}
	return strings.Join(ids, ",")
}

// TestRolloutOverlay (plan M11 decision 30): outside the wave every staged key renders its before-state — an update
// the before item, a creation absent, a deletion the before item (scoped to its group by name), the update settings
// the before settings — and unstaged keys render live; inside the wave (by bucket or canary group) everything is live
// and the bundle row names the rollout.
func TestRolloutOverlay(t *testing.T) {
	w := newStagedWorld(t)
	w.mustCompile(statechange.ScopeOrg, w.org)
	w.expectLive(w.in, &w.rollout)
	w.expectLive(w.canary, &w.rollout)
	w.expectBefore(w.out)
}

// TestRolloutOverlayHaltedCompletedReverted: a halted rollout keeps the split of the wave it reached; a completed or
// reverted rollout applies no overlay.
func TestRolloutOverlayHaltedCompletedReverted(t *testing.T) {
	w := newStagedWorld(t)
	w.exec("UPDATE config_rollout SET status = 'halted' WHERE id = $1", w.rollout)
	w.mustCompile(statechange.ScopeOrg, w.org)
	w.expectLive(w.in, &w.rollout)
	w.expectBefore(w.out)

	for _, status := range []string{"completed", "reverted"} {
		w.exec("UPDATE config_rollout SET status = $2 WHERE id = $1", w.rollout, status)
		w.mustCompile(statechange.ScopeOrg, w.org)
		w.expectLive(w.out, nil)
		w.exec("UPDATE config_rollout SET status = 'halted' WHERE id = $1", w.rollout)
		w.mustCompile(statechange.ScopeOrg, w.org)
		w.expectBefore(w.out)
	}
}

// TestRolloutOverlayNeverWidens (PDK-157 review 1, B1/B2): outside the wave the overlay never ships a before item on a
// denied path (ADR 0034 decision 2) or one whose device group is gone.
func TestRolloutOverlayNeverWidens(t *testing.T) {
	w := newStagedWorld(t)
	changes, _ := json.Marshal([]map[string]any{
		{"section": "managed_files", "key": `[null,"/etc/sudoers.d/legacy"]`, "action": "delete"},
		{"section": "managed_files", "key": `["gone","/etc/acme/gone.conf"]`, "action": "delete"},
	})
	before, _ := json.Marshal(map[string]any{
		`[null,"/etc/sudoers.d/legacy"]`: map[string]any{"id": uuid.Must(uuid.NewV7()), "path": "/etc/sudoers.d/legacy", "device_group": nil,
			"mode": "0440", "owner": "root", "group": "root", "content": "ALL ALL=(ALL) NOPASSWD: ALL"},
		`["gone","/etc/acme/gone.conf"]`: map[string]any{"id": uuid.Must(uuid.NewV7()), "path": "/etc/acme/gone.conf", "device_group": "gone",
			"mode": "0644", "owner": "root", "group": "root", "content": "gone"},
	})
	w.exec(`UPDATE change_set SET plan = jsonb_set(plan, '{changes}', (plan->'changes') || $2::jsonb),
		before = jsonb_set(before, '{managed_files}', (before->'managed_files') || $3::jsonb) WHERE id = $1`, w.changeSet, changes, before)
	w.mustCompile(statechange.ScopeOrg, w.org)
	w.expectBefore(w.out)
}

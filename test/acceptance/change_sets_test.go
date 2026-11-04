package acceptance

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// changeSetView is the part of a change set the gate reads.
type changeSetView struct {
	ID              string  `json:"id"`
	Rollout         string  `json:"rollout"`
	BeforeAvailable bool    `json:"before_available"`
	RevertedBy      *string `json:"reverted_by"`
	Summary         struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
		Deleted int `json:"deleted"`
	} `json:"summary"`
	Plan struct {
		Changes []struct {
			Section string `json:"section"`
			Action  string `json:"action"`
			Fields  []struct {
				Name   string `json:"name"`
				Before any    `json:"before"`
				After  any    `json:"after"`
			} `json:"fields"`
		} `json:"changes"`
	} `json:"plan"`
}

// TestChangeSetsEveryWrite is the gate of plan M11 decisions 17 to 20 (PDK-154): every single-resource write records
// a change set with exactly one audit event that names it, the update of a managed file keeps its before-state, a
// device group deletion lists every cascaded definition in one change set.
func TestChangeSetsEveryWrite(t *testing.T) {
	admin, _ := gateOrg(t, "m11-cs")

	changeSet := func(t *testing.T, res env.Response, code string) changeSetView {
		t.Helper()
		ev := expectOneEvent(t, admin.Portal, res.RequestID, code, "success")
		id, _ := ev.Params["change_set_id"].(string)
		if id == "" {
			t.Fatalf("%s carries no change_set_id: %+v", code, ev.Params)
		}
		got := call(t, admin.Portal, http.MethodGet, "/api/v1/change-sets/"+id, nil)
		expectStatus(t, got, http.StatusOK, "")
		var cs changeSetView
		if err := got.JSON(&cs); err != nil {
			t.Fatal(err)
		}
		if cs.ID != id || cs.Rollout != "immediate" || !cs.BeforeAvailable || cs.RevertedBy != nil {
			t.Fatalf("change set %+v for %s", cs, id)
		}
		return cs
	}

	res := call(t, admin.Portal, http.MethodPost, "/api/v1/managed-files", map[string]any{"path": "/etc/paddock-gates/m11-cs.conf", "content": "first\n"})
	expectStatus(t, res, http.StatusCreated, "")
	fileID := responseID(t, res).String()
	cs := changeSet(t, res, "managed_file.created")
	if cs.Summary.Created != 1 || cs.Summary.Updated != 0 || len(cs.Plan.Changes) != 1 || cs.Plan.Changes[0].Action != "create" {
		t.Fatalf("create change set %+v", cs)
	}

	res = call(t, admin.Portal, http.MethodPatch, "/api/v1/managed-files/"+fileID, map[string]any{"content": "second\n"})
	expectStatus(t, res, http.StatusOK, "")
	cs = changeSet(t, res, "managed_file.updated")
	if cs.Summary.Updated != 1 || len(cs.Plan.Changes) != 1 || cs.Plan.Changes[0].Action != "update" {
		t.Fatalf("update change set %+v", cs)
	}
	for _, f := range cs.Plan.Changes[0].Fields {
		if f.Name == "content" && (f.Before == "first\n" || f.After == "second\n") {
			t.Fatalf("the plan shows the file content: %+v", f)
		}
	}

	res = call(t, admin.Portal, http.MethodDelete, "/api/v1/managed-files/"+fileID, nil)
	expectStatus(t, res, http.StatusNoContent, "")
	if cs = changeSet(t, res, "managed_file.deleted"); cs.Summary.Deleted != 1 || cs.Plan.Changes[0].Action != "delete" {
		t.Fatalf("delete change set %+v", cs)
	}

	t.Run("device group deletion cascades into one change set", func(t *testing.T) {
		res := call(t, admin.Portal, http.MethodPost, "/api/v1/device-groups", map[string]any{"name": uniqueName("m11 cs group")})
		expectStatus(t, res, http.StatusCreated, "")
		group := responseID(t, res).String()
		changeSet(t, res, "device_group.created")
		res = call(t, admin.Portal, http.MethodPost, "/api/v1/managed-files",
			map[string]any{"path": "/etc/paddock-gates/m11-cs-group.conf", "content": "group\n", "device_group_id": group})
		expectStatus(t, res, http.StatusCreated, "")
		prof := profile(t, admin.Portal, "restricted", "/usr/bin/systemctl restart m11.service")
		res = call(t, admin.Portal, http.MethodPost, "/api/v1/profile-assignments",
			map[string]any{"profile_id": prof, "subject_type": "global", "device_group_id": group})
		expectStatus(t, res, http.StatusCreated, "")

		res = call(t, admin.Portal, http.MethodDelete, "/api/v1/device-groups/"+group, nil)
		expectStatus(t, res, http.StatusNoContent, "")
		cs := changeSet(t, res, "device_group.deleted")
		sections := map[string]int{}
		for _, c := range cs.Plan.Changes {
			if c.Action != "delete" {
				t.Fatalf("cascade change set holds %+v", c)
			}
			sections[c.Section]++
		}
		if cs.Summary.Deleted != 3 || sections["device_groups"] != 1 || sections["managed_files"] != 1 || sections["profile_assignments"] != 1 {
			t.Fatalf("cascade change set: %+v, sections %v", cs, sections)
		}
	})

	t.Run("a refused write records no change set", func(t *testing.T) {
		before := listTotal(t, admin.Portal, "/api/v1/change-sets")
		res := call(t, admin.Portal, http.MethodPost, "/api/v1/managed-files", map[string]any{"path": "/proc/forbidden", "content": "x"})
		expectStatus(t, res, http.StatusUnprocessableEntity, "path_not_allowed")
		ev := expectOneEvent(t, admin.Portal, res.RequestID, "managed_file.created", "failure")
		if _, ok := ev.Params["change_set_id"]; ok {
			t.Fatalf("a refused write names a change set: %+v", ev.Params)
		}
		if after := listTotal(t, admin.Portal, "/api/v1/change-sets"); after != before {
			t.Fatalf("%d change sets after a refused write, want %d", after, before)
		}
	})

	t.Run("rollout filter", func(t *testing.T) {
		all := listTotal(t, admin.Portal, "/api/v1/change-sets")
		if n := listTotal(t, admin.Portal, "/api/v1/change-sets?"+url.Values{"rollout": {"immediate"}}.Encode()); n != all || n == 0 {
			t.Fatalf("rollout=immediate lists %d of %d change sets", n, all)
		}
		if n := listTotal(t, admin.Portal, "/api/v1/change-sets?rollout=staged&rollout=urgent"); n != 0 {
			t.Fatalf("rollout=staged,urgent lists %d change sets", n)
		}
		expectStatus(t, call(t, admin.Portal, http.MethodGet, "/api/v1/change-sets?rollout=bogus", nil), http.StatusBadRequest, "invalid_request")
	})
}

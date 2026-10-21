package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type ownersWorld struct {
	privilegesHarness
	pool    *db.OrgPool
	devices *app.Devices
	users   *app.Users
	device  uuid.UUID
}

func newOwnersWorld(t *testing.T) ownersWorld {
	t.Helper()
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	w := ownersWorld{privilegesHarness: h, pool: pool, devices: app.NewDevices(h.runner, pool, nil), users: app.NewUsers(h.runner, pool, nil),
		device: uuid.Must(uuid.NewV7())}
	if _, err := h.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')",
		w.device, h.org, "owned-"+w.device.String()[24:]); err != nil {
		t.Fatal(err)
	}
	return w
}

// user inserts a local user of org with the given username suffix.
func (w ownersWorld) user(t *testing.T, org uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), `INSERT INTO app_user (id, organization_id, authentik_pk, username, display_name, source)
		VALUES ($1, $2, $3, $4, $5, 'local')`, id, org, "o"+id.String()[24:], name+"-"+id.String()[24:], "Display "+name); err != nil {
		t.Fatal(err)
	}
	return id
}

func usernames(users []pgstore.AppUser) []string {
	out := []string{}
	for _, u := range users {
		out = append(out, u.Username)
	}
	return out
}

// TestDeviceOwners: an operator sets and changes the owners (audited with added, removed and owners); more than 20,
// an unknown user and a user of another organization are invalid requests; an auditor is forbidden; the device list
// filters and searches by owner, the user's device list shows it, and deleting the user removes the ownership.
func TestDeviceOwners(t *testing.T) {
	w := newOwnersWorld(t)
	operator := w.account(t, principal.RoleOrgOperator, false)
	auditor := w.account(t, principal.RoleOrgAuditor, false)
	ctx := principal.With(context.Background(), operator)
	a, b := w.user(t, w.org, "alice"), w.user(t, w.org, "bob")

	d, err := w.devices.SetOwners(ctx, w.device, []uuid.UUID{b, a, a})
	if err != nil {
		t.Fatalf("set owners = %v", err)
	}
	if got := usernames(d.Owners); len(got) != 2 || !slices.IsSorted(got) {
		t.Fatalf("owners = %v", got)
	}
	ev := w.lastEvent(t)
	if ev.Code != "device.owners_changed" || len(ev.Params["added"].([]any)) != 2 || len(ev.Params["removed"].([]any)) != 0 ||
		ev.Params["hostname"] != "owned-"+w.device.String()[24:] {
		t.Fatalf("event %+v", ev)
	}
	if _, err := w.devices.SetOwners(ctx, w.device, []uuid.UUID{a}); err != nil {
		t.Fatal(err)
	}
	ev = w.lastEvent(t)
	if removed := ev.Params["removed"].([]any); len(removed) != 1 || !strings.HasPrefix(removed[0].(string), "bob-") ||
		len(ev.Params["added"].([]any)) != 0 || len(ev.Params["owners"].([]any)) != 1 {
		t.Fatalf("second event %+v", ev)
	}

	many := make([]uuid.UUID, app.MaxDeviceOwners+1)
	for i := range many {
		many[i] = uuid.Must(uuid.NewV7())
	}
	if _, err := w.devices.SetOwners(ctx, w.device, many); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("21 owners = %v", err)
	}
	foreign := w.user(t, w.otherOrg(t), "mallory")
	if _, err := w.devices.SetOwners(ctx, w.device, []uuid.UUID{a, foreign}); !errors.Is(err, problem.InvalidRequest) ||
		problem.From(err).Detail != "unknown user "+foreign.String() {
		t.Fatalf("foreign user = %v", err)
	}
	if _, err := w.devices.SetOwners(principal.With(context.Background(), auditor), w.device, []uuid.UUID{b}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor = %v", err)
	}
	if _, err := w.devices.SetOwners(ctx, uuid.Must(uuid.NewV7()), []uuid.UUID{a}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown device = %v", err)
	}

	page := app.ListPage{Sort: "hostname", Limit: 10}
	listed, err := w.devices.List(ctx, app.DeviceQuery{Page: page, OwnerID: &a})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].Device.ID != w.device || !strings.Contains(string(listed.Items[0].Owners), `"username": "alice-`) {
		t.Fatalf("owner filter = %+v, %v", listed, err)
	}
	if listed, err = w.devices.List(ctx, app.DeviceQuery{Page: page, OwnerID: &b}); err != nil || len(listed.Items) != 0 {
		t.Fatalf("filter by a former owner = %+v, %v", listed.Items, err)
	}
	pattern := "%" + "alice-" + a.String()[24:] + "%"
	search := page
	search.QPattern = &pattern
	if listed, err = w.devices.List(ctx, app.DeviceQuery{Page: search}); err != nil || len(listed.Items) != 1 || listed.Count != 1 {
		t.Fatalf("search by owner username = %+v, %v", listed.Items, err)
	}
	owned, err := w.users.ListOwnedDevices(ctx, a, app.DeviceQuery{Page: page})
	if err != nil || len(owned.Items) != 1 || owned.Count != 1 {
		t.Fatalf("owned devices = %+v, %v", owned, err)
	}
	if _, err := w.users.ListOwnedDevices(ctx, foreign, app.DeviceQuery{Page: page}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("owned devices of a foreign user = %v", err)
	}

	before := len(w.actions(t))
	if err := w.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.DeleteAppUser(ctx, a)
		return err
	}); err != nil {
		t.Fatalf("delete user = %v", err)
	}
	got, err := w.devices.Get(ctx, w.device)
	if err != nil || len(got.Owners) != 0 {
		t.Fatalf("owners after deleting the user = %v, %v", usernames(got.Owners), err)
	}
	if len(w.actions(t)) != before {
		t.Fatal("deleting the user recorded an owners event")
	}
}

// otherOrg inserts a second organization.
func (w ownersWorld) otherOrg(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Other', 'active')",
		id, "o"+id.String()[24:]); err != nil {
		t.Fatal(err)
	}
	return id
}

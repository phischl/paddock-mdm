package devicecache_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// TestDeleteOrganizationKeys (plan M17 decision 13, amendment k addendum point 2, amendment l point 3): under the
// worker's real ACL user the deletion removes every key of a device that is not offboarded and the organization's time
// ticket, bp: and tt: included. An offboarded device loses only bp:, hb: and au:; its dk:, cmd:, seq:, sd: and nonce:
// stay for its uninstall. Another organization's keys stay. A single DEL that mixes bp: with dk: is refused for the
// worker, which is why the two go in calls of their own.
func TestDeleteOrganizationKeys(t *testing.T) {
	srv := valkeytest.StartACL(t)
	admin, worker := srv.Client(t, "acceptance"), srv.Client(t, "worker")
	ctx := context.Background()
	org, other := uuid.New(), uuid.New()
	dev, leaving, otherDev := uuid.New(), uuid.New(), uuid.New()
	perDevice := func(d uuid.UUID, keyID string) (gone, kept []string) {
		return []string{"bp:" + d.String(), "hb:" + d.String(), "au:" + d.String()},
			[]string{"cmd:" + d.String(), "seq:" + d.String(), "sd:" + d.String(), "dk:" + keyID, "nonce:" + d.String() + ":n1"}
	}
	devGone, devRest := perDevice(dev, "key-a")
	mine := append(append(devGone, devRest...), "tt:"+org.String())
	leavingGone, leavingKept := perDevice(leaving, "key-l")
	theirsGone, theirsRest := perDevice(otherDev, "key-b")
	theirs := append(append(theirsGone, theirsRest...), "tt:"+other.String())
	all := append(append(append(append([]string{}, mine...), leavingGone...), leavingKept...), theirs...)
	for _, k := range all {
		if err := admin.Do(ctx, admin.B().Set().Key(k).Value("x").Build()).Error(); err != nil {
			t.Fatal(err)
		}
	}

	err := worker.Do(ctx, worker.B().Del().Key("dk:key-b", "bp:"+otherDev.String()).Build()).Error()
	if err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Fatalf("a mixed DEL of the worker: %v, want NOPERM", err)
	}

	devices := []devicecache.OffboardDevice{{ID: dev, KeyIDs: []string{"key-a"}}, {ID: leaving, KeyIDs: []string{"key-l"}, Offboarded: true}}
	// nonce: is outside the worker's ACL and expires by itself (amendment l point 2): it is not deleted.
	want := int64(len(mine) - 1 + len(leavingGone))
	n, err := devicecache.New(worker).DeleteOrganization(ctx, org, devices)
	if err != nil || n != want {
		t.Fatalf("DeleteOrganization = %d, %v; want %d", n, err, want)
	}
	count := func(keys []string) int64 {
		n, err := admin.Do(ctx, admin.B().Exists().Key(keys...).Build()).AsInt64()
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if left := count(mine); left != 1 {
		t.Fatalf("%d keys of the device remain, want only its nonce", left)
	}
	if left := count(leavingGone); left != 0 {
		t.Fatalf("%d of bp:, hb:, au: of the offboarded device remain", left)
	}
	if kept := count(leavingKept); kept != int64(len(leavingKept)) {
		t.Fatalf("the offboarded device kept %d of %d keys (dk:, cmd:, seq:, sd:, nonce:)", kept, len(leavingKept))
	}
	if kept := count(theirs); kept != int64(len(theirs)) {
		t.Fatalf("another organization kept %d of %d keys", kept, len(theirs))
	}
	if n, err := devicecache.New(worker).DeleteOrganization(ctx, org, devices); err != nil || n != 0 {
		t.Fatalf("second deletion = %d, %v", n, err)
	}
}

// TestOffboardedDeviceKeys (plan M17 decision 15, amendments l point 3 and n point 2): under the worker's ACL user the
// devices step adds the disarm and the uninstall to cmd:<device>, keeping what is there (a pending disarm stays), and
// caches the device's keys with status offboarded, keeping a live counter; the device's final report deletes dk:,
// cmd:, seq: and sd: again.
func TestOffboardedDeviceKeys(t *testing.T) {
	srv := valkeytest.StartACL(t)
	admin, worker := srv.Client(t, "acceptance"), srv.Client(t, "worker")
	cache, gateway := devicecache.New(worker), devicecache.New(admin)
	ctx := context.Background()
	dev, org, uninstall, disarm, pendingDisarm := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	if err := cache.PutCommand(ctx, dev, pendingDisarm, devicecache.Command{ExpiresAt: now.Add(time.Hour), Envelope: []byte(`{"disarm":0}`)}); err != nil {
		t.Fatal(err)
	}
	if err := cache.RestoreSeq(ctx, dev, 41); err != nil {
		t.Fatal(err)
	}
	year := now.Add(365 * 24 * time.Hour)
	d := devicecache.OffboardedDevice{ID: dev, OrganizationID: org,
		Keys: []devicecache.OffboardedKey{{KeyID: "key-1", PublicKey: []byte{1}}, {KeyID: "key-2", PublicKey: []byte{2}}},
		Commands: []devicecache.OffboardedCommand{
			{ID: disarm, Command: devicecache.Command{ExpiresAt: year, Envelope: []byte(`{"disarm":1}`)}},
			{ID: uninstall, Command: devicecache.Command{ExpiresAt: year, Envelope: []byte(`{"uninstall":1}`)}}}}
	if err := cache.PutOffboardedDevice(ctx, d, 7); err != nil {
		t.Fatal(err)
	}
	cmds, err := gateway.Commands(ctx, dev, now)
	if err != nil || len(cmds) != 3 || string(cmds[uninstall].Envelope) != `{"uninstall":1}` ||
		string(cmds[disarm].Envelope) != `{"disarm":1}` || string(cmds[pendingDisarm].Envelope) != `{"disarm":0}` {
		t.Fatalf("commands %v, %v; want the pending disarm, the disarm and the uninstall", cmds, err)
	}
	if got, ok, err := gateway.PendingCommand(ctx, dev, uninstall); err != nil || !ok || got.ExpiresAt.Unix() != year.Unix() {
		t.Fatalf("PendingCommand = %+v, %v, %v", got, ok, err)
	}
	if _, ok, err := gateway.PendingCommand(ctx, dev, uuid.New()); ok || err != nil {
		t.Fatalf("PendingCommand of an unknown command: %v %v", ok, err)
	}
	for _, k := range d.Keys {
		got, ok, err := gateway.DeviceKey(ctx, k.KeyID)
		if err != nil || !ok || got.Status != devicecache.KeyOffboarded || got.DeviceID != dev || got.OrganizationID != org {
			t.Fatalf("key %s: %+v %v %v", k.KeyID, got, ok, err)
		}
	}
	if seq, err := gateway.NextSeq(ctx, dev); err != nil || seq != 42 {
		t.Fatalf("NextSeq = %d, %v; the live counter must stay", seq, err)
	}
	if err := gateway.MarkDelivered(ctx, dev, 42); err != nil {
		t.Fatal(err)
	}

	if err := cache.DeleteOffboardedDevice(ctx, dev, []string{"key-1", "key-2"}); err != nil {
		t.Fatal(err)
	}
	keys := []string{"cmd:" + dev.String(), "seq:" + dev.String(), "sd:" + dev.String(), "dk:key-1", "dk:key-2"}
	if n, err := admin.Do(ctx, admin.B().Exists().Key(keys...).Build()).AsInt64(); err != nil || n != 0 {
		t.Fatalf("%d keys of the uninstalled device remain (%v)", n, err)
	}
}

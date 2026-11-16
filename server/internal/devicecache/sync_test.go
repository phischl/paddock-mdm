package devicecache_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	vk "github.com/valkey-io/valkey-go"

	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// commandCalls reads the calls of a command from INFO commandstats (0 when it never ran).
func commandCalls(t *testing.T, c vk.Client, command string) int64 {
	t.Helper()
	info, err := c.Do(context.Background(), c.B().Info().Section("commandstats").Build()).ToString()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(info, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "cmdstat_"+command+":calls=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(rest[:strings.IndexByte(rest, ',')], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	return 0
}

// syncFixture is a live device with two keys and an offboarded device with one key and two commands.
type syncFixture struct {
	live       []devicecache.DeviceKeyEntry
	offboarded []devicecache.OffboardedDevice
	device     uuid.UUID // the live device
	leaving    uuid.UUID // the offboarded device
	disarm     uuid.UUID
	uninstall  uuid.UUID
}

func newSyncFixture() syncFixture {
	org, dev, leaving := uuid.New(), uuid.New(), uuid.New()
	f := syncFixture{device: dev, leaving: leaving, disarm: uuid.New(), uninstall: uuid.New()}
	for _, id := range []string{"a-" + dev.String(), "b-" + dev.String()} {
		f.live = append(f.live, devicecache.DeviceKeyEntry{KeyID: id, LastSeq: 7,
			Key: devicecache.DeviceKey{DeviceID: dev, OrganizationID: org, Status: devicecache.KeyActive, PublicKey: []byte(id)}})
	}
	expires := time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second)
	f.offboarded = []devicecache.OffboardedDevice{{ID: leaving, OrganizationID: org,
		Keys: []devicecache.OffboardedKey{{KeyID: "o-" + leaving.String(), PublicKey: []byte{1, 2}}},
		Commands: []devicecache.OffboardedCommand{
			{ID: f.disarm, Command: devicecache.Command{ExpiresAt: expires, Envelope: []byte(`{"payload":"disarm"}`)}},
			{ID: f.uninstall, Command: devicecache.Command{ExpiresAt: expires, Envelope: []byte(`{"payload":"uninstall"}`)}},
		}}}
	return f
}

// sync runs both Syncer methods and returns the sum of what they wrote.
func (f syncFixture) sync(t *testing.T, s *devicecache.Syncer) int {
	t.Helper()
	ctx := context.Background()
	a, err := s.SyncDeviceKeys(ctx, f.live)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.SyncOffboardedDevices(ctx, f.offboarded)
	if err != nil {
		t.Fatal(err)
	}
	return a + b
}

// TestSyncerWritesOnlyWhatDiffers (plan M17 amendment s point 4.1, PDK-1088 AC1): a second sync of unchanged entries
// writes nothing (no HSET, no DEL in INFO commandstats); a deleted dk:, a changed status, a missing cmd: field and a
// missing seq: are written again; an extra cmd: field and a live seq: keep their values.
func TestSyncerWritesOnlyWhatDiffers(t *testing.T) {
	c := valkeytest.Start(t).Client(t)
	ctx := context.Background()
	cache := devicecache.New(c)
	s := devicecache.NewSyncer(cache)
	f := newSyncFixture()

	// seq: and 2 dk: of the live device; seq:, cmd:, dk: of the offboarded device.
	if n := f.sync(t, s); n != 6 {
		t.Fatalf("first sync wrote %d keys, want 6", n)
	}
	hset, del := commandCalls(t, c, "hset"), commandCalls(t, c, "del")
	if n := f.sync(t, s); n != 0 {
		t.Fatalf("second sync wrote %d keys, want 0", n)
	}
	if h, d := commandCalls(t, c, "hset"), commandCalls(t, c, "del"); h != hset || d != del {
		t.Fatalf("second sync ran HSET %d→%d, DEL %d→%d; want no change", hset, h, del, d)
	}
	for _, e := range f.live {
		if k, ok, err := cache.DeviceKey(ctx, e.KeyID); err != nil || !ok || k.Status != devicecache.KeyActive || k.DeviceID != f.device {
			t.Fatalf("live key %s: %+v %v %v", e.KeyID, k, ok, err)
		}
	}
	if k, ok, err := cache.DeviceKey(ctx, "o-"+f.leaving.String()); err != nil || !ok || k.Status != devicecache.KeyOffboarded {
		t.Fatalf("offboarded key: %+v %v %v", k, ok, err)
	}

	do := func(cmd vk.Completed) {
		t.Helper()
		if err := c.Do(ctx, cmd).Error(); err != nil {
			t.Fatal(err)
		}
	}
	do(c.B().Del().Key("dk:" + f.live[0].KeyID).Build())
	if n := f.sync(t, s); n != 1 {
		t.Fatalf("after deleting a dk: the sync wrote %d keys, want 1", n)
	}
	if _, ok, err := cache.DeviceKey(ctx, f.live[0].KeyID); err != nil || !ok {
		t.Fatalf("deleted dk: not rewritten: %v %v", ok, err)
	}

	f.live[1].Key.Status = devicecache.KeyQuarantined
	if n := f.sync(t, s); n != 1 {
		t.Fatalf("after a status change the sync wrote %d keys, want 1", n)
	}
	if k, _, err := cache.DeviceKey(ctx, f.live[1].KeyID); err != nil || k.Status != devicecache.KeyQuarantined {
		t.Fatalf("changed status not rewritten: %+v %v", k, err)
	}

	pending := uuid.New()
	do(c.B().Hdel().Key("cmd:" + f.leaving.String()).Field(f.uninstall.String()).Build())
	do(c.B().Hset().Key("cmd:"+f.leaving.String()).FieldValue().FieldValue(pending.String(), `{"pending":true}`).Build())
	if n := f.sync(t, s); n != 1 {
		t.Fatalf("after removing a cmd: field the sync wrote %d keys, want 1", n)
	}
	fields, err := c.Do(ctx, c.B().Hgetall().Key("cmd:"+f.leaving.String()).Build()).AsStrMap()
	if err != nil || len(fields) != 3 || fields[f.uninstall.String()] == "" || fields[pending.String()] != `{"pending":true}` {
		t.Fatalf("cmd: after the sync: %v %v; want the uninstall added and the extra field kept", fields, err)
	}

	do(c.B().Del().Key("seq:" + f.device.String()).Build())
	do(c.B().Set().Key("seq:" + f.leaving.String()).Value("42").Build())
	if n := f.sync(t, s); n != 1 {
		t.Fatalf("after deleting a seq: the sync wrote %d keys, want 1", n)
	}
	for device, want := range map[uuid.UUID]string{f.device: "7", f.leaving: "42"} {
		if v, err := c.Do(ctx, c.B().Get().Key("seq:"+device.String()).Build()).ToString(); err != nil || v != want {
			t.Fatalf("seq:%s = %q %v, want %s", device, v, err, want)
		}
	}
	if n := f.sync(t, s); n != 0 {
		t.Fatalf("final sync wrote %d keys, want 0", n)
	}
}

// TestSyncerWorkerACL (plan M17 amendment s point 4.1, ADR 0051 amendment 2026-11-16, PDK-1088 AC2): under the real
// template the worker runs the Syncer through its read-only selector (%R~dk:* %R~cmd:* -@all +hgetall). Everything
// else stays refused: HGETALL on other prefixes, other hash reads on dk: and cmd:, key listing, and any write the root
// permissions do not already grant.
func TestSyncerWorkerACL(t *testing.T) {
	srv := valkeytest.StartACL(t)
	worker := srv.Client(t, "worker")
	ctx := context.Background()
	s := devicecache.NewSyncer(devicecache.New(worker))
	f := newSyncFixture()
	if n := f.sync(t, s); n != 6 {
		t.Fatalf("first sync as worker wrote %d keys, want 6", n)
	}
	if n := f.sync(t, s); n != 0 {
		t.Fatalf("second sync as worker wrote %d keys, want 0", n)
	}
	for _, args := range [][]string{
		{"HGETALL", "sess:x"}, {"HGETALL", "et:x"}, {"HGETALL", "bp:x"}, {"HGETALL", "enr:x"},
		{"HGETALL", "seq:x"}, {"HGETALL", "acct-sess:x"},
		{"HGET", "dk:x", "f"}, {"HKEYS", "dk:x"}, {"HVALS", "cmd:x"}, {"HMGET", "cmd:x", "f"}, {"HLEN", "dk:x"},
		{"KEYS", "*"}, {"SCAN", "0"},
		// Writes under the selector's patterns that the root permissions do not grant stay refused.
		{"HSETNX", "dk:x", "f", "v"}, {"HINCRBY", "cmd:x", "f", "1"}, {"HMSET", "dk:x", "f", "v"},
		{"RENAME", "dk:x", "dk:y"}, {"UNLINK", "cmd:x"}, {"EXPIRE", "dk:x", "10"},
	} {
		err := worker.Do(ctx, worker.B().Arbitrary(args...).Build()).Error()
		if err == nil || !strings.Contains(err.Error(), "NOPERM") {
			t.Errorf("worker %v: %v, want NOPERM", args, err)
		}
	}
	// The root permissions are unchanged: the worker still writes and deletes dk: and cmd:.
	for _, args := range [][]string{{"HSET", "dk:probe", "f", "v"}, {"HDEL", "cmd:probe", "f"}, {"DEL", "dk:probe"}} {
		if err := worker.Do(ctx, worker.B().Arbitrary(args...).Build()).Error(); err != nil {
			t.Errorf("worker %v: %v", args, err)
		}
	}
}

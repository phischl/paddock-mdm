package worker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

func platformPool(t *testing.T) *db.PlatformPool {
	t.Helper()
	p, err := db.NewPlatformPool(context.Background(), pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// offboardedEnvelope is a signed-looking envelope of device's command of typ, valid for the retention.
func offboardedEnvelope(t *testing.T, cmd, device, org uuid.UUID, typ, params string) []byte {
	t.Helper()
	payload, err := command.Encode(command.Command{CommandID: cmd.String(), DeviceID: device.String(), OrganizationID: org.String(),
		Type: typ, Params: json.RawMessage(params), IssuedAt: time.Now().UTC().Truncate(time.Second),
		ExpiresAt: time.Now().UTC().Add(organization.OffboardedDeviceRetention).Truncate(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.New(command.PayloadType, payload, dsse.Signature{KeyID: "command-signing:v1", Sig: "AA=="}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// offboard inserts the record of a device of the fixture's organization with one key and returns its disarm and
// uninstall.
func (f fixture) offboard(t *testing.T, device uuid.UUID, keyID string) (disarm, uninstall uuid.UUID) {
	t.Helper()
	disarm, uninstall = uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	keys, _ := json.Marshal([]map[string]any{{"key_id": keyID, "public_key": []byte{1}}})
	cmds, _ := json.Marshal([]map[string]any{
		{"command_id": disarm, "envelope": offboardedEnvelope(t, disarm, device, f.org, command.TypeDeleteSelfLock, `{}`)},
		{"command_id": uninstall, "envelope": offboardedEnvelope(t, uninstall, device, f.org, command.TypeUninstall, `{"mode":"leave"}`)}})
	if _, err := f.super.Exec(context.Background(), `INSERT INTO offboarded_device (device_id, organization_id, keys, command_envelopes)
		VALUES ($1, $2, $3, $4)`, device, f.org, keys, cmds); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.super.Exec(context.Background(), "DELETE FROM offboarded_device WHERE device_id = $1", device)
	})
	return disarm, uninstall
}

func (f fixture) markDeleted(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.super.Exec(ctx, `UPDATE organization SET status = 'deleted', deleted_at = now(), deletion_requested_at = now(),
		deletion_requested_by = 'platform admin', deletion_reason = 'contract ended', delete_after = now() WHERE id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.RefreshOrganizationStatus(ctx); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) platformEvents(t *testing.T, code audit.Code, device uuid.UUID) int {
	t.Helper()
	return f.count(t, `SELECT count(*) FROM outbox WHERE organization_id = $1 AND payload ->> 'code' = $2
		AND payload -> 'params' ->> 'device_id' = $3`, audit.PlatformOrganizationID, string(code), device.String())
}

// TestOffboardedDeviceRemovalReport (plan M17 decision 15, amendment l point 3): agent.uninstalled of a device of a
// deleted organization deletes its record and the keys it kept (dk:, cmd:, seq:, sd:) and records
// platform.offboarded_device_uninstalled once; a redelivery records nothing more. Another event of the device, and the
// removal report of a device without a record, are dropped.
func TestOffboardedDeviceRemovalReport(t *testing.T) {
	f := newFixture(t)
	platform := platformPool(t)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	reports := NewReports(app.NewDeviceReports(runner, f.pool), app.NewDeviceCommands(runner, f.pool), f.cache).
		WithOffboardedDevices(app.NewOffboardedDevices(runner, platform, f.cache))
	ctx := context.Background()
	dev, unrecorded := f.device(t, "active"), f.device(t, "active")
	_, cmd := f.offboard(t, dev, "k-"+dev.String())
	if err := f.cache.PutOffboardedDevice(ctx, devicecache.OffboardedDevice{ID: dev, OrganizationID: f.org,
		Keys: []devicecache.OffboardedKey{{KeyID: "k-" + dev.String(), PublicKey: []byte{1}}},
		Commands: []devicecache.OffboardedCommand{{ID: cmd,
			Command: devicecache.Command{ExpiresAt: time.Now().Add(time.Hour), Envelope: []byte(`{}`)}}}}, 5); err != nil {
		t.Fatal(err)
	}
	if err := f.cache.MarkDelivered(ctx, dev, 5); err != nil {
		t.Fatal(err)
	}
	f.markDeleted(t)
	batch := func(device uuid.UUID, typ string) []byte {
		b, _ := json.Marshal(ingest.Events{DeviceID: device, OrganizationID: f.org, ReceivedAt: time.Now(), Events: []protocol.Event{
			{EventSeq: 9, Type: typ, OccurredAt: time.Now(), Data: json.RawMessage(`{}`)}}})
		return b
	}
	if o := reports.events(ctx, "other", batch(dev, protocol.EventBundleApplied)); o != ack {
		t.Fatalf("another event: %v, want ack", o)
	}
	if f.count(t, "SELECT count(*) FROM offboarded_device WHERE device_id = $1", dev) != 1 {
		t.Fatal("another event ended the record")
	}
	for i := range 2 {
		if o := reports.events(ctx, "removed", batch(dev, protocol.EventAgentUninstalled)); o != ack {
			t.Fatalf("agent.uninstalled #%d: %v, want ack", i, o)
		}
	}
	if f.count(t, "SELECT count(*) FROM offboarded_device WHERE device_id = $1", dev) != 0 {
		t.Fatal("the record survived the removal report")
	}
	if n := f.platformEvents(t, audit.CodePlatformOffboardedDeviceUninstalled, dev); n != 1 {
		t.Fatalf("platform.offboarded_device_uninstalled recorded %d times, want 1", n)
	}
	if _, ok, err := f.cache.DeviceKey(ctx, "k-"+dev.String()); ok || err != nil {
		t.Fatalf("dk: of the uninstalled device: %v %v", ok, err)
	}
	if cmds, err := f.cache.Commands(ctx, dev, time.Now()); err != nil || len(cmds) != 0 {
		t.Fatalf("cmd: of the uninstalled device: %v %v", cmds, err)
	}
	if _, known, err := f.cache.LastDelivered(ctx, dev); known || err != nil {
		t.Fatalf("sd: of the uninstalled device: %v %v", known, err)
	}
	if o := reports.events(ctx, "unrecorded", batch(unrecorded, protocol.EventAgentUninstalled)); o != ack {
		t.Fatalf("a device without a record: %v, want ack", o)
	}
	if n := f.platformEvents(t, audit.CodePlatformOffboardedDeviceUninstalled, unrecorded); n != 0 {
		t.Fatalf("%d events for a device without a record", n)
	}
}

// TestCacheSyncRestoresOffboardedDevices (plan M17 decision 15, amendment n): after Valkey lost its data, the cache
// sync rewrites an offboarded device's key with status offboarded, its counter, its disarm and its uninstall from the
// platform record.
func TestCacheSyncRestoresOffboardedDevices(t *testing.T) {
	f := newFixture(t)
	platform := platformPool(t)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	dev := f.device(t, "active")
	disarm, cmd := f.offboard(t, dev, "k-"+dev.String())
	f.markDeleted(t)
	sync := NewCacheSync(f.pool, f.cache).WithOffboardedDevices(app.NewOffboardedDevices(runner, platform, f.cache).
		WithCacheSync(devicecache.NewSyncer(f.cache)))
	if err := sync.ReconcileAll(context.Background()); err != nil && strings.Contains(err.Error(), "offboarded devices") {
		t.Fatal(err)
	}
	ctx := context.Background()
	key, ok, err := f.cache.DeviceKey(ctx, "k-"+dev.String())
	if err != nil || !ok || key.Status != devicecache.KeyOffboarded || key.DeviceID != dev || key.OrganizationID != f.org {
		t.Fatalf("restored key %+v %v %v", key, ok, err)
	}
	cmds, err := f.cache.Commands(ctx, dev, time.Now())
	if err != nil || len(cmds) != 2 || cmds[cmd].ExpiresAt.Before(time.Now().Add(300*24*time.Hour)) ||
		cmds[disarm].ExpiresAt.Before(time.Now().Add(300*24*time.Hour)) {
		t.Fatalf("restored commands %v %v", cmds, err)
	}
	if seq, err := f.cache.NextSeq(ctx, dev); err != nil || seq != 1 {
		t.Fatalf("restored counter: %d %v", seq, err)
	}
}

type nopBucket struct{}

func (nopBucket) PurgeObjects(context.Context, string, time.Time) (objectstore.Purge, error) {
	return objectstore.Purge{Done: true}, nil
}
func (nopBucket) PurgeVersions(context.Context, string, time.Time) (objectstore.Purge, error) {
	return objectstore.Purge{Done: true}, nil
}

type nopIdentity struct{}

func (nopIdentity) DeleteOrganization(context.Context, string) (ports.OrgIdentityDeletion, error) {
	return ports.OrgIdentityDeletion{}, nil
}

type nopInventory struct{}

func (nopInventory) DeleteHost(context.Context, ports.HostRef) error { return nil }

type nopSessions struct{}

func (nopSessions) RevokeAccount(context.Context, uuid.UUID) (int, error) { return 0, nil }

type constSigner struct{}

func (constSigner) SignBatch(_ context.Context, _ string, messages [][]byte) ([]bao.RawSignature, error) {
	out := make([]bao.RawSignature, len(messages))
	for i := range out {
		out[i] = bao.RawSignature{KeyVersion: 1, Value: []byte{1}}
	}
	return out, nil
}

// TestOffboardingUnreportedDevicesNeverStall (main's requirement for PDK-1016): devices that never report their
// removal, offline or pending approval, do not hold the deletion. The round deletes the organization without a
// failing step, so neither the backoff nor PaddockOrganizationDeletionStuck (paddock_offboarding_retry_capped) nor
// paddock_offboarding_step_failing ever shows it. An approved offline device is handed over: the hand-over adds the
// disarm and the uninstall to cmd: and keeps a disarm that was pending there (amendment n point 2). A device still
// pending approval gets no uninstall and is not handed over (amendment m, ADR decision §47).
func TestOffboardingUnreportedDevicesNeverStall(t *testing.T) {
	f := newFixture(t)
	platform := platformPool(t)
	ctx := context.Background()
	offline, pending := f.device(t, "active"), f.device(t, "pending")
	pendingDisarm := uuid.Must(uuid.NewV7())
	for _, dev := range []uuid.UUID{offline, pending} {
		if _, err := f.super.Exec(ctx, `INSERT INTO device_identity_key (key_id, organization_id, device_id, public_key, key_protection, status)
			VALUES ($1, $2, $3, '\x01', 'file', 'active')`, "k-"+dev.String(), f.org, dev); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.cache.PutCommand(ctx, offline, pendingDisarm, devicecache.Command{ExpiresAt: time.Now().Add(time.Hour),
		Envelope: offboardedEnvelope(t, pendingDisarm, offline, f.org, command.TypeDeleteSelfLock, `{}`)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.super.Exec(ctx, "DELETE FROM offboarded_device WHERE organization_id = $1", f.org) })
	if _, err := f.super.Exec(ctx, `UPDATE organization SET deletion_requested_at = now(), deletion_requested_by = 'platform admin',
		deletion_reason = 'contract ended', delete_after = now(), deletion_uninstalls_issued = 0, deletion_uninstalls_skipped = 0
		WHERE id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	job := app.NewOffboarding(app.OffboardingObjects{Bundles: nopBucket{}, Escrow: nopBucket{}}).
		WithDeps(app.OffboardingDeps{Runner: runner, Worker: f.pool, Platform: platform, Identity: nopIdentity{},
			Inventory: nopInventory{}, Cache: f.cache, Sessions: nopSessions{}, Signer: constSigner{}})
	r := NewOffboarding(job, platform)
	for round := 0; ; round++ {
		if round == 40 {
			t.Fatal("the deletion did not finish within 40 rounds")
		}
		if err := r.Round(ctx); err != nil {
			t.Fatal(err)
		}
		if testutil.ToFloat64(metricOffboardingRetryCapped) != 0 || testutil.CollectAndCount(metricOffboardingStepFailing) != 0 ||
			len(r.retries) != 0 {
			t.Fatalf("round %d: capped %v, failing %d, retries %d", round, testutil.ToFloat64(metricOffboardingRetryCapped),
				testutil.CollectAndCount(metricOffboardingStepFailing), len(r.retries))
		}
		var status string
		if err := f.super.QueryRow(ctx, "SELECT status FROM organization WHERE id = $1", f.org).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == organization.StatusDeleted {
			break
		}
		// No audit writer runs here: its acknowledgement of the requested final verification is applied as the
		// worker's consumer of worker.offboarding would.
		var requested bool
		if err := f.super.QueryRow(ctx, "SELECT audit_retirement_requested_at IS NOT NULL FROM organization WHERE id = $1",
			f.org).Scan(&requested); err != nil {
			t.Fatal(err)
		}
		if requested {
			if err := job.RecordAuditFinal(ctx, offboarding.AuditRetired{OrganizationID: f.org,
				FinalOutcome: offboarding.AuditFinalVerified, FinalVerifiedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
		}
		// The test need not wait the gate's 6 s margin of the quiescence cutoff.
		if _, err := f.super.Exec(ctx, `UPDATE organization SET deleting_committed_at = deleting_committed_at - interval '7 seconds'
			WHERE id = $1 AND offboarding_wait_vxids IS NULL AND deleting_committed_at IS NOT NULL`, f.org); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM outbox WHERE organization_id = $1 AND payload ->> 'code' = 'organization.deletion_step_failed'
		AND payload -> 'target' ->> 'id' = $2`, audit.PlatformOrganizationID, f.org.String()); n != 0 {
		t.Fatalf("%d failed steps", n)
	}
	if n := f.count(t, "SELECT count(*) FROM offboarded_device WHERE device_id = $1", offline); n != 1 {
		t.Fatalf("the approved offline device was handed over %d times, want once", n)
	}
	if n := f.count(t, "SELECT count(*) FROM offboarded_device WHERE device_id = $1", pending); n != 0 {
		t.Fatalf("the pending device was handed over %d times, want not at all", n)
	}
	if key, ok, err := f.cache.DeviceKey(ctx, "k-"+offline.String()); err != nil || !ok || key.Status != devicecache.KeyOffboarded {
		t.Fatalf("key of the offline device %+v %v %v, want offboarded", key, ok, err)
	}
	if key, ok, err := f.cache.DeviceKey(ctx, "k-"+pending.String()); err != nil || (ok && key.Status == devicecache.KeyOffboarded) {
		t.Fatalf("key of the pending device %+v %v %v, want no offboarded key", key, ok, err)
	}
	if pcmds, err := f.cache.Commands(ctx, pending, time.Now()); err != nil || len(pcmds) != 0 {
		t.Fatalf("cmd: of the pending device: %v %v; want none", pcmds, err)
	}
	cmds, err := f.cache.Commands(ctx, offline, time.Now())
	if err != nil || len(cmds) != 3 {
		t.Fatalf("cmd: of the offline device: %v %v; want the pending disarm, the disarm and the uninstall", cmds, err)
	}
	types := map[string]int{}
	for _, c := range cmds {
		_, payload, err := dsse.Decode(c.Envelope)
		var cc command.Command
		if err != nil || json.Unmarshal(payload, &cc) != nil {
			t.Fatalf("envelope %s: %v", c.Envelope, err)
		}
		types[cc.Type]++
	}
	if _, ok := cmds[pendingDisarm]; !ok || types[command.TypeDeleteSelfLock] != 2 || types[command.TypeUninstall] != 1 {
		t.Fatalf("command types %v, pending disarm kept %v", types, ok)
	}
}

// TestCacheSyncRestoresOffboardedDevicesWithoutOrganizations (review 1 nit 7): the offboarded devices are platform
// records, so the reconcile restores them also when the organization list fails, and reports that failure.
func TestCacheSyncRestoresOffboardedDevicesWithoutOrganizations(t *testing.T) {
	f := newFixture(t)
	platform := platformPool(t)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	dev := f.device(t, "active")
	_, cmd := f.offboard(t, dev, "k-"+dev.String())
	broken, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	sync := NewCacheSync(broken, f.cache).WithOffboardedDevices(app.NewOffboardedDevices(runner, platform, f.cache).
		WithCacheSync(devicecache.NewSyncer(f.cache)))
	if err := sync.ReconcileAll(context.Background()); err == nil {
		t.Fatal("ReconcileAll hid the failed organization list")
	}
	ctx := context.Background()
	if key, ok, err := f.cache.DeviceKey(ctx, "k-"+dev.String()); err != nil || !ok || key.Status != devicecache.KeyOffboarded {
		t.Fatalf("restored key %+v %v %v", key, ok, err)
	}
	if cmds, err := f.cache.Commands(ctx, dev, time.Now()); err != nil || len(cmds) != 2 || cmds[cmd].Envelope == nil {
		t.Fatalf("restored commands %v %v", cmds, err)
	}
}

// TestRetentionRoundPurgesOffboardedDevices (review 1 nit 8, plan M17 decision 15): the retention round runs the
// platform-only store offboarded_device, which has no per-organization purge, without failing, and purges a record
// older than the retention with the keys it kept.
func TestRetentionRoundPurgesOffboardedDevices(t *testing.T) {
	f := newFixture(t)
	platform := platformPool(t)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	ctx := context.Background()
	dev := f.device(t, "active")
	_, cmd := f.offboard(t, dev, "k-"+dev.String())
	if _, err := f.super.Exec(ctx, "UPDATE offboarded_device SET offboarded_at = now() - interval '366 days' WHERE device_id = $1", dev); err != nil {
		t.Fatal(err)
	}
	if err := f.cache.PutCommand(ctx, dev, cmd, devicecache.Command{ExpiresAt: time.Now().Add(time.Hour), Envelope: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	offboarded := app.NewOffboardedDevices(runner, platform, f.cache)
	r := NewRetention(app.NewRetention(runner, f.pool, platform, &fakeSource{}, day, 400), app.NewLoginHistory(runner, f.pool, day),
		f.pool, platform, time.Hour).WithOffboardedDevices(offboarded)
	if err := r.Round(ctx); err != nil {
		t.Logf("retention round: %v (other organizations of the shared database)", err)
	}
	if n := f.count(t, "SELECT count(*) FROM offboarded_device WHERE device_id = $1", dev); n != 0 {
		t.Fatal("the expired record survived the round")
	}
	if ok, err := f.cache.HasCommand(ctx, dev, cmd); ok || err != nil {
		t.Fatalf("cmd: of the purged device: %v %v", ok, err)
	}
	if testutil.ToFloat64(metricRetentionLastSuccess.WithLabelValues(app.StoreOffboardedDevice)) == 0 {
		t.Fatal("the offboarded_device pass recorded no success")
	}
}

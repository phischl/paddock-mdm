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

// offboardedEnvelope is a signed-looking uninstall envelope of device.
func offboardedEnvelope(t *testing.T, cmd, device, org uuid.UUID) []byte {
	t.Helper()
	payload, err := command.Encode(command.Command{CommandID: cmd.String(), DeviceID: device.String(), OrganizationID: org.String(),
		Type: command.TypeUninstall, Params: json.RawMessage(`{"mode":"leave"}`), IssuedAt: time.Now().UTC().Truncate(time.Second),
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

// offboard inserts the record of a device of the fixture's organization with one key and returns its command.
func (f fixture) offboard(t *testing.T, device uuid.UUID, keyID string) uuid.UUID {
	t.Helper()
	cmd := uuid.Must(uuid.NewV7())
	keys, _ := json.Marshal([]map[string]any{{"key_id": keyID, "public_key": []byte{1}}})
	if _, err := f.super.Exec(context.Background(), `INSERT INTO offboarded_device (device_id, organization_id, keys, command_id, command_envelope)
		VALUES ($1, $2, $3, $4, $5)`, device, f.org, keys, cmd, offboardedEnvelope(t, cmd, device, f.org)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.super.Exec(context.Background(), "DELETE FROM offboarded_device WHERE device_id = $1", device)
	})
	return cmd
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
	cmd := f.offboard(t, dev, "k-"+dev.String())
	if err := f.cache.PutOffboardedDevice(ctx, devicecache.OffboardedDevice{ID: dev, OrganizationID: f.org, CommandID: cmd,
		Keys:    []devicecache.OffboardedKey{{KeyID: "k-" + dev.String(), PublicKey: []byte{1}}},
		Command: devicecache.Command{ExpiresAt: time.Now().Add(time.Hour), Envelope: []byte(`{}`)}}, 5); err != nil {
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

// TestCacheSyncRestoresOffboardedDevices (plan M17 decision 15): after Valkey lost its data, the cache sync rewrites
// an offboarded device's key with status offboarded, its counter and its uninstall from the platform record.
func TestCacheSyncRestoresOffboardedDevices(t *testing.T) {
	f := newFixture(t)
	platform := platformPool(t)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	dev := f.device(t, "active")
	cmd := f.offboard(t, dev, "k-"+dev.String())
	f.markDeleted(t)
	sync := NewCacheSync(f.pool, f.cache).WithOffboardedDevices(app.NewOffboardedDevices(runner, platform, f.cache))
	if err := sync.ReconcileAll(context.Background()); err != nil && strings.Contains(err.Error(), "offboarded devices") {
		t.Fatal(err)
	}
	ctx := context.Background()
	key, ok, err := f.cache.DeviceKey(ctx, "k-"+dev.String())
	if err != nil || !ok || key.Status != devicecache.KeyOffboarded || key.DeviceID != dev || key.OrganizationID != f.org {
		t.Fatalf("restored key %+v %v %v", key, ok, err)
	}
	cmds, err := f.cache.Commands(ctx, dev, time.Now())
	if err != nil || len(cmds) != 1 || cmds[cmd].ExpiresAt.Before(time.Now().Add(300*24*time.Hour)) {
		t.Fatalf("restored commands %v %v", cmds, err)
	}
	if seq, err := f.cache.NextSeq(ctx, dev); err != nil || seq != 1 {
		t.Fatalf("restored counter: %d %v", seq, err)
	}
}

type nopBucket struct{}

func (nopBucket) PurgeObjects(context.Context, string) (objectstore.Purge, error) {
	return objectstore.Purge{}, nil
}
func (nopBucket) PurgeVersions(context.Context, string) (objectstore.Purge, error) {
	return objectstore.Purge{}, nil
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
// removal, offline or pending approval, do not hold the deletion. The round hands them over and deletes the
// organization without a failing step, so neither the backoff nor PaddockOrganizationDeletionStuck
// (paddock_offboarding_retry_capped) nor paddock_offboarding_step_failing ever shows it.
func TestOffboardingUnreportedDevicesNeverStall(t *testing.T) {
	f := newFixture(t)
	platform := platformPool(t)
	ctx := context.Background()
	offline, pending := f.device(t, "active"), f.device(t, "pending")
	t.Cleanup(func() { _, _ = f.super.Exec(ctx, "DELETE FROM offboarded_device WHERE organization_id = $1", f.org) })
	if _, err := f.super.Exec(ctx, `UPDATE organization SET deletion_requested_at = now(), deletion_requested_by = 'platform admin',
		deletion_reason = 'contract ended', delete_after = now(), deletion_uninstalls_issued = 0, deletion_uninstalls_skipped = 0
		WHERE id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	job := app.NewOffboarding(app.OffboardingObjects{Bundles: nopBucket{}, Escrow: nopBucket{}}).
		WithDeps(app.OffboardingDeps{Runner: runner, Worker: f.pool, Platform: platform, Identity: nopIdentity{},
			Inventory: nopInventory{}, Cache: f.cache, Sessions: nopSessions{}, Signer: constSigner{}}).
		WithStubbedSteps("audit_final")
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
	if n := f.count(t, "SELECT count(*) FROM offboarded_device WHERE device_id = ANY($1)", []uuid.UUID{offline, pending}); n != 2 {
		t.Fatalf("%d of the 2 unreported devices were handed over", n)
	}
}

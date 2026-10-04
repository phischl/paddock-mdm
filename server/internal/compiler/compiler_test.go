package compiler_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/valkey-io/valkey-go"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/compiler"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/domain/statechange"
	"github.com/paddock-mdm/paddock/server/internal/platform/bao"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/objectstore"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/baotest"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/pgtest"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/s3test"
	"github.com/paddock-mdm/paddock/server/internal/testsupport/valkeytest"
)

// flakyStore fails uploads while broken is set.
type flakyStore struct {
	store  *objectstore.Store
	broken atomic.Bool
}

func (f *flakyStore) Put(ctx context.Context, key, contentType, cacheControl string, body []byte) error {
	if f.broken.Load() {
		return errors.New("injected upload failure")
	}
	return f.store.Put(ctx, key, contentType, cacheControl, body)
}

type world struct {
	t      *testing.T
	comp   *compiler.Compiler
	cache  *devicecache.Cache
	valkey valkey.Client
	store  *flakyStore
	s3     *s3test.RustFS
	super  *pgx.Conn
	trust  bundle.Trust
	org    uuid.UUID
	g1, g2 uuid.UUID

	validator *fakeValidator
}

// fakeValidator refuses rendered sudoers files that contain reject (no visudo needed in unit tests; the real visudo
// is tested in TestVisudo).
type fakeValidator struct {
	reject  string
	checked atomic.Int64
}

func (f *fakeValidator) Validate(_ context.Context, content []byte) error {
	f.checked.Add(1)
	if f.reject != "" && strings.Contains(string(content), f.reject) {
		return errors.New("visudo: syntax error")
	}
	return nil
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	pool, err := db.NewOrgPool(ctx, env.Compiler, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	b := baotest.Start(t)
	role := b.AppRole(t, "paddock-compiler")
	signer, err := bao.New(b.Addr, role.RoleID, role.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := signer.PublicKeys(ctx, "bundle-signing")
	if err != nil {
		t.Fatal(err)
	}
	rfs := s3test.StartPlain(t, "paddock-bundles")
	vk := valkeytest.Start(t).Client(t)
	w := &world{
		t: t, cache: devicecache.New(vk), valkey: vk, s3: rfs, super: super,
		store: &flakyStore{store: objectstore.New(rfs.Endpoint, s3test.RootUser, s3test.RootPassword, rfs.Bucket)},
		trust: bundle.Trust{Keys: map[string]ed25519.PublicKey{"bundle-signing:v1": keys[1]}},
		org:   uuid.Must(uuid.NewV7()), g1: uuid.Must(uuid.NewV7()), g2: uuid.Must(uuid.NewV7()),
	}
	w.validator = &fakeValidator{}
	w.comp = compiler.New(pool, signer, w.store, w.cache, compiler.Config{
		AuthentikURL: "https://auth.test/", HimmelblauVersion: "4.0.4", Sudoers: w.validator,
		Runner: app.NewActionRunner(pool, nil, func(context.Context) string { return "compiler-test" }),
	})
	w.exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'C', 'active')", w.org, "c"+w.org.String()[24:])
	w.exec("INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'g1'), ($3, $2, 'g2')", w.g1, w.org, w.g2)
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.super.Exec(context.Background(), sql, args...); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) device(state string, groups ...uuid.UUID) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', $3)", id, w.org, state)
	for _, g := range groups {
		w.exec("INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)", w.org, g, id)
	}
	return id
}

func (w *world) compile(scope string, id uuid.UUID) error {
	return w.comp.Compile(context.Background(), []statechange.Event{{OrganizationID: w.org, Scope: scope, ID: id}})
}

func (w *world) mustCompile(scope string, id uuid.UUID) {
	w.t.Helper()
	if err := w.compile(scope, id); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) version(dev uuid.UUID) int64 {
	w.t.Helper()
	var v int64
	if err := w.super.QueryRow(context.Background(), "SELECT bundle_seq FROM device WHERE id = $1", dev).Scan(&v); err != nil {
		w.t.Fatal(err)
	}
	return v
}

// fetch downloads the bundle bp:<dev> points to and verifies it as a device would.
func (w *world) fetch(dev uuid.UUID) *bundle.Bundle {
	w.t.Helper()
	ctx := context.Background()
	p, ok, err := w.cache.BundlePointer(ctx, dev)
	if err != nil || !ok {
		w.t.Fatalf("no bundle pointer for %s: %v", dev, err)
	}
	out, err := w.s3.Root.GetObject(ctx, &s3.GetObjectInput{Bucket: &w.s3.Bucket, Key: &p.ObjectKey})
	if err != nil {
		w.t.Fatalf("object %s: %v", p.ObjectKey, err)
	}
	defer func() { _ = out.Body.Close() }()
	env, _ := io.ReadAll(out.Body)
	b, err := bundle.VerifyVersions(env, w.trust, dev.String(), w.org.String(), p.Version-1, []int{bundle.SchemaVersion, bundle.SchemaVersion2})
	if err != nil {
		w.t.Fatalf("bundle of %s does not verify: %v", dev, err)
	}
	return b
}

func resourceIDs(b *bundle.Bundle) string {
	var ids []string
	for _, r := range b.Resources {
		ids = append(ids, r.ID)
	}
	return strings.Join(ids, ",")
}

func TestCompileAffectsExactlyTheChangedDevices(t *testing.T) {
	w := newWorld(t)
	d1, d2, d3 := w.device("active", w.g1), w.device("active", w.g2), w.device("active")
	pending := w.device("pending", w.g1)
	w.mustCompile(statechange.ScopeOrg, w.org)
	for _, d := range []uuid.UUID{d1, d2, d3} {
		if v := w.version(d); v != 1 {
			t.Fatalf("device %s at version %d after the first compile", d, v)
		}
		if b := w.fetch(d); resourceIDs(b) != "time" || b.Agent.CheckinIntervalS != 300 {
			t.Fatalf("initial bundle %+v", b)
		}
	}
	if w.version(pending) != 0 {
		t.Fatal("a pending device was compiled")
	}

	// A managed file for g1 changes d1 only.
	fileID := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO managed_file (id, organization_id, device_group_id, path, mode, content) VALUES ($1, $2, $3, '/etc/motd', '0644', 'hello')", fileID, w.org, w.g1)
	w.mustCompile(statechange.ScopeDeviceGroup, w.g1)
	if w.version(d1) != 2 || w.version(d2) != 1 || w.version(d3) != 1 {
		t.Fatalf("versions after group change: %d %d %d", w.version(d1), w.version(d2), w.version(d3))
	}
	if b := w.fetch(d1); resourceIDs(b) != "file:/etc/motd,time" || b.BundleVersion != 2 {
		t.Fatalf("d1 bundle %s v%d", resourceIDs(b), b.BundleVersion)
	}

	// No-op edit and a whole-organization recompile produce no new versions.
	w.exec("UPDATE managed_file SET content = 'hello', updated_at = now() WHERE id = $1", fileID)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d1) != 2 || w.version(d2) != 1 || w.version(d3) != 1 {
		t.Fatalf("no-op changed versions: %d %d %d", w.version(d1), w.version(d2), w.version(d3))
	}

	// A membership change recompiles the device.
	w.exec("INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)", w.org, w.g1, d2)
	w.mustCompile(statechange.ScopeDevice, d2)
	if w.version(d2) != 2 || resourceIDs(w.fetch(d2)) != "file:/etc/motd,time" {
		t.Fatalf("d2 after joining g1: v%d", w.version(d2))
	}
}

func TestUploadFailureLeavesNoGap(t *testing.T) {
	w := newWorld(t)
	d := w.device("active")
	w.mustCompile(statechange.ScopeDevice, d)
	w.exec("INSERT INTO managed_unit (id, organization_id, unit, enabled, active) VALUES ($1, $2, 'chrony.service', true, true)", uuid.Must(uuid.NewV7()), w.org)

	w.store.broken.Store(true)
	if err := w.compile(statechange.ScopeOrg, w.org); err == nil {
		t.Fatal("compile succeeded although the upload failed")
	}
	if w.version(d) != 1 {
		t.Fatalf("bundle_seq advanced to %d without an uploaded bundle", w.version(d))
	}
	if p, _, _ := w.cache.BundlePointer(context.Background(), d); p.Version != 1 {
		t.Fatalf("bp: points to version %d", p.Version)
	}
	var rows int
	_ = w.super.QueryRow(context.Background(), "SELECT count(*) FROM bundle WHERE device_id = $1", d).Scan(&rows)
	if rows != 1 {
		t.Fatalf("%d bundle rows after a failed upload", rows)
	}

	w.store.broken.Store(false)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if b := w.fetch(d); b.BundleVersion != 2 || resourceIDs(b) != "time,unit:chrony.service" {
		t.Fatalf("after retry: v%d %s", b.BundleVersion, resourceIDs(b))
	}
}

func TestReconcileRestoresPointers(t *testing.T) {
	w := newWorld(t)
	d := w.device("active")
	w.mustCompile(statechange.ScopeDevice, d)
	want, _, _ := w.cache.BundlePointer(context.Background(), d)
	// Valkey lost the pointer (e.g. a failed write after commit, or a flushed Valkey).
	if err := w.valkey.Do(context.Background(), w.valkey.B().Del().Key("bp:"+d.String()).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if err := w.comp.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := w.cache.BundlePointer(context.Background(), d); got != want {
		t.Fatalf("pointer %+v, want %+v", got, want)
	}
}

package backuprole

import (
	"bytes"
	"context"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/s3test"
)

// TestS3TargetOnRustFS: the S3 target mirrors a set below <prefix>/paddock-backup/ of a real bucket, probes it, and a
// wrong secret key is the error class auth (plan M15 decision 11); a snapshot past its keep days leaves it (amendment
// 2026-11-05, D4).
func TestS3TargetOnRustFS(t *testing.T) {
	ctx := context.Background()
	r := s3test.StartPlain(t, "paddock-backup")
	store, err := objectstore.NewWithOptions(r.Endpoint, s3test.RootUser, s3test.RootPassword, r.Bucket, objectstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dst := NewS3Target(store, "/site-a/")

	manifest := testManifest(t, InstallationID(42), nil)
	repo, idx := openSet(t, map[string]string{"openbao/20260901T100000Z.snap.enc": "sealed",
		"openbao/20261104T160000Z.snap.enc": "newer", "escrow/org/o/devices/d/luks-header/1.bin": "header",
		backupset.ManifestPath: string(manifest)})
	if err := mirror(t, repo, idx, dst, map[string]fileInfo{}); err != nil {
		t.Fatal(err)
	}
	keys, err := store.ListSizes(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if keys["site-a/paddock-backup/openbao/20260901T100000Z.snap.enc"] != 6 ||
		keys["site-a/paddock-backup/manifest.json"] != int64(len(manifest)) || len(keys) != 4 {
		t.Errorf("bucket holds %v", keys)
	}
	if data, found, err := dst.Read(ctx, backupset.ManifestPath); err != nil || !found || !bytes.Equal(data, manifest) {
		t.Errorf("manifest read back: found %v, %v", found, err)
	}
	if _, found, err := dst.Read(ctx, "openbao/missing"); err != nil || found {
		t.Errorf("a missing object: found %v, %v", found, err)
	}
	if err := repo.Remove("openbao/20260901T100000Z.snap.enc"); err != nil {
		t.Fatal(err)
	}
	delete(idx, "openbao/20260901T100000Z.snap.enc")
	if err := mirror(t, repo, idx, dst, map[string]fileInfo{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := dst.List(ctx); len(got) != 3 {
		t.Errorf("after the expire the target holds %v", got)
	}
	if err := dst.Probe(ctx); err != nil {
		t.Errorf("probe: %v", err)
	}
	if keys, _ := store.ListSizes(ctx, "site-a/.paddock-test"); len(keys) != 0 {
		t.Errorf("the probe left %v", keys)
	}

	wrong, err := objectstore.NewWithOptions(r.Endpoint, s3test.RootUser, "wrong-secret", r.Bucket, objectstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewS3Target(wrong, "").Probe(ctx); ErrorClass(err) != ClassAuth {
		t.Errorf("wrong secret key: %v (%s)", err, ErrorClass(err))
	}
	if _, err := objectstore.NewWithOptions(r.Endpoint, "a", "b", "c", objectstore.Options{CAPEM: "not a PEM"}); err == nil {
		t.Error("a CA without a certificate was accepted")
	}
}

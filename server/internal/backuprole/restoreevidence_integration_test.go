package backuprole

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// seedAuditEvent indexes one event of org as the audit writer does.
func seedAuditEvent(t *testing.T, writer *db.AuditWriterPool, org uuid.UUID, seq int64, code, outcome, target string,
	at time.Time) {
	t.Helper()
	err := writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.EnsureAuditPartition(ctx, at); err != nil {
			return err
		}
		_, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
			EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: at, RecordedAt: at, Code: code,
			Outcome: outcome, Source: "system", Actor: []byte(`{"type":"system","id":"issuer"}`), Target: []byte(target),
			Params: []byte(`{}`), CorrelationID: "c", ObjectKey: "k", CommitSeq: seq,
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRestoreEscrowReadsTheAuditIndex (PDK-831): after a point-in-time restore to before a Destroy, the audit index
// still holds the successful device.escrow_destroyed, so the header is not put back. Failed Destroys and other organizations' events are no evidence, and an unreadable index fails.
func TestRestoreEscrowReadsTheAuditIndex(t *testing.T) {
	ctx := context.Background()
	ag := pgtest.SharedAudit(t)
	reader, err := db.NewAuditReader(ctx, ag.Reader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	writer, err := db.NewAuditWriterPool(ctx, ag.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)

	org, other := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	destroyedAt := time.Now().UTC().Truncate(time.Second)
	devs := map[string]string{}
	for _, d := range []string{"d1", "d2", "d3", "d4"} {
		devs[d] = uuid.Must(uuid.NewV7()).String()
	}
	target := func(dev string) string { return `{"type":"device","id":"` + devs[dev] + `"}` }
	seedAuditEvent(t, writer, org, 1, "device.escrow_destroyed", "success", target("d1"), destroyedAt.Add(-time.Hour))
	seedAuditEvent(t, writer, org, 2, "device.escrow_destroyed", "success", target("d1"), destroyedAt)
	seedAuditEvent(t, writer, org, 3, "device.escrow_destroyed", "failure", target("d2"), destroyedAt)
	seedAuditEvent(t, writer, org, 4, "device.escrow_uploaded", "success", target("d3"), destroyedAt)
	seedAuditEvent(t, writer, other, 1, "device.escrow_destroyed", "success", target("d4"), destroyedAt)

	key := func(dev string) string { return "org/" + org.String() + "/devices/" + devs[dev] + "/luks-header/h1" }
	files := map[string]string{}
	m := backupset.Manifest{Schema: backupset.ManifestSchema, InstallationID: restoreInstallation, ServerVersion: "t",
		GeneratedAt: destroyedAt, KeyID: testKeyID, KeyFingerprint: backupset.Fingerprint(testKey)}
	m.Contents.PgBackRest.Path = backupset.RepoPath(testKeyID)
	for _, dev := range []string{"d1", "d2", "d3", "d4"} {
		files["escrow/"+key(dev)] = "aaaa"
		m.Contents.Escrow = append(m.Contents.Escrow,
			backupset.File{Path: "escrow/" + key(dev), Bytes: 4, At: destroyedAt.Add(-30 * time.Minute)})
	}
	root := openRoot(t, writeSet(t, files))

	orgs, err := EscrowOrganizations(root)
	if err != nil || len(orgs) != 1 || orgs[0] != org {
		t.Fatalf("organizations %v %v", orgs, err)
	}
	audited, err := AuditEscrowEvidence(ctx, reader, []uuid.UUID{org})
	if err != nil {
		t.Fatal(err)
	}
	if len(audited) != 1 || !audited[org.String()+"/"+devs["d1"]].Equal(destroyedAt) {
		t.Fatalf("audit evidence %v, want d1 at its newest Destroy %v", audited, destroyedAt)
	}
	bucket := &fakeS3{objects: map[string]string{}}
	res, err := RestoreEscrow(ctx, root, m, bucket, bucket, audited)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bucket.objects[key("d1")]; ok || res.Destroyed != 1 || res.Put != 3 {
		t.Errorf("result %+v, bucket %v: the destroyed device's header went back", res, bucket.objects)
	}

	closed, err := db.NewAuditReader(ctx, ag.Reader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if _, err := AuditEscrowEvidence(ctx, closed, []uuid.UUID{org}); err == nil {
		t.Error("an unreadable audit index yielded evidence instead of an error")
	}
}

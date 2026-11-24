package db_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// TestBackupLeaderFence (plan M19 D5, RR-134): when the leader's lock session dies and a second process leads, the
// first process's next write fails with ErrFenced, ends its leadership's context with that cause and records nothing,
// while its own lock check has not noticed the loss yet; every acquisition increments the epoch.
func TestBackupLeaderFence(t *testing.T) {
	env := sharedPaddock(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	lockPool := func() *db.PlatformPool {
		p, err := db.NewPlatformPool(ctx, env.Platform, db.Options{MaxConns: 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	backupPool := func() *db.BackupPool {
		p, err := db.NewBackupPool(ctx, env.Backup, db.Options{MaxConns: 2})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	first, second := lockPool(), lockPool()
	firstDB, secondDB := backupPool(), backupPool()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })
	const key = int64(0x7465737434)
	failed := "failed"
	insertRun := func(ctx context.Context, p *db.BackupPool, id uuid.UUID) error {
		now := time.Now()
		return p.InBackup(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			return q.BackupRoleInsertFinishedRun(ctx, pgstore.BackupRoleInsertFinishedRunParams{ID: id, Kind: "openbao",
				Outcome: &failed, StartedAt: &now, FinishedAt: &now, ErrorClass: &failed, Targets: json.RawMessage("[]")})
		})
	}
	recorded := func(id uuid.UUID) bool {
		var ok bool
		if err := super.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM backup_run WHERE id = $1)", id).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	firstEpoch := make(chan int64, 1)
	write := make(chan struct{})
	firstResult := make(chan error, 1)
	stale, early := uuid.New(), uuid.New()
	go func() {
		// The lock check never runs within the test, so only the epoch can stop the first process's write.
		ok, err := first.Lead(ctx, key, time.Hour, func(ctx context.Context) error {
			fenced, stop, err := firstDB.TakeLeaderEpoch(ctx, "first")
			if err != nil {
				return err
			}
			defer stop()
			if err := insertRun(fenced, firstDB, early); err != nil {
				return fmt.Errorf("write while leading: %w", err)
			}
			epoch, _ := db.LeaderEpoch(fenced)
			firstEpoch <- epoch
			<-write
			werr := insertRun(fenced, firstDB, stale)
			if cause := context.Cause(fenced); !errors.Is(cause, db.ErrFenced) {
				return errors.Join(fmt.Errorf("leadership context cause %v, want ErrFenced", cause), werr)
			}
			return werr
		})
		if !ok {
			err = errors.Join(errors.New("first did not lead"), err)
		}
		firstResult <- err
	}()
	epoch1 := <-firstEpoch
	if !recorded(early) {
		t.Fatal("the leader's write before the takeover was not recorded")
	}
	if _, err := super.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_locks
		WHERE locktype = 'advisory' AND ((classid::bigint << 32) | objid::bigint) = $1`, key); err != nil {
		t.Fatal(err)
	}

	var epoch2 int64
	var firstErr, secondErr error
	deadline := time.Now().Add(30 * time.Second)
	for {
		ok, err := second.Lead(ctx, key, time.Hour, func(ctx context.Context) error {
			fenced, stop, err := secondDB.TakeLeaderEpoch(ctx, "second")
			if err != nil {
				return err
			}
			defer stop()
			epoch2, _ = db.LeaderEpoch(fenced)
			close(write)
			firstErr = <-firstResult
			secondErr = insertRun(fenced, secondDB, uuid.New())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second process never got the lock after the first's session died")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if epoch2 != epoch1+1 {
		t.Errorf("second epoch %d after first epoch %d, want one more", epoch2, epoch1)
	}
	if !errors.Is(firstErr, db.ErrFenced) {
		t.Fatalf("first process's write after the takeover: %v, want ErrFenced", firstErr)
	}
	if recorded(stale) {
		t.Error("the fenced write was recorded")
	}
	if secondErr != nil {
		t.Errorf("the new leader's write: %v", secondErr)
	}

	_, stop, err := secondDB.TakeLeaderEpoch(ctx, "again")
	if err != nil {
		t.Fatal(err)
	}
	stop()
	var epoch3 int64
	var holder string
	if err := super.QueryRow(ctx, "SELECT epoch, holder FROM backup_leader").Scan(&epoch3, &holder); err != nil {
		t.Fatal(err)
	}
	if epoch3 != epoch2+1 || holder != "again" {
		t.Errorf("after a third acquisition: epoch %d holder %q, want %d \"again\"", epoch3, holder, epoch2+1)
	}

	// Without a leader epoch in the context (the host's one-off commands) a transaction is not fenced.
	if err := insertRun(ctx, firstDB, uuid.New()); err != nil {
		t.Errorf("unfenced write: %v", err)
	}
}

// TestBackupLeaderGrants (migration 00127): paddock_backup reads and advances the epoch but cannot add or remove the
// row; no other service role reaches the table.
func TestBackupLeaderGrants(t *testing.T) {
	env := sharedPaddock(t)
	ctx := context.Background()
	connect := func(dsn string) *pgx.Conn {
		c, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(ctx) })
		return c
	}
	backup := connect(env.Backup)
	_, err := backup.Exec(ctx, "INSERT INTO backup_leader (id, epoch, holder, acquired_at) VALUES (true, 0, 'x', now())")
	wantDenied(t, "paddock_backup INSERT backup_leader", err)
	_, err = backup.Exec(ctx, "DELETE FROM backup_leader")
	wantDenied(t, "paddock_backup DELETE backup_leader", err)
	for name, dsn := range map[string]string{"paddock_api": env.API, "paddock_worker": env.Worker,
		"paddock_platform": env.Platform, "paddock_compiler": env.Compiler, "paddock_relay": env.Relay,
		"paddock_notifier": env.Notifier, "paddock_escrow_reader": env.EscrowReader, "paddock_revocation": env.Revocation} {
		_, err := connect(dsn).Exec(ctx, "SELECT epoch FROM backup_leader")
		wantDenied(t, name+" SELECT backup_leader", err)
	}
}

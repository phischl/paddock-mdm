package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/backup"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// GeneratedKey is the one response that holds a backup key's text (plan M15 decision 7); it is never stored, logged or
// shown again.
type GeneratedKey struct {
	KeyID       string
	Text        string
	Fingerprint string
	// Positions are the 1-based positions of Text whose characters confirm the key.
	Positions    [backupset.ChallengeLength]int
	DownloadName string
}

// LegacyImport is the outcome of BackupKeys.ImportLegacy.
type LegacyImport int

const (
	// LegacyImported: the host file's key was stored as key legacy, waiting for its confirmation.
	LegacyImported LegacyImport = iota
	// LegacyKeyPresent: a key exists and none of them is confirmed; nothing was imported.
	LegacyKeyPresent
	// LegacyKeyConfirmed: a confirmed key exists, so the host file is no longer needed; nothing was imported.
	LegacyKeyConfirmed
)

// Key states of backup_key.
const (
	keyStateUnconfirmed = "unconfirmed"
	keyStateDiscarded   = "discarded"
)

// backupKeyMaxAttempts is the number of failed confirmations that discard a key (plan M15 decision 5 of 2026-11-04).
const backupKeyMaxAttempts = 3

// backupKeyPendingIdx is the unique index that allows one unconfirmed key.
const backupKeyPendingIdx = "backup_key_one_pending_idx"

// apiActor is the actor of the legacy key import, which only the api can do: it alone may encrypt with backup-wrap.
var apiActor = audit.Actor{Type: audit.ActorSystem, Display: "paddock-api"}

// Privileged actions of the backup key (plan M15 decision 7).
var (
	SpecBackupKeyGenerate = ActionSpec{Code: audit.CodePlatformBackupKeyGenerated, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecBackupKeyConfirm  = ActionSpec{Code: audit.CodePlatformBackupKeyConfirmed, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecBackupKeyDiscard  = ActionSpec{Code: audit.CodePlatformBackupKeyDiscarded, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	specBackupKeyImport   = ActionSpec{Code: audit.CodePlatformBackupKeyGenerated, Actor: &apiActor}
)

// BackupKeys are the platform use cases of the backup key (plan M15 decisions 7–9).
type BackupKeys struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	keys     PlatformEncrypter
	now      func() time.Time
}

// NewBackupKeys creates the use cases; keys encrypts with backup-wrap.
func NewBackupKeys(runner *ActionRunner, platform *db.PlatformPool, keys PlatformEncrypter) *BackupKeys {
	return &BackupKeys{runner: runner, platform: platform, keys: keys, now: time.Now}
}

// Status returns the active, the pending and the retired keys; platform administrators only (a read, not audited).
func (k *BackupKeys) Status(ctx context.Context) (KeyStatus, error) {
	if _, err := RequirePlatform(ctx); err != nil {
		return KeyStatus{}, err
	}
	var out KeyStatus
	err := k.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = readKeyStatus(ctx, q)
		return err
	})
	return out, err
}

// Generate creates a new key (audited: platform.backup_key_generated): 32 random bytes, Transit-encrypted at rest, in
// state unconfirmed with a challenge of six positions. The text is returned only here. 409 invalid_state while another
// key waits for its confirmation. A key generated while one is active is a rotation, completed by Confirm.
func (k *BackupKeys) Generate(ctx context.Context) (GeneratedKey, error) {
	var out GeneratedKey
	err := k.runner.RunTx(ctx, ScopePlatform, SpecBackupKeyGenerate, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		switch id, err := q.PendingBackupKeyID(ctx); {
		case err == nil:
			return problem.InvalidState.WithDetail("confirm or discard key " + id + " first")
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("read the pending backup key: %w", err)
		}
		raw := make([]byte, backup.KeySize)
		defer clear(raw)
		var idRnd [4]byte
		if _, err := rand.Read(raw); err != nil {
			return fmt.Errorf("generate the backup key: %w", err)
		}
		if _, err := rand.Read(idRnd[:]); err != nil {
			return fmt.Errorf("generate the backup key ID: %w", err)
		}
		keyID := backupset.KeyID(k.now(), idRnd[:])
		text := base64.StdEncoding.EncodeToString(raw)
		ciphertext, err := k.keys.EncryptPlatform(ctx, BackupWrapKey, raw)
		if err != nil {
			return fmt.Errorf("encrypt the backup key: %w", err)
		}
		positions, err := k.insert(ctx, q, rec, keyID, raw, text, ciphertext, p.Display, false)
		if err != nil {
			return err
		}
		out = GeneratedKey{KeyID: keyID, Text: text, Fingerprint: backupset.Fingerprint(raw), Positions: positions,
			DownloadName: "paddock-backup-key-" + keyID + ".txt"}
		return nil
	})
	return out, err
}

// ImportLegacy stores the key of the host file of an installation older than M15 as key legacy in state unconfirmed
// (plan M15 decision 9; audited: platform.backup_key_generated with legacy true, actor paddock-api), but only while
// backup_key has no row: a second start, or a replica that loses the race, imports nothing and records nothing.
// keyText is the file's content. An error (OpenBao sealed, PostgreSQL unreachable) records nothing either: the caller
// retries until it succeeds.
func (k *BackupKeys) ImportLegacy(ctx context.Context, keyText string) (LegacyImport, error) {
	raw, err := backup.ParseKey(keyText)
	if err != nil {
		return 0, err
	}
	defer clear(raw)
	ctx = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: apiActor.Display})
	var keys int64
	var confirmed bool
	err = k.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if keys, err = q.CountBackupKeys(ctx); err != nil {
			return fmt.Errorf("count backup keys: %w", err)
		}
		_, err = q.ActiveBackupKeyID(ctx)
		switch {
		case err == nil:
			confirmed = true
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("read the active backup key: %w", err)
		}
		return nil
	})
	switch {
	case err != nil:
		return 0, err
	case confirmed:
		return LegacyKeyConfirmed, nil
	case keys > 0:
		return LegacyKeyPresent, nil
	}
	// Encrypting before the recorded transaction keeps a sealed OpenBao from recording one failure per retry.
	ciphertext, err := k.keys.EncryptPlatform(ctx, BackupWrapKey, raw)
	if err != nil {
		return 0, fmt.Errorf("encrypt the backup key: %w", err)
	}
	imported, err := k.runner.RecordOnceInScope(ctx, ScopePlatform, specBackupKeyImport, func(ctx context.Context, q *pgstore.Queries, rec Recorder) (bool, error) {
		if err := q.LockBackupKeys(ctx); err != nil {
			return false, fmt.Errorf("lock the backup keys: %w", err)
		}
		n, err := q.CountBackupKeys(ctx)
		if err != nil || n > 0 {
			return false, err
		}
		_, err = k.insert(ctx, q, rec, backupset.LegacyKeyID, raw, base64.StdEncoding.EncodeToString(raw), ciphertext, apiActor.Display, true)
		return err == nil, err
	})
	switch {
	case err != nil:
		return 0, err
	case !imported:
		return LegacyKeyPresent, nil
	}
	return LegacyImported, nil
}

// insert stores the key, encrypted as ciphertext, with the challenge drawn from text; it returns the challenge's
// positions. The challenge's answer is kept only as ChallengeHash.
func (k *BackupKeys) insert(ctx context.Context, q *pgstore.Queries, rec Recorder, keyID string, raw []byte, text, ciphertext,
	createdBy string, legacy bool) ([backupset.ChallengeLength]int, error) {
	fingerprint := backupset.Fingerprint(raw)
	rec.SetTarget(audit.Target{Type: "backup_key", ID: keyID, Display: keyID})
	rec.SetParam("key_id", keyID)
	rec.SetParam("fingerprint", fingerprint)
	rec.SetParam("legacy", legacy)
	_, err := q.ActiveBackupKeyID(ctx)
	switch {
	case err == nil:
		rec.SetParam("rotation", true)
	case errors.Is(err, pgx.ErrNoRows):
		rec.SetParam("rotation", false)
	default:
		return [backupset.ChallengeLength]int{}, fmt.Errorf("read the active backup key: %w", err)
	}
	// The base64 padding is the same for every key: a position on it would give one character away (decision 5).
	positions, answer, err := backupset.Challenge(strings.TrimRight(text, "="), rand.Reader)
	if err != nil {
		return positions, err
	}
	hash := backupset.ChallengeHash(keyID, answer)
	stored := make([]int32, len(positions))
	for i, p := range positions {
		stored[i] = int32(p) //nolint:gosec // positions are at most the key text's length (44)
	}
	_, err = q.InsertBackupKey(ctx, pgstore.InsertBackupKeyParams{
		KeyID: keyID, Ciphertext: ciphertext, Fingerprint: fingerprint, ChallengePositions: stored,
		ChallengeSha256: hash[:], Legacy: legacy, CreatedBy: createdBy,
	})
	if db.IsUniqueViolation(err, backupKeyPendingIdx) {
		return positions, problem.InvalidState.WithDetail("another key waits for its confirmation")
	}
	if err != nil {
		return positions, fmt.Errorf("store the backup key: %w", err)
	}
	return positions, nil
}

// Confirm activates a key when answer holds its characters at the challenge's positions (audited:
// platform.backup_key_confirmed); a confirmed key is retired in the same transaction. A wrong answer is 409
// backup_key_mismatch with the attempts left, recorded as failure together with the counted attempt; the third
// discards the key. 400 invalid_request for an answer that is not six characters, 409 invalid_state for a key that
// is not unconfirmed, 404 not_found.
func (k *BackupKeys) Confirm(ctx context.Context, keyID, answer string) (Key, error) {
	if k.knownMismatch(ctx, keyID, answer) {
		return k.recordMismatch(ctx, keyID)
	}
	var out Key
	err := k.runner.RunTx(ctx, ScopePlatform, SpecBackupKeyConfirm, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		setKeyTarget(rec, keyID)
		if len(answer) != backupset.ChallengeLength {
			return problem.InvalidRequest.WithDetail(fmt.Sprintf("answer must be %d characters", backupset.ChallengeLength))
		}
		row, err := lockPendingKey(ctx, q, keyID)
		if err != nil {
			return err
		}
		rec.SetParam("fingerprint", row.Fingerprint)
		rec.SetParam("attempts", row.Attempts)
		rec.SetParam("rotated_from", nil)
		want := backupset.ChallengeHash(keyID, answer)
		if subtle.ConstantTimeCompare(row.ChallengeSha256, want[:]) != 1 {
			// Only reached when the read before the transaction failed; the attempt is then refused uncounted.
			return problem.BackupKeyMismatch.WithDetail("the characters do not match")
		}
		// Retire first: the unique index allows one confirmed key.
		retired, err := q.RetireConfirmedBackupKey(ctx)
		if err != nil {
			return fmt.Errorf("retire the active backup key: %w", err)
		}
		if len(retired) > 0 {
			rec.SetParam("rotated_from", retired[0])
		}
		row, err = q.ConfirmBackupKey(ctx, pgstore.ConfirmBackupKeyParams{KeyID: keyID, ConfirmedBy: &p.Display})
		if err != nil {
			return fmt.Errorf("confirm the backup key: %w", err)
		}
		out = keyFromRow(row)
		return nil
	})
	return out, err
}

// knownMismatch reads the stored challenge hash before the audited transaction, because the runner must know whether
// to record a refusal before that transaction counts the attempt. Any failure to read leaves the decision to RunTx,
// which refuses or reports it; the hash never changes, so the transaction re-checks only the state under its lock.
func (k *BackupKeys) knownMismatch(ctx context.Context, keyID, answer string) bool {
	if len(answer) != backupset.ChallengeLength || !backupset.ValidKeyID(keyID) {
		return false
	}
	if _, err := RequirePlatform(ctx); err != nil {
		return false
	}
	var stored []byte
	err := k.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		stored, err = q.GetBackupKeyChallenge(ctx, keyID)
		return err
	})
	if err != nil {
		return false
	}
	want := backupset.ChallengeHash(keyID, answer)
	return subtle.ConstantTimeCompare(stored, want[:]) != 1
}

// recordMismatch counts a failed confirmation and records it as failure backup_key_mismatch in one transaction.
func (k *BackupKeys) recordMismatch(ctx context.Context, keyID string) (Key, error) {
	// The detail depends on the count read under the lock; the runner returns this same error after recording it.
	refusal := problem.BackupKeyMismatch.WithDetail("the characters do not match")
	var out Key
	err := k.runner.RunTxRefusal(ctx, ScopePlatform, SpecBackupKeyConfirm, refusal, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		setKeyTarget(rec, keyID)
		if _, err := lockPendingKey(ctx, q, keyID); err != nil {
			return err
		}
		row, err := q.RecordBackupKeyMismatch(ctx, pgstore.RecordBackupKeyMismatchParams{MaxAttempts: backupKeyMaxAttempts, KeyID: keyID})
		if err != nil {
			return fmt.Errorf("count the failed confirmation: %w", err)
		}
		rec.SetParam("fingerprint", row.Fingerprint)
		rec.SetParam("attempts", row.Attempts)
		rec.SetParam("rotated_from", nil)
		if row.State == keyStateDiscarded {
			refusal.Detail = "key discarded after three failed confirmations; generate a new key"
		} else {
			refusal.Detail = fmt.Sprintf("the characters do not match; attempts_left=%d", backupKeyMaxAttempts-int(row.Attempts))
		}
		out = keyFromRow(row)
		return nil
	})
	return out, err
}

// Discard discards a key that is not confirmed (audited: platform.backup_key_discarded); 409 invalid_state for any
// other state, 404 not_found.
func (k *BackupKeys) Discard(ctx context.Context, keyID string) (Key, error) {
	var out Key
	err := k.runner.RunTx(ctx, ScopePlatform, SpecBackupKeyDiscard, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		setKeyTarget(rec, keyID)
		row, err := lockPendingKey(ctx, q, keyID)
		if err != nil {
			return err
		}
		rec.SetParam("attempts", row.Attempts)
		if row, err = q.DiscardBackupKey(ctx, keyID); err != nil {
			return fmt.Errorf("discard the backup key: %w", err)
		}
		out = keyFromRow(row)
		return nil
	})
	return out, err
}

// setKeyTarget names the key in the event; an ID that cannot exist is not echoed into the trail.
func setKeyTarget(rec Recorder, keyID string) {
	if backupset.ValidKeyID(keyID) {
		rec.SetTarget(audit.Target{Type: "backup_key", ID: keyID, Display: keyID})
		rec.SetParam("key_id", keyID)
	}
}

// lockPendingKey locks the key's row; not_found for a missing key, invalid_state unless it is unconfirmed.
func lockPendingKey(ctx context.Context, q *pgstore.Queries, keyID string) (pgstore.BackupKey, error) {
	if !backupset.ValidKeyID(keyID) {
		return pgstore.BackupKey{}, problem.NotFound
	}
	row, err := q.GetBackupKeyForUpdate(ctx, keyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, problem.NotFound
	}
	if err != nil {
		return row, fmt.Errorf("read the backup key: %w", err)
	}
	if row.State != keyStateUnconfirmed {
		return row, problem.InvalidState.WithDetail("key " + keyID + " is " + row.State)
	}
	return row, nil
}

func keyFromRow(r pgstore.BackupKey) Key {
	return Key{KeyID: r.KeyID, Fingerprint: r.Fingerprint, State: r.State, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
		ConfirmedAt: r.ConfirmedAt, ConfirmedBy: r.ConfirmedBy, RetiredAt: r.RetiredAt, Attempts: int(r.Attempts), Legacy: r.Legacy}
}

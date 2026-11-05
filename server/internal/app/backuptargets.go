package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Privileged actions on backup targets (plan M15 decision 10): platform administrators with a step-up.
var (
	SpecBackupTargetCreate = ActionSpec{Code: audit.CodePlatformBackupTargetCreated, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecBackupTargetUpdate = ActionSpec{Code: audit.CodePlatformBackupTargetUpdated, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecBackupTargetDelete = ActionSpec{Code: audit.CodePlatformBackupTargetDeleted, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecBackupTargetTest   = ActionSpec{Code: audit.CodePlatformBackupTargetTested, AllowedRoles: RolesPlatform, RequiresStepUp: true}
)

// BackupWrapKey is the Transit key of the backup target credentials and the backup key (plan M15 decision 5): the api
// encrypts, only the backup role decrypts.
const BackupWrapKey = "backup-wrap"

// Host states of a target (plan M15 decision 2).
const (
	HostStateNA      = "n/a"
	HostStatePending = "pending_host"
)

// backupTargetNameKey is the unique constraint of backup_target.name.
const backupTargetNameKey = "backup_target_name_key"

// credentialPlaceholder stands in for a stored credential the api cannot decrypt, so that an update without the
// password or secret key passes the length checks of ValidateTarget.
const credentialPlaceholder = "-"

// PlatformEncrypter encrypts platform data with a Transit key that is not derived (the bao client).
type PlatformEncrypter interface {
	EncryptPlatform(ctx context.Context, key string, plaintext []byte) (string, error)
}

// BackupTargets are the platform use cases of the backup targets (plan M15 decisions 10 and 11).
type BackupTargets struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	keys     PlatformEncrypter
	policy   backupset.Policy
}

// NewBackupTargets creates the use cases; policy is the S3 endpoint policy (the development stack admits private
// addresses).
func NewBackupTargets(runner *ActionRunner, platform *db.PlatformPool, keys PlatformEncrypter, policy backupset.Policy) *BackupTargets {
	return &BackupTargets{runner: runner, platform: platform, keys: keys, policy: policy}
}

// TargetInput are the writable fields of a target; only the group of Type is read. On an update an empty
// SMB.Password, or empty S3.AccessKey and S3.SecretKey, keep the stored credentials.
type TargetInput struct {
	Name    string
	Type    backupset.TargetType
	Enabled bool
	Local   backupset.Local
	SMB     backupset.SMB
	NFS     backupset.NFS
	S3      backupset.S3
}

// Target is a target as the API shows it: never a credential.
type Target struct {
	ID              uuid.UUID
	Name            string
	Type            string
	Enabled         bool
	HostState       string
	HostRevision    int
	Settings        backupset.Settings
	HasCredentials  bool
	TestRequestedAt *time.Time
	LastTestAt      *time.Time
	LastTestOK      *bool
	LastTestError   *string
	Status          []TargetKindStatus
	CreatedBy       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// TargetKindStatus is the mirror state of one kind on a target, written by the backup role.
type TargetKindStatus struct {
	Kind          string
	LastSuccessAt *time.Time
	LastError     *string
	Bytes         int64
}

// TargetQuery selects one page of targets.
type TargetQuery struct {
	Page       ListPage
	Types      []string
	Enabled    *bool
	HostStates []string
}

// List returns one page of the targets.
func (b *BackupTargets) List(ctx context.Context, query TargetQuery) (Listed[Target], error) {
	var out Listed[Target]
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	err := b.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		types, states := nilIfEmpty(query.Types), nilIfEmpty(query.HostStates)
		n, err := q.CountBackupTargets(ctx, pgstore.CountBackupTargetsParams{
			QPattern: query.Page.QPattern, Types: types, Enabled: query.Enabled, HostStates: states, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count backup targets: %w", err)
		}
		out.Count = int(n)
		rows, err := q.ListBackupTargets(ctx, pgstore.ListBackupTargetsParams{
			QPattern: query.Page.QPattern, Types: types, Enabled: query.Enabled, HostStates: states,
			Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list backup targets: %w", err)
		}
		out.Items = make([]Target, len(rows))
		for i, r := range rows {
			out.Items[i] = toTarget(ctx, pgstore.GetBackupTargetRow(r))
		}
		return withTargetStatus(ctx, q, out.Items)
	})
	return out, err
}

// Get returns one target; a missing or deleted one is not_found.
func (b *BackupTargets) Get(ctx context.Context, id uuid.UUID) (Target, error) {
	var out Target
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	err := b.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = getTarget(ctx, q, id)
		return err
	})
	return out, err
}

// Create adds a target (audited: platform.backup_target_created). A local, SMB or NFS target waits for the host step
// (pending_host, revision 1); an S3 target has no host state.
func (b *BackupTargets) Create(ctx context.Context, in TargetInput) (Target, error) {
	var out Target
	spec := withTargetInputParams(SpecBackupTargetCreate, in)
	err := b.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		t := in.target()
		if err := b.validate(t); err != nil {
			return err
		}
		settings, err := json.Marshal(backupset.SettingsOf(t))
		if err != nil {
			return err
		}
		var ciphertext *string
		if creds, ok := backupset.CredentialsOf(t); ok {
			ct, err := b.encrypt(ctx, creds)
			if err != nil {
				return err
			}
			ciphertext = &ct
		}
		id := uuid.Must(uuid.NewV7())
		hostState := HostStateNA
		if backupset.Mounted(t.Type) {
			hostState = HostStatePending
		}
		if err := q.InsertBackupTarget(ctx, pgstore.InsertBackupTargetParams{
			ID: id, Name: in.Name, Type: string(t.Type), Enabled: in.Enabled, Settings: settings,
			CredentialsCiphertext: ciphertext, HostState: hostState, CreatedBy: actorDisplay(ctx),
		}); err != nil {
			return duplicateTargetName(err)
		}
		out, err = getTarget(ctx, q, id)
		if err != nil {
			return err
		}
		recordTarget(rec, out)
		return nil
	})
	return out, err
}

// Update replaces a target's settings (audited: platform.backup_target_updated). The type never changes. Without a
// new password (SMB) or key pair (S3) the stored credentials stay, but only for the same destination: the api cannot
// decrypt them, so a change of a setting that decides where they go (backupset.DestinationChange) needs them again. A change of a local, SMB or NFS target's settings or credentials raises its host
// revision and resets its host state to pending_host (plan M15 decision 10).
func (b *BackupTargets) Update(ctx context.Context, id uuid.UUID, in TargetInput) (Target, error) {
	var out Target
	spec := withTargetInputParams(SpecBackupTargetUpdate, in)
	spec.Params["change"] = "updated"
	delete(spec.Params, "type")
	err := b.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.LockBackupTarget(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(backupTargetAudit(id, cur.Name))
		rec.SetParam("type", cur.Type)
		rec.SetParam("host_revision", cur.HostRevision)
		if in.Type != "" && string(in.Type) != cur.Type {
			return problem.InvalidRequest.WithDetail("the type of a backup target cannot change; create a new target")
		}
		in.Type = backupset.TargetType(cur.Type)
		curSettings, err := backupset.ParseSettings(cur.Settings)
		if err != nil {
			return err
		}
		t := in.target()
		creds, hasCreds := backupset.CredentialsOf(t)
		replace := hasCreds && (creds.Password != "" || creds.AccessKey != "" || creds.SecretKey != "")
		if hasCreds && !replace {
			if err := keepCredentials(&t, cur.HasCredentials, curSettings, backupset.SettingsOf(t)); err != nil {
				return err
			}
		}
		if err := b.validate(t); err != nil {
			return err
		}
		next := backupset.SettingsOf(t)
		settings, err := json.Marshal(next)
		if err != nil {
			return err
		}
		var ciphertext *string
		if replace {
			ct, err := b.encrypt(ctx, creds)
			if err != nil {
				return err
			}
			ciphertext = &ct
		}
		hostState, revision := cur.HostState, cur.HostRevision
		if backupset.Mounted(t.Type) && (next != curSettings || replace) {
			hostState, revision = HostStatePending, cur.HostRevision+1
		}
		if err := q.UpdateBackupTarget(ctx, pgstore.UpdateBackupTargetParams{
			ID: id, Name: in.Name, Enabled: in.Enabled, Settings: settings, CredentialsCiphertext: ciphertext,
			HostState: hostState, HostRevision: revision,
		}); err != nil {
			return duplicateTargetName(err)
		}
		out, err = getTarget(ctx, q, id)
		if err != nil {
			return err
		}
		recordTarget(rec, out)
		return nil
	})
	return out, err
}

// keepCredentials completes t with placeholders for the stored credentials. A target without stored credentials or
// with a changed destination (cur → next) needs the full credentials.
func keepCredentials(t *backupset.Target, stored bool, cur, next backupset.Settings) error {
	changed := backupset.DestinationChange(t.Type, cur, next)
	switch t.Type {
	case backupset.TypeSMB:
		if !stored {
			return problem.InvalidRequest.WithDetail("smb.password is required")
		}
		if changed != "" {
			return problem.InvalidRequest.WithDetail("smb.password is required when " + changed + " changes")
		}
		t.SMB.Password = credentialPlaceholder
	case backupset.TypeS3:
		if !stored {
			return problem.InvalidRequest.WithDetail("s3.access_key and s3.secret_key are required")
		}
		if changed != "" {
			return problem.InvalidRequest.WithDetail("s3.access_key and s3.secret_key are required when " + changed + " changes")
		}
		t.S3.AccessKey, t.S3.SecretKey = credentialPlaceholder, credentialPlaceholder
	}
	return nil
}

// Delete removes a target (audited: platform.backup_target_deleted). A local, SMB or NFS target is marked deleted and
// disabled: ./paddock backup-target apply unmounts its volume and then deletes the row. The sets written to it stay.
func (b *BackupTargets) Delete(ctx context.Context, id uuid.UUID) error {
	return b.runner.RunTx(ctx, ScopePlatform, SpecBackupTargetDelete, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.LockBackupTarget(ctx, id)
		if err != nil {
			return notFound(err)
		}
		recordLocked(rec, cur)
		if backupset.Mounted(backupset.TargetType(cur.Type)) {
			return q.MarkBackupTargetDeleted(ctx, id)
		}
		return q.DeleteBackupTarget(ctx, id)
	})
}

// Enable enables a disabled target (audited: platform.backup_target_updated, change enabled).
func (b *BackupTargets) Enable(ctx context.Context, id uuid.UUID) (Target, error) {
	return b.setEnabled(ctx, id, true)
}

// Disable disables an enabled target (audited: platform.backup_target_updated, change disabled): the backup role no
// longer mirrors to it.
func (b *BackupTargets) Disable(ctx context.Context, id uuid.UUID) (Target, error) {
	return b.setEnabled(ctx, id, false)
}

func (b *BackupTargets) setEnabled(ctx context.Context, id uuid.UUID, enabled bool) (Target, error) {
	var out Target
	spec := SpecBackupTargetUpdate
	change := "disabled"
	if enabled {
		change = "enabled"
	}
	spec.Params = map[string]any{"change": change}
	err := b.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.LockBackupTarget(ctx, id)
		if err != nil {
			return notFound(err)
		}
		recordLocked(rec, cur)
		if cur.Enabled == enabled {
			return problem.InvalidState.WithDetail("the backup target is already " + change)
		}
		if err := q.SetBackupTargetEnabled(ctx, pgstore.SetBackupTargetEnabledParams{ID: id, Enabled: enabled}); err != nil {
			return err
		}
		out, err = getTarget(ctx, q, id)
		if err != nil {
			return err
		}
		recordTarget(rec, out)
		return nil
	})
	return out, err
}

// Test requests a connection test (audited: platform.backup_target_tested; success means requested). The api cannot
// decrypt the credentials, so the backup role tests in its next round and writes last_test_* (plan M15 decision 11).
func (b *BackupTargets) Test(ctx context.Context, id uuid.UUID) (Target, error) {
	var out Target
	err := b.runner.RunTx(ctx, ScopePlatform, SpecBackupTargetTest, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.LockBackupTarget(ctx, id)
		if err != nil {
			return notFound(err)
		}
		recordLocked(rec, cur)
		if err := q.RequestBackupTargetTest(ctx, id); err != nil {
			return err
		}
		out, err = getTarget(ctx, q, id)
		return err
	})
	return out, err
}

func (b *BackupTargets) validate(t backupset.Target) error {
	if err := b.policy.ValidateTarget(t); err != nil {
		if errors.Is(err, backupset.ErrInvalidTarget) {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		return err
	}
	return nil
}

func (b *BackupTargets) encrypt(ctx context.Context, creds backupset.Credentials) (string, error) {
	// The JSON is the plaintext that Transit encrypts at once; it is cleared afterwards and never stored or logged.
	plain, err := json.Marshal(creds) //nolint:gosec // G117: the credentials are marshalled only to be encrypted
	if err != nil {
		return "", err
	}
	defer clear(plain)
	ct, err := b.keys.EncryptPlatform(ctx, BackupWrapKey, plain)
	if err != nil {
		return "", fmt.Errorf("encrypt the backup target credentials: %w", err)
	}
	return ct, nil
}

func (in TargetInput) target() backupset.Target {
	return backupset.Target{Name: in.Name, Type: in.Type, Local: in.Local, SMB: in.SMB, NFS: in.NFS, S3: in.S3}
}

func getTarget(ctx context.Context, q *pgstore.Queries, id uuid.UUID) (Target, error) {
	row, err := q.GetBackupTarget(ctx, id)
	if err != nil {
		return Target{}, notFound(err)
	}
	out := []Target{toTarget(ctx, row)}
	if err := withTargetStatus(ctx, q, out); err != nil {
		return Target{}, err
	}
	return out[0], nil
}

func toTarget(ctx context.Context, r pgstore.GetBackupTargetRow) Target {
	// The api wrote the settings itself; a row it cannot read shows empty settings instead of failing the list.
	settings, err := backupset.ParseSettings(r.Settings)
	if err != nil {
		slog.ErrorContext(ctx, "backup target settings unreadable", "target_id", r.ID, "error", err)
	}
	return Target{
		ID: r.ID, Name: r.Name, Type: r.Type, Enabled: r.Enabled, HostState: r.HostState,
		HostRevision: int(r.HostRevision), Settings: settings, HasCredentials: r.HasCredentials,
		TestRequestedAt: r.TestRequestedAt, LastTestAt: r.LastTestAt, LastTestOK: r.LastTestOk,
		LastTestError: r.LastTestError, Status: []TargetKindStatus{}, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

// withTargetStatus fills the mirror state of every target with one query.
func withTargetStatus(ctx context.Context, q *pgstore.Queries, targets []Target) error {
	if len(targets) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(targets))
	index := make(map[uuid.UUID]int, len(targets))
	for i, t := range targets {
		ids[i], index[t.ID] = t.ID, i
	}
	rows, err := q.ListBackupTargetStatus(ctx, ids)
	if err != nil {
		return fmt.Errorf("list backup target status: %w", err)
	}
	for _, r := range rows {
		i := index[r.TargetID]
		targets[i].Status = append(targets[i].Status, TargetKindStatus{
			Kind: r.Kind, LastSuccessAt: r.LastSuccessAt, LastError: r.LastError, Bytes: r.Bytes,
		})
	}
	return nil
}

func withTargetInputParams(spec ActionSpec, in TargetInput) ActionSpec {
	spec.Params = map[string]any{"name": in.Name, "type": string(in.Type), "enabled": in.Enabled}
	return spec
}

func backupTargetAudit(id uuid.UUID, name string) audit.Target {
	return audit.Target{Type: "backup_target", ID: id.String(), Display: name}
}

func recordLocked(rec Recorder, cur pgstore.LockBackupTargetRow) {
	rec.SetTarget(backupTargetAudit(cur.ID, cur.Name))
	rec.SetParam("target_id", cur.ID.String())
	rec.SetParam("name", cur.Name)
	rec.SetParam("type", cur.Type)
	rec.SetParam("enabled", cur.Enabled)
	rec.SetParam("host_revision", cur.HostRevision)
}

func recordTarget(rec Recorder, t Target) {
	rec.SetTarget(backupTargetAudit(t.ID, t.Name))
	rec.SetParam("target_id", t.ID.String())
	rec.SetParam("name", t.Name)
	rec.SetParam("type", t.Type)
	rec.SetParam("enabled", t.Enabled)
	rec.SetParam("host_revision", t.HostRevision)
}

func duplicateTargetName(err error) error {
	if db.IsUniqueViolation(err, backupTargetNameKey) {
		return problem.AlreadyExists.WithDetail("a backup target with this name exists or waits for its removal on the host")
	}
	return err
}

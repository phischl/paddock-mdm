package backuprole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

// SetReader is a backup set a restore reads (plan M15 decision 23): a set directory (an extracted upload, the
// repository), a mounted target's copy or an S3 target's copy. Paths are relative to the set's root.
type SetReader interface {
	// List returns the size of every file of the set.
	List(ctx context.Context) (map[string]int64, error)
	// Open streams the file at path.
	Open(ctx context.Context, path string) (io.ReadCloser, error)
}

// setDir is a set directory: its root holds manifest.json.
type setDir string

// NewSetDir returns the set whose root is the directory root. Every access goes through an os.Root, so a symlink in
// an uploaded set never leads outside it.
func NewSetDir(root string) SetReader { return setDir(root) }

func (d setDir) List(_ context.Context) (map[string]int64, error) {
	r, err := os.OpenRoot(string(d))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	idx, err := indexRepo(r)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(idx))
	for p, fi := range idx {
		out[p] = fi.size
	}
	return out, nil
}

func (d setDir) Open(_ context.Context, p string) (io.ReadCloser, error) {
	if !validPath(p) {
		return nil, fmt.Errorf("backup set: invalid path %q", p)
	}
	r, err := os.OpenRoot(string(d))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return openRegular(r, p)
}

// Open streams a file of a mounted target's set.
func (d *dirTarget) Open(_ context.Context, p string) (io.ReadCloser, error) {
	if !validPath(p) {
		return nil, fmt.Errorf("backup target: invalid path %q", p)
	}
	r, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return openRegular(r, p)
}

// Open streams a file of an S3 target's set.
func (s *s3Target) Open(ctx context.Context, p string) (io.ReadCloser, error) {
	if !validPath(p) {
		return nil, fmt.Errorf("backup target: invalid path %q", p)
	}
	return s.store.Open(ctx, s.setPrefix()+p)
}

// AsSetReader returns the target as a set a restore reads; every target TargetFactory and OpenTargetFile return is
// one.
func AsSetReader(t Target) (SetReader, error) {
	r, ok := t.(SetReader)
	if !ok {
		return nil, fmt.Errorf("backup target %T cannot be read by a restore", t)
	}
	return r, nil
}

// CopyOptions select what CopySet copies.
type CopyOptions struct {
	// Prefix limits the copy to the paths below it, e.g. "pgbackrest/<key_id>/"; empty copies the whole set.
	Prefix string
	// NoClobber keeps every file dst already holds, whatever its size: merging into a live repository never replaces
	// pgBackRest's info files with an older copy.
	NoClobber bool
}

// CopySet copies every file of src below o.Prefix that dst lacks, or holds with another size unless o.NoClobber,
// with manifest.json last, so an interrupted copy never looks complete. It returns the files and bytes copied.
func CopySet(ctx context.Context, src SetReader, dst *os.Root, o CopyOptions) (int, int64, error) {
	have, err := src.List(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("list the backup set: %w", err)
	}
	local, err := indexRepo(dst)
	if err != nil {
		return 0, 0, fmt.Errorf("list the destination: %w", err)
	}
	paths := slices.Sorted(maps.Keys(have))
	if i := slices.Index(paths, backupset.ManifestPath); i >= 0 {
		paths = append(slices.Delete(paths, i, i+1), backupset.ManifestPath)
	}
	var files int
	var bytes int64
	for _, p := range paths {
		if !strings.HasPrefix(p, o.Prefix) || !validPath(p) {
			continue
		}
		if fi, ok := local[p]; ok && (o.NoClobber || fi.size == have[p]) {
			continue
		}
		if err := copyOne(ctx, src, dst, p, have[p]); err != nil {
			return files, bytes, err
		}
		files++
		bytes += have[p]
	}
	return files, bytes, nil
}

func copyOne(ctx context.Context, src SetReader, dst *os.Root, p string, size int64) error {
	body, err := src.Open(ctx, p)
	if err != nil {
		return fmt.Errorf("read %s: %w", p, err)
	}
	defer func() { _ = body.Close() }()
	if err := writeInRoot(dst, p, body, size); err != nil {
		return fmt.Errorf("write %s: %w", p, err)
	}
	return nil
}

// EmptyDir removes everything below the root r, which stays (the repository volume's mount point).
func EmptyDir(r *os.Root) error {
	entries, err := fs.ReadDir(r.FS(), ".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := r.RemoveAll(e.Name()); err != nil {
			return err
		}
	}
	return nil
}

// SetInfo is what a restore needs to know of a backup set before it changes anything (plan M15 decision 23).
type SetInfo struct {
	Manifest backupset.Manifest
	// Stanzas are the stanzas the set's pgBackRest repository holds at least one backup of, sorted.
	Stanzas []string
	// Oldest is the start time of each stanza's oldest backup: a point before it cannot be restored.
	Oldest map[string]time.Time
	// OpenBao and Fleet are the set paths of the newest snapshot and dump at or before the restore point; empty when
	// the set holds none.
	OpenBao, Fleet string
}

var (
	stanzaDir = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	// backupLabel is pgBackRest's backup directory name: a full backup's start, or for a differential or incremental
	// backup the full one it depends on and its own start.
	backupLabel = regexp.MustCompile(`^([0-9]{8}-[0-9]{6})F(?:_([0-9]{8}-[0-9]{6})[DI])?$`)
)

// InspectSet reads and validates the manifest of the set at root and picks the newest OpenBao snapshot and Fleet
// dump at or before at (the newest of all when at is zero). A file counts only when it is a regular file whose name
// is exactly the time format the backup role writes; the manifest's lists are not trusted for the choice, because a
// target can hold older files the manifest no longer names.
func InspectSet(root *os.Root, at time.Time) (SetInfo, error) {
	f, err := openRegular(root, backupset.ManifestPath)
	if err != nil {
		return SetInfo{}, fmt.Errorf("backup set: %w", err)
	}
	raw, err := readLimited(f, backupset.ManifestPath)
	_ = f.Close()
	if err != nil {
		return SetInfo{}, err
	}
	m, err := backupset.Parse(raw)
	if err != nil {
		return SetInfo{}, err
	}
	info := SetInfo{Manifest: m, Oldest: map[string]time.Time{}}
	entries, err := fs.ReadDir(root.FS(), m.Contents.PgBackRest.Path+"/backup")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return SetInfo{}, err
	}
	for _, e := range entries {
		if !e.IsDir() || !stanzaDir.MatchString(e.Name()) {
			continue
		}
		oldest, err := oldestBackup(root, m.Contents.PgBackRest.Path+"/backup/"+e.Name())
		if err != nil {
			return SetInfo{}, err
		}
		if !oldest.IsZero() {
			info.Stanzas = append(info.Stanzas, e.Name())
			info.Oldest[e.Name()] = oldest
		}
	}
	if info.OpenBao, err = newestAtOrBefore(root, "openbao", ".snap.enc", at); err != nil {
		return SetInfo{}, err
	}
	if info.Fleet, err = newestAtOrBefore(root, "fleet", ".sql.gz.enc", at); err != nil {
		return SetInfo{}, err
	}
	return info, nil
}

// oldestBackup is the start of the oldest backup in a stanza's directory, zero when it holds none. The labels are
// plain directory names even in an encrypted repository; pgBackRest writes them in its container's time zone, UTC.
func oldestBackup(root *os.Root, dir string) (time.Time, error) {
	entries, err := fs.ReadDir(root.FS(), dir)
	if err != nil {
		return time.Time{}, err
	}
	var oldest time.Time
	for _, e := range entries {
		g := backupLabel.FindStringSubmatch(e.Name())
		if !e.IsDir() || g == nil {
			continue
		}
		start := g[1]
		if g[2] != "" {
			start = g[2]
		}
		t, err := time.Parse("20060102-150405", start)
		if err != nil {
			continue
		}
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	return oldest, nil
}

func newestAtOrBefore(root *os.Root, dir, suffix string, at time.Time) (string, error) {
	entries, err := fs.ReadDir(root.FS(), dir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var best string
	var bestAt time.Time
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		t, ok := nameTime(e.Name())
		if !ok || e.Name() != t.Format("20060102T150405Z")+suffix || (!at.IsZero() && t.After(at)) {
			continue
		}
		if best == "" || t.After(bestAt) {
			best, bestAt = dir+"/"+e.Name(), t
		}
	}
	return best, nil
}

// EscrowLister lists the escrow bucket (the backup role's read-only credential).
type EscrowLister interface {
	ListSizes(ctx context.Context, prefix string) (map[string]int64, error)
}

// EscrowPutter writes escrowed LUKS headers into the escrow bucket.
type EscrowPutter interface {
	PutReader(ctx context.Context, key string, body io.ReadSeeker, size int64) error
}

// EscrowResult counts what RestoreEscrow did.
type EscrowResult struct {
	// Put headers were written, Present ones the bucket already held with the same size.
	Put, Present int
	// Destroyed headers were skipped because their device's escrow was destroyed after (or, without a recorded time,
	// possibly after) the copy was taken.
	Destroyed int
}

// RestoreEscrow puts every escrowed LUKS header of the set at root into the escrow bucket that the bucket lacks or
// holds with another size (plan M15 decision 23 step 7). destroyed maps "<org>/<device>" to the time of the device's
// newest successful Destroy (Store.EscrowEvidence): a copy that Destroy covers, or one without a recorded time of a
// destroyed device, is never put back, because that would undo the crypto-shredding (ADR 0046, note 2026-11-05 c).
func RestoreEscrow(ctx context.Context, root *os.Root, m backupset.Manifest, list EscrowLister, put EscrowPutter,
	destroyed map[string]time.Time) (EscrowResult, error) {
	var res EscrowResult
	present, err := list.ListSizes(ctx, "org/")
	if err != nil {
		return res, fmt.Errorf("list the escrow bucket: %w", err)
	}
	recorded := map[string]time.Time{}
	for _, f := range m.Contents.Escrow {
		if !f.At.IsZero() {
			recorded[f.Path] = f.At.UTC()
		}
	}
	idx, err := indexRepo(root)
	if err != nil {
		return res, err
	}
	for _, p := range idx.under(backupset.EscrowKey("")) {
		key := strings.TrimPrefix(p, backupset.EscrowKey(""))
		if !backupset.EscrowHeader(key) {
			continue
		}
		if at, ok := destroyed[escrowDevice(p)]; ok {
			copied, known := recorded[p]
			if !known || !copied.After(at) {
				res.Destroyed++
				continue
			}
		}
		if size, ok := present[key]; ok && size == idx[p].size {
			res.Present++
			continue
		}
		if err := putEscrow(ctx, root, put, p, key, idx[p].size); err != nil {
			return res, err
		}
		res.Put++
	}
	return res, nil
}

func putEscrow(ctx context.Context, root *os.Root, put EscrowPutter, p, key string, size int64) error {
	f, err := openRegular(root, p)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := put.PutReader(ctx, key, f, size); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	return nil
}

// TargetFileSchema identifies the file ./paddock backup-target export writes.
const TargetFileSchema = "paddock.backup-target.v1"

// TargetFile is one S3 target with its credentials (plan M15 decision 24): the operator keeps it with the backup key
// and restores a lost installation from that target with ./paddock restore --from-target-file, without a database.
type TargetFile struct {
	Schema      string                `json:"schema"`
	Name        string                `json:"name"`
	Type        backupset.TargetType  `json:"type"`
	Settings    backupset.Settings    `json:"settings"`
	Credentials backupset.Credentials `json:"credentials"`
}

// ParseTargetFile reads a target file and checks that it names an S3 target with credentials.
func ParseTargetFile(raw []byte) (TargetFile, error) {
	var f TargetFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return TargetFile{}, errors.New("backup target file: not valid JSON")
	}
	switch {
	case f.Schema != TargetFileSchema:
		return TargetFile{}, fmt.Errorf("backup target file: schema must be %s", TargetFileSchema)
	case f.Type != backupset.TypeS3:
		return TargetFile{}, errors.New("backup target file: only an S3 target can be read without its host mount")
	case f.Settings.Endpoint == "" || f.Settings.Bucket == "":
		return TargetFile{}, errors.New("backup target file: endpoint and bucket are required")
	case f.Credentials.AccessKey == "" || f.Credentials.SecretKey == "":
		return TargetFile{}, errors.New("backup target file: access_key and secret_key are required")
	}
	return f, nil
}

// OpenTargetFile returns the set an S3 target file names.
func OpenTargetFile(f TargetFile) (SetReader, error) {
	store, err := objectstore.NewWithOptions(f.Settings.Endpoint, f.Credentials.AccessKey, f.Credentials.SecretKey,
		f.Settings.Bucket, objectstore.Options{Region: f.Settings.Region, CAPEM: f.Settings.CAPEM})
	if err != nil {
		return nil, err
	}
	return AsSetReader(NewS3Target(store, f.Settings.Prefix))
}

// ExportTarget returns the target file of an S3 target record with its decrypted credentials.
func ExportTarget(ctx context.Context, keys Decrypter, t TargetRecord) (TargetFile, error) {
	if t.Type != backupset.TypeS3 {
		return TargetFile{}, fmt.Errorf("backup target %s is a %s target: mount its share on the new host and restore "+
			"with --from <path>", t.Name, t.Type)
	}
	creds, err := decryptCredentials(ctx, keys, t)
	if err != nil {
		return TargetFile{}, err
	}
	return TargetFile{Schema: TargetFileSchema, Name: t.Name, Type: t.Type, Settings: t.Settings,
		Credentials: backupset.Credentials{AccessKey: creds.AccessKey, SecretKey: creds.SecretKey}}, nil
}

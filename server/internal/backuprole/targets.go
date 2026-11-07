package backuprole

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

// Target is one place that holds a copy of the backup set (plan M15 §6.3). Paths are relative to the set's root.
type Target interface {
	// List returns the size of every file of the set the target holds.
	List(ctx context.Context) (map[string]int64, error)
	// Newest returns the modification time of the newest file of the set below dir (a path with a trailing slash), or
	// the zero time when the target holds none.
	Newest(ctx context.Context, dir string) (time.Time, error)
	// Read returns the file at path, at most maxRead bytes; found is false when the target lacks it.
	Read(ctx context.Context, path string) (data []byte, found bool, err error)
	// Put stores size bytes of r at path, replacing a file there.
	Put(ctx context.Context, path string, r io.Reader, size int64) error
	// Delete removes the file at path; a missing file is no error.
	Delete(ctx context.Context, path string) error
	// Probe writes and removes a test file next to the set (plan M15 decision 11).
	Probe(ctx context.Context) error
}

// Error classes of a target (plan M15 decision 11): stored in last_test_error, backup_target_status.last_error and the
// runs' targets, never an error text that could carry a host's answer.
const (
	ClassDNS        = "dns"
	ClassDial       = "dial"
	ClassTLS        = "tls"
	ClassAuth       = "auth"
	ClassForbidden  = "forbidden"
	ClassNotMounted = "not_mounted"
	ClassReadOnly   = "read_only"
	ClassIO         = "io"
	// ClassForeignSet: the target holds the set of another installation (or a manifest that does not parse); the
	// mirror neither writes nor deletes there, so a rebuilt host never wipes the copies it may have to restore from.
	ClassForeignSet = "foreign_set"
	// ClassSetShrunk: writing pgBackRest's files to the target could make its copy unrestorable (plan M15, amendment
	// 2026-11-05, A3 step 2): the target holds a full backup the local stanza lacks and the local expire would still
	// keep, info files the local set lacks, or the active key's repository the local set lacks entirely, as after a
	// lost repository volume; the mirror writes and deletes nothing there until the set is whole.
	ClassSetShrunk = "set_shrunk"
	// ClassUnknownPath: the target holds a repository path of no key the database knows; the mirror copies but deletes
	// nothing on that target until an operator removed the path (A3 G3).
	ClassUnknownPath = "unknown_path"
	// ClassSizeMismatch: a file copied in this round has another size on the target (A3 step 4).
	ClassSizeMismatch = "size_mismatch"
	// ClassContinues is no error: the mirror used the round's copy budget and goes on next round (decisions-alpha9
	// item 79). The run's target is not ok, but the target's status records no last_error and keeps its last success.
	ClassContinues = "continues"
)

var (
	errForeignSet   = errors.New("backup target holds the set of another installation")
	errSetShrunk    = errors.New("the local backup set lacks what the target holds; nothing is written or deleted")
	errUnknownPath  = errors.New("backup target holds a repository path no backup key names; nothing is deleted there")
	errSizeMismatch = errors.New("backup target holds another size than the copied file")
	// errBudget ends a mirror that used its round's time; the target is not current yet (ClassContinues), and the next
	// round goes on with the files it still lacks.
	errBudget = errors.New("backup target mirror used its round's budget; it continues next round")
)

// maxRead bounds a file Read takes into memory (a manifest, a marker): a share or bucket can plant any size.
const maxRead = 64 << 20

// errNotMounted marks a volume target whose volume the host has not mounted (yet).
var errNotMounted = errors.New("backup target is not mounted")

// ErrorClass maps a target error to its class.
func ErrorClass(err error) string {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certErr x509.CertificateInvalidError
	var api interface{ ErrorCode() string }
	var resp *awshttp.ResponseError
	switch {
	case errors.Is(err, errNotMounted):
		return ClassNotMounted
	case errors.Is(err, errForeignSet):
		return ClassForeignSet
	case errors.Is(err, errSetShrunk):
		return ClassSetShrunk
	case errors.Is(err, errUnknownPath):
		return ClassUnknownPath
	case errors.Is(err, errSizeMismatch):
		return ClassSizeMismatch
	case errors.Is(err, syscall.EROFS):
		return ClassReadOnly
	case errors.As(err, &dnsErr):
		return ClassDNS
	case errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &certErr),
		strings.Contains(err.Error(), "tls: "):
		return ClassTLS
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return ClassDial
	case errors.As(err, &api) && s3AuthCodes[api.ErrorCode()]:
		return ClassAuth
	case errors.As(err, &api) && api.ErrorCode() == "AccessDenied",
		errors.Is(err, fs.ErrPermission):
		return ClassForbidden
	case errors.As(err, &resp) && resp.HTTPStatusCode() == 401:
		return ClassAuth
	case errors.As(err, &resp) && resp.HTTPStatusCode() == 403:
		return ClassForbidden
	}
	return ClassIO
}

var s3AuthCodes = map[string]bool{"InvalidAccessKeyId": true, "SignatureDoesNotMatch": true,
	"InvalidToken": true, "ExpiredToken": true}

// testFile is the file a probe writes and removes (plan M15 decision 11).
const testFile = ".paddock-test"

// tmpPrefix starts the name of a file a directory target is still writing; List never reports it.
const tmpPrefix = ".paddock-tmp-"

// validPath reports whether p is a clean relative slash path: a target never writes outside its set, whatever an
// object key of the escrow bucket or a file name of the repository holds (PDK-729 review, minor 4).
func validPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return false
	}
	for el := range strings.SplitSeq(p, "/") {
		if el == "" || el == "." || el == ".." {
			return false
		}
	}
	return true
}

// dirTarget is a mounted volume target: the set lives in <mount>/paddock-backup.
type dirTarget struct{ mount, name string }

// NewDirTarget returns the target whose set is the directory root (<targets>/<id>/paddock-backup). Every access goes
// through an os.Root on the volume, so neither a path nor a symlink planted on the share (the set's directory
// included) leads outside the volume.
func NewDirTarget(root string) Target {
	return &dirTarget{mount: filepath.Dir(root), name: filepath.Base(root)}
}

// errPlanted marks a directory or file of a share that is not what the role created there (a symlink, a file).
var errPlanted = errors.New("backup target: unexpected file type")

// openMount opens a target's volume as an os.Root. The volume's directory is the role's own mount point; everything
// below it belongs to whoever can write to the share.
func openMount(mount string) (*os.Root, error) {
	info, err := os.Lstat(mount) //nolint:gosec // the role's own mount point below the configured targets directory
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotMounted, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s", errPlanted, mount)
	}
	return os.OpenRoot(mount)
}

func (d *dirTarget) open() (*os.Root, error) {
	m, err := openMount(d.mount)
	if err != nil {
		return nil, err
	}
	defer func() { _ = m.Close() }()
	if err := m.Mkdir(d.name, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	// os.Root confines the paths below a root, not the root itself: a planted paddock-backup symlink would make the
	// set any directory the role can write (the repository, the runtime tmpfs, the Fleet dumps).
	info, err := m.Lstat(d.name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s", errPlanted, d.name)
	}
	return m.OpenRoot(d.name)
}

func (d *dirTarget) List(ctx context.Context) (map[string]int64, error) {
	return d.ListProgress(ctx, func() {})
}

// listTickEvery is the number of directory entries a target's listing walks between two progress ticks.
const listTickEvery = 1024

// ListProgress is List and calls tick every listTickEvery entries. It stops once ctx ends: a mirror given up on a
// slow share must not keep walking it and hold the target busy (PDK-866).
func (d *dirTarget) ListProgress(ctx context.Context, tick func()) (map[string]int64, error) {
	r, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	out := map[string]int64{}
	walked := 0
	err = fs.WalkDir(r.FS(), ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if walked++; walked%listTickEvery == 0 {
			tick()
		}
		if e.IsDir() || strings.HasPrefix(e.Name(), tmpPrefix) {
			return nil
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			out[p] = info.Size()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (d *dirTarget) Newest(ctx context.Context, dir string) (time.Time, error) {
	dir = strings.TrimSuffix(dir, "/")
	if !validPath(dir) {
		return time.Time{}, fmt.Errorf("backup target: invalid path %q", dir)
	}
	r, err := d.open()
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = r.Close() }()
	var newest time.Time
	err = fs.WalkDir(r.FS(), dir, func(_ string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDir() || strings.HasPrefix(e.Name(), tmpPrefix) {
			return nil
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, nil
	}
	return newest, err
}

func (d *dirTarget) Read(_ context.Context, p string) ([]byte, bool, error) {
	if !validPath(p) {
		return nil, false, fmt.Errorf("backup target: invalid path %q", p)
	}
	r, err := d.open()
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = r.Close() }()
	f, err := openRegular(r, p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	b, err := readLimited(f, p)
	return b, err == nil, err
}

// openRegular opens p below r for reading and fails unless it is a regular file. O_NONBLOCK keeps the open of a FIFO
// planted on the share from blocking until a writer appears; a regular file ignores the flag.
func openRegular(r *os.Root, p string) (*os.File, error) {
	f, err := r.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("%w: %s", errPlanted, p)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// readLimited reads r up to maxRead bytes and fails on a longer file.
func readLimited(r io.Reader, p string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxRead+1))
	if err == nil && len(b) > maxRead {
		err = fmt.Errorf("backup target: %s exceeds %d bytes", p, maxRead)
	}
	return b, err
}

// Put stops copying once ctx ends and then leaves no file at p: a mirror the stall watchdog gave up must not write
// to the target any more (PDK-862).
func (d *dirTarget) Put(ctx context.Context, p string, src io.Reader, size int64) error {
	if !validPath(p) {
		return fmt.Errorf("backup target: invalid path %q", p)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r, err := d.open()
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	return writeInRootCtx(ctx, r, p, ctxReader{ctx: ctx, r: src}, size)
}

// ctxReader ends a copy with ctx's error once ctx ended.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(b []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(b)
}

// writeInRoot writes src to p below r through a temporary file and a rename, so a reader never sees a partial file.
func writeInRoot(r *os.Root, p string, src io.Reader, size int64) error {
	return writeInRootCtx(context.Background(), r, p, src, size)
}

// writeInRootCtx is writeInRoot and does not rename the temporary file into place once ctx ended.
func writeInRootCtx(ctx context.Context, r *os.Root, p string, src io.Reader, size int64) error {
	dir := path.Dir(p)
	if dir != "." {
		if err := r.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	tmp := path.Join(dir, tmpPrefix+path.Base(p))
	// O_EXCL after the removal: a FIFO or device planted under the temporary name would block or redirect the write.
	if err := r.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, src)
	if err == nil && size >= 0 && n != size {
		err = fmt.Errorf("backup target: wrote %d of %d bytes of %s", n, size, p)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = r.Rename(tmp, p)
	}
	if err != nil {
		_ = r.Remove(tmp)
	}
	return err
}

func (d *dirTarget) Delete(_ context.Context, p string) error {
	if !validPath(p) {
		return fmt.Errorf("backup target: invalid path %q", p)
	}
	r, err := d.open()
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if err := r.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Empty directories of an expired pgBackRest backup would otherwise pile up; a directory still in use stays.
	for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
		if r.Remove(dir) != nil {
			break
		}
	}
	return nil
}

func (d *dirTarget) Probe(_ context.Context) error {
	r, err := openMount(d.mount)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	return probeIn(r, testFile)
}

// probeIn writes and removes name below r. It removes whatever the share left at name first and creates the file
// exclusively, so a planted symlink is never followed (O_EXCL does not follow it) and nothing but the probe is written.
func probeIn(r *os.Root, name string) error {
	if err := r.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte{'1'})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if rerr := r.Remove(name); err == nil {
		err = rerr
	}
	return err
}

// progressLister is a Target whose listing reports progress: listing a set of a few hundred thousand objects takes
// minutes on some S3 endpoints and on a slow share, and a mirror's stall watchdog must not take that for a stall
// (PDK-865).
type progressLister interface {
	ListProgress(ctx context.Context, tick func()) (map[string]int64, error)
}

// listProgress lists dst and reports progress to tick when dst can.
func listProgress(ctx context.Context, dst Target, tick func()) (map[string]int64, error) {
	if p, ok := dst.(progressLister); ok {
		return p.ListProgress(ctx, tick)
	}
	return dst.List(ctx)
}

// S3Store is the part of objectstore.Store an S3 target uses.
type S3Store interface {
	Ping(ctx context.Context) error
	ListSizes(ctx context.Context, prefix string) (map[string]int64, error)
	ListSizesPaged(ctx context.Context, prefix string, page func()) (map[string]int64, error)
	Newest(ctx context.Context, prefix string) (newest time.Time, found bool, err error)
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	PutReader(ctx context.Context, key string, body io.ReadSeeker, size int64) error
	Delete(ctx context.Context, key string) error
}

// s3Target is a bucket target: the set lives below <prefix>/paddock-backup/.
type s3Target struct {
	store S3Store
	// base is the administrator's prefix with a trailing slash, or "".
	base string
}

// NewS3Target returns the target whose set lives below <prefix>/paddock-backup/ of store's bucket.
func NewS3Target(store S3Store, prefix string) Target {
	base := strings.Trim(prefix, "/")
	if base != "" {
		base += "/"
	}
	return &s3Target{store: store, base: base}
}

func (s *s3Target) setPrefix() string { return s.base + backupset.SetRoot + "/" }

func (s *s3Target) List(ctx context.Context) (map[string]int64, error) {
	return s.ListProgress(ctx, func() {})
}

// ListProgress is List and calls tick after every page of the bucket listing.
func (s *s3Target) ListProgress(ctx context.Context, tick func()) (map[string]int64, error) {
	all, err := s.store.ListSizesPaged(ctx, s.setPrefix(), tick)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(all))
	for k, size := range all {
		p := strings.TrimPrefix(k, s.setPrefix())
		if !validPath(p) {
			// The role never writes such a key and cannot delete it either; reporting it would fail every round.
			slog.WarnContext(ctx, "backup target object with an unusable key skipped", "key", k)
			continue
		}
		out[p] = size
	}
	return out, nil
}

func (s *s3Target) Newest(ctx context.Context, dir string) (time.Time, error) {
	if !validPath(strings.TrimSuffix(dir, "/")) {
		return time.Time{}, fmt.Errorf("backup target: invalid path %q", dir)
	}
	newest, _, err := s.store.Newest(ctx, s.setPrefix()+dir)
	return newest, err
}

func (s *s3Target) Read(ctx context.Context, p string) ([]byte, bool, error) {
	if !validPath(p) {
		return nil, false, fmt.Errorf("backup target: invalid path %q", p)
	}
	body, err := s.store.Open(ctx, s.setPrefix()+p)
	if errors.Is(err, objectstore.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = body.Close() }()
	b, err := readLimited(body, p)
	return b, err == nil, err
}

func (s *s3Target) Put(ctx context.Context, p string, r io.Reader, size int64) error {
	if !validPath(p) {
		return fmt.Errorf("backup target: invalid path %q", p)
	}
	rs, ok := r.(io.ReadSeeker)
	if !ok {
		return fmt.Errorf("backup target: %s is not seekable", p)
	}
	return s.store.PutReader(ctx, s.setPrefix()+p, rs, size)
}

func (s *s3Target) Delete(ctx context.Context, p string) error {
	if !validPath(p) {
		return fmt.Errorf("backup target: invalid path %q", p)
	}
	return s.store.Delete(ctx, s.setPrefix()+p)
}

func (s *s3Target) Probe(ctx context.Context) error {
	if err := s.store.Ping(ctx); err != nil {
		// HeadBucket's answer has no body, so a refused credential and a refused bucket both read 403; a listing
		// carries S3's error code and tells them apart.
		if _, lerr := s.store.ListSizes(ctx, s.base+testFile); lerr != nil && ErrorClass(lerr) == ClassAuth {
			return lerr
		}
		return err
	}
	key := s.base + testFile
	if err := s.store.PutReader(ctx, key, strings.NewReader("1"), 1); err != nil {
		return err
	}
	return s.store.Delete(ctx, key)
}

// Decrypter decrypts Transit ciphertext of the platform (bao.Client.DecryptPlatform with the AppRole paddock-backup).
type Decrypter interface {
	DecryptPlatform(ctx context.Context, key, ciphertext string) ([]byte, error)
}

// TargetFactory opens the Target of a target record.
type TargetFactory interface {
	Open(ctx context.Context, t TargetRecord) (Target, error)
}

// targetFactory opens S3 targets with their decrypted credentials and volume targets below the targets directory.
type targetFactory struct {
	keys       Decrypter
	targetsDir string
}

// NewTargetFactory returns the factory of the backup role.
func NewTargetFactory(keys Decrypter, targetsDir string) TargetFactory {
	return &targetFactory{keys: keys, targetsDir: targetsDir}
}

func (f *targetFactory) Open(ctx context.Context, t TargetRecord) (Target, error) {
	if backupset.Mounted(t.Type) {
		return NewDirTarget(filepath.Join(MountDir(f.targetsDir, t), backupset.SetRoot)), nil
	}
	if t.Type != backupset.TypeS3 {
		return nil, fmt.Errorf("backup target %s: unknown type %q", t.ID, t.Type)
	}
	creds, err := decryptCredentials(ctx, f.keys, t)
	if err != nil {
		return nil, err
	}
	store, err := objectstore.NewWithOptions(t.Settings.Endpoint, creds.AccessKey, creds.SecretKey, t.Settings.Bucket,
		objectstore.Options{Region: t.Settings.Region, CAPEM: t.Settings.CAPEM})
	if err != nil {
		return nil, err
	}
	return NewS3Target(store, t.Settings.Prefix), nil
}

// decryptCredentials decrypts the Transit-wrapped credentials of a target (backup-wrap).
func decryptCredentials(ctx context.Context, keys Decrypter, t TargetRecord) (backupset.Credentials, error) {
	if t.CredentialsCiphertext == "" {
		return backupset.Credentials{}, fmt.Errorf("backup target %s: no credentials", t.ID)
	}
	plain, err := keys.DecryptPlatform(ctx, app.BackupWrapKey, t.CredentialsCiphertext)
	if err != nil {
		return backupset.Credentials{}, fmt.Errorf("backup target %s: decrypt credentials: %w", t.ID, err)
	}
	creds, err := backupset.ParseCredentials(plain)
	if err != nil {
		return backupset.Credentials{}, fmt.Errorf("backup target %s: %w", t.ID, err)
	}
	return creds, nil
}

// MountDir is the directory of a volume target in the backup role's container (plan M15 decision 16 g).
func MountDir(targetsDir string, t TargetRecord) string {
	return filepath.Join(targetsDir, t.ID.String())
}

// markerFile is written into a volume target by ./paddock backup-target apply with the host revision it mounted.
const markerFile = ".paddock-mount"

// probeTimeout bounds the host check of a share: a hard-mounted share that went away blocks a read or write instead of
// failing.
const probeTimeout = 10 * time.Second

// probeFile is the file the host check writes and removes in a volume.
const probeFile = ".paddock-probe"

// HostState returns the host state of a volume target (plan M15 decision 16 g): pending_host while the volume or its
// marker for the current revision is missing, unreachable when a write fails, mounted otherwise. It blocks while the
// share does; the engine bounds it.
func HostState(targetsDir string, t TargetRecord) string {
	return hostState(MountDir(targetsDir, t), t.HostRevision)
}

// hostState reads the marker and probes the volume inside an os.Root on it, so a symlink planted on the share is
// never followed out of the volume.
func hostState(dir string, revision int) string {
	m, err := openMount(dir)
	if err != nil {
		return HostPending
	}
	defer func() { _ = m.Close() }()
	f, err := openRegular(m, markerFile)
	if err != nil {
		return HostPending
	}
	raw, err := io.ReadAll(io.LimitReader(f, 32))
	_ = f.Close()
	if err != nil {
		return HostPending
	}
	rev, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || rev < revision {
		return HostPending
	}
	if probeIn(m, probeFile) != nil {
		return HostUnreachable
	}
	return HostMounted
}

// Host states of a target (plan M15 decision 2).
const (
	HostNA          = "n/a"
	HostPending     = "pending_host"
	HostMounted     = "mounted"
	HostUnreachable = "unreachable"
)

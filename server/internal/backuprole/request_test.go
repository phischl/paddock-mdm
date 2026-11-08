package backuprole

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestRequestNotAnsweredByARunningFull: a backup requested while a full was running (it started before the request
// and finished after it) is not answered by that full; the request stays for serve, which takes a full that starts
// after it. A request at or before the full's start is answered (decisions-alpha9 item 89; gates BS1/BS3, where the
// path switch's full after a restore answered `backup now` and the target status never reached the request).
func TestRequestNotAnsweredByARunningFull(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	for _, k := range []string{KindOpenBao, KindEscrow, KindFleet, KindAuthentik} {
		f.store.history[k] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	}
	started := f.now.Add(-2 * time.Minute).Truncate(time.Second)
	finished := started.Add(30 * time.Second)
	before := RequestedRun{ID: uuid.New(), Kind: KindPostgres, CreatedAt: started.Add(400 * time.Millisecond)}
	during := RequestedRun{ID: uuid.New(), Kind: KindPostgres, CreatedAt: started.Add(10 * time.Second)}
	f.store.requests = []RequestedRun{before, during}
	for name, at := range map[string]time.Time{"last-full-start": started, "last-full": finished} {
		if err := os.WriteFile(filepath.Join(f.cfg.StateDir, "paddock", name), []byte(strconvUnix(at)), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	f.round(t)
	if n := f.store.answers(before.ID); n != 1 {
		t.Errorf("the request in the full's start second answered %d times, want once", n)
	}
	if n := f.store.answers(during.ID); n != 0 {
		t.Errorf("the request made while the full ran answered %d times, want none", n)
	}
	req, err := os.ReadFile(filepath.Join(f.cfg.RuntimeDir, "request-paddock"))
	if err != nil || string(req) != strconvUnix(during.CreatedAt) {
		t.Errorf("request file %q, %v; want the waiting request for serve", req, err)
	}
}

// TestShareGoneIsUnreachable: a mount or marker the share's server no longer answers is unreachable, one that is absent
// or planted is pending (decisions-alpha9 item 89; gate BS1 stops smbd and expects unreachable).
func TestShareGoneIsUnreachable(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"smbd stopped":      {&fs.PathError{Op: "openat", Path: markerFile, Err: syscall.EHOSTDOWN}, HostUnreachable},
		"I/O error":         {&fs.PathError{Op: "read", Path: markerFile, Err: syscall.EIO}, HostUnreachable},
		"stale NFS handle":  {&fs.PathError{Op: "lstat", Path: "/backup-targets/x", Err: syscall.ESTALE}, HostUnreachable},
		"not mounted":       {&fs.PathError{Op: "openat", Path: markerFile, Err: syscall.ENOENT}, HostPending},
		"planted":           {errPlanted, HostPending},
		"escaping symlink":  {&fs.PathError{Op: "openat", Path: markerFile, Err: syscall.EXDEV}, HostPending},
		"permission denied": {&fs.PathError{Op: "openat", Path: markerFile, Err: syscall.EACCES}, HostPending},
	} {
		if got := absentOr(tc.err); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
}

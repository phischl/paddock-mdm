package supervisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/update"
	"github.com/phischl/paddock-mdm/pkg/releasesig"
)

// fake is a supervisor on temporary directories whose agent binaries are shell scripts.
type fake struct {
	t       *testing.T
	dir     string
	cfg     Config
	priv    minisign.PrivateKey
	usr1    chan os.Signal
	cancel  context.CancelFunc
	done    chan struct{}
	notices chan string
	clock   *clock
}

// clock is the supervisor's injected clock: real time plus an offset the test sets to end a probation exactly when
// the test has observed what it needs (no race between a real-time probation and a slow -race run).
type clock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *clock) set(offset time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset = offset
}

// testProbation is longer than any test; probations end through endProbation.
const testProbation = time.Hour

// script returns a fake paddockd: `version` prints version, `self-test` exits selfTest, `run` runs run.
func script(version string, selfTest int, run string) []byte {
	return fmt.Appendf(nil, "#!/bin/sh\ncase \"$1\" in\nversion) echo %s ;;\nself-test) exit %d ;;\nrun) %s ;;\nesac\n", version, selfTest, run)
}

func newFake(t *testing.T) *fake {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{t: t, dir: dir, priv: priv, usr1: make(chan os.Signal, 1), notices: make(chan string, 1000), clock: &clock{}}
	f.cfg = Config{
		Slots: filepath.Join(dir, "slots"), Staging: filepath.Join(dir, "staging"), Result: filepath.Join(dir, "result.json"),
		ProbationLog: filepath.Join(dir, "probation.json"), LastCheckin: filepath.Join(dir, "last-checkin"),
		PublicKey: &pub, Probation: testProbation, SelfTest: 5 * time.Second, Tick: 20 * time.Millisecond,
		MaxBackoff: 2 * time.Second, Notify: func(s string) { f.notices <- s }, Now: f.clock.now,
	}
	for _, d := range []string{"slots/A", "slots/B", "staging"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script("1.0.0", 0, f.good()))
	if err := os.Symlink("A", filepath.Join(f.cfg.Slots, "current")); err != nil {
		t.Fatal(err)
	}
	return f
}

// good is a run behaviour that checks in once and keeps running. The check-in is a shell builtin, not touch: a
// forked touch can outlive the SIGTERM of a stopping test and write into its removed temporary directory.
func (f *fake) good() string { return "trap '' HUP; : >" + f.cfg.LastCheckin + "; exec sleep 300" }

func (f *fake) writeExec(path string, data []byte) {
	f.t.Helper()
	if err := os.WriteFile(path, data, 0o755); err != nil { //nolint:gosec // test script
		f.t.Fatal(err)
	}
}

func (f *fake) start() {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel, f.done = cancel, make(chan struct{})
	s := New(f.cfg)
	go func() { s.Run(ctx, f.usr1); close(f.done) }()
	f.t.Cleanup(f.stop)
}

func (f *fake) stop() {
	if f.cancel != nil {
		f.cancel()
		<-f.done
		f.cancel = nil
	}
}

// stage puts a release into staging as the agent does and sends SIGUSR1; signer nil signs with the release key, the
// trusted comment names version and this architecture.
func (f *fake) stage(version string, bin []byte, signer *minisign.PrivateKey) {
	f.t.Helper()
	f.stageSigned(version, bin, signer, releasesig.Comment(version, runtime.GOARCH))
}

// stageSigned is stage with the trusted comment comment ("": minisign's default timestamp comment).
func (f *fake) stageSigned(version string, bin []byte, signer *minisign.PrivateKey, comment string) {
	f.t.Helper()
	key := f.priv
	if signer != nil {
		key = *signer
	}
	sig := minisign.Sign(key, bin)
	if comment != "" {
		sig = minisign.SignWithComments(key, bin, comment, "paddock agent release")
	}
	dir := filepath.Join(f.cfg.Staging, version)
	_ = os.MkdirAll(dir, 0o700)
	f.writeExec(filepath.Join(dir, "paddockd"), bin)
	if err := os.WriteFile(filepath.Join(dir, "paddockd.minisig"), sig, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.cfg.Staging, "request.json"), []byte(`{"version":"`+version+`"}`), 0o600); err != nil {
		f.t.Fatal(err)
	}
	f.usr1 <- syscall.SIGUSR1
}

type result struct {
	Version, FromVersion, Outcome string
	At                            time.Time
}

func (f *fake) waitResult(timeout time.Duration) result {
	f.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(f.cfg.Result)
		if err == nil {
			var r struct {
				Version     string    `json:"version"`
				FromVersion string    `json:"from_version"`
				Outcome     string    `json:"outcome"`
				At          time.Time `json:"at"`
			}
			if err := json.Unmarshal(data, &r); err != nil {
				f.t.Fatal(err)
			}
			return result{r.Version, r.FromVersion, r.Outcome, r.At}
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("no update result within %s", timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitFor polls cond until it holds.
func (f *fake) waitFor(what string, cond func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			f.t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *fake) checkedIn() bool {
	_, err := os.Stat(f.cfg.LastCheckin)
	return err == nil
}

// endProbation waits until the switch to slot happened, moves the clock past the probation and returns the result.
func (f *fake) endProbation(slot string) result {
	f.t.Helper()
	f.waitFor("current → "+slot, func() bool { return f.active() == slot })
	f.clock.set(testProbation + time.Minute)
	defer f.clock.set(0)
	return f.waitResult(10 * time.Second)
}

// stageAfterCheckin waits until the running agent has checked in, removes its check-in mark (so only the new
// agent can set it again) and stages a release.
func (f *fake) stageAfterCheckin(version string, bin []byte) {
	f.t.Helper()
	f.waitFor("the running agent checked in", f.checkedIn)
	if err := os.Remove(f.cfg.LastCheckin); err != nil {
		f.t.Fatal(err)
	}
	f.stage(version, bin, nil)
}

func (f *fake) active() string {
	target, _ := os.Readlink(filepath.Join(f.cfg.Slots, "current"))
	return target
}

func (f *fake) expectStagingClean() {
	f.t.Helper()
	entries, _ := os.ReadDir(f.cfg.Staging)
	if len(entries) != 0 {
		f.t.Fatalf("staging not cleaned: %v", entries)
	}
}

func TestUpdateSuccess(t *testing.T) {
	f := newFake(t)
	f.start()
	f.stageAfterCheckin("1.1.0", script("1.1.0", 0, f.good()))
	f.waitFor("the new agent checked in", f.checkedIn)
	r := f.endProbation("B")
	if r.Outcome != outcomeUpdated || r.Version != "1.1.0" || r.FromVersion != "1.0.0" {
		t.Fatalf("result %+v", r)
	}
	if f.active() != "B" {
		t.Fatalf("current → %s, want B", f.active())
	}
	if _, err := os.Stat(f.cfg.ProbationLog); !os.IsNotExist(err) {
		t.Fatal("probation log left behind")
	}
	f.expectStagingClean()
	// The next update goes into the other slot again.
	_ = os.Remove(f.cfg.Result)
	f.stageAfterCheckin("1.2.0", script("1.2.0", 0, f.good()))
	f.waitFor("the new agent checked in", f.checkedIn)
	if r := f.endProbation("A"); r.Outcome != outcomeUpdated || f.active() != "A" {
		t.Fatalf("second update %+v, current %s", r, f.active())
	}
}

// TestUpdateCheckinStampedBeforeTheSwitch (PDK-031): the kernel stamps files with its coarse clock, so a check-in
// right after the switch can carry an mtime before the switch time; it still proves the new agent healthy.
func TestUpdateCheckinStampedBeforeTheSwitch(t *testing.T) {
	f := newFake(t)
	f.start()
	staged := time.Now()
	f.stageAfterCheckin("1.1.0", script("1.1.0", 0, f.good()))
	f.waitFor("the new agent checked in", f.checkedIn)
	stamp := staged.Add(-time.Millisecond)
	if err := os.Chtimes(f.cfg.LastCheckin, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if r := f.endProbation("B"); r.Outcome != outcomeUpdated || r.Version != "1.1.0" || f.active() != "B" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
}

// TestRollbackWhenOnlyTheOldAgentCheckedIn: a check-in mark of the agent before the switch never passes the
// probation of the new one, even if the test leaves it in place.
func TestRollbackWhenOnlyTheOldAgentCheckedIn(t *testing.T) {
	f := newFake(t)
	f.start()
	f.waitFor("the running agent checked in", f.checkedIn)
	f.stage("1.1.0", script("1.1.0", 0, "trap '' HUP; exec sleep 300"), nil)
	r := f.endProbation("B")
	if r.Outcome != outcomeRolledBack || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
}

func TestUpdateRefused(t *testing.T) {
	_, other, _ := minisign.GenerateKey(rand.Reader)
	tests := []struct {
		name    string
		bin     func(f *fake) []byte
		signer  *minisign.PrivateKey
		outcome string
	}{
		{"bad signature", func(f *fake) []byte { return script("1.1.0", 0, f.good()) }, &other, outcomeSignatureInvalid},
		{"self-test fails", func(f *fake) []byte { return script("1.1.0", 1, f.good()) }, nil, outcomeSelfTestFailed},
		{"wrong version", func(f *fake) []byte { return script("9.9.9", 0, f.good()) }, nil, outcomeSelfTestFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.start()
			f.stage("1.1.0", tt.bin(f), tt.signer)
			if r := f.waitResult(10 * time.Second); r.Outcome != tt.outcome || r.FromVersion != "1.0.0" {
				t.Fatalf("result %+v", r)
			}
			if f.active() != "A" {
				t.Fatalf("switched to %s", f.active())
			}
			f.expectStagingClean()
		})
	}
}

// TestReleaseBinding (plan M4b.1 decision 11): the signed trusted comment must name the requested version and this
// architecture, and a release not newer than the active agent is refused, unless the active agent has failed.
func TestReleaseBinding(t *testing.T) {
	tests := []struct {
		name, version, comment, outcome string
	}{
		{"missing comment", "1.1.0", "", outcomeSignatureInvalid},
		{"other version in comment", "1.1.0", releasesig.Comment("1.0.5", runtime.GOARCH), outcomeSignatureInvalid},
		{"other architecture", "1.1.0", releasesig.Comment("1.1.0", "riscv64"), outcomeSignatureInvalid},
		{"older release", "0.9.0", releasesig.Comment("0.9.0", runtime.GOARCH), outcomeDowngradeRefused},
		{"same release", "1.0.0", releasesig.Comment("1.0.0", runtime.GOARCH), outcomeDowngradeRefused},
		{"pre-release of the active", "1.0.0-rc.1", releasesig.Comment("1.0.0-rc.1", runtime.GOARCH), outcomeDowngradeRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.start()
			f.stageSigned(tt.version, script(tt.version, 0, f.good()), nil, tt.comment)
			if r := f.waitResult(10 * time.Second); r.Outcome != tt.outcome || r.FromVersion != "1.0.0" || r.Version != tt.version {
				t.Fatalf("result %+v", r)
			}
			if f.active() != "A" {
				t.Fatalf("switched to %s", f.active())
			}
			f.expectStagingClean()
		})
	}
	t.Run("older release replaces a failed agent", func(t *testing.T) {
		f := newFake(t)
		// The active agent runs but cannot report its version.
		f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), []byte("#!/bin/sh\n[ \"$1\" = run ] || exit 1\n"+f.good()+"\n"))
		f.start()
		f.stageAfterCheckin("0.9.0", script("0.9.0", 0, f.good()))
		f.waitFor("the new agent checked in", f.checkedIn)
		if r := f.endProbation("B"); r.Outcome != outcomeUpdated || r.Version != "0.9.0" {
			t.Fatalf("result %+v", r)
		}
	})
}

// alphaSequence is the release order of Paddock's pre-releases (PDK-022): alpha, beta and release candidates of a
// version precede the version itself.
var alphaSequence = []string{"0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-beta.1", "0.1.0-rc.1", "0.1.0"}

// TestPreReleaseSequence: the supervisor updates along the pre-release sequence and refuses every step back to an
// earlier pre-release.
func TestPreReleaseSequence(t *testing.T) {
	t.Run("updates", func(t *testing.T) {
		f := newFake(t)
		f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script(alphaSequence[0], 0, f.good()))
		f.start()
		slot := "A"
		for i, v := range alphaSequence[1:] {
			_ = os.Remove(f.cfg.Result)
			slot = map[string]string{"A": "B", "B": "A"}[slot]
			f.stageAfterCheckin(v, script(v, 0, f.good()))
			f.waitFor("the new agent checked in", f.checkedIn)
			if r := f.endProbation(slot); r.Outcome != outcomeUpdated || r.Version != v || r.FromVersion != alphaSequence[i] {
				t.Fatalf("%s → %s: result %+v", alphaSequence[i], v, r)
			}
		}
	})
	active := alphaSequence[2]
	for _, v := range alphaSequence[:3] {
		t.Run("refuses "+v+" over "+active, func(t *testing.T) {
			f := newFake(t)
			f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script(active, 0, f.good()))
			f.start()
			f.stage(v, script(v, 0, f.good()), nil)
			if r := f.waitResult(10 * time.Second); r.Outcome != outcomeDowngradeRefused || r.FromVersion != active || f.active() != "A" {
				t.Fatalf("result %+v, current %s", r, f.active())
			}
			f.expectStagingClean()
		})
	}
}

func TestUpdateWithoutReleaseKeyIsRefused(t *testing.T) {
	f := newFake(t)
	f.cfg.PublicKey = nil
	f.start()
	f.stage("1.1.0", script("1.1.0", 0, f.good()), nil)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeSignatureInvalid || f.active() != "A" {
		t.Fatalf("result %+v", r)
	}
}

func TestRollbackOnCrashLoop(t *testing.T) {
	f := newFake(t)
	f.start()
	f.stage("1.1.0", script("1.1.0", 0, "exit 1"), nil)
	r := f.waitResult(20 * time.Second)
	if r.Outcome != outcomeRolledBack || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
}

func TestRollbackOnProbationTimeout(t *testing.T) {
	f := newFake(t)
	f.start()
	// The old agent checked in before the switch; the new one never does.
	f.stageAfterCheckin("1.1.0", script("1.1.0", 0, "trap '' HUP; exec sleep 300"))
	r := f.endProbation("B")
	if r.Outcome != outcomeRolledBack || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
}

func TestResumeProbation(t *testing.T) {
	f := newFake(t)
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, "exit 1"))
	if err := flip(f.cfg.Slots, "B", syncDir); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(f.cfg.ProbationLog, probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B"}, syncFile); err != nil {
		t.Fatal(err)
	}
	f.start()
	if r := f.waitResult(20 * time.Second); r.Outcome != outcomeRolledBack || f.active() != "A" {
		t.Fatalf("a probation interrupted by a restart must still roll back: %+v", r)
	}
}

// TestResumeProbationIgnoresAnEarlierCheckin: a check-in mark from before the supervisor restarted does not pass the
// resumed probation of an agent that never checks in.
func TestResumeProbationIgnoresAnEarlierCheckin(t *testing.T) {
	f := newFake(t)
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, "trap '' HUP; exec sleep 300"))
	if err := flip(f.cfg.Slots, "B", syncDir); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(f.cfg.ProbationLog, probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B"}, syncFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.cfg.LastCheckin, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.start()
	// The supervisor removes the mark only after it has resumed the probation and set its deadline.
	f.waitFor("the supervisor removed the earlier check-in", func() bool { return !f.checkedIn() })
	if r := f.endProbation("B"); r.Outcome != outcomeRolledBack || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
}

// lockedBuffer collects the supervisor's log, which its goroutine writes while the test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog redirects slog until the test ends; call it before fake.start so the supervisor stops first.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	b := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(b, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return b
}

// keepCheckinMark makes the check-in mark a non-empty directory, which os.Remove cannot remove.
func (f *fake) keepCheckinMark() {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.cfg.LastCheckin, "stuck"), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

// TestRollbackWhenTheCheckinMarkSurvivesTheSwitch (PDK-031): a mark that cannot be removed at the switch would pass
// a new agent that never checks in, so the probation rolls back without waiting for its deadline.
func TestRollbackWhenTheCheckinMarkSurvivesTheSwitch(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script("1.0.0", 0, "trap '' HUP; exec sleep 300"))
	f.keepCheckinMark()
	f.start()
	f.stage("1.1.0", script("1.1.0", 0, "trap '' HUP; exec sleep 300"), nil)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.Version != "1.1.0" || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	if !strings.Contains(log.String(), "check-in mark could not be cleared") {
		t.Fatalf("rollback reason missing from the log:\n%s", log.String())
	}
}

// TestRollbackWhenTheCheckinMarkSurvivesTheResume (PDK-031): the same for a probation that a restarted supervisor
// resumes; the rollback happens in the loop, after the current agent started, never in resumeProbation.
func TestRollbackWhenTheCheckinMarkSurvivesTheResume(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, "trap '' HUP; exec sleep 300"))
	if err := flip(f.cfg.Slots, "B", syncDir); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(f.cfg.ProbationLog, probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B"}, syncFile); err != nil {
		t.Fatal(err)
	}
	f.keepCheckinMark()
	f.start()
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.Version != "1.1.0" || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	if !strings.Contains(log.String(), "check-in mark could not be cleared") {
		t.Fatalf("rollback reason missing from the log:\n%s", log.String())
	}
}

// waitSent waits for a watchdog notice that the Run loop sends after the current one; after an update result showed
// up, its arrival proves that finish returned and so sent the check-in request.
func (f *fake) waitSent() {
	f.t.Helper()
	for len(f.notices) > 0 {
		<-f.notices
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case n := <-f.notices:
			if n == "WATCHDOG=1" {
				return
			}
		case <-deadline:
			f.t.Fatal("timed out waiting for the next watchdog notice")
		}
	}
}

// resumeFailingProbation prepares a supervisor that resumes a probation of 1.1.0 in slot B and rolls it back on its
// first tick, because the check-in mark cannot be cleared; sleep replaces the waits between flip attempts.
func (f *fake) resumeFailingProbation(sleep func(time.Duration)) {
	f.t.Helper()
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, "trap '' HUP; exec sleep 300"))
	if err := flip(f.cfg.Slots, "B", syncDir); err != nil {
		f.t.Fatal(err)
	}
	if err := writeJSON(f.cfg.ProbationLog, probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B"}, syncFile); err != nil {
		f.t.Fatal(err)
	}
	f.keepCheckinMark()
	f.cfg.Sleep = sleep
}

// blockFlip makes the flip's temporary symlink path a non-empty directory, so every flip fails until unblockFlip;
// unlike a read-only directory, this also holds for root.
func (f *fake) blockFlip() {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.cfg.Slots, ".current.tmp", "stuck"), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fake) unblockFlip() {
	if err := os.RemoveAll(filepath.Join(f.cfg.Slots, ".current.tmp")); err != nil {
		f.t.Error(err)
	}
}

// waits records the supervisor's waits between flip attempts; the supervisor's goroutine writes while the test reads.
type waits struct {
	mu   sync.Mutex
	list []time.Duration
}

func (w *waits) add(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.list = append(w.list, d)
}

func (w *waits) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return fmt.Sprint(w.list)
}

// TestRollbackReportsAFailedFlipBack (PDK-037): if current cannot be flipped back, the supervisor retries with
// bounded back-off, then reports the release as failed instead of rolled_back, while the new agent keeps running.
func TestRollbackReportsAFailedFlipBack(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	w := &waits{}
	f.resumeFailingProbation(w.add)
	f.blockFlip()
	f.start()
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeSelfTestFailed || r.Version != "1.1.0" || r.FromVersion != "1.0.0" {
		t.Fatalf("result %+v", r)
	}
	if f.active() != "B" {
		t.Fatalf("current → %s, want B", f.active())
	}
	if got := w.String(); got != "[250ms 500ms 1s 2s]" {
		t.Fatalf("waits between the flip attempts %s", got)
	}
	if !strings.Contains(log.String(), "rollback failed: current still points at the new agent") {
		t.Fatalf("failed rollback missing from the log:\n%s", log.String())
	}
}

// TestRollbackRetriesTheFlipBack (PDK-037): a flip back that fails once and then succeeds is a rollback.
func TestRollbackRetriesTheFlipBack(t *testing.T) {
	f := newFake(t)
	w := &waits{}
	f.resumeFailingProbation(func(d time.Duration) { w.add(d); f.unblockFlip() })
	f.blockFlip()
	f.start()
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.Version != "1.1.0" || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	if got := w.String(); got != "[250ms]" {
		t.Fatalf("waits between the flip attempts %s", got)
	}
}

// TestRollbackKeepsTheRestartedAgentAlive (PDK-035): the check-in request (SIGHUP) that follows a rollback reaches the
// old agent right after its start, before it could install a handler; it must not end the agent. The old agent sets
// no trap and waits on a FIFO that the test opens only after the request was sent, so it can only go on if it survived.
// The result file becomes visible before finish sends the request; a watchdog notice that arrives after the result
// proves the request was sent, because only the Run loop notifies and finish runs inside a tick after its notice.
func TestRollbackKeepsTheRestartedAgentAlive(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	fifo, alive := filepath.Join(f.dir, "go-on"), filepath.Join(f.dir, "alive")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script("1.0.0", 0, "read x < "+fifo+"; : > "+alive+"; exec sleep 300"))
	f.resumeFailingProbation(nil)
	f.start()
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	f.waitSent()
	if err := os.WriteFile(fifo, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.waitFor("the restarted agent went on", func() bool { _, err := os.Stat(alive); return err == nil })
	if strings.Contains(log.String(), "agent exited") {
		t.Fatalf("the check-in request ended the restarted agent:\n%s", log.String())
	}
}

func TestRestartsTheAgentAndPetsTheWatchdog(t *testing.T) {
	f := newFake(t)
	runs := filepath.Join(f.dir, "runs")
	f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script("1.0.0", 0, "echo x >> "+runs+"; exit 1"))
	f.start()
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, _ := os.ReadFile(runs) //nolint:gosec // test file
		if strings.Count(string(data), "x") >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent started %d times within 10 s", strings.Count(string(data), "x"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	f.stop()
	seen := map[string]bool{}
	for len(f.notices) > 0 {
		seen[<-f.notices] = true
	}
	if !seen["READY=1"] || !seen["WATCHDOG=1"] {
		t.Fatalf("notifications %v", seen)
	}
	if _, err := os.Stat(f.cfg.Result); !os.IsNotExist(err) {
		t.Fatal("a plain restart wrote an update result")
	}
}

// syncFault is the supervisor's injected sync of the slot directory: it fails with EIO while broken and records, for
// every call, which symlink current was and whether the sync succeeded.
type syncFault struct {
	mu     sync.Mutex
	broken bool
	calls  []syncCall
}

type syncCall struct {
	current os.FileInfo
	ok      bool
}

func (s *syncFault) sync(dir string) error {
	current, _ := os.Lstat(filepath.Join(dir, "current"))
	s.mu.Lock()
	broken := s.broken
	s.calls = append(s.calls, syncCall{current: current, ok: !broken})
	s.mu.Unlock()
	if broken {
		return fmt.Errorf("syncing %s: %w", dir, syscall.EIO)
	}
	return syncDir(dir)
}

// expectProvenByNewRename checks that the first successful sync after the last failed one saw another symlink current
// than the failed one: only a sync that follows a new rename proves the flip durable, a retried sync does not.
func (s *syncFault) expectProvenByNewRename(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	failed := -1
	for i, c := range s.calls {
		if !c.ok {
			failed = i
		}
	}
	if failed < 0 || failed+1 >= len(s.calls) {
		t.Fatalf("no successful sync after a failed one in %d syncs", len(s.calls))
	}
	before, after := s.calls[failed].current, s.calls[failed+1].current
	if before == nil || after == nil || os.SameFile(before, after) {
		t.Fatal("the sync that confirmed the flip followed no new rename of current")
	}
}

func (s *syncFault) set(broken bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.broken = broken
}

func (s *syncFault) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// waitSyncs waits until the supervisor synced the slot directory n times in all, and fails on any update result
// meanwhile; a sync after the flip's own is a confirmation attempt in a later tick, so by then a result of the flip
// would have been written.
func (f *fake) waitSyncs(sf *syncFault, n int) {
	f.t.Helper()
	f.waitFor(fmt.Sprintf("%d syncs of the slot directory", n), func() bool {
		f.expectNoResult()
		return sf.count() >= n
	})
}

func (f *fake) expectNoResult() {
	f.t.Helper()
	if data, err := os.ReadFile(f.cfg.Result); err == nil {
		f.t.Fatalf("an update result before the flip was durable: %s", data)
	}
}

// expectProbationLog checks that the probation log is still on disk and whether it marks a rollback.
func (f *fake) expectProbationLog(rollingBack bool) {
	f.t.Helper()
	var p probation
	data, err := os.ReadFile(f.cfg.ProbationLog)
	if err == nil {
		err = json.Unmarshal(data, &p)
	}
	if err != nil || p.RollingBack != rollingBack || p.ToSlot != "B" {
		f.t.Fatalf("probation log %s, error %v; want to_slot B, rolling_back %t", data, err, rollingBack)
	}
}

func (f *fake) expectNoProbationLog() {
	f.t.Helper()
	if _, err := os.Stat(f.cfg.ProbationLog); !os.IsNotExist(err) {
		f.t.Fatal("probation log left behind")
	}
}

// writeRollingBack writes the probation log of a rollback from B to A that waits for a durable flip back.
func (f *fake) writeRollingBack() {
	f.t.Helper()
	p := probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B", RollingBack: true}
	if err := writeJSON(f.cfg.ProbationLog, p, syncFile); err != nil {
		f.t.Fatal(err)
	}
}

// TestRollbackWaitsForADurableFlipBack (PDK-045): a flip back whose directory sync failed is visible but may be lost
// with the power. The supervisor runs the old agent, keeps the probation log marked as rolling back and reports
// rolled_back only after a new flip was synced.
func TestRollbackWaitsForADurableFlipBack(t *testing.T) {
	f := newFake(t)
	sf := &syncFault{broken: true}
	f.cfg.SyncDir = sf.sync
	f.resumeFailingProbation(nil)
	f.start()
	f.waitSyncs(sf, 2)
	if f.active() != "A" {
		t.Fatalf("current → %s, want A", f.active())
	}
	f.expectNoResult()
	f.expectProbationLog(true)
	sf.set(false)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.Version != "1.1.0" || r.FromVersion != "1.0.0" || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	f.expectNoProbationLog()
	sf.expectProvenByNewRename(t)
}

// TestUpdateWaitsForADurableSwitch (PDK-045): a switch whose directory sync failed still starts the new agent and its
// probation; the synced probation log stays, and "updated" follows only after a new flip was synced.
func TestUpdateWaitsForADurableSwitch(t *testing.T) {
	f := newFake(t)
	sf := &syncFault{}
	f.cfg.SyncDir = sf.sync
	f.start()
	sf.set(true)
	f.stageAfterCheckin("1.1.0", script("1.1.0", 0, f.good()))
	f.waitFor("the new agent checked in", func() bool { f.expectNoResult(); return f.checkedIn() })
	f.waitFor("current → B", func() bool { return f.active() == "B" })
	f.clock.set(testProbation + time.Minute)
	defer f.clock.set(0)
	f.waitSyncs(sf, 2)
	f.expectNoResult()
	f.expectProbationLog(false)
	sf.set(false)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeUpdated || r.Version != "1.1.0" || f.active() != "B" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	f.expectNoProbationLog()
	sf.expectProvenByNewRename(t)
}

// TestResumeARollbackThatWaitsForADurableFlipBack (PDK-045): after a restart, a rollback whose flip back is visible
// but unconfirmed is reported once a new flip was synced, not dropped as a flip that never happened.
func TestResumeARollbackThatWaitsForADurableFlipBack(t *testing.T) {
	f := newFake(t)
	sf := &syncFault{broken: true}
	f.cfg.SyncDir = sf.sync
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, f.good()))
	f.writeRollingBack()
	f.start()
	f.waitSyncs(sf, 1)
	f.expectNoResult()
	f.expectProbationLog(true)
	sf.set(false)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.Version != "1.1.0" || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	f.expectNoProbationLog()
}

// TestRestartAfterALostFlipBackDecidesAgain (PDK-045): a power loss takes the unsynced flip back with it, so current
// points at the new slot again. The probation log is still there, so the restarted supervisor resumes the probation
// and decides again, here a rollback, instead of leaving the new agent running without one.
func TestRestartAfterALostFlipBackDecidesAgain(t *testing.T) {
	f := newFake(t)
	sf := &syncFault{broken: true}
	f.cfg.SyncDir = sf.sync
	f.resumeFailingProbation(nil)
	f.start()
	f.waitSyncs(sf, 2)
	f.expectNoResult()
	f.stop()
	if err := flip(f.cfg.Slots, "B", syncDir); err != nil {
		t.Fatal(err)
	}
	sf.set(false)
	f.start()
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.Version != "1.1.0" || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	f.expectNoProbationLog()
}

// TestResumedProbationWaitsForADurableSwitch (PDK-045): a restarted supervisor cannot know whether the switch was ever
// synced, so a resumed probation that passes reports "updated" only after a new flip was synced.
func TestResumedProbationWaitsForADurableSwitch(t *testing.T) {
	f := newFake(t)
	sf := &syncFault{broken: true}
	f.cfg.SyncDir = sf.sync
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, f.good()))
	if err := flip(f.cfg.Slots, "B", syncDir); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(f.cfg.ProbationLog, probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B"}, syncFile); err != nil {
		t.Fatal(err)
	}
	f.start()
	f.waitFor("the resumed agent checked in", f.checkedIn)
	f.clock.set(testProbation + time.Minute)
	defer f.clock.set(0)
	f.waitSyncs(sf, 1)
	f.expectProbationLog(false)
	sf.set(false)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeUpdated || r.Version != "1.1.0" || f.active() != "B" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	f.expectNoProbationLog()
	sf.expectProvenByNewRename(t)
}

// TestUpdateRequestWhileARollbackWaits (PDK-045): a release staged while a rollback waits for a durable flip back is
// ignored; it neither switches slots nor overwrites the rolling_back log, and the rollback is still reported.
func TestUpdateRequestWhileARollbackWaits(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	sf := &syncFault{broken: true}
	f.cfg.SyncDir = sf.sync
	f.resumeFailingProbation(nil)
	f.start()
	f.waitSyncs(sf, 2)
	f.stage("1.2.0", script("1.2.0", 0, f.good()), nil)
	f.waitFor("the update request was ignored", func() bool {
		f.expectNoResult()
		if f.active() != "A" {
			t.Fatalf("the staged release switched current to %s", f.active())
		}
		return strings.Contains(log.String(), "update request ignored")
	})
	f.expectProbationLog(true)
	sf.set(false)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.Version != "1.1.0" || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
}

// TestPassedProbationIsNotRolledBackWhileItsSwitchWaits (PDK-045): once the new agent was healthy at the deadline,
// only the confirmation of the switch is outstanding; later exits of the agent are restarted, not rolled back.
func TestPassedProbationIsNotRolledBackWhileItsSwitchWaits(t *testing.T) {
	f := newFake(t)
	sf := &syncFault{broken: true}
	f.cfg.SyncDir = sf.sync
	die, runs := filepath.Join(f.dir, "die"), filepath.Join(f.dir, "runs")
	run := "trap '' HUP; echo x >> " + runs + "; : > " + f.cfg.LastCheckin + "; while [ ! -e " + die + " ]; do sleep 0.05; done; exit 1"
	f.start()
	f.stageAfterCheckin("1.1.0", script("1.1.0", 0, run))
	f.waitFor("the new agent checked in", func() bool { f.expectNoResult(); return f.checkedIn() })
	f.clock.set(testProbation + time.Minute)
	defer f.clock.set(0)
	f.waitSyncs(sf, 2)
	if err := os.WriteFile(die, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.waitFor("the new agent exited and was restarted three times", func() bool {
		f.expectNoResult()
		if f.active() != "B" {
			t.Fatalf("a passed release was rolled back: current → %s", f.active())
		}
		data, _ := os.ReadFile(runs) //nolint:gosec // test file
		return strings.Count(string(data), "x") >= 4
	})
	sf.set(false)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeUpdated || r.Version != "1.1.0" || f.active() != "B" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
}

// TestProbationLogIsSyncedBeforeTheSwitch (PDK-059): writeJSON syncs the file before the rename, and a switch whose
// probation log could not be synced does not happen, because a log lost with the power would drop the probation.
func TestProbationLogIsSyncedBeforeTheSwitch(t *testing.T) {
	f := newFake(t)
	f.cfg.SyncFile = func(file *os.File) error {
		if strings.HasPrefix(filepath.Base(file.Name()), filepath.Base(f.cfg.ProbationLog)) {
			return fmt.Errorf("syncing %s: %w", file.Name(), syscall.EIO)
		}
		return file.Sync()
	}
	f.start()
	f.stage("1.1.0", script("1.1.0", 0, f.good()), nil)
	f.waitFor("an update result", func() bool {
		if f.active() != "A" {
			t.Fatalf("switched to %s without a synced probation log", f.active())
		}
		_, err := os.Stat(f.cfg.Result)
		return err == nil
	})
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeSelfTestFailed || r.Version != "1.1.0" || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	f.expectNoProbationLog()
	if _, err := os.Stat(f.cfg.ProbationLog + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary probation log left behind")
	}
}

// durableLog is the supervisor's injected file sync; it records the probation log as last synced, which is the log a
// power loss brings back if its removal was not yet durable.
type durableLog struct {
	mu   sync.Mutex
	data []byte
}

func (d *durableLog) sync(log string) func(*os.File) error {
	return func(file *os.File) error {
		if file.Name() == log+".tmp" {
			data, err := os.ReadFile(file.Name())
			if err != nil {
				return err
			}
			d.mu.Lock()
			d.data = data
			d.mu.Unlock()
		}
		return file.Sync()
	}
}

// restartAfterLostLogRemoval simulates a power loss after the update result became durable but before the removal of
// the probation log did: it stops the supervisor, puts the last synced log back, removes the result as an agent that
// already reported it does, and starts the supervisor again.
func (f *fake) restartAfterLostLogRemoval(d *durableLog) {
	f.t.Helper()
	f.stop()
	f.expectNoProbationLog()
	d.mu.Lock()
	data := d.data
	d.mu.Unlock()
	if data == nil {
		f.t.Fatal("the probation log was never synced")
	}
	if err := os.WriteFile(f.cfg.ProbationLog, data, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Remove(f.cfg.Result); err != nil {
		f.t.Fatal(err)
	}
	f.start()
}

// expectSameResult checks that the restarted supervisor writes the result want again, unchanged, so that the agent,
// which reports a result once per "at", does not report it twice; and that two ticks later it still stands with
// current on slot.
func (f *fake) expectSameResult(want result, slot string) {
	f.t.Helper()
	check := func() {
		f.t.Helper()
		got := f.waitResult(10 * time.Second)
		if got.Outcome != want.Outcome || got.Version != want.Version || got.FromVersion != want.FromVersion || !got.At.Equal(want.At) {
			f.t.Fatalf("result after the restart %+v, want the first result %+v", got, want)
		}
		if f.active() != slot {
			f.t.Fatalf("current → %s, want %s", f.active(), slot)
		}
	}
	check()
	f.waitSent()
	f.waitSent()
	check()
	f.expectNoProbationLog()
	f.expectStagingClean()
}

// TestRestartAfterUpdatedDoesNotDecideAgain (PDK-058): a power loss after "updated" was written can bring back the
// probation log, whose removal was not synced. The restarted supervisor writes the same result again instead of
// resuming the probation, which here would roll back at once, because the check-in mark cannot be cleared.
func TestRestartAfterUpdatedDoesNotDecideAgain(t *testing.T) {
	f := newFake(t)
	d := &durableLog{}
	f.cfg.SyncFile = d.sync(f.cfg.ProbationLog)
	f.start()
	f.stageAfterCheckin("1.1.0", script("1.1.0", 0, f.good()))
	f.waitFor("the new agent checked in", f.checkedIn)
	first := f.endProbation("B")
	if first.Outcome != outcomeUpdated || first.Version != "1.1.0" {
		t.Fatalf("result %+v", first)
	}
	f.stop()
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, "trap '' HUP; exec sleep 300"))
	if err := os.Remove(f.cfg.LastCheckin); err != nil {
		t.Fatal(err)
	}
	f.keepCheckinMark()
	f.restartAfterLostLogRemoval(d)
	f.expectSameResult(first, "B")
}

// TestRestartAfterRolledBackDoesNotReportAgain (PDK-058): the same for a rollback whose flip back waited for a durable
// sync; the log that comes back is marked rolling_back, and the restarted supervisor writes the same rolled_back again
// instead of confirming the rollback anew with a second result.
func TestRestartAfterRolledBackDoesNotReportAgain(t *testing.T) {
	f := newFake(t)
	sf := &syncFault{broken: true}
	f.cfg.SyncDir = sf.sync
	d := &durableLog{}
	f.cfg.SyncFile = d.sync(f.cfg.ProbationLog)
	f.resumeFailingProbation(nil)
	f.start()
	f.waitSyncs(sf, 2)
	f.expectProbationLog(true)
	sf.set(false)
	first := f.waitResult(10 * time.Second)
	if first.Outcome != outcomeRolledBack || first.Version != "1.1.0" || f.active() != "A" {
		t.Fatalf("result %+v, current %s", first, f.active())
	}
	f.restartAfterLostLogRemoval(d)
	f.expectSameResult(first, "A")
}

// waitReady waits for the supervisor's READY notice, which it sends once it has resumed or dropped a probation log.
func (f *fake) waitReady() {
	f.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case n := <-f.notices:
			if n == "READY=1" {
				return
			}
		case <-deadline:
			f.t.Fatal("timed out waiting for READY")
		}
	}
}

// TestDroppedProbationCleansTheUpdateRequest (PDK-060): a probation log that a restarted supervisor cannot resume is
// dropped together with the update request, so that the agent stages the next release (update.Pending is false). No
// result is written: the log's release is unknown, or the switch may have been lost with the power.
func TestDroppedProbationCleansTheUpdateRequest(t *testing.T) {
	staged := probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B"}
	rolling := staged
	rolling.RollingBack = true
	for _, tc := range []struct {
		name string
		log  []byte // the raw probation log; nil writes probation instead
		probation
		current string
		// releaseKept: an unreadable log does not name the release, so its staged directory stays.
		releaseKept bool
	}{
		{name: "unreadable log", log: []byte("{"), current: "A", releaseKept: true},
		{name: "switch never happened", probation: staged, current: "A"},
		{name: "current on neither slot", probation: rolling, current: "C"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			layout := paths.Layout{Root: f.dir}
			f.cfg.Staging = layout.Staging()
			bin := script("1.1.0", 0, f.good())
			f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), bin)
			f.stage("1.1.0", bin, nil)
			<-f.usr1
			if !update.Pending(layout) {
				t.Fatal("the staged release is not pending")
			}
			if err := flip(f.cfg.Slots, tc.current, syncDir); err != nil {
				t.Fatal(err)
			}
			if tc.log != nil {
				if err := os.WriteFile(f.cfg.ProbationLog, tc.log, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := writeJSON(f.cfg.ProbationLog, tc.probation, syncFile); err != nil {
				t.Fatal(err)
			}
			f.start()
			f.waitReady()
			if update.Pending(layout) {
				t.Fatal("the update request is still pending after the probation log was dropped")
			}
			f.expectNoProbationLog()
			f.expectNoResult()
			if _, err := os.Stat(filepath.Join(f.cfg.Staging, "1.1.0")); os.IsNotExist(err) == tc.releaseKept {
				t.Fatalf("staged release kept %t, want %t", !os.IsNotExist(err), tc.releaseKept)
			}
		})
	}
}

package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"aead.dev/minisign"

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

func TestCompareVersions(t *testing.T) {
	// Ascending by SemVer 2.0.0 precedence (its own example list, Paddock's pre-release sequence, build metadata and
	// wide numbers).
	ordered := slices.Concat([]string{"0.0.0-dev"}, alphaSequence, []string{"0.9.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0", "10.0.0"})
	for i, a := range ordered {
		for j, b := range ordered {
			if got, want := compareVersions(a, b), cmpIndex(i, j); got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
	if compareVersions("1.0.0+build.1", "1.0.0+build.2") != 0 || compareVersions("0.2.1700000000-good", "0.1.0") != 1 {
		t.Error("build metadata or system test versions ordered wrongly")
	}
}

func cmpIndex(i, j int) int {
	switch {
	case i < j:
		return -1
	case i > j:
		return 1
	}
	return 0
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
	if err := flip(f.cfg.Slots, "B"); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(f.cfg.ProbationLog, probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B"}); err != nil {
		t.Fatal(err)
	}
	f.start()
	if r := f.waitResult(20 * time.Second); r.Outcome != outcomeRolledBack || f.active() != "A" {
		t.Fatalf("a probation interrupted by a restart must still roll back: %+v", r)
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

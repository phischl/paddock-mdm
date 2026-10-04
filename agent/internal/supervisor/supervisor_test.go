package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"aead.dev/minisign"
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
}

// script returns a fake paddockd: `version` prints version, `self-test` exits selfTest, `run` runs run.
func script(version string, selfTest int, run string) []byte {
	return fmt.Appendf(nil, "#!/bin/sh\ncase \"$1\" in\nversion) echo %s ;;\nself-test) exit %d ;;\nrun) %s ;;\nesac\n", version, selfTest, run)
}

func newFake(t *testing.T, probation time.Duration) *fake {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{t: t, dir: dir, priv: priv, usr1: make(chan os.Signal, 1), notices: make(chan string, 1000)}
	f.cfg = Config{
		Slots: filepath.Join(dir, "slots"), Staging: filepath.Join(dir, "staging"), Result: filepath.Join(dir, "result.json"),
		ProbationLog: filepath.Join(dir, "probation.json"), LastCheckin: filepath.Join(dir, "last-checkin"),
		PublicKey: &pub, Probation: probation, SelfTest: 5 * time.Second, Tick: 20 * time.Millisecond,
		MaxBackoff: 2 * time.Second, Notify: func(s string) { f.notices <- s },
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

// good is a run behaviour that checks in once and keeps running.
func (f *fake) good() string { return "trap '' HUP; touch " + f.cfg.LastCheckin + "; exec sleep 300" }

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

// stage puts a release into staging as the agent does and sends SIGUSR1; signer nil signs with the release key.
func (f *fake) stage(version string, bin []byte, signer *minisign.PrivateKey) {
	f.t.Helper()
	key := f.priv
	if signer != nil {
		key = *signer
	}
	dir := filepath.Join(f.cfg.Staging, version)
	_ = os.MkdirAll(dir, 0o700)
	f.writeExec(filepath.Join(dir, "paddockd"), bin)
	if err := os.WriteFile(filepath.Join(dir, "paddockd.minisig"), minisign.Sign(key, bin), 0o600); err != nil {
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
	f := newFake(t, 500*time.Millisecond)
	f.start()
	f.stage("1.1.0", script("1.1.0", 0, f.good()), nil)
	r := f.waitResult(10 * time.Second)
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
	f.stage("1.2.0", script("1.2.0", 0, f.good()), nil)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeUpdated || f.active() != "A" {
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
			f := newFake(t, time.Second)
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

func TestUpdateWithoutReleaseKeyIsRefused(t *testing.T) {
	f := newFake(t, time.Second)
	f.cfg.PublicKey = nil
	f.start()
	f.stage("1.1.0", script("1.1.0", 0, f.good()), nil)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeSignatureInvalid || f.active() != "A" {
		t.Fatalf("result %+v", r)
	}
}

func TestRollbackOnCrashLoop(t *testing.T) {
	f := newFake(t, time.Minute)
	f.start()
	f.stage("1.1.0", script("1.1.0", 0, "exit 1"), nil)
	r := f.waitResult(20 * time.Second)
	if r.Outcome != outcomeRolledBack || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
}

func TestRollbackOnProbationTimeout(t *testing.T) {
	f := newFake(t, time.Second)
	f.start()
	time.Sleep(200 * time.Millisecond) // the old agent checked in before the switch
	f.stage("1.1.0", script("1.1.0", 0, "trap '' HUP; exec sleep 300"), nil)
	r := f.waitResult(10 * time.Second)
	if r.Outcome != outcomeRolledBack || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
}

func TestResumeProbation(t *testing.T) {
	f := newFake(t, 500*time.Millisecond)
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
	f := newFake(t, time.Second)
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

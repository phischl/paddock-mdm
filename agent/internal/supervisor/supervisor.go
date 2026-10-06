// Package supervisor is paddock-supervisor (plan M2b decisions 15 and 16, design contract 1–5): it runs
// /opt/paddock/agent/current/paddockd as its child and restarts it with back-off, and it alone installs agent
// releases: signature check with the compiled-in release key, copy into the inactive A/B slot, self-test, one
// symlink flip, probation and automatic rollback. It is deliberately small, so it never needs an update itself.
package supervisor

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
)

// Outcomes written to update-result.json (shared contract with agent/internal/update).
const (
	outcomeUpdated          = "updated"
	outcomeSelfTestFailed   = "self_test_failed"
	outcomeRolledBack       = "rolled_back"
	outcomeSignatureInvalid = "signature_invalid"
	outcomeDowngradeRefused = "downgrade_refused"
)

// Config are the paths and timings of a supervisor.
type Config struct {
	Slots        string // directory with A, B and the symlink current
	Staging      string // staging directory with request.json and <version>/paddockd(.minisig)
	Result       string // update-result.json
	ProbationLog string // probation.json
	LastCheckin  string // touched by the agent after every check-in
	PublicKey    *minisign.PublicKey
	Probation    time.Duration
	SelfTest     time.Duration // self-test timeout
	Tick         time.Duration // watchdog and probation check interval
	MaxBackoff   time.Duration
	Notify       func(state string) // sd_notify
	Now          func() time.Time   // clock of the probation; nil is time.Now (tests inject one)
}

// probation is a switch under observation; it is persisted so that a restarted supervisor resumes it.
type probation struct {
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	FromSlot    string    `json:"from_slot"`
	ToSlot      string    `json:"to_slot"`
	SwitchedAt  time.Time `json:"switched_at"`
	deadline    time.Time
	exits       int
}

type selfTest struct {
	version, slot string
	err           error
}

// Supervisor runs the agent. All fields are owned by the goroutine that calls Run.
type Supervisor struct {
	cfg       Config
	child     *exec.Cmd
	exited    chan error
	started   time.Time
	backoff   time.Duration
	restart   <-chan time.Time
	probation *probation
	testing   bool
	tested    chan selfTest
}

// New creates a supervisor.
func New(cfg Config) *Supervisor {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Supervisor{cfg: cfg, exited: make(chan error, 1), tested: make(chan selfTest, 1), backoff: time.Second}
}

// Run supervises the agent until ctx ends; usr1 delivers update requests from the agent.
func (s *Supervisor) Run(ctx context.Context, usr1 <-chan os.Signal) {
	s.resumeProbation()
	s.start()
	s.cfg.Notify("READY=1")
	tick := time.NewTicker(s.cfg.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.stop()
			return
		case err := <-s.exited:
			s.onExit(err)
		case <-s.restart:
			s.restart = nil
			s.start()
		case <-usr1:
			s.onRequest(ctx)
		case r := <-s.tested:
			s.onSelfTest(r)
		case <-tick.C:
			// Petting the watchdog from this loop proves that the loop is responsive.
			s.cfg.Notify("WATCHDOG=1")
			s.checkProbation()
		}
	}
}

func (s *Supervisor) current() string { return filepath.Join(s.cfg.Slots, "current") }

func (s *Supervisor) start() {
	cmd := exec.Command(filepath.Join(s.current(), "paddockd"), "run") //nolint:gosec // fixed path below /opt/paddock
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	s.started = time.Now()
	if err := cmd.Start(); err != nil {
		slog.Error("starting the agent failed", "error", err)
		s.exited <- err
		return
	}
	s.child = cmd
	go func() { s.exited <- cmd.Wait() }()
}

// stop terminates the child (SIGTERM, SIGKILL after 10 s) and consumes its exit.
func (s *Supervisor) stop() {
	if s.child == nil {
		return
	}
	_ = s.child.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.exited:
	case <-time.After(10 * time.Second):
		_ = s.child.Process.Kill()
		<-s.exited
	}
	s.child = nil
}

func (s *Supervisor) onExit(err error) {
	s.child = nil
	slog.Warn("agent exited", "error", err)
	if s.probation != nil {
		if s.probation.exits++; s.probation.exits >= 3 {
			s.rollback("crash loop")
			return
		}
	}
	if time.Since(s.started) >= time.Minute {
		s.backoff = time.Second
	}
	slog.Info("restarting the agent", "in", s.backoff)
	s.restart = time.After(s.backoff)
	s.backoff = min(2*s.backoff, s.cfg.MaxBackoff)
}

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// onRequest verifies a staged release and starts its self-test in the inactive slot.
func (s *Supervisor) onRequest(ctx context.Context) {
	if s.testing || s.probation != nil {
		slog.Warn("update request ignored: an update is in progress")
		return
	}
	var req struct{ Version string }
	data, err := os.ReadFile(filepath.Join(s.cfg.Staging, "request.json"))
	if err == nil {
		err = json.Unmarshal(data, &req)
	}
	if err != nil || !versionPattern.MatchString(req.Version) {
		slog.Error("invalid update request", "error", err, "version", req.Version)
		s.cleanup("")
		return
	}
	dir := filepath.Join(s.cfg.Staging, req.Version)
	from := s.version(s.current())
	bin, err := os.ReadFile(filepath.Join(dir, "paddockd")) //nolint:gosec // version validated above
	if err != nil || !s.verify(bin, filepath.Join(dir, "paddockd.minisig"), req.Version) {
		slog.Error("release signature invalid or not for this version and architecture; update refused", "version", req.Version, "error", err)
		s.finish(req.Version, from, outcomeSignatureInvalid)
		return
	}
	// An active agent that cannot report its version has failed; any signed release may replace it.
	if versionPattern.MatchString(from) && compareVersions(req.Version, from) <= 0 {
		slog.Error("release is not newer than the active agent; downgrade refused", "version", req.Version, "active", from)
		s.finish(req.Version, from, outcomeDowngradeRefused)
		return
	}
	slot := s.inactiveSlot()
	if err := install(bin, filepath.Join(s.cfg.Slots, slot, "paddockd")); err != nil {
		slog.Error("installing the release into the inactive slot failed", "slot", slot, "error", err)
		s.finish(req.Version, from, outcomeSelfTestFailed)
		return
	}
	s.testing = true
	go func() {
		s.tested <- selfTest{version: req.Version, slot: slot, err: s.runSelfTest(ctx, slot, req.Version)}
	}()
}

// verify checks the signature of bin, which covers its trusted comment, and that the comment names version and this
// architecture (plan M4b.1 decision 11).
func (s *Supervisor) verify(bin []byte, sigPath, version string) bool {
	raw, err := os.ReadFile(sigPath) //nolint:gosec // path below the staging directory
	if err != nil || s.cfg.PublicKey == nil || !minisign.Verify(*s.cfg.PublicKey, bin, raw) {
		return false
	}
	var sig minisign.Signature
	if sig.UnmarshalText(raw) != nil {
		return false
	}
	v, arch, ok := releasesig.Parse(sig.TrustedComment)
	return ok && v == version && arch == runtime.GOARCH
}

// compareVersions orders two semantic versions by SemVer 2.0.0 precedence, build metadata ignored: -1, 0 or 1.
func compareVersions(a, b string) int {
	a, _, _ = strings.Cut(a, "+")
	b, _, _ = strings.Cut(b, "+")
	aCore, aPre, _ := strings.Cut(a, "-")
	bCore, bPre, _ := strings.Cut(b, "-")
	if c := compareIdentifiers(strings.Split(aCore, "."), strings.Split(bCore, ".")); c != 0 {
		return c
	}
	switch {
	case aPre == bPre:
		return 0
	case aPre == "": // a release ranks above its pre-releases
		return 1
	case bPre == "":
		return -1
	}
	return compareIdentifiers(strings.Split(aPre, "."), strings.Split(bPre, "."))
}

// compareIdentifiers compares dot-separated identifiers: numeric ones numerically and below alphanumeric ones, the
// others in ASCII order; with equal shared identifiers the longer list ranks higher.
func compareIdentifiers(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aErr := strconv.ParseUint(a[i], 10, 64)
		bn, bErr := strconv.ParseUint(b[i], 10, 64)
		switch {
		case aErr == nil && bErr == nil && an != bn:
			return cmp.Compare(an, bn)
		case aErr == nil && bErr != nil:
			return -1
		case aErr != nil && bErr == nil:
			return 1
		case aErr != nil && a[i] != b[i]:
			return strings.Compare(a[i], b[i])
		}
	}
	return cmp.Compare(len(a), len(b))
}

// runSelfTest runs `<slot>/paddockd self-test` and checks that the binary is the requested version.
func (s *Supervisor) runSelfTest(ctx context.Context, slot, version string) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.SelfTest)
	defer cancel()
	bin := filepath.Join(s.cfg.Slots, slot, "paddockd")
	out, err := exec.CommandContext(ctx, bin, "self-test").CombinedOutput() //nolint:gosec // our slot
	if err != nil {
		return fmt.Errorf("self-test: %w: %s", err, out)
	}
	if got := s.version(filepath.Join(s.cfg.Slots, slot)); got != version {
		return fmt.Errorf("the release reports version %q, not %q", got, version)
	}
	return nil
}

// onSelfTest switches to the tested slot or reports the failure.
func (s *Supervisor) onSelfTest(r selfTest) {
	s.testing = false
	from := s.version(s.current())
	if r.err != nil {
		slog.Error("release failed its self-test; not switching", "version", r.version, "error", r.err)
		s.finish(r.version, from, outcomeSelfTestFailed)
		return
	}
	p := &probation{Version: r.version, FromVersion: from, FromSlot: s.activeSlot(), ToSlot: r.slot, SwitchedAt: s.cfg.Now()}
	err := writeJSON(s.cfg.ProbationLog, p)
	if err == nil {
		err = flip(s.cfg.Slots, r.slot)
	}
	if err != nil {
		slog.Error("switching slots failed", "error", err)
		_ = os.Remove(s.cfg.ProbationLog)
		s.finish(r.version, from, outcomeSelfTestFailed)
		return
	}
	slog.Info("switched to the new agent version; probation started", "version", r.version, "slot", r.slot, "probation", s.cfg.Probation)
	p.deadline = p.SwitchedAt.Add(s.cfg.Probation)
	s.probation = p
	s.restartChild()
}

// checkProbation ends a probation at its deadline: healthy is a running child that checked in after the switch.
func (s *Supervisor) checkProbation() {
	p := s.probation
	if p == nil || s.cfg.Now().Before(p.deadline) {
		return
	}
	fi, err := os.Stat(s.cfg.LastCheckin)
	if s.child == nil || err != nil || !fi.ModTime().After(p.SwitchedAt) {
		s.rollback("not healthy at the end of the probation")
		return
	}
	slog.Info("probation passed", "version", p.Version)
	s.probation = nil
	_ = os.Remove(s.cfg.ProbationLog)
	s.finish(p.Version, p.FromVersion, outcomeUpdated)
}

// rollback flips back to the previous slot and restarts the old agent.
func (s *Supervisor) rollback(reason string) {
	p := s.probation
	s.probation = nil
	slog.Error("rolling back", "version", p.Version, "to_version", p.FromVersion, "reason", reason)
	if err := flip(s.cfg.Slots, p.FromSlot); err != nil {
		slog.Error("flipping back failed", "error", err)
	}
	_ = os.Remove(s.cfg.ProbationLog)
	s.restartChild()
	s.finish(p.Version, p.FromVersion, outcomeRolledBack)
}

func (s *Supervisor) restartChild() {
	s.stop()
	s.restart = nil
	s.backoff = time.Second
	s.start()
}

// finish cleans the staging directory, writes the update result and asks the agent to check in (SIGHUP).
func (s *Supervisor) finish(version, from, outcome string) {
	s.cleanup(version)
	res := map[string]any{"version": version, "from_version": from, "outcome": outcome, "at": time.Now().UTC()}
	if err := writeJSON(s.cfg.Result, res); err != nil {
		slog.Error("writing the update result failed", "error", err)
	}
	if s.child != nil {
		_ = s.child.Process.Signal(syscall.SIGHUP)
	}
}

func (s *Supervisor) cleanup(version string) {
	_ = os.Remove(filepath.Join(s.cfg.Staging, "request.json"))
	if version != "" {
		_ = os.RemoveAll(filepath.Join(s.cfg.Staging, version))
	}
}

// resumeProbation continues a probation that a restarted supervisor (or device) interrupted.
func (s *Supervisor) resumeProbation() {
	var p probation
	data, err := os.ReadFile(s.cfg.ProbationLog)
	if err != nil {
		return
	}
	if json.Unmarshal(data, &p) != nil || s.activeSlot() != p.ToSlot {
		_ = os.Remove(s.cfg.ProbationLog) // the flip never happened
		return
	}
	p.SwitchedAt = s.cfg.Now()
	p.deadline = p.SwitchedAt.Add(s.cfg.Probation)
	s.probation = &p
	slog.Info("resuming probation", "version", p.Version)
}

func (s *Supervisor) activeSlot() string {
	target, err := os.Readlink(s.current())
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func (s *Supervisor) inactiveSlot() string {
	if s.activeSlot() == "A" {
		return "B"
	}
	return "A"
}

// version runs `<dir>/paddockd version`.
func (s *Supervisor) version(dir string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(dir, "paddockd"), "version").Output() //nolint:gosec // our slot
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// flip points current at slot with one atomic rename of a new symlink.
func flip(slots, slot string) error {
	tmp := filepath.Join(slots, ".current.tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(slot, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(slots, "current")); err != nil {
		return err
	}
	return syncDir(slots)
}

// install copies bin to path atomically (0755).
func install(bin []byte, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // slot directories are 0755
		return err
	}
	tmp := path + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //nolint:gosec // executable
	if err != nil {
		return err
	}
	_, err = f.Write(bin)
	err = errors.Join(err, f.Sync(), f.Close())
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // our own directories
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

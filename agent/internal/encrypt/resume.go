package encrypt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// ResumeUnit is the transient unit the agent runs `paddockd encrypt-resume` in (plan M8e decision 21).
const ResumeUnit = "paddock-encrypt-resume.service"

// Timing of the background phase (plan M8e decision 21).
const (
	// BatteryPoll is how often the helper looks for mains power while it waits on battery.
	BatteryPoll = 30 * time.Second
	// PowerPoll is how often the helper looks for a lost mains supply while cryptsetup runs.
	PowerPoll = 10 * time.Second
	// ProgressInterval is how often at most progress.json is written while cryptsetup runs.
	ProgressInterval = 5 * time.Second
)

// Exit codes of `paddockd encrypt-resume` (plan M8e decision 21).
const (
	ResumeCompleted  = 0
	ResumeFailed     = 1
	ResumeTerminated = 143
)

// Process is a running cryptsetup reencrypt: the lines it prints (closed once it closed its output), a signal to it,
// and its end.
type Process interface {
	Lines() <-chan string
	Signal(sig os.Signal) error
	// Wait returns the exit code (-1 when a signal ended it) and the first line of its stderr that is no progress line.
	Wait() (exit int, stderr string, err error)
}

// Resumer is `paddockd encrypt-resume`, the background phase (plan M8e decision 21): it resumes the online
// reencryption the init step started, pauses on battery and resumes on mains power, and leaves progress.json while
// it runs and result.json when the reencryption ended. ctx ending is SIGTERM from systemd (shutdown, or the agent's
// stop before a revocation hand-over): it is forwarded to cryptsetup, which stops at a safe point, and no result is
// written.
type Resumer struct {
	Sys    System
	Layout paths.Layout
	// Partition is the conversion's partition the agent passes (--partition); "" takes it from plan.json, which must
	// then name it. With both, they must agree.
	Partition string
	// Start runs a tool and streams its output; the process is not tied to ctx, the Resumer signals it itself.
	Start func(name string, args ...string) (Process, error)
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	// PowerPoll overrides PowerPoll (tests).
	PowerPoll time.Duration

	// dataBytes is the plan's data_bytes (0 without plan.json: the progress lines tell).
	dataBytes int64
	last      Progress
	written   time.Time
	running   time.Duration
}

// how a cryptsetup run ended.
type stop int

const (
	exited stop = iota
	onBattery
	terminated
)

// Run runs the background phase and returns the helper's exit code.
func (r *Resumer) Run(ctx context.Context) int {
	partition := r.Partition
	plan, err := ReadPlan(r.Layout)
	switch {
	case err != nil && partition == "":
		return r.fail(ctx, "resume_plan:"+firstLine(err.Error()))
	case plan != nil && partition == "":
		partition = plan.Partition
	case plan != nil && plan.Partition != partition:
		return r.fail(ctx, "resume_plan_mismatch")
	case partition == "":
		return r.fail(ctx, "resume_plan:plan.json is missing")
	}
	if plan != nil {
		r.dataBytes, r.last.DataBytes = plan.DataBytes, plan.DataBytes
	}
	if isLUKS, ok := IsLUKS(ctx, r.Sys, r.Layout, Disk{Partition: partition}); !isLUKS || !ok {
		return r.fail(ctx, "resume_not_luks")
	}
	md, err := luks.Dump(ctx, LUKSTools(r.Sys), partition)
	if err != nil {
		return r.fail(ctx, "resume_dump:"+firstLine(err.Error()))
	}
	if !md.Reencrypting() {
		slog.InfoContext(ctx, "the reencryption is complete already")
		return r.completed()
	}
	for {
		if ctx.Err() != nil {
			return ResumeTerminated
		}
		if OnBattery(r.Layout) {
			r.pause(PausedOnBattery)
			if err := r.Sleep(ctx, BatteryPoll); err != nil {
				return ResumeTerminated
			}
			continue
		}
		exit, stderr, how, err := r.reencrypt(ctx, partition)
		switch {
		case how == terminated:
			slog.InfoContext(ctx, "reencryption stopped by SIGTERM; it resumes at the next start")
			return ResumeTerminated
		case how == onBattery:
			// cryptsetup may have finished just as mains power went.
			if md, err := luks.Dump(ctx, LUKSTools(r.Sys), partition); err == nil && !md.Reencrypting() {
				return r.completed()
			}
			slog.InfoContext(ctx, "mains power lost; the reencryption waits for it")
			r.pause(PausedOnBattery)
			continue
		case err != nil:
			return r.fail(ctx, "resume_start:"+firstLine(err.Error()))
		case exit != 0:
			reason := fmt.Sprintf("resume_exit_%d", exit)
			if stderr != "" {
				reason += ":" + stderr
			}
			return r.fail(ctx, reason)
		}
		md, err := luks.Dump(ctx, LUKSTools(r.Sys), partition)
		if err != nil {
			return r.fail(ctx, "resume_dump:"+firstLine(err.Error()))
		}
		if md.Reencrypting() {
			return r.fail(ctx, "resume_exit_0:reencrypt keyslot left")
		}
		return r.completed()
	}
}

// reencrypt runs cryptsetup reencrypt --resume-only once. It stops it with SIGTERM when ctx ends or the mains supply
// is lost (safe at any time, cryptsetup(8)) and waits for it.
func (r *Resumer) reencrypt(ctx context.Context, partition string) (exit int, stderr string, how stop, err error) {
	started := r.Now()
	proc, err := r.Start("cryptsetup", "reencrypt", "--resume-only", "--batch-mode", "--key-file", r.Layout.InstallPassphrase(),
		"--progress-json", "--progress-frequency", "5", partition)
	if err != nil {
		return 0, "", exited, err
	}
	defer func() { r.running += r.Now().Sub(started) }()
	r.last.PausedReason = ""
	r.written = time.Time{}
	poll := r.PowerPoll
	if poll <= 0 {
		poll = PowerPoll
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	lines, done := proc.Lines(), ctx.Done()
	how = exited
	signal := func(why stop) {
		how, done = why, nil
		if err := proc.Signal(syscall.SIGTERM); err != nil {
			slog.WarnContext(ctx, "stopping cryptsetup failed", "error", err)
		}
	}
	for lines != nil {
		select {
		case line, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			if p, ok := ParseProgress(line); ok {
				r.progress(p)
			}
		case <-done:
			signal(terminated)
		case <-tick.C:
			if how == exited && OnBattery(r.Layout) {
				signal(onBattery)
			}
		}
	}
	exit, stderr, err = proc.Wait()
	return exit, stderr, how, err
}

// progress records a progress line, written at most every ProgressInterval.
func (r *Resumer) progress(p Progress) {
	now := r.Now()
	r.last.DoneBytes, r.last.SpeedBPS, r.last.ETASeconds, r.last.PausedReason = p.DoneBytes, p.SpeedBPS, p.ETASeconds, ""
	if p.DataBytes > 0 {
		r.last.DataBytes = p.DataBytes
	}
	if !r.written.IsZero() && now.Sub(r.written) < ProgressInterval {
		return
	}
	r.written = now
	r.write()
}

// pause records why the reencryption waits.
func (r *Resumer) pause(reason string) {
	r.last.PausedReason, r.last.SpeedBPS, r.last.ETASeconds = reason, 0, 0
	r.write()
}

func (r *Resumer) write() {
	r.last.UpdatedAt = r.Now().UTC()
	if err := writeProgress(r.Layout, r.last); err != nil {
		slog.Error("writing the reencryption progress failed", "error", err)
	}
}

func (r *Resumer) completed() int {
	data := r.dataBytes
	if data == 0 {
		data = r.last.DataBytes
	}
	res := Result{Outcome: OutcomeCompleted, DataBytes: data, DurationS: int64(r.running / time.Second),
		FinishedAt: r.Now().UTC()}
	if err := writeResult(r.Layout, res); err != nil {
		slog.Error("writing the reencryption result failed", "error", err)
		return ResumeFailed
	}
	slog.Info("reencryption completed", "duration_s", res.DurationS)
	return ResumeCompleted
}

// fail writes the failed result; a failure caused by SIGTERM is no result.
func (r *Resumer) fail(ctx context.Context, reason string) int {
	if ctx.Err() != nil {
		return ResumeTerminated
	}
	reason = cut(reason)
	slog.ErrorContext(ctx, "reencryption failed", "reason", reason)
	if err := writeResult(r.Layout, Result{Outcome: OutcomeFailed, Reason: reason, DataBytes: r.last.DataBytes,
		DurationS: int64(r.running / time.Second), FinishedAt: r.Now().UTC()}); err != nil {
		slog.ErrorContext(ctx, "writing the reencryption result failed", "error", err)
	}
	return ResumeFailed
}

// OnBattery reports whether the device runs on battery: a battery that is not a peripheral's (scope Device) and no
// mains supply online — the init step's rule (plan M8e decision 16).
func OnBattery(l paths.Layout) bool {
	supplies, _ := filepath.Glob(l.Join("/sys/class/power_supply/*"))
	battery, mains := false, false
	for _, dir := range supplies {
		read := func(name string) string {
			b, _ := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // sysfs below the layout
			return strings.TrimSpace(string(b))
		}
		switch read("type") {
		case "Battery":
			battery = battery || read("scope") != "Device"
		case "Mains":
			mains = mains || read("online") == "1"
		}
	}
	return battery && !mains
}

// StartProcess runs cryptsetup with its output streamed: progress lines of stdout and stderr go to Lines, other
// stderr lines are kept for the failure reason. Like OS it takes the tool from PATH and keeps it off the
// supervisor's notification socket.
func StartProcess(name string, args ...string) (Process, error) {
	if name != "cryptsetup" {
		return nil, errors.New("encrypt: not a reencryption tool: " + name)
	}
	cmd := exec.Command(name, args...) //nolint:gosec // a fixed tool; the Resumer stops it with SIGTERM, not ctx
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(e string) bool {
		return strings.HasPrefix(e, "NOTIFY_SOCKET=") || strings.HasPrefix(e, "LC_ALL=")
	}), "LC_ALL=C")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &osProcess{cmd: cmd, lines: make(chan string, 16)}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.scan(stdout, false)
	}()
	go func() {
		defer wg.Done()
		p.scan(stderr, true)
	}()
	go func() {
		wg.Wait()
		close(p.lines)
	}()
	return p, nil
}

type osProcess struct {
	cmd   *exec.Cmd
	lines chan string
	mu    sync.Mutex
	first string
}

func (p *osProcess) scan(r io.Reader, stderr bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if _, ok := ParseProgress(line); ok || !stderr {
			p.lines <- line
			continue
		}
		p.mu.Lock()
		if p.first == "" && strings.TrimSpace(line) != "" {
			p.first = cut(strings.TrimSpace(line))
		}
		p.mu.Unlock()
	}
}

func (p *osProcess) Lines() <-chan string { return p.lines }

func (p *osProcess) Signal(sig os.Signal) error { return p.cmd.Process.Signal(sig) }

func (p *osProcess) Wait() (int, string, error) {
	err := p.cmd.Wait()
	p.mu.Lock()
	first := p.first
	p.mu.Unlock()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), first, nil
	}
	if err != nil {
		return -1, first, err
	}
	return 0, first, nil
}

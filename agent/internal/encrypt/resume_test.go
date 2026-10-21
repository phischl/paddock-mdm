package encrypt_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
)

// progressLine is a line of cryptsetup reencrypt --progress-json as recorded on a device.
const progressLine = `{"device":"/dev/sda3","device_bytes":"8192","device_size":"44040192","speed":"126877696","eta_ms":"2520012","time_ms":"12"}`

// TestParseProgress: the recorded --progress-json line maps to the progress of plan M8e §6.3; other lines do not.
func TestParseProgress(t *testing.T) {
	p, ok := encrypt.ParseProgress(progressLine)
	if !ok || p.DoneBytes != 8192 || p.DataBytes != 44040192 || p.SpeedBPS != 126877696 || p.ETASeconds != 2520 {
		t.Fatalf("parsed %+v %v", p, ok)
	}
	if p, ok := encrypt.ParseProgress(`{"device_bytes":1024,"device_size":2048,"speed":0,"eta_ms":999}`); !ok || p.DoneBytes != 1024 ||
		p.DataBytes != 2048 || p.ETASeconds != 0 {
		t.Fatalf("numbers: %+v %v", p, ok)
	}
	for _, line := range []string{"", "Finished, time 00m01s", `{"device_bytes":"x","device_size":"1"}`, `{"speed":"1"}`,
		`{"device_bytes":"-1","device_size":"1"}`, "{"} {
		if _, ok := encrypt.ParseProgress(line); ok {
			t.Errorf("%q parsed", line)
		}
	}
}

// step is what a fake cryptsetup does next: print a line, move the clock, change the power supply, or run a check once
// every line before it has been read.
type step struct {
	line    string
	advance time.Duration
	battery *bool
	check   func()
}

// fakeProc is a cryptsetup reencrypt that runs its steps, then exits with exit — or, with untilSignal, waits for a
// signal first.
type fakeProc struct {
	lines       chan string
	signals     chan os.Signal
	exit        int
	stderr      string
	untilSignal bool
	mu          sync.Mutex
	got         []os.Signal
	done        chan struct{}
}

func (p *fakeProc) Lines() <-chan string { return p.lines }

func (p *fakeProc) Signal(sig os.Signal) error {
	p.mu.Lock()
	p.got = append(p.got, sig)
	p.mu.Unlock()
	select {
	case p.signals <- sig:
	default:
	}
	return nil
}

func (p *fakeProc) Wait() (int, string, error) {
	<-p.done
	return p.exit, p.stderr, nil
}

func (p *fakeProc) signaled() []os.Signal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.got)
}

// resumeFixture runs the helper on a converted device with a fake cryptsetup and a fake sysfs.
type resumeFixture struct {
	*fixture
	mu     sync.Mutex
	clock  time.Time
	procs  []*fakeProc
	runs   [][]step
	starts []string
	sleeps []time.Duration
	// onSleep runs at every wait for mains power.
	onSleep func()
}

func newResumeFixture(t *testing.T) *resumeFixture {
	t.Helper()
	f := &resumeFixture{fixture: convertedFixture(t), clock: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	f.dev.Write("/sys/class/power_supply/BAT0/type", "Battery\n")
	f.dev.Write("/sys/class/power_supply/AC/type", "Mains\n")
	f.setMains(true)
	return f
}

func (f *resumeFixture) setMains(on bool) {
	v := "0\n"
	if on {
		v = "1\n"
	}
	f.dev.Write("/sys/class/power_supply/AC/online", v)
}

func (f *resumeFixture) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clock
}

// run adds a cryptsetup run with its steps, its exit code and whether it waits for a signal.
func (f *resumeFixture) run(exit int, untilSignal bool, steps ...step) *fakeProc {
	p := &fakeProc{lines: make(chan string), signals: make(chan os.Signal, 1), exit: exit, untilSignal: untilSignal,
		done: make(chan struct{})}
	f.procs = append(f.procs, p)
	f.runs = append(f.runs, steps)
	return p
}

func (f *resumeFixture) resumer() *encrypt.Resumer {
	return &encrypt.Resumer{Sys: f.dev, Layout: f.dev.layout, Now: f.now, PowerPoll: time.Millisecond,
		Sleep: func(ctx context.Context, d time.Duration) error {
			f.mu.Lock()
			f.sleeps = append(f.sleeps, d)
			f.clock = f.clock.Add(d)
			hook := f.onSleep
			f.mu.Unlock()
			if hook != nil {
				hook()
			}
			return ctx.Err()
		},
		Start: func(name string, args ...string) (encrypt.Process, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.starts = append(f.starts, strings.Join(append([]string{name}, args...), " "))
			n := len(f.starts) - 1
			if n >= len(f.procs) {
				return nil, errors.New("no more runs")
			}
			p, steps := f.procs[n], f.runs[n]
			go func() {
				defer close(p.done)
				for _, s := range steps {
					f.mu.Lock()
					f.clock = f.clock.Add(s.advance)
					f.mu.Unlock()
					if s.battery != nil {
						f.setMains(!*s.battery)
					}
					if s.check != nil {
						p.lines <- "barrier"
						s.check()
					}
					if s.line != "" {
						p.lines <- s.line
					}
				}
				if p.untilSignal {
					<-p.signals
				}
				close(p.lines)
			}()
			return p, nil
		}}
}

func (f *resumeFixture) progress() encrypt.Progress {
	f.t.Helper()
	p, err := encrypt.ReadProgress(f.dev.layout)
	if err != nil || p == nil {
		f.t.Fatalf("progress %v %v", p, err)
	}
	return *p
}

func (f *resumeFixture) result() *encrypt.Result {
	f.t.Helper()
	r, err := encrypt.ReadResult(f.dev.layout)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func progressJSON(done, eta int64) string {
	b, _ := json.Marshal(map[string]string{"device_bytes": itoa(done), "device_size": "44040192", "speed": "1000",
		"eta_ms": itoa(eta * 1000)})
	return string(b)
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestResumeCompletes: plan M8e decision 21 — the helper runs cryptsetup reencrypt --resume-only with the conversion
// key, writes progress.json at most every 5 s, and on exit 0 without a reencrypt keyslot writes the completed result
// with the summed running time.
func TestResumeCompletes(t *testing.T) {
	f := newResumeFixture(t)
	f.run(0, false,
		step{line: progressLine},
		step{line: progressJSON(16384, 100), advance: time.Second},
		step{check: func() {
			if p := f.progress(); p.DoneBytes != 8192 || p.DataBytes != 44040192 || p.SpeedBPS != 126877696 || p.ETASeconds != 2520 ||
				p.PausedReason != "" {
				t.Errorf("first progress %+v", p)
			}
		}},
		step{line: progressJSON(40000000, 10), advance: 5 * time.Second},
		step{check: func() {
			if p := f.progress(); p.DoneBytes != 40000000 || p.ETASeconds != 10 {
				t.Errorf("progress after 6 s %+v", p)
			}
			f.dev.set(func(d *device) { d.slots = []string{"password"} })
		}},
		step{advance: 4 * time.Second})
	if got := f.resumer().Run(context.Background()); got != encrypt.ResumeCompleted {
		t.Fatalf("exit %d", got)
	}
	want := "cryptsetup reencrypt --resume-only --batch-mode --key-file " + f.dev.Path("/var/lib/paddock/install-passphrase") +
		" --progress-json --progress-frequency 5 /dev/disk/by-partuuid/8c2f8d4e-5b7a-4f1c-9e0d-2a6b3c4d5e6f"
	if !slices.Equal(f.starts, []string{want}) {
		t.Fatalf("starts %v", f.starts)
	}
	r := f.result()
	if r == nil || r.Outcome != encrypt.OutcomeCompleted || r.DataBytes != f.conversion().DataBytes || r.DurationS != 10 ||
		!r.FinishedAt.Equal(f.now()) {
		t.Fatalf("result %+v", r)
	}
}

// TestResumeOnBattery: on battery the helper waits for mains power (polling every 30 s) with paused_reason on_battery
// and starts cryptsetup only then; a mains supply lost while it runs stops cryptsetup with SIGTERM, pauses, and
// cryptsetup runs again when mains returns. A peripheral's battery does not count.
func TestResumeOnBattery(t *testing.T) {
	f := newResumeFixture(t)
	f.setMains(false)
	waits := 0
	f.onSleep = func() {
		if p := f.progress(); p.PausedReason != encrypt.PausedOnBattery {
			t.Errorf("waiting: %+v", p)
		}
		if waits++; waits == 2 || waits == 3 {
			f.setMains(true)
		}
	}
	on := true
	first := f.run(1, true, step{line: progressLine}, step{battery: &on})
	f.run(0, false, step{line: progressJSON(44040192, 0), check: func() {
		f.dev.set(func(d *device) { d.slots = []string{"password"} })
	}})
	if got := f.resumer().Run(context.Background()); got != encrypt.ResumeCompleted {
		t.Fatalf("exit %d, result %+v", got, f.result())
	}
	if len(f.starts) != 2 || !slices.Equal(first.signaled(), []os.Signal{syscall.SIGTERM}) || waits != 3 ||
		!slices.Equal(f.sleeps, []time.Duration{encrypt.BatteryPoll, encrypt.BatteryPoll, encrypt.BatteryPoll}) {
		t.Fatalf("starts %v, signals %v, waits %d, sleeps %v", f.starts, first.signaled(), waits, f.sleeps)
	}
	// The waits on battery are no running time (duration_s sums the cryptsetup runs of this helper run).
	if r := f.result(); r == nil || r.Outcome != encrypt.OutcomeCompleted || r.DurationS != 0 {
		t.Fatalf("result %+v", r)
	}

	if encrypt.OnBattery(f.dev.layout) {
		t.Fatal("on battery with mains online")
	}
	f.setMains(false)
	if !encrypt.OnBattery(f.dev.layout) {
		t.Fatal("not on battery without mains")
	}
	f.dev.Write("/sys/class/power_supply/BAT0/scope", "Device\n")
	if encrypt.OnBattery(f.dev.layout) {
		t.Fatal("a peripheral's battery counts")
	}
}

// TestResumeSIGTERM: SIGTERM from systemd (ctx) is forwarded to cryptsetup; the helper writes no result and exits 143.
// While it waits on battery it exits as well.
func TestResumeSIGTERM(t *testing.T) {
	f := newResumeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	p := f.run(1, true, step{line: progressLine}, step{check: cancel})
	if got := f.resumer().Run(ctx); got != encrypt.ResumeTerminated {
		t.Fatalf("exit %d", got)
	}
	if !slices.Equal(p.signaled(), []os.Signal{syscall.SIGTERM}) || f.result() != nil {
		t.Fatalf("signals %v, result %+v", p.signaled(), f.result())
	}

	f = newResumeFixture(t)
	f.setMains(false)
	ctx, cancel = context.WithCancel(context.Background())
	f.onSleep = cancel
	if got := f.resumer().Run(ctx); got != encrypt.ResumeTerminated || len(f.starts) != 0 || f.result() != nil {
		t.Fatalf("on battery: exit %d, starts %v", got, f.starts)
	}
}

// TestResumeResults: a non-zero exit of cryptsetup that the helper did not cause is a failed result with the exit
// code and the first stderr line; exit 0 with the reencrypt keyslot left is failed too; a reencryption that is
// complete already is completed at once; a partition that is not LUKS fails without running cryptsetup.
func TestResumeResults(t *testing.T) {
	f := newResumeFixture(t)
	p := f.run(5, false, step{line: progressLine})
	p.stderr = "Device /dev/sda3 is in use."
	if got := f.resumer().Run(context.Background()); got != encrypt.ResumeFailed {
		t.Fatalf("exit %d", got)
	}
	if r := f.result(); r == nil || r.Outcome != encrypt.OutcomeFailed || r.Reason != "resume_exit_5:Device /dev/sda3 is in use." {
		t.Fatalf("result %+v", r)
	}

	f = newResumeFixture(t)
	f.run(0, false)
	if got := f.resumer().Run(context.Background()); got != encrypt.ResumeFailed || f.result().Reason != "resume_exit_0:reencrypt keyslot left" {
		t.Fatalf("exit %d, result %+v", got, f.result())
	}

	f = newResumeFixture(t)
	f.dev.set(func(d *device) { d.slots = []string{"password", "tpm2+pin"} })
	if got := f.resumer().Run(context.Background()); got != encrypt.ResumeCompleted || len(f.starts) != 0 ||
		f.result().Outcome != encrypt.OutcomeCompleted {
		t.Fatalf("complete already: exit %d, starts %v", got, f.starts)
	}

	f = newResumeFixture(t)
	f.dev.set(func(d *device) { d.luks = false })
	if got := f.resumer().Run(context.Background()); got != encrypt.ResumeFailed || len(f.starts) != 0 ||
		f.result().Reason != "resume_not_luks" {
		t.Fatalf("not LUKS: exit %d, starts %v, result %+v", got, f.starts, f.result())
	}
}

// TestResumeDoneAsMainsLost: Review 1, M1 — cryptsetup finishing just as mains power goes completes the
// reencryption instead of waiting on battery for work that is done.
func TestResumeDoneAsMainsLost(t *testing.T) {
	f := newResumeFixture(t)
	f.onSleep = func() { f.setMains(true) } // ends the wait without the fix: the next start finds no run
	on := true
	f.run(0, true, step{line: progressLine}, step{check: func() {
		f.dev.set(func(d *device) { d.slots = []string{"password"} })
	}}, step{battery: &on})
	if got := f.resumer().Run(context.Background()); got != encrypt.ResumeCompleted || len(f.sleeps) != 0 || len(f.starts) != 1 {
		t.Fatalf("exit %d, sleeps %v, starts %v", got, f.sleeps, f.starts)
	}
	if r := f.result(); r == nil || r.Outcome != encrypt.OutcomeCompleted {
		t.Fatalf("result %+v", r)
	}
}

// TestResumePartitionArgument: amendment 2026-10-21, item 7 — the agent passes the partition, so the helper resumes
// without plan.json; a partition that disagrees with plan.json fails.
func TestResumePartitionArgument(t *testing.T) {
	f := newResumeFixture(t)
	_ = os.Remove(f.dev.Path("/var/lib/paddock/encrypt/plan.json"))
	f.run(0, false, step{line: progressLine, check: func() {
		f.dev.set(func(d *device) { d.slots = []string{"password", "tpm2"} })
	}})
	r := f.resumer()
	r.Partition = partition
	if got := r.Run(context.Background()); got != encrypt.ResumeCompleted || f.result().DataBytes != 44040192 {
		t.Fatalf("without plan.json: exit %d, result %+v", got, f.result())
	}

	f = newResumeFixture(t)
	r = f.resumer()
	r.Partition = "/dev/disk/by-partuuid/00000000-0000-4000-8000-000000000000"
	if got := r.Run(context.Background()); got != encrypt.ResumeFailed || f.result().Reason != "resume_plan_mismatch" || len(f.starts) != 0 {
		t.Fatalf("mismatch: exit %d, result %+v", got, f.result())
	}

	f = newResumeFixture(t)
	_ = os.Remove(f.dev.Path("/var/lib/paddock/encrypt/plan.json"))
	if got := f.resumer().Run(context.Background()); got != encrypt.ResumeFailed || !strings.HasPrefix(f.result().Reason, "resume_plan") {
		t.Fatalf("neither: exit %d, result %+v", got, f.result())
	}
}

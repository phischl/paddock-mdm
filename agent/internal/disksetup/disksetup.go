// Package disksetup is `paddockd disk-setup` (plan M4b decisions 5 and 6): at the first boot of a device installed
// with the Paddock autoinstall it asks on the console for the boot PIN, twice, and enrolls TPM2+PIN for the root
// volume, unlocking with the temporary install passphrase. Skipping is possible (fail safe: the device boots and is
// reported non-compliant); the PIN never leaves the device and is never logged.
package disksetup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"unicode/utf8"

	"github.com/phischl/paddock-mdm/agent/internal/luks"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// Bounds of the boot PIN length (the organization setting boot_pin_min_length).
const (
	MinPINLength     = 6
	MaxPINLength     = 32
	DefaultPINLength = 8
)

// MaxEnrollFailures is how often enrolling may fail before the device boots without a PIN; it asks again at the
// next boot.
const MaxEnrollFailures = 3

// Options are the dependencies of one disk setup.
type Options struct {
	Layout paths.Layout
	Tools  luks.Tools
	In     io.Reader // the console
	Out    io.Writer
	// Echo turns the console's echo on or off; nil when the input is no terminal (tests).
	Echo func(on bool) error
	// TPM2Present reports whether the device has a TPM 2.0; nil uses luks.TPM2Present below Layout.Root.
	TPM2Present func() bool
}

// Run runs the disk setup if it is pending. It removes the pending marker when the PIN is enrolled, when the user
// skips, and when the device cannot use TPM2+PIN; a failed enrollment keeps it, so the next boot asks again. Run
// returns an error only if the console cannot be used; the boot continues in every case.
func Run(ctx context.Context, o Options) error {
	if _, err := os.Stat(o.Layout.DiskSetupPending()); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if o.TPM2Present == nil {
		o.TPM2Present = func() bool { return luks.TPM2Present(o.Layout.Root) }
	}
	d := &dialogue{o: o, in: bufio.NewReader(o.In)}
	if !o.TPM2Present() {
		d.say("Paddock disk encryption setup\n\nThis device has no TPM 2.0, so its disk cannot be unlocked with a boot PIN. The device\n" +
			"starts with the disk passphrase as before and is reported to IT.\n\n")
		slog.WarnContext(ctx, "disk setup skipped: no TPM 2.0")
		return done(o.Layout)
	}
	vol, err := luks.Root(ctx, o.Tools)
	if err != nil {
		slog.ErrorContext(ctx, "disk setup skipped: no LUKS root volume", "error", err)
		return done(o.Layout)
	}
	if _, err := os.Stat(o.Layout.InstallPassphrase()); err != nil {
		slog.ErrorContext(ctx, "disk setup skipped: the install passphrase is missing", "error", err)
		return done(o.Layout)
	}
	minLength := minPINLength(o.Layout)
	d.say(fmt.Sprintf(intro, minLength))
	for failures := 0; failures < MaxEnrollFailures; {
		pin, err := d.choosePIN(minLength)
		if err != nil {
			return err
		}
		if pin == nil {
			d.say(skipped)
			slog.WarnContext(ctx, "boot PIN skipped; the disk keeps its install passphrase")
			return done(o.Layout)
		}
		d.say("\nSetting the boot PIN. This takes a few seconds ...\n")
		err = luks.EnrollTPM2PIN(ctx, o.Tools, vol.Device, o.Layout.InstallPassphrase(), pin)
		clear(pin)
		if err == nil {
			d.say("The boot PIN is set. From the next start on, the device asks for it before anything else.\n\n")
			slog.InfoContext(ctx, "boot PIN enrolled (TPM2+PIN, PCR 7)", "device", vol.Device)
			return done(o.Layout)
		}
		failures++
		slog.ErrorContext(ctx, "enrolling the boot PIN failed", "device", vol.Device, "error", err)
		d.say("Setting the boot PIN failed. Please try again.\n\n")
	}
	d.say("The boot PIN could not be set. The device starts without it for now and asks again at the next start.\n\n")
	return nil
}

const intro = `Paddock disk encryption setup

The disk of this device is encrypted. Choose a boot PIN: you will type it
every time the device starts, before anything else. It needs at least %d
characters.

Keep the PIN to yourself and do not forget it. IT cannot recover a forgotten
PIN; without it, the disk can only be unlocked with the recovery key that IT
keeps for this device.

To skip for now, press Enter twice without typing a PIN. The device then starts
as usual but is reported to IT as not compliant.

`

const skipped = `
No boot PIN was set. The device starts as usual and is reported to IT as not
compliant; the disk keeps asking for its passphrase.

`

type dialogue struct {
	o  Options
	in *bufio.Reader
}

func (d *dialogue) say(s string) { _, _ = io.WriteString(d.o.Out, s) }

// choosePIN asks until the user enters the same PIN of at least minLength characters twice, or nothing twice
// (skip: nil, nil).
func (d *dialogue) choosePIN(minLength int) ([]byte, error) {
	for {
		first, err := d.read("Boot PIN: ")
		if err != nil {
			return nil, err
		}
		second, err := d.read("Repeat the boot PIN: ")
		if err != nil {
			clear(first)
			return nil, err
		}
		same := bytes.Equal(first, second)
		clear(second)
		switch {
		case same && len(first) == 0:
			return nil, nil
		case !same:
			d.say("The two entries differ. Please try again.\n\n")
		case utf8.RuneCount(first) < minLength:
			d.say(fmt.Sprintf("The PIN needs at least %d characters. Please try again.\n\n", minLength))
		default:
			return first, nil
		}
		clear(first)
	}
}

// read prompts and reads one line without echo.
func (d *dialogue) read(prompt string) ([]byte, error) {
	d.say(prompt)
	if d.o.Echo != nil {
		if err := d.o.Echo(false); err != nil {
			return nil, fmt.Errorf("disksetup: turn off the echo: %w", err)
		}
		defer func() { _ = d.o.Echo(true) }()
	}
	line, err := d.in.ReadBytes('\n')
	d.say("\n")
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
		clear(line)
		return nil, fmt.Errorf("disksetup: read from the console: %w", err)
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

// minPINLength reads boot_pin_min_length from disk-setup.json; a missing or invalid file gives the default.
func minPINLength(l paths.Layout) int {
	var s struct {
		BootPINMinLength int `json:"boot_pin_min_length"`
	}
	data, err := os.ReadFile(l.DiskSetupConfig())
	if err != nil || json.Unmarshal(data, &s) != nil || s.BootPINMinLength < MinPINLength || s.BootPINMinLength > MaxPINLength {
		return DefaultPINLength
	}
	return s.BootPINMinLength
}

// done removes the pending marker.
func done(l paths.Layout) error {
	if err := os.Remove(l.DiskSetupPending()); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Error("removing the disk setup marker failed", "error", err)
	}
	return nil
}

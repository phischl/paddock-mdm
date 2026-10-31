package encrypt

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// TestCPIONewcLayout: the override segment's archive byte for byte (newc, PDK-482): the 110-byte header of thirteen
// 8-digit hex fields, the name with its NUL padded to 4, the data padded to 4, and the trailer entry.
func TestCPIONewcLayout(t *testing.T) {
	got := cpioNewc([]cpioFile{{Name: "a/b", Mode: 0o600, Ino: 7, Mtime: 0x5f, Data: []byte("hello")}})
	want := "070701" + "00000007" + "00008180" + "00000000" + "00000000" + "00000001" + "0000005F" + "00000005" +
		"00000000" + "00000000" + "00000000" + "00000000" + "00000004" + "00000000" +
		"a/b\x00" + "\x00\x00" + // 110 + 4 = 114, padded to 116
		"hello" + "\x00\x00\x00" + // 116 + 5 = 121, padded to 124
		"070701" + "00000000" + "00000000" + "00000000" + "00000000" + "00000001" + "00000000" + "00000000" +
		"00000000" + "00000000" + "00000000" + "00000000" + "0000000B" + "00000000" +
		"TRAILER!!!\x00" + "\x00\x00\x00" // 124 + 110 + 11 = 245, padded to 248
	if string(got) != want {
		t.Fatalf("archive\n got %q\nwant %q", got, want)
	}
	// Name and data that end on a multiple of 4 get no padding.
	got = cpioNewc([]cpioFile{{Name: "x", Mode: 0o644, Data: []byte("abcd")}})
	if len(got) != 110+2+4+110+11+3 || string(got[110:116]) != "x\x00abcd" || string(got[116:122]) != "070701" {
		t.Fatalf("aligned archive %q", got)
	}
}

// TestSegmentAt: the segment starts at an offset aligned to 4 behind the initrd (the kernel reads a cpio header only
// there and skips the zeros before it).
func TestSegmentAt(t *testing.T) {
	for size, pad := range map[int64]int{1000: 0, 1001: 3, 1002: 2, 1003: 1} {
		seg := segmentAt(size)
		if len(seg) != pad+len(neutralizeSegment) || !bytes.Equal(seg[pad:], neutralizeSegment) ||
			!bytes.Equal(seg[:pad], make([]byte, pad)) || (size+int64(pad))%4 != 0 {
			t.Errorf("size %d: %d bytes of padding", size, len(seg)-len(neutralizeSegment))
		}
	}
}

// TestNeutralizeSegmentReadByCPIO: an independent reader (GNU cpio) finds exactly the plan path in the segment, with
// mode 0600 and the invalid plan as content.
func TestNeutralizeSegmentReadByCPIO(t *testing.T) {
	cpio, err := exec.LookPath("cpio")
	if err != nil {
		t.Skip("cpio is not installed")
	}
	list := exec.Command(cpio, "-t", "-v", "--quiet") //nolint:gosec // the test's own tool
	list.Stdin = bytes.NewReader(neutralizeSegment)
	out, err := list.Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "-rw-------") || !strings.HasSuffix(lines[0], " "+initrdPlanPath) {
		t.Fatalf("listing %q", out)
	}
	extract := exec.Command(cpio, "-i", "--quiet", "--to-stdout", initrdPlanPath) //nolint:gosec // the test's own tool
	extract.Stdin = bytes.NewReader(neutralizeSegment)
	content, err := extract.Output()
	if err != nil || string(content) != cancelledPlan {
		t.Fatalf("content %q, %v", content, err)
	}
	if strings.Contains(cancelledPlan, "PADDOCK_PART_UUID") {
		t.Fatal("the invalid plan names a partition")
	}
}

// fullWriter takes room bytes, then fails like a full file system.
type fullWriter struct {
	room int
	got  bytes.Buffer
}

func (w *fullWriter) Write(b []byte) (int, error) {
	if w.got.Len()+len(b) > w.room {
		n := w.room - w.got.Len()
		w.got.Write(b[:n])
		return n, syscall.ENOSPC
	}
	return w.got.Write(b)
}

// fixedFree answers FreeBytes with free.
type fixedFree int64

func (f fixedFree) FreeBytes(string) (int64, error) { return int64(f), nil }

// TestNeutralizeCopyNoSpace: review 1 of PDK-482, M1 — a copy that runs out of room in /boot while the initrd or the
// segment is written is a BootSpaceError with the bytes needed and free (health boot_space_low, event reason
// boot_space_low); any other error stays as it is.
func TestNeutralizeCopyNoSpace(t *testing.T) {
	initrd := strings.Repeat("i", 1000)
	for _, room := range []int{10, len(initrd) + 3} {
		err := writeWithSegment(&fullWriter{room: room}, strings.NewReader(initrd), int64(len(initrd)), segmentAt(1000))
		if !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("room %d: %v", room, err)
		}
		var space *BootSpaceError
		if !errors.As(bootSpaceOr(err, fixedFree(512), paths.Layout{Root: t.TempDir()}, 4096), &space) ||
			space.Needed != 4096 || space.Free != 512 {
			t.Fatalf("room %d: %v", room, bootSpaceOr(err, fixedFree(512), paths.Layout{}, 4096))
		}
	}
	other := errors.New("input/output error")
	if got := bootSpaceOr(other, fixedFree(512), paths.Layout{}, 4096); got != other {
		t.Fatalf("mapped %v", got)
	}
	var w fullWriter
	w.room = 1 << 20
	if err := writeWithSegment(&w, strings.NewReader(initrd), int64(len(initrd)), segmentAt(1000)); err != nil ||
		w.got.String() != initrd+string(neutralizeSegment) {
		t.Fatalf("copy %v", err)
	}
}

// TestCheckAppendable: review 2 of PDK-482, X2 — the segment is appended only behind a main archive whose compression
// the kernel is known to end exactly (zstd, gzip, xz) or behind an initrd that is uncompressed to its end; the early
// uncompressed archives and the zeros between archives are skipped as the kernel's unpacker skips them. Any other or an
// unknown compression, and a truncated early archive, are errors.
func TestCheckAppendable(t *testing.T) {
	early := cpioNewc([]cpioFile{{Name: "kernel/x86/microcode/GenuineIntel.bin", Mode: 0o644, Data: []byte("ucode")}})
	zeros := string(make([]byte, 512-len(early)%512))
	tests := []struct {
		name, content, wantErr string
	}{
		{"zstd", string(early) + zeros + "\x28\xb5\x2f\xfd rest", ""},
		{"gzip", string(early) + "\x1f\x8b\x08 rest", ""},
		{"xz", string(early) + string(early) + "\xfd7zXZ\x00 rest", ""},
		{"zstd without early archive", "\x28\xb5\x2f\xfd rest", ""},
		{"uncompressed", string(early) + zeros + string(cpioNewc([]cpioFile{{Name: "init", Mode: 0o755, Data: []byte("#!/bin/sh")}})), ""},
		{"empty", "", ""},
		{"lz4", string(early) + "\x02\x21\x4c\x18 rest", "lz4-compressed"},
		{"bzip2", string(early) + "BZh91AY", "bzip2-compressed"},
		{"lzo", "\x89LZO\x00", "lzo-compressed"},
		{"lzma", "\x5d\x00\x00\x80\x00", "lzma-compressed"},
		{"unknown", string(early) + "PK\x03\x04", "unknown compression"},
		{"truncated early archive", string(early[:200]), "truncated cpio archive"},
		{"no newc archive", strings.Repeat("0123456789", 12), "no newc archive"},
	}
	for _, tt := range tests {
		name := filepath.Join(t.TempDir(), "initrd")
		if err := os.WriteFile(name, []byte(tt.content), 0o600); err != nil {
			t.Fatal(err)
		}
		err := checkAppendable(name, int64(len(tt.content)))
		if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
			t.Errorf("%s: error %v, want %q", tt.name, err, tt.wantErr)
		}
	}
}

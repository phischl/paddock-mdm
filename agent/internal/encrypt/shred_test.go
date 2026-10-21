package encrypt_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
	"github.com/phischl/paddock-mdm/agent/internal/state"
)

const installPassphrase = "/var/lib/paddock/install-passphrase"

func zeroed(t *testing.T, path string) bool {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // a test path
	if err != nil {
		t.Fatal(err)
	}
	return len(raw) > 0 && strings.Trim(string(raw), "\x00") == ""
}

// TestCleanupShredsHardLinkedKey: amendment item 19, rule A — the conversion key is overwritten whatever its link
// count: a hard link elsewhere reads zeros afterwards, and the cleanup finishes.
func TestCleanupShredsHardLinkedKey(t *testing.T) {
	f := preparedFixture(t)
	f.dev.Write("/var/tmp/other", "")
	outside := f.dev.Path("/var/tmp/key-copy")
	if err := os.Link(f.dev.Path(installPassphrase), outside); err != nil {
		t.Fatal(err)
	}
	done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	if !done || err != nil || f.dev.Exists(installPassphrase) || !zeroed(t, outside) {
		t.Fatalf("cleanup %v %v", done, err)
	}
}

// TestCleanupNeverShredsThroughKeySymlink: amendment item 19, rule A — a symlink at the key's path is not followed: its
// target stays byte for byte and the cleanup does not finish (fail closed); a FIFO there fails the same way.
func TestCleanupNeverShredsThroughKeySymlink(t *testing.T) {
	f := preparedFixture(t)
	f.dev.Write("/var/tmp/other", "someone else's file")
	if err := os.Remove(f.dev.Path(installPassphrase)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.dev.Path("/var/tmp/other"), f.dev.Path(installPassphrase)); err != nil {
		t.Fatal(err)
	}
	done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	if done || err == nil || f.read("/var/tmp/other") != "someone else's file" {
		t.Fatalf("cleanup %v %v", done, err)
	}

	// A FIFO at the key's path neither blocks the cleanup nor counts as shredded.
	if err := os.Remove(f.dev.Path(installPassphrase)); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(f.dev.Path(installPassphrase), 0o600); err != nil {
		t.Fatal(err)
	}
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); done || err == nil {
		t.Fatalf("fifo: %v %v", done, err)
	}
}

// TestCleanupOrphanLinkedOutside: amendment item 19, rule B — an orphan initrd with a hard link outside the listed
// initrds is neither written nor unlinked; the cleanup stays pending with key_material_hardlinked (replacing the other
// issue fields), and finishes once that link is gone, with orphan_initrd_removed in its place.
func TestCleanupOrphanLinkedOutside(t *testing.T) {
	const orphan = "6.2.0-1-generic"
	f := preparedFixture(t)
	f.dev.buildInitrd("/boot/initrd.img-"+orphan, orphan, true)
	before := f.read("/boot/initrd.img-" + orphan)
	outside := f.dev.Path("/boot/initrd.img.bak")
	if err := os.Link(f.dev.Path("/boot/initrd.img-"+orphan), outside); err != nil {
		t.Fatal(err)
	}
	_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) {
		c.InitrdIssue, c.BootSpaceNeeded, c.InitrdIssueKernel = encrypt.IssueBootSpaceLow, 1, "6.8.0-91-generic"
	})
	done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
	var linked *encrypt.KeyMaterialHardlinkedError
	if done || !errors.As(err, &linked) || linked.Links != 2 || f.read("/boot/initrd.img-"+orphan) != before ||
		!f.dev.Exists(installPassphrase) {
		t.Fatalf("outside link: %v %v", done, err)
	}
	if c := f.conversion(); c.InitrdIssue != encrypt.IssueKeyMaterialHardlinked || c.BootSpaceNeeded != 0 || c.InitrdIssueKernel != "" ||
		!strings.Contains(c.CleanupError, "initrd.img-"+orphan) {
		t.Fatalf("conversion %+v", c)
	}
	if err := os.Remove(outside); err != nil {
		t.Fatal(err)
	}
	if done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); !done || err != nil ||
		f.dev.Exists("/boot/initrd.img-"+orphan) || f.conversion().CleanupError != "" || f.conversion().InitrdIssue != encrypt.IssueOrphanInitrdRemoved {
		t.Fatalf("after the link went: %v %v", done, err)
	}
}

// TestCleanupStraysOfOneFile: amendment item 19, rule B — two stray names of one file are both orphans: the file is
// overwritten once and both names go; the cleanup finishes.
func TestCleanupStraysOfOneFile(t *testing.T) {
	const a, b = "6.2.0-1-generic", "6.2.0-2-generic"
	for _, readable := range []bool{true, false} {
		f := preparedFixture(t)
		if readable {
			f.dev.buildInitrd("/boot/initrd.img-"+a, a, true)
		} else {
			f.dev.Write("/boot/initrd.img-"+a, "TRUNCATED")
		}
		if err := os.Link(f.dev.Path("/boot/initrd.img-"+a), f.dev.Path("/boot/initrd.img-"+b)); err != nil {
			t.Fatal(err)
		}
		held, err := os.Open(f.dev.Path("/boot/initrd.img-" + a))
		if err != nil {
			t.Fatal(err)
		}
		done, orphans, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
		raw := make([]byte, 64)
		n, _ := held.Read(raw)
		_ = held.Close()
		slices.Sort(orphans)
		if !done || err != nil || !slices.Equal(orphans, []string{a, b}) || f.dev.Exists("/boot/initrd.img-"+a) ||
			f.dev.Exists("/boot/initrd.img-"+b) || n == 0 || strings.Trim(string(raw[:n]), "\x00") != "" {
			t.Fatalf("readable %v: %v %v %v", readable, done, orphans, err)
		}
	}
}

// TestCleanupUnreadableWithoutLister: PDK-383 — an initrd of no kernel is no orphan when no lister is installed (the
// listing could not even be tried): it stays and the cleanup does not finish. The bootable kernels have no initrd here,
// so that only the stray one is left to read.
func TestCleanupUnreadableWithoutLister(t *testing.T) {
	f := preparedFixture(t)
	f.dev.set(func(d *device) {
		d.packages["dracut"] = "config-files"
		d.missing = map[string]bool{"lsinitrd": true, "lsinitramfs": true}
	})
	for _, v := range []string{runningKernel, olderKernel} {
		if err := os.Remove(f.dev.Path("/boot/initrd.img-" + v)); err != nil {
			t.Fatal(err)
		}
	}
	f.dev.Write("/boot/initrd.img-6.2.0-1-generic", "TRUNCATED")
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); done || err == nil ||
		f.read("/boot/initrd.img-6.2.0-1-generic") != "TRUNCATED" {
		t.Fatalf("no lister: %v %v", done, err)
	}
}

// TestCleanupUnreadableOfKernelImage: amendment item 19(i) and PDK-383 — an unreadable initrd next to a kernel image
// (vmlinuz, vmlinux, kernel, or a kept vmlinuz-<v>.old) without modules.dep is no stray: it stays and the listing error
// is reported.
func TestCleanupUnreadableOfKernelImage(t *testing.T) {
	const v = "6.2.0-1-generic"
	for _, image := range []string{"vmlinuz-" + v, "vmlinux-" + v, "kernel-" + v, "vmlinuz-" + v + ".old"} {
		f := preparedFixture(t)
		f.dev.set(func(d *device) { d.packages["dracut"] = "config-files" })
		f.dev.Write("/boot/"+image, "kernel")
		f.dev.Write("/boot/initrd.img-"+v, "TRUNCATED")
		done, orphans, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
		if done || err == nil || len(orphans) != 0 || f.read("/boot/initrd.img-"+v) != "TRUNCATED" {
			t.Fatalf("%s: %v %v %v", image, done, orphans, err)
		}
	}
}

// TestRegenerateTempLinkedOutside: amendment item 19, rule B — a temporary initrd with a hard link outside /boot's
// listed initrds is not removed; the regeneration reports key_material_hardlinked's error.
func TestRegenerateTempLinkedOutside(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	f.dev.Write(tempPath("6.5.0-9-generic"), "a key-carrying temporary initrd")
	f.dev.Write("/var/tmp/other", "")
	if err := os.Link(f.dev.Path(tempPath("6.5.0-9-generic")), f.dev.Path("/var/tmp/copy")); err != nil {
		t.Fatal(err)
	}
	err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true)
	var linked *encrypt.KeyMaterialHardlinkedError
	if !errors.As(err, &linked) || f.read(tempPath("6.5.0-9-generic")) != "a key-carrying temporary initrd" {
		t.Fatalf("regeneration: %v", err)
	}
}

// TestFailedTempZeroed: Review 12 of PDK-245, M9 — a temporary initrd that fails its check is zeroed before it goes,
// not only unlinked.
func TestFailedTempZeroed(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	var held *os.File
	f.dev.set(func(d *device) {
		d.onTempCrypttab = func() {
			if held != nil {
				return
			}
			temps := glob(t, d.Path("/boot/.initrd.img-*"))
			var err error
			if held, err = os.Open(temps[0]); err != nil {
				t.Fatal(err)
			}
			// The same inode, now without the crypttab line: the check fails.
			if err := os.WriteFile(temps[0], []byte("a key-carrying initrd"+crypttabMark), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err == nil || held == nil {
		t.Fatalf("regeneration: %v", err)
	}
	defer func() { _ = held.Close() }()
	raw := make([]byte, 64)
	if n, _ := held.Read(raw); n == 0 || strings.Trim(string(raw[:n]), "\x00") != "" {
		t.Fatalf("the failed temporary initrd was not overwritten: %q", raw[:n])
	}
}

// TestCleanupRemovesSymlinkedTemp: Review 12 of PDK-245, M10 — a symlink at a temporary initrd's path is removed
// without writing through it; its target stays byte for byte and the cleanup finishes.
func TestCleanupRemovesSymlinkedTemp(t *testing.T) {
	f := preparedFixture(t)
	f.dev.Write("/var/tmp/other", "someone else's file")
	if err := os.Symlink(f.dev.Path("/var/tmp/other"), f.dev.Path(tempPath("6.5.0-9-generic"))); err != nil {
		t.Fatal(err)
	}
	done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	if !done || err != nil || f.read("/var/tmp/other") != "someone else's file" {
		t.Fatalf("cleanup %v %v", done, err)
	}
	if _, err := os.Lstat(f.dev.Path(tempPath("6.5.0-9-generic"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the symlink stayed: %v", err)
	}
}

// TestHardlinkedIssueCleared: Review 12 of PDK-245, m14 — key_material_hardlinked is cleared once the cleanup fails for
// another reason or finishes.
func TestHardlinkedIssueCleared(t *testing.T) {
	f := preparedFixture(t)
	f.dev.Write(tempPath("6.5.0-9-generic"), "a key-carrying temporary initrd")
	f.dev.Write("/var/tmp/other", "")
	if err := os.Link(f.dev.Path(tempPath("6.5.0-9-generic")), f.dev.Path("/var/tmp/copy")); err != nil {
		t.Fatal(err)
	}
	if done, _ := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); done ||
		f.conversion().InitrdIssue != encrypt.IssueKeyMaterialHardlinked {
		t.Fatalf("linked: %+v", f.conversion())
	}
	if err := os.Remove(f.dev.Path("/var/tmp/copy")); err != nil {
		t.Fatal(err)
	}
	// Another reason keeps the cleanup pending: the issue no longer applies.
	f.dev.Write(tempPath("6.5.0-8-generic")+"/file", "")
	if done, _ := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); done || f.conversion().InitrdIssue != "" {
		t.Fatalf("other reason: %+v", f.conversion())
	}
	if err := os.RemoveAll(f.dev.Path(tempPath("6.5.0-8-generic"))); err != nil {
		t.Fatal(err)
	}
	if done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); !done || err != nil ||
		f.conversion().InitrdIssue != "" {
		t.Fatalf("after the link went: %v %v %+v", done, err, f.conversion())
	}
}

// TestCleanupBootableSymlinkToOrphan: amendment item 19, rule B (review of 3ff90816, point 1) — a bootable kernel's
// initrd that is a symlink to a key-carrying orphan keeps its target: with dracut in config-files (verify only) the file
// stays byte for byte, the link resolves, and the cleanup stays pending with key_material_shared_bootable; with dracut
// installed the kernel's rebuild replaces the link and the orphan goes.
func TestCleanupBootableSymlinkToOrphan(t *testing.T) {
	const orphan = "6.2.0-1-generic"
	for _, installed := range []bool{false, true} {
		f := preparedFixture(t)
		if !installed {
			f.dev.set(func(d *device) { d.packages["dracut"] = "config-files" })
		}
		f.dev.buildInitrd("/boot/initrd.img-"+orphan, orphan, true)
		before := f.read("/boot/initrd.img-" + orphan)
		if err := os.Remove(f.dev.Path("/boot/initrd.img-" + olderKernel)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(f.dev.Path("/boot/initrd.img-"+orphan), f.dev.Path("/boot/initrd.img-"+olderKernel)); err != nil {
			t.Fatal(err)
		}
		done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store)
		if installed {
			if info, lerr := os.Lstat(f.dev.Path("/boot/initrd.img-" + olderKernel)); !done || err != nil || f.dev.Exists("/boot/initrd.img-"+orphan) ||
				lerr != nil || !info.Mode().IsRegular() {
				t.Fatalf("dracut installed: %v %v", done, err)
			}
			continue
		}
		var shared *encrypt.KeySharedBootableError
		if done || !errors.As(err, &shared) || shared.Kernel != olderKernel || f.read("/boot/initrd.img-"+orphan) != before ||
			f.read("/boot/initrd.img-"+olderKernel) != before || !f.dev.Exists(installPassphrase) {
			t.Fatalf("verify only: %v %v", done, err)
		}
		if c := f.conversion(); c.InitrdIssue != encrypt.IssueKeyMaterialSharedBootable || c.InitrdIssueKernel != olderKernel {
			t.Fatalf("conversion %+v", c)
		}
	}
}

// TestCleanupHandlesEveryGroup: amendment item 19, rule B (review of 3ff90816, point 2) — a file kept for an outside
// hard link does not keep another orphan from being overwritten and removed; the cleanup stays pending.
func TestCleanupHandlesEveryGroup(t *testing.T) {
	const linked, plain = "6.2.0-1-generic", "6.2.0-2-generic"
	f := preparedFixture(t)
	f.dev.buildInitrd("/boot/initrd.img-"+linked, linked, true)
	f.dev.buildInitrd("/boot/initrd.img-"+plain, plain, true)
	before := f.read("/boot/initrd.img-" + linked)
	if err := os.Link(f.dev.Path("/boot/initrd.img-"+linked), f.dev.Path("/boot/initrd.img.bak")); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(f.dev.Path("/boot/initrd.img-" + plain))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	done, orphans, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	var hardlinked *encrypt.KeyMaterialHardlinkedError
	if done || !errors.As(err, &hardlinked) || !slices.Equal(orphans, []string{plain}) || f.dev.Exists("/boot/initrd.img-"+plain) ||
		f.read("/boot/initrd.img-"+linked) != before {
		t.Fatalf("cleanup %v %v %v", done, orphans, err)
	}
	raw := make([]byte, 64)
	if n, _ := held.Read(raw); n == 0 || strings.Trim(string(raw[:n]), "\x00") != "" {
		t.Fatal("the other orphan was not overwritten")
	}
}

// allZero reports whether f holds size bytes, all zero.
func allZero(t *testing.T, f *os.File, size int64) bool {
	t.Helper()
	raw := make([]byte, size+1)
	n, _ := f.ReadAt(raw, 0)
	return int64(n) == size && strings.Trim(string(raw[:n]), "\x00") == ""
}

// TestShredInChunks: review of 3ff90816, point 4 — the key file and an orphan larger than the 1 MiB chunk, sparse ones
// included, are overwritten over their whole size.
func TestShredInChunks(t *testing.T) {
	const size = 5<<20 + 7
	f := preparedFixture(t)
	key := f.dev.Path(installPassphrase)
	orphan := f.dev.Path("/boot/initrd.img-6.2.0-1-generic")
	f.dev.Write("/boot/initrd.img-6.2.0-1-generic", "TRUNCATED")
	var held []*os.File
	for _, p := range []string{key, orphan} {
		h, err := os.OpenFile(p, os.O_RDWR, 0) //nolint:gosec // a test path
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = h.Close() }()
		// Sparse up to 4 MiB, then data the overwrite must reach.
		if _, err := h.WriteAt([]byte("secret"), 4<<20); err != nil {
			t.Fatal(err)
		}
		if err := h.Truncate(size); err != nil {
			t.Fatal(err)
		}
		held = append(held, h)
	}
	done, orphans, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true)
	if !done || err != nil || !slices.Equal(orphans, []string{"6.2.0-1-generic"}) {
		t.Fatalf("cleanup %v %v %v", done, orphans, err)
	}
	for i, h := range held {
		if !allZero(t, h, size) {
			t.Fatalf("file %d not overwritten over its whole size", i)
		}
	}
}

// TestBuildClearsTempBeforeDracut: Review 12 of PDK-245, M10 — a symlink that appears at the temporary path after the
// start of a build is removed before dracut runs: dracut never writes through it.
func TestBuildClearsTempBeforeDracut(t *testing.T) {
	f := convertedFixture(t)
	c := f.conversion()
	f.dev.Write("/var/tmp/other", "someone else's file")
	f.dev.FreeFunc = func(string) int64 {
		for _, v := range []string{runningKernel, olderKernel} {
			_ = os.Symlink(f.dev.Path("/var/tmp/other"), f.dev.Path(tempPath(v)))
		}
		return 1 << 40
	}
	if err := encrypt.RegenerateInitrd(context.Background(), f.dev, f.dev.layout, c.Mapping, c.LUKSUUID, true); err != nil {
		t.Fatalf("regeneration: %v", err)
	}
	if f.read("/var/tmp/other") != "someone else's file" {
		t.Fatal("dracut wrote through a symlink at the temporary path")
	}
}

// TestCleanupKeepsTempDirectory: Review 12 of PDK-245, M10 — a directory at a temporary path is not removed; the
// cleanup fails closed and keeps the key.
func TestCleanupKeepsTempDirectory(t *testing.T) {
	f := preparedFixture(t)
	if err := os.Mkdir(f.dev.Path(tempPath("6.5.0-9-generic")), 0o700); err != nil {
		t.Fatal(err)
	}
	if done, _, err := encrypt.Cleanup(context.Background(), f.dev, f.dev.layout, true); done || err == nil ||
		!f.dev.Exists(tempPath("6.5.0-9-generic")) || !f.dev.Exists(installPassphrase) {
		t.Fatalf("cleanup %v %v", done, err)
	}
}

// TestTempsRemovedOnlyByRuleB: Review 12 of PDK-245, M9 — no code of the package removes a temporary initrd by a plain
// os.Remove: every removal of such a path goes through removeInitrdNames.
func TestTempsRemovedOnlyByRuleB(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == "removeInitrdNames" || fn.Name.Name == "removeFile" || fn.Name.Name == "shred" {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if pkg, isIdent := selX(sel); !ok || !isIdent || pkg != "os" || (sel.Sel.Name != "Remove" && sel.Sel.Name != "RemoveAll") {
					return true
				}
				ast.Inspect(call.Args[0], func(a ast.Node) bool {
					if id, ok := a.(*ast.Ident); ok && (id.Name == "tmp" || id.Name == "tempInitrd" || id.Name == "stale") {
						t.Errorf("%s: %s removes a temporary initrd with os.%s", fset.Position(call.Pos()), fn.Name.Name, sel.Sel.Name)
					}
					return true
				})
				return true
			})
		}
	}
}

func selX(sel *ast.SelectorExpr) (string, bool) {
	if sel == nil {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

// TestFinishedCleanupClearsIssues: review of 3ff90816 (m14) — a finished cleanup clears every initrd issue and its
// fields; only orphan_initrd_removed stays (amendment item 19(g)).
func TestFinishedCleanupClearsIssues(t *testing.T) {
	f := preparedFixture(t)
	_ = f.store.Update(func(c *state.DiskConversion, _ *state.LUKS) {
		c.InitrdIssue, c.BootSpaceNeeded, c.BootSpaceFree, c.InitrdIssueKernel = encrypt.IssueBootSpaceLow, 1, 2, "6.8.0-91-generic"
	})
	if done, err := encrypt.RunCleanup(context.Background(), f.dev, f.dev.layout, f.store); !done || err != nil {
		t.Fatalf("cleanup %v %v", done, err)
	}
	if c := f.conversion(); c.InitrdIssue != "" || c.BootSpaceNeeded != 0 || c.BootSpaceFree != 0 || c.InitrdIssueKernel != "" {
		t.Fatalf("conversion %+v", c)
	}
}

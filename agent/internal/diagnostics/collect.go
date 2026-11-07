package diagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
)

// Manifest is manifest.json, the first file of the archive.
type Manifest struct {
	Schema       string          `json:"schema"`
	CollectedAt  time.Time       `json:"collected_at"`
	DeviceID     string          `json:"device_id"`
	AgentVersion string          `json:"agent_version"`
	Entries      []ManifestEntry `json:"entries"`
}

// ManifestEntry is the outcome of one element of Entries. An entry that could not be read has Error and no content;
// a glob or KindLUKS entry lists its files in Files and has no SHA256 of its own.
type ManifestEntry struct {
	Name      string `json:"name"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256,omitempty"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
	Files     []File `json:"files,omitempty"`
}

// File is one archive file of a multi-file entry.
type File struct {
	Name      string `json:"name"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated"`
}

// Files is the number of archive files besides manifest.json.
func (m Manifest) Files() int {
	n := 0
	for _, e := range m.Entries {
		switch {
		case len(e.Files) > 0:
			n += len(e.Files)
		case e.Error == "" && e.SHA256 != "":
			n++
		}
	}
	return n
}

// Truncated are the names of the archive files cut at their cap or at MaxContent.
func (m Manifest) Truncated() []string {
	var out []string
	for _, e := range m.Entries {
		if e.Truncated && len(e.Files) == 0 {
			out = append(out, e.Name)
		}
		for _, f := range e.Files {
			if f.Truncated {
				out = append(out, f.Name)
			}
		}
	}
	return out
}

// Health returns the agent's current health report.
type Health interface {
	Report() health.Report
}

// Sources are what Collect reads besides the device.
type Sources struct {
	Health Health
	// Healthz returns the answer of GET <server_url>/healthz; nil records the entry as unavailable.
	Healthz      func(ctx context.Context) ([]byte, error)
	DeviceID     string
	AgentVersion string
	Now          time.Time
}

// Collect writes the archive of Entries to w as tar.gz with manifest.json first and returns the manifest. One entry
// that cannot be read is recorded with its error and never aborts the archive; only a failed write does.
func Collect(ctx context.Context, sys reconcile.System, src Sources, w io.Writer) (Manifest, error) {
	c := collector{ctx: ctx, sys: sys, src: src, budget: MaxContent}
	m := Manifest{Schema: Schema, CollectedAt: src.Now.UTC(), DeviceID: src.DeviceID, AgentVersion: src.AgentVersion}
	for _, e := range Entries() {
		m.Entries = append(m.Entries, c.entry(e))
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	zw := gzip.NewWriter(w)
	tw := tar.NewWriter(zw)
	if err := add(tw, "manifest.json", append(manifest, '\n'), m.CollectedAt); err != nil {
		return Manifest{}, err
	}
	for _, f := range c.files {
		if err := add(tw, f.name, f.data, m.CollectedAt); err != nil {
			return Manifest{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Manifest{}, fmt.Errorf("diagnostics: close the archive: %w", err)
	}
	if err := zw.Close(); err != nil {
		return Manifest{}, fmt.Errorf("diagnostics: close the archive: %w", err)
	}
	return m, nil
}

func add(tw *tar.Writer, name string, data []byte, at time.Time) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: at, Typeflag: tar.TypeReg}); err != nil {
		return fmt.Errorf("diagnostics: write %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("diagnostics: write %s: %w", name, err)
	}
	return nil
}

type archived struct {
	name string
	data []byte
}

type collector struct {
	ctx    context.Context
	sys    reconcile.System
	src    Sources
	budget int64
	files  []archived
}

// entry reads one element of the list into the archive; once the content budget is spent, it is not read at all.
func (c *collector) entry(e Entry) ManifestEntry {
	if c.budget <= 0 {
		return ManifestEntry{Name: e.Name, Truncated: true}
	}
	switch e.Kind {
	case KindGlob:
		return c.glob(e)
	case KindLUKS:
		return c.luks(e)
	}
	data, err := c.read(e)
	if err != nil {
		return ManifestEntry{Name: e.Name, Error: err.Error()}
	}
	f := c.keep(e.Name, data, e)
	return ManifestEntry{Name: e.Name, Bytes: f.Bytes, SHA256: f.SHA256, Truncated: f.Truncated}
}

// keep redacts and caps data and adds it to the archive.
func (c *collector) keep(name string, data []byte, e Entry) File {
	if e.Redact != nil {
		data = e.Redact(data)
	}
	limit := min(e.MaxBytes, c.budget)
	truncated := int64(len(data)) > limit
	if truncated {
		// A copy: the slice would keep the whole read (up to the 16 MiB of a command's output) alive until the
		// archive is written.
		data = bytes.Clone(data[:limit])
	}
	c.budget -= int64(len(data))
	c.files = append(c.files, archived{name: name, data: data})
	sum := sha256.Sum256(data)
	return File{Name: name, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Truncated: truncated}
}

// errNotRegular is a listed path that is not a regular file (a symlink is never followed).
var errNotRegular = errors.New("not a regular file")

func (c *collector) read(e Entry) ([]byte, error) {
	switch e.Kind {
	case KindFile:
		return c.file(e.Source)
	case KindExec:
		f := strings.Fields(e.Source)
		return c.output(e, f[0], f[1:]...)
	case KindJournal:
		return c.output(e, "journalctl", "-u", e.Source, "--since=-7d", "--no-pager", "-o", "short-iso", "--reverse")
	case KindHealth:
		if c.src.Health == nil {
			return nil, errors.New("no health report")
		}
		out, err := json.MarshalIndent(c.src.Health.Report(), "", "  ")
		return append(out, '\n'), err
	case KindTPM:
		var b strings.Builder
		for _, dev := range strings.Fields(e.Source) {
			_, _, err := c.sys.ReadFile(dev)
			fmt.Fprintf(&b, "%s present=%t\n", dev, err == nil)
		}
		return []byte(b.String()), nil
	case KindHealthz:
		if c.src.Healthz == nil {
			return nil, errors.New("no server")
		}
		return c.src.Healthz(c.ctx)
	}
	return nil, fmt.Errorf("unknown kind %q", e.Kind)
}

func (c *collector) file(p string) ([]byte, error) {
	data, _, err := c.sys.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, errNotRegular
	}
	return data, nil
}

// output runs a command; output beyond the reconcile.MaxOutput limit is kept as far as it goes (the entry is cut at
// its cap anyway), and an exit code of e.Exits still counts as content.
func (c *collector) output(e Entry, name string, args ...string) ([]byte, error) {
	out, err := c.sys.Output(c.ctx, name, args...)
	var exit *reconcile.ExitError
	switch {
	case err == nil, errors.Is(err, reconcile.ErrOutputLimit):
		return out, nil
	case errors.As(err, &exit) && slices.Contains(e.Exits, exit.Code):
		return out, nil
	}
	return nil, err
}

func (c *collector) glob(e Entry) ManifestEntry {
	dir, pattern := path.Split(e.Source)
	names, err := c.sys.ReadDir(dir)
	if err != nil {
		return ManifestEntry{Name: e.Name, Error: err.Error()}
	}
	me := ManifestEntry{Name: e.Name}
	for _, n := range names {
		if ok, _ := path.Match(pattern, n); !ok {
			continue
		}
		if c.budget <= 0 {
			me.Truncated = true
			break
		}
		data, err := c.file(dir + n)
		if err != nil {
			continue
		}
		f := c.keep(e.Name+"/"+n, data, e)
		me.Files = append(me.Files, f)
		me.Bytes += f.Bytes
		me.Truncated = me.Truncated || f.Truncated
	}
	return me
}

var luksUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// luks dumps the LUKS volumes the agent manages: those of its health report, by UUID.
func (c *collector) luks(e Entry) ManifestEntry {
	me := ManifestEntry{Name: e.Name}
	if c.src.Health == nil {
		me.Error = "no health report"
		return me
	}
	disk := c.src.Health.Report().Disk
	if disk == nil {
		return me
	}
	f := strings.Fields(e.Source)
	var errs []string
	for _, v := range disk.Volumes {
		if v.SharedUUID || !luksUUID.MatchString(v.UUID) {
			continue
		}
		if c.budget <= 0 {
			me.Truncated = true
			break
		}
		out, err := c.output(e, f[0], append(f[1:], "--", "/dev/disk/by-uuid/"+v.UUID)...)
		if err != nil {
			errs = append(errs, v.UUID+": "+err.Error())
			continue
		}
		file := c.keep(e.Name+"-"+v.UUID+".txt", out, e)
		me.Files = append(me.Files, file)
		me.Bytes += file.Bytes
		me.Truncated = me.Truncated || file.Truncated
	}
	me.Error = strings.Join(errs, "; ")
	return me
}

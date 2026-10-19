package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// HostsFile is the file whose 127.0.1.1 line the hostname reconciler keeps (sudo resolves the local hostname there).
const HostsFile = "/etc/hosts"

const (
	avahiUnit    = "avahi-daemon.service"
	hostsLoopIP  = "127.0.1.1"
	hostsLocalIP = "127.0.0.1"
)

// Hostname reconciles the hostname resource (plan M8h decision 13): the static and transient hostname, a pretty
// hostname that is empty or the name, the 127.0.1.1 line of /etc/hosts and a running avahi-daemon.
type Hostname struct {
	Sys System
	// HostsManaged reports whether the current bundle manages /etc/hosts as a file; then the reconciler leaves
	// the file alone (ADR 0041 decision 6).
	HostsManaged func() bool
	// State carries what one pass leaves for the next; the applier keeps one for the agent's lifetime. Without it
	// a failed avahi-daemon restart is not retried.
	State *HostnameState
}

// HostnameState is what the hostname reconciler remembers between passes.
type HostnameState struct {
	// avahiPending is set while the restart of avahi-daemon after a rename has not succeeded: the names are in
	// sync then, so only this flag makes the next pass retry it.
	avahiPending atomic.Bool
	// hostsSkipped is set while /etc/hosts is not a regular file and that was logged, so it is logged once rather
	// than at every drift pass.
	hostsSkipped atomic.Bool
}

// Type implements Reconciler.
func (h *Hostname) Type() string { return bundle.TypeHostname }

// Plan implements Reconciler.
func (h *Hostname) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	changes, _, err := h.plan(ctx, r)
	return changes, err
}

// plan is Plan that also returns the device's current static and transient name, the old names Apply looks for on
// the 127.0.1.1 line of /etc/hosts.
func (h *Hostname) plan(ctx context.Context, r bundle.Resource) ([]string, []string, error) {
	name, err := hostnameOf(r)
	if err != nil {
		return nil, nil, err
	}
	out, exit, err := h.Sys.Hostnamectl(ctx, "--json=short")
	if err == nil && exit != 0 {
		err = fmt.Errorf("exit %d %s", exit, strings.TrimSpace(out))
	}
	var names struct{ Hostname, StaticHostname, PrettyHostname string }
	if err == nil {
		err = json.Unmarshal([]byte(out), &names)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("hostnamed unavailable: %w", err)
	}
	var changes []string
	// hostnamectl clears the pretty name when it sets a valid host name (systemd set_hostname, ADR 0041 amendment
	// 2026-10-18), so an empty pretty name is in sync; only a pretty name of its own is drift.
	if names.StaticHostname != name || names.Hostname != name || (names.PrettyHostname != "" && names.PrettyHostname != name) {
		changes = append(changes, "hostnamectl hostname "+name)
	} else if h.State != nil && h.State.avahiPending.Load() {
		changes = append(changes, "systemctl restart "+avahiUnit)
	}
	if h.HostsManaged == nil || !h.HostsManaged() {
		data, _, err := h.Sys.ReadFile(HostsFile)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("read %s: %w", HostsFile, err)
		}
		if err == nil && data == nil {
			h.skipHosts(ctx)
		} else {
			if h.State != nil {
				h.State.hostsSkipped.Store(false)
			}
			if !hostsHasName(data, name) {
				changes = append(changes, "write "+HostsFile+" "+hostsLoopIP+" "+name)
			}
		}
	}
	return changes, []string{names.StaticHostname, names.Hostname}, nil
}

// Apply implements Reconciler. A refused rename leaves /etc/hosts and Avahi alone; after a rename avahi-daemon is
// restarted whether or not /etc/hosts can be written, and both errors are reported. The device keeps working with
// whatever name it has (contract 8).
func (h *Hostname) Apply(ctx context.Context, r bundle.Resource) Result {
	var old []string
	plan := func(ctx context.Context, r bundle.Resource) ([]string, error) {
		changes, names, err := h.plan(ctx, r)
		old = names
		return changes, err
	}
	return apply(ctx, r, plan, func(changes []string) error {
		name, err := hostnameOf(r)
		if err != nil {
			return err
		}
		var errs []error
		for _, c := range changes {
			switch {
			case strings.HasPrefix(c, "hostnamectl "):
				out, exit, err := h.Sys.Hostnamectl(ctx, "hostname", name)
				if err != nil {
					return fmt.Errorf("%s: %w", c, err)
				}
				if exit != 0 {
					return fmt.Errorf("%s: exit %d %s", c, exit, strings.TrimSpace(out))
				}
				errs = append(errs, h.restartAvahi(ctx))
			case c == "systemctl restart "+avahiUnit:
				errs = append(errs, h.restartAvahi(ctx))
			case strings.HasPrefix(c, "write "+HostsFile):
				errs = append(errs, h.writeHosts(old, name))
			default:
				return fmt.Errorf("unknown change %q", c)
			}
		}
		return errors.Join(errs...)
	})
}

// restartAvahi restarts a running avahi-daemon: it reads the host name at startup only and would keep announcing
// the old one (ADR 0041 context). A failed restart stays pending in State for the next pass.
func (h *Hostname) restartAvahi(ctx context.Context) error {
	if _, exit, err := h.Sys.Systemctl(ctx, "is-active", avahiUnit); err != nil || exit != 0 {
		h.setAvahiPending(false)
		return nil
	}
	out, exit, err := h.Sys.Systemctl(ctx, "restart", avahiUnit)
	if err == nil && exit != 0 {
		err = fmt.Errorf("exit %d %s", exit, strings.TrimSpace(out))
	}
	h.setAvahiPending(err != nil)
	if err != nil {
		return fmt.Errorf("avahi-daemon restart failed: %w", err)
	}
	return nil
}

// skipHosts leaves a non-regular /etc/hosts (a symlink, e.g. to a file another tool generates) alone: writing it
// would replace the link (RR-70). It is logged once while it stays so.
func (h *Hostname) skipHosts(ctx context.Context) {
	if h.State == nil || h.State.hostsSkipped.CompareAndSwap(false, true) {
		slog.WarnContext(ctx, "the hostname reconciler leaves a non-regular file alone", "path", HostsFile)
	}
}

func (h *Hostname) setAvahiPending(pending bool) {
	if h.State != nil {
		h.State.avahiPending.Store(pending)
	}
}

func (h *Hostname) writeHosts(old []string, name string) error {
	data, _, err := h.Sys.ReadFile(HostsFile)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", HostsFile, err)
	}
	if exists && data == nil {
		return fmt.Errorf("%s is not a regular file", HostsFile)
	}
	if err := h.Sys.WriteFileAtomic(HostsFile, hostsWithName(data, exists, old, name), 0o644, 0, 0); err != nil {
		return fmt.Errorf("write %s: %w", HostsFile, err)
	}
	return nil
}

func hostnameOf(r bundle.Resource) (string, error) {
	var s bundle.HostnameSpec
	if err := json.Unmarshal(r.Spec, &s); err != nil {
		return "", fmt.Errorf("invalid hostname spec: %w", err)
	}
	if !bundle.ValidHostname(s.Name) {
		return "", fmt.Errorf("invalid hostname spec: %q is not a host name label", s.Name)
	}
	return s.Name, nil
}

// hostsHasName reports whether a 127.0.1.1 line of /etc/hosts lists name among its host names.
func hostsHasName(data []byte, name string) bool {
	for line := range strings.Lines(string(data)) {
		line, _, _ = strings.Cut(line, "#")
		if f := strings.Fields(line); len(f) >= 2 && f[0] == hostsLoopIP && slices.Contains(f[1:], name) {
			return true
		}
	}
	return false
}

// hostsWithName returns /etc/hosts with the old names on its first 127.0.1.1 line renamed to name (withName) and
// every other byte kept; without such a line the entry "127.0.1.1\t<name>" follows the first 127.0.0.1 line or ends
// the file. A missing file becomes the two loopback lines.
func hostsWithName(data []byte, exists bool, old []string, name string) []byte {
	entry := hostsLoopIP + "\t" + name
	if !exists {
		return []byte(hostsLocalIP + "\tlocalhost\n" + entry + "\n")
	}
	lines := strings.SplitAfter(string(data), "\n")
	local := -1
	for i, line := range lines {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == hostsLoopIP {
			lines[i] = withName(line, old, name)
			return []byte(strings.Join(lines, ""))
		}
		if f[0] == hostsLocalIP && local < 0 {
			local = i
		}
	}
	if local < 0 {
		out := string(data)
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		return []byte(out + entry + "\n")
	}
	if !strings.HasSuffix(lines[local], "\n") {
		lines[local] += "\n"
	}
	lines = append(lines[:local+1], append([]string{entry + "\n"}, lines[local+1:]...)...)
	return []byte(strings.Join(lines, ""))
}

// withName renames a 127.0.1.1 line from the old names to name, keeping the Debian layout "<fqdn> <short>": a host
// name equal to an old name becomes name, "<old>.<domain>" becomes "<name>.<domain>", every other alias stays. When
// only a "<old>.<domain>" matched, name follows it so that the short name resolves. When nothing matched (an unknown
// layout), the first host name becomes name; a line without one gets name after the address. Separators, a comment
// and the line ending stay.
func withName(line string, old []string, name string) string {
	start := strings.Index(line, hostsLoopIP) + len(hostsLoopIP)
	head, rest := line[:start], line[start:]
	comment := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest, comment = rest[:i], rest[i:]
	}
	var spans [][2]int
	for i := 0; i < len(rest); {
		if strings.IndexByte(" \t\r\n", rest[i]) >= 0 {
			i++
			continue
		}
		j := i
		for j < len(rest) && strings.IndexByte(" \t\r\n", rest[j]) < 0 {
			j++
		}
		spans = append(spans, [2]int{i, j})
		i = j
	}
	if len(spans) == 0 {
		tail := strings.TrimLeft(rest, " \t")
		lead := rest[:len(rest)-len(tail)]
		if lead == "" {
			lead = "\t"
		}
		if comment != "" && tail == "" {
			tail = " "
		}
		return head + lead + name + tail + comment
	}
	renamed := make([]string, len(spans))
	matched, short, fqdn := false, false, -1
	for k, sp := range spans {
		f := rest[sp[0]:sp[1]]
		renamed[k] = f
		for _, o := range old {
			if o == "" {
				continue
			}
			if f == o {
				renamed[k], matched, short = name, true, true
				break
			}
			if strings.HasPrefix(f, o+".") {
				renamed[k], matched = name+f[len(o):], true
				if fqdn < 0 {
					fqdn = k
				}
				break
			}
		}
	}
	if !matched {
		renamed[0] = name
	} else if !short {
		renamed[fqdn] += " " + name
	}
	var b strings.Builder
	b.WriteString(head)
	prev := 0
	for k, sp := range spans {
		b.WriteString(rest[prev:sp[0]])
		b.WriteString(renamed[k])
		prev = sp[1]
	}
	b.WriteString(rest[prev:])
	b.WriteString(comment)
	return b.String()
}

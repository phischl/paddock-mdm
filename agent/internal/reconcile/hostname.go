package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// HostsFile is the file whose 127.0.1.1 line the hostname reconciler keeps (sudo resolves the local hostname there).
const HostsFile = "/etc/hosts"

const (
	avahiUnit    = "avahi-daemon.service"
	hostsLoopIP  = "127.0.1.1"
	hostsLocalIP = "127.0.0.1"
)

// Hostname reconciles the hostname resource (plan M8h decision 13): the static, transient and pretty hostname,
// the 127.0.1.1 line of /etc/hosts and a running avahi-daemon.
type Hostname struct {
	Sys System
	// HostsManaged reports whether the current bundle manages /etc/hosts as a file; then the reconciler leaves
	// the file alone (ADR 0041 decision 6).
	HostsManaged func() bool
}

// Type implements Reconciler.
func (h *Hostname) Type() string { return bundle.TypeHostname }

// Plan implements Reconciler.
func (h *Hostname) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	name, err := hostnameOf(r)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("hostnamed unavailable: %w", err)
	}
	var changes []string
	if names.StaticHostname != name || names.Hostname != name || names.PrettyHostname != name {
		changes = append(changes, "hostnamectl hostname "+name)
	}
	if h.HostsManaged == nil || !h.HostsManaged() {
		data, _, err := h.Sys.ReadFile(HostsFile)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("read %s: %w", HostsFile, err)
		}
		if !hostsHasName(data, name) {
			changes = append(changes, "write "+HostsFile+" "+hostsLoopIP+" "+name)
		}
	}
	return changes, nil
}

// Apply implements Reconciler. A failing step leaves the later ones undone; the device keeps working with
// whatever name it has (contract 8).
func (h *Hostname) Apply(ctx context.Context, r bundle.Resource) Result {
	return apply(ctx, r, h.Plan, func(changes []string) error {
		name, err := hostnameOf(r)
		if err != nil {
			return err
		}
		renamed := false
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
				renamed = true
			case strings.HasPrefix(c, "write "+HostsFile):
				if err := h.writeHosts(name); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown change %q", c)
			}
		}
		if renamed {
			return h.restartAvahi(ctx)
		}
		return nil
	})
}

// restartAvahi restarts a running avahi-daemon: it reads the host name at startup only and would keep announcing
// the old one (ADR 0041 context).
func (h *Hostname) restartAvahi(ctx context.Context) error {
	if _, exit, err := h.Sys.Systemctl(ctx, "is-active", avahiUnit); err != nil || exit != 0 {
		return nil
	}
	out, exit, err := h.Sys.Systemctl(ctx, "restart", avahiUnit)
	if err == nil && exit != 0 {
		err = fmt.Errorf("exit %d %s", exit, strings.TrimSpace(out))
	}
	if err != nil {
		return fmt.Errorf("avahi-daemon restart failed: %w", err)
	}
	return nil
}

func (h *Hostname) writeHosts(name string) error {
	data, _, err := h.Sys.ReadFile(HostsFile)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", HostsFile, err)
	}
	if exists && data == nil {
		return fmt.Errorf("%s is not a regular file", HostsFile)
	}
	if err := h.Sys.WriteFileAtomic(HostsFile, hostsWithName(data, exists, name), 0o644, 0, 0); err != nil {
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

// hostsHasName reports whether a line of /etc/hosts maps 127.0.1.1 to name as its first host name.
func hostsHasName(data []byte, name string) bool {
	for line := range strings.Lines(string(data)) {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == hostsLoopIP && f[1] == name {
			return true
		}
	}
	return false
}

// hostsWithName returns /etc/hosts with its first 127.0.1.1 line replaced by "127.0.1.1\t<name>" and every other
// byte kept; without such a line the entry follows the first 127.0.0.1 line or ends the file. A missing file
// becomes the two loopback lines.
func hostsWithName(data []byte, exists bool, name string) []byte {
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
			lines[i] = entry + line[len(strings.TrimRight(line, "\r\n")):]
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

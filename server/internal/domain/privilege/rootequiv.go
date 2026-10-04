package privilege

import (
	"slices"
	"strings"
)

// CatalogVersion identifies the root-equivalence rules below; it changes with every change of the rules, so a
// recorded root_equivalent flag can be traced to the rules that produced it (architecture §10.2).
const CatalogVersion = 1

// rootEquivalent is one catalog entry: a binary that hands out root, either with any arguments (always), or only with
// the given first argument (subcommand). Any argument wildcard on a catalog binary counts as root-equivalent too, and
// so does a catalog binary without arguments, which sudo reads as "any arguments".
type rootEquivalent struct {
	binary     string
	always     bool
	subcommand string
}

// catalog lists binaries by their /usr path; commands are matched after mapping /bin and /sbin to /usr (merged /usr).
var catalog = []rootEquivalent{
	// Shells, privilege tools and interpreters run arbitrary code.
	{binary: "/usr/bin/sh", always: true}, {binary: "/usr/bin/bash", always: true}, {binary: "/usr/bin/dash", always: true},
	{binary: "/usr/bin/zsh", always: true}, {binary: "/usr/bin/fish", always: true}, {binary: "/usr/bin/ksh", always: true},
	{binary: "/usr/bin/su", always: true}, {binary: "/usr/bin/sudo", always: true}, {binary: "/usr/bin/sudoedit", always: true},
	{binary: "/usr/bin/env", always: true}, {binary: "/usr/bin/nohup", always: true}, {binary: "/usr/bin/xargs", always: true},
	{binary: "/usr/bin/python", always: true}, {binary: "/usr/bin/python3", always: true}, {binary: "/usr/bin/perl", always: true},
	{binary: "/usr/bin/ruby", always: true}, {binary: "/usr/bin/node", always: true}, {binary: "/usr/bin/lua", always: true},
	{binary: "/usr/bin/php", always: true}, {binary: "/usr/bin/awk", always: true}, {binary: "/usr/bin/gawk", always: true},
	{binary: "/usr/bin/mawk", always: true},
	// Editors and pagers with a shell escape.
	{binary: "/usr/bin/vi", always: true}, {binary: "/usr/bin/vim", always: true}, {binary: "/usr/bin/vim.basic", always: true},
	{binary: "/usr/bin/view", always: true}, {binary: "/usr/bin/nano", always: true}, {binary: "/usr/bin/emacs", always: true},
	{binary: "/usr/bin/ed", always: true}, {binary: "/usr/bin/less", always: true}, {binary: "/usr/bin/more", always: true},
	{binary: "/usr/bin/man", always: true},
	// Package managers install packages and run maintainer scripts as root.
	{binary: "/usr/bin/apt", always: true}, {binary: "/usr/bin/apt-get", always: true}, {binary: "/usr/bin/dpkg", always: true},
	{binary: "/usr/bin/snap", always: true}, {binary: "/usr/bin/pip", always: true}, {binary: "/usr/bin/pip3", always: true},
	{binary: "/usr/bin/flatpak", always: true},
	// Containers, units and kernel modules.
	{binary: "/usr/bin/docker", always: true}, {binary: "/usr/bin/podman", always: true},
	{binary: "/usr/bin/systemd-run", always: true}, {binary: "/usr/bin/systemctl", subcommand: "edit"},
	{binary: "/usr/bin/systemctl", subcommand: "link"}, {binary: "/usr/bin/mount", always: true},
	{binary: "/usr/sbin/insmod", always: true}, {binary: "/usr/sbin/modprobe", always: true},
	// Account and scheduling tools.
	{binary: "/usr/bin/crontab", always: true}, {binary: "/usr/sbin/visudo", always: true},
	{binary: "/usr/sbin/usermod", always: true}, {binary: "/usr/sbin/useradd", always: true},
	{binary: "/usr/bin/passwd", always: true}, {binary: "/usr/bin/chpasswd", always: true},
	// File tools: root-equivalent on arbitrary paths (without arguments or with a wildcard) and on the sensitive
	// destinations below.
	{binary: "/usr/bin/chmod"}, {binary: "/usr/bin/chown"}, {binary: "/usr/bin/tee"}, {binary: "/usr/bin/cp"},
	{binary: "/usr/bin/mv"}, {binary: "/usr/bin/dd"}, {binary: "/usr/bin/find"}, {binary: "/usr/bin/tar"},
	{binary: "/usr/bin/rsync"}, {binary: "/usr/bin/sed"}, {binary: "/usr/bin/ln"}, {binary: "/usr/bin/install"},
}

// writers are file tools whose path arguments are written (tee) or whose last path argument is the destination.
var writers = map[string]bool{
	"/usr/bin/tee": true, "/usr/bin/cp": true, "/usr/bin/mv": true, "/usr/bin/install": true, "/usr/bin/ln": true,
	"/usr/bin/rsync": true, "/usr/bin/chmod": true, "/usr/bin/chown": true,
}

// sensitiveDestinations are paths whose modification hands out root: privilege, authentication and boot
// configuration, scheduled jobs and units, and the directories root runs binaries from.
var sensitiveDestinations = []string{
	"/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/pam.d/", "/etc/security/",
	"/etc/cron", "/etc/anacrontab", "/etc/systemd/", "/usr/lib/systemd/", "/etc/init.d/", "/etc/rc.local",
	"/etc/profile", "/etc/environment", "/etc/ld.so.", "/etc/apt/", "/etc/paddock/", "/opt/paddock/", "/root/",
	"/boot/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/usr/lib/", "/etc/himmelblau/",
	"/etc/nsswitch.conf", "/etc/polkit-1/",
}

// RootEquivalentCommands returns the commands of a set that hand out root, sorted. A command does so on its own
// (catalog, wildcard or a glob in the binary path, a write to a sensitive destination), or in combination: a command
// that writes a path together with a command that runs that path (or a binary below a written directory) makes both
// root-equivalent, although each is harmless alone.
func RootEquivalentCommands(commands []string) []string {
	parsed := make([]command, len(commands))
	for i, c := range commands {
		parsed[i] = parse(c)
	}
	flagged := make([]bool, len(commands))
	for i, c := range parsed {
		flagged[i] = c.rootEquivalentAlone()
	}
	for w, writer := range parsed {
		for _, target := range writer.targets() {
			for x, exec := range parsed {
				if x != w && (exec.binary == target || strings.HasPrefix(exec.binary, strings.TrimSuffix(target, "/")+"/")) {
					flagged[w], flagged[x] = true, true
				}
			}
		}
	}
	var out []string
	for i, c := range commands {
		if flagged[i] {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// IsRootEquivalent reports whether a single command hands out root on its own.
func IsRootEquivalent(c string) bool { return parse(c).rootEquivalentAlone() }

type command struct {
	binary   string   // /usr path of the binary (glob characters kept)
	fields   []string // arguments
	wildcard bool     // no arguments (sudo: any arguments) or a glob in the arguments
}

func parse(c string) command {
	binary, args, _ := strings.Cut(c, " ")
	fields := strings.Fields(args)
	return command{binary: usrPath(binary), fields: fields, wildcard: len(fields) == 0 || strings.ContainsAny(args, "*?[")}
}

func (c command) rootEquivalentAlone() bool {
	if strings.ContainsAny(c.binary, "*?[") {
		return true
	}
	for _, e := range catalog {
		if e.binary == c.binary && (e.always || c.wildcard || (e.subcommand != "" && c.fields[0] == e.subcommand)) {
			return true
		}
	}
	for _, t := range c.targets() {
		for _, s := range sensitiveDestinations {
			if strings.HasPrefix(usrPath(t), s) {
				return true
			}
		}
	}
	return false
}

// targets are the paths a writer command modifies: every path argument of tee, chmod and chown, the last path
// argument of the copying tools; none for other commands.
func (c command) targets() []string {
	if !writers[c.binary] {
		return nil
	}
	var paths []string
	for _, f := range c.fields {
		if strings.HasPrefix(f, "/") {
			paths = append(paths, f)
		}
	}
	switch c.binary {
	case "/usr/bin/tee", "/usr/bin/chmod", "/usr/bin/chown":
		return paths
	}
	if len(paths) == 0 {
		return nil
	}
	return paths[len(paths)-1:]
}

// usrPath maps /bin/x and /sbin/x to /usr/bin/x and /usr/sbin/x; /usr/local/bin is not merged and stays as is.
func usrPath(p string) string {
	for _, dir := range []string{"/bin/", "/sbin/", "/lib/"} {
		if rest, ok := strings.CutPrefix(p, dir); ok {
			return "/usr" + dir + rest
		}
	}
	return p
}

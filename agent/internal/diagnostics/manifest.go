// Package diagnostics collects the diagnostics bundle of a device (ADR 0048 decision 2, plan M12 decision 8): the
// closed list of Entries — Paddock's own state, journals and managed configuration and a few system facts — as a
// tar.gz with manifest.json first. Nothing outside Entries ever enters the archive; secrets in the listed files are
// redacted before they do.
package diagnostics

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// Schema is the schema of manifest.json.
const Schema = "paddock.diagnostics.v1"

// Kinds of an entry: what Source names and how it is read.
const (
	// KindFile is a regular file at Source (a symlink is not followed).
	KindFile = "file"
	// KindGlob is every regular file of a directory whose name matches the pattern Source; Name is the archive
	// directory the files go to.
	KindGlob = "glob"
	// KindJournal is the journal of the units Source (a unit name or glob) of the last 7 days, newest first.
	KindJournal = "journal"
	// KindExec is the stdout of the read-only command line Source.
	KindExec = "exec"
	// KindHealth is the agent's health report.
	KindHealth = "health"
	// KindTPM is the presence of each device node of Source.
	KindTPM = "tpm"
	// KindLUKS is `cryptsetup luksDump` of every LUKS volume of the health report, one file per volume named
	// Name-<uuid>.txt.
	KindLUKS = "luks"
	// KindHealthz is the answer of GET <server_url>/healthz.
	KindHealthz = "healthz"
)

// Bounds of the archive (plan M12 decision 8): every journal is cut at MaxJournal, the content of all entries at
// MaxContent, so that the archive stays under MaxArchive and the sealed object under the 32 MiB of an upload.
const (
	MaxArchive = 24 << 20
	MaxContent = MaxArchive - 512<<10
	MaxJournal = 8 << 20
	maxConfig  = 1 << 20
	maxState   = 4 << 20
	maxFact    = 256 << 10
)

// Entry is one element of the closed content list.
type Entry struct {
	// Name is the path in the archive (the directory of a glob, the file prefix of KindLUKS).
	Name   string
	Kind   string
	Source string
	// MaxBytes is the cap of the entry's content (of each file of a glob or of KindLUKS).
	MaxBytes int64
	// Redact removes secrets and personal data from the content before it is archived; nil keeps it.
	Redact func([]byte) []byte
	// Exits are the non-zero exit codes of a KindExec command whose output is still the entry's content (df of a
	// missing mount point, dpkg -l of a package that is not installed).
	Exits []int
}

// Entries is the closed content list of ADR 0048 decision 2. Journals come last: the content is cut at MaxContent in
// this order, and the small state and configuration files matter most.
func Entries() []Entry {
	l := paths.Default
	return []Entry{
		{Name: "paddock/health.json", Kind: KindHealth, Source: "/run/paddock/agent.sock", MaxBytes: maxConfig},
		{Name: "paddock/state.json", Kind: KindFile, Source: l.State(), MaxBytes: maxState, Redact: redactState},
		{Name: "paddock/managed.json", Kind: KindFile, Source: l.Managed(), MaxBytes: maxState},
		{Name: "paddock/probation.json", Kind: KindFile, Source: l.Probation(), MaxBytes: maxConfig},
		{Name: "paddock/update-result.json", Kind: KindFile, Source: l.UpdateResult(), MaxBytes: maxConfig},
		{Name: "paddock/updates-result.json", Kind: KindFile, Source: l.UpdatesResult(), MaxBytes: maxConfig},
		{Name: "paddock/supervisor-upgrade-result.json", Kind: KindFile, Source: l.SupervisorUpgradeResult(), MaxBytes: maxConfig},
		{Name: "paddock/bundle-redacted.json", Kind: KindFile, Source: l.Bundle(), MaxBytes: maxState, Redact: redactBundle},
		{Name: "paddock/trust.json", Kind: KindFile, Source: l.Trust(), MaxBytes: maxConfig},
		{Name: "paddock/agent.yml", Kind: KindFile, Source: l.AgentConfig(), MaxBytes: maxConfig, Redact: redactURLCredentials},
		{Name: "systemd/status.txt", Kind: KindExec, MaxBytes: maxConfig, Redact: keepUnitState,
			Source: "systemctl show --property=" + strings.Join(UnitStateProperties, ",") + " paddock-supervisor.service " +
				"paddock-supervisor-upgrade.service paddock-encrypt-resume.service paddock-uninstall.service himmelblaud.service " +
				"himmelblaud-tasks.service orbit.service"},
		{Name: "systemd/failed-units.txt", Kind: KindExec, Source: "systemctl list-units --failed --no-pager --plain", MaxBytes: maxFact},
		{Name: "etc/sudoers", Kind: KindFile, Source: "/etc/sudoers", MaxBytes: maxConfig},
		{Name: "etc/sudoers.d", Kind: KindGlob, Source: "/etc/sudoers.d/*", MaxBytes: maxConfig},
		{Name: "etc/pam.d", Kind: KindGlob, Source: "/etc/pam.d/common-*", MaxBytes: maxConfig},
		{Name: "etc/nsswitch.conf", Kind: KindFile, Source: "/etc/nsswitch.conf", MaxBytes: maxConfig},
		{Name: "etc/himmelblau/himmelblau.conf", Kind: KindFile, Source: "/etc/himmelblau/himmelblau.conf", MaxBytes: maxConfig,
			Redact: RedactSecrets},
		{Name: "etc/apt/sources.list.d", Kind: KindGlob, Source: "/etc/apt/sources.list.d/paddock-*", MaxBytes: maxConfig},
		{Name: "etc/apt/preferences.d", Kind: KindGlob, Source: "/etc/apt/preferences.d/5*paddock*", MaxBytes: maxConfig},
		{Name: "etc/crypttab", Kind: KindFile, Source: "/etc/crypttab", MaxBytes: maxConfig, Redact: redactMountPasswords},
		{Name: "etc/fstab", Kind: KindFile, Source: "/etc/fstab", MaxBytes: maxConfig, Redact: redactMountPasswords},
		{Name: "system/os-release", Kind: KindFile, Source: "/usr/lib/os-release", MaxBytes: maxFact},
		{Name: "system/uname.txt", Kind: KindExec, Source: "uname -a", MaxBytes: maxFact},
		{Name: "system/timedatectl.txt", Kind: KindExec, Source: "timedatectl show", MaxBytes: maxFact},
		{Name: "system/df.txt", Kind: KindExec, Source: "df -h / /boot /boot/efi", MaxBytes: maxFact, Exits: []int{1}},
		{Name: "system/uptime.txt", Kind: KindExec, Source: "uptime -p", MaxBytes: maxFact},
		{Name: "system/lsblk.txt", Kind: KindExec, Source: "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT", MaxBytes: maxFact},
		{Name: "system/luksDump", Kind: KindLUKS, Source: "cryptsetup luksDump", MaxBytes: maxFact},
		{Name: "system/tpm.txt", Kind: KindTPM, Source: "/dev/tpm0 /dev/tpmrm0", MaxBytes: maxFact},
		{Name: "system/dpkg.txt", Kind: KindExec, Source: "dpkg -l paddock* himmelblau* fleet*", MaxBytes: maxConfig, Exits: []int{1}},
		{Name: "system/ip-link.txt", Kind: KindExec, Source: "ip -brief link", MaxBytes: maxFact, Redact: redactHardwareAddresses},
		{Name: "system/resolvectl.txt", Kind: KindExec, Source: "resolvectl status --no-pager", MaxBytes: maxFact},
		{Name: "system/apt-history.log", Kind: KindFile, Source: "/var/log/apt/history.log", MaxBytes: maxConfig, Redact: redactRequestedBy},
		{Name: "system/server-healthz.txt", Kind: KindHealthz, Source: "/healthz", MaxBytes: maxFact},
		// The supervisor runs the agent as its child: both write to the journal of paddock-supervisor.service, which
		// is the agent's log; the supervisor's own transient unit is its upgrade.
		{Name: "journal/paddockd.log", Kind: KindJournal, Source: "paddock-supervisor.service", MaxBytes: MaxJournal},
		{Name: "journal/paddock-supervisor.log", Kind: KindJournal, Source: "paddock-supervisor-upgrade.service", MaxBytes: MaxJournal},
		{Name: "journal/paddock-encrypt.log", Kind: KindJournal, Source: "paddock-encrypt*", MaxBytes: MaxJournal},
		{Name: "journal/paddock-uninstall.log", Kind: KindJournal, Source: "paddock-uninstall.service", MaxBytes: MaxJournal},
		{Name: "journal/himmelblaud.log", Kind: KindJournal, Source: "himmelblaud.service", MaxBytes: MaxJournal},
		{Name: "journal/himmelblaud-tasks.log", Kind: KindJournal, Source: "himmelblaud-tasks.service", MaxBytes: MaxJournal},
	}
}

// UnitStateProperties are the only unit properties systemd/status.txt holds (decision of 2026-11-05 on PDK-791):
// state and timestamps, never the unit's processes (their command lines, the CGroup tree) or journal lines, which
// the privacy document's "Never: process lists, other units' journals" excludes.
var UnitStateProperties = []string{
	"ActiveState", "SubState", "Result", "ExecMainStatus", "StateChangeTimestamp", "ActiveEnterTimestamp",
	"ActiveExitTimestamp", "InactiveEnterTimestamp", "ExecMainStartTimestamp", "ExecMainExitTimestamp",
}

// keepUnitState keeps the blank lines that separate the units and the lines <property>=<value> of
// UnitStateProperties; every other line is dropped, so that no output but these properties reaches the archive.
func keepUnitState(data []byte) []byte {
	var out bytes.Buffer
	for line := range strings.Lines(string(data)) {
		key, _, ok := strings.Cut(line, "=")
		if strings.TrimRight(line, "\n") == "" || ok && slices.Contains(UnitStateProperties, key) {
			out.WriteString(line)
		}
	}
	return out.Bytes()
}

// Redacted replaces a secret.
const Redacted = "<redacted>"

var secretLine = regexp.MustCompile(`(?i)secret|password|key`)

// RedactSecrets replaces the value of every line that matches (?i)secret|password|key with <redacted> (the whole
// line when it has no "=" or ":"), comments included: a commented-out secret is still one.
func RedactSecrets(data []byte) []byte {
	return mapLines(data, func(line string) string {
		if !secretLine.MatchString(line) {
			return line
		}
		if i := strings.IndexAny(line, "=:"); i >= 0 {
			return strings.TrimRight(line[:i+1], " \t") + " " + Redacted
		}
		return Redacted
	})
}

// redactState drops every identity-named field of state.json and the hash of the local administrator's shadow
// entry; a state that is not JSON is replaced, because it cannot be checked.
func redactState(data []byte) []byte {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return []byte(Redacted + "\n")
	}
	out, err := marshalIndent(dropFields(v))
	if err != nil {
		return []byte(Redacted + "\n")
	}
	return out
}

// marshalIndent renders v as indented JSON without HTML escaping, so that <redacted> stays literal like in the text
// files of the archive.
func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func dropFields(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "identity") || strings.Contains(lk, "shadow") {
				delete(t, k)
				continue
			}
			t[k] = dropFields(child)
		}
	case []any:
		for i := range t {
			t[i] = dropFields(t[i])
		}
	}
	return v
}

// urlCredentials runs to the last "@" before the path: url.Parse accepts an unescaped "@" in the password.
var urlCredentials = regexp.MustCompile(`://[^/\s]*@`)

// redactURLCredentials removes the user and password of URLs (a proxy URL of agent.yml may carry them).
func redactURLCredentials(data []byte) []byte {
	return urlCredentials.ReplaceAll(data, []byte("://"+Redacted+"@"))
}

// mountPassword is a password option of fstab or crypttab (CIFS mounts carry password=, pass= or pwd= inline);
// mount.cifs reads ",," as a comma inside the password.
var mountPassword = regexp.MustCompile(`(?i)\b(pass|password|pwd)=(?:[^,\s]|,,)*`)

// redactMountPasswords replaces the value of every password option of fstab and crypttab.
func redactMountPasswords(data []byte) []byte {
	return mountPassword.ReplaceAll(data, []byte("${1}="+Redacted))
}

var hardwareAddress = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(:[0-9a-f]{2}){5,19}\b`)

// redactHardwareAddresses removes link-layer addresses: the ADR keeps link states and no addresses.
func redactHardwareAddresses(data []byte) []byte {
	return hardwareAddress.ReplaceAll(data, []byte(Redacted))
}

// redactRequestedBy removes the user of every apt history record: the ADR keeps package operations without users.
func redactRequestedBy(data []byte) []byte {
	return mapLines(data, func(line string) string {
		if strings.HasPrefix(line, "Requested-By:") {
			return "Requested-By: " + Redacted
		}
		return line
	})
}

// mapLines applies fn to every line of data and keeps the line ends.
func mapLines(data []byte, fn func(string) string) []byte {
	var out bytes.Buffer
	r := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			body, nl := strings.CutSuffix(line, "\n")
			out.WriteString(fn(body))
			if nl {
				out.WriteByte('\n')
			}
		}
		if err != nil {
			return out.Bytes()
		}
	}
}

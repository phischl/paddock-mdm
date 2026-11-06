package backuprole

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// HostTarget is a volume target (local, SMB, NFS) as ./paddock backup-target apply renders it (plan M15 decision 20):
// the settings, the decrypted credentials of an SMB target and whether a platform administrator deleted it.
type HostTarget struct {
	ID          uuid.UUID
	Name        string
	Type        backupset.TargetType
	Settings    backupset.Settings
	Credentials backupset.Credentials
	Revision    int
	Deleted     bool
}

// ErrHostRender marks a target the host step cannot render safely; nothing is rendered then.
var ErrHostRender = errors.New("backup target apply: cannot render")

// VolumeName is the Compose volume of a target's revision and rendered mount. Docker never changes the options of an
// existing volume and a non-interactive Compose run keeps the old one, so every change of what is mounted must change
// the name: a new revision (a changed share or password) and a changed type, device or option without one (another
// PADDOCK_BACKUP_LOCAL_ROOT, a release that changes the default options). The host step removes the old volume.
//
// The fingerprint leaves the password out, because the name appears in the host step's output; a new password always
// raises the revision (app.BackupTargets.Update).
func VolumeName(id uuid.UUID, revision int, typ, device, publicOpts string) string {
	sum := sha256.Sum256([]byte(typ + "\x00" + device + "\x00" + publicOpts))
	return "backup-target-" + id.String() + "-r" + strconv.Itoa(revision) + "-" + hex.EncodeToString(sum[:6])
}

// Revisions is the revision list the rendered file records and ./paddock check --online compares with the database:
// "<id>=<revision>" of every live volume target, sorted by ID, or "none".
func Revisions(targets []HostTarget) string {
	var out []string
	for _, t := range targets {
		if !t.Deleted {
			out = append(out, t.ID.String()+"="+strconv.Itoa(t.Revision))
		}
	}
	if len(out) == 0 {
		return "none"
	}
	slices.Sort(out)
	return strings.Join(out, " ")
}

// cifsBase are the mount options of every SMB volume: files belong to the backup role's uid (plan M15 §6.7).
const cifsBase = "uid=999,gid=999,file_mode=0640,dir_mode=0750"

// WriteHostRender writes what the host step needs, one record per line, every free value base64-encoded because the
// host has no JSON parser (plan M15 decision 20):
//
//	compose <base64 of compose.backup-targets.yaml>   absent when no live volume target exists
//	mount <id> <revision> <base64 name> <volume>     a live target: the marker to write and the volume to keep
//	deleted <id> <base64 name>                       a deleted target: remove its volumes, then its row
//
// localRoot is PADDOCK_BACKUP_LOCAL_ROOT ("" means backupset.DefaultLocalRoot). An invalid root or a target that cannot
// be rendered safely fails the whole render and writes nothing.
func WriteHostRender(w io.Writer, now time.Time, localRoot string, targets []HostTarget) error {
	if localRoot == "" {
		localRoot = backupset.DefaultLocalRoot
	}
	if err := backupset.LocalRoot(localRoot); err != nil {
		return fmt.Errorf("%w: %w", ErrHostRender, err)
	}
	sorted := slices.Clone(targets)
	slices.SortFunc(sorted, func(a, b HostTarget) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	var lines []string
	var live []HostTarget
	for _, t := range sorted {
		if t.Deleted {
			lines = append(lines, "deleted "+t.ID.String()+" "+base64.StdEncoding.EncodeToString([]byte(t.Name)))
			continue
		}
		live = append(live, t)
	}
	if len(live) > 0 {
		vols, err := hostVolumes(localRoot, live)
		if err != nil {
			return err
		}
		var mounts []string
		for i, t := range live {
			mounts = append(mounts, "mount "+t.ID.String()+" "+strconv.Itoa(t.Revision)+" "+
				base64.StdEncoding.EncodeToString([]byte(t.Name))+" "+vols[i].name)
		}
		doc, err := renderCompose(now, live, vols)
		if err != nil {
			return err
		}
		lines = append(append([]string{"compose " + base64.StdEncoding.EncodeToString(doc)}, mounts...), lines...)
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}

// hostVolume is the Docker local volume of a live target; opts is publicOpts plus, for SMB, the password.
type hostVolume struct{ name, typ, device, publicOpts, opts string }

// hostVolumes renders the volume of every live target (plan M15 §6.7, amended by decisions-alpha9 item 35: the SMB
// login is in the volume's options, because Docker's local driver mounts with mount(2) and the kernel ignores
// mount.cifs's credentials=).
func hostVolumes(localRoot string, targets []HostTarget) ([]hostVolume, error) {
	var vols []hostVolume
	for _, t := range targets {
		var v hostVolume
		var err error
		switch t.Type {
		case backupset.TypeLocal:
			if err = backupset.LocalSubpath(t.Settings.Path); err == nil {
				v.typ, v.device, v.publicOpts = "none", filepath.Join(localRoot, t.Settings.Path), "bind"
			}
		case backupset.TypeSMB:
			v.typ, v.device = "cifs", "//"+t.Settings.Host+"/"+t.Settings.Share
			if t.Settings.Path != "" {
				v.device += "/" + t.Settings.Path
			}
			v.publicOpts, err = cifsOptions(t)
		case backupset.TypeNFS:
			v.typ, v.device = "nfs", ":"+path.Join(t.Settings.Export, t.Settings.Path)
			v.publicOpts = "addr=" + t.Settings.Host + "," + withDefault(t.Settings.Options, "vers=", "vers=4")
		default:
			err = fmt.Errorf("type %q is not a volume target", t.Type)
		}
		if err == nil && t.Type == backupset.TypeSMB {
			err = checkSMBPassword(t.Credentials.Password)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: target %q: %w", ErrHostRender, t.Name, err)
		}
		v.opts = v.publicOpts
		if t.Type == backupset.TypeSMB {
			v.opts += ",password=" + t.Credentials.Password
		}
		v.name = VolumeName(t.ID, t.Revision, v.typ, v.device, v.publicOpts)
		vols = append(vols, v)
	}
	return vols, nil
}

// renderCompose renders compose.backup-targets.yaml from the live targets and their volumes. The header records the
// revisions and, base64-encoded, every local device, which ./paddock up resolves again before each start.
func renderCompose(now time.Time, targets []HostTarget, vols []hostVolume) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Rendered by ./paddock backup-target apply on " + now.UTC().Format(time.RFC3339) +
		" from the database; do not edit.\n# Holds share passwords: mode 0600, never commit, copy or print it.\n")
	b.WriteString("# revisions: " + Revisions(targets) + "\n")
	for _, v := range vols {
		if v.typ == "none" {
			b.WriteString("# local: " + base64.StdEncoding.EncodeToString([]byte(v.device)) + "\n")
		}
	}
	b.WriteString("services:\n  paddock-backup:\n    volumes:\n")
	for i, v := range vols {
		b.WriteString("      - \"" + v.name + ":/backup-targets/" + targets[i].ID.String() + "\"\n")
	}
	b.WriteString("volumes:\n")
	for i, v := range vols {
		fields := [][2]string{{"type", v.typ}, {"device", v.device}, {"o", v.opts}}
		b.WriteString("  " + v.name + ":\n    driver: local\n    driver_opts:\n")
		for _, f := range fields {
			q, err := quote(f[1])
			if err != nil {
				return nil, fmt.Errorf("%w: target %q: %s %w", ErrHostRender, targets[i].Name, f[0], err)
			}
			b.WriteString("      " + f[0] + ": " + q + "\n")
		}
	}
	return []byte(b.String()), nil
}

// cifsOptions are the mount options of an SMB volume without the password, which hostVolumes appends last. A comma in
// the username or domain would start a new option (ip=, sec=) and is refused.
func cifsOptions(t HostTarget) (string, error) {
	user := t.Credentials.Username
	if user == "" {
		user = t.Settings.Username
	}
	if user == "" || t.Credentials.Password == "" {
		return "", errors.New("no SMB credentials")
	}
	if strings.Contains(user, ",") || strings.Contains(t.Settings.Domain, ",") {
		return "", errors.New("a comma in the SMB username or domain cannot be passed to the kernel")
	}
	opts := cifsBase + "," + withDefault(t.Settings.Options, "vers=", "vers=3") + ",username=" + user
	if t.Settings.Domain != "" {
		opts += ",domain=" + t.Settings.Domain
	}
	return opts, nil
}

// checkSMBPassword refuses an SMB password that backupset.ValidateTarget refuses since PDK-733 review 3 but that an
// older row may still hold: a comma or whitespace. Docker splits o on every comma first and turns a segment that names
// a mount flag (bind, ro, remount, …) into a flag of the mount (PDK-733 review 1), and Compose folds the o line at a
// space, so the password's tail would escape the redaction of ./paddock's output (review 3).
func checkSMBPassword(pw string) error {
	if !backupset.SMBPasswordPassable(pw) {
		return errors.New("the SMB password contains a comma or whitespace, which cannot be passed to the share's " +
			"mount; choose another password for the target in the portal")
	}
	return nil
}

// withDefault returns the administrator's options, with def added when none of them starts with prefix.
func withDefault(opts, prefix, def string) string {
	if opts == "" {
		return def
	}
	for o := range strings.SplitSeq(opts, ",") {
		if strings.HasPrefix(o, prefix) {
			return opts
		}
	}
	return def + "," + opts
}

// quote returns s as a YAML double-quoted scalar for Compose: backslash and quote escaped, and "$" doubled, because
// Compose interpolates every value and would read "backup$" as a variable (PDK-729 review). Control characters are
// refused: they have no business in a mount option and would need escapes the host cannot check.
func quote(s string) (string, error) {
	if strings.ContainsFunc(s, unicode.IsControl) {
		return "", errors.New("holds a control character")
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`)
	return `"` + r.Replace(s) + `"`, nil
}

// WriteMountMarker writes the marker of a volume target's revision into its mount below targetsDir (plan M15 decision
// 20; ./paddock backup-target apply runs it in a one-off paddock-backup container). The backup role reports the target
// mounted once the marker holds the current revision. It writes inside an os.Root on the mount and renames a temporary
// file, so a symlink planted on the share is never followed and a reader never sees half a marker.
func WriteMountMarker(targetsDir string, id uuid.UUID, revision int) error {
	m, err := openMount(filepath.Join(targetsDir, id.String()))
	if err != nil {
		return fmt.Errorf("backup target %s: %w", id, err)
	}
	defer func() { _ = m.Close() }()
	tmp := markerFile + ".tmp"
	if err := m.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("backup target %s: %w", id, err)
	}
	f, err := m.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return fmt.Errorf("backup target %s: %w", id, err)
	}
	_, err = f.WriteString(strconv.Itoa(revision) + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = m.Rename(tmp, markerFile)
	}
	if err != nil {
		_ = m.Remove(tmp)
		return fmt.Errorf("backup target %s: write marker: %w", id, err)
	}
	return nil
}

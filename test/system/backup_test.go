package system

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// Paths of the backup API (plan M15 §6.2).
const (
	backupKeyPath     = "/api/platform/v1/backup/key"
	backupTargetsPath = "/api/platform/v1/backup/targets"
	restorePlansPath  = "/api/platform/v1/backup/restore-plans"
)

// backupKinds are the kinds every backup run and every target's mirror covers; authentik is checked when the target
// reports it.
var backupKinds = []string{"postgres", "openbao", "fleet", "escrow"}

// backupWorld is the lab of the backup gates with its confirmed key and the targets every gate uses.
type backupWorld struct {
	l   *Lab
	s   *Stack // the organization administrator
	key string // the confirmed backup key's text, which the operator types at a restore
	// local and s3 are the targets every run mirrors to: BS2 restores from local's set, BS3 from s3's.
	local, s3 string
	// recovery is VM B's escrowed recovery key before the first loss.
	recovery string
}

// TestBackupGates runs the system gates of plan M15 §9, BS1–BS4, and BS5 (the lost local repository, A4 L1) in order on
// one lab-profile installation of the local bundle on the host (lab.go; `make bundle` first): VM A serves the SMB share
// and the NFS export of BS1, VM B is the device whose escrowed recovery key must survive the losses of BS2 and BS3 and
// whose bundle the point-in-time restore of BS4 changes. It runs only with PADDOCK_SYSTEM_BACKUP=1 (it needs sudo, the
// bundle and free host ports, and takes about two hours), alone, serial with every other stack test (it binds 80, 443,
// 445 and 2049 and destroys the lab twice): PADDOCK_SYSTEM_BACKUP=1 make system-test VM=all T='TestBackupGates'.
func TestBackupGates(t *testing.T) {
	if os.Getenv("PADDOCK_SYSTEM_BACKUP") != "1" {
		t.Skip("the backup gates run only with PADDOCK_SYSTEM_BACKUP=1 (part of every release regression; " +
			"prerequisites in test/system/README.md, section Backup and recovery)")
	}
	names := vms(t)
	if len(names) < 2 {
		t.Skip("the backup gates need both VMs (A serves the shares, B is the device): make system-test VM=all")
	}
	root, err := portal.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	// The portal helpers' API calls go to the lab, not to the development stack.
	t.Setenv("PADDOCK_TEST_ADMIN_URL", labAdminURL)
	t.Setenv("PADDOCK_TEST_AUTH_URL", labAuthURL)
	a, b := newVM(t, root, names[0]), newVM(t, root, names[1])
	a.Fresh()
	b.Fresh()
	l := newLab(t, root)
	w := &backupWorld{l: l, s: l.stack(t), key: ensureBackupKey(t, l)}
	w.local = createTarget(t, l, map[string]any{"name": "systest-local", "type": "local", "enabled": true,
		"local": map[string]string{"path": labLocalPath}}, "pending_host")
	ca, err := os.ReadFile(l.caFile())
	if err != nil {
		t.Fatal(err)
	}
	w.s3 = createTarget(t, l, map[string]any{"name": "systest-s3", "type": "s3", "enabled": true, "s3": map[string]string{
		"endpoint": s3Endpoint, "bucket": s3Bucket, "region": "us-east-1", "access_key": l.s3.AccessKey,
		"secret_key": l.s3.SecretKey, "ca_pem": string(ca),
	}}, "n/a")
	applyTargets(t, l)
	waitTarget(t, l, w.local, 5*time.Minute, "mounted", func(bt labTarget) bool { return bt.HostState == "mounted" })
	// Enrolled here, not in BS2: Install registers the deletes of the device's group, files and unit and the token
	// revoke on the t it gets, and BS3 and BS4 still need them.
	d := Install(t, w.s, b, debDir(w.s))

	t.Run("BS1_TestBackupShareTargets", func(t *testing.T) { a.Bind(t); gateBS1(t, w, a) })
	if !t.Run("BS2_TestRestoreFreshInstallFromUpload", func(t *testing.T) { d.Bind(t); gateBS2(t, w, d) }) {
		t.FailNow()
	}
	if !t.Run("BS3_TestRestoreFreshInstallFromTarget", func(t *testing.T) { d.Bind(t); gateBS3(t, w, d) }) {
		t.FailNow()
	}
	bs4 := t.Run("BS4_TestRestorePointInTime", func(t *testing.T) { d.Bind(t); gateBS4(t, w, d) })
	if !bs4 {
		t.Skip("BS4 failed; the lab state is undefined")
	}
	t.Run("BS5_TestRestoreBackupRepoFromTarget", func(t *testing.T) { gateBS5(t, w) })
}

// gateBS1 is gate BS1: an SMB and an NFS target served by VM A go from pending_host to mounted after `backup-target
// apply` and `up`, receive the set of `backup now`, and the SMB target turns unreachable within five minutes of smbd
// stopping, with PaddockBackupTargetUnreachable pending, while every service stays healthy.
func gateBS1(t *testing.T, w *backupWorld, vm *VM) {
	l := w.l
	sh := newShares(t, l, vm)
	smb := createTarget(t, l, map[string]any{"name": "systest-smb", "type": "smb", "enabled": true, "smb": map[string]string{
		"host": "127.0.0.1", "share": shareSMBName, "username": shareSMBUser, "password": sh.Password, "options": "vers=3.1.1",
	}}, "pending_host")
	nfs := createTarget(t, l, map[string]any{"name": "systest-nfs", "type": "nfs", "enabled": true, "nfs": map[string]string{
		"host": "127.0.0.1", "export": shareNFSDir, "options": "vers=4.2",
	}}, "pending_host")
	// Registered last, so it runs first: the shares go before the relay and the forwards that newShares removes.
	t.Cleanup(func() {
		sh.StartSMB()
		for _, id := range []string{smb, nfs} {
			l.platformCall(t, http.MethodDelete, backupTargetsPath+"/"+id, nil, http.StatusNoContent)
		}
		// apply drops the deleted targets from the overlay, up recreates the role without their volumes, and the second
		// apply removes the volumes, which are unused only then (deploy/bundle/README.md).
		applyTargets(t, l)
		l.paddock(t, "backup-target", "apply")
	})
	applyTargets(t, l)
	for _, id := range []string{smb, nfs} {
		waitTarget(t, l, id, 5*time.Minute, "mounted", func(bt labTarget) bool { return bt.HostState == "mounted" })
	}
	l.requireHealthy(t)

	since := backupNow(t, l)
	for _, id := range []string{smb, nfs} {
		waitMirrored(t, l, id, since)
	}
	for _, dir := range []string{shareSMBDir, shareNFSDir} {
		if !sh.HasSet(dir) {
			t.Fatalf("%s on %s holds no backup set with a manifest", dir, vm.Name)
		}
	}

	sh.StopSMB()
	stopped := time.Now()
	waitTarget(t, l, smb, 5*time.Minute, "unreachable", func(bt labTarget) bool { return bt.HostState == "unreachable" })
	t.Logf("the SMB target turned unreachable %s after smbd stopped", time.Since(stopped).Round(time.Second))
	Until(t, "PaddockBackupTargetUnreachable pending", 3*time.Minute, 10*time.Second, nil, func() bool {
		out, err := l.tryPaddock([]byte{}, "compose", "exec", "-T", "prometheus", "wget", "-qO-",
			"http://127.0.0.1:9090/api/v1/alerts")
		return err == nil && alertActive(out, "PaddockBackupTargetUnreachable", "systest-smb")
	})
	if bt := getTarget(t, l, nfs); bt.HostState != "mounted" {
		t.Fatalf("the NFS target is %s while only the SMB share stopped", bt.HostState)
	}
	l.requireHealthy(t)
}

// alertActive reports whether Prometheus' /api/v1/alerts answer holds alert for target, pending or firing.
func alertActive(body, alert, target string) bool {
	var res struct {
		Data struct {
			Alerts []struct {
				Labels map[string]string `json:"labels"`
				State  string            `json:"state"`
			} `json:"alerts"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &res) != nil {
		return false
	}
	for _, a := range res.Data.Alerts {
		if a.Labels["alertname"] == alert && a.Labels["target"] == target && (a.State == "pending" || a.State == "firing") {
			return true
		}
	}
	return false
}

// gateBS2 is gate BS2: VM B, enrolled into the lab, escrows its recovery key and header; after `backup now`, the set
// copied from the local target as a tarball restores the installation after `down --volumes` and `secrets`: the portal
// signs in, VM B checks in and applies a higher bundle version, the recovery key is the one before the loss and the
// header downloads.
func gateBS2(t *testing.T, w *backupWorld, d *Device) {
	l := w.l
	d.PrepareDisk(t)
	d.RebootWithPassphrase(t)
	d.AnswerDiskSetup(t, randomDigits(t, 8))
	d.WaitDisk(t, "compliant with escrows", 15*time.Minute, func(i diskInfo) bool {
		return i.state() == "compliant" && stored(i.RecoveryKeys) >= 1 && stored(i.Headers) >= 1
	})
	w.recovery, _ = revealDisk(t, d)

	before := d.bundleVersion()
	since := backupNow(t, l)
	waitMirrored(t, l, w.local, since)
	tarball := filepath.Join(l.work, "paddock-backup-set-"+since.UTC().Format("20060102T150405Z")+".tar")
	mustRun(t, "", nil, "sudo", "-n", "tar", "-C", filepath.Join(l.localRoot, labLocalPath), "-cf", tarball, "paddock-backup")

	loss := time.Now()
	l.paddock(t, "down", "--volumes")
	l.paddock(t, "secrets")
	l.restore(t, w.key, "--from", tarball)
	requireRestored(t, w, d, before, loss, "set")
}

// gateBS3 is gate BS3: as BS2, from the S3 target with the target file `backup-target export` wrote before the loss.
func gateBS3(t *testing.T, w *backupWorld, d *Device) {
	l := w.l
	before := d.bundleVersion()
	since := backupNow(t, l)
	waitMirrored(t, l, w.s3, since)
	file := filepath.Join(l.work, "systest-s3.target.json")
	l.paddock(t, "backup-target", "export", "systest-s3", file)

	loss := time.Now()
	l.paddock(t, "down", "--volumes")
	l.paddock(t, "secrets")
	l.restore(t, w.key, "--from-target-file", file)
	requireRestored(t, w, d, before, loss, "target")
}

// gateBS4 is gate BS4: a managed file created at T1 and a second at T2; a plan to T1 + 30 s, executed with
// `./paddock restore --plan`, leaves only the first, VM B applies a higher bundle version with it, the plan is completed
// and platform.restore_completed names the operator.
func gateBS4(t *testing.T, w *backupWorld, d *Device) {
	l := w.l
	backupNow(t, l)
	first := createManagedFile(t, w.s, d, "pitr-1")
	t1 := time.Now()
	// Far enough past T1 + 30 s that the second file's commit lies after the plan's point even with the clocks' seconds.
	time.Sleep(90 * time.Second)
	second := createManagedFile(t, w.s, d, "pitr-2")
	at := t1.Add(30 * time.Second).UTC().Truncate(time.Second)
	// Both stanzas' WAL must reach past the point, or the recovery would end before it.
	for _, db := range [][3]string{{"postgres", "postgres", "paddock"}, {"authentik-postgres", "authentik", "authentik"}} {
		l.psql(t, db[0], db[1], db[2], "select pg_switch_wal()")
		Until(t, db[0]+" archived past the plan's point", 3*time.Minute, 5*time.Second, nil, func() bool {
			out := l.psql(t, db[0], db[1], db[2], "select coalesce(extract(epoch from last_archived_time)::bigint, 0) from pg_stat_archiver")
			var sec int64
			_ = json.Unmarshal([]byte(out), &sec)
			return sec > at.Unix()
		})
	}

	res := l.platformCall(t, http.MethodPost, restorePlansPath, map[string]any{
		"kind": "point_in_time", "at": at.Format(time.RFC3339), "components": []string{"postgres", "openbao", "fleet", "escrow"},
		"confirmation": "restore",
	}, http.StatusCreated)
	var plan struct {
		ID          string `json:"id"`
		State       string `json:"state"`
		HostCommand string `json:"host_command"`
	}
	if err := json.Unmarshal(res.Body, &plan); err != nil || plan.State != "approved" || plan.HostCommand != "./paddock restore --plan "+plan.ID {
		t.Fatalf("restore plan %s: %v", res.Body, err)
	}
	before := d.bundleVersion()
	started := time.Now()
	l.restore(t, w.key, "--plan", plan.ID)

	l.requireHealthy(t)
	w.s.Call(t, http.MethodGet, "/api/v1/managed-files/"+first.id, nil, http.StatusOK)
	w.s.Call(t, http.MethodGet, "/api/v1/managed-files/"+second.id, nil, http.StatusNotFound)
	if err := json.Unmarshal(l.platformCall(t, http.MethodGet, restorePlansPath+"/"+plan.ID, nil, http.StatusOK).Body, &plan); err != nil ||
		plan.State != "completed" {
		t.Fatalf("plan %s after the restore: %s %v", plan.ID, plan.State, err)
	}
	d.WaitEvent(t, "device.bundle_applied", 10*time.Minute, func(p map[string]any) bool {
		v, _ := p["bundle_version"].(float64)
		return v > before
	})
	if out := d.Must("sudo cat " + first.path); out != strings.TrimSpace(first.content) {
		t.Fatalf("%s on the device: %q, want %q", first.path, out, first.content)
	}
	who := operator(t)
	l.waitAuditEvent(t, "platform.restore_completed", started, func(e labAuditEvent) bool {
		return e.Outcome == "success" && e.Params["plan_id"] == plan.ID && e.Display == who
	})
}

// classSetShrunk is the error class of a target the mirror leaves untouched because the local set lacks what it holds
// (backuprole.ClassSetShrunk; plan M15 amendment 2026-11-05, A3 step 2).
const classSetShrunk = "set_shrunk"

// gateBS5 is gate BS5 (plan M15 amendment 2026-11-05, A4 L1 and A5): after a mirrored round the local repository volume
// is lost while pgBackRest's state volumes stay. Every target keeps its copy unchanged and reports set_shrunk, with
// PaddockBackupTargetUnreachable pending (it fires after 30 minutes); `./paddock restore --only backup-repo --from
// systest-local` rebuilds the local repository from the local target, platform.restore_completed records it, and the
// next round succeeds on every target.
func gateBS5(t *testing.T, w *backupWorld) {
	l := w.l
	targets := map[string]string{"systest-local": w.local, "systest-s3": w.s3}
	since := backupNow(t, l)
	for _, id := range targets {
		waitMirrored(t, l, id, since)
	}

	// The backup role is the targets' only writer: with it stopped, the listings are those the loss must leave alone.
	l.paddock(t, "compose", "--profile", "paddock", "rm", "--stop", "--force", "pgbackrest", "pgbackrest-authentik",
		"paddock-backup")
	before := map[string]string{"systest-local": l.localListing(t), "systest-s3": l.s3.listing(t, l)}
	for name, list := range before {
		if strings.TrimSpace(list) == "" {
			t.Fatalf("the target %s holds nothing before the loss", name)
		}
	}
	mustRun(t, "", nil, "docker", "volume", "rm", labProject+"_backup-repo")
	l.paddockIn(t, []byte{}, "up")
	for name, id := range targets {
		waitTarget(t, l, id, 10*time.Minute, classSetShrunk, func(bt labTarget) bool { return bt.failedWith(classSetShrunk) })
		Until(t, "PaddockBackupTargetUnreachable pending for "+name, 3*time.Minute, 10*time.Second, nil, func() bool {
			out, err := l.tryPaddock([]byte{}, "compose", "exec", "-T", "prometheus", "wget", "-qO-",
				"http://127.0.0.1:9090/api/v1/alerts")
			return err == nil && alertActive(out, "PaddockBackupTargetUnreachable", name)
		})
	}
	after := map[string]string{"systest-local": l.localListing(t), "systest-s3": l.s3.listing(t, l)}
	for name := range targets {
		if diff := listingDiff(before[name], after[name]); len(diff) > 0 {
			t.Fatalf("the target %s changed after the local repository was lost:\n%s", name, strings.Join(diff, "\n"))
		}
	}

	started := time.Now()
	l.restore(t, "", "--only", "backup-repo", "--from", "systest-local")
	l.waitAuditEvent(t, "platform.restore_completed", started, func(e labAuditEvent) bool {
		return e.Outcome == "success" && e.Params["source"] == "target" && e.Params["plan_id"] == "" &&
			paramHas(e.Params, "components", "backup-repo")
	})
	since = backupNow(t, l)
	for name, id := range targets {
		waitMirrored(t, l, id, since)
		if bt := getTarget(t, l, id); !bt.failedWith("") {
			t.Fatalf("the target %s reports an error after the repository restore: %+v", name, bt.Status)
		}
	}
	l.requireHealthy(t)
}

// listingDiff compares two listings of a target, one object per line in any order, and returns the lines only before
// holds ("- …") and only after holds ("+ …"), sorted.
func listingDiff(before, after string) []string {
	count := map[string]int{}
	for _, line := range strings.Split(before, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			count[line]--
		}
	}
	for _, line := range strings.Split(after, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			count[line]++
		}
	}
	var diff []string
	for line, n := range count {
		for ; n < 0; n++ {
			diff = append(diff, "- "+line)
		}
		for ; n > 0; n-- {
			diff = append(diff, "+ "+line)
		}
	}
	sort.Strings(diff)
	return diff
}

// paramHas reports whether the audit event's param key is a list that holds value.
func paramHas(params map[string]any, key, value string) bool {
	list, _ := params[key].([]any)
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// localListing lists the local target's files (minus the backup role's host probe file, which the role rewrites) with size and modification time (root-owned, hence sudo).
func (l *Lab) localListing(t *testing.T) string {
	t.Helper()
	return mustRun(t, "", nil, "sudo", "-n", "find", filepath.Join(l.localRoot, labLocalPath), "-type", "f",
		"!", "-name", ".paddock-probe", "-printf", "%P %s %T@\n")
}

// managedFile is a managed file a gate created.
type managedFile struct{ id, path, content string }

// createManagedFile creates a managed file of d's group below the operator root that Install set (no step-up).
func createManagedFile(t *testing.T, s *Stack, d *Device, name string) managedFile {
	t.Helper()
	f := managedFile{path: d.managedPath(name), content: "managed " + name + " " + d.run + "\n"}
	f.id = s.ID(t, s.Call(t, http.MethodPost, "/api/v1/managed-files", map[string]any{
		"path": f.path, "content": f.content, "mode": "0640", "owner": "root", "group": "adm", "device_group_id": d.Group,
	}, http.StatusCreated))
	return f
}

// requireRestored checks a restored installation (BS2, BS3): every service healthy, both administrators sign in again,
// VM B applies a bundle above the version before the loss, its recovery key is the one escrowed before the first loss,
// its header downloads, and platform.restore_completed records the restore from source.
func requireRestored(t *testing.T, w *backupWorld, d *Device, before float64, loss time.Time, source string) {
	t.Helper()
	l := w.l
	l.requireHealthy(t)
	w.s.Login(t)
	l.platformCall(t, http.MethodGet, backupKeyPath, nil, http.StatusOK)
	d.WaitEvent(t, "device.bundle_applied", 10*time.Minute, func(p map[string]any) bool {
		v, _ := p["bundle_version"].(float64)
		return v > before
	})
	if key, _ := revealDisk(t, d); key != w.recovery {
		t.Fatal("the recovery key revealed after the restore differs from the one revealed before the loss")
	}
	l.waitAuditEvent(t, "platform.restore_completed", loss, func(e labAuditEvent) bool {
		return e.Outcome == "success" && e.Params["source"] == source && e.Params["plan_id"] == ""
	})
}

// revealDisk reveals d's escrowed recovery key and downloads its newest header after a step-up; an empty header fails t.
func revealDisk(t *testing.T, d *Device) (key string, header []byte) {
	t.Helper()
	body := map[string]any{"confirm_hostname": d.Must("hostname")}
	d.s.StepUp(t)
	var revealed struct {
		RecoveryKey string `json:"recovery_key"`
	}
	if err := json.Unmarshal(d.s.Call(t, http.MethodPost, "/api/v1/devices/"+d.ID+"/disk/recovery-key", body, http.StatusOK).Body,
		&revealed); err != nil || revealed.RecoveryKey == "" {
		t.Fatalf("recovery key of %s: %v", d.Name, err)
	}
	header = d.s.Call(t, http.MethodPost, "/api/v1/devices/"+d.ID+"/disk/header", body, http.StatusOK).Body
	if len(header) == 0 {
		t.Fatalf("the header download of %s is empty", d.Name)
	}
	return revealed.RecoveryKey, header
}

// ensureBackupKey confirms the lab's backup key and returns its text: on a lab upgraded from 0.1.0-alpha.8 the legacy
// key of its .secrets/backup_encryption_key, which the api imported as unconfirmed (plan M15 decision 9); on a fresh
// lab, which has no such file, a generated one.
func ensureBackupKey(t *testing.T, l *Lab) string {
	t.Helper()
	type key struct {
		KeyID     string `json:"key_id"`
		Key       string `json:"key"`
		Legacy    bool   `json:"legacy"`
		Positions []int  `json:"positions"`
	}
	var st struct{ Active, Pending *key }
	if err := json.Unmarshal(l.platformCall(t, http.MethodGet, backupKeyPath, nil, http.StatusOK).Body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Active != nil {
		t.Fatal("the fresh lab has an active backup key, whose text the gates do not know")
	}
	var k key
	switch {
	case st.Pending != nil && st.Pending.Legacy:
		text, err := os.ReadFile(filepath.Join(l.dir, ".secrets", "backup_encryption_key"))
		if err != nil {
			t.Fatal(err)
		}
		k, k.Key = *st.Pending, strings.TrimSpace(string(text))
	default:
		if st.Pending != nil {
			l.platformCall(t, http.MethodPost, backupKeyPath+"/"+st.Pending.KeyID+"/discard", nil, http.StatusOK)
		}
		if err := json.Unmarshal(l.platformCall(t, http.MethodPost, backupKeyPath, nil, http.StatusCreated).Body, &k); err != nil {
			t.Fatal(err)
		}
	}
	var answer strings.Builder
	for _, p := range k.Positions {
		if p < 1 || p > len(k.Key) {
			t.Fatalf("challenge position %d outside the key text of %d characters", p, len(k.Key))
		}
		answer.WriteByte(k.Key[p-1])
	}
	l.platformCall(t, http.MethodPost, backupKeyPath+"/"+k.KeyID+"/confirm", map[string]string{"answer": answer.String()},
		http.StatusOK)
	return k.Key
}

// labTarget is BackupTarget of the admin API, as far as the gates read it.
type labTarget struct {
	Name      string          `json:"name"`
	HostState string          `json:"host_state"`
	Status    []labKindStatus `json:"status"`
}

// labKindStatus is BackupTargetKindStatus of the admin API.
type labKindStatus struct {
	Kind          string     `json:"kind"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	LastError     *string    `json:"last_error"`
}

// failedWith reports whether the target has a status and every kind's status carries the error class; "" means none.
func (bt labTarget) failedWith(class string) bool {
	if len(bt.Status) == 0 {
		return false
	}
	for _, s := range bt.Status {
		got := ""
		if s.LastError != nil {
			got = *s.LastError
		}
		if got != class {
			return false
		}
	}
	return true
}

// createTarget creates a backup target, expects its host state and returns its ID.
func createTarget(t *testing.T, l *Lab, body map[string]any, hostState string) string {
	t.Helper()
	var created struct {
		ID        string `json:"id"`
		HostState string `json:"host_state"`
	}
	if err := json.Unmarshal(l.platformCall(t, http.MethodPost, backupTargetsPath, body, http.StatusCreated).Body, &created); err != nil ||
		created.ID == "" || created.HostState != hostState {
		t.Fatalf("created target %v: id %q, host state %q (want %s), %v", body["name"], created.ID, created.HostState, hostState, err)
	}
	return created.ID
}

func getTarget(t *testing.T, l *Lab, id string) labTarget {
	t.Helper()
	var bt labTarget
	if err := json.Unmarshal(l.platformCall(t, http.MethodGet, backupTargetsPath+"/"+id, nil, http.StatusOK).Body, &bt); err != nil {
		t.Fatal(err)
	}
	return bt
}

// waitTarget polls the target every 5 s until cond holds.
func waitTarget(t *testing.T, l *Lab, id string, timeout time.Duration, what string, cond func(labTarget) bool) labTarget {
	t.Helper()
	var bt labTarget
	Until(t, "backup target "+id+" "+what, timeout, 5*time.Second, nil, func() bool {
		bt = getTarget(t, l, id)
		return cond(bt)
	})
	return bt
}

// mirroredSince reports whether the target holds every kind's set of a run that succeeded at or after since.
func (bt labTarget) mirroredSince(since time.Time) bool {
	got := map[string]bool{}
	for _, s := range bt.Status {
		ok := s.LastSuccessAt != nil && !s.LastSuccessAt.Before(since)
		if s.Kind == "authentik" && !ok {
			return false
		}
		got[s.Kind] = ok
	}
	for _, k := range backupKinds {
		if !got[k] {
			return false
		}
	}
	return true
}

// waitMirrored waits up to ten minutes until the target holds the set of the run started at since.
func waitMirrored(t *testing.T, l *Lab, id string, since time.Time) {
	t.Helper()
	waitTarget(t, l, id, 10*time.Minute, "mirrored", func(bt labTarget) bool { return bt.mirroredSince(since) })
}

// backupNow runs `./paddock backup now --wait`, the host's path without the portal, and returns when it started.
func backupNow(t *testing.T, l *Lab) time.Time {
	t.Helper()
	since := time.Now().Add(-time.Second)
	l.paddockIn(t, []byte{}, "backup", "now", "--wait")
	return since
}

// applyTargets runs `./paddock backup-target apply` and `./paddock up`, the host step after a target change.
func applyTargets(t *testing.T, l *Lab) {
	t.Helper()
	l.paddockIn(t, []byte{}, "backup-target", "apply")
	l.paddockIn(t, []byte{}, "up")
}

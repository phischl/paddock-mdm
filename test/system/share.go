package system

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The storage servers of the backup gates (plan M15 §9): an SMB share and an NFS export on VM A, and an S3 store that
// outlives the lab's `./paddock down --volumes`. None needs a container image beyond the ones versions.env pins.

// Paths and names of VM A's share and export.
const (
	shareSMBDir  = "/srv/paddock-share/smb"
	shareNFSDir  = "/srv/paddock-share/nfs"
	shareSMBName = "paddock"
	shareSMBUser = "paddock-smb"
	// The VMs sit behind VirtualBox NAT, and a target names no port (backupset allows none), so the host reaches VM
	// A's 445 and 2049 through NAT forwards on these host ports and a relay on 127.0.0.1:445 and 127.0.0.1:2049.
	shareSMBForward = "14445"
	shareNFSForward = "12049"
	shareRelay      = "paddock-systest-share-relay"
)

// Shares is VM A serving the SMB share and the NFS export that the host mounts as backup targets.
type Shares struct {
	vm       *VM
	Password string // the SMB account's password
}

// shareRelayConf is the relay's Nginx configuration: plain TCP from the standard ports on the host's loopback to the
// NAT forwards of VM A.
const shareRelayConf = `worker_processes 1;
events {}
stream {
  server { listen 127.0.0.1:445; proxy_pass 127.0.0.1:` + shareSMBForward + `; }
  server { listen 127.0.0.1:2049; proxy_pass 127.0.0.1:` + shareNFSForward + `; }
}
`

// sambaShare is the share's section of smb.conf: every file belongs to the SMB account, so the backup role's writes as
// uid 999 on the host's side land as that account.
const sambaShare = `
[` + shareSMBName + `]
   path = ` + shareSMBDir + `
   read only = no
   valid users = ` + shareSMBUser + `
   force user = ` + shareSMBUser + `
`

// nfsExport exports the directory owned by uid 999 (the backup role) to any client; insecure, because the host's
// requests reach the guest from VirtualBox NAT's unprivileged source ports.
const nfsExport = shareNFSDir + " *(rw,sync,no_subtree_check,insecure)\n"

// newShares installs samba and nfs-kernel-server on vm (from the Ubuntu archive), creates the share and the export, and
// opens the host's path to them: the NAT forwards of vm and the relay on the host. Both are removed when the test ends.
func newShares(t *testing.T, l *Lab, vm *VM) *Shares {
	t.Helper()
	sh := &Shares{vm: vm, Password: randomToken(t)}
	vm.Must("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=600 samba nfs-kernel-server >/dev/null")
	vm.Must("id " + shareSMBUser + " >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin " + shareSMBUser)
	vm.Must("sudo install -d -o " + shareSMBUser + " -g " + shareSMBUser + " -m 0770 " + shareSMBDir +
		" && sudo install -d -o 999 -g 999 -m 0770 " + shareNFSDir)
	vm.MustIn([]byte(sh.Password+"\n"+sh.Password+"\n"), "sudo smbpasswd -s -a "+shareSMBUser+" >/dev/null")
	vm.MustIn([]byte(sambaShare), "sudo tee -a /etc/samba/smb.conf >/dev/null")
	vm.MustIn([]byte(nfsExport), "sudo mkdir -p /etc/exports.d && sudo tee /etc/exports.d/paddock-systest.exports >/dev/null")
	vm.Must("sudo systemctl restart smbd nfs-server && sudo exportfs -ra && systemctl is-active smbd nfs-server")

	ctx := context.Background()
	for _, rule := range []string{"paddock-systest-smb,tcp,127.0.0.1," + shareSMBForward + ",,445",
		"paddock-systest-nfs,tcp,127.0.0.1," + shareNFSForward + ",,2049"} {
		if out, err := run(ctx, "VBoxManage", "controlvm", vm.Name, "natpf1", rule); err != nil {
			t.Fatalf("NAT forward %s on %s: %v: %s", rule, vm.Name, err, out)
		}
		name := strings.SplitN(rule, ",", 2)[0]
		t.Cleanup(func() { _, _ = run(context.Background(), "VBoxManage", "controlvm", vm.Name, "natpf1", "delete", name) })
	}
	conf := filepath.Join(l.work, "share-relay.conf")
	if err := os.WriteFile(conf, []byte(shareRelayConf), 0o644); err != nil { //nolint:gosec // relay configuration
		t.Fatal(err)
	}
	_ = exec.Command("docker", "rm", "-f", shareRelay).Run()
	mustRun(t, "", nil, "docker", "run", "-d", "--name", shareRelay, "--network", "host",
		"-v", conf+":/etc/nginx/nginx.conf:ro", l.image(t, "NGINX_IMAGE"))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", shareRelay).Run() })
	return sh
}

// StopSMB stops smbd on the VM: the share becomes unreachable while the mount stays.
func (sh *Shares) StopSMB() { sh.vm.Must("sudo systemctl stop smbd") }

// StartSMB starts smbd again.
func (sh *Shares) StartSMB() { sh.vm.Must("sudo systemctl start smbd && systemctl is-active smbd") }

// HasSet reports whether the backup set's manifest is in dir on the VM (the set's root paddock-backup/).
func (sh *Shares) HasSet(dir string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := sh.vm.SSH(ctx, nil, "sudo test -s "+dir+"/paddock-backup/manifest.json")
	return err == nil
}

// The S3 store of gate BS3: RustFS behind an Nginx TLS front with the lab's throwaway CA, on a network of its own
// outside the lab's Compose project, so `./paddock down --volumes` leaves it and the set on it. A production-profile
// target needs https and a host name that is no private IP literal (backupset.Policy); the backup role reaches the
// front by its container name through the gates' Compose overlay.
const (
	s3Network  = "paddock-systest-s3"
	s3Front    = "paddock-systest-s3"
	s3RustFS   = "paddock-systest-rustfs"
	s3Bucket   = "paddock-systest"
	s3Endpoint = "https://" + s3Front
)

// s3Overlay attaches the backup role, whose one-off containers also fetch a set at a restore, to the S3 store's
// network. The list keeps cp in case Compose replaced the service's networks instead of merging them.
const s3Overlay = `# Backup system gates (test/system/share.go): the backup role reaches the gates' S3 store. Never shipped.
services:
  paddock-backup:
    networks: [cp, systest-s3]
networks:
  systest-s3:
    external: true
    name: ` + s3Network + `
`

// s3FrontConf terminates TLS for the S3 store and passes the bytes on, so the request's Host header, which the
// signature covers, reaches RustFS unchanged.
const s3FrontConf = `worker_processes 1;
events {}
stream {
  server {
    listen 443 ssl;
    ssl_certificate /tls/s3.crt;
    ssl_certificate_key /tls/s3.key;
    proxy_pass ` + s3RustFS + `:9000;
  }
}
`

// s3Store is the S3 store with its root credentials, which the gate's S3 target uses.
type s3Store struct {
	overlay              string // the Compose overlay file
	AccessKey, SecretKey string
}

// startS3Store starts the S3 store and creates its bucket; Lab.teardown removes it.
func startS3Store(t *testing.T, l *Lab) *s3Store {
	t.Helper()
	st := &s3Store{overlay: filepath.Join(l.work, "compose.systest-s3.yaml"), AccessKey: "systest" + l.run, SecretKey: randomToken(t)}
	st.remove()
	if err := os.WriteFile(st.overlay, []byte(s3Overlay), 0o644); err != nil { //nolint:gosec // Compose overlay
		t.Fatal(err)
	}
	conf := filepath.Join(l.work, "s3-front.conf")
	if err := os.WriteFile(conf, []byte(s3FrontConf), 0o644); err != nil { //nolint:gosec // proxy configuration
		t.Fatal(err)
	}
	mustRun(t, "", nil, "docker", "network", "create", s3Network)
	env := append(os.Environ(), "RUSTFS_ACCESS_KEY="+st.AccessKey, "RUSTFS_SECRET_KEY="+st.SecretKey,
		"AWS_ACCESS_KEY_ID="+st.AccessKey, "AWS_SECRET_ACCESS_KEY="+st.SecretKey)
	// The credentials travel in the environment of docker, never on its command line.
	mustRun(t, "", env, "docker", "run", "-d", "--name", s3RustFS, "--network", s3Network, "-e", "RUSTFS_ACCESS_KEY",
		"-e", "RUSTFS_SECRET_KEY", "-e", "RUSTFS_ADDRESS=:9000", "-e", "RUSTFS_CONSOLE_ENABLE=false",
		"-e", "RUSTFS_OBS_LOG_DIRECTORY=", l.image(t, "RUSTFS_IMAGE"))
	aws := l.image(t, "AWS_CLI_IMAGE")
	Until(t, "S3 store bucket "+s3Bucket, 2*time.Minute, 3*time.Second, nil, func() bool {
		cmd := exec.Command("docker", "run", "--rm", "--network", s3Network, "-e", "AWS_ACCESS_KEY_ID",
			"-e", "AWS_SECRET_ACCESS_KEY", "-e", "AWS_DEFAULT_REGION=us-east-1", "-e", "AWS_PAGER=", aws,
			"--endpoint-url", "http://"+s3RustFS+":9000", "s3api", "create-bucket", "--bucket", s3Bucket)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return err == nil || strings.Contains(string(out), "BucketAlreadyOwnedByYou")
	})
	mustRun(t, "", nil, "docker", "run", "-d", "--name", s3Front, "--network", s3Network,
		"-v", conf+":/etc/nginx/nginx.conf:ro", "-v", filepath.Join(l.work, "tls")+":/tls:ro", l.image(t, "NGINX_IMAGE"))
	return st
}

// listing lists the bucket's objects with size, ETag and modification time.
func (st *s3Store) listing(t *testing.T, l *Lab) string {
	t.Helper()
	// The credentials travel in the environment of docker, never on its command line.
	env := append(os.Environ(), "AWS_ACCESS_KEY_ID="+st.AccessKey, "AWS_SECRET_ACCESS_KEY="+st.SecretKey)
	return mustRun(t, "", env, "docker", "run", "--rm", "--network", s3Network, "-e", "AWS_ACCESS_KEY_ID",
		"-e", "AWS_SECRET_ACCESS_KEY", "-e", "AWS_DEFAULT_REGION=us-east-1", "-e", "AWS_PAGER=", l.image(t, "AWS_CLI_IMAGE"),
		"--endpoint-url", "http://"+s3RustFS+":9000", "s3api", "list-objects-v2", "--bucket", s3Bucket,
		"--query", "Contents[].[Key,Size,ETag,LastModified]", "--output", "text")
}

// remove removes the store's containers and network (a leftover of an earlier run too).
func (st *s3Store) remove() {
	_ = exec.Command("docker", "rm", "-f", "-v", s3Front, s3RustFS).Run()
	_ = exec.Command("docker", "network", "rm", s3Network).Run()
}

// writeLabTLS writes the throwaway CA (ca.crt) and the certificates of the lab's proxy (fullchain.pem, privkey.pem: the
// five names, as smoke-lab.sh issues them) and of the S3 store's front (s3.crt, s3.key) into dir.
func writeLabTLS(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Paddock backup gates CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER, 0o644)
	var names []string
	for _, n := range []string{"admin", "auth", "device", "bundles", "fleet"} {
		names = append(names, n+"."+labDomain)
	}
	for i, leaf := range []struct {
		names     []string
		cert, key string
	}{{names, "fullchain.pem", "privkey.pem"}, {[]string{s3Front}, "s3.crt", "s3.key"}} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: leaf.names[0]},
			DNSNames: leaf.names, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		writePEM(t, filepath.Join(dir, leaf.cert), "CERTIFICATE", der, 0o644)
		// Readable by the proxies' worker processes, which do not run as the file's owner; a throwaway key.
		writePEM(t, filepath.Join(dir, leaf.key), "PRIVATE KEY", keyDER, 0o644)
	}
}

func writePEM(t *testing.T, path, typ string, der []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode); err != nil {
		t.Fatal(fmt.Errorf("write %s: %w", path, err))
	}
}

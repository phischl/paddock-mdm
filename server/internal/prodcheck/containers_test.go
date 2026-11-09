package prodcheck_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

// shippedExceptions reads the exceptions file the bundle ships and tools/composelint checks.
func shippedExceptions(t *testing.T) prodcheck.HardeningExceptions {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "..", "deploy", "compose", "hardening-exceptions.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := prodcheck.ParseHardeningExceptions(f)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// authentikInspect is `docker inspect` of authentik-postgres, -server and -worker as PDK-825 started them on a scratch
// project (trimmed to the fields Docker prints for the matrix; CapAdd as Docker reports it, with the CAP_ prefix).
func authentikInspect(t *testing.T) []prodcheck.InspectedContainer {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "inspect-authentik.json"))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := prodcheck.ParseInspect(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 3 {
		t.Fatalf("fixture has %d containers, want 3", len(cs))
	}
	return cs
}

// hardened is a container that satisfies the matrix without any exception.
func hardened(service string) prodcheck.InspectedContainer {
	var c prodcheck.InspectedContainer
	c.Name = "/paddock-" + service + "-1"
	c.Config.Labels = map[string]string{"com.docker.compose.project": "paddock", "com.docker.compose.service": service}
	pids := int64(256)
	c.HostConfig.CapDrop = []string{"ALL"}
	c.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	c.HostConfig.PidsLimit = &pids
	c.HostConfig.Memory = 512 << 20
	c.HostConfig.IpcMode = "private"
	return c
}

func matrix(t *testing.T, cs ...prodcheck.InspectedContainer) prodcheck.Result {
	t.Helper()
	return prodcheck.CheckContainerMatrix(prodcheck.ContainerMatrix{Containers: cs, Exceptions: shippedExceptions(t)})
}

// TestContainerMatrixPassesHardenedAuthentik: the containers of the scratch run pass against the shipped exceptions file.
func TestContainerMatrixPassesHardenedAuthentik(t *testing.T) {
	r := matrix(t, authentikInspect(t)...)
	if !r.OK || r.Warn || r.Item != prodcheck.ContainerMatrixItem {
		t.Fatalf("hardened Authentik: %+v", r)
	}
}

// TestContainerMatrixFindings: every drift of CapAdd, CapDrop, SecurityOpt and the limits fails and names the container;
// a listed exception allows exactly its setting; the isolation settings fail even for a listed service.
func TestContainerMatrixFindings(t *testing.T) {
	cases := []struct {
		name    string
		service string
		mutate  func(c *prodcheck.InspectedContainer)
		want    string // empty: passes
	}{
		{"caddy with its one capability", "caddy", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.CapAdd = []string{"CAP_NET_BIND_SERVICE"}
			c.HostConfig.Memory = 0
		}, ""},
		{"caddy recreated with an added capability", "caddy", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.CapAdd = []string{"CAP_NET_BIND_SERVICE", "CAP_NET_RAW"}
		}, "paddock-caddy-1 (service caddy): CapAdd [NET_BIND_SERVICE NET_RAW], the matrix allows [NET_BIND_SERVICE]"},
		{"caddy without its capability", "caddy", func(c *prodcheck.InspectedContainer) {}, "paddock-caddy-1 (service caddy): CapAdd [], the matrix allows [NET_BIND_SERVICE]"},
		{"authentik keeps the default capabilities", "authentik-server", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.CapDrop = nil
		}, "paddock-authentik-server-1 (service authentik-server): CapDrop [] lacks ALL"},
		{"authentik drops only NET_RAW", "authentik-server", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.CapDrop = []string{"NET_RAW"}
		}, "paddock-authentik-server-1 (service authentik-server): CapDrop [NET_RAW] lacks ALL"},
		{"authentik may gain privileges", "authentik-worker", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.SecurityOpt = nil
		}, "paddock-authentik-worker-1 (service authentik-worker): SecurityOpt [] lacks no-new-privileges:true"},
		{"no-new-privileges=false", "authentik-worker", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.SecurityOpt = []string{"no-new-privileges=false"}
		}, "lacks no-new-privileges:true"},
		{"no-new-privileges spelled with =", "authentik-worker", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.SecurityOpt = []string{"no-new-privileges=true"}
		}, ""},
		{"a role adds a capability", "paddock-api", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.CapAdd = []string{"CAP_NET_RAW"}
		}, "paddock-paddock-api-1 (service paddock-api): CapAdd [NET_RAW], the matrix allows []"},
		{"unlimited pids", "authentik-server", func(c *prodcheck.InspectedContainer) {
			pids := int64(-1)
			c.HostConfig.PidsLimit = &pids
		}, "paddock-authentik-server-1 (service authentik-server): no pids limit"},
		{"no pids limit at all", "authentik-server", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.PidsLimit = nil
		}, "no pids limit"},
		{"no memory limit", "authentik-server", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.Memory = 0
		}, "paddock-authentik-server-1 (service authentik-server): no memory limit"},
		{"memory limit excepted (pending PDK-910)", "paddock-api", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.Memory = 0
		}, ""},
		{"openbao with its one capability", "openbao", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.CapAdd = []string{"CAP_IPC_LOCK"}
		}, ""},
		{"openbao back on Docker's default capabilities", "openbao", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.CapDrop = nil
			c.HostConfig.CapAdd = []string{"CAP_IPC_LOCK"}
		}, "paddock-openbao-1 (service openbao): CapDrop [] lacks ALL"},
		{"audit-rustfs without a memory limit", "audit-rustfs", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.Memory = 0
		}, "paddock-audit-rustfs-1 (service audit-rustfs): no memory limit"},
		{"rustfs may gain privileges", "rustfs", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.SecurityOpt = nil
		}, "(service rustfs)"},
		{"privileged even where listed", "openbao", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.CapAdd = []string{"CAP_IPC_LOCK"}
			c.HostConfig.Privileged = true
		}, "paddock-openbao-1 (service openbao): privileged (cannot be excepted)"},
		{"unconfined seccomp", "authentik-server", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.SecurityOpt = append(c.HostConfig.SecurityOpt, "seccomp=unconfined")
		}, "paddock-authentik-server-1 (service authentik-server): SecurityOpt seccomp=unconfined (cannot be excepted)"},
		{"unconfined AppArmor", "authentik-server", func(c *prodcheck.InspectedContainer) {
			c.HostConfig.SecurityOpt = append(c.HostConfig.SecurityOpt, "apparmor:unconfined")
		}, "SecurityOpt apparmor:unconfined (cannot be excepted)"},
		{"host PID namespace", "fleet", func(c *prodcheck.InspectedContainer) { c.HostConfig.PidMode = "host" }, "host PID namespace"},
		{"host IPC namespace", "fleet", func(c *prodcheck.InspectedContainer) { c.HostConfig.IpcMode = "host" }, "host IPC namespace"},
		{"a container without Compose labels", "", func(c *prodcheck.InspectedContainer) {
			c.Name = "/stray"
			c.Config.Labels = nil
			c.HostConfig.CapDrop = nil
		}, "stray (service stray): CapDrop [] lacks ALL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := hardened(tc.service)
			tc.mutate(&c)
			r := matrix(t, c)
			if tc.want == "" {
				if !r.OK {
					t.Fatalf("want PASS, got %+v", r)
				}
				return
			}
			if r.OK || !strings.Contains(r.Detail, tc.want) {
				t.Fatalf("want FAIL with %q, got %+v", tc.want, r)
			}
		})
	}
}

// TestContainerMatrixValkeyReference: valkey and fleet-redis add exactly CHOWN, SETUID, SETGID and DAC_READ_SEARCH
// (plan M12h amendment A10-5); one more or one fewer fails.
func TestContainerMatrixValkeyReference(t *testing.T) {
	reference := []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH", "CAP_SETGID", "CAP_SETUID"}
	e := shippedExceptions(t)
	for _, service := range []string{"valkey", "fleet-redis"} {
		got := e[service]["cap_add"].Value
		slices.Sort(got)
		if !slices.Equal(got, []string{"CHOWN", "DAC_READ_SEARCH", "SETGID", "SETUID"}) {
			t.Fatalf("%s: exceptions file lists cap_add %v, want the Valkey reference set", service, got)
		}
		for _, caps := range [][]string{reference, {"CHOWN", "SETUID", "SETGID", "DAC_READ_SEARCH"}} {
			c := hardened(service)
			c.HostConfig.CapAdd = caps
			if r := matrix(t, c); !r.OK {
				t.Fatalf("%s with %v: %+v", service, caps, r)
			}
		}
		for _, caps := range [][]string{reference[:3], append(slices.Clone(reference), "CAP_DAC_OVERRIDE")} {
			c := hardened(service)
			c.HostConfig.CapAdd = caps
			if r := matrix(t, c); r.OK || !strings.Contains(r.Detail, "the matrix allows [CHOWN DAC_READ_SEARCH SETGID SETUID]") {
				t.Fatalf("%s with %v: want FAIL, got %+v", service, caps, r)
			}
		}
	}
}

// TestContainerMatrixNoContainer: without a running container the item warns that it checked nothing.
func TestContainerMatrixNoContainer(t *testing.T) {
	r := matrix(t)
	if !r.OK || !r.Warn || !strings.Contains(r.Detail, "not checked") {
		t.Fatalf("no container: %+v", r)
	}
}

// TestContainerMatrixInRun: the item belongs to the checklist only when the online check passed the containers.
func TestContainerMatrixInRun(t *testing.T) {
	items := func(o prodcheck.Options) string {
		var out bytes.Buffer
		prodcheck.Write(&out, prodcheck.Run(context.Background(), prodcheck.Config{}, o))
		return out.String()
	}
	if out := items(prodcheck.Options{}); strings.Contains(out, prodcheck.ContainerMatrixItem) {
		t.Fatalf("offline:\n%s", out)
	}
	bad := hardened("caddy")
	m := &prodcheck.ContainerMatrix{Containers: []prodcheck.InspectedContainer{bad}, Exceptions: shippedExceptions(t)}
	if out := items(prodcheck.Options{Containers: m}); !strings.Contains(out, "FAIL  "+prodcheck.ContainerMatrixItem) ||
		!strings.Contains(out, "- paddock-caddy-1 (service caddy): CapAdd []") {
		t.Fatalf("online:\n%s", out)
	}
}

// TestParseInspectFullOutput: the parser reads the fields of a complete `docker inspect` object and ignores the rest.
func TestParseInspectFullOutput(t *testing.T) {
	full := []map[string]any{{
		"Id": "abc", "Name": "/p-x-1", "State": map[string]any{"Running": true},
		"Config":     map[string]any{"Image": "x", "Labels": map[string]string{"com.docker.compose.service": "x"}},
		"HostConfig": map[string]any{"CapAdd": nil, "CapDrop": []string{"ALL"}, "PidsLimit": nil, "Memory": 0, "Binds": []string{"/a:/b"}},
	}}
	b, _ := json.Marshal(full)
	cs, err := prodcheck.ParseInspect(bytes.NewReader(b))
	if err != nil || len(cs) != 1 || cs[0].Config.Labels["com.docker.compose.service"] != "x" || cs[0].HostConfig.PidsLimit != nil {
		t.Fatalf("%v %+v", err, cs)
	}
	if _, err := prodcheck.ParseInspect(strings.NewReader("not json")); err == nil {
		t.Fatal("invalid inspect output parsed")
	}
}

// TestParseHardeningExceptions: the schema rules of tools/composelint apply to the online check too.
func TestParseHardeningExceptions(t *testing.T) {
	bad := map[string]string{
		"unknown setting":       "services:\n  x:\n    read_only:\n      reason: r\n",
		"no reason":             "services:\n  x:\n    cap_drop:\n      reason: ''\n",
		"isolation":             "services:\n  x:\n    isolation:\n      reason: r\n",
		"cap_add without value": "services:\n  x:\n    cap_add:\n      reason: r\n",
		"value on cap_drop":     "services:\n  x:\n    cap_drop:\n      value: [ALL]\n      reason: r\n",
		"empty entry":           "services:\n  x: {}\n",
		"unknown top-level key": "service:\n  x:\n    cap_drop:\n      reason: r\n",
	}
	for name, doc := range bad {
		if _, err := prodcheck.ParseHardeningExceptions(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	e, err := prodcheck.ParseHardeningExceptions(strings.NewReader(""))
	if err != nil || e == nil || len(e) != 0 {
		t.Fatalf("empty file: %v %v", e, err)
	}
}

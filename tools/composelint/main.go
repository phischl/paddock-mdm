// Command composelint fails when a Compose service of any host's file set runs without the container hardening of
// ADR 0051 decision 4 (plan M12h decision 10): `cap_drop: [ALL]`, `security_opt: no-new-privileges:true`, a
// `pids_limit` and a memory limit (`mem_limit` or `deploy.resources.limits.memory`), and no `cap_add` entries. A
// service may deviate only where deploy/compose/hardening-exceptions.yaml lists it with the exact setting and a reason;
// an exception that no file set needs any more fails too, so the file shrinks as services are hardened. A service that
// runs privileged, in the host's PID or IPC namespace, or with an unconfined seccomp or AppArmor profile fails without
// any possible exception, because that voids the dropped capabilities.
//
// The file sets come from the variables of deploy/compose/scripts/lib.sh, read literally (the single source of truth
// of the Compose file sets): each host's base set and its set with every optional file, so that an optional file can
// neither add an unhardened service nor reset a setting unseen. Each set is rendered with
// `docker compose config --format json`, so YAML anchors, merges and overrides are resolved by Compose itself.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Settings a service is checked for; the keys of an exception.
const (
	settingCapDrop   = "cap_drop"
	settingNoNewPriv = "no_new_privileges"
	settingPidsLimit = "pids_limit"
	settingMemLimit  = "mem_limit"
	settingCapAdd    = "cap_add"
	// settingIsolation covers settings that undo the container boundary as a whole (privileged mode, the host's PID
	// or IPC namespace, an unconfined seccomp or AppArmor profile); no exception can allow it.
	settingIsolation = "isolation"
)

var settings = []string{settingCapDrop, settingNoNewPriv, settingPidsLimit, settingMemLimit, settingCapAdd}

// placeholderEnv satisfies the `${VAR:?}` variables of the production files; their values never affect hardening.
var placeholderEnv = map[string]string{
	"PADDOCK_INTERCONNECT_ADDR":    "192.0.2.1",
	"PADDOCK_CONTROLPLANE_ADDR":    "192.0.2.2",
	"PADDOCK_LAB_PROXY_ADDR":       "192.0.2.3",
	"PADDOCK_ADMIN_ALLOWED_CIDRS":  "192.0.2.0/24",
	"PADDOCK_EDGE_TRUSTED_PROXIES": "192.0.2.0/24",
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, dockerRender))
}

// hostSet is one Compose file set: a name for the report and the files relative to the Compose directory.
type hostSet struct {
	Name  string
	Files []string
}

// renderFunc renders a file set to the JSON of `docker compose config --format json`.
type renderFunc func(ctx context.Context, composeDir string, set hostSet) ([]byte, error)

func run(ctx context.Context, args []string, stdout, stderr io.Writer, render renderFunc) int {
	fs := flag.NewFlagSet("composelint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("compose-dir", "deploy/compose", "Compose directory with scripts/lib.sh")
	exceptionsPath := fs.String("exceptions", "", "exceptions file (default <compose-dir>/hardening-exceptions.yaml)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *exceptionsPath == "" {
		*exceptionsPath = filepath.Join(*dir, "hardening-exceptions.yaml")
	}
	sets, err := hostSets(filepath.Join(*dir, "scripts", "lib.sh"))
	if err != nil {
		fmt.Fprintln(stderr, "composelint:", err)
		return 2
	}
	exceptions, err := loadExceptions(*exceptionsPath)
	if err != nil {
		fmt.Fprintln(stderr, "composelint:", err)
		return 2
	}
	rendered := map[string]map[string]service{}
	for _, set := range sets {
		out, err := render(ctx, *dir, set)
		if err != nil {
			fmt.Fprintf(stderr, "composelint: render %s: %v\n", set.Name, err)
			return 2
		}
		services, err := parseServices(out)
		if err != nil {
			fmt.Fprintf(stderr, "composelint: %s: %v\n", set.Name, err)
			return 2
		}
		rendered[set.Name] = services
	}
	findings, checked := lint(sets, rendered, exceptions)
	if len(findings) > 0 {
		fmt.Fprintf(stderr, "composelint: %d finding(s); harden the service or list it in %s with the exact setting and a reason:\n", len(findings), *exceptionsPath)
		for _, f := range findings {
			fmt.Fprintln(stderr, "  "+f)
		}
		return 1
	}
	fmt.Fprintf(stdout, "composelint: %d services in %d file sets hardened or excepted\n", checked, len(sets))
	return 0
}

// libVar matches one `NAME="value"` line of lib.sh.
var libVar = regexp.MustCompile(`^([A-Z_a-z]+)="([^"$]*)"$`)

// hostSets reads the file set variables of lib.sh and returns each host's base set and its set with every optional
// file (the union compose_files can produce on that host).
func hostSets(libPath string) ([]hostSet, error) {
	f, err := os.Open(libPath) //nolint:gosec // G304: the operator names the Compose directory
	if err != nil {
		return nil, fmt.Errorf("read file sets: %w", err)
	}
	defer f.Close()
	vars := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := libVar.FindStringSubmatch(sc.Text()); m != nil {
			vars[m[1]] = strings.Fields(m[2])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read file sets: %w", err)
	}
	get := func(names ...string) ([]string, error) {
		var files []string
		for _, n := range names {
			v, ok := vars[n]
			if !ok || len(v) == 0 {
				return nil, fmt.Errorf("%s: no %s=\"…\" line", libPath, n)
			}
			for _, file := range v {
				if !slices.Contains(files, file) {
					files = append(files, file)
				}
			}
		}
		return files, nil
	}
	defs := []struct {
		name string
		vars []string
	}{
		{"dev", []string{"DEV_FILES"}},
		{"dev+backup", []string{"DEV_FILES", "DEV_BACKUP_FILES"}},
		{"controlplane", []string{"PROD_FILES_controlplane"}},
		{"controlplane+optional", []string{"PROD_FILES_controlplane", "AUTO_UNSEAL_FILES", "BACKUP_LEGACY_KEY_FILES"}},
		{"audit", []string{"PROD_FILES_audit"}},
		{"lab", []string{"PROD_FILES_lab"}},
		{"lab+optional", []string{"PROD_FILES_lab", "AUTO_UNSEAL_FILES", "LAB_BACKUP_FILES", "BACKUP_LEGACY_KEY_FILES"}},
	}
	sets := make([]hostSet, 0, len(defs))
	for _, d := range defs {
		files, err := get(d.vars...)
		if err != nil {
			return nil, err
		}
		sets = append(sets, hostSet{Name: d.name, Files: files})
	}
	return sets, nil
}

// exception is one excepted setting of a service.
type exception struct {
	Value  []string `yaml:"value"`
	Reason string   `yaml:"reason"`
}

// exceptionsFile is the schema of hardening-exceptions.yaml.
type exceptionsFile struct {
	Services map[string]map[string]exception `yaml:"services"`
}

func loadExceptions(path string) (map[string]map[string]exception, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the exceptions file
	if err != nil {
		return nil, fmt.Errorf("read exceptions: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var file exceptionsFile
	if err := dec.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var problems []string
	for name, entries := range file.Services {
		if len(entries) == 0 {
			problems = append(problems, fmt.Sprintf("%s: no excepted setting", name))
		}
		for setting, e := range entries {
			if setting == settingIsolation {
				problems = append(problems, fmt.Sprintf("%s.%s: cannot be excepted", name, setting))
				continue
			}
			if !slices.Contains(settings, setting) {
				problems = append(problems, fmt.Sprintf("%s: unknown setting %q (one of %s)", name, setting, strings.Join(settings, ", ")))
				continue
			}
			if strings.TrimSpace(e.Reason) == "" {
				problems = append(problems, fmt.Sprintf("%s.%s: no reason", name, setting))
			}
			if setting == settingCapAdd && len(e.Value) == 0 {
				problems = append(problems, fmt.Sprintf("%s.%s: value must list the exact capabilities", name, setting))
			}
			if setting != settingCapAdd && e.Value != nil {
				problems = append(problems, fmt.Sprintf("%s.%s: only cap_add takes a value", name, setting))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%s: %s", path, strings.Join(problems, "; "))
	}
	return file.Services, nil
}

// service holds the rendered settings composelint checks.
type service struct {
	CapDrop     []string        `json:"cap_drop"`
	CapAdd      []string        `json:"cap_add"`
	SecurityOpt []string        `json:"security_opt"`
	Privileged  bool            `json:"privileged"`
	Pid         string          `json:"pid"`
	Ipc         string          `json:"ipc"`
	PidsLimit   json.RawMessage `json:"pids_limit"`
	MemLimit    json.RawMessage `json:"mem_limit"`
	Deploy      struct {
		Resources struct {
			Limits struct {
				Memory json.RawMessage `json:"memory"`
			} `json:"limits"`
		} `json:"resources"`
	} `json:"deploy"`
}

func parseServices(out []byte) (map[string]service, error) {
	var cfg struct {
		Services map[string]service `json:"services"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, fmt.Errorf("parse rendered configuration: %w", err)
	}
	if len(cfg.Services) == 0 {
		return nil, errors.New("rendered configuration has no services")
	}
	return cfg.Services, nil
}

// positive reports whether a rendered limit is set and above zero (Compose renders sizes as byte strings).
func positive(raw json.RawMessage) bool {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || s == "null" {
		return false
	}
	n, err := strconv.ParseFloat(s, 64)
	return err == nil && n > 0
}

// normCaps returns the capabilities sorted, upper-case and without the CAP_ prefix.
func normCaps(caps []string) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_"))
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// violations returns the settings a service lacks, keyed by setting, with the observed value for the report.
func violations(s service) map[string]string {
	v := map[string]string{}
	if !slices.ContainsFunc(s.CapDrop, func(c string) bool { return normCaps([]string{c})[0] == "ALL" }) {
		v[settingCapDrop] = fmt.Sprintf("cap_drop %v lacks ALL", s.CapDrop)
	}
	if !slices.Contains(s.SecurityOpt, "no-new-privileges:true") && !slices.Contains(s.SecurityOpt, "no-new-privileges") {
		v[settingNoNewPriv] = "security_opt lacks no-new-privileges:true"
	}
	if !positive(s.PidsLimit) {
		v[settingPidsLimit] = "no pids_limit"
	}
	if !positive(s.MemLimit) && !positive(s.Deploy.Resources.Limits.Memory) {
		v[settingMemLimit] = "no mem_limit or deploy.resources.limits.memory"
	}
	if len(s.CapAdd) > 0 {
		v[settingCapAdd] = fmt.Sprintf("cap_add %v", normCaps(s.CapAdd))
	}
	var isolation []string
	if s.Privileged {
		isolation = append(isolation, "privileged: true")
	}
	if s.Pid == "host" {
		isolation = append(isolation, "pid: host")
	}
	if s.Ipc == "host" {
		isolation = append(isolation, "ipc: host")
	}
	for _, opt := range s.SecurityOpt {
		switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(opt)), "=", ":") {
		case "seccomp:unconfined", "apparmor:unconfined":
			isolation = append(isolation, "security_opt "+opt)
		}
	}
	if len(isolation) > 0 {
		v[settingIsolation] = strings.Join(isolation, ", ") + " (cannot be excepted)"
	}
	return v
}

// lint checks every service of every set against the exceptions and returns the findings, one per service and
// problem with the file sets that show it, and the number of distinct services checked.
func lint(sets []hostSet, rendered map[string]map[string]service, exceptions map[string]map[string]exception) ([]string, int) {
	inSets := map[string][]string{}
	// needed records which exceptions some set uses, so that the stale ones are found.
	needed := map[string]map[string]bool{}
	seen := map[string]bool{}
	for _, set := range sets {
		for name, svc := range rendered[set.Name] {
			seen[name] = true
			v := violations(svc)
			if msg, bad := v[settingIsolation]; bad {
				key := name + ": " + msg
				inSets[key] = append(inSets[key], set.Name)
			}
			for _, setting := range settings {
				msg, bad := v[setting]
				if !bad {
					continue
				}
				e, excepted := exceptions[name][setting]
				switch {
				case !excepted:
					key := name + ": " + msg
					inSets[key] = append(inSets[key], set.Name)
				case setting == settingCapAdd && !slices.Equal(normCaps(e.Value), normCaps(svc.CapAdd)):
					key := fmt.Sprintf("%s: %s differs from the exception %v", name, msg, normCaps(e.Value))
					inSets[key] = append(inSets[key], set.Name)
				default:
					if needed[name] == nil {
						needed[name] = map[string]bool{}
					}
					needed[name][setting] = true
				}
			}
		}
	}
	findings := make([]string, 0, len(inSets))
	for key, names := range inSets {
		findings = append(findings, fmt.Sprintf("%s (%s)", key, strings.Join(names, ", ")))
	}
	sort.Strings(findings)
	var stale []string
	for name, entries := range exceptions {
		if !seen[name] {
			stale = append(stale, fmt.Sprintf("exceptions: %s is in no file set; remove it", name))
			continue
		}
		for setting := range entries {
			if !needed[name][setting] {
				stale = append(stale, fmt.Sprintf("exceptions: %s.%s is no longer needed; remove it", name, setting))
			}
		}
	}
	sort.Strings(stale)
	return append(findings, stale...), len(seen)
}

// dockerRender renders a set with every profile, against versions.env only, so a host's .env cannot change the result.
func dockerRender(ctx context.Context, composeDir string, set hostSet) ([]byte, error) {
	args := []string{"compose", "--project-directory", composeDir, "-p", "composelint", "--env-file", filepath.Join(composeDir, "versions.env")}
	for _, f := range set.Files {
		args = append(args, "-f", filepath.Join(composeDir, f))
	}
	args = append(args, "--profile", "*", "config", "--format", "json")
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: fixed binary, file names from lib.sh
	cmd.Env = os.Environ()
	for k, v := range placeholderEnv {
		if os.Getenv(k) == "" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker compose config: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

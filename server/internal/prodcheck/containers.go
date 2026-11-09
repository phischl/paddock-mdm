package prodcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ContainerMatrixItem is the online item that compares the running containers with the hardening matrix (plan M12h
// decision 10, ADR 0051 decision 4).
const ContainerMatrixItem = "containers: capabilities and security options match the matrix"

// Settings of the hardening matrix: the keys of an entry in hardening-exceptions.yaml, the same as tools/composelint
// checks in the Compose files.
const (
	hardeningCapDrop   = "cap_drop"
	hardeningNoNewPriv = "no_new_privileges"
	hardeningPidsLimit = "pids_limit"
	hardeningMemLimit  = "mem_limit"
	hardeningCapAdd    = "cap_add"
	// hardeningIsolation covers privileged mode, the host's PID or IPC namespace and an unconfined seccomp or AppArmor
	// profile; no exception can allow it.
	hardeningIsolation = "isolation"
)

var hardeningSettings = []string{hardeningCapDrop, hardeningNoNewPriv, hardeningPidsLimit, hardeningMemLimit, hardeningCapAdd}

// HardeningException is one excepted setting of a service: the reason and, for cap_add, the exact capabilities.
type HardeningException struct {
	Value  []string `yaml:"value"`
	Reason string   `yaml:"reason"`
}

// HardeningExceptions maps a Compose service to its excepted settings (deploy/compose/hardening-exceptions.yaml).
type HardeningExceptions map[string]map[string]HardeningException

// ParseHardeningExceptions reads hardening-exceptions.yaml with the schema rules of tools/composelint: known settings
// only, a reason for each, a value for cap_add only, and never the isolation setting.
func ParseHardeningExceptions(r io.Reader) (HardeningExceptions, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read hardening exceptions: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var file struct {
		Services HardeningExceptions `yaml:"services"`
	}
	if err := dec.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse hardening exceptions: %w", err)
	}
	var problems []string
	for name, entries := range file.Services {
		if len(entries) == 0 {
			problems = append(problems, name+": no excepted setting")
		}
		for setting, e := range entries {
			switch {
			case setting == hardeningIsolation:
				problems = append(problems, fmt.Sprintf("%s.%s: cannot be excepted", name, setting))
			case !slices.Contains(hardeningSettings, setting):
				problems = append(problems, fmt.Sprintf("%s: unknown setting %q", name, setting))
			case strings.TrimSpace(e.Reason) == "":
				problems = append(problems, fmt.Sprintf("%s.%s: no reason", name, setting))
			case setting == hardeningCapAdd && len(e.Value) == 0:
				problems = append(problems, fmt.Sprintf("%s.%s: value must list the exact capabilities", name, setting))
			case setting != hardeningCapAdd && e.Value != nil:
				problems = append(problems, fmt.Sprintf("%s.%s: only cap_add takes a value", name, setting))
			}
		}
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return nil, fmt.Errorf("parse hardening exceptions: %s", strings.Join(problems, "; "))
	}
	if file.Services == nil {
		file.Services = HardeningExceptions{}
	}
	return file.Services, nil
}

// InspectedContainer is the part of `docker inspect` the matrix reads.
type InspectedContainer struct {
	Name   string `json:"Name"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		CapAdd      []string `json:"CapAdd"`
		CapDrop     []string `json:"CapDrop"`
		SecurityOpt []string `json:"SecurityOpt"`
		Privileged  bool     `json:"Privileged"`
		PidMode     string   `json:"PidMode"`
		IpcMode     string   `json:"IpcMode"`
		// PidsLimit is null, 0 or -1 without a limit.
		PidsLimit *int64 `json:"PidsLimit"`
		Memory    int64  `json:"Memory"`
	} `json:"HostConfig"`
}

// ParseInspect reads the JSON array `docker inspect <container>...` prints.
func ParseInspect(r io.Reader) ([]InspectedContainer, error) {
	var cs []InspectedContainer
	if err := json.NewDecoder(r).Decode(&cs); err != nil {
		return nil, fmt.Errorf("parse docker inspect: %w", err)
	}
	return cs, nil
}

// ContainerMatrix is the input of the online item: the running containers of the project and the exceptions file.
type ContainerMatrix struct {
	Containers []InspectedContainer
	Exceptions HardeningExceptions
}

// CheckContainerMatrix compares every container with the matrix: each drops ALL capabilities, sets no-new-privileges,
// has a pids and a memory limit and adds no capability, unless the exceptions list its service with that setting; a
// listed cap_add must match exactly. Privileged mode, the host's PID or IPC namespace and an unconfined seccomp or
// AppArmor profile always fail. A Compose edit or a hand-made container that drifts from the matrix shows here even
// when the files still pass `make lint-compose`.
func CheckContainerMatrix(m ContainerMatrix) Result {
	if len(m.Containers) == 0 {
		return Result{Item: ContainerMatrixItem, OK: true, Warn: true, Detail: "not checked: no running container of the project"}
	}
	var f []string
	for _, c := range m.Containers {
		f = append(f, containerFindings(c, m.Exceptions)...)
	}
	return result(ContainerMatrixItem, f)
}

func containerFindings(c InspectedContainer, exceptions HardeningExceptions) []string {
	name := strings.TrimPrefix(c.Name, "/")
	service := c.Config.Labels["com.docker.compose.service"]
	if service == "" {
		service = name
	}
	h := c.HostConfig
	excepted := func(setting string) bool {
		_, ok := exceptions[service][setting]
		return ok
	}
	label := fmt.Sprintf("%s (service %s)", name, service)
	var f []string
	if !slices.Contains(normalizeCaps(h.CapDrop), "ALL") && !excepted(hardeningCapDrop) {
		f = append(f, fmt.Sprintf("%s: CapDrop %v lacks ALL", label, normalizeCaps(h.CapDrop)))
	}
	if !hasNoNewPrivileges(h.SecurityOpt) && !excepted(hardeningNoNewPriv) {
		f = append(f, fmt.Sprintf("%s: SecurityOpt %v lacks no-new-privileges:true", label, h.SecurityOpt))
	}
	if (h.PidsLimit == nil || *h.PidsLimit <= 0) && !excepted(hardeningPidsLimit) {
		f = append(f, label+": no pids limit")
	}
	if h.Memory <= 0 && !excepted(hardeningMemLimit) {
		f = append(f, label+": no memory limit")
	}
	want := []string{}
	if e, ok := exceptions[service][hardeningCapAdd]; ok {
		want = normalizeCaps(e.Value)
	}
	if got := normalizeCaps(h.CapAdd); !slices.Equal(got, want) {
		f = append(f, fmt.Sprintf("%s: CapAdd %v, the matrix allows %v", label, got, want))
	}
	if h.Privileged {
		f = append(f, label+": privileged (cannot be excepted)")
	}
	if h.PidMode == "host" {
		f = append(f, label+": host PID namespace (cannot be excepted)")
	}
	if h.IpcMode == "host" {
		f = append(f, label+": host IPC namespace (cannot be excepted)")
	}
	for _, opt := range h.SecurityOpt {
		switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(opt)), "=", ":") {
		case "seccomp:unconfined", "apparmor:unconfined":
			f = append(f, fmt.Sprintf("%s: SecurityOpt %s (cannot be excepted)", label, opt))
		}
	}
	return f
}

// hasNoNewPrivileges accepts the spellings Docker and Compose use for the option.
func hasNoNewPrivileges(opts []string) bool {
	return slices.ContainsFunc(opts, func(o string) bool {
		switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(o)), "=", ":") {
		case "no-new-privileges", "no-new-privileges:true":
			return true
		}
		return false
	})
}

// normalizeCaps returns the capabilities sorted, upper-case and without the CAP_ prefix Docker adds in its inspect
// output, so that they compare with the names of the Compose files.
func normalizeCaps(caps []string) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_"))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

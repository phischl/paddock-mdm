package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
)

func TestParseAdmin(t *testing.T) {
	for _, c := range []struct {
		args []string
		want adminCommand
	}{
		{[]string{"bump-bundle-seq", "--by", "1000000"}, adminCommand{name: "bump-bundle-seq", by: 1000000}},
		{[]string{"bump-bundle-seq", "--by=1"}, adminCommand{name: "bump-bundle-seq", by: 1}},
		{[]string{"bump-bundle-seq", "--by", "1000000000"}, adminCommand{name: "bump-bundle-seq", by: 1000000000}},
		{[]string{"raise-bundle-seq", "--at-least", "2000003"}, adminCommand{name: "raise-bundle-seq", atLeast: 2000003}},
		{[]string{"raise-bundle-seq", "--at-least=1"}, adminCommand{name: "raise-bundle-seq", atLeast: 1}},
		{[]string{"raise-bundle-seq", "--at-least", "1000000000000"}, adminCommand{name: "raise-bundle-seq", atLeast: 1000000000000}},
		{[]string{"recompile", "--all"}, adminCommand{name: "recompile"}},
		{[]string{"rebuild-cache"}, adminCommand{name: "rebuild-cache"}},
		{[]string{"security-review"}, adminCommand{name: "security-review"}},
		{[]string{"end-sessions"}, adminCommand{name: "end-sessions"}},
		{[]string{"allowlist", "show"}, adminCommand{name: "allowlist", sub: "show"}},
		{[]string{"allowlist", "disable"}, adminCommand{name: "allowlist", sub: "disable"}},
		{[]string{"allowlist", "add", "--cidr", "203.0.113.0/24", "--label", "host"}, adminCommand{name: "allowlist", sub: "add", cidr: "203.0.113.0/24", label: "host"}},
		{[]string{"allowlist", "add", "--label=office vpn", "--cidr=2001:db8::/32"}, adminCommand{name: "allowlist", sub: "add", cidr: "2001:db8::/32", label: "office vpn"}},
		{[]string{"agent-release", "--version", "1.2.0", "--dir", "/release"}, adminCommand{name: "agent-release", version: "1.2.0", dir: "/release"}},
		{[]string{"agent-release", "--dir=/r", "--version=0.1.0-alpha.1"}, adminCommand{name: "agent-release", version: "0.1.0-alpha.1", dir: "/r"}},
		{[]string{"agent-rollout", "--version", "1.2.0"}, adminCommand{name: "agent-rollout", version: "1.2.0"}},
		{[]string{"agent-rollout", "--version=1.2.0", "--waves", "1, 10,50,100", "--min-wave-minutes", "90",
			"--failure-threshold-percent", "5", "--failure-threshold-min=2"}, adminCommand{name: "agent-rollout", version: "1.2.0",
			rollout: app.RolloutOptions{Waves: []int{1, 10, 50, 100}, MinWaveMinutes: ptr(90), FailureThresholdPercent: ptr(5),
				FailureThresholdMin: ptr(2)}}},
		{[]string{"agent-rollout", "--version", "1.2.0", "--waves", "50,10"}, adminCommand{name: "agent-rollout", version: "1.2.0",
			rollout: app.RolloutOptions{Waves: []int{50, 10}}}},
		{[]string{"agent-rollout-halt", "--version", "0.1.0-alpha.6"}, adminCommand{name: "agent-rollout-halt", version: "0.1.0-alpha.6"}},
		{[]string{"agent-rollout-resume", "--version=0.1.0-alpha.6"}, adminCommand{name: "agent-rollout-resume", version: "0.1.0-alpha.6"}},
		{[]string{"auto-unseal", "show"}, adminCommand{name: "auto-unseal", sub: "show"}},
		{[]string{"auto-unseal", "verify"}, adminCommand{name: "auto-unseal", sub: "verify"}},
		{[]string{"auto-unseal", "disable"}, adminCommand{name: "auto-unseal", sub: "disable"}},
		{[]string{"upgrade-check", "--target-version", "0.1.0-alpha.9"}, adminCommand{name: "upgrade-check", version: "0.1.0-alpha.9"}},
		{[]string{"upgrade-check", "--json", "--target-version=0.1.0-alpha.9"}, adminCommand{name: "upgrade-check", version: "0.1.0-alpha.9", json: true}},
	} {
		got, err := parseAdmin(c.args)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseAdmin(%q) = %+v, %v; want %+v", c.args, got, err, c.want)
		}
	}
	for _, args := range [][]string{
		nil, {"unknown"}, {"bump-bundle-seq"}, {"bump-bundle-seq", "--by", "0"}, {"bump-bundle-seq", "--by", "-5"},
		{"bump-bundle-seq", "--by", "1000000001"}, {"bump-bundle-seq", "--by", "x"}, {"bump-bundle-seq", "--by", "5", "extra"},
		{"raise-bundle-seq"}, {"raise-bundle-seq", "--at-least", "0"}, {"raise-bundle-seq", "--at-least", "-5"},
		{"raise-bundle-seq", "--at-least", "1000000000001"}, {"raise-bundle-seq", "--at-least", "x"},
		{"raise-bundle-seq", "--by", "5"}, {"raise-bundle-seq", "--at-least", "5", "extra"},
		{"recompile"}, {"recompile", "--all", "x"}, {"recompile", "--some"}, {"rebuild-cache", "--all"}, {"security-review", "x"},
		{"end-sessions", "--all"},
		{"upgrade-check"}, {"upgrade-check", "--json"}, {"upgrade-check", "0.1.0-alpha.9"},
		{"upgrade-check", "--target-version", "0.1.0-alpha.9", "extra"}, {"upgrade-check", "--target-version", "a", "--target-version", "b"},
		{"allowlist"}, {"allowlist", "list"}, {"allowlist", "show", "x"}, {"allowlist", "disable", "--all"},
		{"allowlist", "add"}, {"allowlist", "add", "--cidr", "203.0.113.0/24"}, {"allowlist", "add", "--label", "host"},
		{"allowlist", "add", "--cidr", "203.0.113.0/24", "--label", "host", "extra"},
		{"agent-release"}, {"agent-release", "--version", "1.0.0"}, {"agent-release", "--dir", "/r"},
		{"agent-release", "--version", "1.0.0", "--dir", "/r", "extra"}, {"agent-release", "--version", "1.0.0", "--dir", "/r", "--publish"},
		{"agent-rollout"}, {"agent-rollout", "1.2.0"}, {"agent-rollout", "--version", "1.2.0", "extra"},
		{"agent-rollout", "--version", "1.2.0", "--waves", "1,x"}, {"agent-rollout", "--version", "1.2.0", "--waves", ""},
		{"agent-rollout", "--version", "1.2.0", "--min-wave-minutes", "1h"}, {"agent-rollout", "--version", "1.2.0", "--publish"},
		{"agent-rollout", "--waves", "100"}, {"agent-rollout-halt"}, {"agent-rollout-halt", "--version", "1.2.0", "extra"},
		{"agent-rollout-halt", "--version", "1.2.0", "--waves", "100"},
		{"agent-rollout", "--version", "1.2.3", "--version", "9.9.9"}, {"agent-rollout", "--version=1.2.3", "--waves", "100", "--version=9.9.9"},
		{"agent-rollout", "--version", "", "--version", "9.9.9"}, {"agent-rollout-halt", "--version", "1.2.3", "--version", "9.9.9"},
		{"agent-rollout-resume"}, {"agent-rollout-resume", "1.2.0"}, {"agent-rollout-resume", "--version", "1.2.0", "extra"},
		{"agent-rollout-resume", "--version", "1.2.0", "--waves", "100"}, {"agent-rollout-resume", "--version", "1.2.3", "--version", "9.9.9"},
		{"auto-unseal"}, {"auto-unseal", "enable"}, {"auto-unseal", "show", "x"}, {"auto-unseal", "--force"},
	} {
		if _, err := parseAdmin(args); !errors.Is(err, errUsage) {
			t.Errorf("parseAdmin(%q) = %v, want a usage error", args, err)
		}
	}
}

func ptr(n int) *int { return &n }

func TestWriteUpgradeCheck(t *testing.T) {
	r := app.UpgradeCheckReport{
		GeneratedAt: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC), TargetVersion: "0.1.0-alpha.9",
		Window:        []string{"0.1.0-alpha.7", "0.1.0-alpha.8", "0.1.0-alpha.9"},
		Items:         []app.UpgradeCheckItem{{Name: "migrations", Status: "PASS", Detail: "ok"}, {Name: "agents", Status: "FAIL", Detail: "7 of 120"}},
		AgentsOutside: []app.OutdatedAgent{{DeviceID: uuid.MustParse("0192f0c4-0000-7000-8000-000000000001"), Hostname: "lt-01", AgentVersion: "0.1.0-alpha.6"}},
	}
	var table bytes.Buffer
	if err := writeUpgradeCheck(&table, r, false); err != nil {
		t.Fatal(err)
	}
	if got := table.String(); !strings.Contains(got, "agent window: 0.1.0-alpha.7, 0.1.0-alpha.8, 0.1.0-alpha.9") ||
		!strings.Contains(got, "FAIL  agents      7 of 120") {
		t.Errorf("table:\n%s", got)
	}
	var doc bytes.Buffer
	if err := writeUpgradeCheck(&doc, r, true); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		TargetVersion string   `json:"target_version"`
		Window        []string `json:"window"`
		Items         []struct {
			Name, Status, Detail string
		} `json:"items"`
		AgentsOutside []struct {
			DeviceID     string `json:"device_id"`
			Hostname     string `json:"hostname"`
			AgentVersion string `json:"agent_version"`
		} `json:"agents_outside"`
	}
	if err := json.Unmarshal(doc.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.TargetVersion != "0.1.0-alpha.9" || len(parsed.Window) != 3 || len(parsed.Items) != 2 || parsed.Items[1].Status != "FAIL" ||
		len(parsed.AgentsOutside) != 1 || parsed.AgentsOutside[0].Hostname != "lt-01" || parsed.AgentsOutside[0].DeviceID == "" {
		t.Errorf("json: %s", doc.String())
	}
}

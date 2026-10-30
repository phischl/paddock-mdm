package main

import (
	"errors"
	"reflect"
	"testing"

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
	} {
		got, err := parseAdmin(c.args)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseAdmin(%q) = %+v, %v; want %+v", c.args, got, err, c.want)
		}
	}
	for _, args := range [][]string{
		nil, {"unknown"}, {"bump-bundle-seq"}, {"bump-bundle-seq", "--by", "0"}, {"bump-bundle-seq", "--by", "-5"},
		{"bump-bundle-seq", "--by", "1000000001"}, {"bump-bundle-seq", "--by", "x"}, {"bump-bundle-seq", "--by", "5", "extra"},
		{"recompile"}, {"recompile", "--all", "x"}, {"recompile", "--some"}, {"rebuild-cache", "--all"}, {"security-review", "x"},
		{"end-sessions", "--all"},
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

package main

import (
	"errors"
	"testing"
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
		{[]string{"allowlist", "show"}, adminCommand{name: "allowlist", sub: "show"}},
		{[]string{"allowlist", "disable"}, adminCommand{name: "allowlist", sub: "disable"}},
		{[]string{"allowlist", "add", "--cidr", "203.0.113.0/24", "--label", "host"}, adminCommand{name: "allowlist", sub: "add", cidr: "203.0.113.0/24", label: "host"}},
		{[]string{"allowlist", "add", "--label=office vpn", "--cidr=2001:db8::/32"}, adminCommand{name: "allowlist", sub: "add", cidr: "2001:db8::/32", label: "office vpn"}},
		{[]string{"agent-release", "--version", "1.2.0", "--dir", "/release"}, adminCommand{name: "agent-release", version: "1.2.0", dir: "/release"}},
		{[]string{"agent-release", "--dir=/r", "--version=0.1.0-alpha.1"}, adminCommand{name: "agent-release", version: "0.1.0-alpha.1", dir: "/r"}},
	} {
		got, err := parseAdmin(c.args)
		if err != nil || got != c.want {
			t.Errorf("parseAdmin(%q) = %+v, %v; want %+v", c.args, got, err, c.want)
		}
	}
	for _, args := range [][]string{
		nil, {"unknown"}, {"bump-bundle-seq"}, {"bump-bundle-seq", "--by", "0"}, {"bump-bundle-seq", "--by", "-5"},
		{"bump-bundle-seq", "--by", "1000000001"}, {"bump-bundle-seq", "--by", "x"}, {"bump-bundle-seq", "--by", "5", "extra"},
		{"recompile"}, {"recompile", "--all", "x"}, {"recompile", "--some"}, {"rebuild-cache", "--all"},
		{"allowlist"}, {"allowlist", "list"}, {"allowlist", "show", "x"}, {"allowlist", "disable", "--all"},
		{"allowlist", "add"}, {"allowlist", "add", "--cidr", "203.0.113.0/24"}, {"allowlist", "add", "--label", "host"},
		{"allowlist", "add", "--cidr", "203.0.113.0/24", "--label", "host", "extra"},
		{"agent-release"}, {"agent-release", "--version", "1.0.0"}, {"agent-release", "--dir", "/r"},
		{"agent-release", "--version", "1.0.0", "--dir", "/r", "extra"}, {"agent-release", "--version", "1.0.0", "--dir", "/r", "--publish"},
	} {
		if _, err := parseAdmin(args); !errors.Is(err, errUsage) {
			t.Errorf("parseAdmin(%q) = %v, want a usage error", args, err)
		}
	}
}

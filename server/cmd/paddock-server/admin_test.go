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
	} {
		if _, err := parseAdmin(args); !errors.Is(err, errUsage) {
			t.Errorf("parseAdmin(%q) = %v, want a usage error", args, err)
		}
	}
}

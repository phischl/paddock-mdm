package ipallowlist

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.0/8": "10.0.0.0/8", "198.51.100.7/32": "198.51.100.7/32", "2001:db8::/32": "2001:db8::/32",
		"2001:db8::9/128": "2001:db8::9/128", "192.0.2.0/24": "192.0.2.0/24",
	} {
		p, err := ParseCIDR(in)
		if err != nil || p.String() != want {
			t.Errorf("%s: %v %v, want %s", in, p, err, want)
		}
	}
	for in, want := range map[string]string{
		"0.0.0.0/0":         "/0",
		"::/0":              "/0",
		"10.0.0.1":          "not a CIDR",
		"2001:db8::9":       "not a CIDR",
		"10.0.0.1/8":        "use 10.0.0.0/8",
		"2001:db8::9/32":    "use 2001:db8::/32",
		"::ffff:10.0.0.0/8": "IPv4-mapped",
		"10.0.0.0/33":       "not a CIDR",
		"example.com/24":    "not a CIDR",
		"fe80::1%eth0/64":   "not a CIDR",
		"":                  "not a CIDR",
	} {
		_, err := ParseCIDR(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %v, want %q", in, err, want)
		}
	}
}

func TestValidateLabel(t *testing.T) {
	if ValidateLabel("office") != nil || ValidateLabel(strings.Repeat("ä", 64)) != nil {
		t.Error("valid labels refused")
	}
	for _, bad := range []string{"", strings.Repeat("x", 65), "a\tb", "line\nbreak"} {
		if ValidateLabel(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

func TestConsequenceOf(t *testing.T) {
	caller := netip.MustParseAddr("192.0.2.9")
	cases := []struct {
		name          string
		before, after []netip.Prefix
		caller        netip.Addr
		want          Consequence
	}{
		{"first entry covers the caller", nil, prefixes("192.0.2.0/24"), caller, ConsequenceNone},
		{"first entry excludes the caller", nil, prefixes("198.51.100.0/24"), caller, ConsequenceLockout},
		{"removing the covering entry", prefixes("192.0.2.0/24", "198.51.100.0/24"), prefixes("198.51.100.0/24"), caller, ConsequenceLockout},
		{"removing another entry", prefixes("192.0.2.0/24", "198.51.100.0/24"), prefixes("192.0.2.0/24"), caller, ConsequenceNone},
		{"removing the last entry", prefixes("192.0.2.0/24"), nil, caller, ConsequenceDisable},
		{"empty stays empty", nil, nil, caller, ConsequenceNone},
		{"invalid caller is not covered", nil, prefixes("192.0.2.0/24"), netip.Addr{}, ConsequenceLockout},
		{"IPv4-mapped caller", nil, prefixes("192.0.2.0/24"), netip.MustParseAddr("::ffff:192.0.2.9"), ConsequenceNone},
		{"IPv6 caller", nil, prefixes("2001:db8::/32"), netip.MustParseAddr("2001:db8::9"), ConsequenceNone},
		{"IPv6 caller outside", nil, prefixes("2001:db8::/32", "192.0.2.0/24"), netip.MustParseAddr("2001:db9::9"), ConsequenceLockout},
	}
	for _, tc := range cases {
		if got := ConsequenceOf(tc.before, tc.after, tc.caller); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestSet(t *testing.T) {
	off := NewSet(nil)
	if off.Enabled() || !off.Allows(netip.MustParseAddr("203.0.113.1")) || off.Len() != 0 {
		t.Error("an empty set must allow everyone")
	}
	s := NewSet(prefixes("192.0.2.0/24", "2001:db8::/32", "198.51.100.7/32"))
	if !s.Enabled() || s.Len() != 3 {
		t.Error("enabled")
	}
	for ip, want := range map[string]bool{
		"192.0.2.1": true, "192.0.3.1": false, "::ffff:192.0.2.1": true, "2001:db8:1::1": true, "2001:db9::1": false,
		"198.51.100.7": true, "198.51.100.8": false,
	} {
		if got := s.Allows(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Allows(%s) = %v", ip, got)
		}
	}
	if s.Allows(netip.Addr{}) {
		t.Error("an invalid address must not be allowed by an enabled set")
	}
	if got := s.Covering(netip.MustParseAddr("192.0.2.1")); len(got) != 1 || got[0].String() != "192.0.2.0/24" {
		t.Errorf("Covering: %v", got)
	}
	if got := s.Covering(netip.MustParseAddr("203.0.113.1")); len(got) != 0 {
		t.Errorf("Covering outside: %v", got)
	}
}

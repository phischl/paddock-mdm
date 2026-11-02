package software

import (
	"errors"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	pkgs := []PackageRef{
		{"ubuntu", "24.04", "amd64", "a"}, {"ubuntu", "24.04", "*", "b"},
		{"ubuntu", "*", "amd64", "c"}, {"ubuntu", "*", "*", "d"},
	}
	for _, tc := range []struct {
		os, version, arch, want string
	}{
		{"ubuntu", "24.04", "amd64", "a"},
		{"ubuntu", "24.04", "arm64", "b"},
		{"ubuntu", "26.04", "amd64", "c"},
		{"ubuntu", "26.04", "arm64", "d"},
		{"ubuntu", "26.04", "", "d"},
		{"ubuntu", "24.04", "", "b"},
		{"debian", "12", "amd64", ""},
		{"ubuntu", "", "amd64", "c"},
	} {
		got, ok := Resolve(pkgs, tc.os, tc.version, tc.arch)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("Resolve(%s, %s, %q) = %q, %v; want %q", tc.os, tc.version, tc.arch, got, ok, tc.want)
		}
	}
	if _, ok := Resolve([]PackageRef{{"ubuntu", "24.04", "amd64", "a"}}, "ubuntu", "24.04", ""); ok {
		t.Error("an empty architecture matched an exact architecture")
	}
	if _, ok := Resolve([]PackageRef{{"ubuntu", "24.04", "*", "a"}}, "ubuntu", "22.04", "amd64"); ok {
		t.Error("another release matched an exact release")
	}
}

func TestValidateEntry(t *testing.T) {
	ok := []PackageRef{{"ubuntu", "*", "*", "nano"}}
	many := make([]PackageRef, MaxPackages+1)
	for i := range many {
		many[i] = PackageRef{"ubuntu", "r" + strings.Repeat("1", i%30), "*", "nano"}
		many[i].Release = "1." + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	for _, tc := range []struct {
		name     string
		n, d, c  string
		packages []PackageRef
		wantErr  string
	}{
		{"minimal", "Editor", "", "", ok, ""},
		{"full", "Editor", "A text editor.\nSecond line.", "Tools", append(ok, PackageRef{"debian", "12", "amd64", "nano"}), ""},
		{"trimmed", "  Editor  ", "", "  Tools ", ok, ""},
		{"max packages", "Editor", "", "", many[:MaxPackages], ""},
		{"empty name", " ", "", "", ok, "name"},
		{"long name", strings.Repeat("a", 101), "", "", ok, "name"},
		{"bidi name", "Ed\u202eitor", "", "", ok, "name"},
		{"long description", "Editor", strings.Repeat("a", 1001), "", ok, "description"},
		{"control description", "Editor", "a\x1bb", "", ok, "description"},
		{"bidi description", "Editor", "a\u202eb", "", ok, "description"},
		{"long category", "Editor", "", strings.Repeat("a", 65), ok, "category"},
		{"bidi category", "Editor", "", "To\u200bols", ok, "category"},
		{"no packages", "Editor", "", "", nil, "packages"},
		{"too many packages", "Editor", "", "", many, "packages"},
		{"upper package", "Editor", "", "", []PackageRef{{"ubuntu", "*", "*", "Nano"}}, "package"},
		{"short package", "Editor", "", "", []PackageRef{{"ubuntu", "*", "*", "n"}}, "package"},
		{"distribution", "Editor", "", "", []PackageRef{{"Ubuntu", "*", "*", "nano"}}, "distribution"},
		{"empty distribution", "Editor", "", "", []PackageRef{{"", "*", "*", "nano"}}, "distribution"},
		{"release", "Editor", "", "", []PackageRef{{"ubuntu", "24 04", "*", "nano"}}, "release"},
		{"empty release", "Editor", "", "", []PackageRef{{"ubuntu", "", "*", "nano"}}, "release"},
		{"architecture", "Editor", "", "", []PackageRef{{"ubuntu", "*", "i386", "nano"}}, "architecture"},
		{"duplicate tuple", "Editor", "", "", []PackageRef{{"ubuntu", "*", "*", "nano"}, {"ubuntu", "*", "*", "vim"}}, "unique"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEntry(tc.n, tc.d, tc.c, tc.packages)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if !errors.Is(err, ErrEntry) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want ErrEntry naming %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateAssignment(t *testing.T) {
	v := func(s string) *string { return &s }
	for _, tc := range []struct {
		name, intent, rule string
		version            *string
		reason             string
		wantErr            bool
	}{
		{"required latest", IntentRequired, UpdateLatest, nil, "", false},
		{"required pinned", IntentRequired, UpdatePinned, v("1.0"), "because", false},
		{"required pinned without version", IntentRequired, UpdatePinned, nil, "", true},
		{"required latest with version", IntentRequired, UpdateLatest, v("1.0"), "", true},
		{"hold without version", IntentHold, UpdateLatest, nil, "", false},
		{"hold with version", IntentHold, UpdateLatest, v("1.0"), "", false},
		{"hold pinned", IntentHold, UpdatePinned, v("1.0"), "", true},
		{"uninstall", IntentUninstall, UpdateLatest, nil, "", false},
		{"uninstall with version", IntentUninstall, UpdateLatest, v("1.0"), "", true},
		{"uninstall pinned", IntentUninstall, UpdatePinned, nil, "", true},
		{"forbid", IntentForbid, UpdateLatest, nil, "", false},
		{"forbid with version", IntentForbid, UpdateLatest, v("1.0"), "", true},
		{"forbid pinned", IntentForbid, UpdatePinned, nil, "", true},
		{"unknown intent", "available", UpdateLatest, nil, "", true},
		{"unknown rule", IntentRequired, "newest", nil, "", true},
		{"bad version", IntentHold, UpdateLatest, v("1 0"), "", true},
		{"long version", IntentHold, UpdateLatest, v(strings.Repeat("1", 129)), "", true},
		{"long reason", IntentRequired, UpdateLatest, nil, strings.Repeat("a", 501), true},
		{"reason line break", IntentRequired, UpdateLatest, nil, "a\nb", true},
		{"reason bidi", IntentRequired, UpdateLatest, nil, "a\u202eb", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAssignment(tc.intent, tc.rule, tc.version, tc.reason)
			if (err != nil) != tc.wantErr || err != nil && !errors.Is(err, ErrAssignment) {
				t.Fatalf("got %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestDefaultUpdateRule(t *testing.T) {
	one := "1.0"
	for _, tc := range []struct {
		intent  string
		version *string
		want    string
	}{
		{IntentRequired, &one, UpdatePinned}, {IntentRequired, nil, UpdateLatest},
		{IntentHold, &one, UpdateLatest}, {IntentForbid, nil, UpdateLatest},
	} {
		if got := DefaultUpdateRule(tc.intent, tc.version); got != tc.want {
			t.Errorf("DefaultUpdateRule(%s, %v) = %s, want %s", tc.intent, tc.version, got, tc.want)
		}
	}
}

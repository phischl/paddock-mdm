package software

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestResolve(t *testing.T) {
	pkgs := []PackageRef{
		{Distribution: "ubuntu", Release: "24.04", Architecture: "amd64", Package: "a"}, {Distribution: "ubuntu", Release: "24.04", Architecture: "*", Package: "b"},
		{Distribution: "ubuntu", Release: "*", Architecture: "amd64", Package: "c"}, {Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "d"},
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
	if _, ok := Resolve([]PackageRef{{Distribution: "ubuntu", Release: "24.04", Architecture: "amd64", Package: "a"}}, "ubuntu", "24.04", ""); ok {
		t.Error("an empty architecture matched an exact architecture")
	}
	if _, ok := Resolve([]PackageRef{{Distribution: "ubuntu", Release: "24.04", Architecture: "*", Package: "a"}}, "ubuntu", "22.04", "amd64"); ok {
		t.Error("another release matched an exact release")
	}
}

func TestValidateEntry(t *testing.T) {
	ok := []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "nano"}}
	many := make([]PackageRef, MaxPackages+1)
	for i := range many {
		many[i] = PackageRef{Distribution: "ubuntu", Release: "r" + strings.Repeat("1", i%30), Architecture: "*", Package: "nano"}
		many[i].Release = "1." + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	for _, tc := range []struct {
		name     string
		n, d, c  string
		packages []PackageRef
		wantErr  string
	}{
		{"minimal", "Editor", "", "", ok, ""},
		{"full", "Editor", "A text editor.\nSecond line.", "Tools", append(ok, PackageRef{Distribution: "debian", Release: "12", Architecture: "amd64", Package: "nano"}), ""},
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
		{"upper package", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "Nano"}}, "package"},
		{"short package", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "n"}}, "package"},
		{"distribution", "Editor", "", "", []PackageRef{{Distribution: "Ubuntu", Release: "*", Architecture: "*", Package: "nano"}}, "distribution"},
		{"empty distribution", "Editor", "", "", []PackageRef{{Distribution: "", Release: "*", Architecture: "*", Package: "nano"}}, "distribution"},
		{"release", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "24 04", Architecture: "*", Package: "nano"}}, "release"},
		{"empty release", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "", Architecture: "*", Package: "nano"}}, "release"},
		{"architecture", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "i386", Package: "nano"}}, "architecture"},
		{"protected agent", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "paddock-agent"}}, "paddock-agent"},
		{"himmelblau addon", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "himmelblau-apparmor"}}, "himmelblau-apparmor"},
		{"removal-protected is an entry", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "sudo"}}, ""},
		{"apt regex of himmelblau", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "himmelblau."}}, "himmelblau."},
		{"apt regex of the agent", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "paddoc+k-agent"}}, "paddoc+k-agent"},
		{"apt regex of sudo", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "sud."}}, "sud."},
		{"exact name with plus", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "libstdc++6"}}, ""},
		{"protected on one release", "Editor", "", "", append(ok, PackageRef{Distribution: "debian", Release: "12", Architecture: "amd64", Package: "himmelblau"}), "himmelblau"},
		{"duplicate tuple", "Editor", "", "", []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "nano"}, {Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "vim"}}, "unique"},
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
		{"available", IntentAvailable, UpdateLatest, nil, "offered", false},
		{"available with version", IntentAvailable, UpdateLatest, v("1.0"), "", true},
		{"available pinned", IntentAvailable, UpdatePinned, nil, "", true},
		{"unknown intent", "install", UpdateLatest, nil, "", true},
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

func TestValidateAssignmentTarget(t *testing.T) {
	one := func(pkg string) []PackageRef {
		return []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: pkg}}
	}
	for _, tc := range []struct {
		pkg, intent string
		refused     bool
	}{
		{"nano", IntentForbid, false}, {"sudo", IntentRequired, false}, {"sudo", IntentHold, false},
		{"sudo", IntentForbid, true}, {"sudo", IntentUninstall, true}, {"dracut", IntentUninstall, true},
		{"initramfs-tools", IntentRequired, true}, {"initramfs-tools", IntentHold, true},
		{"initramfs-tools", IntentForbid, false}, {"initramfs-tools", IntentUninstall, false},
		{"paddock-agent", IntentRequired, true}, {"himmelblau-apparmor", IntentHold, true},
		{"paddock-agen.", IntentRequired, true}, {"sud.", IntentUninstall, true}, {"himmelblau.", IntentRequired, true},
		{"initramfs-tools", IntentAvailable, true}, {"sudo", IntentAvailable, false}, {"nano", IntentAvailable, false},
	} {
		err := ValidateAssignmentTarget(tc.intent, one(tc.pkg))
		if (err != nil) != tc.refused || err != nil && (!errors.Is(err, ErrAssignment) || !strings.Contains(err.Error(), tc.pkg)) {
			t.Errorf("%s %s: %v, refused %v", tc.intent, tc.pkg, err, tc.refused)
		}
	}
	if err := ValidateAssignmentTarget(IntentForbid, []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "nano"}, {Distribution: "debian", Release: "*", Architecture: "*", Package: "sudo"}}); err == nil {
		t.Error("a protected package on one distribution was accepted")
	}
}

func TestValidatePackages(t *testing.T) {
	apt := PackageRef{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "nano"}
	flat := func(ref, scope string) PackageRef {
		return PackageRef{Distribution: "ubuntu", Release: "*", Architecture: "*", FlatpakRef: ref, Scope: scope}
	}
	for _, tc := range []struct {
		name     string
		kind     string
		packages []PackageRef
		wantErr  string
	}{
		{"apt source", SourceKindAPT, []PackageRef{apt}, ""},
		{"distribution repositories", "", []PackageRef{apt}, ""},
		{"flatpak system", SourceKindFlatpak, []PackageRef{flat("org.gimp.GIMP", ScopeSystem)}, ""},
		{"flatpak user", SourceKindFlatpak, []PackageRef{flat("com.visualstudio.code", ScopeUser)}, ""},
		{"flatpak default scope", SourceKindFlatpak, []PackageRef{flat("org.mozilla.firefox", "")}, ""},
		{"flatpak ref with dash and underscore", SourceKindFlatpak, []PackageRef{flat("io.git_hub.My-App", "")}, ""},
		{"flatpak ref on apt source", SourceKindAPT, []PackageRef{flat("org.gimp.GIMP", "")}, "flatpak source"},
		{"flatpak ref without source", "", []PackageRef{flat("org.gimp.GIMP", "")}, "flatpak source"},
		{"package on flatpak source", SourceKindFlatpak, []PackageRef{apt}, "flatpak_ref"},
		{"both names", SourceKindFlatpak, []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*",
			Package: "gimp", FlatpakRef: "org.gimp.GIMP"}}, "not both"},
		{"neither name", SourceKindAPT, []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*"}}, "package"},
		{"two segments", SourceKindFlatpak, []PackageRef{flat("org.gimp", "")}, "application ID"},
		{"leading digit", SourceKindFlatpak, []PackageRef{flat("org.1gimp.GIMP", "")}, "application ID"},
		{"slash", SourceKindFlatpak, []PackageRef{flat("app/org.gimp.GIMP/x86_64/stable", "")}, "application ID"},
		{"long ref", SourceKindFlatpak, []PackageRef{flat("org.example."+strings.Repeat("a", 244), "")}, "application ID"},
		{"unknown scope", SourceKindFlatpak, []PackageRef{flat("org.gimp.GIMP", "global")}, "scope"},
		{"scope on apt package", SourceKindAPT, []PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*",
			Package: "nano", Scope: ScopeUser}}, "scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePackages(tc.kind, tc.packages)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrEntry) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want an entry error naming %q", err, tc.wantErr)
			}
		})
	}
	if long := "org.example." + strings.Repeat("a", 243); len(long) != MaxFlatpakRefLength ||
		ValidatePackages(SourceKindFlatpak, []PackageRef{flat(long, "")}) != nil {
		t.Errorf("a flatpak_ref of %d characters was refused", MaxFlatpakRefLength)
	}
}

func TestNormalizePackages(t *testing.T) {
	in := []PackageRef{
		{Distribution: "ubuntu", Release: "*", Architecture: "*", FlatpakRef: "org.gimp.GIMP"},
		{Distribution: "debian", Release: "*", Architecture: "*", FlatpakRef: "org.gimp.GIMP", Scope: ScopeUser},
	}
	got := NormalizePackages(in)
	if got[0].Scope != ScopeSystem || got[1].Scope != ScopeUser || in[0].Scope != "" {
		t.Fatalf("NormalizePackages = %+v (input %+v)", got, in)
	}
}

func TestTarget(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	for _, tc := range []struct {
		name              string
		group, user, ugrp *uuid.UUID
		want              string
	}{
		{"organization", nil, nil, nil, TargetOrganization},
		{"device group", &a, nil, nil, TargetDeviceGroup},
		{"user", nil, &a, nil, TargetUser},
		{"user group", nil, nil, &a, TargetUserGroup},
		{"device group and user", &a, &b, nil, ""},
		{"user and user group", nil, &a, &b, ""},
		{"all three", &a, &b, &a, ""},
	} {
		got, err := Target(tc.group, tc.user, tc.ugrp)
		if got != tc.want || (err != nil) != (tc.want == "") || err != nil && !errors.Is(err, ErrAssignment) {
			t.Errorf("%s: Target = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

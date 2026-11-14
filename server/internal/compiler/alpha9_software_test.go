package compiler_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file freezes the software-section rules of the alpha.9 agent: ValidateSoftware and what it calls, copied from
// pkg/bundle/bundle.go and pkg/bundle/protected.go at tag v0.1.0-alpha.9 and renamed with the prefix a9. It is the
// oracle of the golden check that an older agent accepts the section the compiler renders for it (architect decision
// A10-6), so a later change to pkg/bundle cannot move it. It is never edited except to fix a copying error against
// that tag.

const (
	a9SoftwareRequired  = "required"
	a9SoftwareUninstall = "uninstall"
	a9SoftwareHold      = "hold"
	a9SoftwareForbid    = "forbid"

	a9MaxPackageField   = 128
	a9MaxSourceURIs     = 4
	a9MaxSourceURI      = 512
	a9MaxSourceSuites   = 8
	a9MaxSourceComps    = 8
	a9MaxSourceArchs    = 2
	a9MaxSourceKeyring  = 65536
	a9SourceArchAMD64   = "amd64"
	a9SourceArchARM64   = "arm64"
	a9SourceSchemeHTTPS = "https://"
)

var (
	a9PackageName       = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	a9PackageVersion    = regexp.MustCompile(`^[A-Za-z0-9.+:~-]+$`)
	a9SourceSlug        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}$`)
	a9SourceSuite       = regexp.MustCompile(`^[A-Za-z0-9./_-]{1,64}$`)
	a9SourceComponent   = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	a9SourceFingerprint = regexp.MustCompile(`^[0-9A-F]{40}$`)
	a9CatalogEntryID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	a9FullyProtected = []string{
		"fleet-osquery", "paddock-agent", "paddock-revoke", "paddock-supervisor",
		"himmelblau", "himmelblau-apparmor", "himmelblau-qr-greeter", "himmelblau-sshd-config", "nss-himmelblau",
		"pam-himmelblau",
	}
	a9RemovalProtected  = []string{"cryptsetup", "libpam-modules", "sudo", "tpm2-tools", "dracut"}
	a9ConflictingResult = []string{"initramfs-tools"}
	a9AptPatternExempt  = []string{"g++"}
)

func a9ValidateSoftware(s alpha9Software) error {
	slugs := make([]string, 0, len(s.Sources))
	for _, src := range s.Sources {
		if err := a9ValidateSoftwareSource(src.Slug, src.URIs, src.Suites, src.Components, src.Architectures, src.Keyring, src.Fingerprint); err != nil {
			return err
		}
		if slices.Contains(slugs, src.Slug) {
			return fmt.Errorf("bundle: duplicate software source %q", src.Slug)
		}
		slugs = append(slugs, src.Slug)
	}
	var names []string
	for _, p := range s.Packages {
		if !a9ValidPackage(p.Package) {
			return fmt.Errorf("bundle: invalid software package %q", p.Package)
		}
		if slices.Contains(names, p.Package) {
			return fmt.Errorf("bundle: duplicate software package %q", p.Package)
		}
		names = append(names, p.Package)
		switch p.Intent {
		case a9SoftwareRequired, a9SoftwareHold:
			if p.Version != nil && !a9ValidPackageVersion(*p.Version) {
				return fmt.Errorf("bundle: invalid version of software package %q", p.Package)
			}
		case a9SoftwareUninstall, a9SoftwareForbid:
			if p.Version != nil {
				return fmt.Errorf("bundle: software package %q with intent %s must not have a version", p.Package, p.Intent)
			}
		default:
			return fmt.Errorf("bundle: invalid intent %q of software package %q", p.Intent, p.Package)
		}
		if a9RefusedIntent(p.Package, p.Intent) {
			return fmt.Errorf("bundle: software package %q is protected against intent %s", p.Package, p.Intent)
		}
		if p.SupersededHold && p.Intent != a9SoftwareForbid && p.Intent != a9SoftwareUninstall {
			return fmt.Errorf("bundle: software package %q with intent %s cannot supersede a hold", p.Package, p.Intent)
		}
		if p.Source != "" && !slices.Contains(slugs, p.Source) {
			return fmt.Errorf("bundle: software package %q names the unknown source %q", p.Package, p.Source)
		}
		if !a9CatalogEntryID.MatchString(p.CatalogEntryID) {
			return fmt.Errorf("bundle: invalid catalog_entry_id of software package %q", p.Package)
		}
	}
	return nil
}

func a9ValidateSoftwareSource(slug string, uris, suites, components, archs []string, keyringB64, fingerprint string) error {
	if !a9SourceSlug.MatchString(slug) {
		return fmt.Errorf("bundle: invalid software source slug %q", slug)
	}
	if len(uris) < 1 || len(uris) > a9MaxSourceURIs {
		return fmt.Errorf("bundle: software source %q must have 1 to %d uris", slug, a9MaxSourceURIs)
	}
	for _, raw := range uris {
		if err := a9CheckSourceURI(raw); err != nil {
			return fmt.Errorf("bundle: software source %q: %w", slug, err)
		}
	}
	if len(suites) < 1 || len(suites) > a9MaxSourceSuites {
		return fmt.Errorf("bundle: software source %q must have 1 to %d suites", slug, a9MaxSourceSuites)
	}
	flat := 0
	for i, suite := range suites {
		if !a9SourceSuite.MatchString(suite) || slices.Contains(suites[:i], suite) ||
			slices.Contains(strings.Split(suite, "/"), "..") {
			return fmt.Errorf("bundle: software source %q has an invalid suite %q", slug, suite)
		}
		if strings.HasSuffix(suite, "/") {
			flat++
		}
	}
	if len(components) > a9MaxSourceComps {
		return fmt.Errorf("bundle: software source %q must have at most %d components", slug, a9MaxSourceComps)
	}
	for i, c := range components {
		if !a9SourceComponent.MatchString(c) || slices.Contains(components[:i], c) {
			return fmt.Errorf("bundle: software source %q has an invalid component %q", slug, c)
		}
	}
	if (flat > 0 && (flat < len(suites) || len(components) > 0)) || (flat == 0 && len(components) == 0) {
		return fmt.Errorf("bundle: software source %q mixes flat and non-flat suites or components", slug)
	}
	if len(archs) > a9MaxSourceArchs {
		return fmt.Errorf("bundle: software source %q must have at most %d architectures", slug, a9MaxSourceArchs)
	}
	for i, a := range archs {
		if (a != a9SourceArchAMD64 && a != a9SourceArchARM64) || slices.Contains(archs[:i], a) {
			return fmt.Errorf("bundle: software source %q has an invalid architecture %q", slug, a)
		}
	}
	keyring, err := base64.StdEncoding.Strict().DecodeString(keyringB64)
	if err != nil || len(keyring) == 0 || len(keyring) > a9MaxSourceKeyring {
		return fmt.Errorf("bundle: software source %q has an invalid keyring", slug)
	}
	if !a9SourceFingerprint.MatchString(fingerprint) {
		return fmt.Errorf("bundle: software source %q has an invalid fingerprint", slug)
	}
	return nil
}

func a9CheckSourceURI(raw string) error {
	if !strings.HasPrefix(raw, a9SourceSchemeHTTPS) {
		return errors.New("uris must use https")
	}
	if len(raw) > a9MaxSourceURI {
		return fmt.Errorf("uris must be at most %d characters", a9MaxSourceURI)
	}
	if strings.ContainsFunc(raw, unicode.IsSpace) || strings.ContainsAny(raw, "?#") {
		return errors.New("uris must not contain white space, a query or a fragment")
	}
	if strings.ContainsAny(raw, `"<>`) {
		return errors.New(`uris must not contain ", < or >`)
	}
	if !utf8.ValidString(raw) || strings.ContainsFunc(raw, a9InvisibleInURI) {
		return errors.New("uris must not contain control, format, invisible, replacement or line separator characters")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return errors.New("uris must be https://host[/path] without user info")
	}
	if p := u.Port(); p != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("uris must use a port from 1 to 65535")
		}
	}
	return nil
}

func a9InvisibleInURI(r rune) bool {
	switch r {
	case 'ᅟ', 'ᅠ', 'ㅤ', 'ﾠ', '⠀', unicode.ReplacementChar:
		return true
	}
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Other_Default_Ignorable_Code_Point,
		unicode.Variation_Selector) || (r >= 0xE0000 && r <= 0xE007F)
}

func a9ValidPackage(name string) bool {
	return len(name) <= a9MaxPackageField && a9PackageName.MatchString(name)
}

func a9ValidPackageVersion(v string) bool {
	return len(v) <= a9MaxPackageField && a9PackageVersion.MatchString(v)
}

func a9FullyProtectedName(pkg string) bool {
	return slices.Contains(a9FullyProtected, pkg) || pkg == "himmelblau" || strings.HasPrefix(pkg, "himmelblau-") ||
		strings.HasSuffix(pkg, "-himmelblau")
}

func a9AptPatternMatches(pkg string) bool {
	if !strings.ContainsAny(pkg, ".+") {
		return false
	}
	for strings.Contains(pkg, "++") {
		pkg = strings.ReplaceAll(pkg, "++", "+")
	}
	re, err := regexp.Compile("(?i)" + pkg)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(slices.Concat(a9FullyProtected, a9RemovalProtected, a9ConflictingResult), re.MatchString)
}

func a9RefusedIntent(pkg, intent string) bool {
	switch {
	case a9FullyProtectedName(pkg) || (!slices.Contains(a9AptPatternExempt, pkg) && a9AptPatternMatches(pkg)):
		return true
	case slices.Contains(a9RemovalProtected, pkg):
		return intent == a9SoftwareForbid || intent == a9SoftwareUninstall
	case slices.Contains(a9ConflictingResult, pkg):
		return intent == a9SoftwareRequired || intent == a9SoftwareHold
	}
	return false
}

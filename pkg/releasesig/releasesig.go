// Package releasesig is the trusted comment of agent release signatures (plan M4b.1 decision 10). minisign signs the
// trusted comment together with the binary, so "paddock-agent version=<semver> arch=<arch>" binds a signed paddockd
// to its version and architecture: the server checks it at upload, the supervisor before it installs.
package releasesig

import "strings"

const prefix = "paddock-agent version="

// Comment returns the trusted comment of release version for arch.
func Comment(version, arch string) string { return prefix + version + " arch=" + arch }

// Parse returns version and arch of a trusted comment; ok is false unless the comment has exactly the form of
// Comment with a non-empty version and arch.
func Parse(comment string) (version, arch string, ok bool) {
	rest, found := strings.CutPrefix(comment, prefix)
	if !found {
		return "", "", false
	}
	version, arch, found = strings.Cut(rest, " arch=")
	if !found || version == "" || arch == "" || strings.ContainsAny(version, " \t") || strings.ContainsAny(arch, " \t") {
		return "", "", false
	}
	return version, arch, true
}

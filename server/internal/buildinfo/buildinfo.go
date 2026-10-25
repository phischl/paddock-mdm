// Package buildinfo holds the facts fixed when paddock-server is built.
package buildinfo

// Version is the server version, set with -ldflags "-X github.com/phischl/paddock-mdm/server/internal/buildinfo.Version=<version>".
// The release images carry the release tag without the leading v (e.g. 0.1.0-alpha.5); local builds keep 0.0.0-dev.
var Version = "0.0.0-dev"

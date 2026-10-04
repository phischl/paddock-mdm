// Package buildinfo holds the facts fixed at build time: the version (set with -ldflags -X) and the build tags that
// change behaviour (paddock_dev and the test-only broken builds of plan M2b decision 18).
package buildinfo

// Version is the agent version, set with -ldflags "-X github.com/paddock-mdm/paddock/agent/internal/buildinfo.Version=<semver>".
var Version = "0.0.0-dev"

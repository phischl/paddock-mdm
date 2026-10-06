// Package pkg holds code shared between paddock-server and paddock-agent: the device protocol (protocol), RFC 8785
// canonical JSON (canonicaljson), DSSE envelopes (dsse), the bundle schemas (bundle), device commands (command), the
// sudoers renderer (sudoers), the device path and unit policy (policy) and the trusted comment of agent release
// signatures (releasesig). It depends only on the standard library and github.com/gowebpki/jcs and never imports
// server code.
package pkg

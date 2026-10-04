// Package pkg holds code shared between paddock-server and paddock-agent: the device protocol (protocol), RFC 8785
// canonical JSON (canonicaljson), DSSE envelopes (dsse), bundle schema v1 (bundle) and the device path and unit
// policy (policy). It depends only on the standard library and github.com/gowebpki/jcs and never imports server
// code.
package pkg

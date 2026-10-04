//go:build !paddock_testbroken_selftest

package buildinfo

// BrokenSelfTest makes `paddockd self-test` fail (test releases only, never release packaging).
const BrokenSelfTest = false

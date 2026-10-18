//go:build paddock_testbroken_supervisor

package buildinfo

// BrokenSupervisor makes paddock-supervisor exit 1 after 20 s (gate S-UP2b only, never release packaging).
const BrokenSupervisor = true

//go:build paddock_testbroken_probation

package buildinfo

// BrokenProbation makes `paddockd run` exit 1 after 20 s (test releases only, never release packaging).
const BrokenProbation = true

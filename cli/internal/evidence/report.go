package evidence

import (
	"fmt"
	"io"
	"strings"
)

// WriteText prints the result as the lines of decision 39.
func (r *Result) WriteText(w io.Writer) {
	anchor := "none"
	if r.ChainAnchor != nil {
		anchor = clean(*r.ChainAnchor)
	}
	summary := fmt.Sprintf("%s %s..%s: %d days, %d objects, %d events", clean(r.OrganizationID), clean(r.FromDay), clean(r.ToDay),
		r.Days, r.Objects, r.Events)
	if r.OK {
		fmt.Fprintf(w, "OK %s; signed with audit-chain v%d (fingerprint %s); chain anchor %s\n", summary, r.KeyVersion, r.Fingerprint, anchor)
	} else {
		for _, p := range r.Problems {
			fmt.Fprintf(w, "FAIL %s\n", p)
		}
		fmt.Fprintf(w, "NOT OK %s; %d problem(s); chain anchor %s\n", summary, len(r.Problems), anchor)
	}
	yes := "no"
	if r.Server.OK {
		yes = "yes"
	}
	fmt.Fprintf(w, "chain verified by the server: %s\n", yes)
	fmt.Fprintf(w, "nightly runs: %d, with problems: %d\n", r.Server.Runs, r.Server.RunsWithProblems)
	for _, p := range r.Server.Problems {
		fmt.Fprintf(w, "  server problem: %s\n", p)
	}
	if !r.FingerprintChecked {
		fmt.Fprintln(w, "NOTE no --fingerprint given: the signing key comes from the package itself and is not authenticated; "+
			"compare the fingerprint above with the one recorded out of band: "+strings.ToLower(r.Fingerprint))
	}
}

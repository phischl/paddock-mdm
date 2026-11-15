package worker

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetricsOnlyWhereRegistered (main §46): the package alone puts none of its metrics into the default registry,
// which every role serves; PaddockOpenBaoUnreachable compares paddock_openbao_reachable with 0, and every role but
// the worker would export that default.
func TestMetricsOnlyWhereRegistered(t *testing.T) {
	names := []string{
		"paddock_openbao_reachable",
		"paddock_openbao_sealed",
		"paddock_auto_unseal_enabled",
		"paddock_auto_unseal_shares_present",
		"paddock_auto_unseal_unsealer_up",
		"paddock_offboarding_retry_capped",
		"paddock_osv_stale",
		"paddock_retention_stores",
		"paddock_tls_probe_hosts",
	}
	for _, name := range names {
		if n, err := testutil.GatherAndCount(prometheus.DefaultGatherer, name); err != nil || n != 0 {
			t.Errorf("default registry: %d series of %s (%v), want none", n, name, err)
		}
	}
	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if n, err := testutil.GatherAndCount(reg, name); err != nil || n != 1 {
			t.Errorf("worker registry: %d series of %s (%v), want 1", n, name, err)
		}
	}
	if err := RegisterMetrics(reg); err == nil {
		t.Error("a second registration in the same registry succeeded")
	}
}

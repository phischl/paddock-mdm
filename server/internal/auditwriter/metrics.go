package auditwriter

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterMetrics registers the audit writer's metrics with reg. paddock-server is one binary and every role serves
// the default registry, so a metric the writer alone sets must not be registered at init: the other roles would export
// its default (paddock_audit_verify_last_run_timestamp_seconds at 0) and the staleness alerts would fire for each of
// them (main §46). Only serve audit-writer calls it.
func RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{
		metricVerifyFailedOrganizations, metricVerifyLastRun,
		metricPurgeLastSuccess, metricPartitionsDropped,
		metricExport, metricExportPendingAge, metricExportBuild,
		metricWritten, metricTransaction, metricPut, metricSeal,
	} {
		if err := reg.Register(c); err != nil {
			return fmt.Errorf("auditwriter: register metrics: %w", err)
		}
	}
	return nil
}

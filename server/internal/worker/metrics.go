package worker

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterMetrics registers the worker's metrics with reg. paddock-server is one binary and every role serves the
// default registry, so a metric the worker alone sets must not be registered at init: the other roles would export its
// default (a gauge at 0, e.g. paddock_openbao_reachable) and the alerts that compare it with 0 would fire without a
// worker (main §46). Only serveWorker calls it.
func RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{
		metricOffboardingStepFailing, metricOffboardingRetryCapped, metricOffboardingCapReached, metricOffboardingFinalizeBusy,
		metricOffboardingStepYields, metricOffboardingRoundOverruns,
		metricRetentionLastSuccess, metricRetentionDeleted, metricRetentionStores,
		metricAutoUnsealEnabled, metricAutoUnsealSharesPresent, metricAutoUnsealUnsealerUp,
		metricDirectoryRefusals, metricUnknownEvents, metricDropped, metricConfigRollouts, metricUnmappedHosts,
		metricOSVLastSuccess, metricOSVStale, metricOSVEntries,
		metricOpenBaoSealed, metricOpenBaoReachable, metricTLSExpiry, metricTLSProbeSuccess, metricTLSProbeHosts,
	} {
		if err := reg.Register(c); err != nil {
			return fmt.Errorf("worker: register metrics: %w", err)
		}
	}
	return nil
}

package ratelimit

import "github.com/prometheus/client_golang/prometheus"

// MetricErrors exposes paddock_ratelimit_errors_total to the tests.
func MetricErrors() prometheus.Collector { return metricErrors }

// MetricRejected exposes paddock_ratelimit_rejected_total of class to the tests.
func MetricRejected(class Class) prometheus.Collector {
	return metricRejected.WithLabelValues(string(class))
}

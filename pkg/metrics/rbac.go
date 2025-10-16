package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// RBACMetrics holds all Prometheus metrics for RBAC policy engine
type RBACMetrics struct {
	// ChecksTotal tracks total permission checks performed
	ChecksTotal prometheus.Counter

	// ResultsTotal tracks permission check results
	// Labels: result={granted,denied,error}
	ResultsTotal *prometheus.CounterVec

	// CacheOperationsTotal tracks RBAC permission cache operations
	// Labels: result={hit,miss}
	CacheOperationsTotal *prometheus.CounterVec

	// AdminOverridesTotal tracks tenant admin bypasses
	AdminOverridesTotal prometheus.Counter

	// OwnershipChecksTotal tracks ABAC ownership validations
	OwnershipChecksTotal prometheus.Counter

	// ConditionEvalsTotal tracks ABAC condition evaluations
	ConditionEvalsTotal prometheus.Counter

	// ErrorsTotal tracks permission check errors
	ErrorsTotal prometheus.Counter

	// CheckLatencySeconds tracks permission check latency distribution
	// Uses histogram for percentile calculations
	CheckLatencySeconds prometheus.Histogram
}

// NewRBACMetrics creates and initializes RBAC metrics
func NewRBACMetrics() *RBACMetrics {
	return &RBACMetrics{
		ChecksTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "kube_manager",
				Subsystem: "rbac",
				Name:      "permission_checks_total",
				Help:      "Total number of permission checks performed",
			},
		),

		ResultsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_manager",
				Subsystem: "rbac",
				Name:      "permission_results_total",
				Help:      "Total number of permission check results by outcome",
			},
			[]string{"result"},
		),

		CacheOperationsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_manager",
				Subsystem: "rbac",
				Name:      "cache_operations_total",
				Help:      "Total number of RBAC cache operations by result",
			},
			[]string{"result"},
		),

		AdminOverridesTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "kube_manager",
				Subsystem: "rbac",
				Name:      "admin_overrides_total",
				Help:      "Total number of tenant admin permission bypasses",
			},
		),

		OwnershipChecksTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "kube_manager",
				Subsystem: "rbac",
				Name:      "ownership_checks_total",
				Help:      "Total number of ABAC ownership validations performed",
			},
		),

		ConditionEvalsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "kube_manager",
				Subsystem: "rbac",
				Name:      "condition_evaluations_total",
				Help:      "Total number of ABAC condition evaluations performed",
			},
		),

		ErrorsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "kube_manager",
				Subsystem: "rbac",
				Name:      "errors_total",
				Help:      "Total number of errors during permission checks",
			},
		),

		CheckLatencySeconds: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: "kube_manager",
				Subsystem: "rbac",
				Name:      "check_duration_seconds",
				Help:      "Permission check latency distribution in seconds",
				Buckets: []float64{
					0.00001, // 10µs
					0.00005, // 50µs
					0.0001,  // 100µs
					0.0005,  // 500µs
					0.001,   // 1ms
					0.002,   // 2ms
					0.005,   // 5ms (target p99)
					0.01,    // 10ms
					0.05,    // 50ms
					0.1,     // 100ms
					0.5,     // 500ms
				},
			},
		),
	}
}

// Describe implements prometheus.Collector
func (m *RBACMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.ChecksTotal.Describe(ch)
	m.ResultsTotal.Describe(ch)
	m.CacheOperationsTotal.Describe(ch)
	m.AdminOverridesTotal.Describe(ch)
	m.OwnershipChecksTotal.Describe(ch)
	m.ConditionEvalsTotal.Describe(ch)
	m.ErrorsTotal.Describe(ch)
	m.CheckLatencySeconds.Describe(ch)
}

// Collect implements prometheus.Collector
func (m *RBACMetrics) Collect(ch chan<- prometheus.Metric) {
	m.ChecksTotal.Collect(ch)
	m.ResultsTotal.Collect(ch)
	m.CacheOperationsTotal.Collect(ch)
	m.AdminOverridesTotal.Collect(ch)
	m.OwnershipChecksTotal.Collect(ch)
	m.ConditionEvalsTotal.Collect(ch)
	m.ErrorsTotal.Collect(ch)
	m.CheckLatencySeconds.Collect(ch)
}

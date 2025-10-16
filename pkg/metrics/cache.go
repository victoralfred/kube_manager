package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// CacheMetrics holds all Prometheus metrics for cache operations
type CacheMetrics struct {
	// OperationsTotal tracks cache operations by type and result
	// Labels: operation={get,set,delete}, result={hit,miss,""}
	OperationsTotal *prometheus.CounterVec

	// ErrorsTotal tracks total cache errors
	ErrorsTotal prometheus.Counter

	// HitRatio tracks cache hit ratio (0-1)
	// This is a gauge showing current hit rate as a ratio
	HitRatio prometheus.Gauge

	// LatencySeconds tracks cache operation latency distribution
	// Uses histogram for percentile calculations (p50, p95, p99)
	LatencySeconds prometheus.Histogram

	// CircuitBreakerState tracks circuit breaker state
	// Values: 0=closed (healthy), 1=open (failing), 2=half-open (testing)
	CircuitBreakerState prometheus.Gauge
}

// NewCacheMetrics creates and initializes cache metrics
func NewCacheMetrics() *CacheMetrics {
	return &CacheMetrics{
		OperationsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_manager",
				Subsystem: "cache",
				Name:      "operations_total",
				Help:      "Total number of cache operations by type and result",
			},
			[]string{"operation", "result"},
		),

		ErrorsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "kube_manager",
				Subsystem: "cache",
				Name:      "errors_total",
				Help:      "Total number of cache errors",
			},
		),

		HitRatio: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "kube_manager",
				Subsystem: "cache",
				Name:      "hit_ratio",
				Help:      "Cache hit ratio (0-1), calculated as hits / (hits + misses)",
			},
		),

		LatencySeconds: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: "kube_manager",
				Subsystem: "cache",
				Name:      "operation_duration_seconds",
				Help:      "Cache operation latency distribution in seconds",
				Buckets: []float64{
					0.00001, // 10µs
					0.00005, // 50µs
					0.0001,  // 100µs
					0.0005,  // 500µs
					0.001,   // 1ms
					0.005,   // 5ms
					0.01,    // 10ms
					0.05,    // 50ms
					0.1,     // 100ms
					0.5,     // 500ms
					1.0,     // 1s
				},
			},
		),

		CircuitBreakerState: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "kube_manager",
				Subsystem: "cache",
				Name:      "circuit_breaker_state",
				Help:      "Circuit breaker state: 0=closed (healthy), 1=open (failing), 2=half-open (testing)",
			},
		),
	}
}

// Describe implements prometheus.Collector
func (m *CacheMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.OperationsTotal.Describe(ch)
	m.ErrorsTotal.Describe(ch)
	m.HitRatio.Describe(ch)
	m.LatencySeconds.Describe(ch)
	m.CircuitBreakerState.Describe(ch)
}

// Collect implements prometheus.Collector
func (m *CacheMetrics) Collect(ch chan<- prometheus.Metric) {
	m.OperationsTotal.Collect(ch)
	m.ErrorsTotal.Collect(ch)
	m.HitRatio.Collect(ch)
	m.LatencySeconds.Collect(ch)
	m.CircuitBreakerState.Collect(ch)
}

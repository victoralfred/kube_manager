// Package metrics provides Prometheus metrics collection and exposition for the kube_manager system.
//
// It exposes metrics for cache operations, RBAC permission checks, and system health.
// Metrics follow Prometheus naming conventions and best practices.
//
// Usage:
//
//	// Initialize metrics collector
//	collector := metrics.NewCollector(cache, policyEngine)
//	collector.Start()
//	defer collector.Stop()
//
//	// Expose /metrics endpoint
//	http.Handle("/metrics", promhttp.Handler())
package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/pkg/cache"
)

// Collector manages Prometheus metrics collection
type Collector struct {
	cache        cache.Cache
	policyEngine rbac.PolicyEngine

	cacheMetrics *CacheMetrics
	rbacMetrics  *RBACMetrics

	registry *prometheus.Registry
	handler  http.Handler

	stopCh chan struct{}
	wg     sync.WaitGroup
	mu     sync.RWMutex

	// Track last values to compute deltas
	lastCacheStats cacheStatsSnapshot
	lastRBACStats  rbacStatsSnapshot
}

// Snapshots for delta calculation
type cacheStatsSnapshot struct {
	Hits    uint64
	Misses  uint64
	Sets    uint64
	Deletes uint64
	Errors  uint64
}

type rbacStatsSnapshot struct {
	TotalChecks     uint64
	Granted         uint64
	Denials         uint64
	Errors          uint64
	CacheHits       uint64
	CacheMisses     uint64
	AdminOverrides  uint64
	OwnershipChecks uint64
	ConditionEvals  uint64
}

// CollectorConfig holds configuration for metrics collector
type CollectorConfig struct {
	Cache            cache.Cache
	PolicyEngine     rbac.PolicyEngine
	UpdateInterval   time.Duration // How often to sync metrics (default: 15s)
	EnableGoMetrics  bool          // Include Go runtime metrics
	EnableProcessMetrics bool      // Include process metrics
}

// NewCollector creates a new Prometheus metrics collector
func NewCollector(config CollectorConfig) *Collector {
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 15 * time.Second
	}

	// Create custom registry
	registry := prometheus.NewRegistry()

	// Optionally add Go and process metrics
	if config.EnableGoMetrics {
		registry.MustRegister(prometheus.NewGoCollector())
	}
	if config.EnableProcessMetrics {
		registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	}

	c := &Collector{
		cache:        config.Cache,
		policyEngine: config.PolicyEngine,
		cacheMetrics: NewCacheMetrics(),
		rbacMetrics:  NewRBACMetrics(),
		registry:     registry,
		stopCh:       make(chan struct{}),
	}

	// Register custom metrics
	c.registerMetrics()

	// Create HTTP handler
	c.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})

	return c
}

// registerMetrics registers all custom metrics with Prometheus
func (c *Collector) registerMetrics() {
	// Cache metrics
	c.registry.MustRegister(
		c.cacheMetrics.OperationsTotal,
		c.cacheMetrics.ErrorsTotal,
		c.cacheMetrics.HitRatio,
		c.cacheMetrics.LatencySeconds,
		c.cacheMetrics.CircuitBreakerState,
	)

	// RBAC metrics
	c.registry.MustRegister(
		c.rbacMetrics.ChecksTotal,
		c.rbacMetrics.ResultsTotal,
		c.rbacMetrics.CacheOperationsTotal,
		c.rbacMetrics.AdminOverridesTotal,
		c.rbacMetrics.OwnershipChecksTotal,
		c.rbacMetrics.ConditionEvalsTotal,
		c.rbacMetrics.ErrorsTotal,
		c.rbacMetrics.CheckLatencySeconds,
	)
}

// Start begins collecting metrics in the background
func (c *Collector) Start() {
	c.wg.Add(1)
	go c.collectLoop()
}

// Stop gracefully stops metrics collection
func (c *Collector) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

// collectLoop periodically syncs metrics from cache and RBAC engine
func (c *Collector) collectLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Initial collection
	c.collect()

	for {
		select {
		case <-ticker.C:
			c.collect()
		case <-c.stopCh:
			return
		}
	}
}

// collect updates Prometheus metrics from current stats
func (c *Collector) collect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Collect cache metrics
	if c.cache != nil {
		c.collectCacheMetrics()
	}

	// Collect RBAC metrics
	if c.policyEngine != nil {
		c.collectRBACMetrics()
	}
}

// collectCacheMetrics updates cache metrics
func (c *Collector) collectCacheMetrics() {
	stats := c.cache.Stats()

	// Compute deltas since last collection
	deltaHits := stats.Hits - c.lastCacheStats.Hits
	deltaMisses := stats.Misses - c.lastCacheStats.Misses
	deltaSets := stats.Sets - c.lastCacheStats.Sets
	deltaDeletes := stats.Deletes - c.lastCacheStats.Deletes
	deltaErrors := stats.Errors - c.lastCacheStats.Errors

	// Update counters with deltas only
	if deltaHits > 0 {
		c.cacheMetrics.OperationsTotal.WithLabelValues("get", "hit").Add(float64(deltaHits))
	}
	if deltaMisses > 0 {
		c.cacheMetrics.OperationsTotal.WithLabelValues("get", "miss").Add(float64(deltaMisses))
	}
	if deltaSets > 0 {
		c.cacheMetrics.OperationsTotal.WithLabelValues("set", "").Add(float64(deltaSets))
	}
	if deltaDeletes > 0 {
		c.cacheMetrics.OperationsTotal.WithLabelValues("delete", "").Add(float64(deltaDeletes))
	}
	if deltaErrors > 0 {
		c.cacheMetrics.ErrorsTotal.Add(float64(deltaErrors))
	}

	// Save current values for next delta calculation
	c.lastCacheStats.Hits = stats.Hits
	c.lastCacheStats.Misses = stats.Misses
	c.lastCacheStats.Sets = stats.Sets
	c.lastCacheStats.Deletes = stats.Deletes
	c.lastCacheStats.Errors = stats.Errors

	// Update gauges (point-in-time values, not cumulative)
	c.cacheMetrics.HitRatio.Set(stats.HitRate / 100.0) // Convert percentage to ratio 0-1

	// Update histogram with current average (only if there have been operations)
	if stats.Hits+stats.Misses > 0 {
		c.cacheMetrics.LatencySeconds.Observe(stats.AvgLatencyMs / 1000.0) // Convert ms to seconds
	}

	// Circuit breaker state (numeric)
	var state float64
	if stats.CircuitOpen {
		state = 1.0 // Open
	} else {
		state = 0.0 // Closed
	}
	c.cacheMetrics.CircuitBreakerState.Set(state)
}

// collectRBACMetrics updates RBAC policy engine metrics
func (c *Collector) collectRBACMetrics() {
	stats := c.policyEngine.Stats()

	// Compute deltas since last collection
	deltaTotalChecks := stats.TotalChecks - c.lastRBACStats.TotalChecks
	deltaDenials := stats.Denials - c.lastRBACStats.Denials
	deltaErrors := stats.Errors - c.lastRBACStats.Errors
	deltaCacheHits := stats.CacheHits - c.lastRBACStats.CacheHits
	deltaCacheMisses := stats.CacheMisses - c.lastRBACStats.CacheMisses
	deltaAdminOverrides := stats.AdminOverrides - c.lastRBACStats.AdminOverrides
	deltaOwnershipChecks := stats.OwnershipChecks - c.lastRBACStats.OwnershipChecks
	deltaConditionEvals := stats.ConditionEvals - c.lastRBACStats.ConditionEvals

	// Results breakdown (granted = total - denied - errors)
	currentGranted := stats.TotalChecks - stats.Denials - stats.Errors
	deltaGranted := currentGranted - c.lastRBACStats.Granted

	// Update counters with deltas only
	if deltaTotalChecks > 0 {
		c.rbacMetrics.ChecksTotal.Add(float64(deltaTotalChecks))
	}
	if deltaGranted > 0 {
		c.rbacMetrics.ResultsTotal.WithLabelValues("granted").Add(float64(deltaGranted))
	}
	if deltaDenials > 0 {
		c.rbacMetrics.ResultsTotal.WithLabelValues("denied").Add(float64(deltaDenials))
	}
	if deltaErrors > 0 {
		c.rbacMetrics.ResultsTotal.WithLabelValues("error").Add(float64(deltaErrors))
		c.rbacMetrics.ErrorsTotal.Add(float64(deltaErrors))
	}
	if deltaCacheHits > 0 {
		c.rbacMetrics.CacheOperationsTotal.WithLabelValues("hit").Add(float64(deltaCacheHits))
	}
	if deltaCacheMisses > 0 {
		c.rbacMetrics.CacheOperationsTotal.WithLabelValues("miss").Add(float64(deltaCacheMisses))
	}
	if deltaAdminOverrides > 0 {
		c.rbacMetrics.AdminOverridesTotal.Add(float64(deltaAdminOverrides))
	}
	if deltaOwnershipChecks > 0 {
		c.rbacMetrics.OwnershipChecksTotal.Add(float64(deltaOwnershipChecks))
	}
	if deltaConditionEvals > 0 {
		c.rbacMetrics.ConditionEvalsTotal.Add(float64(deltaConditionEvals))
	}

	// Save current values for next delta calculation
	c.lastRBACStats.TotalChecks = stats.TotalChecks
	c.lastRBACStats.Granted = currentGranted
	c.lastRBACStats.Denials = stats.Denials
	c.lastRBACStats.Errors = stats.Errors
	c.lastRBACStats.CacheHits = stats.CacheHits
	c.lastRBACStats.CacheMisses = stats.CacheMisses
	c.lastRBACStats.AdminOverrides = stats.AdminOverrides
	c.lastRBACStats.OwnershipChecks = stats.OwnershipChecks
	c.lastRBACStats.ConditionEvals = stats.ConditionEvals

	// Latency histogram (only observe if there have been permission checks)
	if stats.TotalChecks > 0 {
		c.rbacMetrics.CheckLatencySeconds.Observe(stats.AvgCheckTimeMs / 1000.0) // Convert ms to seconds
	}
}

// Handler returns the HTTP handler for /metrics endpoint
func (c *Collector) Handler() http.Handler {
	return c.handler
}

// Registry returns the Prometheus registry
func (c *Collector) Registry() *prometheus.Registry {
	return c.registry
}

package metrics

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler provides HTTP handlers for metrics endpoints
type Handler struct {
	collector *Collector
}

// NewHandler creates a new metrics HTTP handler
func NewHandler(collector *Collector) *Handler {
	return &Handler{
		collector: collector,
	}
}

// RegisterRoutes registers metrics endpoints with Gin router
func (h *Handler) RegisterRoutes(router *gin.Engine) {
	metrics := router.Group("/metrics")
	{
		// Prometheus metrics endpoint (standard)
		metrics.GET("", h.PrometheusMetrics)

		// JSON metrics endpoints (alternative format)
		metrics.GET("/json", h.GetAllMetrics)
		metrics.GET("/json/cache", h.GetCacheMetrics)
		metrics.GET("/json/rbac", h.GetRBACMetrics)
	}

	// Health check with metrics
	router.GET("/health", h.HealthCheck)
}

// PrometheusMetrics exposes metrics in Prometheus format
// GET /metrics
func (h *Handler) PrometheusMetrics(c *gin.Context) {
	handler := promhttp.HandlerFor(
		h.collector.Registry(),
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		},
	)
	handler.ServeHTTP(c.Writer, c.Request)
}

// GetAllMetrics returns all metrics in JSON format
// GET /metrics/json
func (h *Handler) GetAllMetrics(c *gin.Context) {
	cacheStats := h.collector.cache.Stats()
	rbacStats := h.collector.policyEngine.Stats()

	response := gin.H{
		"cache": formatCacheStatsJSON(cacheStats),
		"rbac":  formatRBACStatsJSON(rbacStats),
	}

	c.JSON(http.StatusOK, response)
}

// GetCacheMetrics returns cache metrics in JSON format
// GET /metrics/json/cache
func (h *Handler) GetCacheMetrics(c *gin.Context) {
	stats := h.collector.cache.Stats()
	c.JSON(http.StatusOK, formatCacheStatsJSON(stats))
}

// GetRBACMetrics returns RBAC metrics in JSON format
// GET /metrics/json/rbac
func (h *Handler) GetRBACMetrics(c *gin.Context) {
	stats := h.collector.policyEngine.Stats()
	c.JSON(http.StatusOK, formatRBACStatsJSON(stats))
}

// HealthCheck returns system health with basic metrics
// GET /health
func (h *Handler) HealthCheck(c *gin.Context) {
	cacheStats := h.collector.cache.Stats()
	rbacStats := h.collector.policyEngine.Stats()

	// Determine health status
	status := "healthy"
	httpStatus := http.StatusOK

	// Check for critical issues
	if cacheStats.CircuitOpen {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	if cacheStats.HitRate < 50 && cacheStats.Hits+cacheStats.Misses > 1000 {
		status = "degraded"
	}

	if cacheStats.Errors > 100 || rbacStats.Errors > 100 {
		status = "unhealthy"
		httpStatus = http.StatusServiceUnavailable
	}

	response := gin.H{
		"status": status,
		"cache": gin.H{
			"hit_ratio":       cacheStats.HitRate / 100.0,
			"circuit_breaker": !cacheStats.CircuitOpen,
			"errors":          cacheStats.Errors,
		},
		"rbac": gin.H{
			"avg_latency_ms": rbacStats.AvgCheckTimeMs,
			"errors":         rbacStats.Errors,
			"total_checks":   rbacStats.TotalChecks,
		},
	}

	c.JSON(httpStatus, response)
}

// Helper functions to format stats for JSON output

func formatCacheStatsJSON(stats interface{}) gin.H {
	// Type assertion to get cache stats
	s, ok := stats.(struct {
		Hits         uint64
		Misses       uint64
		Sets         uint64
		Deletes      uint64
		Errors       uint64
		HitRate      float64
		AvgLatencyMs float64
		CircuitOpen  bool
	})

	if !ok {
		// Try to marshal and unmarshal to convert
		data, _ := json.Marshal(stats)
		json.Unmarshal(data, &s)
	}

	return gin.H{
		"operations": gin.H{
			"hits":    s.Hits,
			"misses":  s.Misses,
			"sets":    s.Sets,
			"deletes": s.Deletes,
		},
		"errors":              s.Errors,
		"hit_ratio":           s.HitRate / 100.0, // Convert to ratio
		"avg_latency_seconds": s.AvgLatencyMs / 1000.0,
		"circuit_breaker": gin.H{
			"open":   s.CircuitOpen,
			"state":  getCircuitBreakerState(s.CircuitOpen),
			"healthy": !s.CircuitOpen,
		},
	}
}

func formatRBACStatsJSON(stats interface{}) gin.H {
	// Type assertion for RBAC stats
	s, ok := stats.(struct {
		TotalChecks      uint64
		CacheHits        uint64
		CacheMisses      uint64
		AdminOverrides   uint64
		OwnershipChecks  uint64
		ConditionEvals   uint64
		Denials          uint64
		Errors           uint64
		AvgCheckTimeMs   float64
	})

	if !ok {
		data, _ := json.Marshal(stats)
		json.Unmarshal(data, &s)
	}

	granted := s.TotalChecks - s.Denials - s.Errors

	return gin.H{
		"total_checks": s.TotalChecks,
		"results": gin.H{
			"granted": granted,
			"denied":  s.Denials,
			"errors":  s.Errors,
		},
		"cache": gin.H{
			"hits":      s.CacheHits,
			"misses":    s.CacheMisses,
			"hit_ratio": calculateHitRatio(s.CacheHits, s.CacheMisses),
		},
		"abac": gin.H{
			"admin_overrides":     s.AdminOverrides,
			"ownership_checks":    s.OwnershipChecks,
			"condition_evaluations": s.ConditionEvals,
		},
		"avg_check_duration_seconds": s.AvgCheckTimeMs / 1000.0,
		"errors_total":               s.Errors,
	}
}

func getCircuitBreakerState(open bool) string {
	if open {
		return "open"
	}
	return "closed"
}

func calculateHitRatio(hits, misses uint64) float64 {
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total)
}

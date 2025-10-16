package metrics

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/pkg/cache"
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

func formatCacheStatsJSON(stats cache.CacheStats) gin.H {
	return gin.H{
		"operations": gin.H{
			"hits":    stats.Hits,
			"misses":  stats.Misses,
			"sets":    stats.Sets,
			"deletes": stats.Deletes,
		},
		"errors":              stats.Errors,
		"hit_ratio":           stats.HitRate / 100.0, // Convert to ratio
		"avg_latency_seconds": stats.AvgLatencyMs / 1000.0,
		"circuit_breaker": gin.H{
			"open":    stats.CircuitOpen,
			"state":   getCircuitBreakerState(stats.CircuitOpen),
			"healthy": !stats.CircuitOpen,
		},
	}
}

func formatRBACStatsJSON(stats rbac.PolicyEngineStats) gin.H {
	granted := stats.TotalChecks - stats.Denials - stats.Errors

	return gin.H{
		"total_checks": stats.TotalChecks,
		"results": gin.H{
			"granted": granted,
			"denied":  stats.Denials,
			"errors":  stats.Errors,
		},
		"cache": gin.H{
			"hits":      stats.CacheHits,
			"misses":    stats.CacheMisses,
			"hit_ratio": calculateHitRatio(stats.CacheHits, stats.CacheMisses),
		},
		"abac": gin.H{
			"admin_overrides":       stats.AdminOverrides,
			"ownership_checks":      stats.OwnershipChecks,
			"condition_evaluations": stats.ConditionEvals,
		},
		"avg_check_duration_seconds": stats.AvgCheckTimeMs / 1000.0,
		"errors_total":               stats.Errors,
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

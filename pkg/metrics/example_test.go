package metrics_test

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/pkg/cache"
	"github.com/victoralfred/kube_manager/pkg/metrics"
)

// Example demonstrates how to integrate metrics with cache and RBAC subsystems
func Example() {
	ctx := context.Background()

	// 1. Initialize cache (in-memory for this example)
	cacheInstance := cache.NewInMemoryCache()

	// 2. Initialize RBAC policy engine
	// (Assuming you have a repository and other dependencies set up)
	// policyEngine := rbac.NewPolicyEngine(rbac.PolicyEngineConfig{
	// 	Repository: repo,
	// 	Cache:      cacheInstance,
	// 	CacheTTL:   15 * time.Minute,
	// })

	// For this example, we'll show the structure
	var policyEngine rbac.PolicyEngine // Replace with actual initialization

	// 3. Create metrics collector
	collector := metrics.NewCollector(metrics.CollectorConfig{
		Cache:                cacheInstance,
		PolicyEngine:         policyEngine,
		UpdateInterval:       15 * time.Second,
		EnableGoMetrics:      true, // Include Go runtime metrics
		EnableProcessMetrics: true, // Include process metrics (CPU, memory, etc.)
	})

	// 4. Start background metrics collection
	collector.Start()
	defer collector.Stop()

	// 5. Setup HTTP server with metrics endpoints
	router := gin.Default()

	// Create metrics handler and register routes
	metricsHandler := metrics.NewHandler(collector)
	metricsHandler.RegisterRoutes(router)

	// This will register:
	// - GET /metrics           (Prometheus format)
	// - GET /metrics/json      (JSON format - all metrics)
	// - GET /metrics/json/cache (JSON format - cache only)
	// - GET /metrics/json/rbac  (JSON format - RBAC only)
	// - GET /health            (Health check with metrics)

	// 6. Add your application routes
	router.GET("/api/v1/example", func(c *gin.Context) {
		// Your application logic here

		// Cache usage example - metrics are automatically tracked
		var value string
		err := cacheInstance.Get(ctx, "example_key", &value)
		if err != nil {
			// Cache miss - will be tracked in metrics
			cacheInstance.Set(ctx, "example_key", "example_value", 5*time.Minute)
		}

		// RBAC permission check example - metrics are automatically tracked
		// result, err := policyEngine.CheckPermission(ctx, rbac.PermissionCheckRequest{
		// 	UserID:     "user123",
		// 	TenantID:   "tenant456",
		// 	Resource:   "namespace",
		// 	Action:     "create",
		// 	ResourceID: "prod-namespace",
		// })

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// 7. Start server
	router.Run(":8080")

	// Metrics are now automatically exposed at:
	// http://localhost:8080/metrics           (Prometheus scraping)
	// http://localhost:8080/metrics/json      (JSON API)
	// http://localhost:8080/health            (Health check)
}

// ExampleCollector_directUsage shows direct metrics access without HTTP
func ExampleCollector_directUsage() {
	// Setup (same as above)
	cacheInstance := cache.NewInMemoryCache()
	var policyEngine rbac.PolicyEngine

	collector := metrics.NewCollector(metrics.CollectorConfig{
		Cache:        cacheInstance,
		PolicyEngine: policyEngine,
	})

	collector.Start()
	defer collector.Stop()

	// You can also access the Prometheus registry directly
	registry := collector.Registry()
	_ = registry // Use for custom integrations

	// Or get the HTTP handler for custom routing
	handler := collector.Handler()
	http.Handle("/custom/metrics", handler)
}

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/victoralfred/kube_manager/internal/auth"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/internal/tenant"
	"github.com/victoralfred/kube_manager/pkg/cache"
	"github.com/victoralfred/kube_manager/pkg/config"
	"github.com/victoralfred/kube_manager/pkg/database"
	"github.com/victoralfred/kube_manager/pkg/logger"
	"github.com/victoralfred/kube_manager/pkg/metrics"
	"github.com/victoralfred/kube_manager/pkg/middleware"
)

func main() {
	// Create context for initialization
	ctx := context.Background()

	// Initialize logger
	log := logger.New("info", "kube_manager")
	log.Info("starting kube_manager server")

	// Load configuration from Vault
	log.Info("loading configuration from vault")
	cfg, err := config.LoadWithVault(ctx, log)
	if err != nil {
		log.Fatal("failed to load configuration from vault", err)
	}

	// Validate configuration
	if err := config.ValidateSecureConfig(cfg); err != nil {
		log.Fatal("configuration validation failed", err)
	}

	log.Info("configuration loaded successfully from vault")

	// Connect to database
	log.Info("connecting to database")
	db, err := database.NewPostgres(database.Config{
		DSN:             cfg.Database.DSN(),
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
	})
	if err != nil {
		log.Fatal("failed to connect to database", err)
	}
	defer db.Close()

	// Check database health
	if err := db.Health(ctx); err != nil {
		log.Fatal("database health check failed", err)
	}
	log.Info("database connected successfully")

	// Initialize tenant module
	log.Info("initializing tenant module")
	tenantModule := tenant.NewModule(db, log)

	// Initialize auth module with RSA keys from Vault
	log.Info("initializing auth module with vault RSA keys")
	authModule := auth.NewModule(db, auth.Config{
		PrivateKey:      cfg.JWT.PrivateKey,
		PublicKey:       cfg.JWT.PublicKey,
		KeyID:           cfg.JWT.KeyID,
		AccessTokenTTL:  cfg.JWT.AccessTokenTTL,
		RefreshTokenTTL: cfg.JWT.RefreshTokenTTL,
	}, log)

	// Initialize cache (Redis with in-memory fallback)
	log.Info("initializing cache system")
	var cacheInstance cache.Cache
	if cfg.Redis.Host != "" {
		// Try Redis connection
		redisClient := redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})

		redisCache, err := cache.NewRedisCache(cache.RedisConfig{
			Client:          redisClient,
			FallbackEnabled: true,
			MaxFailures:     5,
			ResetTimeout:    30 * time.Second,
		})

		if err != nil {
			log.Warnf("redis connection failed, falling back to in-memory cache: %v", err)
			cacheInstance = cache.NewInMemoryCache()
		} else {
			log.Info("redis cache initialized successfully")
			cacheInstance = redisCache
		}
	} else {
		log.Info("redis not configured, using in-memory cache")
		cacheInstance = cache.NewInMemoryCache()
	}

	// Initialize RBAC module
	log.Info("initializing RBAC module")
	rbacModule := rbac.NewModule(db, rbac.ModuleConfig{
		Cache:    cacheInstance,
		CacheTTL: 15 * time.Minute,
	}, log)
	log.Info("RBAC module initialized successfully")

	// Initialize metrics collector
	log.Info("initializing prometheus metrics collector")
	metricsCollector := metrics.NewCollector(metrics.CollectorConfig{
		Cache:                cacheInstance,
		PolicyEngine:         rbacModule.GetPolicyEngine(),
		UpdateInterval:       15 * time.Second,
		EnableGoMetrics:      cfg.App.Environment == "production",
		EnableProcessMetrics: cfg.App.Environment == "production",
	})
	metricsCollector.Start()
	defer metricsCollector.Stop()
	log.Info("metrics collector started successfully")

	log.Info("all modules initialized successfully")

	// Set Gin mode
	if cfg.App.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create HTTP router
	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(ginLogger(log))
	router.Use(corsMiddleware())

	// Metrics endpoints (Prometheus and JSON)
	// No authentication required - typically accessed by monitoring systems
	metricsHandler := metrics.NewHandler(metricsCollector)
	metricsHandler.RegisterRoutes(router)
	log.Info("metrics endpoints registered at /metrics and /health")

	// Override default health check with metrics-integrated health check
	// (metricsHandler.RegisterRoutes already registered /health)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Public auth routes (no tenant required)
		authPublic := v1.Group("/auth")
		{
			authPublic.POST("/register", authModule.Handler.Register)
			authPublic.POST("/login", authModule.Handler.Login)
			authPublic.POST("/refresh", authModule.Handler.RefreshToken)
		}

		// Protected auth routes (requires authentication)
		authProtected := v1.Group("/auth")
		authProtected.Use(middleware.RequireAuth(authModule.TokenValidator))
		{
			authProtected.POST("/logout", authModule.Handler.Logout)
			authProtected.GET("/me", authModule.Handler.Me)
			authProtected.POST("/revoke-all", authModule.Handler.RevokeAllSessions)
		}

		// Tenant routes (requires tenant context)
		tenants := v1.Group("/tenants")
		tenants.Use(middleware.OptionalTenantIdentifier())
		{
			// Public tenant operations
			tenants.POST("", tenantModule.Handler.CreateTenant)
			tenants.GET("", tenantModule.Handler.ListTenants)

			// Protected tenant operations (requires auth)
			tenantsProtected := tenants.Group("")
			tenantsProtected.Use(middleware.RequireAuth(authModule.TokenValidator))
			{
				tenantsProtected.GET("/:id", tenantModule.Handler.GetTenant)
				tenantsProtected.PUT("/:id", tenantModule.Handler.UpdateTenant)
				tenantsProtected.DELETE("/:id", tenantModule.Handler.DeleteTenant)
				tenantsProtected.POST("/:id/suspend", tenantModule.Handler.SuspendTenant)
				tenantsProtected.POST("/:id/activate", tenantModule.Handler.ActivateTenant)
				tenantsProtected.GET("/:id/stats", tenantModule.Handler.GetTenantStats)
			}
		}

		// RBAC routes (requires authentication and tenant context)
		rbacGroup := v1.Group("")
		rbacGroup.Use(middleware.RequireAuth(authModule.TokenValidator))
		rbacGroup.Use(middleware.OptionalTenantIdentifier())
		{
			// Role management
			rbacGroup.POST("/roles", rbacModule.Handler.CreateRole)
			rbacGroup.GET("/roles", rbacModule.Handler.ListRoles)
			rbacGroup.GET("/roles/:id", rbacModule.Handler.GetRole)
			rbacGroup.PUT("/roles/:id", rbacModule.Handler.UpdateRole)
			rbacGroup.DELETE("/roles/:id", rbacModule.Handler.DeleteRole)

			// Permission management
			rbacGroup.GET("/permissions", rbacModule.Handler.GetAllPermissions)
			rbacGroup.GET("/roles/:id/permissions", rbacModule.Handler.GetRolePermissions)
			rbacGroup.POST("/roles/:id/permissions", rbacModule.Handler.AssignPermissionsToRole)

			// User role management
			rbacGroup.POST("/users/:id/roles", rbacModule.Handler.AssignRoleToUser)
			rbacGroup.DELETE("/users/:id/roles/:role_id", rbacModule.Handler.RemoveRoleFromUser)
			rbacGroup.GET("/users/:id/roles", rbacModule.Handler.GetUserRoles)
			rbacGroup.GET("/users/:id/permissions", rbacModule.Handler.GetUserPermissions)

			// Resource registration
			rbacGroup.POST("/resources", rbacModule.Handler.RegisterResource)
			rbacGroup.GET("/resources", rbacModule.Handler.ListResources)

			// Permission checking
			rbacGroup.POST("/permissions/check", rbacModule.Handler.CheckPermission)
		}
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.ServerAddr(),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		log.WithField("address", srv.Addr).Info("starting http server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("failed to start server", err)
		}
	}()

	log.WithField("address", srv.Addr).
		WithField("environment", cfg.App.Environment).
		Info("server started successfully")

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server")

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("server forced to shutdown", err)
	}

	// Stop metrics collector (also handled by defer, but explicit for clarity)
	log.Info("stopping metrics collector")
	metricsCollector.Stop()

	// Close secrets manager
	if err := cfg.Close(); err != nil {
		log.Error("failed to close secrets manager", err)
	}

	log.Info("server stopped")
}

// ginLogger is a middleware that logs HTTP requests
func ginLogger(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()

		if raw != "" {
			path = path + "?" + raw
		}

		log.WithField("status", statusCode).
			WithField("method", method).
			WithField("path", path).
			WithField("ip", clientIP).
			WithField("latency", latency.String()).
			Info("http request")
	}
}

// corsMiddleware handles CORS headers
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Tenant-ID")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

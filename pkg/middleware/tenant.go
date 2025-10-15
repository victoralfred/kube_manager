package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/pkg/errors"
)

// TenantContextKey is the context key for tenant ID
type TenantContextKey string

const (
	TenantIDKey TenantContextKey = "tenant_id"
	TenantIDHeader               = "X-Tenant-ID"
)

// TenantIdentifier middleware extracts tenant ID from request
func TenantIdentifier() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID := extractTenantID(c)
		if tenantID == "" {
			c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
			c.Abort()
			return
		}

		// Add tenant ID to context
		ctx := context.WithValue(c.Request.Context(), TenantIDKey, tenantID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// extractTenantID extracts tenant ID from various sources
func extractTenantID(c *gin.Context) string {
	// 1. Check header
	if tenantID := c.GetHeader(TenantIDHeader); tenantID != "" {
		return tenantID
	}

	// 2. Check subdomain
	host := c.Request.Host
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		return parts[0]
	}

	// 3. Check path parameter
	if tenantID := c.Param("tenant_id"); tenantID != "" {
		return tenantID
	}

	// 4. Check query parameter
	if tenantID := c.Query("tenant_id"); tenantID != "" {
		return tenantID
	}

	return ""
}

// GetTenantID retrieves tenant ID from context
func GetTenantID(ctx context.Context) string {
	if tenantID, ok := ctx.Value(TenantIDKey).(string); ok {
		return tenantID
	}
	return ""
}

// OptionalTenantIdentifier middleware extracts tenant ID but doesn't require it
func OptionalTenantIdentifier() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID := extractTenantID(c)
		if tenantID != "" {
			ctx := context.WithValue(c.Request.Context(), TenantIDKey, tenantID)
			c.Request = c.Request.WithContext(ctx)
		}
		c.Next()
	}
}

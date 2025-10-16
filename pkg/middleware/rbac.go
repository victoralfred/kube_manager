package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/pkg/errors"
)

// PermissionChecker defines interface for permission checking
type PermissionChecker interface {
	CheckPermission(ctx context.Context, req PermissionCheckRequest) (PermissionCheckResult, error)
}

// PermissionCheckRequest represents a permission check request
type PermissionCheckRequest struct {
	UserID   string
	TenantID string
	Resource string
	Action   string
	ObjectID string
}

// PermissionCheckResult represents the result of a permission check
type PermissionCheckResult struct {
	Allowed bool
	Reason  string
}

// UserClaims interface for extracting user info from claims
type UserClaims interface {
	GetUserID() string
	GetTenantID() string
}

// RequirePermission middleware checks if the user has the required permission
// Usage: router.GET("/projects", middleware.RequirePermission(policyEngine, "project", "read"))
func RequirePermission(checker PermissionChecker, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get claims from context (set by RequireAuth middleware)
		claimsVal, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Authentication required"))
			c.Abort()
			return
		}

		// Extract user claims
		claims, ok := claimsVal.(UserClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid authentication claims"))
			c.Abort()
			return
		}

		userID := claims.GetUserID()
		tenantID := claims.GetTenantID()

		if userID == "" {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("User ID not found in token"))
			c.Abort()
			return
		}

		if tenantID == "" {
			c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID not found in token"))
			c.Abort()
			return
		}

		// Extract object ID from URL params if available (for object-level permissions)
		objectID := c.Param("id")

		// Check permission
		result, err := checker.CheckPermission(c.Request.Context(), PermissionCheckRequest{
			UserID:   userID,
			TenantID: tenantID,
			Resource: resource,
			Action:   action,
			ObjectID: objectID,
		})

		if err != nil {
			c.JSON(http.StatusInternalServerError, errors.Internal("Permission check failed", err))
			c.Abort()
			return
		}

		if !result.Allowed {
			c.JSON(http.StatusForbidden, errors.PermissionDenied(resource+":"+action))
			c.Abort()
			return
		}

		// Permission granted, continue to handler
		c.Next()
	}
}

// RequireAnyPermission middleware checks if the user has any of the specified permissions
// Usage: router.GET("/admin", middleware.RequireAnyPermission(policyEngine,
//   []Permission{{"user", "manage"}, {"role", "manage"}}))
func RequireAnyPermission(checker PermissionChecker, permissions []struct{ Resource, Action string }) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get claims from context
		claimsVal, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Authentication required"))
			c.Abort()
			return
		}

		claims, ok := claimsVal.(UserClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid authentication claims"))
			c.Abort()
			return
		}

		userID := claims.GetUserID()
		tenantID := claims.GetTenantID()

		if userID == "" || tenantID == "" {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid token claims"))
			c.Abort()
			return
		}

		objectID := c.Param("id")

		// Check each permission until one is granted
		for _, perm := range permissions {
			result, err := checker.CheckPermission(c.Request.Context(), PermissionCheckRequest{
				UserID:   userID,
				TenantID: tenantID,
				Resource: perm.Resource,
				Action:   perm.Action,
				ObjectID: objectID,
			})

			if err != nil {
				continue // Try next permission
			}

			if result.Allowed {
				// At least one permission granted
				c.Next()
				return
			}
		}

		// No permissions granted
		c.JSON(http.StatusForbidden, errors.PermissionDenied("required permissions"))
		c.Abort()
	}
}

// RequireAllPermissions middleware checks if the user has all of the specified permissions
// Usage: router.POST("/projects/:id/deploy", middleware.RequireAllPermissions(policyEngine,
//   []Permission{{"project", "update"}, {"deployment", "create"}}))
func RequireAllPermissions(checker PermissionChecker, permissions []struct{ Resource, Action string }) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get claims from context
		claimsVal, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Authentication required"))
			c.Abort()
			return
		}

		claims, ok := claimsVal.(UserClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid authentication claims"))
			c.Abort()
			return
		}

		userID := claims.GetUserID()
		tenantID := claims.GetTenantID()

		if userID == "" || tenantID == "" {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid token claims"))
			c.Abort()
			return
		}

		objectID := c.Param("id")

		// Check all permissions - all must be granted
		for _, perm := range permissions {
			result, err := checker.CheckPermission(c.Request.Context(), PermissionCheckRequest{
				UserID:   userID,
				TenantID: tenantID,
				Resource: perm.Resource,
				Action:   perm.Action,
				ObjectID: objectID,
			})

			if err != nil {
				c.JSON(http.StatusInternalServerError, errors.Internal("Permission check failed", err))
				c.Abort()
				return
			}

			if !result.Allowed {
				// One permission denied, reject request
				c.JSON(http.StatusForbidden, errors.PermissionDenied(perm.Resource+":"+perm.Action))
				c.Abort()
				return
			}
		}

		// All permissions granted
		c.Next()
	}
}

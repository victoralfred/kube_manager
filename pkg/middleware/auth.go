package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/pkg/errors"
)

// ClaimsValidator defines an interface for token validation
type ClaimsValidator interface {
	VerifyAccessToken(token string) (interface{}, error)
}

// RequireAuth middleware ensures the request has a valid JWT access token
func RequireAuth(validator ClaimsValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Authorization token required"))
			c.Abort()
			return
		}

		claims, err := validator.VerifyAccessToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid or expired token"))
			c.Abort()
			return
		}

		// Set claims in context for downstream handlers
		c.Set("claims", claims)
		c.Set("token", token)

		c.Next()
	}
}

// OptionalAuth middleware validates token if present, but doesn't require it
func OptionalAuth(validator ClaimsValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token != "" {
			claims, err := validator.VerifyAccessToken(token)
			if err == nil {
				c.Set("claims", claims)
				c.Set("token", token)
			}
		}

		c.Next()
	}
}

// RequireRoles middleware ensures the user has at least one of the specified roles
func RequireRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsVal, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, errors.Unauthorized("Authentication required"))
			c.Abort()
			return
		}

		// Type assertion to get user roles
		// This assumes claims has a Roles field - adjust based on your Claims struct
		type RolesProvider interface {
			GetRoles() []string
		}

		provider, ok := claimsVal.(RolesProvider)
		if !ok {
			c.JSON(http.StatusForbidden, errors.Forbidden("Insufficient permissions"))
			c.Abort()
			return
		}

		userRoles := provider.GetRoles()
		if !hasAnyRole(userRoles, roles) {
			c.JSON(http.StatusForbidden, errors.Forbidden("Insufficient permissions"))
			c.Abort()
			return
		}

		c.Next()
	}
}

// extractBearerToken extracts the token from the Authorization header
func extractBearerToken(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// hasAnyRole checks if user has any of the required roles
func hasAnyRole(userRoles, requiredRoles []string) bool {
	roleMap := make(map[string]bool)
	for _, role := range userRoles {
		roleMap[role] = true
	}

	for _, required := range requiredRoles {
		if roleMap[required] {
			return true
		}
	}

	return false
}

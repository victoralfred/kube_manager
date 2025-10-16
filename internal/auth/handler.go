package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/pkg/errors"
)

// RegistrationService interface for handlers
type RegistrationService interface {
	Register(ctx context.Context, req RegisterRequest) (any, error)
	VerifyEmail(ctx context.Context, req VerifyEmailRequest) error
	ResendVerification(ctx context.Context, req ResendVerificationRequest) error
}

// Handler handles HTTP requests for authentication
type Handler struct {
	service             Service
	registrationService RegistrationService
}

// NewHandler creates a new auth handler
func NewHandler(service Service, registrationService RegistrationService) *Handler {
	return &Handler{
		service:             service,
		registrationService: registrationService,
	}
}

// Login handles user login requests
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid request body"))
		return
	}

	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	response, err := h.service.Login(c.Request.Context(), req, ipAddress, userAgent)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, response)
}

// Register handles user registration requests (with tenant creation)
func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid request body"))
		return
	}

	response, err := h.registrationService.Register(c.Request.Context(), req)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusCreated, response)
}

// VerifyEmail handles email verification requests
func (h *Handler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid request body"))
		return
	}

	if err := h.registrationService.VerifyEmail(c.Request.Context(), req); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

// ResendVerification handles resend verification email requests
func (h *Handler) ResendVerification(c *gin.Context) {
	var req ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid request body"))
		return
	}

	if err := h.registrationService.ResendVerification(c.Request.Context(), req); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}

// RefreshToken handles token refresh requests
func (h *Handler) RefreshToken(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid request body"))
		return
	}

	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	tokens, err := h.service.RefreshToken(c.Request.Context(), req.RefreshToken, ipAddress, userAgent)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, tokens)
}

// Logout handles user logout requests
func (h *Handler) Logout(c *gin.Context) {
	// Get refresh token from request
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid request body"))
		return
	}

	if err := h.service.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// Me returns the current authenticated user's information
func (h *Handler) Me(c *gin.Context) {
	// Get user claims from context (set by auth middleware)
	claims := getClaimsFromContext(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Not authenticated"))
		return
	}

	userInfo := UserInfo{
		ID:       claims.UserID,
		TenantID: claims.TenantID,
		Email:    claims.Email,
		Roles:    claims.Roles,
	}

	c.JSON(http.StatusOK, userInfo)
}

// RevokeAllSessions revokes all sessions for the current user
func (h *Handler) RevokeAllSessions(c *gin.Context) {
	claims := getClaimsFromContext(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Not authenticated"))
		return
	}

	if err := h.service.RevokeAllSessions(c.Request.Context(), claims.UserID); err != nil {
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to revoke sessions", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "All sessions revoked successfully"})
}

// Helper functions

func handleAuthError(c *gin.Context, err error) {
	switch err {
	case ErrInvalidCredentials:
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid credentials"))
	case ErrUserNotFound:
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid credentials"))
	case ErrUserInactive:
		c.JSON(http.StatusForbidden, errors.Forbidden("User account is inactive"))
	case ErrUserSuspended:
		c.JSON(http.StatusForbidden, errors.Forbidden("User account is suspended"))
	case ErrEmailAlreadyExists:
		c.JSON(http.StatusConflict, errors.Conflict("Email already exists"))
	case ErrInvalidToken, ErrTokenMalformed:
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid token"))
	case ErrTokenExpired:
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Token has expired"))
	case ErrTokenRevoked:
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Token has been revoked"))
	case ErrTokenNotFound:
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid token"))
	case ErrInvalidTokenType:
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Invalid token type"))
	case ErrTenantNotFound:
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant not specified"))
	case ErrTenantSuspended:
		c.JSON(http.StatusForbidden, errors.Forbidden("Tenant is suspended"))
	default:
		c.JSON(http.StatusInternalServerError, errors.Internal("Internal server error", err))
	}
}

func getClaimsFromContext(c *gin.Context) *Claims {
	if val, exists := c.Get("claims"); exists {
		if claims, ok := val.(*Claims); ok {
			return claims
		}
	}
	return nil
}

// extractTokenFromHeader extracts bearer token from Authorization header
func extractTokenFromHeader(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

package auth

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/victoralfred/kube_manager/internal/tenant"
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
		appErr := extractValidationErrors(err)
		c.JSON(appErr.Status, appErr)
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
		appErr := extractValidationErrors(err)
		c.JSON(appErr.Status, appErr)
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
		appErr := extractValidationErrors(err)
		c.JSON(appErr.Status, appErr)
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
		appErr := extractValidationErrors(err)
		c.JSON(appErr.Status, appErr)
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
		appErr := extractValidationErrors(err)
		c.JSON(appErr.Status, appErr)
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
		appErr := extractValidationErrors(err)
		c.JSON(appErr.Status, appErr)
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
	// Check for tenant-specific errors using errors.Is
	if stderrors.Is(err, tenant.ErrTenantAlreadyExists) {
		c.JSON(http.StatusConflict, errors.Conflict("Organization with this slug already exists. Please choose a different slug."))
		return
	}
	if stderrors.Is(err, tenant.ErrTenantSuspended) {
		c.JSON(http.StatusForbidden, errors.Forbidden("Organization is suspended"))
		return
	}
	if stderrors.Is(err, tenant.ErrTenantNotFound) {
		c.JSON(http.StatusNotFound, errors.NotFound("Organization"))
		return
	}
	if stderrors.Is(err, tenant.ErrInvalidTenantSlug) {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid organization slug. Must be 3-50 alphanumeric characters."))
		return
	}
	if stderrors.Is(err, tenant.ErrUserLimitExceeded) {
		c.JSON(http.StatusForbidden, errors.Forbidden("User limit exceeded for this organization"))
		return
	}

	// Check for auth-specific errors
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
		c.JSON(http.StatusConflict, errors.Conflict("Email address already registered. Please use a different email or try logging in."))
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
		c.JSON(http.StatusBadRequest, errors.BadRequest("Organization not specified"))
	case ErrTenantSuspended:
		c.JSON(http.StatusForbidden, errors.Forbidden("Organization is suspended"))
	default:
		// Check if it's a wrapped error with more context
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, errors.Conflict("Resource already exists"))
			return
		}
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

// extractValidationErrors extracts specific field validation errors from gin binding errors
func extractValidationErrors(err error) *errors.AppError {
	// Check if it's a validator.ValidationErrors type
	var validationErrs validator.ValidationErrors
	if stderrors.As(err, &validationErrs) {
		// Get the first validation error for simplicity
		if len(validationErrs) > 0 {
			fieldErr := validationErrs[0]
			field := fieldErr.Field()
			tag := fieldErr.Tag()

			// Create user-friendly error messages based on validation tag
			var message string
			switch tag {
			case "required":
				message = fmt.Sprintf("Field '%s' is required", field)
			case "email":
				message = fmt.Sprintf("Field '%s' must be a valid email address", field)
			case "min":
				message = fmt.Sprintf("Field '%s' must be at least %s characters", field, fieldErr.Param())
			case "max":
				message = fmt.Sprintf("Field '%s' must be at most %s characters", field, fieldErr.Param())
			case "alphanum":
				message = fmt.Sprintf("Field '%s' must contain only alphanumeric characters", field)
			default:
				message = fmt.Sprintf("Field '%s' failed validation: %s", field, tag)
			}

			return errors.Validation(message)
		}
	}

	// Check if it's a JSON unmarshaling error
	if strings.Contains(err.Error(), "json") || strings.Contains(err.Error(), "unmarshal") {
		return errors.BadRequest("Invalid JSON format in request body")
	}

	// Default error for other binding errors
	return errors.BadRequest(fmt.Sprintf("Invalid request: %v", err))
}

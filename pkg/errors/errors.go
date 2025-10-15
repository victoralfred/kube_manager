package errors

import (
	"fmt"
	"net/http"
)

// AppError represents a custom application error
type AppError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"status"`
	Err     error  `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap implements the errors.Unwrap interface
func (e *AppError) Unwrap() error {
	return e.Err
}

// Common error codes
const (
	ErrCodeInternal          = "INTERNAL_ERROR"
	ErrCodeNotFound          = "NOT_FOUND"
	ErrCodeBadRequest        = "BAD_REQUEST"
	ErrCodeUnauthorized      = "UNAUTHORIZED"
	ErrCodeForbidden         = "FORBIDDEN"
	ErrCodeConflict          = "CONFLICT"
	ErrCodeValidation        = "VALIDATION_ERROR"
	ErrCodeDatabaseError     = "DATABASE_ERROR"
	ErrCodeTenantNotFound    = "TENANT_NOT_FOUND"
	ErrCodeUserNotFound      = "USER_NOT_FOUND"
	ErrCodeInvalidToken      = "INVALID_TOKEN"
	ErrCodePermissionDenied  = "PERMISSION_DENIED"
	ErrCodeResourceExhausted = "RESOURCE_EXHAUSTED"
)

// New creates a new AppError
func New(code, message string, status int) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Status:  status,
	}
}

// Wrap wraps an error with additional context
func Wrap(err error, code, message string, status int) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Status:  status,
		Err:     err,
	}
}

// Common error constructors
func Internal(message string, err error) *AppError {
	return Wrap(err, ErrCodeInternal, message, http.StatusInternalServerError)
}

func NotFound(resource string) *AppError {
	return New(ErrCodeNotFound, fmt.Sprintf("%s not found", resource), http.StatusNotFound)
}

func BadRequest(message string) *AppError {
	return New(ErrCodeBadRequest, message, http.StatusBadRequest)
}

func Unauthorized(message string) *AppError {
	return New(ErrCodeUnauthorized, message, http.StatusUnauthorized)
}

func Forbidden(message string) *AppError {
	return New(ErrCodeForbidden, message, http.StatusForbidden)
}

func Conflict(message string) *AppError {
	return New(ErrCodeConflict, message, http.StatusConflict)
}

func Validation(message string) *AppError {
	return New(ErrCodeValidation, message, http.StatusBadRequest)
}

func DatabaseError(err error) *AppError {
	return Wrap(err, ErrCodeDatabaseError, "Database operation failed", http.StatusInternalServerError)
}

func TenantNotFound(tenantID string) *AppError {
	return New(ErrCodeTenantNotFound, fmt.Sprintf("Tenant %s not found", tenantID), http.StatusNotFound)
}

func UserNotFound(userID string) *AppError {
	return New(ErrCodeUserNotFound, fmt.Sprintf("User %s not found", userID), http.StatusNotFound)
}

func InvalidToken(message string) *AppError {
	return New(ErrCodeInvalidToken, message, http.StatusUnauthorized)
}

func PermissionDenied(action string) *AppError {
	return New(ErrCodePermissionDenied, fmt.Sprintf("Permission denied: %s", action), http.StatusForbidden)
}

func ResourceExhausted(resource string) *AppError {
	return New(ErrCodeResourceExhausted, fmt.Sprintf("%s limit exceeded", resource), http.StatusTooManyRequests)
}

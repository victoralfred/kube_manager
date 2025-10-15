package auth

import "errors"

var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrUserSuspended      = errors.New("user account is suspended")
	ErrEmailAlreadyExists = errors.New("email already exists")

	// Token errors
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenRevoked       = errors.New("token has been revoked")
	ErrTokenNotFound      = errors.New("refresh token not found")
	ErrInvalidTokenType   = errors.New("invalid token type")
	ErrTokenSignature     = errors.New("token signature verification failed")
	ErrTokenMalformed     = errors.New("token is malformed")

	// Tenant errors
	ErrTenantMismatch     = errors.New("tenant mismatch")
	ErrTenantNotFound     = errors.New("tenant not found")
	ErrTenantSuspended    = errors.New("tenant is suspended")

	// General errors
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrSessionExpired     = errors.New("session has expired")
)

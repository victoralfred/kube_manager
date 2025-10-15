package auth

import (
	"context"
)

// TokenValidator wraps the auth service to implement ClaimsValidator interface
type TokenValidator struct {
	service Service
}

// NewTokenValidator creates a new token validator
func NewTokenValidator(service Service) *TokenValidator {
	return &TokenValidator{
		service: service,
	}
}

// VerifyAccessToken verifies an access token and returns claims
func (v *TokenValidator) VerifyAccessToken(token string) (interface{}, error) {
	return v.service.VerifyAccessToken(context.Background(), token)
}

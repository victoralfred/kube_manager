package auth

import (
	"context"
	"time"

	"github.com/victoralfred/kube_manager/pkg/crypto"
	"github.com/victoralfred/kube_manager/pkg/database"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// RegistrationServiceInterface defines the interface for registration operations
// This allows the auth module to work with the registration module without importing it
type RegistrationServiceInterface interface {
	Register(ctx context.Context, req RegisterRequest) (interface{}, error)
	VerifyEmail(ctx context.Context, req VerifyEmailRequest) error
	ResendVerification(ctx context.Context, req ResendVerificationRequest) error
}

// Module holds all auth components
type Module struct {
	Repository       Repository
	VerificationRepo VerificationRepository
	JWTService       *JWTService
	Service          Service
	Handler          *Handler
	TokenValidator   *TokenValidator
}

// Config holds configuration for auth module
type Config struct {
	PrivateKey      *crypto.PrivateKey
	PublicKey       *crypto.PublicKey
	KeyID           string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// NewModule creates a new auth module with all dependencies
// Note: RegistrationService needs to be set separately after tenant and rbac modules are created
func NewModule(db *database.DB, cfg Config, log *logger.Logger) *Module {
	// Create JWT service with RSA keys
	jwtService := NewJWTService(
		cfg.PrivateKey,
		cfg.PublicKey,
		cfg.KeyID,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
	)

	// Create repositories
	repo := NewRepository(db)
	verificationRepo := NewVerificationRepository(db)

	// Create service
	svc := NewService(repo, jwtService, log)

	// Note: Handler and RegistrationService will be set via SetRegistrationService
	// Create token validator for middleware
	validator := NewTokenValidator(svc)

	return &Module{
		Repository:       repo,
		VerificationRepo: verificationRepo,
		JWTService:       jwtService,
		Service:          svc,
		TokenValidator:   validator,
		// Handler set via SetHandler after registration module is created
	}
}

// SetHandler sets the handler with the registration service
// This should be called after the registration module is created
func (m *Module) SetHandler(registrationService RegistrationServiceInterface) {
	m.Handler = NewHandler(m.Service, registrationService)
}

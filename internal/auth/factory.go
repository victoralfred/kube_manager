package auth

import (
	"time"

	"github.com/victoralfred/kube_manager/pkg/crypto"
	"github.com/victoralfred/kube_manager/pkg/database"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Module holds all auth components
type Module struct {
	Repository           Repository
	VerificationRepo     VerificationRepository
	JWTService           *JWTService
	Service              Service
	RegistrationService  RegistrationService
	Handler              *Handler
	TokenValidator       *TokenValidator
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
		// Handler and RegistrationService set via SetRegistrationService
	}
}

// SetRegistrationService sets the registration service and creates the handler
// This should be called after tenant and rbac modules are created to avoid circular dependencies
func (m *Module) SetRegistrationService(registrationService RegistrationService) {
	m.RegistrationService = registrationService
	m.Handler = NewHandler(m.Service, registrationService)
}

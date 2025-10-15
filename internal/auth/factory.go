package auth

import (
	"time"

	"github.com/victoralfred/kube_manager/pkg/crypto"
	"github.com/victoralfred/kube_manager/pkg/database"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Module holds all auth components
type Module struct {
	Repository     Repository
	JWTService     *JWTService
	Service        Service
	Handler        *Handler
	TokenValidator *TokenValidator
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
func NewModule(db *database.DB, cfg Config, log *logger.Logger) *Module {
	// Create JWT service with RSA keys
	jwtService := NewJWTService(
		cfg.PrivateKey,
		cfg.PublicKey,
		cfg.KeyID,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
	)

	// Create repository
	repo := NewRepository(db)

	// Create service
	svc := NewService(repo, jwtService, log)

	// Create handler
	handler := NewHandler(svc)

	// Create token validator for middleware
	validator := NewTokenValidator(svc)

	return &Module{
		Repository:     repo,
		JWTService:     jwtService,
		Service:        svc,
		Handler:        handler,
		TokenValidator: validator,
	}
}

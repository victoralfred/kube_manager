package secrets

import (
	"context"
	"crypto/rsa"
)

// Manager defines interface for secrets management
type Manager interface {
	// GetDatabaseCredentials retrieves database connection credentials
	GetDatabaseCredentials(ctx context.Context) (*DatabaseCredentials, error)

	// GetRedisCredentials retrieves Redis connection credentials
	GetRedisCredentials(ctx context.Context) (*RedisCredentials, error)

	// GetJWTKeys retrieves RSA key pair for JWT signing/verification
	GetJWTKeys(ctx context.Context) (*JWTKeys, error)

	// GetCSRFKey retrieves RSA key pair for CSRF token generation
	GetCSRFKey(ctx context.Context) (*CSRFKey, error)

	// GetAPIKeys retrieves external API keys
	GetAPIKeys(ctx context.Context, service string) (string, error)

	// Health checks secrets manager health
	Health(ctx context.Context) error

	// Close performs cleanup
	Close() error
}

// DatabaseCredentials holds database connection information
type DatabaseCredentials struct {
	Host     string
	Port     int
	Username string
	Password string
	Database string
	SSLMode  string
}

// RedisCredentials holds Redis connection information
type RedisCredentials struct {
	Host     string
	Port     int
	Password string
	DB       int
	UseTLS   bool
}

// JWTKeys holds RSA key pairs for JWT operations
type JWTKeys struct {
	PrivateKey *rsa.PrivateKey // For signing tokens
	PublicKey  *rsa.PublicKey  // For verifying tokens
	KeyID      string          // Key identifier for rotation
}

// CSRFKey holds RSA key pair for CSRF tokens
type CSRFKey struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KeyID      string
}

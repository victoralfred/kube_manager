package auth

import (
	"time"
)

// Claims represents JWT token claims
type Claims struct {
	UserID    string   `json:"user_id"`
	TenantID  string   `json:"tenant_id"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	TokenType string   `json:"token_type"` // "access" or "refresh"
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	Subject   string   `json:"sub"`
	KeyID     string   `json:"kid"` // Key identifier for rotation
}

// TokenPair holds access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"` // "Bearer"
	ExpiresIn    int64     `json:"expires_in"` // Seconds until expiration
	ExpiresAt    time.Time `json:"expires_at"`
}

// RefreshToken represents a stored refresh token
type RefreshToken struct {
	ID        string
	Token     string
	UserID    string
	TenantID  string
	ExpiresAt time.Time
	CreatedAt time.Time
	RevokedAt *time.Time
	IPAddress string
	UserAgent string
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// RegisterRequest represents registration data
type RegisterRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=8"`
	Name        string `json:"name" binding:"required"`
	TenantID    string `json:"tenant_id"`
	TenantSlug  string `json:"tenant_slug"`
	TenantName  string `json:"tenant_name"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	User   UserInfo   `json:"user"`
	Tokens TokenPair  `json:"tokens"`
}

// UserInfo represents basic user information
type UserInfo struct {
	ID       string   `json:"id"`
	TenantID string   `json:"tenant_id"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
}

// IsExpired checks if the refresh token is expired
func (r *RefreshToken) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// IsRevoked checks if the refresh token is revoked
func (r *RefreshToken) IsRevoked() bool {
	return r.RevokedAt != nil
}

// IsValid checks if the refresh token is valid
func (r *RefreshToken) IsValid() bool {
	return !r.IsExpired() && !r.IsRevoked()
}

// GetRoles returns the roles from claims (implements RolesProvider interface)
func (c *Claims) GetRoles() []string {
	return c.Roles
}

// GetUserID returns the user ID from claims (implements UserClaims interface)
func (c *Claims) GetUserID() string {
	return c.UserID
}

// GetTenantID returns the tenant ID from claims (implements UserClaims interface)
func (c *Claims) GetTenantID() string {
	return c.TenantID
}

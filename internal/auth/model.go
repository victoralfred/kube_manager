package auth

import (
	"time"
)

// UserStatus represents the status of a user account
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"     // User is active and email verified
	UserStatusPending   UserStatus = "pending"    // User registered but email not verified
	UserStatusInactive  UserStatus = "inactive"   // User account is inactive
	UserStatusSuspended UserStatus = "suspended"  // User account is suspended
	UserStatusDeleted   UserStatus = "deleted"    // User account is soft-deleted (legacy)
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

// RegisterRequest represents registration data for a new organization and user
// Aligned with OpenAPI specification
type RegisterRequest struct {
	Email      string  `json:"email" binding:"required,email"`
	Password   string  `json:"password" binding:"required,min=8"`
	FirstName  string  `json:"first_name" binding:"required"`
	LastName   string  `json:"last_name" binding:"required"`
	Username   string  `json:"username" binding:"omitempty,min=3,max=50,alphanum"`
	TenantSlug string  `json:"tenant_slug" binding:"required,alphanum,min=3,max=50"`

	// Legacy fields for backward compatibility (will be deprecated)
	OrganizationName string `json:"organization_name,omitempty"`
	Domain           string `json:"domain,omitempty"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LoginResponse represents the login response
// Aligned with OpenAPI specification - flattened structure
type LoginResponse struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	TokenType    string     `json:"token_type"`    // Always "Bearer"
	ExpiresIn    int64      `json:"expires_in"`    // Seconds until access token expiration
	User         UserInfo   `json:"user"`
}

// UserInfo represents basic user information
// Aligned with OpenAPI specification
type UserInfo struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	Email       string                 `json:"email"`
	Username    string                 `json:"username,omitempty"`
	FirstName   string                 `json:"first_name"`
	LastName    string                 `json:"last_name"`
	Phone       *string                `json:"phone,omitempty"`
	AvatarURL   *string                `json:"avatar_url,omitempty"`
	Status      UserStatus             `json:"status"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	LastLoginAt *time.Time             `json:"last_login_at,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Roles       []string               `json:"roles,omitempty"`

	// Legacy field for backward compatibility (will be deprecated)
	EmailVerified bool `json:"email_verified,omitempty"`
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

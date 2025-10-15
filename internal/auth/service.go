package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/victoralfred/kube_manager/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

// Service defines the auth service interface
type Service interface {
	// Authentication
	Login(ctx context.Context, req LoginRequest, ipAddress, userAgent string) (*LoginResponse, error)
	Register(ctx context.Context, req RegisterRequest) (*UserInfo, error)
	RefreshToken(ctx context.Context, refreshToken, ipAddress, userAgent string) (*TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	RevokeAllSessions(ctx context.Context, userID string) error

	// Token verification
	VerifyAccessToken(ctx context.Context, token string) (*Claims, error)
	VerifyRefreshToken(ctx context.Context, token string) (*Claims, error)
}

type service struct {
	repo       Repository
	jwtService *JWTService
	log        *logger.Logger
}

// NewService creates a new auth service
func NewService(repo Repository, jwtService *JWTService, log *logger.Logger) Service {
	return &service{
		repo:       repo,
		jwtService: jwtService,
		log:        log,
	}
}

// Login authenticates a user and returns tokens
func (s *service) Login(ctx context.Context, req LoginRequest, ipAddress, userAgent string) (*LoginResponse, error) {
	// Get tenant ID from context
	tenantID := getTenantIDFromContext(ctx)
	if tenantID == "" {
		return nil, ErrTenantNotFound
	}

	// Get user by email
	user, err := s.repo.GetUserByEmail(ctx, tenantID, req.Email)
	if err != nil {
		if err == ErrUserNotFound {
			s.log.WithField("email", req.Email).Warn("login attempt with non-existent email")
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.log.WithField("user_id", user.ID).Warn("invalid password attempt")
		return nil, ErrInvalidCredentials
	}

	// Check user status
	if user.Status != "active" {
		if user.Status == "suspended" {
			return nil, ErrUserSuspended
		}
		return nil, ErrUserInactive
	}

	// Generate token pair
	tokens, err := s.jwtService.GenerateTokenPair(user.ID, user.TenantID, user.Email, user.Roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store refresh token
	refreshToken := &RefreshToken{
		ID:        uuid.New().String(),
		Token:     tokens.RefreshToken,
		UserID:    user.ID,
		TenantID:  user.TenantID,
		ExpiresAt: time.Now().Add(s.jwtService.GetRefreshTokenTTL()),
		CreatedAt: time.Now(),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.repo.StoreRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	s.log.WithField("user_id", user.ID).WithField("tenant_id", user.TenantID).Info("user logged in successfully")

	return &LoginResponse{
		User: UserInfo{
			ID:       user.ID,
			TenantID: user.TenantID,
			Email:    user.Email,
			Name:     user.Name,
			Roles:    user.Roles,
		},
		Tokens: *tokens,
	}, nil
}

// Register creates a new user account
func (s *service) Register(ctx context.Context, req RegisterRequest) (*UserInfo, error) {
	// Get tenant ID from context or request
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = getTenantIDFromContext(ctx)
	}

	if tenantID == "" {
		return nil, ErrTenantNotFound
	}

	// Check if email already exists
	existing, err := s.repo.GetUserByEmail(ctx, tenantID, req.Email)
	if err != nil && err != ErrUserNotFound {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	if existing != nil {
		return nil, ErrEmailAlreadyExists
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	now := time.Now()
	user := &UserCredentials{
		ID:           uuid.New().String(),
		TenantID:     tenantID,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		Name:         req.Name,
		Status:       "active",
		Roles:        []string{},
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.log.WithField("user_id", user.ID).WithField("tenant_id", user.TenantID).Info("user registered successfully")

	return &UserInfo{
		ID:       user.ID,
		TenantID: user.TenantID,
		Email:    user.Email,
		Name:     user.Name,
		Roles:    user.Roles,
	}, nil
}

// RefreshToken generates a new access token from a refresh token
func (s *service) RefreshToken(ctx context.Context, refreshTokenStr, ipAddress, userAgent string) (*TokenPair, error) {
	// Verify refresh token signature and claims
	claims, err := s.jwtService.VerifyToken(refreshTokenStr)
	if err != nil {
		return nil, err
	}

	// Verify it's a refresh token
	if claims.TokenType != "refresh" {
		return nil, ErrInvalidTokenType
	}

	// Get stored refresh token
	storedToken, err := s.repo.GetRefreshToken(ctx, refreshTokenStr)
	if err != nil {
		return nil, err
	}

	// Validate stored token
	if !storedToken.IsValid() {
		if storedToken.IsRevoked() {
			return nil, ErrTokenRevoked
		}
		return nil, ErrTokenExpired
	}

	// Get user to get current roles
	user, err := s.repo.GetUserByEmail(ctx, claims.TenantID, claims.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate new token pair
	tokens, err := s.jwtService.GenerateTokenPair(user.ID, user.TenantID, user.Email, user.Roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store new refresh token
	newRefreshToken := &RefreshToken{
		ID:        uuid.New().String(),
		Token:     tokens.RefreshToken,
		UserID:    user.ID,
		TenantID:  user.TenantID,
		ExpiresAt: time.Now().Add(s.jwtService.GetRefreshTokenTTL()),
		CreatedAt: time.Now(),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.repo.StoreRefreshToken(ctx, newRefreshToken); err != nil {
		return nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	// Revoke old refresh token
	if err := s.repo.RevokeRefreshToken(ctx, refreshTokenStr); err != nil {
		s.log.Error("failed to revoke old refresh token", err)
		// Continue even if revocation fails
	}

	s.log.WithField("user_id", user.ID).Info("token refreshed successfully")

	return tokens, nil
}

// Logout revokes a refresh token
func (s *service) Logout(ctx context.Context, refreshToken string) error {
	if err := s.repo.RevokeRefreshToken(ctx, refreshToken); err != nil {
		if err == ErrTokenNotFound {
			// Token already revoked or doesn't exist, treat as success
			return nil
		}
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	s.log.Info("user logged out successfully")
	return nil
}

// RevokeAllSessions revokes all refresh tokens for a user
func (s *service) RevokeAllSessions(ctx context.Context, userID string) error {
	if err := s.repo.RevokeAllUserTokens(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}

	s.log.WithField("user_id", userID).Info("all user sessions revoked")
	return nil
}

// VerifyAccessToken verifies an access token
func (s *service) VerifyAccessToken(ctx context.Context, token string) (*Claims, error) {
	claims, err := s.jwtService.VerifyToken(token)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "access" {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// VerifyRefreshToken verifies a refresh token
func (s *service) VerifyRefreshToken(ctx context.Context, token string) (*Claims, error) {
	claims, err := s.jwtService.VerifyToken(token)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "refresh" {
		return nil, ErrInvalidTokenType
	}

	// Also check if it's revoked in database
	storedToken, err := s.repo.GetRefreshToken(ctx, token)
	if err != nil {
		return nil, err
	}

	if !storedToken.IsValid() {
		if storedToken.IsRevoked() {
			return nil, ErrTokenRevoked
		}
		return nil, ErrTokenExpired
	}

	return claims, nil
}

// Helper function to get tenant ID from context
func getTenantIDFromContext(ctx context.Context) string {
	if val := ctx.Value("tenant_id"); val != nil {
		if tenantID, ok := val.(string); ok {
			return tenantID
		}
	}
	return ""
}

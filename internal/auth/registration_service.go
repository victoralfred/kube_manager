package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/internal/tenant"
	"github.com/victoralfred/kube_manager/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

// RegistrationService handles complete user and tenant registration
type RegistrationService interface {
	Register(ctx context.Context, req RegisterRequest) (*RegistrationResponse, error)
	VerifyEmail(ctx context.Context, req VerifyEmailRequest) error
	ResendVerification(ctx context.Context, req ResendVerificationRequest) error
}

type registrationService struct {
	authRepo         Repository
	verificationRepo VerificationRepository
	tenantService    tenant.Service
	rbacService      rbac.Service
	jwtService       *JWTService
	log              *logger.Logger
}

// NewRegistrationService creates a new registration service
func NewRegistrationService(
	authRepo Repository,
	verificationRepo VerificationRepository,
	tenantService tenant.Service,
	rbacService rbac.Service,
	jwtService *JWTService,
	log *logger.Logger,
) RegistrationService {
	return &registrationService{
		authRepo:         authRepo,
		verificationRepo: verificationRepo,
		tenantService:    tenantService,
		rbacService:      rbacService,
		jwtService:       jwtService,
		log:              log,
	}
}

// RegistrationResponse represents the response after successful registration
type RegistrationResponse struct {
	User   UserInfo   `json:"user"`
	Tokens *TokenPair `json:"tokens,omitempty"`
}

// Register creates a new organization (tenant) with the first user as admin
func (s *registrationService) Register(ctx context.Context, req RegisterRequest) (*RegistrationResponse, error) {
	// Validate request
	if err := s.validateRegisterRequest(req); err != nil {
		return nil, err
	}

	// Step 1: Create tenant
	tenantReq := tenant.CreateTenantRequest{
		Name:         req.OrganizationName,
		Slug:         req.Domain,
		ContactName:  req.FirstName + " " + req.LastName,
		ContactEmail: req.Email,
		MaxUsers:     100,                // Default limit
		MaxStorage:   10737418240,        // 10GB default
		Settings:     map[string]interface{}{},
	}

	newTenant, err := s.tenantService.CreateTenant(ctx, tenantReq)
	if err != nil {
		s.log.Error("failed to create tenant", err)
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	s.log.WithField("tenant_id", newTenant.ID).Info("tenant created")

	// Step 2: Create user
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	userID := uuid.New().String()
	user := &UserCredentials{
		ID:           userID,
		TenantID:     newTenant.ID,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Status:       "active",
		Roles:        []string{},
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.authRepo.CreateUser(ctx, user); err != nil {
		s.log.Error("failed to create user", err)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.log.WithField("user_id", userID).WithField("tenant_id", newTenant.ID).Info("user created")

	// Step 3: Get Admin role (created by database trigger)
	roles, err := s.rbacService.ListRoles(ctx, newTenant.ID, true)
	if err != nil {
		s.log.Error("failed to list roles", err)
		return nil, fmt.Errorf("failed to get admin role: %w", err)
	}

	var adminRoleID string
	for _, role := range roles {
		if role.Slug == "admin" && role.IsSystem {
			adminRoleID = role.ID
			break
		}
	}

	if adminRoleID == "" {
		s.log.Error("admin role not found", nil)
		return nil, fmt.Errorf("admin role not found (database trigger may have failed)")
	}

	// Step 4: Assign Admin role to user
	if err := s.rbacService.AssignRoleToUser(ctx, userID, adminRoleID, newTenant.ID, userID); err != nil {
		s.log.Error("failed to assign admin role", err)
		return nil, fmt.Errorf("failed to assign admin role: %w", err)
	}

	s.log.WithField("user_id", userID).WithField("role_id", adminRoleID).Info("admin role assigned")

	// Step 5: Generate email verification token
	verificationToken, err := s.generateVerificationToken(ctx, userID)
	if err != nil {
		s.log.Error("failed to generate verification token", err)
		// Don't fail registration, just log the error
		s.log.Warn("user registered but email verification token creation failed")
	}

	// Step 6: Send verification email (async - implement later with email service)
	if verificationToken != "" {
		s.log.WithField("user_id", userID).Info("email verification token generated (email sending not yet implemented)")
	}

	// Step 7: Generate JWT tokens
	user.Roles = []string{"admin"}
	tokens, err := s.jwtService.GenerateTokenPair(userID, newTenant.ID, req.Email, user.Roles)
	if err != nil {
		s.log.Error("failed to generate tokens", err)
		// Don't fail registration, return without tokens
		return &RegistrationResponse{
			User: UserInfo{
				ID:            userID,
				TenantID:      newTenant.ID,
				Email:         req.Email,
				FirstName:     req.FirstName,
				LastName:      req.LastName,
				EmailVerified: false,
				Roles:         []string{"admin"},
			},
		}, nil
	}

	s.log.WithField("user_id", userID).WithField("tenant_id", newTenant.ID).Info("registration completed successfully")

	return &RegistrationResponse{
		User: UserInfo{
			ID:            userID,
			TenantID:      newTenant.ID,
			Email:         req.Email,
			FirstName:     req.FirstName,
			LastName:      req.LastName,
			EmailVerified: false,
			Roles:         []string{"admin"},
		},
		Tokens: tokens,
	}, nil
}

// VerifyEmail verifies a user's email using the verification token
func (s *registrationService) VerifyEmail(ctx context.Context, req VerifyEmailRequest) error {
	// Get verification token
	token, err := s.verificationRepo.GetVerificationToken(ctx, req.Token)
	if err != nil {
		return fmt.Errorf("invalid verification token: %w", err)
	}

	// Check if token is valid
	if !token.IsValid() {
		if token.IsExpired() {
			return fmt.Errorf("verification token has expired")
		}
		if token.IsVerified() {
			return fmt.Errorf("email already verified")
		}
		return fmt.Errorf("invalid verification token")
	}

	// Mark as verified
	if err := s.verificationRepo.MarkAsVerified(ctx, req.Token); err != nil {
		s.log.Error("failed to mark token as verified", err)
		return fmt.Errorf("failed to verify email: %w", err)
	}

	s.log.WithField("user_id", token.UserID).Info("email verified successfully")
	return nil
}

// ResendVerification resends the verification email
func (s *registrationService) ResendVerification(ctx context.Context, req ResendVerificationRequest) error {
	// Find user by email (need tenant context)
	// For now, we'll implement a basic version
	// This would be enhanced with proper tenant resolution

	return fmt.Errorf("not implemented yet")
}

// Helper functions

func (s *registrationService) validateRegisterRequest(req RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" || len(req.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if req.FirstName == "" {
		return fmt.Errorf("first name is required")
	}
	if req.LastName == "" {
		return fmt.Errorf("last name is required")
	}
	if req.OrganizationName == "" {
		return fmt.Errorf("organization name is required")
	}
	if req.Domain == "" || len(req.Domain) < 3 {
		return fmt.Errorf("domain must be at least 3 characters")
	}
	return nil
}

func (s *registrationService) generateVerificationToken(ctx context.Context, userID string) (string, error) {
	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	tokenString := hex.EncodeToString(tokenBytes)

	// Create verification token
	token := &EmailVerificationToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     tokenString,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour expiry
		CreatedAt: time.Now(),
	}

	if err := s.verificationRepo.CreateVerificationToken(ctx, token); err != nil {
		return "", fmt.Errorf("failed to store verification token: %w", err)
	}

	return tokenString, nil
}

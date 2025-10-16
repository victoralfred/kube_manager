package invitation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/victoralfred/kube_manager/internal/auth"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/internal/tenant"
	"github.com/victoralfred/kube_manager/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

// Service defines the interface for invitation business logic
type Service interface {
	InviteUser(ctx context.Context, tenantID, actorID string, req InviteUserRequest) (*InvitationResponse, error)
	AcceptInvitation(ctx context.Context, req AcceptInvitationRequest) (*auth.UserInfo, error)
	RevokeInvitation(ctx context.Context, tenantID, invitationID, actorID string) error
	GetInvitation(ctx context.Context, token string) (*InvitationResponse, error)
	ListInvitations(ctx context.Context, filter ListInvitationsFilter) ([]*InvitationResponse, int, error)
}

type service struct {
	repo          Repository
	authRepo      auth.Repository
	tenantService tenant.Service
	rbacService   rbac.Service
	log           *logger.Logger
}

// NewService creates a new invitation service
func NewService(
	repo Repository,
	authRepo auth.Repository,
	tenantService tenant.Service,
	rbacService rbac.Service,
	log *logger.Logger,
) Service {
	return &service{
		repo:          repo,
		authRepo:      authRepo,
		tenantService: tenantService,
		rbacService:   rbacService,
		log:           log,
	}
}

// InviteUser sends an invitation to a user
func (s *service) InviteUser(ctx context.Context, tenantID, actorID string, req InviteUserRequest) (*InvitationResponse, error) {
	// Validate request
	if err := s.validateInviteRequest(req); err != nil {
		return nil, err
	}

	// Check if user already exists
	existingUser, err := s.authRepo.GetUserByEmail(ctx, tenantID, req.Email)
	if err == nil && existingUser != nil {
		return nil, fmt.Errorf("user with this email already exists in this organization")
	}

	// Check if pending invitation already exists
	exists, err := s.repo.ExistsPendingForEmail(ctx, tenantID, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing invitations: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("pending invitation already exists for this email")
	}

	// Validate role IDs belong to tenant
	for _, roleID := range req.RoleIDs {
		role, err := s.rbacService.GetRole(ctx, tenantID, roleID)
		if err != nil || role == nil {
			return nil, fmt.Errorf("invalid role ID: %s", roleID)
		}
	}

	// Generate invitation token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Create invitation
	now := time.Now()
	invitation := &Invitation{
		ID:         uuid.New().String(),
		TenantID:   tenantID,
		Email:      req.Email,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Token:      token,
		RoleIDs:    req.RoleIDs,
		InvitedBy:  actorID,
		Status:     StatusPending,
		Message:    req.Message,
		ExpiresAt:  now.Add(7 * 24 * time.Hour), // 7 days expiry
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := s.repo.Create(ctx, invitation); err != nil {
		s.log.Error("failed to create invitation", err)
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}

	s.log.WithField("invitation_id", invitation.ID).WithField("email", req.Email).Info("invitation created")

	// Get inviter info and role names for response
	inviter, _ := s.authRepo.GetUserByID(ctx, actorID)
	inviterName := "Admin"
	if inviter != nil {
		inviterName = inviter.FirstName + " " + inviter.LastName
	}

	tenantInfo, _ := s.tenantService.GetTenant(ctx, tenantID)
	tenantName := "Organization"
	if tenantInfo != nil {
		tenantName = tenantInfo.Name
	}

	roleNames := []string{}
	for _, roleID := range req.RoleIDs {
		if role, err := s.rbacService.GetRole(ctx, tenantID, roleID); err == nil && role != nil {
			roleNames = append(roleNames, role.Name)
		}
	}

	return &InvitationResponse{
		ID:            invitation.ID,
		TenantID:      tenantID,
		TenantName:    tenantName,
		Email:         req.Email,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		RoleNames:     roleNames,
		InvitedByName: inviterName,
		Status:        string(StatusPending),
		Message:       req.Message,
		ExpiresAt:     invitation.ExpiresAt,
		CreatedAt:     invitation.CreatedAt,
	}, nil
}

// AcceptInvitation accepts an invitation and creates a user account
func (s *service) AcceptInvitation(ctx context.Context, req AcceptInvitationRequest) (*auth.UserInfo, error) {
	// Get invitation by token
	invitation, err := s.repo.GetByToken(ctx, req.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid invitation token: %w", err)
	}

	// Validate invitation
	if !invitation.IsValid() {
		if invitation.IsExpired() {
			return nil, fmt.Errorf("invitation has expired")
		}
		if invitation.IsAccepted() {
			return nil, fmt.Errorf("invitation has already been accepted")
		}
		if invitation.IsRevoked() {
			return nil, fmt.Errorf("invitation has been revoked")
		}
		return nil, fmt.Errorf("invalid invitation")
	}

	// Check if user already exists
	existingUser, err := s.authRepo.GetUserByEmail(ctx, invitation.TenantID, invitation.Email)
	if err == nil && existingUser != nil {
		return nil, fmt.Errorf("user with this email already exists")
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Use names from request if provided, otherwise use from invitation
	firstName := req.FirstName
	if firstName == "" {
		firstName = invitation.FirstName
	}
	lastName := req.LastName
	if lastName == "" {
		lastName = invitation.LastName
	}

	// Create user
	now := time.Now()
	userID := uuid.New().String()
	user := &auth.UserCredentials{
		ID:           userID,
		TenantID:     invitation.TenantID,
		Email:        invitation.Email,
		PasswordHash: string(passwordHash),
		FirstName:    firstName,
		LastName:     lastName,
		Status:       "active",
		Roles:        []string{},
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.authRepo.CreateUser(ctx, user); err != nil {
		s.log.Error("failed to create user from invitation", err)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.log.WithField("user_id", userID).WithField("invitation_id", invitation.ID).Info("user created from invitation")

	// Assign roles to user
	for _, roleID := range invitation.RoleIDs {
		if err := s.rbacService.AssignRoleToUser(ctx, userID, roleID, invitation.TenantID, invitation.InvitedBy); err != nil {
			s.log.Error("failed to assign role to user", err)
			// Continue with other roles even if one fails
		}
	}

	// Mark invitation as accepted
	if err := s.repo.MarkAsAccepted(ctx, req.Token); err != nil {
		s.log.Error("failed to mark invitation as accepted", err)
		// User is already created, so don't fail here
	}

	// Get role slugs for response
	roleNames := []string{}
	for _, roleID := range invitation.RoleIDs {
		if role, err := s.rbacService.GetRole(ctx, invitation.TenantID, roleID); err == nil && role != nil {
			roleNames = append(roleNames, role.Slug)
		}
	}

	s.log.WithField("user_id", userID).Info("invitation accepted successfully")

	return &auth.UserInfo{
		ID:            userID,
		TenantID:      invitation.TenantID,
		Email:         invitation.Email,
		FirstName:     firstName,
		LastName:      lastName,
		EmailVerified: false,
		Roles:         roleNames,
	}, nil
}

// RevokeInvitation revokes a pending invitation
func (s *service) RevokeInvitation(ctx context.Context, tenantID, invitationID, actorID string) error {
	// Get invitation
	invitation, err := s.repo.GetByID(ctx, invitationID)
	if err != nil {
		return fmt.Errorf("invitation not found: %w", err)
	}

	// Verify tenant ownership
	if invitation.TenantID != tenantID {
		return fmt.Errorf("invitation not found")
	}

	// Check if already accepted or revoked
	if invitation.Status != StatusPending {
		return fmt.Errorf("can only revoke pending invitations")
	}

	// Mark as revoked
	if err := s.repo.MarkAsRevoked(ctx, invitationID); err != nil {
		s.log.Error("failed to revoke invitation", err)
		return fmt.Errorf("failed to revoke invitation: %w", err)
	}

	s.log.WithField("invitation_id", invitationID).WithField("actor_id", actorID).Info("invitation revoked")
	return nil
}

// GetInvitation retrieves an invitation by token (public endpoint)
func (s *service) GetInvitation(ctx context.Context, token string) (*InvitationResponse, error) {
	invitation, err := s.repo.GetByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invitation not found: %w", err)
	}

	// Get tenant name
	tenantInfo, _ := s.tenantService.GetTenant(ctx, invitation.TenantID)
	tenantName := "Organization"
	if tenantInfo != nil {
		tenantName = tenantInfo.Name
	}

	// Get inviter name
	inviter, _ := s.authRepo.GetUserByID(ctx, invitation.InvitedBy)
	inviterName := "Admin"
	if inviter != nil {
		inviterName = inviter.FirstName + " " + inviter.LastName
	}

	// Get role names
	roleNames := []string{}
	for _, roleID := range invitation.RoleIDs {
		if role, err := s.rbacService.GetRole(ctx, invitation.TenantID, roleID); err == nil && role != nil {
			roleNames = append(roleNames, role.Name)
		}
	}

	return &InvitationResponse{
		ID:            invitation.ID,
		TenantID:      invitation.TenantID,
		TenantName:    tenantName,
		Email:         invitation.Email,
		FirstName:     invitation.FirstName,
		LastName:      invitation.LastName,
		RoleNames:     roleNames,
		InvitedByName: inviterName,
		Status:        string(invitation.Status),
		Message:       invitation.Message,
		ExpiresAt:     invitation.ExpiresAt,
		CreatedAt:     invitation.CreatedAt,
	}, nil
}

// ListInvitations lists invitations for a tenant
func (s *service) ListInvitations(ctx context.Context, filter ListInvitationsFilter) ([]*InvitationResponse, int, error) {
	invitations, total, err := s.repo.List(ctx, filter)
	if err != nil {
		s.log.Error("failed to list invitations", err)
		return nil, 0, fmt.Errorf("failed to list invitations: %w", err)
	}

	responses := make([]*InvitationResponse, 0, len(invitations))
	for _, inv := range invitations {
		// Get tenant name
		tenantInfo, _ := s.tenantService.GetTenant(ctx, inv.TenantID)
		tenantName := "Organization"
		if tenantInfo != nil {
			tenantName = tenantInfo.Name
		}

		// Get inviter name
		inviter, _ := s.authRepo.GetUserByID(ctx, inv.InvitedBy)
		inviterName := "Admin"
		if inviter != nil {
			inviterName = inviter.FirstName + " " + inviter.LastName
		}

		// Get role names
		roleNames := []string{}
		for _, roleID := range inv.RoleIDs {
			if role, err := s.rbacService.GetRole(ctx, inv.TenantID, roleID); err == nil && role != nil {
				roleNames = append(roleNames, role.Name)
			}
		}

		responses = append(responses, &InvitationResponse{
			ID:            inv.ID,
			TenantID:      inv.TenantID,
			TenantName:    tenantName,
			Email:         inv.Email,
			FirstName:     inv.FirstName,
			LastName:      inv.LastName,
			RoleNames:     roleNames,
			InvitedByName: inviterName,
			Status:        string(inv.Status),
			Message:       inv.Message,
			ExpiresAt:     inv.ExpiresAt,
			CreatedAt:     inv.CreatedAt,
		})
	}

	return responses, total, nil
}

// Helper functions

func (s *service) validateInviteRequest(req InviteUserRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if len(req.RoleIDs) == 0 {
		return fmt.Errorf("at least one role must be specified")
	}
	return nil
}

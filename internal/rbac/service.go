package rbac

import (
	"context"
	"fmt"

	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Service provides business logic for RBAC operations
type Service interface {
	// Role management
	CreateRole(ctx context.Context, tenantID string, req CreateRoleRequest) (*Role, error)
	UpdateRole(ctx context.Context, tenantID, roleID string, req UpdateRoleRequest) (*Role, error)
	DeleteRole(ctx context.Context, tenantID, roleID string) error
	GetRole(ctx context.Context, tenantID, roleID string) (*Role, error)
	ListRoles(ctx context.Context, tenantID string, includeSystem bool) ([]*Role, error)

	// Permission management
	GetAllPermissions(ctx context.Context) ([]Permission, error)
	GetRolePermissions(ctx context.Context, roleID string) ([]Permission, error)
	AssignPermissionsToRole(ctx context.Context, roleID string, permissionIDs []string) error

	// User role management
	AssignRoleToUser(ctx context.Context, userID, roleID, tenantID, actorID string) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID, tenantID string) error
	GetUserRoles(ctx context.Context, userID, tenantID string) ([]Role, error)
	GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error)

	// Resource registration (tenant admin)
	RegisterResource(ctx context.Context, tenantID string, req RegisterResourceRequest) (*ResourceDefinition, error)
	ListResources(ctx context.Context, scope PermissionScope) ([]ResourceDefinition, error)

	// Permission checking (delegates to policy engine)
	CheckPermission(ctx context.Context, userID, tenantID, resource, action, objectID string) (PermissionCheckResult, error)
}

// service implements Service interface
type service struct {
	repo         Repository
	policyEngine PolicyEngine
	registry     *ResourceRegistry
	log          *logger.Logger
}

// NewService creates a new RBAC service
func NewService(repo Repository, policyEngine PolicyEngine, registry *ResourceRegistry, log *logger.Logger) Service {
	return &service{
		repo:         repo,
		policyEngine: policyEngine,
		registry:     registry,
		log:          log,
	}
}

// CreateRole creates a new custom role
func (s *service) CreateRole(ctx context.Context, tenantID string, req CreateRoleRequest) (*Role, error) {
	// Validate request
	if err := s.validateCreateRoleRequest(req); err != nil {
		return nil, err
	}

	// Check if role with same slug already exists
	existing, err := s.repo.GetRoleBySlug(ctx, tenantID, req.Slug)
	if err == nil && existing != nil {
		return nil, ErrRoleAlreadyExists
	}

	// Create role entity
	role := &Role{
		TenantID:    &tenantID,
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		RoleType:    RoleTypeCustom,
		IsSystem:    false,
	}

	// Create role in database
	if err := s.repo.CreateRole(ctx, role); err != nil {
		s.log.Error("failed to create role", err)
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	// Assign permissions if provided
	if len(req.PermissionIDs) > 0 {
		if err := s.repo.AssignPermissionsToRole(ctx, role.ID, req.PermissionIDs); err != nil {
			s.log.Error("failed to assign permissions to role", err)
			// Role created but permissions failed - log warning but continue
			s.log.Warn("role created but permission assignment failed")
		}
	}

	// Invalidate role cache (for users who might get this role)
	if err := s.policyEngine.InvalidateRoleCache(ctx, role.ID); err != nil {
		s.log.WithField("error", err).Warn("failed to invalidate role cache")
	}

	s.log.WithField("role_id", role.ID).WithField("tenant_id", tenantID).Info("role created successfully")
	return role, nil
}

// UpdateRole updates an existing role
func (s *service) UpdateRole(ctx context.Context, tenantID, roleID string, req UpdateRoleRequest) (*Role, error) {
	// Get existing role
	role, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		return nil, ErrRoleNotFound
	}

	// Verify tenant ownership
	if role.TenantID == nil || *role.TenantID != tenantID {
		return nil, ErrRoleNotFound
	}

	// Prevent modification of system roles
	if role.IsSystem {
		return nil, ErrSystemRoleProtected
	}

	// Update fields if provided
	if req.Name != nil {
		role.Name = *req.Name
	}
	if req.Description != nil {
		role.Description = *req.Description
	}

	// Update role in database
	if err := s.repo.UpdateRole(ctx, role); err != nil {
		s.log.Error("failed to update role", err)
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	// Update permissions if provided
	if req.PermissionIDs != nil {
		// Remove all existing permissions
		if err := s.repo.RemoveAllPermissionsFromRole(ctx, roleID); err != nil {
			s.log.Error("failed to remove old permissions", err)
			return nil, fmt.Errorf("failed to update permissions: %w", err)
		}

		// Assign new permissions
		if len(req.PermissionIDs) > 0 {
			if err := s.repo.AssignPermissionsToRole(ctx, roleID, req.PermissionIDs); err != nil {
				s.log.Error("failed to assign new permissions", err)
				return nil, fmt.Errorf("failed to update permissions: %w", err)
			}
		}
	}

	// Invalidate caches for all users with this role
	if err := s.policyEngine.InvalidateRoleCache(ctx, roleID); err != nil {
		s.log.WithField("error", err).Warn("failed to invalidate role cache")
	}

	s.log.WithField("role_id", roleID).Info("role updated successfully")
	return role, nil
}

// DeleteRole deletes a custom role
func (s *service) DeleteRole(ctx context.Context, tenantID, roleID string) error {
	// Get existing role
	role, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		return ErrRoleNotFound
	}

	// Verify tenant ownership
	if role.TenantID == nil || *role.TenantID != tenantID {
		return ErrRoleNotFound
	}

	// Prevent deletion of system roles
	if role.IsSystem {
		return ErrSystemRoleProtected
	}

	// Delete role (cascades to role_permissions and user_roles)
	if err := s.repo.DeleteRole(ctx, roleID); err != nil {
		s.log.Error("failed to delete role", err)
		return fmt.Errorf("failed to delete role: %w", err)
	}

	// Invalidate caches for all users who had this role
	if err := s.policyEngine.InvalidateRoleCache(ctx, roleID); err != nil {
		s.log.WithField("error", err).Warn("failed to invalidate role cache")
	}

	s.log.WithField("role_id", roleID).Info("role deleted successfully")
	return nil
}

// GetRole retrieves a role by ID
func (s *service) GetRole(ctx context.Context, tenantID, roleID string) (*Role, error) {
	role, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		return nil, ErrRoleNotFound
	}

	// Verify tenant ownership (system roles are visible to all tenants)
	if role.TenantID != nil && *role.TenantID != tenantID {
		return nil, ErrRoleNotFound
	}

	return role, nil
}

// ListRoles lists all roles for a tenant
func (s *service) ListRoles(ctx context.Context, tenantID string, includeSystem bool) ([]*Role, error) {
	filter := ListRolesFilter{
		TenantID:      tenantID,
		IncludeSystem: includeSystem,
	}

	roles, _, err := s.repo.ListRoles(ctx, filter)
	if err != nil {
		s.log.Error("failed to list roles", err)
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	return roles, nil
}

// GetAllPermissions retrieves all available permission templates
func (s *service) GetAllPermissions(ctx context.Context) ([]Permission, error) {
	permissions, err := s.repo.GetAllPermissions(ctx)
	if err != nil {
		s.log.Error("failed to get all permissions", err)
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}

	return permissions, nil
}

// GetRolePermissions retrieves permissions assigned to a role
func (s *service) GetRolePermissions(ctx context.Context, roleID string) ([]Permission, error) {
	permissions, err := s.repo.GetRolePermissions(ctx, roleID)
	if err != nil {
		s.log.Error("failed to get role permissions", err)
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	return permissions, nil
}

// AssignPermissionsToRole assigns permissions to a role
func (s *service) AssignPermissionsToRole(ctx context.Context, roleID string, permissionIDs []string) error {
	// Verify role exists
	role, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		return ErrRoleNotFound
	}

	// Prevent modification of system roles
	if role.IsSystem {
		return ErrSystemRoleProtected
	}

	// Validate permission IDs exist
	// This will be validated by foreign key constraint in the database

	// Remove existing permissions
	if err := s.repo.RemoveAllPermissionsFromRole(ctx, roleID); err != nil {
		s.log.Error("failed to remove existing permissions", err)
		return fmt.Errorf("failed to update permissions: %w", err)
	}

	// Assign new permissions
	if len(permissionIDs) > 0 {
		if err := s.repo.AssignPermissionsToRole(ctx, roleID, permissionIDs); err != nil {
			s.log.Error("failed to assign permissions", err)
			return fmt.Errorf("failed to assign permissions: %w", err)
		}
	}

	// Invalidate caches for all users with this role
	if err := s.policyEngine.InvalidateRoleCache(ctx, roleID); err != nil {
		s.log.WithField("error", err).Warn("failed to invalidate role cache")
	}

	s.log.WithField("role_id", roleID).WithField("permission_count", len(permissionIDs)).Info("permissions assigned to role")
	return nil
}

// AssignRoleToUser assigns a role to a user
func (s *service) AssignRoleToUser(ctx context.Context, userID, roleID, tenantID, actorID string) error {
	// Verify role exists and belongs to tenant (or is system role)
	role, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		return ErrRoleNotFound
	}

	// Verify role is available for this tenant
	if role.TenantID != nil && *role.TenantID != tenantID {
		return ErrRoleNotFound
	}

	// Create user role assignment
	userRole := &UserRole{
		UserID:    userID,
		RoleID:    roleID,
		TenantID:  tenantID,
		CreatedBy: actorID,
	}

	if err := s.repo.AssignRoleToUser(ctx, userRole); err != nil {
		// Check if it's a duplicate error
		if err.Error() == "duplicate key value violates unique constraint" {
			return ErrUserAlreadyHasRole
		}
		s.log.Error("failed to assign role to user", err)
		return fmt.Errorf("failed to assign role: %w", err)
	}

	// Invalidate user's permission cache
	if err := s.policyEngine.InvalidateUserCache(ctx, userID, tenantID); err != nil {
		s.log.WithField("error", err).Warn("failed to invalidate user cache")
	}

	s.log.WithField("user_id", userID).WithField("role_id", roleID).WithField("tenant_id", tenantID).Info("role assigned to user")
	return nil
}

// RemoveRoleFromUser removes a role from a user
func (s *service) RemoveRoleFromUser(ctx context.Context, userID, roleID, tenantID string) error {
	if err := s.repo.RemoveRoleFromUser(ctx, userID, roleID); err != nil {
		s.log.Error("failed to remove role from user", err)
		return fmt.Errorf("failed to remove role: %w", err)
	}

	// Invalidate user's permission cache
	if err := s.policyEngine.InvalidateUserCache(ctx, userID, tenantID); err != nil {
		s.log.WithField("error", err).Warn("failed to invalidate user cache")
	}

	s.log.WithField("user_id", userID).WithField("role_id", roleID).Info("role removed from user")
	return nil
}

// GetUserRoles retrieves all roles assigned to a user in a tenant
func (s *service) GetUserRoles(ctx context.Context, userID, tenantID string) ([]Role, error) {
	roles, err := s.repo.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		s.log.Error("failed to get user roles", err)
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return roles, nil
}

// GetUserPermissions retrieves effective permissions for a user
func (s *service) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error) {
	permissions, err := s.policyEngine.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		s.log.Error("failed to get user permissions", err)
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	return permissions, nil
}

// RegisterResource registers a custom resource (tenant admin only)
func (s *service) RegisterResource(ctx context.Context, tenantID string, req RegisterResourceRequest) (*ResourceDefinition, error) {
	// Validate request
	if err := s.validateRegisterResourceRequest(req); err != nil {
		return nil, err
	}

	// Register in memory registry
	resourceDef := ResourceDefinition{
		Name:        req.Name,
		Description: req.Description,
		Scope:       PermissionScopeTenant,
		TenantID:    &tenantID,
		Actions:     req.Actions,
		CreatedBy:   "tenant_admin",
	}

	if err := s.registry.Register(resourceDef); err != nil {
		s.log.Error("failed to register resource in registry", err)
		return nil, err
	}

	// Persist to database
	if err := s.repo.RegisterResource(ctx, &resourceDef); err != nil {
		s.log.Error("failed to persist resource", err)
		return nil, fmt.Errorf("failed to register resource: %w", err)
	}

	s.log.WithField("resource_name", req.Name).WithField("tenant_id", tenantID).Info("resource registered successfully")
	return &resourceDef, nil
}

// ListResources lists registered resources
func (s *service) ListResources(ctx context.Context, scope PermissionScope) ([]ResourceDefinition, error) {
	resources, err := s.repo.ListResources(ctx, scope)
	if err != nil {
		s.log.Error("failed to list resources", err)
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}

	return resources, nil
}

// CheckPermission checks if a user has permission for an action
func (s *service) CheckPermission(ctx context.Context, userID, tenantID, resource, action, objectID string) (PermissionCheckResult, error) {
	req := PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: resource,
		Action:   action,
		ObjectID: objectID,
	}

	result, err := s.policyEngine.CheckPermission(ctx, req)
	if err != nil {
		s.log.Error("permission check failed", err)
		return PermissionCheckResult{}, err
	}

	return result, nil
}

// Validation helpers

func (s *service) validateCreateRoleRequest(req CreateRoleRequest) error {
	if req.Name == "" {
		return fmt.Errorf("role name is required")
	}
	if req.Slug == "" {
		return fmt.Errorf("role slug is required")
	}
	if len(req.Name) < 3 || len(req.Name) > 100 {
		return fmt.Errorf("role name must be between 3 and 100 characters")
	}
	if len(req.Slug) < 3 || len(req.Slug) > 50 {
		return fmt.Errorf("role slug must be between 3 and 50 characters")
	}
	return nil
}

func (s *service) validateRegisterResourceRequest(req RegisterResourceRequest) error {
	if req.Name == "" {
		return fmt.Errorf("resource name is required")
	}
	if len(req.Actions) == 0 {
		return fmt.Errorf("at least one action is required")
	}
	if len(req.Name) < 3 || len(req.Name) > 50 {
		return fmt.Errorf("resource name must be between 3 and 50 characters")
	}
	return nil
}

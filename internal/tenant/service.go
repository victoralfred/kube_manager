package tenant

import (
	"context"
	"fmt"

	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Service defines the interface for tenant business logic
type Service interface {
	CreateTenant(ctx context.Context, req CreateTenantRequest) (*Tenant, error)
	GetTenant(ctx context.Context, id string) (*Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error)
	UpdateTenant(ctx context.Context, id string, req UpdateTenantRequest) (*Tenant, error)
	DeleteTenant(ctx context.Context, id string) error
	ListTenants(ctx context.Context, filter ListTenantsFilter) ([]*Tenant, int, error)
	SuspendTenant(ctx context.Context, id string) error
	ActivateTenant(ctx context.Context, id string) error
	GetTenantStats(ctx context.Context, id string) (*TenantStats, error)
	ValidateTenantAccess(ctx context.Context, tenantID string) error
}

// service implements Service interface
type service struct {
	repo   Repository
	logger *logger.Logger
}

// NewService creates a new tenant service
func NewService(repo Repository, log *logger.Logger) Service {
	return &service{
		repo:   repo,
		logger: log,
	}
}

// CreateTenant creates a new tenant
func (s *service) CreateTenant(ctx context.Context, req CreateTenantRequest) (*Tenant, error) {
	// Validate request
	if err := req.Validate(); err != nil {
		s.logger.Error("validation failed", err)
		return nil, err
	}

	// Check if tenant already exists
	exists, err := s.repo.Exists(ctx, req.Slug)
	if err != nil {
		s.logger.Error("failed to check tenant existence", err)
		return nil, fmt.Errorf("failed to check tenant existence: %w", err)
	}

	if exists {
		s.logger.Warn(fmt.Sprintf("tenant with slug %s already exists", req.Slug))
		return nil, ErrTenantAlreadyExists
	}

	// Create tenant
	tenant := req.ToTenant()
	if err := s.repo.Create(ctx, tenant); err != nil {
		s.logger.Error("failed to create tenant", err)
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	s.logger.WithTenantID(tenant.ID).Info("tenant created successfully")
	return tenant, nil
}

// GetTenant retrieves a tenant by ID
func (s *service) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	if id == "" {
		return nil, ErrInvalidTenantID
	}

	tenant, err := s.repo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get tenant", err)
		return nil, err
	}

	return tenant, nil
}

// GetTenantBySlug retrieves a tenant by slug
func (s *service) GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error) {
	if slug == "" {
		return nil, ErrInvalidTenantSlug
	}

	tenant, err := s.repo.GetBySlug(ctx, slug)
	if err != nil {
		s.logger.Error("failed to get tenant by slug", err)
		return nil, err
	}

	return tenant, nil
}

// UpdateTenant updates a tenant
func (s *service) UpdateTenant(ctx context.Context, id string, req UpdateTenantRequest) (*Tenant, error) {
	// Get existing tenant
	tenant, err := s.repo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get tenant for update", err)
		return nil, err
	}

	// Apply updates
	if req.Name != nil {
		tenant.Name = *req.Name
	}
	if req.Status != nil {
		tenant.Status = *req.Status
	}
	if req.ContactName != nil {
		tenant.ContactName = *req.ContactName
	}
	if req.ContactEmail != nil {
		tenant.ContactEmail = *req.ContactEmail
	}
	if req.MaxUsers != nil {
		tenant.MaxUsers = *req.MaxUsers
	}
	if req.MaxStorage != nil {
		tenant.MaxStorage = *req.MaxStorage
	}
	if req.Settings != nil {
		tenant.Settings = req.Settings
	}

	// Update in repository
	if err := s.repo.Update(ctx, tenant); err != nil {
		s.logger.Error("failed to update tenant", err)
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	s.logger.WithTenantID(tenant.ID).Info("tenant updated successfully")
	return tenant, nil
}

// DeleteTenant deletes a tenant
func (s *service) DeleteTenant(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalidTenantID
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		s.logger.Error("failed to delete tenant", err)
		return err
	}

	s.logger.WithTenantID(id).Info("tenant deleted successfully")
	return nil
}

// ListTenants lists tenants with filters
func (s *service) ListTenants(ctx context.Context, filter ListTenantsFilter) ([]*Tenant, int, error) {
	tenants, total, err := s.repo.List(ctx, filter)
	if err != nil {
		s.logger.Error("failed to list tenants", err)
		return nil, 0, err
	}

	return tenants, total, nil
}

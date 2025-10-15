package tenant

import (
	"context"
	"fmt"
)

// SuspendTenant suspends a tenant
func (s *service) SuspendTenant(ctx context.Context, id string) error {
	tenant, err := s.repo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get tenant for suspension", err)
		return err
	}

	if tenant.Status == TenantStatusSuspended {
		return nil
	}

	tenant.Status = TenantStatusSuspended
	if err := s.repo.Update(ctx, tenant); err != nil {
		s.logger.Error("failed to suspend tenant", err)
		return fmt.Errorf("failed to suspend tenant: %w", err)
	}

	s.logger.WithTenantID(id).Info("tenant suspended successfully")
	return nil
}

// ActivateTenant activates a tenant
func (s *service) ActivateTenant(ctx context.Context, id string) error {
	tenant, err := s.repo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get tenant for activation", err)
		return err
	}

	if tenant.Status == TenantStatusActive {
		return nil
	}

	tenant.Status = TenantStatusActive
	if err := s.repo.Update(ctx, tenant); err != nil {
		s.logger.Error("failed to activate tenant", err)
		return fmt.Errorf("failed to activate tenant: %w", err)
	}

	s.logger.WithTenantID(id).Info("tenant activated successfully")
	return nil
}

// GetTenantStats retrieves tenant statistics
func (s *service) GetTenantStats(ctx context.Context, id string) (*TenantStats, error) {
	if id == "" {
		return nil, ErrInvalidTenantID
	}

	// Verify tenant exists
	_, err := s.repo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to verify tenant existence", err)
		return nil, err
	}

	stats, err := s.repo.GetStats(ctx, id)
	if err != nil {
		s.logger.Error("failed to get tenant stats", err)
		return nil, fmt.Errorf("failed to get tenant stats: %w", err)
	}

	return stats, nil
}

// ValidateTenantAccess validates if a tenant is accessible
func (s *service) ValidateTenantAccess(ctx context.Context, tenantID string) error {
	tenant, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}

	if !tenant.IsActive() {
		if tenant.IsSuspended() {
			return ErrTenantSuspended
		}
		return ErrTenantInactive
	}

	return nil
}

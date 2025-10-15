package tenant

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// TestTenantDataIsolation tests that tenant data is properly isolated
func TestTenantDataIsolation(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("GetStats should only return data for specified tenant", func(t *testing.T) {
		tenant1ID := "tenant-111"
		tenant2ID := "tenant-222"

		// Tenant 1 stats
		stats1 := &TenantStats{
			TenantID:     tenant1ID,
			UserCount:    10,
			StorageUsed:  5000,
			ResourceUsed: 3,
		}

		// Tenant 2 stats
		stats2 := &TenantStats{
			TenantID:     tenant2ID,
			UserCount:    20,
			StorageUsed:  10000,
			ResourceUsed: 5,
		}

		mockRepo.On("GetByID", ctx, tenant1ID).Return(&Tenant{ID: tenant1ID}, nil).Once()
		mockRepo.On("GetStats", ctx, tenant1ID).Return(stats1, nil).Once()

		mockRepo.On("GetByID", ctx, tenant2ID).Return(&Tenant{ID: tenant2ID}, nil).Once()
		mockRepo.On("GetStats", ctx, tenant2ID).Return(stats2, nil).Once()

		// Get stats for tenant 1
		result1, err := svc.GetTenantStats(ctx, tenant1ID)
		assert.NoError(t, err)
		assert.Equal(t, tenant1ID, result1.TenantID)
		assert.Equal(t, 10, result1.UserCount)

		// Get stats for tenant 2
		result2, err := svc.GetTenantStats(ctx, tenant2ID)
		assert.NoError(t, err)
		assert.Equal(t, tenant2ID, result2.TenantID)
		assert.Equal(t, 20, result2.UserCount)

		// Verify no cross-contamination
		assert.NotEqual(t, result1.TenantID, result2.TenantID)
		assert.NotEqual(t, result1.UserCount, result2.UserCount)

		mockRepo.AssertExpectations(t)
	})
}

// TestTenantListIsolation tests that list operations don't expose other tenants
func TestTenantListIsolation(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("list should only return matching tenants", func(t *testing.T) {
		activeStatus := TenantStatusActive
		filter := ListTenantsFilter{
			Status: &activeStatus,
			Limit:  10,
			Offset: 0,
		}

		activeTenants := []*Tenant{
			{ID: "tenant-1", Status: TenantStatusActive, Name: "Active 1"},
			{ID: "tenant-2", Status: TenantStatusActive, Name: "Active 2"},
		}

		mockRepo.On("List", ctx, filter).Return(activeTenants, 2, nil).Once()

		tenants, total, err := svc.ListTenants(ctx, filter)
		assert.NoError(t, err)
		assert.Equal(t, 2, total)
		assert.Equal(t, 2, len(tenants))

		// Verify all returned tenants match the filter
		for _, tenant := range tenants {
			assert.Equal(t, TenantStatusActive, tenant.Status)
		}

		mockRepo.AssertExpectations(t)
	})

	t.Run("suspended tenants should not appear in active list", func(t *testing.T) {
		activeStatus := TenantStatusActive
		filter := ListTenantsFilter{
			Status: &activeStatus,
			Limit:  10,
			Offset: 0,
		}

		// Only active tenants returned
		activeTenants := []*Tenant{
			{ID: "tenant-1", Status: TenantStatusActive, Name: "Active 1"},
		}

		mockRepo.On("List", ctx, filter).Return(activeTenants, 1, nil).Once()

		tenants, total, err := svc.ListTenants(ctx, filter)
		assert.NoError(t, err)
		assert.Equal(t, 1, total)

		// Verify no suspended tenants in results
		for _, tenant := range tenants {
			assert.NotEqual(t, TenantStatusSuspended, tenant.Status)
		}

		mockRepo.AssertExpectations(t)
	})
}

// TestTenantSlugUniqueness tests that slug uniqueness is enforced
func TestTenantSlugUniqueness(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("cannot create tenant with existing slug", func(t *testing.T) {
		existingSlug := "existing-slug"

		// First tenant created successfully
		mockRepo.On("Exists", ctx, existingSlug).Return(false, nil).Once()
		mockRepo.On("Create", ctx, mock.AnythingOfType("*tenant.Tenant")).Return(nil).Once()

		req1 := CreateTenantRequest{
			Name:         "First Tenant",
			Slug:         existingSlug,
			ContactName:  "John Doe",
			ContactEmail: "john@example.com",
			MaxUsers:     100,
			MaxStorage:   1000000,
		}
		tenant1, err := svc.CreateTenant(ctx, req1)
		assert.NoError(t, err)
		assert.NotNil(t, tenant1)

		// Second attempt with same slug should fail
		mockRepo.On("Exists", ctx, existingSlug).Return(true, nil).Once()

		req2 := CreateTenantRequest{
			Name:         "Second Tenant",
			Slug:         existingSlug,
			ContactName:  "Jane Doe",
			ContactEmail: "jane@example.com",
			MaxUsers:     100,
			MaxStorage:   1000000,
		}
		tenant2, err := svc.CreateTenant(ctx, req2)
		assert.Error(t, err)
		assert.Nil(t, tenant2)
		assert.Equal(t, ErrTenantAlreadyExists, err)

		mockRepo.AssertExpectations(t)
	})
}

// TestTenantDeletion tests that tenant deletion doesn't affect other tenants
func TestTenantDeletion(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("deleting one tenant should not affect others", func(t *testing.T) {
		tenant1ID := "tenant-to-delete"
		tenant2ID := "tenant-to-keep"

		// Delete tenant 1
		mockRepo.On("Delete", ctx, tenant1ID).Return(nil).Once()
		err := svc.DeleteTenant(ctx, tenant1ID)
		assert.NoError(t, err)

		// Tenant 2 should still be accessible
		tenant2 := &Tenant{
			ID:     tenant2ID,
			Name:   "Kept Tenant",
			Status: TenantStatusActive,
		}
		mockRepo.On("GetByID", ctx, tenant2ID).Return(tenant2, nil).Once()

		result, err := svc.GetTenant(ctx, tenant2ID)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, tenant2ID, result.ID)

		mockRepo.AssertExpectations(t)
	})
}

// TestTenantAccessValidation tests that tenant access is properly validated
func TestTenantAccessValidation(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("active tenant should pass validation", func(t *testing.T) {
		tenantID := "active-tenant"
		activeTenant := &Tenant{
			ID:     tenantID,
			Status: TenantStatusActive,
		}

		mockRepo.On("GetByID", ctx, tenantID).Return(activeTenant, nil).Once()

		err := svc.ValidateTenantAccess(ctx, tenantID)
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("suspended tenant should fail validation", func(t *testing.T) {
		tenantID := "suspended-tenant"
		suspendedTenant := &Tenant{
			ID:     tenantID,
			Status: TenantStatusSuspended,
		}

		mockRepo.On("GetByID", ctx, tenantID).Return(suspendedTenant, nil).Once()

		err := svc.ValidateTenantAccess(ctx, tenantID)
		assert.Error(t, err)
		assert.Equal(t, ErrTenantSuspended, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("non-existent tenant should fail validation", func(t *testing.T) {
		tenantID := "non-existent"
		mockRepo.On("GetByID", ctx, tenantID).Return(nil, ErrTenantNotFound).Once()

		err := svc.ValidateTenantAccess(ctx, tenantID)
		assert.Error(t, err)
		assert.Equal(t, ErrTenantNotFound, err)
		mockRepo.AssertExpectations(t)
	})
}

// TestResourceQuotaEnforcement tests that resource limits are checked
func TestResourceQuotaEnforcement(t *testing.T) {
	t.Run("CanCreateUser should enforce max users limit", func(t *testing.T) {
		tenant := &Tenant{
			ID:       "tenant-1",
			MaxUsers: 10,
		}

		// Should allow when under limit
		assert.True(t, tenant.CanCreateUser(9))
		assert.True(t, tenant.CanCreateUser(5))

		// Should block when at or over limit
		assert.False(t, tenant.CanCreateUser(10))
		assert.False(t, tenant.CanCreateUser(11))
	})

	t.Run("CanAllocateStorage should enforce max storage limit", func(t *testing.T) {
		tenant := &Tenant{
			ID:         "tenant-1",
			MaxStorage: 1000,
		}

		// Should allow when under limit
		assert.True(t, tenant.CanAllocateStorage(500, 400))
		assert.True(t, tenant.CanAllocateStorage(900, 99))

		// Should block when would exceed limit
		assert.False(t, tenant.CanAllocateStorage(500, 501))
		assert.False(t, tenant.CanAllocateStorage(1000, 1))
		assert.True(t, tenant.CanAllocateStorage(999, 1))
	})
}

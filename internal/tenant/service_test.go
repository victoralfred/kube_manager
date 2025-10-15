package tenant

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// MockRepository is a mock implementation of Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) Create(ctx context.Context, tenant *Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

func (m *MockRepository) GetByID(ctx context.Context, id string) (*Tenant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Tenant), args.Error(1)
}

func (m *MockRepository) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	args := m.Called(ctx, slug)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Tenant), args.Error(1)
}

func (m *MockRepository) Update(ctx context.Context, tenant *Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

func (m *MockRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) List(ctx context.Context, filter ListTenantsFilter) ([]*Tenant, int, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*Tenant), args.Int(1), args.Error(2)
}

func (m *MockRepository) Exists(ctx context.Context, slug string) (bool, error) {
	args := m.Called(ctx, slug)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) GetStats(ctx context.Context, tenantID string) (*TenantStats, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TenantStats), args.Error(1)
}

func TestService_CreateTenant(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("successfully create tenant", func(t *testing.T) {
		req := CreateTenantRequest{
			Name:         "Test Tenant",
			Slug:         "test-tenant",
			ContactName:  "John Doe",
			ContactEmail: "john@example.com",
			MaxUsers:     100,
			MaxStorage:   1000000,
			Settings:     map[string]interface{}{},
		}

		mockRepo.On("Exists", ctx, req.Slug).Return(false, nil).Once()
		mockRepo.On("Create", ctx, mock.AnythingOfType("*tenant.Tenant")).Return(nil).Once()

		tenant, err := svc.CreateTenant(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, tenant)
		assert.Equal(t, req.Name, tenant.Name)
		assert.Equal(t, req.Slug, tenant.Slug)
		assert.Equal(t, TenantStatusActive, tenant.Status)
		mockRepo.AssertExpectations(t)
	})

	t.Run("fail when tenant already exists", func(t *testing.T) {
		req := CreateTenantRequest{
			Name:         "Existing Tenant",
			Slug:         "existing-tenant",
			ContactName:  "Jane Doe",
			ContactEmail: "jane@example.com",
			MaxUsers:     100,
			MaxStorage:   1000000,
		}

		mockRepo.On("Exists", ctx, req.Slug).Return(true, nil).Once()

		tenant, err := svc.CreateTenant(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, tenant)
		assert.Equal(t, ErrTenantAlreadyExists, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestService_GetTenant(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("successfully get tenant", func(t *testing.T) {
		tenantID := "tenant-123"
		expectedTenant := &Tenant{
			ID:     tenantID,
			Name:   "Test Tenant",
			Slug:   "test-tenant",
			Status: TenantStatusActive,
		}

		mockRepo.On("GetByID", ctx, tenantID).Return(expectedTenant, nil).Once()

		tenant, err := svc.GetTenant(ctx, tenantID)

		assert.NoError(t, err)
		assert.NotNil(t, tenant)
		assert.Equal(t, expectedTenant.ID, tenant.ID)
		mockRepo.AssertExpectations(t)
	})

	t.Run("fail with invalid tenant ID", func(t *testing.T) {
		tenant, err := svc.GetTenant(ctx, "")

		assert.Error(t, err)
		assert.Nil(t, tenant)
		assert.Equal(t, ErrInvalidTenantID, err)
	})

	t.Run("fail when tenant not found", func(t *testing.T) {
		tenantID := "nonexistent"
		mockRepo.On("GetByID", ctx, tenantID).Return(nil, ErrTenantNotFound).Once()

		tenant, err := svc.GetTenant(ctx, tenantID)

		assert.Error(t, err)
		assert.Nil(t, tenant)
		assert.Equal(t, ErrTenantNotFound, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestService_UpdateTenant(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("successfully update tenant", func(t *testing.T) {
		tenantID := "tenant-123"
		existingTenant := &Tenant{
			ID:     tenantID,
			Name:   "Old Name",
			Status: TenantStatusActive,
		}

		newName := "New Name"
		req := UpdateTenantRequest{
			Name: &newName,
		}

		mockRepo.On("GetByID", ctx, tenantID).Return(existingTenant, nil).Once()
		mockRepo.On("Update", ctx, mock.AnythingOfType("*tenant.Tenant")).Return(nil).Once()

		tenant, err := svc.UpdateTenant(ctx, tenantID, req)

		assert.NoError(t, err)
		assert.NotNil(t, tenant)
		assert.Equal(t, newName, tenant.Name)
		mockRepo.AssertExpectations(t)
	})
}

func TestService_SuspendTenant(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("successfully suspend tenant", func(t *testing.T) {
		tenantID := "tenant-123"
		existingTenant := &Tenant{
			ID:     tenantID,
			Status: TenantStatusActive,
		}

		mockRepo.On("GetByID", ctx, tenantID).Return(existingTenant, nil).Once()
		mockRepo.On("Update", ctx, mock.AnythingOfType("*tenant.Tenant")).Return(nil).Once()

		err := svc.SuspendTenant(ctx, tenantID)

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestService_ValidateTenantAccess(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("valid access for active tenant", func(t *testing.T) {
		tenantID := "tenant-123"
		activeTenant := &Tenant{
			ID:     tenantID,
			Status: TenantStatusActive,
		}

		mockRepo.On("GetByID", ctx, tenantID).Return(activeTenant, nil).Once()

		err := svc.ValidateTenantAccess(ctx, tenantID)

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("fail for suspended tenant", func(t *testing.T) {
		tenantID := "tenant-123"
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

	t.Run("fail for inactive tenant", func(t *testing.T) {
		tenantID := "tenant-123"
		now := time.Now()
		inactiveTenant := &Tenant{
			ID:        tenantID,
			Status:    TenantStatusInactive,
			DeletedAt: &now,
		}

		mockRepo.On("GetByID", ctx, tenantID).Return(inactiveTenant, nil).Once()

		err := svc.ValidateTenantAccess(ctx, tenantID)

		assert.Error(t, err)
		assert.Equal(t, ErrTenantInactive, err)
		mockRepo.AssertExpectations(t)
	})
}

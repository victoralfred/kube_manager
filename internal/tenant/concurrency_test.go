package tenant

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// TestConcurrentSlugCreation tests that concurrent attempts to create tenants
// with the same slug are properly handled
func TestConcurrentSlugCreation(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("concurrent creation with same slug should fail for second attempt", func(t *testing.T) {
		slug := "concurrent-tenant"

		// First call should succeed
		mockRepo.On("Exists", ctx, slug).Return(false, nil).Once()
		mockRepo.On("Create", ctx, mock.MatchedBy(func(t *Tenant) bool {
			return t.Slug == slug
		})).Return(nil).Once()

		// Second call should find it exists
		mockRepo.On("Exists", ctx, slug).Return(true, nil).Once()

		var wg sync.WaitGroup
		results := make(chan error, 2)

		// Launch two goroutines trying to create same tenant
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				req := CreateTenantRequest{
					Name:         "Concurrent Tenant",
					Slug:         slug,
					ContactName:  "Test User",
					ContactEmail: "test@example.com",
					MaxUsers:     100,
					MaxStorage:   1000000,
				}
				_, err := svc.CreateTenant(ctx, req)
				results <- err
			}(i)
		}

		wg.Wait()
		close(results)

		// One should succeed, one should fail
		var successCount, failureCount int
		for err := range results {
			if err == nil {
				successCount++
			} else if err == ErrTenantAlreadyExists {
				failureCount++
			}
		}

		assert.Equal(t, 1, successCount, "Exactly one creation should succeed")
		assert.Equal(t, 1, failureCount, "Exactly one creation should fail with ErrTenantAlreadyExists")
		mockRepo.AssertExpectations(t)
	})
}

// TestConcurrentTenantUpdates tests concurrent updates to the same tenant
func TestConcurrentTenantUpdates(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("concurrent updates should not cause data corruption", func(t *testing.T) {
		tenantID := "tenant-123"

		// Setup mocks for concurrent updates - each call returns a new instance
		for i := 0; i < 5; i++ {
			mockRepo.On("GetByID", ctx, tenantID).Return(&Tenant{
				ID:     tenantID,
				Name:   "Original Name",
				Status: TenantStatusActive,
			}, nil).Once()
		}
		mockRepo.On("Update", ctx, mock.MatchedBy(func(t *Tenant) bool {
			return t.ID == tenantID
		})).Return(nil).Times(5)

		var wg sync.WaitGroup
		errors := make(chan error, 5)

		// Launch 5 concurrent updates
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				newName := "Updated Name"
				req := UpdateTenantRequest{
					Name: &newName,
				}
				_, err := svc.UpdateTenant(ctx, tenantID, req)
				errors <- err
			}(i)
		}

		wg.Wait()
		close(errors)

		// All updates should succeed (optimistic locking not implemented yet)
		for err := range errors {
			assert.NoError(t, err)
		}

		mockRepo.AssertExpectations(t)
	})
}

// TestConcurrentTenantSuspension tests concurrent suspension operations
func TestConcurrentTenantSuspension(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("concurrent suspension attempts should be idempotent", func(t *testing.T) {
		tenantID := "tenant-123"
		activeTenant := &Tenant{
			ID:     tenantID,
			Status: TenantStatusActive,
		}

		// First call gets active tenant
		mockRepo.On("GetByID", ctx, tenantID).Return(activeTenant, nil).Once()
		mockRepo.On("Update", ctx, mock.MatchedBy(func(t *Tenant) bool {
			return t.ID == tenantID && t.Status == TenantStatusSuspended
		})).Return(nil).Once()

		// Subsequent calls might get suspended tenant (idempotent check)
		suspendedTenant := &Tenant{
			ID:     tenantID,
			Status: TenantStatusSuspended,
		}
		mockRepo.On("GetByID", ctx, tenantID).Return(suspendedTenant, nil).Times(2)

		var wg sync.WaitGroup
		errors := make(chan error, 3)

		// Launch 3 concurrent suspension attempts
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := svc.SuspendTenant(ctx, tenantID)
				errors <- err
			}()
		}

		wg.Wait()
		close(errors)

		// All should succeed (idempotent operation)
		for err := range errors {
			assert.NoError(t, err)
		}

		mockRepo.AssertExpectations(t)
	})
}

// TestSlugCaseSensitivity tests that slug comparison is case-sensitive
func TestSlugCaseSensitivity(t *testing.T) {
	mockRepo := new(MockRepository)
	log := logger.New("debug", "test")
	svc := NewService(mockRepo, log)
	ctx := context.Background()

	t.Run("different case slugs should be treated as different", func(t *testing.T) {
		// Create tenant with lowercase slug
		lowerSlug := "test-tenant"
		mockRepo.On("Exists", ctx, lowerSlug).Return(false, nil).Once()
		mockRepo.On("Create", ctx, mock.MatchedBy(func(t *Tenant) bool {
			return t.Slug == lowerSlug
		})).Return(nil).Once()

		req1 := CreateTenantRequest{
			Name:         "Test Tenant Lower",
			Slug:         lowerSlug,
			ContactName:  "Test User",
			ContactEmail: "test1@example.com",
			MaxUsers:     100,
			MaxStorage:   1000000,
		}
		_, err := svc.CreateTenant(ctx, req1)
		assert.NoError(t, err)

		// Try to create tenant with uppercase slug
		upperSlug := "TEST-TENANT"
		mockRepo.On("Exists", ctx, upperSlug).Return(false, nil).Once()
		mockRepo.On("Create", ctx, mock.MatchedBy(func(t *Tenant) bool {
			return t.Slug == upperSlug
		})).Return(nil).Once()

		req2 := CreateTenantRequest{
			Name:         "Test Tenant Upper",
			Slug:         upperSlug,
			ContactName:  "Test User",
			ContactEmail: "test2@example.com",
			MaxUsers:     100,
			MaxStorage:   1000000,
		}
		_, err = svc.CreateTenant(ctx, req2)
		assert.NoError(t, err)

		mockRepo.AssertExpectations(t)
	})
}


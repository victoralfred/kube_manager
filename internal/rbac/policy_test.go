package rbac

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/victoralfred/kube_manager/pkg/cache"
)

// ========================================
// Mock Implementations
// ========================================

// MockRepository mocks the Repository interface
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) GetPermission(ctx context.Context, resource, action string) (*Permission, error) {
	args := m.Called(ctx, resource, action)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Permission), args.Error(1)
}

func (m *MockRepository) GetAllPermissions(ctx context.Context) ([]Permission, error) {
	args := m.Called(ctx)
	return args.Get(0).([]Permission), args.Error(1)
}

func (m *MockRepository) GetPermissionByID(ctx context.Context, permissionID string) (*Permission, error) {
	args := m.Called(ctx, permissionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Permission), args.Error(1)
}

func (m *MockRepository) GetPermissionsByResource(ctx context.Context, resource string) ([]Permission, error) {
	args := m.Called(ctx, resource)
	return args.Get(0).([]Permission), args.Error(1)
}

func (m *MockRepository) GetRolePermissions(ctx context.Context, roleID string) ([]Permission, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).([]Permission), args.Error(1)
}

func (m *MockRepository) CreateRole(ctx context.Context, role *Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRepository) GetRoleByID(ctx context.Context, roleID string) (*Role, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Role), args.Error(1)
}

func (m *MockRepository) GetRoleBySlug(ctx context.Context, tenantID, slug string) (*Role, error) {
	args := m.Called(ctx, tenantID, slug)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Role), args.Error(1)
}

func (m *MockRepository) UpdateRole(ctx context.Context, role *Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRepository) DeleteRole(ctx context.Context, roleID string) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

func (m *MockRepository) ListRoles(ctx context.Context, filter ListRolesFilter) ([]*Role, int, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*Role), args.Int(1), args.Error(2)
}

func (m *MockRepository) RoleExists(ctx context.Context, tenantID, slug string) (bool, error) {
	args := m.Called(ctx, tenantID, slug)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) AssignPermissionsToRole(ctx context.Context, roleID string, permissionIDs []string) error {
	args := m.Called(ctx, roleID, permissionIDs)
	return args.Error(0)
}

func (m *MockRepository) RemovePermissionsFromRole(ctx context.Context, roleID string, permissionIDs []string) error {
	args := m.Called(ctx, roleID, permissionIDs)
	return args.Error(0)
}

func (m *MockRepository) RemoveAllPermissionsFromRole(ctx context.Context, roleID string) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

func (m *MockRepository) AssignRoleToUser(ctx context.Context, userRole *UserRole) error {
	args := m.Called(ctx, userRole)
	return args.Error(0)
}

func (m *MockRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockRepository) GetUserRoles(ctx context.Context, userID, tenantID string) ([]Role, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Get(0).([]Role), args.Error(1)
}

func (m *MockRepository) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Get(0).([]Permission), args.Error(1)
}

func (m *MockRepository) GetUserPermissionsWithConditions(ctx context.Context, userID, tenantID string) ([]PermissionWithConditions, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]PermissionWithConditions), args.Error(1)
}

func (m *MockRepository) UserHasRole(ctx context.Context, userID, roleID string) (bool, error) {
	args := m.Called(ctx, userID, roleID)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) RegisterResource(ctx context.Context, resource *ResourceDefinition) error {
	args := m.Called(ctx, resource)
	return args.Error(0)
}

func (m *MockRepository) GetResource(ctx context.Context, name string, tenantID *string) (*ResourceDefinition, error) {
	args := m.Called(ctx, name, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ResourceDefinition), args.Error(1)
}

func (m *MockRepository) ListResources(ctx context.Context, scope PermissionScope) ([]ResourceDefinition, error) {
	args := m.Called(ctx, scope)
	return args.Get(0).([]ResourceDefinition), args.Error(1)
}

func (m *MockRepository) IsTenantAdmin(ctx context.Context, userID, tenantID string) (bool, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) UserHasPlatformRole(ctx context.Context, userID, role string) (bool, error) {
	args := m.Called(ctx, userID, role)
	return args.Bool(0), args.Error(1)
}

func (m *MockRepository) GetResourceOwner(ctx context.Context, resourceType, objectID string) (string, error) {
	args := m.Called(ctx, resourceType, objectID)
	return args.String(0), args.Error(1)
}

// MockCache mocks the cache.Cache interface
type MockCache struct {
	mock.Mock
}

func (m *MockCache) Get(ctx context.Context, key string, dest interface{}) error {
	args := m.Called(ctx, key, dest)
	return args.Error(0)
}

func (m *MockCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	args := m.Called(ctx, key, value, ttl)
	return args.Error(0)
}

func (m *MockCache) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockCache) DeletePattern(ctx context.Context, pattern string) error {
	args := m.Called(ctx, pattern)
	return args.Error(0)
}

func (m *MockCache) MGet(ctx context.Context, keys []string, dest interface{}) error {
	args := m.Called(ctx, keys, dest)
	return args.Error(0)
}

func (m *MockCache) MSet(ctx context.Context, items map[string]interface{}, ttl time.Duration) error {
	args := m.Called(ctx, items, ttl)
	return args.Error(0)
}

func (m *MockCache) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockCache) Stats() cache.CacheStats {
	args := m.Called()
	return args.Get(0).(cache.CacheStats)
}

func (m *MockCache) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockOwnershipChecker mocks the OwnershipChecker interface
type MockOwnershipChecker struct {
	mock.Mock
}

func (m *MockOwnershipChecker) CheckOwnership(ctx context.Context, userID, resource, objectID string) (bool, error) {
	args := m.Called(ctx, userID, resource, objectID)
	return args.Bool(0), args.Error(1)
}

func (m *MockOwnershipChecker) GetObjectOwner(ctx context.Context, resource, objectID string) (string, error) {
	args := m.Called(ctx, resource, objectID)
	return args.String(0), args.Error(1)
}

// ========================================
// Helper Functions
// ========================================

func setupPolicyEngine(repo Repository, cache cache.Cache, registry *ResourceRegistry, ownershipChecker OwnershipChecker) PolicyEngine {
	return NewPolicyEngine(PolicyEngineConfig{
		Repository:       repo,
		Cache:            cache,
		Registry:         registry,
		OwnershipChecker: ownershipChecker,
		CacheTTL:         5 * time.Minute,
	})
}

func createTestRegistry() *ResourceRegistry {
	registry := NewResourceRegistry()
	registry.RegisterReserved(ResourceDefinition{
		Name:        "user",
		Description: "User management",
		Scope:       PermissionScopeTenant,
		Actions:     []string{"create", "read", "update", "delete"},
	})
	registry.RegisterReserved(ResourceDefinition{
		Name:        "project",
		Description: "Project management",
		Scope:       PermissionScopeTenant,
		Actions:     []string{"create", "read", "update", "delete"},
	})
	registry.RegisterReserved(ResourceDefinition{
		Name:        "tenant",
		Description: "Tenant management",
		Scope:       PermissionScopeSystem,
		Actions:     []string{"create", "read", "update", "delete"},
	})
	return registry
}

// ========================================
// Test Cases
// ========================================

func TestPolicyEngine_CheckPermission_InvalidRequest(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	tests := []struct {
		name string
		req  PermissionCheckRequest
	}{
		{
			name: "Missing UserID",
			req: PermissionCheckRequest{
				TenantID: "tenant-1",
				Resource: "user",
				Action:   "read",
			},
		},
		{
			name: "Missing TenantID",
			req: PermissionCheckRequest{
				UserID:   "user-1",
				Resource: "user",
				Action:   "read",
			},
		},
		{
			name: "Missing Resource",
			req: PermissionCheckRequest{
				UserID:   "user-1",
				TenantID: "tenant-1",
				Action:   "read",
			},
		},
		{
			name: "Missing Action",
			req: PermissionCheckRequest{
				UserID:   "user-1",
				TenantID: "tenant-1",
				Resource: "user",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.CheckPermission(context.Background(), tt.req)

			assert.Error(t, err)
			assert.False(t, result.Allowed)
			assert.Equal(t, "denied", result.Reason)
		})
	}
}

func TestPolicyEngine_CheckPermission_ResourceNotRegistered(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "nonexistent",
		Action:   "read",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidResource, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "denied", result.Reason)
	assert.Contains(t, result.Message, "not registered")
}

func TestPolicyEngine_CheckPermission_PermissionNotFound(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	mockRepo.On("GetPermission", mock.Anything, "user", "invalid-action").
		Return(nil, ErrPermissionNotFound)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "invalid-action",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.Error(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "denied", result.Reason)
	mockRepo.AssertExpectations(t)
}

func TestPolicyEngine_CheckPermission_SystemScope_PlatformAdmin(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := &Permission{
		ID:       "perm-1",
		Resource: "tenant",
		Action:   "create",
		Scope:    PermissionScopeSystem,
	}

	mockRepo.On("GetPermission", mock.Anything, "tenant", "create").Return(permission, nil)
	mockRepo.On("UserHasPlatformRole", mock.Anything, "user-1", "platform_admin").Return(true, nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "tenant",
		Action:   "create",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "granted", result.Reason)
	assert.Contains(t, result.Message, "Platform admin")
	mockRepo.AssertExpectations(t)
}

func TestPolicyEngine_CheckPermission_SystemScope_NotPlatformAdmin(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := &Permission{
		ID:       "perm-1",
		Resource: "tenant",
		Action:   "create",
		Scope:    PermissionScopeSystem,
	}

	mockRepo.On("GetPermission", mock.Anything, "tenant", "create").Return(permission, nil)
	mockRepo.On("UserHasPlatformRole", mock.Anything, "user-1", "platform_admin").Return(false, nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "tenant",
		Action:   "create",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "denied", result.Reason)
	assert.Contains(t, result.Message, "platform admin")
	mockRepo.AssertExpectations(t)
}

func TestPolicyEngine_CheckPermission_TenantAdminBypass(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := &Permission{
		ID:       "perm-1",
		Resource: "user",
		Action:   "create",
		Scope:    PermissionScopeTenant,
	}

	mockRepo.On("GetPermission", mock.Anything, "user", "create").Return(permission, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(true, nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "create",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "admin_override", result.Reason)
	assert.Contains(t, result.Message, "Tenant admin")
	mockRepo.AssertExpectations(t)

	// Verify admin override metric
	mockCache.On("Stats").Return(cache.CacheStats{})
	stats := engine.Stats()
	assert.Equal(t, uint64(1), stats.AdminOverrides)
}

func TestPolicyEngine_CheckPermission_RBACGranted_CacheHit(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := &Permission{
		ID:       "perm-1",
		Resource: "user",
		Action:   "read",
		Scope:    PermissionScopeTenant,
	}

	cachedPerms := []PermissionWithConditions{
		{
			Permission: *permission,
			Conditions: nil,
		},
	}

	mockRepo.On("GetPermission", mock.Anything, "user", "read").Return(permission, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(false, nil)
	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Run(func(args mock.Arguments) {
			dest := args.Get(2).(*[]PermissionWithConditions)
			*dest = cachedPerms
		}).
		Return(nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "read",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "granted", result.Reason)
	mockRepo.AssertExpectations(t)
	mockCache.AssertExpectations(t)

	// Verify cache hit metric
	mockCache.On("Stats").Return(cache.CacheStats{})
	stats := engine.Stats()
	assert.Equal(t, uint64(1), stats.CacheHits)
}

func TestPolicyEngine_CheckPermission_RBACGranted_CacheMiss(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := &Permission{
		ID:       "perm-1",
		Resource: "user",
		Action:   "read",
		Scope:    PermissionScopeTenant,
	}

	dbPerms := []PermissionWithConditions{
		{
			Permission: *permission,
			Conditions: nil,
		},
	}

	mockRepo.On("GetPermission", mock.Anything, "user", "read").Return(permission, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(false, nil)
	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Return(cache.ErrCacheMiss)
	mockRepo.On("GetUserPermissionsWithConditions", mock.Anything, "user-1", "tenant-1").
		Return(dbPerms, nil)
	mockCache.On("Set", mock.Anything, "user:user-1:tenant:tenant-1:perms", dbPerms, 5*time.Minute).
		Return(nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "read",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "granted", result.Reason)
	mockRepo.AssertExpectations(t)
	mockCache.AssertExpectations(t)

	// Verify cache miss metric
	mockCache.On("Stats").Return(cache.CacheStats{})
	stats := engine.Stats()
	assert.Equal(t, uint64(1), stats.CacheMisses)
}

func TestPolicyEngine_CheckPermission_RBACDenied(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := &Permission{
		ID:       "perm-1",
		Resource: "user",
		Action:   "delete",
		Scope:    PermissionScopeTenant,
	}

	dbPerms := []PermissionWithConditions{} // Empty - user has no permissions

	mockRepo.On("GetPermission", mock.Anything, "user", "delete").Return(permission, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(false, nil)
	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Return(cache.ErrCacheMiss)
	mockRepo.On("GetUserPermissionsWithConditions", mock.Anything, "user-1", "tenant-1").
		Return(dbPerms, nil)
	mockCache.On("Set", mock.Anything, "user:user-1:tenant:tenant-1:perms", dbPerms, 5*time.Minute).
		Return(nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "delete",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "denied", result.Reason)
	assert.Contains(t, result.Message, "does not have permission")
	mockRepo.AssertExpectations(t)
	mockCache.AssertExpectations(t)

	// Verify denial metric
	mockCache.On("Stats").Return(cache.CacheStats{})
	stats := engine.Stats()
	assert.Equal(t, uint64(1), stats.Denials)
}

func TestPolicyEngine_CheckPermission_OwnershipGranted(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	mockOwnership := new(MockOwnershipChecker)
	registry := createTestRegistry()

	permission := &Permission{
		ID:                "perm-1",
		Resource:          "user",
		Action:            "update",
		Scope:             PermissionScopeTenant,
		RequiresOwnership: true,
	}

	dbPerms := []PermissionWithConditions{
		{
			Permission: *permission,
			Conditions: nil,
		},
	}

	mockRepo.On("GetPermission", mock.Anything, "user", "update").Return(permission, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(false, nil)
	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Return(cache.ErrCacheMiss)
	mockRepo.On("GetUserPermissionsWithConditions", mock.Anything, "user-1", "tenant-1").
		Return(dbPerms, nil)
	mockCache.On("Set", mock.Anything, "user:user-1:tenant:tenant-1:perms", dbPerms, 5*time.Minute).
		Return(nil)
	mockOwnership.On("CheckOwnership", mock.Anything, "user-1", "user", "user-1").
		Return(true, nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, mockOwnership)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "update",
		ObjectID: "user-1", // User updating their own record
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "owner", result.Reason)
	assert.Contains(t, result.Message, "ownership")
	mockRepo.AssertExpectations(t)
	mockCache.AssertExpectations(t)
	mockOwnership.AssertExpectations(t)

	// Verify ownership check metric
	mockCache.On("Stats").Return(cache.CacheStats{})
	stats := engine.Stats()
	assert.Equal(t, uint64(1), stats.OwnershipChecks)
}

func TestPolicyEngine_CheckPermission_OwnershipDenied(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	mockOwnership := new(MockOwnershipChecker)
	registry := createTestRegistry()

	permission := &Permission{
		ID:                "perm-1",
		Resource:          "user",
		Action:            "update",
		Scope:             PermissionScopeTenant,
		RequiresOwnership: true,
	}

	dbPerms := []PermissionWithConditions{
		{
			Permission: *permission,
			Conditions: nil,
		},
	}

	mockRepo.On("GetPermission", mock.Anything, "user", "update").Return(permission, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(false, nil)
	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Return(cache.ErrCacheMiss)
	mockRepo.On("GetUserPermissionsWithConditions", mock.Anything, "user-1", "tenant-1").
		Return(dbPerms, nil)
	mockCache.On("Set", mock.Anything, "user:user-1:tenant:tenant-1:perms", dbPerms, 5*time.Minute).
		Return(nil)
	mockOwnership.On("CheckOwnership", mock.Anything, "user-1", "user", "user-2").
		Return(false, nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, mockOwnership)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "update",
		ObjectID: "user-2", // User trying to update someone else's record
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "denied", result.Reason)
	assert.Contains(t, result.Message, "does not own")
	mockRepo.AssertExpectations(t)
	mockCache.AssertExpectations(t)
	mockOwnership.AssertExpectations(t)
}

func TestPolicyEngine_CheckPermission_ConditionGranted(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := &Permission{
		ID:       "perm-1",
		Resource: "project",
		Action:   "read",
		Scope:    PermissionScopeTenant,
	}

	// Simple condition: always true
	condition := &Condition{
		Operator: "AND",
		Rules: []Rule{
			{
				Field:    "status",
				Operator: "equals",
				Value:    "active",
			},
		},
	}

	dbPerms := []PermissionWithConditions{
		{
			Permission: *permission,
			Conditions: condition,
		},
	}

	mockRepo.On("GetPermission", mock.Anything, "project", "read").Return(permission, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(false, nil)
	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Return(cache.ErrCacheMiss)
	mockRepo.On("GetUserPermissionsWithConditions", mock.Anything, "user-1", "tenant-1").
		Return(dbPerms, nil)
	mockCache.On("Set", mock.Anything, "user:user-1:tenant:tenant-1:perms", dbPerms, 5*time.Minute).
		Return(nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "project",
		Action:   "read",
		Context: map[string]interface{}{
			"status": "active",
		},
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "condition_met", result.Reason)
	assert.Contains(t, result.Message, "condition evaluation")
	mockRepo.AssertExpectations(t)
	mockCache.AssertExpectations(t)

	// Verify condition evaluation metric
	mockCache.On("Stats").Return(cache.CacheStats{})
	stats := engine.Stats()
	assert.Equal(t, uint64(1), stats.ConditionEvals)
}

func TestPolicyEngine_CheckPermissions_Batch(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission1 := &Permission{
		ID:       "perm-1",
		Resource: "user",
		Action:   "read",
		Scope:    PermissionScopeTenant,
	}

	permission2 := &Permission{
		ID:       "perm-2",
		Resource: "project",
		Action:   "read",
		Scope:    PermissionScopeTenant,
	}

	dbPerms := []PermissionWithConditions{
		{Permission: *permission1, Conditions: nil},
	}

	mockRepo.On("GetPermission", mock.Anything, "user", "read").Return(permission1, nil)
	mockRepo.On("GetPermission", mock.Anything, "project", "read").Return(permission2, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(false, nil).Twice()
	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Run(func(args mock.Arguments) {
			dest := args.Get(2).(*[]PermissionWithConditions)
			*dest = dbPerms
		}).
		Return(nil).Twice()

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	reqs := []PermissionCheckRequest{
		{
			UserID:   "user-1",
			TenantID: "tenant-1",
			Resource: "user",
			Action:   "read",
		},
		{
			UserID:   "user-1",
			TenantID: "tenant-1",
			Resource: "project",
			Action:   "read",
		},
	}

	results, err := engine.CheckPermissions(context.Background(), reqs)

	assert.NoError(t, err)
	assert.Len(t, results, 2)
	assert.True(t, results[0].Allowed)
	assert.False(t, results[1].Allowed) // User doesn't have project:read permission
	mockRepo.AssertExpectations(t)
	mockCache.AssertExpectations(t)
}

func TestPolicyEngine_InvalidateUserCache(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	mockCache.On("Delete", mock.Anything, "user:user-1:tenant:tenant-1:perms").Return(nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	err := engine.InvalidateUserCache(context.Background(), "user-1", "tenant-1")

	assert.NoError(t, err)
	mockCache.AssertExpectations(t)
}

func TestPolicyEngine_InvalidateRoleCache(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	mockCache.On("DeletePattern", mock.Anything, "user:*:tenant:*:perms").Return(nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	err := engine.InvalidateRoleCache(context.Background(), "role-1")

	assert.NoError(t, err)
	mockCache.AssertExpectations(t)
}

func TestPolicyEngine_InvalidateTenantCache(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	mockCache.On("DeletePattern", mock.Anything, "user:*:tenant:tenant-1:perms").Return(nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	err := engine.InvalidateTenantCache(context.Background(), "tenant-1")

	assert.NoError(t, err)
	mockCache.AssertExpectations(t)
}

func TestPolicyEngine_Stats(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := &Permission{
		ID:       "perm-1",
		Resource: "user",
		Action:   "read",
		Scope:    PermissionScopeTenant,
	}

	mockRepo.On("GetPermission", mock.Anything, "user", "read").Return(permission, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(true, nil)
	mockCache.On("Stats").Return(cache.CacheStats{
		Hits:   100,
		Misses: 10,
	})

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	// Make a permission check to generate stats
	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "read",
	}

	_, _ = engine.CheckPermission(context.Background(), req)

	stats := engine.Stats()

	assert.Equal(t, uint64(1), stats.TotalChecks)
	assert.Equal(t, uint64(1), stats.AdminOverrides)
	assert.Greater(t, stats.AvgCheckTimeMs, float64(0))
	mockRepo.AssertExpectations(t)
	mockCache.AssertExpectations(t)
}

func TestPolicyEngine_GetUserPermissions_CacheHit(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := Permission{
		ID:       "perm-1",
		Resource: "user",
		Action:   "read",
	}

	cachedPerms := []PermissionWithConditions{
		{
			Permission: permission,
			Conditions: nil,
		},
	}

	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Run(func(args mock.Arguments) {
			dest := args.Get(2).(*[]PermissionWithConditions)
			*dest = cachedPerms
		}).
		Return(nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	permissions, err := engine.GetUserPermissions(context.Background(), "user-1", "tenant-1")

	assert.NoError(t, err)
	assert.Len(t, permissions, 1)
	assert.Equal(t, "perm-1", permissions[0].ID)
	mockCache.AssertExpectations(t)
}

func TestPolicyEngine_GetUserPermissions_CacheMiss(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := Permission{
		ID:       "perm-1",
		Resource: "user",
		Action:   "read",
	}

	dbPerms := []PermissionWithConditions{
		{
			Permission: permission,
			Conditions: nil,
		},
	}

	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Return(cache.ErrCacheMiss)
	mockRepo.On("GetUserPermissionsWithConditions", mock.Anything, "user-1", "tenant-1").
		Return(dbPerms, nil)
	mockCache.On("Set", mock.Anything, "user:user-1:tenant:tenant-1:perms", dbPerms, 5*time.Minute).
		Return(nil)

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	permissions, err := engine.GetUserPermissions(context.Background(), "user-1", "tenant-1")

	assert.NoError(t, err)
	assert.Len(t, permissions, 1)
	assert.Equal(t, "perm-1", permissions[0].ID)
	mockRepo.AssertExpectations(t)
	mockCache.AssertExpectations(t)
}

func TestPolicyEngine_FallbackOwnershipCheck(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	permission := &Permission{
		ID:                "perm-1",
		Resource:          "user",
		Action:            "update",
		Scope:             PermissionScopeTenant,
		RequiresOwnership: true,
	}

	dbPerms := []PermissionWithConditions{
		{
			Permission: *permission,
			Conditions: nil,
		},
	}

	mockRepo.On("GetPermission", mock.Anything, "user", "update").Return(permission, nil)
	mockRepo.On("IsTenantAdmin", mock.Anything, "user-1", "tenant-1").Return(false, nil)
	mockCache.On("Get", mock.Anything, "user:user-1:tenant:tenant-1:perms", mock.Anything).
		Return(cache.ErrCacheMiss)
	mockRepo.On("GetUserPermissionsWithConditions", mock.Anything, "user-1", "tenant-1").
		Return(dbPerms, nil)
	mockCache.On("Set", mock.Anything, "user:user-1:tenant:tenant-1:perms", dbPerms, 5*time.Minute).
		Return(nil)

	// No ownership checker provided - fallback
	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	// User updating their own record - should pass fallback check
	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "update",
		ObjectID: "user-1",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "owner", result.Reason)
}

func TestPolicyEngine_CheckPermission_RepositoryError(t *testing.T) {
	mockRepo := new(MockRepository)
	mockCache := new(MockCache)
	registry := createTestRegistry()

	mockRepo.On("GetPermission", mock.Anything, "user", "read").
		Return(nil, errors.New("database connection failed"))

	engine := setupPolicyEngine(mockRepo, mockCache, registry, nil)

	req := PermissionCheckRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Resource: "user",
		Action:   "read",
	}

	result, err := engine.CheckPermission(context.Background(), req)

	assert.Error(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "denied", result.Reason)
	mockRepo.AssertExpectations(t)

	// Verify error metric
	mockCache.On("Stats").Return(cache.CacheStats{})
	stats := engine.Stats()
	assert.Equal(t, uint64(1), stats.Errors)
}

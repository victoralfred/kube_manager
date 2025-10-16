package rbac_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/pkg/cache"
	"github.com/victoralfred/kube_manager/pkg/database"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// ========================================
// Integration Test Setup
// ========================================

// setupIntegrationTest creates a complete RBAC module with all components
func setupIntegrationTest(t *testing.T) (*rbac.Module, *database.DB, func()) {
	// Use in-memory cache for integration tests
	cacheInstance := cache.NewInMemoryCache()
	log := logger.New("error", "test")

	// Note: For full integration tests with database, set RUN_DB_TESTS=true
	// For now, we'll test with in-memory components where possible
	db, cleanup := setupTestDatabase(t)

	module := rbac.NewModule(db, rbac.ModuleConfig{
		Cache:    cacheInstance,
		CacheTTL: 5 * time.Minute,
	}, log)

	// Register core resources
	require.NoError(t, rbac.RegisterCoreResources(module.GetRegistry()))

	return module, db, cleanup
}

// ========================================
// End-to-End Permission Flow Tests
// ========================================

func TestIntegration_FullPermissionFlow(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "user@example.com")

	// Step 1: Create a custom role
	role, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name:        "Editor",
		Slug:        "editor",
		Description: "Can edit resources",
	})
	require.NoError(t, err)
	require.NotNil(t, role)

	// Step 2: Get available permissions
	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, permissions)

	// Find "resource:update" permission
	var updatePermID string
	for _, perm := range permissions {
		if perm.Resource == "resource" && perm.Action == "update" {
			updatePermID = perm.ID
			break
		}
	}
	require.NotEmpty(t, updatePermID, "resource:update permission should exist")

	// Step 3: Assign permission to role
	err = module.GetService().AssignPermissionsToRole(ctx, role.ID, []string{updatePermID})
	require.NoError(t, err)

	// Step 4: Assign role to user
	err = module.GetService().AssignRoleToUser(ctx, userID, role.ID, tenantID, userID)
	require.NoError(t, err)

	// Step 5: Check if user has permission (should succeed)
	result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: "resource",
		Action:   "update",
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed, "User should have resource:update permission")
	assert.Equal(t, "granted", result.Reason)

	// Step 6: Check a permission user doesn't have (should fail)
	result, err = module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: "resource",
		Action:   "delete",
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed, "User should not have resource:delete permission")
	assert.Equal(t, "denied", result.Reason)
}

func TestIntegration_MultiRolePermissions(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "user@example.com")

	// Create two roles with different permissions
	role1, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Reader",
		Slug: "reader",
	})
	require.NoError(t, err)

	role2, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Writer",
		Slug: "writer",
	})
	require.NoError(t, err)

	// Get permissions
	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(t, err)

	var readPermID, updatePermID string
	for _, perm := range permissions {
		if perm.Resource == "resource" {
			if perm.Action == "read" {
				readPermID = perm.ID
			} else if perm.Action == "update" {
				updatePermID = perm.ID
			}
		}
	}

	// Assign read to role1, update to role2
	require.NoError(t, module.GetService().AssignPermissionsToRole(ctx, role1.ID, []string{readPermID}))
	require.NoError(t, module.GetService().AssignPermissionsToRole(ctx, role2.ID, []string{updatePermID}))

	// Assign both roles to user
	require.NoError(t, module.GetService().AssignRoleToUser(ctx, userID, role1.ID, tenantID, userID))
	require.NoError(t, module.GetService().AssignRoleToUser(ctx, userID, role2.ID, tenantID, userID))

	// User should have both permissions
	result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: "resource",
		Action:   "read",
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed, "User should have read permission from role1")

	result, err = module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: "resource",
		Action:   "update",
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed, "User should have update permission from role2")
}

func TestIntegration_CacheInvalidation(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "user@example.com")

	// Create role with permission
	role, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Test Role",
		Slug: "test-role",
	})
	require.NoError(t, err)

	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(t, err)

	var readPermID string
	for _, perm := range permissions {
		if perm.Resource == "resource" && perm.Action == "read" {
			readPermID = perm.ID
			break
		}
	}

	require.NoError(t, module.GetService().AssignPermissionsToRole(ctx, role.ID, []string{readPermID}))
	require.NoError(t, module.GetService().AssignRoleToUser(ctx, userID, role.ID, tenantID, userID))

	// First check - should populate cache
	result1, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: "resource",
		Action:   "read",
	})
	require.NoError(t, err)
	assert.True(t, result1.Allowed)

	// Get stats - should show cache miss (first access)
	stats1 := module.GetPolicyEngine().Stats()
	initialMisses := stats1.CacheMisses

	// Second check - should hit cache
	result2, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: "resource",
		Action:   "read",
	})
	require.NoError(t, err)
	assert.True(t, result2.Allowed)

	stats2 := module.GetPolicyEngine().Stats()
	assert.Greater(t, stats2.CacheHits, stats1.CacheHits, "Second check should be cache hit")

	// Invalidate user cache
	err = module.GetPolicyEngine().InvalidateUserCache(ctx, userID, tenantID)
	require.NoError(t, err)

	// Third check - should be cache miss again after invalidation
	result3, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: "resource",
		Action:   "read",
	})
	require.NoError(t, err)
	assert.True(t, result3.Allowed)

	stats3 := module.GetPolicyEngine().Stats()
	assert.Greater(t, stats3.CacheMisses, initialMisses, "After invalidation should cause cache miss")
}

func TestIntegration_TenantAdminBypass(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(t, db, "test-tenant")
	adminUserID := createTestUserInDB(t, db, tenantID, "admin@example.com")

	// Get the system admin role (created by trigger)
	roles, err := module.GetService().ListRoles(ctx, tenantID, true)
	require.NoError(t, err)

	var adminRole *rbac.Role
	for _, role := range roles {
		if role.Slug == "admin" && role.IsSystem {
			adminRole = role
			break
		}
	}
	require.NotNil(t, adminRole, "System admin role should exist")

	// Assign admin role to user
	err = module.GetService().AssignRoleToUser(ctx, adminUserID, adminRole.ID, tenantID, adminUserID)
	require.NoError(t, err)

	// Admin should have access to any tenant-scoped resource without explicit permission
	testResources := []struct {
		resource string
		action   string
	}{
		{"resource", "create"},
		{"resource", "read"},
		{"resource", "update"},
		{"resource", "delete"},
		{"user", "create"},
		{"user", "delete"},
	}

	for _, test := range testResources {
		t.Run(test.resource+":"+test.action, func(t *testing.T) {
			result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
				UserID:   adminUserID,
				TenantID: tenantID,
				Resource: test.resource,
				Action:   test.action,
			})
			require.NoError(t, err)
			assert.True(t, result.Allowed, "Admin should have %s:%s permission", test.resource, test.action)
			assert.Equal(t, "admin_override", result.Reason, "Should be admin override")
		})
	}
}

func TestIntegration_RoleModification(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "user@example.com")

	// Create role and assign to user
	role, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Dynamic Role",
		Slug: "dynamic",
	})
	require.NoError(t, err)

	require.NoError(t, module.GetService().AssignRoleToUser(ctx, userID, role.ID, tenantID, userID))

	// Initially, user has no permissions
	result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: "resource",
		Action:   "read",
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed, "User should not have permission initially")

	// Add permission to role
	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(t, err)

	var readPermID string
	for _, perm := range permissions {
		if perm.Resource == "resource" && perm.Action == "read" {
			readPermID = perm.ID
			break
		}
	}

	require.NoError(t, module.GetService().AssignPermissionsToRole(ctx, role.ID, []string{readPermID}))

	// Invalidate cache
	require.NoError(t, module.GetPolicyEngine().InvalidateUserCache(ctx, userID, tenantID))

	// Now user should have permission
	result, err = module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: "resource",
		Action:   "read",
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed, "User should have permission after role modification")
}

func TestIntegration_SystemRoleImmutability(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(t, db, "test-tenant")

	// Get system admin role
	roles, err := module.GetService().ListRoles(ctx, tenantID, true)
	require.NoError(t, err)

	var systemRole *rbac.Role
	for _, role := range roles {
		if role.IsSystem {
			systemRole = role
			break
		}
	}
	require.NotNil(t, systemRole, "Should have at least one system role")

	// Attempt to update system role - should fail
	newName := "Hacked Name"
	_, err = module.GetService().UpdateRole(ctx, tenantID, systemRole.ID, rbac.UpdateRoleRequest{
		Name: &newName,
	})
	assert.Error(t, err)
	assert.Equal(t, rbac.ErrSystemRoleProtected, err)

	// Attempt to delete system role - should fail
	err = module.GetService().DeleteRole(ctx, tenantID, systemRole.ID)
	assert.Error(t, err)
	assert.Equal(t, rbac.ErrSystemRoleProtected, err)

	// Attempt to modify system role permissions - should fail
	err = module.GetService().AssignPermissionsToRole(ctx, systemRole.ID, []string{})
	assert.Error(t, err)
	assert.Equal(t, rbac.ErrSystemRoleProtected, err)
}

func TestIntegration_CrossTenantIsolation(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()

	// Create two tenants
	tenant1ID := createTestTenantInDB(t, db, "tenant1")
	tenant2ID := createTestTenantInDB(t, db, "tenant2")

	user1ID := createTestUserInDB(t, db, tenant1ID, "user1@example.com")
	user2ID := createTestUserInDB(t, db, tenant2ID, "user2@example.com")

	// Create role in tenant1
	role1, err := module.GetService().CreateRole(ctx, tenant1ID, rbac.CreateRoleRequest{
		Name: "Tenant1 Role",
		Slug: "tenant1-role",
	})
	require.NoError(t, err)

	// User2 from tenant2 should NOT be able to get tenant1's role
	_, err = module.GetService().GetRole(ctx, tenant2ID, role1.ID)
	assert.Error(t, err)
	assert.Equal(t, rbac.ErrRoleNotFound, err, "Cross-tenant role access should be denied")

	// Get permissions
	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(t, err)

	var readPermID string
	for _, perm := range permissions {
		if perm.Resource == "resource" && perm.Action == "read" {
			readPermID = perm.ID
			break
		}
	}

	// Assign permission to tenant1 role and role to user1
	require.NoError(t, module.GetService().AssignPermissionsToRole(ctx, role1.ID, []string{readPermID}))
	require.NoError(t, module.GetService().AssignRoleToUser(ctx, user1ID, role1.ID, tenant1ID, user1ID))

	// User1 should have permission in tenant1
	result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   user1ID,
		TenantID: tenant1ID,
		Resource: "resource",
		Action:   "read",
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	// User1 should NOT have permission in tenant2 (wrong tenant)
	result, err = module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   user1ID,
		TenantID: tenant2ID,
		Resource: "resource",
		Action:   "read",
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed, "User should not have permission in different tenant")

	// User2 should not have permission (no role assigned)
	result, err = module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   user2ID,
		TenantID: tenant2ID,
		Resource: "resource",
		Action:   "read",
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestIntegration_PermissionMetrics(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(t, db, "test-tenant")
	adminUserID := createTestUserInDB(t, db, tenantID, "admin@example.com")

	// Get admin role and assign
	roles, err := module.GetService().ListRoles(ctx, tenantID, true)
	require.NoError(t, err)

	var adminRole *rbac.Role
	for _, role := range roles {
		if role.Slug == "admin" {
			adminRole = role
			break
		}
	}
	require.NotNil(t, adminRole)

	require.NoError(t, module.GetService().AssignRoleToUser(ctx, adminUserID, adminRole.ID, tenantID, adminUserID))

	// Get initial stats
	initialStats := module.GetPolicyEngine().Stats()

	// Perform multiple permission checks
	for i := 0; i < 10; i++ {
		_, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
			UserID:   adminUserID,
			TenantID: tenantID,
			Resource: "resource",
			Action:   "read",
		})
		require.NoError(t, err)
	}

	// Get final stats
	finalStats := module.GetPolicyEngine().Stats()

	// Verify metrics increased
	assert.Greater(t, finalStats.TotalChecks, initialStats.TotalChecks)
	assert.Equal(t, uint64(10), finalStats.TotalChecks-initialStats.TotalChecks, "Should have 10 more checks")
	assert.Greater(t, finalStats.AdminOverrides, initialStats.AdminOverrides, "Should have admin overrides")
	assert.Greater(t, finalStats.AvgCheckTimeMs, float64(0), "Average check time should be > 0")
}

func TestIntegration_GetUserPermissions(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "user@example.com")

	// Create role with multiple permissions
	role, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Multi-Perm Role",
		Slug: "multi-perm",
	})
	require.NoError(t, err)

	// Get permissions
	allPermissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(t, err)

	// Find read and update permissions for resource
	var readPermID, updatePermID string
	for _, perm := range allPermissions {
		if perm.Resource == "resource" {
			if perm.Action == "read" {
				readPermID = perm.ID
			} else if perm.Action == "update" {
				updatePermID = perm.ID
			}
		}
	}

	// Assign both permissions to role
	require.NoError(t, module.GetService().AssignPermissionsToRole(ctx, role.ID, []string{readPermID, updatePermID}))

	// Assign role to user
	require.NoError(t, module.GetService().AssignRoleToUser(ctx, userID, role.ID, tenantID, userID))

	// Get user permissions
	userPermissions, err := module.GetPolicyEngine().GetUserPermissions(ctx, userID, tenantID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(userPermissions), 2, "User should have at least 2 permissions")

	// Verify both permissions are present
	hasRead := false
	hasUpdate := false
	for _, perm := range userPermissions {
		if perm.Resource == "resource" {
			if perm.Action == "read" {
				hasRead = true
			} else if perm.Action == "update" {
				hasUpdate = true
			}
		}
	}

	assert.True(t, hasRead, "User should have read permission")
	assert.True(t, hasUpdate, "User should have update permission")
}

func TestIntegration_BatchPermissionChecks(t *testing.T) {
	module, db, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "user@example.com")

	// Create role with read permission only
	role, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Reader",
		Slug: "reader",
	})
	require.NoError(t, err)

	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(t, err)

	var readPermID string
	for _, perm := range permissions {
		if perm.Resource == "resource" && perm.Action == "read" {
			readPermID = perm.ID
			break
		}
	}

	require.NoError(t, module.GetService().AssignPermissionsToRole(ctx, role.ID, []string{readPermID}))
	require.NoError(t, module.GetService().AssignRoleToUser(ctx, userID, role.ID, tenantID, userID))

	// Batch check multiple permissions
	requests := []rbac.PermissionCheckRequest{
		{UserID: userID, TenantID: tenantID, Resource: "resource", Action: "read"},
		{UserID: userID, TenantID: tenantID, Resource: "resource", Action: "update"},
		{UserID: userID, TenantID: tenantID, Resource: "resource", Action: "delete"},
	}

	results, err := module.GetPolicyEngine().CheckPermissions(ctx, requests)
	require.NoError(t, err)
	assert.Len(t, results, 3)

	// First should be allowed (has read permission)
	assert.True(t, results[0].Allowed, "Should have read permission")

	// Others should be denied
	assert.False(t, results[1].Allowed, "Should not have update permission")
	assert.False(t, results[2].Allowed, "Should not have delete permission")
}

// ========================================
// Helper Functions for Integration Tests
// ========================================

// Note: createTestTenantInDB and createTestUserInDB are defined in repository_test.go
// and are reused here for integration tests

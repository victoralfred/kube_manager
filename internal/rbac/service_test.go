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

// TestService_SecurityIsolation tests that tenant data is properly isolated
func TestService_SecurityIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	log := logger.New("error", "test")
	cacheInstance := cache.NewInMemoryCache()

	// Create RBAC module
	module := rbac.NewModule(db, rbac.ModuleConfig{
		Cache:    cacheInstance,
		CacheTTL: 5 * time.Minute,
	}, log)

	// Register core resources
	require.NoError(t, rbac.RegisterCoreResources(module.GetRegistry()))

	// Create two tenants
	tenant1ID := createTestTenant(t, db, "tenant1")
	tenant2ID := createTestTenant(t, db, "tenant2")

	// Create role in tenant1
	role1, err := module.GetService().CreateRole(ctx, tenant1ID, rbac.CreateRoleRequest{
		Name:        "Custom Role 1",
		Slug:        "custom-role-1",
		Description: "Role for tenant 1",
	})
	require.NoError(t, err)
	require.NotNil(t, role1)
	require.Equal(t, tenant1ID, *role1.TenantID)

	// Create role in tenant2
	role2, err := module.GetService().CreateRole(ctx, tenant2ID, rbac.CreateRoleRequest{
		Name:        "Custom Role 2",
		Slug:        "custom-role-2",
		Description: "Role for tenant 2",
	})
	require.NoError(t, err)
	require.NotNil(t, role2)
	require.Equal(t, tenant2ID, *role2.TenantID)

	t.Run("Cannot access role from different tenant", func(t *testing.T) {
		// Tenant 1 trying to get Tenant 2's role
		_, err := module.GetService().GetRole(ctx, tenant1ID, role2.ID)
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrRoleNotFound, err)

		// Tenant 2 trying to get Tenant 1's role
		_, err = module.GetService().GetRole(ctx, tenant2ID, role1.ID)
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrRoleNotFound, err)
	})

	t.Run("Cannot update role from different tenant", func(t *testing.T) {
		newName := "Hacked Name"

		// Tenant 1 trying to update Tenant 2's role
		_, err := module.GetService().UpdateRole(ctx, tenant1ID, role2.ID, rbac.UpdateRoleRequest{
			Name: &newName,
		})
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrRoleNotFound, err)

		// Verify role2 was not modified
		role, err := module.GetService().GetRole(ctx, tenant2ID, role2.ID)
		require.NoError(t, err)
		assert.NotEqual(t, newName, role.Name)
	})

	t.Run("Cannot delete role from different tenant", func(t *testing.T) {
		// Tenant 1 trying to delete Tenant 2's role
		err := module.GetService().DeleteRole(ctx, tenant1ID, role2.ID)
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrRoleNotFound, err)

		// Verify role2 still exists
		role, err := module.GetService().GetRole(ctx, tenant2ID, role2.ID)
		require.NoError(t, err)
		assert.NotNil(t, role)
	})

	t.Run("List roles only returns tenant's own roles", func(t *testing.T) {
		// Tenant 1 list should not include tenant 2's roles
		roles1, err := module.GetService().ListRoles(ctx, tenant1ID, false)
		require.NoError(t, err)

		for _, role := range roles1 {
			if role.TenantID != nil {
				assert.Equal(t, tenant1ID, *role.TenantID, "Tenant 1 should not see tenant 2's roles")
			}
		}

		// Tenant 2 list should not include tenant 1's roles
		roles2, err := module.GetService().ListRoles(ctx, tenant2ID, false)
		require.NoError(t, err)

		for _, role := range roles2 {
			if role.TenantID != nil {
				assert.Equal(t, tenant2ID, *role.TenantID, "Tenant 2 should not see tenant 1's roles")
			}
		}
	})
}

// TestService_SystemRoleProtection tests that system roles cannot be modified
func TestService_SystemRoleProtection(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	log := logger.New("error", "test")
	cacheInstance := cache.NewInMemoryCache()

	module := rbac.NewModule(db, rbac.ModuleConfig{
		Cache:    cacheInstance,
		CacheTTL: 5 * time.Minute,
	}, log)

	require.NoError(t, rbac.RegisterCoreResources(module.GetRegistry()))

	tenantID := createTestTenant(t, db, "test-tenant")

	// Get system admin role
	roles, err := module.GetService().ListRoles(ctx, tenantID, true)
	require.NoError(t, err)

	var systemRole *rbac.Role
	for i := range roles {
		if roles[i].IsSystem && roles[i].Slug == "admin" {
			systemRole = roles[i]
			break
		}
	}
	require.NotNil(t, systemRole, "System admin role should exist")

	t.Run("Cannot update system role", func(t *testing.T) {
		newName := "Hacked Admin"
		_, err := module.GetService().UpdateRole(ctx, tenantID, systemRole.ID, rbac.UpdateRoleRequest{
			Name: &newName,
		})
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrSystemRoleProtected, err)
	})

	t.Run("Cannot delete system role", func(t *testing.T) {
		err := module.GetService().DeleteRole(ctx, tenantID, systemRole.ID)
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrSystemRoleProtected, err)
	})

	t.Run("Cannot modify system role permissions", func(t *testing.T) {
		err := module.GetService().AssignPermissionsToRole(ctx, systemRole.ID, []string{})
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrSystemRoleProtected, err)
	})
}

// setupTestDB creates a test database connection
func setupTestDB(t *testing.T) (*database.DB, func()) {
	// This would connect to a real test database
	// For now, we'll skip actual database tests
	t.Skip("Database tests require test database setup")
	return nil, func() {}
}

// createTestTenant creates a test tenant in the database
func createTestTenant(t *testing.T, db *database.DB, name string) string {
	// This would create a real tenant
	// For now, we return a mock ID
	return "tenant-" + name
}

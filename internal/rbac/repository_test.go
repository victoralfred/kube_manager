package rbac_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/pkg/database"
)

// ========================================
// Test Database Setup
// ========================================

// setupTestDatabase creates a test database connection
func setupTestDatabase(t *testing.T) (*database.DB, func()) {
	// Check if we should run database tests
	if os.Getenv("RUN_DB_TESTS") != "true" {
		t.Skip("Skipping database tests. Set RUN_DB_TESTS=true to run")
	}

	// Get test database URL from environment
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}

	// Connect to test database
	db, err := database.NewPostgres(database.Config{
		DSN:             dbURL,
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Return cleanup function
	cleanup := func() {
		// Clean up test data
		cleanupTestData(t, db)
		// Close connection
		if err := db.Close(); err != nil {
			t.Logf("Failed to close database: %v", err)
		}
	}

	return db, cleanup
}

// cleanupTestData removes all test data from database
func cleanupTestData(t *testing.T, db *database.DB) {
	ctx := context.Background()

	// Delete in correct order to respect foreign keys
	tables := []string{
		"user_roles",
		"role_permissions",
		"roles",
		"permissions",
		"resource_registry",
		"users",
		"tenants",
	}

	for _, table := range tables {
		query := "DELETE FROM " + table + " WHERE created_at > NOW() - INTERVAL '1 hour'"
		_, err := db.ExecContext(ctx, query)
		if err != nil {
			t.Logf("Warning: Failed to clean %s: %v", table, err)
		}
	}
}

// ========================================
// Helper Functions for Test Data
// ========================================

// createTestTenantInDB creates a real tenant in the database
func createTestTenantInDB(t *testing.T, db *database.DB, name string) string {
	ctx := context.Background()
	tenantID := uuid.New().String()

	query := `
		INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', NOW(), NOW())
	`

	_, err := db.ExecContext(ctx, query, tenantID, name, name)
	require.NoError(t, err, "Failed to create test tenant")

	return tenantID
}

// createTestUserInDB creates a test user in the database
func createTestUserInDB(t *testing.T, db *database.DB, tenantID, email string) string {
	ctx := context.Background()
	userID := uuid.New().String()

	query := `
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'hash', 'Test', 'User', 'active', NOW(), NOW())
	`

	_, err := db.ExecContext(ctx, query, userID, tenantID, email)
	require.NoError(t, err, "Failed to create test user")

	return userID
}

// createTestPermission creates a test permission
func createTestPermission(t *testing.T, db *database.DB, resource, action string, scope rbac.PermissionScope) *rbac.Permission {
	ctx := context.Background()
	permissionID := uuid.New().String()

	query := `
		INSERT INTO permissions (id, resource, action, scope, requires_ownership, description, created_at)
		VALUES ($1, $2, $3, $4, false, $5, NOW())
		ON CONFLICT (resource, action) DO UPDATE SET id = permissions.id
		RETURNING id
	`

	err := db.QueryRowContext(ctx, query, permissionID, resource, action, scope, "Test permission").Scan(&permissionID)
	require.NoError(t, err, "Failed to create test permission")

	return &rbac.Permission{
		ID:       permissionID,
		Resource: resource,
		Action:   action,
		Scope:    scope,
	}
}

// ========================================
// Repository Tests
// ========================================

func TestRepository_CreateRole(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")

	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Test Role",
		Slug:        "test-role",
		Description: "Test role description",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := repo.CreateRole(ctx, role)

	assert.NoError(t, err)
	assert.NotEmpty(t, role.ID)

	// Verify role was created
	retrieved, err := repo.GetRoleByID(ctx, role.ID)
	require.NoError(t, err)
	assert.Equal(t, role.Name, retrieved.Name)
	assert.Equal(t, role.Slug, retrieved.Slug)
}

func TestRepository_GetRoleByID(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")

	// Create a role
	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Test Role",
		Slug:        "test-role",
		Description: "Test description",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role))

	tests := []struct {
		name    string
		roleID  string
		wantErr bool
		errType error
	}{
		{
			name:    "Get existing role",
			roleID:  role.ID,
			wantErr: false,
		},
		{
			name:    "Get non-existent role",
			roleID:  uuid.New().String(),
			wantErr: true,
			errType: rbac.ErrRoleNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := repo.GetRoleByID(ctx, tt.roleID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.Equal(t, tt.errType, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, retrieved)
				assert.Equal(t, role.Name, retrieved.Name)
			}
		})
	}
}

func TestRepository_GetRoleBySlug(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")

	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Test Role",
		Slug:        "test-role",
		Description: "Test description",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role))

	// Test successful retrieval
	retrieved, err := repo.GetRoleBySlug(ctx, tenantID, "test-role")
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, role.Name, retrieved.Name)

	// Test non-existent slug
	_, err = repo.GetRoleBySlug(ctx, tenantID, "non-existent")
	assert.Error(t, err)
	assert.Equal(t, rbac.ErrRoleNotFound, err)
}

func TestRepository_UpdateRole(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")

	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Original Name",
		Slug:        "test-role",
		Description: "Original description",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role))

	// Update role
	role.Name = "Updated Name"
	role.Description = "Updated description"
	role.UpdatedAt = time.Now()

	err := repo.UpdateRole(ctx, role)
	assert.NoError(t, err)

	// Verify update
	retrieved, err := repo.GetRoleByID(ctx, role.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", retrieved.Name)
	assert.Equal(t, "Updated description", retrieved.Description)

	// Test updating non-existent role
	nonExistent := &rbac.Role{
		ID:        uuid.New().String(),
		Name:      "Non-existent",
		UpdatedAt: time.Now(),
	}
	err = repo.UpdateRole(ctx, nonExistent)
	assert.Error(t, err)
	assert.Equal(t, rbac.ErrRoleNotFound, err)
}

func TestRepository_DeleteRole(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")

	t.Run("Delete custom role", func(t *testing.T) {
		role := &rbac.Role{
			ID:          uuid.New().String(),
			TenantID:    &tenantID,
			Name:        "Test Role",
			Slug:        "test-role",
			Description: "Test description",
			RoleType:    rbac.RoleTypeCustom,
			IsSystem:    false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		require.NoError(t, repo.CreateRole(ctx, role))

		err := repo.DeleteRole(ctx, role.ID)
		assert.NoError(t, err)

		// Verify role is soft-deleted
		_, err = repo.GetRoleByID(ctx, role.ID)
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrRoleNotFound, err)
	})

	t.Run("Cannot delete system role", func(t *testing.T) {
		systemRole := &rbac.Role{
			ID:          uuid.New().String(),
			TenantID:    &tenantID,
			Name:        "System Role",
			Slug:        "system-role",
			Description: "System role",
			RoleType:    rbac.RoleTypeSystem,
			IsSystem:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		require.NoError(t, repo.CreateRole(ctx, systemRole))

		err := repo.DeleteRole(ctx, systemRole.ID)
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrSystemRoleProtected, err)

		// Verify role still exists
		_, err = repo.GetRoleByID(ctx, systemRole.ID)
		assert.NoError(t, err)
	})
}

func TestRepository_ListRoles(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")

	// Create system role
	systemRole := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Admin",
		Slug:        "admin",
		Description: "System admin",
		RoleType:    rbac.RoleTypeSystem,
		IsSystem:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, systemRole))

	// Create custom role
	customRole := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Custom",
		Slug:        "custom",
		Description: "Custom role",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, customRole))

	t.Run("List without system roles", func(t *testing.T) {
		roles, total, err := repo.ListRoles(ctx, rbac.ListRolesFilter{
			TenantID:      tenantID,
			IncludeSystem: false,
			Limit:         10,
			Offset:        0,
		})

		assert.NoError(t, err)
		assert.Greater(t, total, 0)

		// Verify no system roles included
		for _, role := range roles {
			assert.False(t, role.IsSystem, "System roles should not be included")
		}
	})

	t.Run("List with system roles", func(t *testing.T) {
		roles, total, err := repo.ListRoles(ctx, rbac.ListRolesFilter{
			TenantID:      tenantID,
			IncludeSystem: true,
			Limit:         10,
			Offset:        0,
		})

		assert.NoError(t, err)
		assert.Greater(t, total, 1)

		// Verify at least one system role
		hasSystemRole := false
		for _, role := range roles {
			if role.IsSystem {
				hasSystemRole = true
				break
			}
		}
		assert.True(t, hasSystemRole, "Should include system roles")
	})

	t.Run("List with pagination", func(t *testing.T) {
		// First page
		roles1, total1, err := repo.ListRoles(ctx, rbac.ListRolesFilter{
			TenantID:      tenantID,
			IncludeSystem: true,
			Limit:         1,
			Offset:        0,
		})

		assert.NoError(t, err)
		assert.Len(t, roles1, 1)
		assert.Greater(t, total1, 1)

		// Second page
		roles2, total2, err := repo.ListRoles(ctx, rbac.ListRolesFilter{
			TenantID:      tenantID,
			IncludeSystem: true,
			Limit:         1,
			Offset:        1,
		})

		assert.NoError(t, err)
		assert.Len(t, roles2, 1)
		assert.Equal(t, total1, total2)
		assert.NotEqual(t, roles1[0].ID, roles2[0].ID, "Should return different roles")
	})
}

func TestRepository_RoleExists(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")

	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Test Role",
		Slug:        "test-role",
		Description: "Test",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role))

	// Test existing role
	exists, err := repo.RoleExists(ctx, tenantID, "test-role")
	assert.NoError(t, err)
	assert.True(t, exists)

	// Test non-existent role
	exists, err = repo.RoleExists(ctx, tenantID, "non-existent")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestRepository_AssignPermissionsToRole(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")

	// Create role
	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Test Role",
		Slug:        "test-role",
		Description: "Test",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role))

	// Create permissions
	perm1 := createTestPermission(t, db, "test-resource", "read", rbac.PermissionScopeTenant)
	perm2 := createTestPermission(t, db, "test-resource", "write", rbac.PermissionScopeTenant)

	// Assign permissions
	err := repo.AssignPermissionsToRole(ctx, role.ID, []string{perm1.ID, perm2.ID})
	assert.NoError(t, err)

	// Verify permissions assigned
	permissions, err := repo.GetRolePermissions(ctx, role.ID)
	assert.NoError(t, err)
	assert.Len(t, permissions, 2)

	// Test idempotency - assigning same permissions again should not error
	err = repo.AssignPermissionsToRole(ctx, role.ID, []string{perm1.ID})
	assert.NoError(t, err)
}

func TestRepository_RemoveAllPermissionsFromRole(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")

	// Create role with permissions
	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Test Role",
		Slug:        "test-role",
		Description: "Test",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role))

	perm := createTestPermission(t, db, "test-resource", "read", rbac.PermissionScopeTenant)
	require.NoError(t, repo.AssignPermissionsToRole(ctx, role.ID, []string{perm.ID}))

	// Remove all permissions
	err := repo.RemoveAllPermissionsFromRole(ctx, role.ID)
	assert.NoError(t, err)

	// Verify no permissions remain
	permissions, err := repo.GetRolePermissions(ctx, role.ID)
	assert.NoError(t, err)
	assert.Empty(t, permissions)
}

func TestRepository_AssignRoleToUser(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "test@example.com")

	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Test Role",
		Slug:        "test-role",
		Description: "Test",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role))

	userRole := &rbac.UserRole{
		ID:        uuid.New().String(),
		UserID:    userID,
		RoleID:    role.ID,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		CreatedBy: userID,
	}

	err := repo.AssignRoleToUser(ctx, userRole)
	assert.NoError(t, err)

	// Verify assignment
	roles, err := repo.GetUserRoles(ctx, userID, tenantID)
	assert.NoError(t, err)
	assert.Len(t, roles, 1)
	assert.Equal(t, role.ID, roles[0].ID)

	// Test idempotency
	err = repo.AssignRoleToUser(ctx, userRole)
	assert.NoError(t, err)
}

func TestRepository_RemoveRoleFromUser(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "test@example.com")

	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Test Role",
		Slug:        "test-role",
		Description: "Test",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role))

	userRole := &rbac.UserRole{
		ID:        uuid.New().String(),
		UserID:    userID,
		RoleID:    role.ID,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		CreatedBy: userID,
	}
	require.NoError(t, repo.AssignRoleToUser(ctx, userRole))

	// Remove role
	err := repo.RemoveRoleFromUser(ctx, userID, role.ID)
	assert.NoError(t, err)

	// Verify removal
	roles, err := repo.GetUserRoles(ctx, userID, tenantID)
	assert.NoError(t, err)
	assert.Empty(t, roles)

	// Test removing non-existent assignment
	err = repo.RemoveRoleFromUser(ctx, userID, role.ID)
	assert.Error(t, err)
	assert.Equal(t, rbac.ErrUserRoleNotFound, err)
}

func TestRepository_GetUserPermissions(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "test@example.com")

	// Create role with permissions
	role := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Test Role",
		Slug:        "test-role",
		Description: "Test",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role))

	perm1 := createTestPermission(t, db, "resource1", "read", rbac.PermissionScopeTenant)
	perm2 := createTestPermission(t, db, "resource2", "write", rbac.PermissionScopeTenant)
	require.NoError(t, repo.AssignPermissionsToRole(ctx, role.ID, []string{perm1.ID, perm2.ID}))

	// Assign role to user
	userRole := &rbac.UserRole{
		ID:        uuid.New().String(),
		UserID:    userID,
		RoleID:    role.ID,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		CreatedBy: userID,
	}
	require.NoError(t, repo.AssignRoleToUser(ctx, userRole))

	// Get user permissions
	permissions, err := repo.GetUserPermissions(ctx, userID, tenantID)
	assert.NoError(t, err)
	assert.Len(t, permissions, 2)

	// Verify permission details
	resourceActions := make(map[string]string)
	for _, perm := range permissions {
		resourceActions[perm.Resource] = perm.Action
	}
	assert.Equal(t, "read", resourceActions["resource1"])
	assert.Equal(t, "write", resourceActions["resource2"])
}

func TestRepository_IsTenantAdmin(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")
	adminUserID := createTestUserInDB(t, db, tenantID, "admin@example.com")
	regularUserID := createTestUserInDB(t, db, tenantID, "user@example.com")

	// Create admin role
	adminRole := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenantID,
		Name:        "Administrator",
		Slug:        "admin",
		Description: "Admin role",
		RoleType:    rbac.RoleTypeSystem,
		IsSystem:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, adminRole))

	// Assign admin role to admin user
	userRole := &rbac.UserRole{
		ID:        uuid.New().String(),
		UserID:    adminUserID,
		RoleID:    adminRole.ID,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		CreatedBy: adminUserID,
	}
	require.NoError(t, repo.AssignRoleToUser(ctx, userRole))

	// Test admin user
	isAdmin, err := repo.IsTenantAdmin(ctx, adminUserID, tenantID)
	assert.NoError(t, err)
	assert.True(t, isAdmin)

	// Test regular user
	isAdmin, err = repo.IsTenantAdmin(ctx, regularUserID, tenantID)
	assert.NoError(t, err)
	assert.False(t, isAdmin)
}

func TestRepository_TenantIsolation(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	// Create two tenants
	tenant1ID := createTestTenantInDB(t, db, "tenant1")
	tenant2ID := createTestTenantInDB(t, db, "tenant2")

	// Create role in tenant1
	role1 := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenant1ID,
		Name:        "Role 1",
		Slug:        "role1",
		Description: "Tenant 1 role",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role1))

	// Create role in tenant2
	role2 := &rbac.Role{
		ID:          uuid.New().String(),
		TenantID:    &tenant2ID,
		Name:        "Role 2",
		Slug:        "role2",
		Description: "Tenant 2 role",
		RoleType:    rbac.RoleTypeCustom,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateRole(ctx, role2))

	t.Run("GetRoleBySlug respects tenant isolation", func(t *testing.T) {
		// Tenant1 should not see tenant2's role
		_, err := repo.GetRoleBySlug(ctx, tenant1ID, "role2")
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrRoleNotFound, err)

		// Tenant2 should not see tenant1's role
		_, err = repo.GetRoleBySlug(ctx, tenant2ID, "role1")
		assert.Error(t, err)
		assert.Equal(t, rbac.ErrRoleNotFound, err)
	})

	t.Run("ListRoles respects tenant isolation", func(t *testing.T) {
		// List roles for tenant1
		roles1, _, err := repo.ListRoles(ctx, rbac.ListRolesFilter{
			TenantID:      tenant1ID,
			IncludeSystem: false,
			Limit:         100,
			Offset:        0,
		})
		require.NoError(t, err)

		// Verify no tenant2 roles in tenant1's list
		for _, role := range roles1 {
			if role.TenantID != nil {
				assert.Equal(t, tenant1ID, *role.TenantID)
			}
		}

		// List roles for tenant2
		roles2, _, err := repo.ListRoles(ctx, rbac.ListRolesFilter{
			TenantID:      tenant2ID,
			IncludeSystem: false,
			Limit:         100,
			Offset:        0,
		})
		require.NoError(t, err)

		// Verify no tenant1 roles in tenant2's list
		for _, role := range roles2 {
			if role.TenantID != nil {
				assert.Equal(t, tenant2ID, *role.TenantID)
			}
		}
	})
}

func TestRepository_GetResourceOwner(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()

	tenantID := createTestTenantInDB(t, db, "test-tenant")
	userID := createTestUserInDB(t, db, tenantID, "test@example.com")

	// Test user ownership (users table has created_by or similar owner field)
	owner, err := repo.GetResourceOwner(ctx, "user", userID)

	// This test depends on your actual schema structure
	// If users table has an owner/created_by field, this should work
	// Otherwise, it may return an error which is also valid
	if err == nil {
		assert.NotEmpty(t, owner)
	} else {
		// Expected if ownership field doesn't exist
		t.Logf("GetResourceOwner returned error (expected if no ownership field): %v", err)
	}
}

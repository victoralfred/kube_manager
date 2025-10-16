package rbac_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/pkg/cache"
	"github.com/victoralfred/kube_manager/pkg/database"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// BenchmarkPermissionCheck_CacheHit benchmarks permission checks with warm cache
func BenchmarkPermissionCheck_CacheHit(b *testing.B) {
	module, db, cleanup := setupBenchmarkTest(b)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(b, db, "bench-tenant")
	userID := createTestUserInDB(b, db, tenantID, "bench@example.com")

	// Setup: Create role with permission and assign to user
	role, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Benchmark Role",
		Slug: "bench-role",
	})
	require.NoError(b, err)

	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(b, err)
	require.NotEmpty(b, permissions)

	// Assign first permission to role
	err = module.GetService().AssignPermissionsToRole(ctx, role.ID, []string{permissions[0].ID})
	require.NoError(b, err)

	// Assign role to user
	err = module.GetService().AssignRoleToUser(ctx, userID, role.ID, tenantID, userID)
	require.NoError(b, err)

	// Warm up the cache with one call
	_, _ = module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: permissions[0].Resource,
		Action:   permissions[0].Action,
	})

	b.ResetTimer()
	b.ReportAllocs()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
			UserID:   userID,
			TenantID: tenantID,
			Resource: permissions[0].Resource,
			Action:   permissions[0].Action,
		})
		if err != nil {
			b.Fatalf("Permission check failed: %v", err)
		}
		if !result.Allowed {
			b.Fatalf("Expected permission to be allowed")
		}
	}
}

// BenchmarkPermissionCheck_CacheMiss benchmarks permission checks without cache
func BenchmarkPermissionCheck_CacheMiss(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping cache miss benchmark in short mode")
	}

	// Create fresh module for each iteration to force cache misses
	cacheInstance := cache.NewInMemoryCache()
	log := logger.New("error", "benchmark")

	db, cleanup := setupTestDatabase(b)
	defer cleanup()

	module := rbac.NewModule(db, rbac.ModuleConfig{
		Cache:    cacheInstance,
		CacheTTL: 5 * time.Minute,
	}, log)

	require.NoError(b, rbac.RegisterCoreResources(module.GetRegistry()))

	ctx := context.Background()
	tenantID := createTestTenantInDB(b, db, "bench-tenant-miss")
	userID := createTestUserInDB(b, db, tenantID, "bench-miss@example.com")

	// Setup: Create role with permission and assign to user
	role, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Benchmark Role Miss",
		Slug: "bench-role-miss",
	})
	require.NoError(b, err)

	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(b, err)
	require.NotEmpty(b, permissions)

	// Assign first permission to role
	err = module.GetService().AssignPermissionsToRole(ctx, role.ID, []string{permissions[0].ID})
	require.NoError(b, err)

	// Assign role to user
	err = module.GetService().AssignRoleToUser(ctx, userID, role.ID, tenantID, userID)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	// Run benchmark - clear cache each iteration
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Clear cache to force miss
		_ = cacheInstance.DeletePattern(ctx, fmt.Sprintf("rbac:user:%s:*", userID))
		b.StartTimer()

		result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
			UserID:   userID,
			TenantID: tenantID,
			Resource: permissions[0].Resource,
			Action:   permissions[0].Action,
		})
		if err != nil {
			b.Fatalf("Permission check failed: %v", err)
		}
		if !result.Allowed {
			b.Fatalf("Expected permission to be allowed")
		}
	}
}

// BenchmarkBatchPermissionCheck benchmarks batch permission checks
func BenchmarkBatchPermissionCheck(b *testing.B) {
	module, db, cleanup := setupBenchmarkTest(b)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(b, db, "bench-batch-tenant")
	userID := createTestUserInDB(b, db, tenantID, "bench-batch@example.com")

	// Setup: Create role with multiple permissions
	role, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Batch Benchmark Role",
		Slug: "bench-batch-role",
	})
	require.NoError(b, err)

	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(b, err)
	require.True(b, len(permissions) >= 10, "Need at least 10 permissions for benchmark")

	// Assign first 10 permissions to role
	permIDs := make([]string, 10)
	for i := 0; i < 10; i++ {
		permIDs[i] = permissions[i].ID
	}
	err = module.GetService().AssignPermissionsToRole(ctx, role.ID, permIDs)
	require.NoError(b, err)

	// Assign role to user
	err = module.GetService().AssignRoleToUser(ctx, userID, role.ID, tenantID, userID)
	require.NoError(b, err)

	// Prepare batch requests
	requests := make([]rbac.PermissionCheckRequest, 10)
	for i := 0; i < 10; i++ {
		requests[i] = rbac.PermissionCheckRequest{
			UserID:   userID,
			TenantID: tenantID,
			Resource: permissions[i].Resource,
			Action:   permissions[i].Action,
		}
	}

	// Warm up the cache
	_, _ = module.GetPolicyEngine().CheckPermissions(ctx, requests)

	b.ResetTimer()
	b.ReportAllocs()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		results, err := module.GetPolicyEngine().CheckPermissions(ctx, requests)
		if err != nil {
			b.Fatalf("Batch permission check failed: %v", err)
		}
		if len(results) != 10 {
			b.Fatalf("Expected 10 results, got %d", len(results))
		}
	}
}

// BenchmarkPermissionCheck_AdminBypass benchmarks admin bypass path
func BenchmarkPermissionCheck_AdminBypass(b *testing.B) {
	module, db, cleanup := setupBenchmarkTest(b)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(b, db, "bench-admin-tenant")
	userID := createTestUserInDB(b, db, tenantID, "bench-admin@example.com")

	// Create and assign admin role
	adminRole, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Admin",
		Slug: "admin",
	})
	require.NoError(b, err)

	err = module.GetService().AssignRoleToUser(ctx, userID, adminRole.ID, tenantID, userID)
	require.NoError(b, err)

	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(b, err)
	require.NotEmpty(b, permissions)

	b.ResetTimer()
	b.ReportAllocs()

	// Run benchmark - admin bypass should be fast
	for i := 0; i < b.N; i++ {
		result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
			UserID:   userID,
			TenantID: tenantID,
			Resource: permissions[0].Resource,
			Action:   permissions[0].Action,
		})
		if err != nil {
			b.Fatalf("Permission check failed: %v", err)
		}
		if !result.Allowed {
			b.Fatalf("Expected admin to be allowed")
		}
	}
}

// BenchmarkPermissionCheck_Denied benchmarks denied permission checks
func BenchmarkPermissionCheck_Denied(b *testing.B) {
	module, db, cleanup := setupBenchmarkTest(b)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(b, db, "bench-denied-tenant")
	userID := createTestUserInDB(b, db, tenantID, "bench-denied@example.com")

	// User has no roles or permissions - should be denied
	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(b, err)
	require.NotEmpty(b, permissions)

	// Warm cache with denied result
	_, _ = module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: permissions[0].Resource,
		Action:   permissions[0].Action,
	})

	b.ResetTimer()
	b.ReportAllocs()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
			UserID:   userID,
			TenantID: tenantID,
			Resource: permissions[0].Resource,
			Action:   permissions[0].Action,
		})
		if err != nil {
			b.Fatalf("Permission check failed: %v", err)
		}
		if result.Allowed {
			b.Fatalf("Expected permission to be denied")
		}
	}
}

// BenchmarkPermissionCheck_MultiRole benchmarks checks with multiple roles
func BenchmarkPermissionCheck_MultiRole(b *testing.B) {
	module, db, cleanup := setupBenchmarkTest(b)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(b, db, "bench-multi-tenant")
	userID := createTestUserInDB(b, db, tenantID, "bench-multi@example.com")

	// Create 3 roles with different permissions
	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(b, err)
	require.True(b, len(permissions) >= 3, "Need at least 3 permissions for benchmark")

	for i := 0; i < 3; i++ {
		role, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
			Name: fmt.Sprintf("Multi Role %d", i),
			Slug: fmt.Sprintf("multi-role-%d", i),
		})
		require.NoError(b, err)

		// Assign permission to role
		err = module.GetService().AssignPermissionsToRole(ctx, role.ID, []string{permissions[i].ID})
		require.NoError(b, err)

		// Assign role to user
		err = module.GetService().AssignRoleToUser(ctx, userID, role.ID, tenantID, userID)
		require.NoError(b, err)
	}

	// Warm cache
	_, _ = module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
		UserID:   userID,
		TenantID: tenantID,
		Resource: permissions[1].Resource,
		Action:   permissions[1].Action,
	})

	b.ResetTimer()
	b.ReportAllocs()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
			UserID:   userID,
			TenantID: tenantID,
			Resource: permissions[1].Resource,
			Action:   permissions[1].Action,
		})
		if err != nil {
			b.Fatalf("Permission check failed: %v", err)
		}
		if !result.Allowed {
			b.Fatalf("Expected permission to be allowed")
		}
	}
}

// BenchmarkPermissionCheck_SystemScope benchmarks system-scoped permission checks
func BenchmarkPermissionCheck_SystemScope(b *testing.B) {
	module, db, cleanup := setupBenchmarkTest(b)
	defer cleanup()

	ctx := context.Background()
	tenantID := createTestTenantInDB(b, db, "bench-system-tenant")
	userID := createTestUserInDB(b, db, tenantID, "bench-system@example.com")

	// Create platform admin role
	adminRole, err := module.GetService().CreateRole(ctx, tenantID, rbac.CreateRoleRequest{
		Name: "Platform Admin",
		Slug: "platform-admin",
	})
	require.NoError(b, err)

	err = module.GetService().AssignRoleToUser(ctx, userID, adminRole.ID, tenantID, userID)
	require.NoError(b, err)

	permissions, err := module.GetService().GetAllPermissions(ctx)
	require.NoError(b, err)

	// Find a system-scoped permission
	var systemPerm *rbac.Permission
	for i, p := range permissions {
		if p.Scope == rbac.PermissionScopeSystem {
			systemPerm = &permissions[i]
			break
		}
	}
	require.NotNil(b, systemPerm, "Need at least one system-scoped permission")

	b.ResetTimer()
	b.ReportAllocs()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		result, err := module.GetPolicyEngine().CheckPermission(ctx, rbac.PermissionCheckRequest{
			UserID:   userID,
			TenantID: tenantID,
			Resource: systemPerm.Resource,
			Action:   systemPerm.Action,
		})
		if err != nil {
			b.Fatalf("Permission check failed: %v", err)
		}
		_ = result
	}
}

// BenchmarkCacheOperations benchmarks cache get/set operations
func BenchmarkCacheOperations(b *testing.B) {
	cacheInstance := cache.NewInMemoryCache()
	ctx := context.Background()

	key := "benchmark:key"
	value := []string{"perm1", "perm2", "perm3"}

	b.Run("Set", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			err := cacheInstance.Set(ctx, key, value, 5*time.Minute)
			if err != nil {
				b.Fatalf("Cache set failed: %v", err)
			}
		}
	})

	b.Run("Get", func(b *testing.B) {
		// Setup: Set the value once
		_ = cacheInstance.Set(ctx, key, value, 5*time.Minute)

		var result []string
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := cacheInstance.Get(ctx, key, &result)
			if err != nil {
				b.Fatalf("Cache get failed: %v", err)
			}
		}
	})

	b.Run("DeletePattern", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			// Setup: Create keys
			for j := 0; j < 10; j++ {
				_ = cacheInstance.Set(ctx, fmt.Sprintf("bench:user:%d", j), value, 5*time.Minute)
			}
			b.StartTimer()

			err := cacheInstance.DeletePattern(ctx, "bench:user:*")
			if err != nil {
				b.Fatalf("DeletePattern failed: %v", err)
			}
		}
	})
}

// BenchmarkRepositoryOperations benchmarks database operations
func BenchmarkRepositoryOperations(b *testing.B) {
	db, cleanup := setupTestDatabase(b)
	defer cleanup()

	repo := rbac.NewRepository(db)
	ctx := context.Background()
	tenantID := createTestTenantInDB(b, db, "bench-repo-tenant")
	userID := createTestUserInDB(b, db, tenantID, "bench-repo@example.com")

	// Create a role for benchmarks
	roleID := createTestRoleInDB(b, db, tenantID, "Bench Role", "bench-role")

	b.Run("GetUserRoles", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			roles, err := repo.GetUserRoles(ctx, userID, tenantID)
			if err != nil {
				b.Fatalf("GetUserRoles failed: %v", err)
			}
			_ = roles
		}
	})

	b.Run("GetRolePermissions", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			perms, err := repo.GetRolePermissions(ctx, roleID)
			if err != nil {
				b.Fatalf("GetRolePermissions failed: %v", err)
			}
			_ = perms
		}
	})

	b.Run("IsTenantAdmin", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			isAdmin, err := repo.IsTenantAdmin(ctx, userID, tenantID)
			if err != nil {
				b.Fatalf("IsTenantAdmin failed: %v", err)
			}
			_ = isAdmin
		}
	})
}

// setupBenchmarkTest creates a test environment for benchmarks
func setupBenchmarkTest(b *testing.B) (*rbac.Module, *database.DB, func()) {
	b.Helper()

	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	cacheInstance := cache.NewInMemoryCache()
	log := logger.New("error", "benchmark")

	db, cleanup := setupTestDatabase(b)

	module := rbac.NewModule(db, rbac.ModuleConfig{
		Cache:    cacheInstance,
		CacheTTL: 5 * time.Minute,
	}, log)

	require.NoError(b, rbac.RegisterCoreResources(module.GetRegistry()))

	return module, db, cleanup
}

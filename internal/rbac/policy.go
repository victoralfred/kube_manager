package rbac

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/victoralfred/kube_manager/pkg/cache"
)

// PolicyEngine evaluates RBAC + ABAC permissions with production-ready features
type PolicyEngine interface {
	// Core permission check with full RBAC + ABAC evaluation
	CheckPermission(ctx context.Context, req PermissionCheckRequest) (PermissionCheckResult, error)

	// Batch permission check for efficiency
	CheckPermissions(ctx context.Context, reqs []PermissionCheckRequest) ([]PermissionCheckResult, error)

	// Get user's permission set (for caching and UI)
	GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error)

	// Cache invalidation
	InvalidateUserCache(ctx context.Context, userID, tenantID string) error
	InvalidateRoleCache(ctx context.Context, roleID string) error
	InvalidateTenantCache(ctx context.Context, tenantID string) error

	// Metrics and health
	Stats() PolicyEngineStats
}

// PermissionCheckRequest encapsulates a permission check
type PermissionCheckRequest struct {
	UserID    string
	TenantID  string
	Resource  string
	Action    string
	ObjectID  string                 // Optional - for object-level checks
	Context   map[string]interface{} // Additional context for ABAC evaluation
}

// PermissionCheckResult contains the result of a permission check
type PermissionCheckResult struct {
	Allowed  bool
	Reason   string // "granted", "admin_override", "owner", "denied", "condition_met"
	Message  string
	Metadata map[string]interface{} // Additional info for debugging/audit
}

// PolicyEngineStats provides policy engine metrics
type PolicyEngineStats struct {
	TotalChecks      uint64
	CacheHits        uint64
	CacheMisses      uint64
	AdminOverrides   uint64
	OwnershipChecks  uint64
	ConditionEvals   uint64
	Denials          uint64
	Errors           uint64
	AvgCheckTimeMs   float64
	CacheStats       cache.CacheStats
}

// OwnershipChecker defines interface for checking resource ownership
type OwnershipChecker interface {
	CheckOwnership(ctx context.Context, userID, resource, objectID string) (bool, error)
	GetObjectOwner(ctx context.Context, resource, objectID string) (string, error)
}

type policyEngine struct {
	repo             Repository
	cache            cache.Cache
	registry         *ResourceRegistry
	evaluator        *ConditionEvaluator
	ownershipChecker OwnershipChecker
	cacheTTL         time.Duration
	metrics          *policyMetrics
}

type policyMetrics struct {
	totalChecks     uint64
	cacheHits       uint64
	cacheMisses     uint64
	adminOverrides  uint64
	ownershipChecks uint64
	conditionEvals  uint64
	denials         uint64
	errors          uint64
	totalCheckTime  uint64 // microseconds
}

// PolicyEngineConfig holds configuration for policy engine
type PolicyEngineConfig struct {
	Repository       Repository
	Cache            cache.Cache
	Registry         *ResourceRegistry
	OwnershipChecker OwnershipChecker
	CacheTTL         time.Duration
}

// NewPolicyEngine creates a production-ready policy engine
func NewPolicyEngine(config PolicyEngineConfig) PolicyEngine {
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	return &policyEngine{
		repo:             config.Repository,
		cache:            config.Cache,
		registry:         config.Registry,
		evaluator:        NewConditionEvaluator(),
		ownershipChecker: config.OwnershipChecker,
		cacheTTL:         config.CacheTTL,
		metrics:          &policyMetrics{},
	}
}

// CheckPermission evaluates RBAC + ABAC with 3-tier caching and full condition support
func (p *policyEngine) CheckPermission(ctx context.Context, req PermissionCheckRequest) (PermissionCheckResult, error) {
	start := time.Now()
	defer func() {
		atomic.AddUint64(&p.metrics.totalChecks, 1)
		atomic.AddUint64(&p.metrics.totalCheckTime, uint64(time.Since(start).Microseconds()))
	}()

	// Validate request
	if req.UserID == "" || req.TenantID == "" || req.Resource == "" || req.Action == "" {
		atomic.AddUint64(&p.metrics.errors, 1)
		return PermissionCheckResult{
			Allowed: false,
			Reason:  "denied",
			Message: "Invalid permission check request",
		}, errors.New("invalid request: missing required fields")
	}

	// Step 1: Verify resource exists in registry (Tier 1: In-Memory)
	if !p.registry.Exists(req.Resource) {
		atomic.AddUint64(&p.metrics.denials, 1)
		return PermissionCheckResult{
			Allowed: false,
			Reason:  "denied",
			Message: fmt.Sprintf("Resource '%s' not registered", req.Resource),
		}, ErrInvalidResource
	}

	// Step 2: Get permission template from repository
	permission, err := p.repo.GetPermission(ctx, req.Resource, req.Action)
	if err != nil {
		atomic.AddUint64(&p.metrics.errors, 1)
		return PermissionCheckResult{
			Allowed: false,
			Reason:  "denied",
			Message: fmt.Sprintf("Permission not found: %s:%s", req.Resource, req.Action),
		}, err
	}

	// Step 3: Check scope - system permissions require platform admin
	if permission.Scope == PermissionScopeSystem {
		hasPlatformRole, err := p.repo.UserHasPlatformRole(ctx, req.UserID, "platform_admin")
		if err != nil {
			atomic.AddUint64(&p.metrics.errors, 1)
			return PermissionCheckResult{
				Allowed: false,
				Reason:  "denied",
				Message: "Failed to check platform role",
			}, err
		}

		if hasPlatformRole {
			return PermissionCheckResult{
				Allowed: true,
				Reason:  "granted",
				Message: "Platform admin has system-level permission",
				Metadata: map[string]interface{}{
					"scope":      "system",
					"permission": fmt.Sprintf("%s:%s", req.Resource, req.Action),
				},
			}, nil
		}

		atomic.AddUint64(&p.metrics.denials, 1)
		return PermissionCheckResult{
			Allowed: false,
			Reason:  "denied",
			Message: "System-scoped permission requires platform admin role",
		}, nil
	}

	// Step 4: Tenant admin bypass - implicit permissions for tenant-scoped resources
	isAdmin, err := p.repo.IsTenantAdmin(ctx, req.UserID, req.TenantID)
	if err != nil {
		atomic.AddUint64(&p.metrics.errors, 1)
		return PermissionCheckResult{
			Allowed: false,
			Reason:  "denied",
			Message: "Failed to check tenant admin status",
		}, err
	}

	if isAdmin {
		atomic.AddUint64(&p.metrics.adminOverrides, 1)
		return PermissionCheckResult{
			Allowed: true,
			Reason:  "admin_override",
			Message: "Tenant admin has implicit access to all tenant-scoped permissions",
			Metadata: map[string]interface{}{
				"scope":      "tenant",
				"permission": fmt.Sprintf("%s:%s", req.Resource, req.Action),
			},
		}, nil
	}

	// Step 5: RBAC check via cache (Tier 2: Redis -> Tier 3: PostgreSQL)
	hasPermission, conditions, err := p.hasRBACPermission(ctx, req.UserID, req.TenantID, permission.ID)
	if err != nil {
		atomic.AddUint64(&p.metrics.errors, 1)
		return PermissionCheckResult{
			Allowed: false,
			Reason:  "denied",
			Message: "Failed to check user permissions",
		}, err
	}

	if !hasPermission {
		atomic.AddUint64(&p.metrics.denials, 1)
		return PermissionCheckResult{
			Allowed: false,
			Reason:  "denied",
			Message: fmt.Sprintf("User does not have permission: %s:%s", req.Resource, req.Action),
			Metadata: map[string]interface{}{
				"user_id":    req.UserID,
				"tenant_id":  req.TenantID,
				"permission": fmt.Sprintf("%s:%s", req.Resource, req.Action),
			},
		}, nil
	}

	// Step 6: ABAC ownership check (if required and object specified)
	if permission.RequiresOwnership && req.ObjectID != "" {
		atomic.AddUint64(&p.metrics.ownershipChecks, 1)

		isOwner, err := p.checkOwnership(ctx, req.UserID, req.Resource, req.ObjectID)
		if err != nil {
			atomic.AddUint64(&p.metrics.errors, 1)
			return PermissionCheckResult{
				Allowed: false,
				Reason:  "denied",
				Message: "Failed to verify ownership",
			}, err
		}

		if !isOwner {
			atomic.AddUint64(&p.metrics.denials, 1)
			return PermissionCheckResult{
				Allowed: false,
				Reason:  "denied",
				Message: "User does not own the requested resource",
				Metadata: map[string]interface{}{
					"requires_ownership": true,
					"object_id":          req.ObjectID,
				},
			}, nil
		}

		return PermissionCheckResult{
			Allowed: true,
			Reason:  "owner",
			Message: "Permission granted via ownership",
			Metadata: map[string]interface{}{
				"object_id":  req.ObjectID,
				"permission": fmt.Sprintf("%s:%s", req.Resource, req.Action),
			},
		}, nil
	}

	// Step 7: ABAC condition evaluation (if conditions exist)
	if conditions != nil {
		atomic.AddUint64(&p.metrics.conditionEvals, 1)

		evalCtx := &EvaluationContext{
			UserID:    req.UserID,
			TenantID:  req.TenantID,
			Object:    req.Context,
			Variables: req.Context,
		}

		allowed, err := p.evaluator.Evaluate(ctx, conditions, evalCtx)
		if err != nil {
			atomic.AddUint64(&p.metrics.errors, 1)
			return PermissionCheckResult{
				Allowed: false,
				Reason:  "denied",
				Message: "Failed to evaluate conditions",
			}, err
		}

		if !allowed {
			atomic.AddUint64(&p.metrics.denials, 1)
			return PermissionCheckResult{
				Allowed: false,
				Reason:  "denied",
				Message: "Condition evaluation failed",
				Metadata: map[string]interface{}{
					"has_conditions": true,
				},
			}, nil
		}

		return PermissionCheckResult{
			Allowed: true,
			Reason:  "condition_met",
			Message: "Permission granted after condition evaluation",
			Metadata: map[string]interface{}{
				"has_conditions": true,
				"permission":     fmt.Sprintf("%s:%s", req.Resource, req.Action),
			},
		}, nil
	}

	// Step 8: Grant permission (all checks passed)
	return PermissionCheckResult{
		Allowed: true,
		Reason:  "granted",
		Message: fmt.Sprintf("Permission granted: %s:%s", req.Resource, req.Action),
		Metadata: map[string]interface{}{
			"permission": fmt.Sprintf("%s:%s", req.Resource, req.Action),
		},
	}, nil
}

// CheckPermissions performs batch permission checks
func (p *policyEngine) CheckPermissions(ctx context.Context, reqs []PermissionCheckRequest) ([]PermissionCheckResult, error) {
	results := make([]PermissionCheckResult, len(reqs))

	for i, req := range reqs {
		result, err := p.CheckPermission(ctx, req)
		if err != nil {
			results[i] = PermissionCheckResult{
				Allowed: false,
				Reason:  "denied",
				Message: err.Error(),
			}
		} else {
			results[i] = result
		}
	}

	return results, nil
}

// hasRBACPermission checks if user has permission via their roles
// Returns: (hasPermission, conditions, error)
func (p *policyEngine) hasRBACPermission(ctx context.Context, userID, tenantID, permissionID string) (bool, *Condition, error) {
	// Try cache first (Tier 2: Redis)
	cacheKey := fmt.Sprintf("user:%s:tenant:%s:perms", userID, tenantID)

	var cachedPerms []PermissionWithConditions
	err := p.cache.Get(ctx, cacheKey, &cachedPerms)

	if err == nil {
		// Cache hit
		atomic.AddUint64(&p.metrics.cacheHits, 1)
		for _, pwc := range cachedPerms {
			if pwc.Permission.ID == permissionID {
				return true, pwc.Conditions, nil
			}
		}
		return false, nil, nil
	}

	if !errors.Is(err, cache.ErrCacheMiss) {
		// Cache error (not a miss) - log but continue to database
		// In production, you might want to use a structured logger here
	}

	// Cache miss - query database (Tier 3: PostgreSQL)
	atomic.AddUint64(&p.metrics.cacheMisses, 1)

	permissionsWithConditions, err := p.repo.GetUserPermissionsWithConditions(ctx, userID, tenantID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Cache for configured TTL (gracefully handle cache errors)
	_ = p.cache.Set(ctx, cacheKey, permissionsWithConditions, p.cacheTTL)

	// Check if permission exists and return its conditions
	for _, pwc := range permissionsWithConditions {
		if pwc.Permission.ID == permissionID {
			return true, pwc.Conditions, nil
		}
	}

	return false, nil, nil
}

// checkOwnership validates object-level access (ABAC) using ownership checker
func (p *policyEngine) checkOwnership(ctx context.Context, userID, resource, objectID string) (bool, error) {
	if p.ownershipChecker == nil {
		// Fallback to simple resource-based checks
		return p.fallbackOwnershipCheck(ctx, userID, resource, objectID)
	}

	return p.ownershipChecker.CheckOwnership(ctx, userID, resource, objectID)
}

// fallbackOwnershipCheck provides basic ownership checking without custom checker
func (p *policyEngine) fallbackOwnershipCheck(ctx context.Context, userID, resource, objectID string) (bool, error) {
	switch resource {
	case "user":
		// Users can only access their own user object
		return userID == objectID, nil

	default:
		// For unknown resources, deny by default (fail-safe)
		return false, nil
	}
}

// GetUserPermissions retrieves all permissions for a user (with caching)
func (p *policyEngine) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error) {
	// Try cache first
	cacheKey := fmt.Sprintf("user:%s:tenant:%s:perms", userID, tenantID)

	var cachedPerms []PermissionWithConditions
	err := p.cache.Get(ctx, cacheKey, &cachedPerms)

	if err == nil {
		// Extract just permissions from cached data
		permissions := make([]Permission, len(cachedPerms))
		for i, pwc := range cachedPerms {
			permissions[i] = pwc.Permission
		}
		return permissions, nil
	}

	// Cache miss - query database
	permissionsWithConditions, err := p.repo.GetUserPermissionsWithConditions(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Cache for configured TTL
	_ = p.cache.Set(ctx, cacheKey, permissionsWithConditions, p.cacheTTL)

	// Extract just permissions for return
	permissions := make([]Permission, len(permissionsWithConditions))
	for i, pwc := range permissionsWithConditions {
		permissions[i] = pwc.Permission
	}

	return permissions, nil
}

// InvalidateUserCache invalidates permission cache for a specific user
func (p *policyEngine) InvalidateUserCache(ctx context.Context, userID, tenantID string) error {
	cacheKey := fmt.Sprintf("user:%s:tenant:%s:perms", userID, tenantID)
	return p.cache.Delete(ctx, cacheKey)
}

// InvalidateRoleCache invalidates cache for all users with a specific role
func (p *policyEngine) InvalidateRoleCache(ctx context.Context, roleID string) error {
	// Pattern match: delete all user permission caches
	// In production with large user base, you'd want to:
	// 1. Query users with this role from database
	// 2. Invalidate each user's cache individually
	// Or use Redis pub/sub for distributed cache invalidation

	pattern := "user:*:tenant:*:perms"
	return p.cache.DeletePattern(ctx, pattern)
}

// InvalidateTenantCache invalidates cache for all users in a tenant
func (p *policyEngine) InvalidateTenantCache(ctx context.Context, tenantID string) error {
	pattern := fmt.Sprintf("user:*:tenant:%s:perms", tenantID)
	return p.cache.DeletePattern(ctx, pattern)
}

// Stats returns policy engine statistics
func (p *policyEngine) Stats() PolicyEngineStats {
	totalChecks := p.metrics.totalChecks
	var avgCheckTime float64
	if totalChecks > 0 {
		avgCheckTime = float64(p.metrics.totalCheckTime) / float64(totalChecks) / 1000 // Convert to ms
	}

	return PolicyEngineStats{
		TotalChecks:      totalChecks,
		CacheHits:        p.metrics.cacheHits,
		CacheMisses:      p.metrics.cacheMisses,
		AdminOverrides:   p.metrics.adminOverrides,
		OwnershipChecks:  p.metrics.ownershipChecks,
		ConditionEvals:   p.metrics.conditionEvals,
		Denials:          p.metrics.denials,
		Errors:           p.metrics.errors,
		AvgCheckTimeMs:   avgCheckTime,
		CacheStats:       p.cache.Stats(),
	}
}

// DefaultOwnershipChecker provides a simple database-backed ownership checker
type DefaultOwnershipChecker struct {
	repo Repository
}

// NewDefaultOwnershipChecker creates a default ownership checker
func NewDefaultOwnershipChecker(repo Repository) OwnershipChecker {
	return &DefaultOwnershipChecker{repo: repo}
}

// CheckOwnership checks if a user owns a resource
func (c *DefaultOwnershipChecker) CheckOwnership(ctx context.Context, userID, resource, objectID string) (bool, error) {
	owner, err := c.GetObjectOwner(ctx, resource, objectID)
	if err != nil {
		return false, err
	}

	return owner == userID, nil
}

// GetObjectOwner retrieves the owner of a resource object
func (c *DefaultOwnershipChecker) GetObjectOwner(ctx context.Context, resource, objectID string) (string, error) {
	// Delegate to repository which has knowledge of all resource schemas
	return c.repo.GetResourceOwner(ctx, resource, objectID)
}

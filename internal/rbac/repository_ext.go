package rbac

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"
)

// GetPermission retrieves a permission template by resource and action (template-based)
func (r *repository) GetPermission(ctx context.Context, resource, action string) (*Permission, error) {
	query := `
		SELECT id, resource, action, scope, requires_ownership, description, created_at
		FROM permissions
		WHERE resource = $1 AND action = $2
	`

	var perm Permission
	var scope string
	err := r.db.QueryRowContext(ctx, query, resource, action).Scan(
		&perm.ID,
		&perm.Resource,
		&perm.Action,
		&scope,
		&perm.RequiresOwnership,
		&perm.Description,
		&perm.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrPermissionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	perm.Scope = PermissionScope(scope)
	return &perm, nil
}

// IsTenantAdmin checks if a user is a tenant admin
func (r *repository) IsTenantAdmin(ctx context.Context, userID, tenantID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM user_roles ur
			INNER JOIN roles r ON ur.role_id = r.id
			WHERE ur.user_id = $1
			AND ur.tenant_id = $2
			AND r.slug = 'admin'
			AND r.role_type = 'system'
			AND r.deleted_at IS NULL
		)
	`

	var isAdmin bool
	err := r.db.QueryRowContext(ctx, query, userID, tenantID).Scan(&isAdmin)
	if err != nil {
		return false, fmt.Errorf("failed to check tenant admin status: %w", err)
	}

	return isAdmin, nil
}

// UserHasPlatformRole checks if a user has a specific platform-level role
func (r *repository) UserHasPlatformRole(ctx context.Context, userID, role string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM user_roles ur
			INNER JOIN roles r ON ur.role_id = r.id
			WHERE ur.user_id = $1
			AND r.slug = $2
			AND r.role_type = 'platform'
			AND r.deleted_at IS NULL
		)
	`

	var hasPlatformRole bool
	err := r.db.QueryRowContext(ctx, query, userID, role).Scan(&hasPlatformRole)
	if err != nil {
		return false, fmt.Errorf("failed to check platform role: %w", err)
	}

	return hasPlatformRole, nil
}

// RegisterResource registers a new resource definition
func (r *repository) RegisterResource(ctx context.Context, resource *ResourceDefinition) error {
	query := `
		INSERT INTO resource_registry (id, name, description, scope, tenant_id, actions, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (name, tenant_id) DO UPDATE SET
			description = EXCLUDED.description,
			actions = EXCLUDED.actions
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		resource.ID,
		resource.Name,
		resource.Description,
		resource.Scope,
		resource.TenantID,
		pq.Array(resource.Actions),
		resource.CreatedBy,
		resource.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to register resource: %w", err)
	}

	return nil
}

// GetResource retrieves a resource definition by name
func (r *repository) GetResource(ctx context.Context, name string, tenantID *string) (*ResourceDefinition, error) {
	query := `
		SELECT id, name, description, scope, tenant_id, actions, created_by, created_at
		FROM resource_registry
		WHERE name = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
		ORDER BY tenant_id NULLS LAST
		LIMIT 1
	`

	var resource ResourceDefinition
	var scope string
	var nullableTenantID sql.NullString
	var actions []string

	err := r.db.QueryRowContext(ctx, query, name, tenantID).Scan(
		&resource.ID,
		&resource.Name,
		&resource.Description,
		&scope,
		&nullableTenantID,
		pq.Array(&actions),
		&resource.CreatedBy,
		&resource.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrResourceNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get resource: %w", err)
	}

	resource.Scope = PermissionScope(scope)
	resource.Actions = actions

	if nullableTenantID.Valid {
		resource.TenantID = &nullableTenantID.String
	}

	return &resource, nil
}

// ListResources lists all resources of a specific scope
func (r *repository) ListResources(ctx context.Context, scope PermissionScope) ([]ResourceDefinition, error) {
	query := `
		SELECT id, name, description, scope, tenant_id, actions, created_by, created_at
		FROM resource_registry
		WHERE scope = $1
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to list resources: %w", err)
	}
	defer rows.Close()

	var resources []ResourceDefinition
	for rows.Next() {
		var resource ResourceDefinition
		var scopeStr string
		var nullableTenantID sql.NullString
		var actions []string

		err := rows.Scan(
			&resource.ID,
			&resource.Name,
			&resource.Description,
			&scopeStr,
			&nullableTenantID,
			pq.Array(&actions),
			&resource.CreatedBy,
			&resource.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan resource: %w", err)
		}

		resource.Scope = PermissionScope(scopeStr)
		resource.Actions = actions

		if nullableTenantID.Valid {
			resource.TenantID = &nullableTenantID.String
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// GetUserPermissionsWithConditions retrieves all permissions with ABAC conditions for a user
func (r *repository) GetUserPermissionsWithConditions(ctx context.Context, userID, tenantID string) ([]PermissionWithConditions, error) {
	query := `
		SELECT DISTINCT
			p.id,
			p.resource,
			p.action,
			p.scope,
			p.requires_ownership,
			p.description,
			p.created_at,
			rp.conditions
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN roles r ON rp.role_id = r.id
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
			AND ur.tenant_id = $2
			AND r.deleted_at IS NULL
		ORDER BY p.resource, p.action
	`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions with conditions: %w", err)
	}
	defer rows.Close()

	var results []PermissionWithConditions
	for rows.Next() {
		var pwc PermissionWithConditions
		var scope string
		var conditionsJSON sql.NullString

		err := rows.Scan(
			&pwc.Permission.ID,
			&pwc.Permission.Resource,
			&pwc.Permission.Action,
			&scope,
			&pwc.Permission.RequiresOwnership,
			&pwc.Permission.Description,
			&pwc.Permission.CreatedAt,
			&conditionsJSON,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan permission with conditions: %w", err)
		}

		pwc.Permission.Scope = PermissionScope(scope)

		// Parse JSONB conditions if they exist
		if conditionsJSON.Valid && conditionsJSON.String != "" {
			var cond Condition
			if err := json.Unmarshal([]byte(conditionsJSON.String), &cond); err != nil {
				return nil, fmt.Errorf("failed to unmarshal conditions: %w", err)
			}
			pwc.Conditions = &cond
		}

		results = append(results, pwc)
	}

	return results, nil
}

// GetResourceOwner retrieves the owner/creator of a resource object (production-ready)
func (r *repository) GetResourceOwner(ctx context.Context, resourceType, objectID string) (string, error) {
	// Validate inputs
	if resourceType == "" || objectID == "" {
		return "", fmt.Errorf("resource type and object ID are required")
	}

	// Step 1: Handle special cases with self-ownership
	switch resourceType {
	case "user":
		// Users own themselves (self-ownership model)
		return objectID, nil

	case "role":
		// Roles are tenant-scoped but don't have individual ownership
		// Ownership is implicit via tenant membership
		return "", nil
	}

	// Step 2: Try standard resource table patterns
	// Most resources follow conventions: {resource}s table with created_by or owner_id column
	ownerID, err := r.getOwnerFromStandardTable(ctx, resourceType, objectID)
	if err == nil {
		return ownerID, nil
	}

	// Step 3: Check resource_registry for registered custom resources
	// This supports dynamically registered tenant resources
	resourceDef, regErr := r.GetResource(ctx, resourceType, nil)
	if regErr == nil && resourceDef != nil {
		// Resource is registered - try common ownership patterns
		ownerID, err := r.getOwnerWithFallback(ctx, resourceType, objectID)
		if err != nil {
			return "", fmt.Errorf("failed to get owner for registered resource '%s': %w", resourceType, err)
		}
		return ownerID, nil
	}

	// Step 4: Resource not found in registry and not a standard resource
	return "", fmt.Errorf("ownership check not supported for resource type: %s (not registered)", resourceType)
}

// getOwnerFromStandardTable attempts to get owner from standard table patterns
func (r *repository) getOwnerFromStandardTable(ctx context.Context, resourceType, objectID string) (string, error) {
	// Standard table naming: singular -> plural (e.g., tenant -> tenants)
	tableName := r.pluralizeTableName(resourceType)

	// Try created_by column first (most common pattern)
	ownerID, err := r.queryOwnerField(ctx, tableName, "created_by", objectID)
	if err == nil {
		return ownerID, nil
	}

	// Try owner_id column (alternative pattern)
	ownerID, err = r.queryOwnerField(ctx, tableName, "owner_id", objectID)
	if err == nil {
		return ownerID, nil
	}

	// Try user_id column (for user-related resources)
	ownerID, err = r.queryOwnerField(ctx, tableName, "user_id", objectID)
	if err == nil {
		return ownerID, nil
	}

	return "", fmt.Errorf("no ownership field found for resource type: %s", resourceType)
}

// getOwnerWithFallback tries multiple ownership patterns for registered resources
func (r *repository) getOwnerWithFallback(ctx context.Context, resourceType, objectID string) (string, error) {
	// Try standard patterns
	ownerID, err := r.getOwnerFromStandardTable(ctx, resourceType, objectID)
	if err == nil {
		return ownerID, nil
	}

	// For custom resources, check if there's a metadata table
	// Some resources store ownership in separate metadata tables
	metadataTable := resourceType + "_metadata"
	ownerID, err = r.queryOwnerField(ctx, metadataTable, "owner_id", objectID)
	if err == nil {
		return ownerID, nil
	}

	return "", fmt.Errorf("could not determine ownership for resource: %s", resourceType)
}

// queryOwnerField executes a query to get owner from specific table and column
func (r *repository) queryOwnerField(ctx context.Context, tableName, ownerColumn, objectID string) (string, error) {
	// Use parameterized query with table and column identifiers
	// Note: We cannot parameterize table/column names, but we validate them
	if !r.isValidIdentifier(tableName) || !r.isValidIdentifier(ownerColumn) {
		return "", fmt.Errorf("invalid table or column name")
	}

	// Build query with validated identifiers (safe from SQL injection)
	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE id = $1 AND deleted_at IS NULL LIMIT 1",
		ownerColumn,
		tableName,
	)

	var ownerID sql.NullString
	err := r.db.QueryRowContext(ctx, query, objectID).Scan(&ownerID)

	if err == sql.ErrNoRows {
		// Try without deleted_at check (table might not have soft deletes)
		query = fmt.Sprintf(
			"SELECT %s FROM %s WHERE id = $1 LIMIT 1",
			ownerColumn,
			tableName,
		)
		err = r.db.QueryRowContext(ctx, query, objectID).Scan(&ownerID)
	}

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("resource not found in table %s", tableName)
	}

	if err != nil {
		// Table or column doesn't exist, or other DB error
		return "", err
	}

	if !ownerID.Valid || ownerID.String == "" {
		// Owner field is NULL or empty
		return "", nil
	}

	return ownerID.String, nil
}

// pluralizeTableName converts resource name to typical table name
func (r *repository) pluralizeTableName(resourceType string) string {
	// Simple pluralization rules for common cases
	switch {
	case resourceType == "":
		return ""
	case resourceType[len(resourceType)-1:] == "s":
		// Already plural (e.g., "resources")
		return resourceType
	case resourceType[len(resourceType)-1:] == "y":
		// Convert y to ies (e.g., "policy" -> "policies")
		return resourceType[:len(resourceType)-1] + "ies"
	default:
		// Add 's' (e.g., "tenant" -> "tenants", "role" -> "roles")
		return resourceType + "s"
	}
}

// isValidIdentifier validates SQL identifier to prevent injection
func (r *repository) isValidIdentifier(identifier string) bool {
	// Allow only alphanumeric and underscore characters
	// Must start with letter or underscore
	// Length between 1 and 63 characters (PostgreSQL limit)
	if len(identifier) == 0 || len(identifier) > 63 {
		return false
	}

	for i, c := range identifier {
		if i == 0 {
			// First character must be letter or underscore
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
				return false
			}
		} else {
			// Subsequent characters can be alphanumeric or underscore
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
	}

	return true
}

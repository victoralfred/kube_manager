package rbac

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/victoralfred/kube_manager/pkg/database"
)

// Repository defines the RBAC repository interface
type Repository interface {
	// Permission operations (template-based)
	GetPermission(ctx context.Context, resource, action string) (*Permission, error)
	GetAllPermissions(ctx context.Context) ([]Permission, error)
	GetPermissionByID(ctx context.Context, permissionID string) (*Permission, error)
	GetPermissionsByResource(ctx context.Context, resource string) ([]Permission, error)
	GetRolePermissions(ctx context.Context, roleID string) ([]Permission, error)

	// Role operations
	CreateRole(ctx context.Context, role *Role) error
	GetRoleByID(ctx context.Context, roleID string) (*Role, error)
	GetRoleBySlug(ctx context.Context, tenantID, slug string) (*Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, roleID string) error
	ListRoles(ctx context.Context, filter ListRolesFilter) ([]*Role, int, error)
	RoleExists(ctx context.Context, tenantID, slug string) (bool, error)

	// Role-Permission operations
	AssignPermissionsToRole(ctx context.Context, roleID string, permissionIDs []string) error
	RemovePermissionsFromRole(ctx context.Context, roleID string, permissionIDs []string) error
	RemoveAllPermissionsFromRole(ctx context.Context, roleID string) error

	// User-Role operations
	AssignRoleToUser(ctx context.Context, userRole *UserRole) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID string) error
	GetUserRoles(ctx context.Context, userID, tenantID string) ([]Role, error)
	GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error)
	GetUserPermissionsWithConditions(ctx context.Context, userID, tenantID string) ([]PermissionWithConditions, error)
	UserHasRole(ctx context.Context, userID, roleID string) (bool, error)

	// Resource registry operations
	RegisterResource(ctx context.Context, resource *ResourceDefinition) error
	GetResource(ctx context.Context, name string, tenantID *string) (*ResourceDefinition, error)
	ListResources(ctx context.Context, scope PermissionScope) ([]ResourceDefinition, error)

	// Helper queries for policy engine
	IsTenantAdmin(ctx context.Context, userID, tenantID string) (bool, error)
	UserHasPlatformRole(ctx context.Context, userID, role string) (bool, error)
	GetResourceOwner(ctx context.Context, resourceType, objectID string) (string, error)
}

type repository struct {
	db *database.DB
}

// NewRepository creates a new RBAC repository
func NewRepository(db *database.DB) Repository {
	return &repository{db: db}
}

// CreateRole creates a new role
func (r *repository) CreateRole(ctx context.Context, role *Role) error {
	query := `
		INSERT INTO roles (id, tenant_id, name, slug, description, role_type, is_system, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		role.ID,
		role.TenantID,
		role.Name,
		role.Slug,
		role.Description,
		role.RoleType,
		role.IsSystem,
		role.CreatedAt,
		role.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	return nil
}

// GetRoleByID retrieves a role by ID
func (r *repository) GetRoleByID(ctx context.Context, roleID string) (*Role, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, role_type, is_system, created_at, updated_at, deleted_at
		FROM roles
		WHERE id = $1 AND deleted_at IS NULL
	`

	var role Role
	var deletedAt sql.NullTime
	var tenantID sql.NullString

	err := r.db.QueryRowContext(ctx, query, roleID).Scan(
		&role.ID,
		&tenantID,
		&role.Name,
		&role.Slug,
		&role.Description,
		&role.RoleType,
		&role.IsSystem,
		&role.CreatedAt,
		&role.UpdatedAt,
		&deletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrRoleNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if tenantID.Valid {
		role.TenantID = &tenantID.String
	}

	if deletedAt.Valid {
		role.DeletedAt = &deletedAt.Time
	}

	return &role, nil
}

// GetRoleBySlug retrieves a role by slug and tenant
func (r *repository) GetRoleBySlug(ctx context.Context, tenantID, slug string) (*Role, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, is_system, created_at, updated_at, deleted_at
		FROM roles
		WHERE tenant_id = $1 AND slug = $2 AND deleted_at IS NULL
	`

	var role Role
	var deletedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, tenantID, slug).Scan(
		&role.ID,
		&role.TenantID,
		&role.Name,
		&role.Slug,
		&role.Description,
		&role.IsSystem,
		&role.CreatedAt,
		&role.UpdatedAt,
		&deletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrRoleNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get role by slug: %w", err)
	}

	if deletedAt.Valid {
		role.DeletedAt = &deletedAt.Time
	}

	return &role, nil
}

// UpdateRole updates a role
func (r *repository) UpdateRole(ctx context.Context, role *Role) error {
	query := `
		UPDATE roles
		SET name = $1, description = $2, updated_at = $3
		WHERE id = $4 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, role.Name, role.Description, role.UpdatedAt, role.ID)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrRoleNotFound
	}

	return nil
}

// DeleteRole soft deletes a role
func (r *repository) DeleteRole(ctx context.Context, roleID string) error {
	query := `
		UPDATE roles
		SET deleted_at = NOW()
		WHERE id = $1 AND is_system = FALSE AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrSystemRoleProtected
	}

	return nil
}

// ListRoles lists roles with filtering
func (r *repository) ListRoles(ctx context.Context, filter ListRolesFilter) ([]*Role, int, error) {
	baseQuery := `
		FROM roles
		WHERE tenant_id = $1 AND deleted_at IS NULL
	`
	args := []interface{}{filter.TenantID}
	argIndex := 2

	if !filter.IncludeSystem {
		baseQuery += " AND is_system = FALSE"
	}

	if filter.Search != "" {
		baseQuery += fmt.Sprintf(" AND (name LIKE $%d OR description LIKE $%d)", argIndex, argIndex)
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	// Count total
	countQuery := "SELECT COUNT(*) " + baseQuery
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count roles: %w", err)
	}

	// Get roles
	listQuery := `
		SELECT id, tenant_id, name, slug, description, is_system, created_at, updated_at
	` + baseQuery + `
		ORDER BY created_at DESC
	`

	// Only add LIMIT/OFFSET if Limit is specified
	if filter.Limit > 0 {
		listQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
		args = append(args, filter.Limit, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list roles: %w", err)
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		var role Role
		err := rows.Scan(
			&role.ID,
			&role.TenantID,
			&role.Name,
			&role.Slug,
			&role.Description,
			&role.IsSystem,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, &role)
	}

	return roles, total, nil
}

// RoleExists checks if a role exists by slug
func (r *repository) RoleExists(ctx context.Context, tenantID, slug string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM roles WHERE tenant_id = $1 AND slug = $2 AND deleted_at IS NULL)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID, slug).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check role existence: %w", err)
	}

	return exists, nil
}

// GetAllPermissions retrieves all permissions
func (r *repository) GetAllPermissions(ctx context.Context) ([]Permission, error) {
	query := `
		SELECT id, resource, action, description, created_at
		FROM permissions
		ORDER BY resource, action
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}
	defer rows.Close()

	var permissions []Permission
	for rows.Next() {
		var perm Permission
		err := rows.Scan(&perm.ID, &perm.Resource, &perm.Action, &perm.Description, &perm.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// GetPermissionByID retrieves a permission by ID
func (r *repository) GetPermissionByID(ctx context.Context, permissionID string) (*Permission, error) {
	query := `
		SELECT id, resource, action, description, created_at
		FROM permissions
		WHERE id = $1
	`

	var perm Permission
	err := r.db.QueryRowContext(ctx, query, permissionID).Scan(
		&perm.ID,
		&perm.Resource,
		&perm.Action,
		&perm.Description,
		&perm.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrPermissionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	return &perm, nil
}

// GetPermissionsByResource retrieves permissions for a resource
func (r *repository) GetPermissionsByResource(ctx context.Context, resource string) ([]Permission, error) {
	query := `
		SELECT id, resource, action, description, created_at
		FROM permissions
		WHERE resource = $1
		ORDER BY action
	`

	rows, err := r.db.QueryContext(ctx, query, resource)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions by resource: %w", err)
	}
	defer rows.Close()

	var permissions []Permission
	for rows.Next() {
		var perm Permission
		err := rows.Scan(&perm.ID, &perm.Resource, &perm.Action, &perm.Description, &perm.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// GetRolePermissions retrieves all permissions for a role
func (r *repository) GetRolePermissions(ctx context.Context, roleID string) ([]Permission, error) {
	query := `
		SELECT p.id, p.resource, p.action, p.description, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.resource, p.action
	`

	rows, err := r.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	defer rows.Close()

	var permissions []Permission
	for rows.Next() {
		var perm Permission
		err := rows.Scan(&perm.ID, &perm.Resource, &perm.Action, &perm.Description, &perm.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// AssignPermissionsToRole assigns permissions to a role
func (r *repository) AssignPermissionsToRole(ctx context.Context, roleID string, permissionIDs []string) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT $1, unnest($2::uuid[])
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`

	_, err := r.db.ExecContext(ctx, query, roleID, pq.Array(permissionIDs))
	if err != nil {
		return fmt.Errorf("failed to assign permissions to role: %w", err)
	}

	return nil
}

// RemovePermissionsFromRole removes specific permissions from a role
func (r *repository) RemovePermissionsFromRole(ctx context.Context, roleID string, permissionIDs []string) error {
	query := `
		DELETE FROM role_permissions
		WHERE role_id = $1 AND permission_id = ANY($2)
	`

	_, err := r.db.ExecContext(ctx, query, roleID, pq.Array(permissionIDs))
	if err != nil {
		return fmt.Errorf("failed to remove permissions from role: %w", err)
	}

	return nil
}

// RemoveAllPermissionsFromRole removes all permissions from a role
func (r *repository) RemoveAllPermissionsFromRole(ctx context.Context, roleID string) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1`

	_, err := r.db.ExecContext(ctx, query, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove all permissions from role: %w", err)
	}

	return nil
}

// AssignRoleToUser assigns a role to a user
func (r *repository) AssignRoleToUser(ctx context.Context, userRole *UserRole) error {
	query := `
		INSERT INTO user_roles (id, user_id, role_id, tenant_id, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, role_id, tenant_id) DO NOTHING
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		userRole.ID,
		userRole.UserID,
		userRole.RoleID,
		userRole.TenantID,
		userRole.CreatedAt,
		userRole.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}

	return nil
}

// RemoveRoleFromUser removes a role from a user
func (r *repository) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`

	result, err := r.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role from user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrUserRoleNotFound
	}

	return nil
}

// GetUserRoles retrieves all roles for a user
func (r *repository) GetUserRoles(ctx context.Context, userID, tenantID string) ([]Role, error) {
	query := `
		SELECT r.id, r.tenant_id, r.name, r.slug, r.description, r.is_system, r.created_at, r.updated_at
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND r.deleted_at IS NULL
		ORDER BY r.created_at
	`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var role Role
		err := rows.Scan(
			&role.ID,
			&role.TenantID,
			&role.Name,
			&role.Slug,
			&role.Description,
			&role.IsSystem,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	return roles, nil
}

// GetUserPermissions retrieves all permissions for a user (aggregated from all their roles)
func (r *repository) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error) {
	query := `
		SELECT DISTINCT p.id, p.resource, p.action, p.description, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN roles r ON rp.role_id = r.id
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND r.deleted_at IS NULL
		ORDER BY p.resource, p.action
	`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	defer rows.Close()

	var permissions []Permission
	for rows.Next() {
		var perm Permission
		err := rows.Scan(&perm.ID, &perm.Resource, &perm.Action, &perm.Description, &perm.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// UserHasRole checks if a user has a specific role
func (r *repository) UserHasRole(ctx context.Context, userID, roleID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID, roleID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user role: %w", err)
	}

	return exists, nil
}

package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// TenantStats represents tenant statistics
type TenantStats struct {
	TenantID     string `json:"tenant_id"`
	UserCount    int    `json:"user_count"`
	StorageUsed  int64  `json:"storage_used"`
	ResourceUsed int    `json:"resource_used"`
}

// List retrieves a list of tenants with filters
func (r *repository) List(ctx context.Context, filter ListTenantsFilter) ([]*Tenant, int, error) {
	// Build WHERE clause
	whereClauses := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argCount := 1

	if filter.Status != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("status = $%d", argCount))
		args = append(args, *filter.Status)
		argCount++
	}

	if filter.Search != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("(name ILIKE $%d OR slug ILIKE $%d)", argCount, argCount))
		args = append(args, "%"+filter.Search+"%")
		argCount++
	}

	whereClause := strings.Join(whereClauses, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM tenants WHERE %s", whereClause)
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count tenants: %w", err)
	}

	// Build ORDER BY clause
	orderBy := "created_at"
	if filter.SortBy != "" {
		orderBy = filter.SortBy
	}
	orderDir := "ASC"
	if filter.SortDesc {
		orderDir = "DESC"
	}

	// Set defaults for pagination
	if filter.Limit <= 0 {
		filter.Limit = 10
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}

	// Build query
	query := fmt.Sprintf(`
		SELECT id, name, slug, status, settings, max_users, max_storage,
			   contact_name, contact_email, created_at, updated_at, deleted_at
		FROM tenants
		WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, orderDir, argCount, argCount+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer rows.Close()

	tenants := make([]*Tenant, 0)
	for rows.Next() {
		var tenant Tenant
		var settingsJSON []byte

		err := rows.Scan(
			&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Status,
			&settingsJSON, &tenant.MaxUsers, &tenant.MaxStorage,
			&tenant.ContactName, &tenant.ContactEmail,
			&tenant.CreatedAt, &tenant.UpdatedAt, &tenant.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan tenant: %w", err)
		}

		if len(settingsJSON) > 0 {
			if err := json.Unmarshal(settingsJSON, &tenant.Settings); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal settings: %w", err)
			}
		}

		tenants = append(tenants, &tenant)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}

	return tenants, total, nil
}

// Exists checks if a tenant exists by slug
func (r *repository) Exists(ctx context.Context, slug string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1 AND deleted_at IS NULL)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, slug).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check tenant existence: %w", err)
	}

	return exists, nil
}

// GetStats retrieves tenant statistics
func (r *repository) GetStats(ctx context.Context, tenantID string) (*TenantStats, error) {
	query := `
		SELECT
			t.id as tenant_id,
			COUNT(DISTINCT u.id) as user_count,
			COALESCE(SUM(r.storage_used), 0) as storage_used,
			COUNT(DISTINCT r.id) as resource_used
		FROM tenants t
		LEFT JOIN users u ON t.id = u.tenant_id AND u.deleted_at IS NULL
		LEFT JOIN resources r ON t.id = r.tenant_id AND r.deleted_at IS NULL
		WHERE t.id = $1 AND t.deleted_at IS NULL
		GROUP BY t.id
	`

	var stats TenantStats
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(
		&stats.TenantID,
		&stats.UserCount,
		&stats.StorageUsed,
		&stats.ResourceUsed,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get tenant stats: %w", err)
	}

	return &stats, nil
}

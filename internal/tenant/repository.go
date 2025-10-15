package tenant

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/victoralfred/kube_manager/pkg/database"
)

// Repository defines the interface for tenant data access
type Repository interface {
	Create(ctx context.Context, tenant *Tenant) error
	GetByID(ctx context.Context, id string) (*Tenant, error)
	GetBySlug(ctx context.Context, slug string) (*Tenant, error)
	Update(ctx context.Context, tenant *Tenant) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter ListTenantsFilter) ([]*Tenant, int, error)
	Exists(ctx context.Context, slug string) (bool, error)
	GetStats(ctx context.Context, tenantID string) (*TenantStats, error)
}

// repository implements Repository interface
type repository struct {
	db *database.DB
}

// NewRepository creates a new tenant repository
func NewRepository(db *database.DB) Repository {
	return &repository{db: db}
}

// Create creates a new tenant
func (r *repository) Create(ctx context.Context, tenant *Tenant) error {
	tenant.ID = uuid.New().String()
	tenant.CreatedAt = time.Now()
	tenant.UpdatedAt = time.Now()

	settingsJSON, err := json.Marshal(tenant.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	query := `
		INSERT INTO tenants (
			id, name, slug, status, settings, max_users, max_storage,
			contact_name, contact_email, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err = r.db.ExecContext(
		ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, tenant.Status, settingsJSON,
		tenant.MaxUsers, tenant.MaxStorage, tenant.ContactName,
		tenant.ContactEmail, tenant.CreatedAt, tenant.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// GetByID retrieves a tenant by ID
func (r *repository) GetByID(ctx context.Context, id string) (*Tenant, error) {
	query := `
		SELECT id, name, slug, status, settings, max_users, max_storage,
			   contact_name, contact_email, created_at, updated_at, deleted_at
		FROM tenants
		WHERE id = $1 AND deleted_at IS NULL
	`

	var tenant Tenant
	var settingsJSON []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Status,
		&settingsJSON, &tenant.MaxUsers, &tenant.MaxStorage,
		&tenant.ContactName, &tenant.ContactEmail,
		&tenant.CreatedAt, &tenant.UpdatedAt, &tenant.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrTenantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	if len(settingsJSON) > 0 {
		if err := json.Unmarshal(settingsJSON, &tenant.Settings); err != nil {
			return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
		}
	}

	return &tenant, nil
}

// GetBySlug retrieves a tenant by slug
func (r *repository) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	query := `
		SELECT id, name, slug, status, settings, max_users, max_storage,
			   contact_name, contact_email, created_at, updated_at, deleted_at
		FROM tenants
		WHERE slug = $1 AND deleted_at IS NULL
	`

	var tenant Tenant
	var settingsJSON []byte

	err := r.db.QueryRowContext(ctx, query, slug).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Status,
		&settingsJSON, &tenant.MaxUsers, &tenant.MaxStorage,
		&tenant.ContactName, &tenant.ContactEmail,
		&tenant.CreatedAt, &tenant.UpdatedAt, &tenant.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrTenantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant by slug: %w", err)
	}

	if len(settingsJSON) > 0 {
		if err := json.Unmarshal(settingsJSON, &tenant.Settings); err != nil {
			return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
		}
	}

	return &tenant, nil
}

// Update updates a tenant
func (r *repository) Update(ctx context.Context, tenant *Tenant) error {
	tenant.UpdatedAt = time.Now()

	settingsJSON, err := json.Marshal(tenant.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	query := `
		UPDATE tenants
		SET name = $1, status = $2, settings = $3, max_users = $4,
			max_storage = $5, contact_name = $6, contact_email = $7, updated_at = $8
		WHERE id = $9 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(
		ctx, query,
		tenant.Name, tenant.Status, settingsJSON, tenant.MaxUsers,
		tenant.MaxStorage, tenant.ContactName, tenant.ContactEmail,
		tenant.UpdatedAt, tenant.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrTenantNotFound
	}

	return nil
}

// Delete soft deletes a tenant
func (r *repository) Delete(ctx context.Context, id string) error {
	query := `
		UPDATE tenants
		SET deleted_at = $1, status = $2, updated_at = $3
		WHERE id = $4 AND deleted_at IS NULL
	`

	now := time.Now()
	result, err := r.db.ExecContext(ctx, query, now, TenantStatusDeleted, now, id)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrTenantNotFound
	}

	return nil
}

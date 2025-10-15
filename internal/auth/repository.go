package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/victoralfred/kube_manager/pkg/database"
)

// Repository defines the auth repository interface
type Repository interface {
	// Refresh token operations
	StoreRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	DeleteExpiredTokens(ctx context.Context) error

	// User credential operations (simplified for now)
	GetUserByEmail(ctx context.Context, tenantID, email string) (*UserCredentials, error)
	CreateUser(ctx context.Context, user *UserCredentials) error
}

// UserCredentials represents user authentication data
type UserCredentials struct {
	ID             string
	TenantID       string
	Email          string
	PasswordHash   string
	Name           string
	Status         string
	Roles          []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastLoginAt    *time.Time
}

type repository struct {
	db *database.DB
}

// NewRepository creates a new auth repository
func NewRepository(db *database.DB) Repository {
	return &repository{db: db}
}

// StoreRefreshToken stores a refresh token in the database
func (r *repository) StoreRefreshToken(ctx context.Context, token *RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, token, user_id, tenant_id, expires_at, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		token.ID,
		token.Token,
		token.UserID,
		token.TenantID,
		token.ExpiresAt,
		token.IPAddress,
		token.UserAgent,
		token.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves a refresh token by its value
func (r *repository) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	query := `
		SELECT id, token, user_id, tenant_id, expires_at, created_at, revoked_at, ip_address, user_agent
		FROM refresh_tokens
		WHERE token = $1
	`

	var rt RefreshToken
	var revokedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&rt.ID,
		&rt.Token,
		&rt.UserID,
		&rt.TenantID,
		&rt.ExpiresAt,
		&rt.CreatedAt,
		&revokedAt,
		&rt.IPAddress,
		&rt.UserAgent,
	)

	if err == sql.ErrNoRows {
		return nil, ErrTokenNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if revokedAt.Valid {
		rt.RevokedAt = &revokedAt.Time
	}

	return &rt, nil
}

// RevokeRefreshToken revokes a specific refresh token
func (r *repository) RevokeRefreshToken(ctx context.Context, token string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = $1
		WHERE token = $2 AND revoked_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, time.Now(), token)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrTokenNotFound
	}

	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (r *repository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = $1
		WHERE user_id = $2 AND revoked_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to revoke user tokens: %w", err)
	}

	return nil
}

// DeleteExpiredTokens deletes expired refresh tokens
func (r *repository) DeleteExpiredTokens(ctx context.Context) error {
	query := `
		DELETE FROM refresh_tokens
		WHERE expires_at < $1 OR revoked_at IS NOT NULL AND revoked_at < $2
	`

	// Delete tokens expired more than 7 days ago or revoked more than 30 days ago
	expiryThreshold := time.Now().Add(-7 * 24 * time.Hour)
	revokedThreshold := time.Now().Add(-30 * 24 * time.Hour)

	_, err := r.db.ExecContext(ctx, query, expiryThreshold, revokedThreshold)
	if err != nil {
		return fmt.Errorf("failed to delete expired tokens: %w", err)
	}

	return nil
}

// GetUserByEmail retrieves a user by email and tenant
func (r *repository) GetUserByEmail(ctx context.Context, tenantID, email string) (*UserCredentials, error) {
	query := `
		SELECT u.id, u.tenant_id, u.email, u.password_hash, u.name, u.status,
		       u.created_at, u.updated_at, u.last_login_at,
		       COALESCE(array_agg(r.slug) FILTER (WHERE r.slug IS NOT NULL), '{}') as roles
		FROM users u
		LEFT JOIN user_roles ur ON u.id = ur.user_id
		LEFT JOIN roles r ON ur.role_id = r.id
		WHERE u.tenant_id = $1 AND u.email = $2 AND u.deleted_at IS NULL
		GROUP BY u.id
	`

	var user UserCredentials
	var lastLoginAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, tenantID, email).Scan(
		&user.ID,
		&user.TenantID,
		&user.Email,
		&user.PasswordHash,
		&user.Name,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLoginAt,
		&user.Roles,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}

	return &user, nil
}

// CreateUser creates a new user (simplified implementation)
func (r *repository) CreateUser(ctx context.Context, user *UserCredentials) error {
	query := `
		INSERT INTO users (id, tenant_id, email, password_hash, name, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		user.ID,
		user.TenantID,
		user.Email,
		user.PasswordHash,
		user.Name,
		user.Status,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

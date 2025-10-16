package invitation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"github.com/victoralfred/kube_manager/pkg/database"
)

var (
	ErrInvitationNotFound      = errors.New("invitation not found")
	ErrInvitationAlreadyExists = errors.New("invitation already exists for this email")
	ErrInvalidInvitationID     = errors.New("invalid invitation ID")
)

// Repository defines the interface for invitation persistence
type Repository interface {
	Create(ctx context.Context, invitation *Invitation) error
	GetByID(ctx context.Context, id string) (*Invitation, error)
	GetByToken(ctx context.Context, token string) (*Invitation, error)
	Update(ctx context.Context, invitation *Invitation) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter ListInvitationsFilter) ([]*Invitation, int, error)
	ExistsPendingForEmail(ctx context.Context, tenantID, email string) (bool, error)
	MarkAsAccepted(ctx context.Context, token string) error
	MarkAsRevoked(ctx context.Context, id string) error
	DeleteExpiredInvitations(ctx context.Context) error
}

type repository struct {
	db *database.DB
}

// NewRepository creates a new invitation repository
func NewRepository(db *database.DB) Repository {
	return &repository{db: db}
}

// Create creates a new invitation
func (r *repository) Create(ctx context.Context, invitation *Invitation) error {
	query := `
		INSERT INTO invitations (
			id, tenant_id, email, first_name, last_name, token, role_ids,
			invited_by, status, message, expires_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := r.db.ExecContext(ctx, query,
		invitation.ID,
		invitation.TenantID,
		invitation.Email,
		invitation.FirstName,
		invitation.LastName,
		invitation.Token,
		pq.Array(invitation.RoleIDs),
		invitation.InvitedBy,
		invitation.Status,
		invitation.Message,
		invitation.ExpiresAt,
		invitation.CreatedAt,
		invitation.UpdatedAt,
	)

	if err != nil {
		if strings.Contains(err.Error(), "uq_invitation_email_tenant") {
			return ErrInvitationAlreadyExists
		}
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	return nil
}

// GetByID retrieves an invitation by ID
func (r *repository) GetByID(ctx context.Context, id string) (*Invitation, error) {
	query := `
		SELECT id, tenant_id, email, first_name, last_name, token, role_ids,
		       invited_by, status, message, expires_at, accepted_at, created_at, updated_at
		FROM invitations
		WHERE id = $1
	`

	var inv Invitation
	var acceptedAt sql.NullTime
	var roleIDs pq.StringArray

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&inv.ID,
		&inv.TenantID,
		&inv.Email,
		&inv.FirstName,
		&inv.LastName,
		&inv.Token,
		&roleIDs,
		&inv.InvitedBy,
		&inv.Status,
		&inv.Message,
		&inv.ExpiresAt,
		&acceptedAt,
		&inv.CreatedAt,
		&inv.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvitationNotFound
		}
		return nil, fmt.Errorf("failed to get invitation: %w", err)
	}

	inv.RoleIDs = roleIDs
	if acceptedAt.Valid {
		inv.AcceptedAt = &acceptedAt.Time
	}

	return &inv, nil
}

// GetByToken retrieves an invitation by token
func (r *repository) GetByToken(ctx context.Context, token string) (*Invitation, error) {
	query := `
		SELECT id, tenant_id, email, first_name, last_name, token, role_ids,
		       invited_by, status, message, expires_at, accepted_at, created_at, updated_at
		FROM invitations
		WHERE token = $1
	`

	var inv Invitation
	var acceptedAt sql.NullTime
	var roleIDs pq.StringArray

	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&inv.ID,
		&inv.TenantID,
		&inv.Email,
		&inv.FirstName,
		&inv.LastName,
		&inv.Token,
		&roleIDs,
		&inv.InvitedBy,
		&inv.Status,
		&inv.Message,
		&inv.ExpiresAt,
		&acceptedAt,
		&inv.CreatedAt,
		&inv.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvitationNotFound
		}
		return nil, fmt.Errorf("failed to get invitation by token: %w", err)
	}

	inv.RoleIDs = roleIDs
	if acceptedAt.Valid {
		inv.AcceptedAt = &acceptedAt.Time
	}

	return &inv, nil
}

// Update updates an invitation
func (r *repository) Update(ctx context.Context, invitation *Invitation) error {
	query := `
		UPDATE invitations
		SET status = $1, accepted_at = $2, updated_at = $3
		WHERE id = $4
	`

	result, err := r.db.ExecContext(ctx, query,
		invitation.Status,
		invitation.AcceptedAt,
		invitation.UpdatedAt,
		invitation.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update invitation: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrInvitationNotFound
	}

	return nil
}

// Delete deletes an invitation
func (r *repository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM invitations WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete invitation: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrInvitationNotFound
	}

	return nil
}

// List retrieves invitations with filters
func (r *repository) List(ctx context.Context, filter ListInvitationsFilter) ([]*Invitation, int, error) {
	// Build query with filters
	where := []string{"1=1"}
	args := []interface{}{}
	argCount := 1

	if filter.TenantID != "" {
		where = append(where, fmt.Sprintf("tenant_id = $%d", argCount))
		args = append(args, filter.TenantID)
		argCount++
	}

	if filter.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", argCount))
		args = append(args, filter.Status)
		argCount++
	}

	if filter.Email != "" {
		where = append(where, fmt.Sprintf("email ILIKE $%d", argCount))
		args = append(args, "%"+filter.Email+"%")
		argCount++
	}

	whereClause := strings.Join(where, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM invitations WHERE %s", whereClause)
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count invitations: %w", err)
	}

	// Pagination
	if filter.PageSize == 0 {
		filter.PageSize = 20
	}
	if filter.Page < 1 {
		filter.Page = 1
	}
	offset := (filter.Page - 1) * filter.PageSize

	// Fetch invitations
	query := fmt.Sprintf(`
		SELECT id, tenant_id, email, first_name, last_name, token, role_ids,
		       invited_by, status, message, expires_at, accepted_at, created_at, updated_at
		FROM invitations
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount, argCount+1)

	args = append(args, filter.PageSize, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list invitations: %w", err)
	}
	defer rows.Close()

	invitations := make([]*Invitation, 0)
	for rows.Next() {
		var inv Invitation
		var acceptedAt sql.NullTime
		var roleIDs pq.StringArray

		err := rows.Scan(
			&inv.ID,
			&inv.TenantID,
			&inv.Email,
			&inv.FirstName,
			&inv.LastName,
			&inv.Token,
			&roleIDs,
			&inv.InvitedBy,
			&inv.Status,
			&inv.Message,
			&inv.ExpiresAt,
			&acceptedAt,
			&inv.CreatedAt,
			&inv.UpdatedAt,
		)

		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan invitation: %w", err)
		}

		inv.RoleIDs = roleIDs
		if acceptedAt.Valid {
			inv.AcceptedAt = &acceptedAt.Time
		}

		invitations = append(invitations, &inv)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating invitations: %w", err)
	}

	return invitations, total, nil
}

// ExistsPendingForEmail checks if a pending invitation exists for an email in a tenant
func (r *repository) ExistsPendingForEmail(ctx context.Context, tenantID, email string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM invitations
			WHERE tenant_id = $1 AND email = $2 AND status = 'pending'
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check pending invitation: %w", err)
	}

	return exists, nil
}

// MarkAsAccepted marks an invitation as accepted
func (r *repository) MarkAsAccepted(ctx context.Context, token string) error {
	query := `
		UPDATE invitations
		SET status = 'accepted', accepted_at = NOW(), updated_at = NOW()
		WHERE token = $1 AND status = 'pending'
	`

	result, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to mark invitation as accepted: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrInvitationNotFound
	}

	return nil
}

// MarkAsRevoked marks an invitation as revoked
func (r *repository) MarkAsRevoked(ctx context.Context, id string) error {
	query := `
		UPDATE invitations
		SET status = 'revoked', updated_at = NOW()
		WHERE id = $1 AND status = 'pending'
	`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to mark invitation as revoked: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrInvitationNotFound
	}

	return nil
}

// DeleteExpiredInvitations deletes expired invitations
func (r *repository) DeleteExpiredInvitations(ctx context.Context) error {
	query := `
		UPDATE invitations
		SET status = 'expired', updated_at = NOW()
		WHERE expires_at < NOW() AND status = 'pending'
	`

	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to delete expired invitations: %w", err)
	}

	return nil
}

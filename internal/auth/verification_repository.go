package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/victoralfred/kube_manager/pkg/database"
)

// VerificationRepository defines the interface for email verification persistence
type VerificationRepository interface {
	CreateVerificationToken(ctx context.Context, token *EmailVerificationToken) error
	GetVerificationToken(ctx context.Context, token string) (*EmailVerificationToken, error)
	GetVerificationTokenByUserID(ctx context.Context, userID string) (*EmailVerificationToken, error)
	MarkAsVerified(ctx context.Context, token string) error
	DeleteExpiredTokens(ctx context.Context) error
	DeleteUserTokens(ctx context.Context, userID string) error
}

type verificationRepository struct {
	db *database.DB
}

// NewVerificationRepository creates a new verification repository
func NewVerificationRepository(db *database.DB) VerificationRepository {
	return &verificationRepository{db: db}
}

// CreateVerificationToken creates a new verification token
func (r *verificationRepository) CreateVerificationToken(ctx context.Context, token *EmailVerificationToken) error {
	query := `
		INSERT INTO email_verification_tokens (id, user_id, token, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.ExecContext(ctx, query,
		token.ID,
		token.UserID,
		token.Token,
		token.ExpiresAt,
		token.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}

	return nil
}

// GetVerificationToken retrieves a verification token by token string
func (r *verificationRepository) GetVerificationToken(ctx context.Context, token string) (*EmailVerificationToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, verified_at, created_at
		FROM email_verification_tokens
		WHERE token = $1
	`

	var vToken EmailVerificationToken
	var verifiedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&vToken.ID,
		&vToken.UserID,
		&vToken.Token,
		&vToken.ExpiresAt,
		&verifiedAt,
		&vToken.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to get verification token: %w", err)
	}

	if verifiedAt.Valid {
		vToken.VerifiedAt = &verifiedAt.Time
	}

	return &vToken, nil
}

// GetVerificationTokenByUserID retrieves the latest verification token for a user
func (r *verificationRepository) GetVerificationTokenByUserID(ctx context.Context, userID string) (*EmailVerificationToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, verified_at, created_at
		FROM email_verification_tokens
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`

	var vToken EmailVerificationToken
	var verifiedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&vToken.ID,
		&vToken.UserID,
		&vToken.Token,
		&vToken.ExpiresAt,
		&verifiedAt,
		&vToken.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to get verification token: %w", err)
	}

	if verifiedAt.Valid {
		vToken.VerifiedAt = &verifiedAt.Time
	}

	return &vToken, nil
}

// MarkAsVerified marks a verification token as verified
func (r *verificationRepository) MarkAsVerified(ctx context.Context, token string) error {
	query := `
		UPDATE email_verification_tokens
		SET verified_at = NOW()
		WHERE token = $1 AND verified_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to mark token as verified: %w", err)
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

// DeleteExpiredTokens deletes all expired verification tokens
func (r *verificationRepository) DeleteExpiredTokens(ctx context.Context) error {
	query := `
		DELETE FROM email_verification_tokens
		WHERE expires_at < NOW()
	`

	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to delete expired tokens: %w", err)
	}

	return nil
}

// DeleteUserTokens deletes all verification tokens for a user
func (r *verificationRepository) DeleteUserTokens(ctx context.Context, userID string) error {
	query := `
		DELETE FROM email_verification_tokens
		WHERE user_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user tokens: %w", err)
	}

	return nil
}

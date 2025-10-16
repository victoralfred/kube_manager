package auth

import (
	"time"
)

// EmailVerificationToken represents an email verification token
type EmailVerificationToken struct {
	ID         string
	UserID     string
	Token      string
	ExpiresAt  time.Time
	VerifiedAt *time.Time
	CreatedAt  time.Time
}

// IsExpired checks if the verification token is expired
func (e *EmailVerificationToken) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsVerified checks if the email has been verified
func (e *EmailVerificationToken) IsVerified() bool {
	return e.VerifiedAt != nil
}

// IsValid checks if the token is valid (not expired and not verified)
func (e *EmailVerificationToken) IsValid() bool {
	return !e.IsExpired() && !e.IsVerified()
}

// VerifyEmailRequest represents the request to verify an email
type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

// ResendVerificationRequest represents the request to resend verification email
type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
}

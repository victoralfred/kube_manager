package invitation

import (
	"time"
)

// InvitationStatus represents the status of an invitation
type InvitationStatus string

const (
	StatusPending  InvitationStatus = "pending"
	StatusAccepted InvitationStatus = "accepted"
	StatusExpired  InvitationStatus = "expired"
	StatusRevoked  InvitationStatus = "revoked"
)

// Invitation represents a user invitation
type Invitation struct {
	ID         string
	TenantID   string
	Email      string
	FirstName  string
	LastName   string
	Token      string
	RoleIDs    []string
	InvitedBy  string
	Status     InvitationStatus
	Message    string
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// IsExpired checks if the invitation is expired
func (i *Invitation) IsExpired() bool {
	return time.Now().After(i.ExpiresAt)
}

// IsAccepted checks if the invitation has been accepted
func (i *Invitation) IsAccepted() bool {
	return i.Status == StatusAccepted && i.AcceptedAt != nil
}

// IsRevoked checks if the invitation has been revoked
func (i *Invitation) IsRevoked() bool {
	return i.Status == StatusRevoked
}

// IsValid checks if the invitation is valid (pending and not expired)
func (i *Invitation) IsValid() bool {
	return i.Status == StatusPending && !i.IsExpired()
}

// InviteUserRequest represents the request to invite a user
type InviteUserRequest struct {
	Email     string   `json:"email" binding:"required,email"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	RoleIDs   []string `json:"role_ids" binding:"required,min=1"`
	Message   string   `json:"message"`
}

// AcceptInvitationRequest represents the request to accept an invitation
type AcceptInvitationRequest struct {
	Token     string `json:"token" binding:"required"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// InvitationResponse represents an invitation response
type InvitationResponse struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	TenantName       string    `json:"tenant_name"`
	Email            string    `json:"email"`
	FirstName        string    `json:"first_name"`
	LastName         string    `json:"last_name"`
	RoleNames        []string  `json:"role_names"`
	InvitedByName    string    `json:"invited_by_name"`
	Status           string    `json:"status"`
	Message          string    `json:"message"`
	ExpiresAt        time.Time `json:"expires_at"`
	CreatedAt        time.Time `json:"created_at"`
}

// ListInvitationsFilter represents filters for listing invitations
type ListInvitationsFilter struct {
	TenantID string
	Status   InvitationStatus
	Email    string
	Page     int
	PageSize int
}

package tenant

import (
	"time"
)

// Tenant represents a tenant in the system
type Tenant struct {
	ID          string                 `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Slug        string                 `json:"slug" db:"slug"`
	Status      TenantStatus           `json:"status" db:"status"`
	Settings    map[string]interface{} `json:"settings" db:"settings"`
	MaxUsers    int                    `json:"max_users" db:"max_users"`
	MaxStorage  int64                  `json:"max_storage" db:"max_storage"`
	ContactName string                 `json:"contact_name" db:"contact_name"`
	ContactEmail string                `json:"contact_email" db:"contact_email"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt   *time.Time             `json:"deleted_at,omitempty" db:"deleted_at"`
}

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusInactive  TenantStatus = "inactive"
	TenantStatusDeleted   TenantStatus = "deleted"
)

// CreateTenantRequest represents request to create a tenant
type CreateTenantRequest struct {
	Name         string                 `json:"name" binding:"required,min=3,max=100"`
	Slug         string                 `json:"slug" binding:"required,min=3,max=50,alphanum"`
	ContactName  string                 `json:"contact_name" binding:"required"`
	ContactEmail string                 `json:"contact_email" binding:"required,email"`
	MaxUsers     int                    `json:"max_users" binding:"required,min=1"`
	MaxStorage   int64                  `json:"max_storage" binding:"required,min=1"`
	Settings     map[string]interface{} `json:"settings"`
}

// UpdateTenantRequest represents request to update a tenant
type UpdateTenantRequest struct {
	Name         *string                 `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Status       *TenantStatus           `json:"status,omitempty"`
	ContactName  *string                 `json:"contact_name,omitempty"`
	ContactEmail *string                 `json:"contact_email,omitempty" binding:"omitempty,email"`
	MaxUsers     *int                    `json:"max_users,omitempty" binding:"omitempty,min=1"`
	MaxStorage   *int64                  `json:"max_storage,omitempty" binding:"omitempty,min=1"`
	Settings     map[string]interface{}  `json:"settings,omitempty"`
}

// ListTenantsFilter represents filters for listing tenants
type ListTenantsFilter struct {
	Status   *TenantStatus
	Search   string
	Limit    int
	Offset   int
	SortBy   string
	SortDesc bool
}

// Validate validates the create tenant request
func (r *CreateTenantRequest) Validate() error {
	if r.Name == "" {
		return ErrInvalidTenantName
	}
	if r.Slug == "" {
		return ErrInvalidTenantSlug
	}
	if r.ContactEmail == "" {
		return ErrInvalidContactEmail
	}
	return nil
}

// ToTenant converts CreateTenantRequest to Tenant
func (r *CreateTenantRequest) ToTenant() *Tenant {
	now := time.Now()
	return &Tenant{
		Name:         r.Name,
		Slug:         r.Slug,
		Status:       TenantStatusActive,
		Settings:     r.Settings,
		MaxUsers:     r.MaxUsers,
		MaxStorage:   r.MaxStorage,
		ContactName:  r.ContactName,
		ContactEmail: r.ContactEmail,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// IsActive checks if tenant is active
func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive && t.DeletedAt == nil
}

// IsSuspended checks if tenant is suspended
func (t *Tenant) IsSuspended() bool {
	return t.Status == TenantStatusSuspended
}

// CanCreateUser checks if tenant can create more users
func (t *Tenant) CanCreateUser(currentUserCount int) bool {
	return currentUserCount < t.MaxUsers
}

// CanAllocateStorage checks if tenant can allocate more storage
func (t *Tenant) CanAllocateStorage(currentStorage, requested int64) bool {
	return currentStorage+requested <= t.MaxStorage
}

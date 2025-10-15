package rbac

import (
	"time"
)

// Role represents a role in the system
type Role struct {
	ID          string
	TenantID    string
	Name        string
	Slug        string
	Description string
	Permissions []Permission
	IsSystem    bool // System roles cannot be deleted
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

// Permission represents a specific permission
type Permission struct {
	ID          string
	Resource    string // e.g., "tenant", "user", "role", "resource"
	Action      string // e.g., "create", "read", "update", "delete", "list"
	Description string
	CreatedAt   time.Time
}

// UserRole represents the assignment of a role to a user
type UserRole struct {
	ID        string
	UserID    string
	RoleID    string
	TenantID  string
	CreatedAt time.Time
	CreatedBy string
}

// PolicyRule represents a policy rule for access control
type PolicyRule struct {
	Subject   string // user ID or role ID
	Resource  string // resource type
	Action    string // action to perform
	TenantID  string // tenant scope
	Condition string // optional condition (future use)
}

// CreateRoleRequest represents a request to create a role
type CreateRoleRequest struct {
	Name         string   `json:"name" binding:"required,min=3,max=100"`
	Slug         string   `json:"slug" binding:"required,min=3,max=50,alphanum"`
	Description  string   `json:"description" binding:"max=500"`
	PermissionIDs []string `json:"permission_ids"`
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	Name         *string  `json:"name" binding:"omitempty,min=3,max=100"`
	Description  *string  `json:"description" binding:"omitempty,max=500"`
	PermissionIDs []string `json:"permission_ids"`
}

// AssignRoleRequest represents a request to assign a role to a user
type AssignRoleRequest struct {
	UserID string `json:"user_id" binding:"required,uuid"`
	RoleID string `json:"role_id" binding:"required,uuid"`
}

// CheckPermissionRequest represents a permission check request
type CheckPermissionRequest struct {
	UserID   string `json:"user_id" binding:"required,uuid"`
	Resource string `json:"resource" binding:"required"`
	Action   string `json:"action" binding:"required"`
}

// ListRolesFilter represents filtering options for listing roles
type ListRolesFilter struct {
	TenantID      string
	Search        string
	IncludeSystem bool
	Offset        int
	Limit         int
}

// RoleWithPermissions represents a role with its permissions loaded
type RoleWithPermissions struct {
	Role        *Role
	Permissions []Permission
}

// PermissionSet is a helper type for checking permissions
type PermissionSet map[string]bool

// NewPermissionSet creates a new permission set from a list of permissions
func NewPermissionSet(permissions []Permission) PermissionSet {
	set := make(PermissionSet)
	for _, p := range permissions {
		key := p.Resource + ":" + p.Action
		set[key] = true
	}
	return set
}

// Has checks if the permission set has a specific permission
func (ps PermissionSet) Has(resource, action string) bool {
	key := resource + ":" + action
	return ps[key]
}

// HasAny checks if the permission set has any of the specified permissions
func (ps PermissionSet) HasAny(permissions ...string) bool {
	for _, perm := range permissions {
		if ps[perm] {
			return true
		}
	}
	return false
}

// String returns a formatted key for a permission
func PermissionKey(resource, action string) string {
	return resource + ":" + action
}

// Common system roles
const (
	SystemRoleAdmin    = "admin"
	SystemRoleUser     = "user"
	SystemRoleViewer   = "viewer"
	SystemRoleModerator = "moderator"
)

// Common resources
const (
	ResourceTenant   = "tenant"
	ResourceUser     = "user"
	ResourceRole     = "role"
	ResourceResource = "resource"
	ResourceAuditLog = "audit_log"
)

// Common actions
const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
	ActionList   = "list"
	ActionManage = "manage" // Full access
)

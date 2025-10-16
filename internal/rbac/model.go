package rbac

import (
	"fmt"
	"time"
)

// PermissionScope defines the scope of a permission
type PermissionScope string

const (
	PermissionScopeSystem PermissionScope = "system" // Platform-wide (tenant:create, tenant:delete)
	PermissionScopeTenant PermissionScope = "tenant" // Tenant-specific (invoice:create, project:read)
)

// RoleType defines the type classification of a role
type RoleType string

const (
	RoleTypePlatform RoleType = "platform" // Platform-level role (cross-tenant, created by platform admin)
	RoleTypeSystem   RoleType = "system"   // Auto-created tenant role (admin, user, viewer - cannot be deleted)
	RoleTypeCustom   RoleType = "custom"   // Tenant-created custom role (can be deleted)
)

// Permission represents a permission template (no tenant duplication)
type Permission struct {
	ID                string
	Resource          string
	Action            string
	Scope             PermissionScope
	RequiresOwnership bool   // ABAC: whether this permission requires object ownership check
	Description       string
	CreatedAt         time.Time
}

// PermissionWithConditions represents a permission with ABAC conditions (for caching)
type PermissionWithConditions struct {
	Permission Permission
	Conditions *Condition // ABAC conditions from role_permissions
}

// Role represents a role in the system with type classification
type Role struct {
	ID          string
	TenantID    *string  // NULL for platform roles
	Name        string
	Slug        string
	Description string
	RoleType    RoleType // platform, system, or custom
	Permissions []Permission
	IsSystem    bool // System roles cannot be deleted
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
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

// RegisterResourceRequest represents a request to register a custom resource
type RegisterResourceRequest struct {
	Name        string   `json:"name" binding:"required,min=3,max=50"`
	Description string   `json:"description" binding:"max=500"`
	Actions     []string `json:"actions" binding:"required,min=1"`
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

// ResourceDefinition defines a resource that can be registered dynamically
type ResourceDefinition struct {
	ID          string
	Name        string          // e.g., "invoice", "project", "document"
	Description string          // Human-readable description
	Scope       PermissionScope // System or Tenant scoped
	TenantID    *string         // NULL for system resources, specific for tenant custom resources
	Actions     []string        // Supported actions for this resource
	CreatedBy   string          // "system" or "tenant_admin"
	CreatedAt   time.Time
}

// Condition represents ABAC condition (stored as JSONB)
type Condition struct {
	Operator string `json:"operator"` // "AND", "OR"
	Rules    []Rule `json:"rules"`
}

// Rule represents a single ABAC rule
type Rule struct {
	Field    string      `json:"field"`    // "owner_id", "status", "created_by"
	Operator string      `json:"operator"` // "equals", "in", "contains", "not_equals"
	Value    interface{} `json:"value"`    // "${user.id}", ["draft", "pending"], etc.
}

// StandardActions returns the standard CRUD+List actions
func StandardActions() []string {
	return []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}
}

// ReadOnlyActions returns read-only actions
func ReadOnlyActions() []string {
	return []string{ActionRead, ActionList}
}

// AuditLog represents an audit log entry (stored in binary files)
type AuditLog struct {
	ID           string                 `msgpack:"id"`
	TenantID     *string                `msgpack:"tenant_id"`
	EventType    string                 `msgpack:"event_type"`
	ActorID      string                 `msgpack:"actor_id"`
	ActorEmail   string                 `msgpack:"actor_email"`
	TargetType   string                 `msgpack:"target_type"`
	TargetID     string                 `msgpack:"target_id"`
	Action       string                 `msgpack:"action"`
	BeforeState  map[string]interface{} `msgpack:"before_state"`
	AfterState   map[string]interface{} `msgpack:"after_state"`
	IPAddress    string                 `msgpack:"ip_address"`
	UserAgent    string                 `msgpack:"user_agent"`
	RequestID    string                 `msgpack:"request_id"`
	Result       string                 `msgpack:"result"` // "success", "failure", "denied"
	ErrorMessage string                 `msgpack:"error_message"`
	Metadata     map[string]interface{} `msgpack:"metadata"`
	CreatedAt    time.Time              `msgpack:"created_at"`
}

// Common errors
var (
	ErrInvalidResourceName = fmt.Errorf("invalid resource name")
	ErrReservedName        = fmt.Errorf("name is reserved")
	ErrResourceNotFound    = fmt.Errorf("resource not found")
)

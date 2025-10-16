package audit

import (
	"time"
)

// AuditLog represents an audit log entry
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

// IndexEntry represents an index entry for fast lookups
type IndexEntry struct {
	ID        string
	TenantID  *string
	EventType string
	ActorID   string
	TargetID  string
	CreatedAt time.Time
	Offset    int64 // Byte offset in the data file
	Length    int32 // Length of the entry in bytes
}

// QueryFilter represents filtering criteria for audit log queries
type QueryFilter struct {
	TenantID   *string
	ActorID    string
	TargetType string
	TargetID   string
	EventType  string
	Action     string
	Result     string
	StartTime  time.Time
	EndTime    time.Time
	Limit      int
	Offset     int
}

// Common event types
const (
	EventTypeRoleCreated      = "role.created"
	EventTypeRoleUpdated      = "role.updated"
	EventTypeRoleDeleted      = "role.deleted"
	EventTypeRoleAssigned     = "role.assigned"
	EventTypeRoleUnassigned   = "role.unassigned"
	EventTypePermissionGranted = "permission.granted"
	EventTypePermissionRevoked = "permission.revoked"
	EventTypePermissionDenied  = "permission.denied"
	EventTypeUserCreated       = "user.created"
	EventTypeUserUpdated       = "user.updated"
	EventTypeUserDeleted       = "user.deleted"
	EventTypeUserLogin         = "user.login"
	EventTypeUserLogout        = "user.logout"
	EventTypeTenantCreated     = "tenant.created"
	EventTypeTenantUpdated     = "tenant.updated"
	EventTypeTenantSuspended   = "tenant.suspended"
	EventTypeTenantActivated   = "tenant.activated"
)

// Result types
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultDenied  = "denied"
)

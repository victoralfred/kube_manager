package rbac

import "errors"

var (
	// Role errors
	ErrRoleNotFound        = errors.New("role not found")
	ErrRoleAlreadyExists   = errors.New("role already exists")
	ErrInvalidRoleSlug     = errors.New("invalid role slug")
	ErrSystemRoleProtected = errors.New("system role cannot be modified or deleted")
	ErrRoleInUse           = errors.New("role is in use and cannot be deleted")

	// Permission errors
	ErrPermissionNotFound   = errors.New("permission not found")
	ErrPermissionDenied     = errors.New("permission denied")
	ErrInvalidPermission    = errors.New("invalid permission")
	ErrInvalidResource      = errors.New("invalid resource")
	ErrInvalidAction        = errors.New("invalid action")

	// User role errors
	ErrUserRoleNotFound     = errors.New("user role assignment not found")
	ErrUserAlreadyHasRole   = errors.New("user already has this role")
	ErrCannotRemoveLastRole = errors.New("cannot remove user's last role")
	ErrInvalidUserID        = errors.New("invalid user ID")

	// Policy errors
	ErrPolicyViolation = errors.New("policy violation")
	ErrInvalidPolicy   = errors.New("invalid policy")

	// General errors
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

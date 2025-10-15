package tenant

import "errors"

var (
	// ErrTenantNotFound is returned when tenant is not found
	ErrTenantNotFound = errors.New("tenant not found")

	// ErrTenantAlreadyExists is returned when tenant already exists
	ErrTenantAlreadyExists = errors.New("tenant already exists")

	// ErrInvalidTenantID is returned when tenant ID is invalid
	ErrInvalidTenantID = errors.New("invalid tenant ID")

	// ErrInvalidTenantName is returned when tenant name is invalid
	ErrInvalidTenantName = errors.New("invalid tenant name")

	// ErrInvalidTenantSlug is returned when tenant slug is invalid
	ErrInvalidTenantSlug = errors.New("invalid tenant slug")

	// ErrInvalidContactEmail is returned when contact email is invalid
	ErrInvalidContactEmail = errors.New("invalid contact email")

	// ErrTenantSuspended is returned when tenant is suspended
	ErrTenantSuspended = errors.New("tenant is suspended")

	// ErrTenantInactive is returned when tenant is inactive
	ErrTenantInactive = errors.New("tenant is inactive")

	// ErrUserLimitExceeded is returned when user limit is exceeded
	ErrUserLimitExceeded = errors.New("user limit exceeded")

	// ErrStorageLimitExceeded is returned when storage limit is exceeded
	ErrStorageLimitExceeded = errors.New("storage limit exceeded")
)

package rbac

import (
	"regexp"
	"strings"
	"sync"
)

// ResourceRegistry manages dynamic resource registration with validation
type ResourceRegistry struct {
	mu        sync.RWMutex
	resources map[string]ResourceDefinition
	reserved  []string
}

// NewResourceRegistry creates a new resource registry with reserved names
func NewResourceRegistry() *ResourceRegistry {
	return &ResourceRegistry{
		resources: make(map[string]ResourceDefinition),
		reserved: []string{
			"tenant",
			"user",
			"role",
			"permission",
			"audit_log",
		},
	}
}

// Register adds a resource to the registry with validation
func (r *ResourceRegistry) Register(def ResourceDefinition) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate name
	if err := r.validateName(def.Name); err != nil {
		return err
	}

	// Validate actions
	if len(def.Actions) == 0 {
		return ErrInvalidResource
	}

	r.resources[def.Name] = def
	return nil
}

// RegisterReserved registers a system resource bypassing reserved name checks
// This should only be used during system initialization for core resources
func (r *ResourceRegistry) RegisterReserved(def ResourceDefinition) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Basic validation only (skip reserved name check)
	if len(def.Name) < 3 || len(def.Name) > 50 {
		return ErrInvalidResourceName
	}

	matched, _ := regexp.MatchString(`^[a-z][a-z0-9_]{2,49}$`, def.Name)
	if !matched {
		return ErrInvalidResourceName
	}

	if len(def.Actions) == 0 {
		return ErrInvalidResource
	}

	r.resources[def.Name] = def
	return nil
}

// Get retrieves a resource definition
func (r *ResourceRegistry) Get(name string) (ResourceDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	def, exists := r.resources[name]
	return def, exists
}

// GetAll returns all registered resources
func (r *ResourceRegistry) GetAll() []ResourceDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	defs := make([]ResourceDefinition, 0, len(r.resources))
	for _, def := range r.resources {
		defs = append(defs, def)
	}
	return defs
}

// Exists checks if a resource is registered
func (r *ResourceRegistry) Exists(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.resources[name]
	return exists
}

// IsReserved checks if a name is reserved
func (r *ResourceRegistry) IsReserved(name string) bool {
	for _, reserved := range r.reserved {
		if name == reserved {
			return true
		}
	}

	// Check reserved prefixes
	if strings.HasPrefix(name, "system_") || strings.HasPrefix(name, "platform_") {
		return true
	}

	return false
}

// validateName checks resource naming rules
func (r *ResourceRegistry) validateName(name string) error {
	// Check length
	if len(name) < 3 || len(name) > 50 {
		return ErrInvalidResourceName
	}

	// Check pattern: ^[a-z][a-z0-9_]{2,49}$
	// Must start with lowercase letter, only lowercase letters, numbers, underscores
	matched, _ := regexp.MatchString(`^[a-z][a-z0-9_]{2,49}$`, name)
	if !matched {
		return ErrInvalidResourceName
	}

	// Check reserved names
	if r.IsReserved(name) {
		return ErrReservedName
	}

	// Check for near-matches to reserved names (prevent confusion)
	for _, reserved := range r.reserved {
		if levenshteinDistance(name, reserved) <= 2 {
			return ErrReservedName
		}
	}

	return nil
}

// levenshteinDistance calculates the edit distance between two strings
// Used to detect names too similar to reserved ones
func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Create matrix
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	// Fill matrix
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}

			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// GeneratePermissions generates permission templates for a resource
func (r *ResourceRegistry) GeneratePermissions(resourceName string) []Permission {
	def, exists := r.resources[resourceName]
	if !exists {
		return nil
	}

	permissions := make([]Permission, 0, len(def.Actions))
	for _, action := range def.Actions {
		permissions = append(permissions, Permission{
			Resource:          def.Name,
			Action:            action,
			Scope:             def.Scope,
			RequiresOwnership: false, // Default, can be overridden
			Description:       def.Description + " - " + action,
		})
	}
	return permissions
}

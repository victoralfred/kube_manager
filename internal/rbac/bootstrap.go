package rbac

// RegisterCoreResources registers system resources at application startup
func RegisterCoreResources(registry *ResourceRegistry) error {
	coreResources := []ResourceDefinition{
		{
			Name:        "tenant",
			Description: "Tenant management",
			Scope:       PermissionScopeSystem,
			Actions:     []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList, "suspend"},
			CreatedBy:   "system",
		},
		{
			Name:        "user",
			Description: "User management",
			Scope:       PermissionScopeTenant,
			Actions:     []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList},
			CreatedBy:   "system",
		},
		{
			Name:        "role",
			Description: "Role management",
			Scope:       PermissionScopeTenant,
			Actions:     []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList, "assign"},
			CreatedBy:   "system",
		},
		{
			Name:        "resource",
			Description: "Resource management",
			Scope:       PermissionScopeTenant,
			Actions:     []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList},
			CreatedBy:   "system",
		},
	}

	for _, resource := range coreResources {
		if err := registry.RegisterReserved(resource); err != nil {
			return err
		}
	}

	return nil
}

// GetCoreResourceNames returns the list of core resource names
func GetCoreResourceNames() []string {
	return []string{"tenant", "user", "role", "resource"}
}

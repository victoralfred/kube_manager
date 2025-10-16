package middleware

import (
	"context"
)

// RBACPermissionChecker is an interface that matches the RBAC PolicyEngine
type RBACPermissionChecker interface {
	CheckPermission(ctx context.Context, req RBACPermissionCheckRequest) (RBACPermissionCheckResult, error)
}

// RBACPermissionCheckRequest matches the RBAC package's PermissionCheckRequest
type RBACPermissionCheckRequest struct {
	UserID   string
	TenantID string
	Resource string
	Action   string
	ObjectID string
	Context  map[string]interface{}
}

// RBACPermissionCheckResult matches the RBAC package's PermissionCheckResult
type RBACPermissionCheckResult struct {
	Allowed bool
	Reason  string
}

// PolicyEngineAdapter adapts the RBAC PolicyEngine to work with the middleware
type PolicyEngineAdapter struct {
	engine RBACPermissionChecker
}

// NewPolicyEngineAdapter creates a new adapter
func NewPolicyEngineAdapter(engine RBACPermissionChecker) *PolicyEngineAdapter {
	return &PolicyEngineAdapter{engine: engine}
}

// CheckPermission implements the PermissionChecker interface
func (a *PolicyEngineAdapter) CheckPermission(ctx context.Context, req PermissionCheckRequest) (PermissionCheckResult, error) {
	// Convert middleware request to RBAC request
	rbacReq := RBACPermissionCheckRequest{
		UserID:   req.UserID,
		TenantID: req.TenantID,
		Resource: req.Resource,
		Action:   req.Action,
		ObjectID: req.ObjectID,
	}

	// Call the RBAC policy engine
	rbacResult, err := a.engine.CheckPermission(ctx, rbacReq)
	if err != nil {
		return PermissionCheckResult{}, err
	}

	// Convert RBAC result to middleware result
	return PermissionCheckResult{
		Allowed: rbacResult.Allowed,
		Reason:  rbacResult.Reason,
	}, nil
}

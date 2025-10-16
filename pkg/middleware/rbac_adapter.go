package middleware

import (
	"context"

	"github.com/victoralfred/kube_manager/internal/rbac"
)

// PolicyEngineAdapter adapts the RBAC PolicyEngine to work with the middleware
type PolicyEngineAdapter struct {
	engine rbac.PolicyEngine
}

// NewPolicyEngineAdapter creates a new adapter
func NewPolicyEngineAdapter(engine rbac.PolicyEngine) *PolicyEngineAdapter {
	return &PolicyEngineAdapter{engine: engine}
}

// CheckPermission implements the PermissionChecker interface
func (a *PolicyEngineAdapter) CheckPermission(ctx context.Context, req PermissionCheckRequest) (PermissionCheckResult, error) {
	// Convert middleware request to RBAC request
	rbacReq := rbac.PermissionCheckRequest{
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

package rbac

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/pkg/errors"
)

// AssignRoleToUser handles assigning a role to a user
func (h *Handler) AssignRoleToUser(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("User ID is required"))
		return
	}

	var req AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest(err.Error()))
		return
	}

	actorID := c.GetString("user_id")
	if actorID == "" {
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Authentication required"))
		return
	}

	if err := h.service.AssignRoleToUser(c.Request.Context(), userID, req.RoleID, tenantID, actorID); err != nil {
		handleRBACError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role assigned to user successfully"})
}

// RemoveRoleFromUser handles removing a role from a user
func (h *Handler) RemoveRoleFromUser(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("User ID is required"))
		return
	}

	roleID := c.Param("role_id")
	if roleID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Role ID is required"))
		return
	}

	if err := h.service.RemoveRoleFromUser(c.Request.Context(), userID, roleID, tenantID); err != nil {
		handleRBACError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// GetUserRoles handles retrieving all roles assigned to a user
func (h *Handler) GetUserRoles(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("User ID is required"))
		return
	}

	roles, err := h.service.GetUserRoles(c.Request.Context(), userID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to get user roles", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"roles": roles,
		"count": len(roles),
	})
}

// GetUserPermissions handles retrieving effective permissions for a user
func (h *Handler) GetUserPermissions(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("User ID is required"))
		return
	}

	permissions, err := h.service.GetUserPermissions(c.Request.Context(), userID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to get user permissions", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"permissions": permissions,
		"count":       len(permissions),
	})
}

// RegisterResource handles registering a custom resource
func (h *Handler) RegisterResource(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	var req RegisterResourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest(err.Error()))
		return
	}

	resource, err := h.service.RegisterResource(c.Request.Context(), tenantID, req)
	if err != nil {
		handleRBACError(c, err)
		return
	}

	c.JSON(http.StatusCreated, resource)
}

// ListResources handles listing registered resources
func (h *Handler) ListResources(c *gin.Context) {
	scope := PermissionScope(c.Query("scope"))
	if scope == "" {
		scope = PermissionScopeTenant
	}

	if scope != PermissionScopeSystem && scope != PermissionScopeTenant {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid scope. Must be 'system' or 'tenant'"))
		return
	}

	resources, err := h.service.ListResources(c.Request.Context(), scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to list resources", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"resources": resources,
		"count":     len(resources),
	})
}

// CheckPermission handles permission checking requests
func (h *Handler) CheckPermission(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	var req CheckPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest(err.Error()))
		return
	}

	objectID := c.Query("object_id")

	result, err := h.service.CheckPermission(c.Request.Context(), req.UserID, tenantID, req.Resource, req.Action, objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errors.Internal("Permission check failed", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"allowed": result.Allowed,
		"reason":  result.Reason,
	})
}

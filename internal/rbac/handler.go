package rbac

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/pkg/errors"
)

// Handler handles HTTP requests for RBAC operations
type Handler struct {
	service Service
}

// NewHandler creates a new RBAC handler
func NewHandler(service Service) *Handler {
	return &Handler{
		service: service,
	}
}

// CreateRole handles role creation
func (h *Handler) CreateRole(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest(err.Error()))
		return
	}

	role, err := h.service.CreateRole(c.Request.Context(), tenantID, req)
	if err != nil {
		handleRBACError(c, err)
		return
	}

	c.JSON(http.StatusCreated, role)
}

// UpdateRole handles role updates
func (h *Handler) UpdateRole(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	roleID := c.Param("id")
	if roleID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Role ID is required"))
		return
	}

	var req UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest(err.Error()))
		return
	}

	role, err := h.service.UpdateRole(c.Request.Context(), tenantID, roleID, req)
	if err != nil {
		handleRBACError(c, err)
		return
	}

	c.JSON(http.StatusOK, role)
}

// DeleteRole handles role deletion
func (h *Handler) DeleteRole(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	roleID := c.Param("id")
	if roleID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Role ID is required"))
		return
	}

	if err := h.service.DeleteRole(c.Request.Context(), tenantID, roleID); err != nil {
		handleRBACError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// GetRole handles retrieving a role by ID
func (h *Handler) GetRole(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	roleID := c.Param("id")
	if roleID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Role ID is required"))
		return
	}

	role, err := h.service.GetRole(c.Request.Context(), tenantID, roleID)
	if err != nil {
		handleRBACError(c, err)
		return
	}

	c.JSON(http.StatusOK, role)
}

// ListRoles handles listing roles for a tenant
func (h *Handler) ListRoles(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Tenant ID is required"))
		return
	}

	includeSystem := c.Query("include_system") == "true"

	roles, err := h.service.ListRoles(c.Request.Context(), tenantID, includeSystem)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to list roles", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"roles": roles,
		"count": len(roles),
	})
}

// GetAllPermissions handles listing all available permissions
func (h *Handler) GetAllPermissions(c *gin.Context) {
	permissions, err := h.service.GetAllPermissions(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to get permissions", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"permissions": permissions,
		"count":       len(permissions),
	})
}

// GetRolePermissions handles retrieving permissions for a specific role
func (h *Handler) GetRolePermissions(c *gin.Context) {
	roleID := c.Param("id")
	if roleID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Role ID is required"))
		return
	}

	permissions, err := h.service.GetRolePermissions(c.Request.Context(), roleID)
	if err != nil {
		handleRBACError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"permissions": permissions,
		"count":       len(permissions),
	})
}

// AssignPermissionsToRole handles assigning permissions to a role
func (h *Handler) AssignPermissionsToRole(c *gin.Context) {
	roleID := c.Param("id")
	if roleID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Role ID is required"))
		return
	}

	var req struct {
		PermissionIDs []string `json:"permission_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest(err.Error()))
		return
	}

	if err := h.service.AssignPermissionsToRole(c.Request.Context(), roleID, req.PermissionIDs); err != nil {
		handleRBACError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Permissions assigned successfully"})
}

// Error handler helper
func handleRBACError(c *gin.Context, err error) {
	switch err {
	case ErrRoleNotFound:
		c.JSON(http.StatusNotFound, errors.NotFound("Role"))
	case ErrRoleAlreadyExists:
		c.JSON(http.StatusConflict, errors.Conflict("Role with this slug already exists"))
	case ErrSystemRoleProtected:
		c.JSON(http.StatusForbidden, errors.Forbidden("System roles cannot be modified or deleted"))
	case ErrUserAlreadyHasRole:
		c.JSON(http.StatusConflict, errors.Conflict("User already has this role"))
	case ErrPermissionDenied:
		c.JSON(http.StatusForbidden, errors.PermissionDenied("access"))
	case ErrInvalidResourceName, ErrReservedName:
		c.JSON(http.StatusBadRequest, errors.BadRequest(err.Error()))
	case ErrResourceNotFound:
		c.JSON(http.StatusNotFound, errors.NotFound("Resource"))
	default:
		c.JSON(http.StatusInternalServerError, errors.Internal("Internal server error", err))
	}
}

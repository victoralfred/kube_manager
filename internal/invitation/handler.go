package invitation

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/pkg/errors"
)

// Handler handles HTTP requests for invitations
type Handler struct {
	service Service
}

// NewHandler creates a new invitation handler
func NewHandler(service Service) *Handler {
	return &Handler{
		service: service,
	}
}

// InviteUser handles user invitation requests
func (h *Handler) InviteUser(c *gin.Context) {
	// Get tenant and actor from context (set by middleware)
	tenantID := getTenantIDFromContext(c)
	actorID := getUserIDFromContext(c)

	if tenantID == "" || actorID == "" {
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Missing authentication context"))
		return
	}

	var req InviteUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid request body"))
		return
	}

	invitation, err := h.service.InviteUser(c.Request.Context(), tenantID, actorID, req)
	if err != nil {
		handleInvitationError(c, err)
		return
	}

	c.JSON(http.StatusCreated, invitation)
}

// AcceptInvitation handles invitation acceptance requests
func (h *Handler) AcceptInvitation(c *gin.Context) {
	var req AcceptInvitationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invalid request body"))
		return
	}

	user, err := h.service.AcceptInvitation(c.Request.Context(), req)
	if err != nil {
		handleInvitationError(c, err)
		return
	}

	c.JSON(http.StatusOK, user)
}

// GetInvitation handles getting invitation details by token
func (h *Handler) GetInvitation(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Token is required"))
		return
	}

	invitation, err := h.service.GetInvitation(c.Request.Context(), token)
	if err != nil {
		handleInvitationError(c, err)
		return
	}

	c.JSON(http.StatusOK, invitation)
}

// ListInvitations handles listing invitations for a tenant
func (h *Handler) ListInvitations(c *gin.Context) {
	tenantID := getTenantIDFromContext(c)
	if tenantID == "" {
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Missing tenant context"))
		return
	}

	// Parse query parameters
	filter := ListInvitationsFilter{
		TenantID: tenantID,
		Status:   InvitationStatus(c.Query("status")),
		Email:    c.Query("email"),
	}

	// Parse pagination
	if pageStr := c.Query("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil {
			filter.Page = page
		}
	}
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil {
			filter.PageSize = pageSize
		}
	}

	invitations, total, err := h.service.ListInvitations(c.Request.Context(), filter)
	if err != nil {
		handleInvitationError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"invitations": invitations,
		"total":       total,
		"page":        filter.Page,
		"page_size":   filter.PageSize,
	})
}

// RevokeInvitation handles revoking an invitation
func (h *Handler) RevokeInvitation(c *gin.Context) {
	tenantID := getTenantIDFromContext(c)
	actorID := getUserIDFromContext(c)
	invitationID := c.Param("id")

	if tenantID == "" || actorID == "" {
		c.JSON(http.StatusUnauthorized, errors.Unauthorized("Missing authentication context"))
		return
	}

	if invitationID == "" {
		c.JSON(http.StatusBadRequest, errors.BadRequest("Invitation ID is required"))
		return
	}

	if err := h.service.RevokeInvitation(c.Request.Context(), tenantID, invitationID, actorID); err != nil {
		handleInvitationError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Invitation revoked successfully"})
}

// Helper functions

func handleInvitationError(c *gin.Context, err error) {
	switch err {
	case ErrInvitationNotFound:
		c.JSON(http.StatusNotFound, errors.NotFound("Invitation not found"))
	case ErrInvitationAlreadyExists:
		c.JSON(http.StatusConflict, errors.Conflict("Invitation already exists for this email"))
	default:
		// Check error message for common patterns
		errMsg := err.Error()
		if contains(errMsg, "already exists") {
			c.JSON(http.StatusConflict, errors.Conflict(errMsg))
		} else if contains(errMsg, "not found") {
			c.JSON(http.StatusNotFound, errors.NotFound(errMsg))
		} else if contains(errMsg, "expired") {
			c.JSON(http.StatusBadRequest, errors.BadRequest(errMsg))
		} else if contains(errMsg, "revoked") {
			c.JSON(http.StatusBadRequest, errors.BadRequest(errMsg))
		} else if contains(errMsg, "invalid") {
			c.JSON(http.StatusBadRequest, errors.BadRequest(errMsg))
		} else {
			c.JSON(http.StatusInternalServerError, errors.Internal("Internal server error", err))
		}
	}
}

func getTenantIDFromContext(c *gin.Context) string {
	if val, exists := c.Get("tenant_id"); exists {
		if tenantID, ok := val.(string); ok {
			return tenantID
		}
	}
	return ""
}

func getUserIDFromContext(c *gin.Context) string {
	if val, exists := c.Get("user_id"); exists {
		if userID, ok := val.(string); ok {
			return userID
		}
	}
	return ""
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

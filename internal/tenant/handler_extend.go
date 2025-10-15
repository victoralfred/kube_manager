package tenant

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/pkg/errors"
)

// ListTenants handles listing tenants with filters
// @Summary List tenants
// @Tags tenants
// @Produce json
// @Param status query string false "Filter by status"
// @Param search query string false "Search by name or slug"
// @Param limit query int false "Limit results"
// @Param offset query int false "Offset results"
// @Param sort_by query string false "Sort by field"
// @Param sort_desc query bool false "Sort descending"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} errors.AppError
// @Router /tenants [get]
func (h *Handler) ListTenants(c *gin.Context) {
	filter := ListTenantsFilter{
		Search: c.Query("search"),
		Limit:  10,
		Offset: 0,
		SortBy: c.Query("sort_by"),
	}

	if status := c.Query("status"); status != "" {
		s := TenantStatus(status)
		filter.Status = &s
	}

	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil {
			filter.Limit = l
		}
	}

	if offset := c.Query("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil {
			filter.Offset = o
		}
	}

	if sortDesc := c.Query("sort_desc"); sortDesc == "true" {
		filter.SortDesc = true
	}

	tenants, total, err := h.service.ListTenants(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to list tenants", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   tenants,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// SuspendTenant handles suspending a tenant
// @Summary Suspend tenant
// @Tags tenants
// @Param id path string true "Tenant ID"
// @Success 200 {object} map[string]string
// @Failure 404 {object} errors.AppError
// @Failure 500 {object} errors.AppError
// @Router /tenants/{id}/suspend [post]
func (h *Handler) SuspendTenant(c *gin.Context) {
	id := c.Param("id")

	if err := h.service.SuspendTenant(c.Request.Context(), id); err != nil {
		if err == ErrTenantNotFound {
			c.JSON(http.StatusNotFound, errors.NotFound("Tenant"))
			return
		}
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to suspend tenant", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tenant suspended successfully"})
}

// ActivateTenant handles activating a tenant
// @Summary Activate tenant
// @Tags tenants
// @Param id path string true "Tenant ID"
// @Success 200 {object} map[string]string
// @Failure 404 {object} errors.AppError
// @Failure 500 {object} errors.AppError
// @Router /tenants/{id}/activate [post]
func (h *Handler) ActivateTenant(c *gin.Context) {
	id := c.Param("id")

	if err := h.service.ActivateTenant(c.Request.Context(), id); err != nil {
		if err == ErrTenantNotFound {
			c.JSON(http.StatusNotFound, errors.NotFound("Tenant"))
			return
		}
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to activate tenant", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tenant activated successfully"})
}

// GetTenantStats handles retrieving tenant statistics
// @Summary Get tenant statistics
// @Tags tenants
// @Produce json
// @Param id path string true "Tenant ID"
// @Success 200 {object} TenantStats
// @Failure 404 {object} errors.AppError
// @Failure 500 {object} errors.AppError
// @Router /tenants/{id}/stats [get]
func (h *Handler) GetTenantStats(c *gin.Context) {
	id := c.Param("id")

	stats, err := h.service.GetTenantStats(c.Request.Context(), id)
	if err != nil {
		if err == ErrTenantNotFound {
			c.JSON(http.StatusNotFound, errors.NotFound("Tenant"))
			return
		}
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to get tenant stats", err))
		return
	}

	c.JSON(http.StatusOK, stats)
}

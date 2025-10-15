package tenant

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/kube_manager/pkg/errors"
)

// Handler handles HTTP requests for tenant operations
type Handler struct {
	service Service
}

// NewHandler creates a new tenant handler
func NewHandler(service Service) *Handler {
	return &Handler{
		service: service,
	}
}

// CreateTenant handles tenant creation
// @Summary Create a new tenant
// @Tags tenants
// @Accept json
// @Produce json
// @Param request body CreateTenantRequest true "Tenant creation request"
// @Success 201 {object} Tenant
// @Failure 400 {object} errors.AppError
// @Failure 500 {object} errors.AppError
// @Router /tenants [post]
func (h *Handler) CreateTenant(c *gin.Context) {
	var req CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest(err.Error()))
		return
	}

	tenant, err := h.service.CreateTenant(c.Request.Context(), req)
	if err != nil {
		if err == ErrTenantAlreadyExists {
			c.JSON(http.StatusConflict, errors.Conflict("Tenant already exists"))
			return
		}
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to create tenant", err))
		return
	}

	c.JSON(http.StatusCreated, tenant)
}

// GetTenant handles retrieving a tenant by ID
// @Summary Get tenant by ID
// @Tags tenants
// @Produce json
// @Param id path string true "Tenant ID"
// @Success 200 {object} Tenant
// @Failure 404 {object} errors.AppError
// @Failure 500 {object} errors.AppError
// @Router /tenants/{id} [get]
func (h *Handler) GetTenant(c *gin.Context) {
	id := c.Param("id")

	tenant, err := h.service.GetTenant(c.Request.Context(), id)
	if err != nil {
		if err == ErrTenantNotFound {
			c.JSON(http.StatusNotFound, errors.NotFound("Tenant"))
			return
		}
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to get tenant", err))
		return
	}

	c.JSON(http.StatusOK, tenant)
}

// GetTenantBySlug handles retrieving a tenant by slug
// @Summary Get tenant by slug
// @Tags tenants
// @Produce json
// @Param slug path string true "Tenant slug"
// @Success 200 {object} Tenant
// @Failure 404 {object} errors.AppError
// @Failure 500 {object} errors.AppError
// @Router /tenants/slug/{slug} [get]
func (h *Handler) GetTenantBySlug(c *gin.Context) {
	slug := c.Param("slug")

	tenant, err := h.service.GetTenantBySlug(c.Request.Context(), slug)
	if err != nil {
		if err == ErrTenantNotFound {
			c.JSON(http.StatusNotFound, errors.NotFound("Tenant"))
			return
		}
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to get tenant", err))
		return
	}

	c.JSON(http.StatusOK, tenant)
}

// UpdateTenant handles updating a tenant
// @Summary Update tenant
// @Tags tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Param request body UpdateTenantRequest true "Tenant update request"
// @Success 200 {object} Tenant
// @Failure 400 {object} errors.AppError
// @Failure 404 {object} errors.AppError
// @Failure 500 {object} errors.AppError
// @Router /tenants/{id} [put]
func (h *Handler) UpdateTenant(c *gin.Context) {
	id := c.Param("id")

	var req UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.BadRequest(err.Error()))
		return
	}

	tenant, err := h.service.UpdateTenant(c.Request.Context(), id, req)
	if err != nil {
		if err == ErrTenantNotFound {
			c.JSON(http.StatusNotFound, errors.NotFound("Tenant"))
			return
		}
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to update tenant", err))
		return
	}

	c.JSON(http.StatusOK, tenant)
}

// DeleteTenant handles deleting a tenant
// @Summary Delete tenant
// @Tags tenants
// @Param id path string true "Tenant ID"
// @Success 204
// @Failure 404 {object} errors.AppError
// @Failure 500 {object} errors.AppError
// @Router /tenants/{id} [delete]
func (h *Handler) DeleteTenant(c *gin.Context) {
	id := c.Param("id")

	if err := h.service.DeleteTenant(c.Request.Context(), id); err != nil {
		if err == ErrTenantNotFound {
			c.JSON(http.StatusNotFound, errors.NotFound("Tenant"))
			return
		}
		c.JSON(http.StatusInternalServerError, errors.Internal("Failed to delete tenant", err))
		return
	}

	c.Status(http.StatusNoContent)
}

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestTenantIdentifier(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("should extract tenant ID from header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set(TenantIDHeader, "tenant-123")
		c.Request = req

		middleware := TenantIdentifier()
		middleware(c)

		// Should not abort
		assert.False(t, c.IsAborted())

		// Tenant ID should be in context
		tenantID := GetTenantID(c.Request.Context())
		assert.Equal(t, "tenant-123", tenantID)
	})

	t.Run("should extract tenant ID from subdomain", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test", nil)
		req.Host = "acme.example.com"
		c.Request = req

		middleware := TenantIdentifier()
		middleware(c)

		assert.False(t, c.IsAborted())

		tenantID := GetTenantID(c.Request.Context())
		assert.Equal(t, "acme", tenantID)
	})

	t.Run("should extract tenant ID from path parameter", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/tenants/tenant-456/users", nil)
		c.Request = req
		c.Params = gin.Params{
			{Key: "tenant_id", Value: "tenant-456"},
		}

		middleware := TenantIdentifier()
		middleware(c)

		assert.False(t, c.IsAborted())

		tenantID := GetTenantID(c.Request.Context())
		assert.Equal(t, "tenant-456", tenantID)
	})

	t.Run("should extract tenant ID from query parameter", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test?tenant_id=tenant-789", nil)
		c.Request = req

		middleware := TenantIdentifier()
		middleware(c)

		assert.False(t, c.IsAborted())

		tenantID := GetTenantID(c.Request.Context())
		assert.Equal(t, "tenant-789", tenantID)
	})

	t.Run("should return error when tenant ID is missing", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test", nil)
		c.Request = req

		middleware := TenantIdentifier()
		middleware(c)

		// Should abort with bad request
		assert.True(t, c.IsAborted())
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("header should take priority over other sources", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test?tenant_id=query-tenant", nil)
		req.Host = "subdomain-tenant.example.com"
		req.Header.Set(TenantIDHeader, "header-tenant")
		c.Request = req

		middleware := TenantIdentifier()
		middleware(c)

		assert.False(t, c.IsAborted())

		tenantID := GetTenantID(c.Request.Context())
		assert.Equal(t, "header-tenant", tenantID)
	})
}

func TestOptionalTenantIdentifier(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("should extract tenant ID when present", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set(TenantIDHeader, "tenant-123")
		c.Request = req

		middleware := OptionalTenantIdentifier()
		middleware(c)

		assert.False(t, c.IsAborted())

		tenantID := GetTenantID(c.Request.Context())
		assert.Equal(t, "tenant-123", tenantID)
	})

	t.Run("should not abort when tenant ID is missing", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test", nil)
		c.Request = req

		middleware := OptionalTenantIdentifier()
		middleware(c)

		// Should NOT abort
		assert.False(t, c.IsAborted())

		// Tenant ID should be empty
		tenantID := GetTenantID(c.Request.Context())
		assert.Empty(t, tenantID)
	})
}

func TestGetTenantID(t *testing.T) {
	t.Run("should return tenant ID from context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set(TenantIDHeader, "tenant-123")
		c.Request = req

		middleware := TenantIdentifier()
		middleware(c)

		tenantID := GetTenantID(c.Request.Context())
		assert.Equal(t, "tenant-123", tenantID)
	})

	t.Run("should return empty string when no tenant ID in context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test", nil)
		c.Request = req

		tenantID := GetTenantID(c.Request.Context())
		assert.Empty(t, tenantID)
	})
}

func TestSubdomainExtraction(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		host           string
		expectedTenant string
	}{
		{
			name:           "simple subdomain",
			host:           "acme.example.com",
			expectedTenant: "acme",
		},
		{
			name:           "no subdomain",
			host:           "example.com",
			expectedTenant: "",
		},
		{
			name:           "localhost",
			host:           "localhost:8080",
			expectedTenant: "",
		},
		{
			name:           "nested subdomain",
			host:           "api.acme.example.com",
			expectedTenant: "api",
		},
		{
			name:           "IP address",
			host:           "192.168.1.1",
			expectedTenant: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req, _ := http.NewRequest("GET", "/test", nil)
			req.Host = tt.host
			c.Request = req

			// Use OptionalTenantIdentifier to not abort on missing tenant
			middleware := OptionalTenantIdentifier()
			middleware(c)

			tenantID := GetTenantID(c.Request.Context())
			assert.Equal(t, tt.expectedTenant, tenantID)
		})
	}
}

func TestTenantIDValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("should accept valid UUID tenant ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set(TenantIDHeader, "550e8400-e29b-41d4-a716-446655440000")
		c.Request = req

		middleware := TenantIdentifier()
		middleware(c)

		assert.False(t, c.IsAborted())

		tenantID := GetTenantID(c.Request.Context())
		assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", tenantID)
	})

	t.Run("should accept alphanumeric tenant ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set(TenantIDHeader, "tenant123")
		c.Request = req

		middleware := TenantIdentifier()
		middleware(c)

		assert.False(t, c.IsAborted())

		tenantID := GetTenantID(c.Request.Context())
		assert.Equal(t, "tenant123", tenantID)
	})
}

func TestMultipleSourcesPriority(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("priority order: header > subdomain > path > query", func(t *testing.T) {
		tests := []struct {
			name           string
			header         string
			subdomain      string
			pathParam      string
			queryParam     string
			expectedTenant string
		}{
			{
				name:           "header wins",
				header:         "header-tenant",
				subdomain:      "subdomain-tenant",
				pathParam:      "path-tenant",
				queryParam:     "query-tenant",
				expectedTenant: "header-tenant",
			},
			{
				name:           "subdomain wins when no header",
				header:         "",
				subdomain:      "subdomain-tenant",
				pathParam:      "path-tenant",
				queryParam:     "query-tenant",
				expectedTenant: "subdomain-tenant",
			},
			{
				name:           "path wins when no header or subdomain",
				header:         "",
				subdomain:      "",
				pathParam:      "path-tenant",
				queryParam:     "query-tenant",
				expectedTenant: "path-tenant",
			},
			{
				name:           "query wins when only source",
				header:         "",
				subdomain:      "",
				pathParam:      "",
				queryParam:     "query-tenant",
				expectedTenant: "query-tenant",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				url := "/test"
				if tt.queryParam != "" {
					url += "?tenant_id=" + tt.queryParam
				}

				req, _ := http.NewRequest("GET", url, nil)

				if tt.header != "" {
					req.Header.Set(TenantIDHeader, tt.header)
				}

				if tt.subdomain != "" {
					req.Host = tt.subdomain + ".example.com"
				}

				if tt.pathParam != "" {
					c.Params = gin.Params{
						{Key: "tenant_id", Value: tt.pathParam},
					}
				}

				c.Request = req

				middleware := TenantIdentifier()
				middleware(c)

				tenantID := GetTenantID(c.Request.Context())
				assert.Equal(t, tt.expectedTenant, tenantID)
			})
		}
	})
}

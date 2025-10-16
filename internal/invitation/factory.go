package invitation

import (
	"github.com/victoralfred/kube_manager/internal/auth"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/internal/tenant"
	"github.com/victoralfred/kube_manager/pkg/database"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Module holds all invitation components
type Module struct {
	Repository Repository
	Service    Service
	Handler    *Handler
}

// NewModule creates a new invitation module with all dependencies
func NewModule(
	db *database.DB,
	authRepo auth.Repository,
	tenantService tenant.Service,
	rbacService rbac.Service,
	log *logger.Logger,
) *Module {
	// Create repository
	repo := NewRepository(db)

	// Create service
	svc := NewService(repo, authRepo, tenantService, rbacService, log)

	// Create handler
	handler := NewHandler(svc)

	return &Module{
		Repository: repo,
		Service:    svc,
		Handler:    handler,
	}
}

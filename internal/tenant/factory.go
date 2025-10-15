package tenant

import (
	"github.com/victoralfred/kube_manager/pkg/database"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Module holds all tenant module components
type Module struct {
	Repository Repository
	Service    Service
	Handler    *Handler
}

// NewModule creates and initializes the tenant module using factory pattern
func NewModule(db *database.DB, log *logger.Logger) *Module {
	// Create repository
	repo := NewRepository(db)

	// Create service with repository dependency
	svc := NewService(repo, log)

	// Create handler with service dependency
	handler := NewHandler(svc)

	return &Module{
		Repository: repo,
		Service:    svc,
		Handler:    handler,
	}
}

// GetService returns the tenant service
func (m *Module) GetService() Service {
	return m.Service
}

// GetHandler returns the tenant handler
func (m *Module) GetHandler() *Handler {
	return m.Handler
}

// GetRepository returns the tenant repository
func (m *Module) GetRepository() Repository {
	return m.Repository
}
